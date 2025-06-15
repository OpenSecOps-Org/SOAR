"""
Unit tests for S3.3 auto-remediation function (Prohibit Public Access)

This control checks whether S3 buckets have bucket-level public access blocks applied.
S3.3 blocks public access on S3 buckets by enabling all public access block settings
unless the bucket has a specific exemption tag.

CRITICAL WARNING: This function lacks comprehensive error handling. Any AWS API failure
will result in unhandled exceptions. Unlike S3.2, this function does not handle 
NoSuchBucket or AccessDenied errors gracefully.

Test triggers:
- Bucket without public access block: aws s3api get-public-access-block --bucket bucket-name
- Check bucket tags: aws s3api get-bucket-tagging --bucket bucket-name

The auto-remediation applies public access block configuration with all settings set to True.
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from moto import mock_aws
import boto3
import botocore.exceptions

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_s3_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from s3_findings import (
    get_s33_basic_finding,
    get_s33_exemption_tag_finding,
    get_s32_cross_account_finding,  # Reuse cross-account fixture
    get_s32_nonexistent_bucket_finding,  # Reuse non-existent bucket fixture
    get_s32_malformed_arn_finding,
    get_s3_missing_details_finding,
    get_s3_empty_resources_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['TAG'] = 'allow-public-access'
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler and internal functions
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_s33'))
from functions.auto_remediations.auto_remediate_s33.app import lambda_handler, has_tag


class TestInternalFunctions:
    """Test internal functions in isolation"""

    class TestHasTag:
        """Test the has_tag() function - identical to S3.2 but testing for completeness"""

        def test_has_tag_found(self):
            """Test tag found in tags list"""
            tags = [
                {'Key': 'Environment', 'Value': 'prod'},
                {'Key': 'allow-public-access', 'Value': 'true'},
                {'Key': 'Owner', 'Value': 'team'}
            ]
            result = has_tag('allow-public-access', tags)
            assert result is True

        def test_has_tag_not_found(self):
            """Test tag not found in tags list"""
            tags = [
                {'Key': 'Environment', 'Value': 'prod'},
                {'Key': 'Owner', 'Value': 'team'}
            ]
            result = has_tag('allow-public-access', tags)
            assert result is False

        def test_has_tag_empty_tags(self):
            """Test tag search with empty tags list"""
            tags = []
            result = has_tag('allow-public-access', tags)
            assert result is False

        def test_has_tag_case_sensitive(self):
            """Test that tag matching is case sensitive"""
            tags = [{'Key': 'Allow-Public-Access', 'Value': 'true'}]
            result = has_tag('allow-public-access', tags)
            assert result is False

        def test_has_tag_value_irrelevant(self):
            """Test that tag value doesn't matter, only key"""
            tags = [{'Key': 'allow-public-access', 'Value': 'false'}]
            result = has_tag('allow-public-access', tags)
            assert result is True


class TestS33SuccessScenarios:
    """Test successful public access blocking scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_basic_public_access_blocking(self, mock_get_client):
        """Test successful public access blocking without exemption tag"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock successful public access block response
        mock_s3_client.put_public_access_block.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}
        }
        
        # Prepare test data without exemption tag
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify remediation was successful
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is False
        assert f"Public access has been disabled, as the tag '{os.environ['TAG']}' wasn't found" in result['messages']['actions_taken']
        assert f"Adding the tag '{os.environ['TAG']}' to an existing bucket will not re-enable" in result['messages']['actions_required']
        
        # Verify correct S3 API call with all public access restrictions
        mock_s3_client.put_public_access_block.assert_called_once_with(
            Bucket='test-bucket-s3-3-control',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '123456789012', 'us-east-1')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_exemption_tag_suppression(self, mock_get_client):
        """Test finding suppression when exemption tag is present"""
        # Setup mock S3 client (should not be called)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Create tags with exemption tag
        exemption_tags = [{'Key': os.environ['TAG'], 'Value': 'enabled'}]
        asff_data = prepare_s3_test_data(get_s33_exemption_tag_finding, tags=exemption_tags)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to exemption tag
        assert result['actions']['suppress_finding'] is True
        assert result['actions']['autoremediation_not_done'] is False
        
        # S3 API should not be called when tag is present
        mock_s3_client.put_public_access_block.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_s33.app.TAG', 'custom-exemption-tag')
    def test_s33_custom_tag_environment(self, mock_get_client):
        """Test S3.3 with custom TAG environment variable"""
        # Setup mock S3 client (should not be called)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Create tags with custom exemption tag
        custom_tags = [{'Key': 'custom-exemption-tag', 'Value': 'enabled'}]
        asff_data = prepare_s3_test_data(get_s33_exemption_tag_finding, tags=custom_tags)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding with custom tag
        assert result['actions']['suppress_finding'] is True
        mock_s3_client.put_public_access_block.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_cross_account_public_access_blocking(self, mock_get_client):
        """Test successful public access blocking for cross-account bucket"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {}
        
        # Prepare cross-account test data without exemption tag
        asff_data = prepare_s3_test_data(get_s32_cross_account_finding, tags=[])
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert "Public access has been disabled" in result['messages']['actions_taken']
        
        # Verify correct cross-account parameters
        mock_s3_client.put_public_access_block.assert_called_once_with(
            Bucket='cross-account-test-bucket',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '555666777888', 'us-west-2')


class TestS33CriticalErrorHandlingGaps:
    """Test the critical error handling gaps in S3.3 function
    
    IMPORTANT: These tests document expected failures due to missing error handling.
    Unlike S3.2, this function does not catch AWS API errors gracefully.
    """

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_no_such_bucket_unhandled_exception(self, mock_get_client):
        """Test that NoSuchBucket error causes unhandled exception (CRITICAL GAP)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock NoSuchBucket error
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'The specified bucket does not exist'}}
        no_such_bucket_error = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')
        mock_s3_client.put_public_access_block.side_effect = no_such_bucket_error
        
        # Prepare test data with non-existent bucket
        asff_data = prepare_s3_test_data(get_s32_nonexistent_bucket_finding, tags=[])
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same NoSuchBucket error
        assert exc_info.value == no_such_bucket_error
        assert exc_info.value.response['Error']['Code'] == 'NoSuchBucket'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_access_denied_unhandled_exception(self, mock_get_client):
        """Test that AccessDenied error causes unhandled exception (CRITICAL GAP)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock AccessDenied error
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}}
        access_denied_error = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')
        mock_s3_client.put_public_access_block.side_effect = access_denied_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same AccessDenied error
        assert exc_info.value == access_denied_error
        assert exc_info.value.response['Error']['Code'] == 'AccessDenied'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_throttling_unhandled_exception(self, mock_get_client):
        """Test that throttling errors cause unhandled exception (CRITICAL GAP)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock Throttling error
        error_response = {'Error': {'Code': 'Throttling', 'Message': 'Rate exceeded'}}
        throttling_error = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')
        mock_s3_client.put_public_access_block.side_effect = throttling_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same throttling error
        assert exc_info.value == throttling_error
        assert exc_info.value.response['Error']['Code'] == 'Throttling'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_invalid_bucket_state_unhandled_exception(self, mock_get_client):
        """Test that InvalidBucketState errors cause unhandled exception (CRITICAL GAP)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock InvalidBucketState error
        error_response = {'Error': {'Code': 'InvalidBucketState', 'Message': 'Bucket state is invalid'}}
        invalid_state_error = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')
        mock_s3_client.put_public_access_block.side_effect = invalid_state_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same InvalidBucketState error
        assert exc_info.value == invalid_state_error
        assert exc_info.value.response['Error']['Code'] == 'InvalidBucketState'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_get_client_failure_unhandled_exception(self, mock_get_client):
        """Test that get_client failure causes unhandled exception (CRITICAL GAP)"""
        # Mock get_client to raise an exception
        client_error = Exception("Failed to create S3 client")
        mock_get_client.side_effect = client_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(Exception) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same exception from get_client
        assert exc_info.value == client_error
        assert str(exc_info.value) == "Failed to create S3 client"


class TestS33EdgeCases:
    """Test edge cases and malformed input scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_malformed_arn_exception(self, mock_get_client):
        """Test handling of malformed bucket ARN raises exception before API call"""
        # Setup mock S3 client (should not be called due to ARN parsing failure)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data with malformed ARN
        asff_data = prepare_s3_test_data(get_s32_malformed_arn_finding, tags=[])
        
        # Should raise exception due to malformed ARN parsing
        with pytest.raises(IndexError):
            lambda_handler(asff_data, None)
        
        # Client should not be called due to ARN parsing failure
        mock_get_client.assert_not_called()
        mock_s3_client.put_public_access_block.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_empty_resources_exception(self, mock_get_client):
        """Test handling of empty resources array raises exception"""
        # Setup mock S3 client (should not be called due to empty resources)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data with empty resources
        asff_data = prepare_s3_test_data(get_s3_empty_resources_finding, tags=[])
        
        # Should raise exception due to empty resources array
        with pytest.raises(IndexError):
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_missing_tags_structure_exception(self, mock_get_client):
        """Test handling of missing tags structure in data"""
        # Setup mock S3 client (should not be called due to missing tags)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data and remove tags structure
        asff_data = prepare_s3_test_data(get_s33_basic_finding)
        del asff_data['tags']  # Remove entire tags structure
        
        # Should raise exception due to missing tags structure
        with pytest.raises(KeyError):
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_large_tag_list_processing(self, mock_get_client):
        """Test processing of bucket with large number of tags"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {}
        
        # Create large tag list without exemption tag
        large_tag_list = [{'Key': f'tag-{i}', 'Value': f'value-{i}'} for i in range(50)]
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=large_tag_list)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should process successfully (no exemption tag found)
        assert result['actions']['suppress_finding'] is False
        assert "Public access has been disabled" in result['messages']['actions_taken']
        mock_s3_client.put_public_access_block.assert_called_once()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_special_characters_in_tags(self, mock_get_client):
        """Test handling of tags with special characters"""
        # Setup mock S3 client (should not be called due to exemption tag)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Create tags with special characters including exemption tag
        special_tags = [
            {'Key': 'unicode-tag', 'Value': 'value-with-émoji-🚀'},
            {'Key': os.environ['TAG'], 'Value': 'special-chars-@#$%'},
            {'Key': 'xml-chars', 'Value': '<tag>&value</tag>'}
        ]
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=special_tags)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to exemption tag (special characters should not affect processing)
        assert result['actions']['suppress_finding'] is True
        mock_s3_client.put_public_access_block.assert_not_called()


class TestS33DataStructureAndIntegration:
    """Test data structure preservation and integration scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_data_structure_preservation(self, mock_get_client):
        """Test that original data structure is preserved during successful remediation"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        original_finding = asff_data['finding'].copy()
        original_actions = asff_data['actions'].copy()
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify original data structure is preserved
        assert result['finding'] == original_finding
        assert result['account'] == asff_data['account']
        assert result['tags'] == asff_data['tags']
        assert result['db'] == asff_data['db']
        
        # Verify actions remain unchanged (no suppression or failure flags)
        assert result['actions']['suppress_finding'] == original_actions['suppress_finding']
        assert result['actions']['autoremediation_not_done'] == original_actions['autoremediation_not_done']
        assert result['actions']['reconsider_later'] == original_actions['reconsider_later']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_message_formatting_success(self, mock_get_client):
        """Test proper message formatting during successful remediation"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify message content and format
        actions_taken = result['messages']['actions_taken']
        actions_required = result['messages']['actions_required']
        
        expected_tag = os.environ['TAG']
        assert f"Public access has been disabled, as the tag '{expected_tag}' wasn't found on the bucket" in actions_taken
        assert f"Adding the tag '{expected_tag}' to an existing bucket will not re-enable public access" in actions_required
        assert "You must redeploy with the correct tag, or add the tag and manually re-enable public access" in actions_required

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_compatibility_with_fetch_bucket_tags(self, mock_get_client):
        """Test S3.3 integration compatibility with fetch_bucket_tags function"""
        # Setup mock S3 client (should not be called)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data with tags structure that mimics fetch_bucket_tags output
        fetch_bucket_tags_output = [
            {'Key': 'Environment', 'Value': 'prod'},
            {'Key': os.environ['TAG'], 'Value': 'true'}
        ]
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=fetch_bucket_tags_output)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should work correctly with fetch_bucket_tags output format
        assert result['actions']['suppress_finding'] is True
        mock_s3_client.put_public_access_block.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s33.app.get_client')
    def test_s33_environment_variable_integration(self, mock_get_client):
        """Test proper integration with TAG environment variable"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s33_basic_finding, tags=[])
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify TAG environment variable is properly used in messages
        tag_value = os.environ['TAG']
        assert tag_value in result['messages']['actions_taken']
        assert tag_value in result['messages']['actions_required']
        
        # Verify the has_tag function would work with current TAG value
        test_tags = [{'Key': tag_value, 'Value': 'any-value'}]
        assert has_tag(tag_value, test_tags) is True