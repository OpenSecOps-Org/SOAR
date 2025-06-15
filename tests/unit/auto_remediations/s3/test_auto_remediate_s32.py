"""
Unit tests for S3.2 auto-remediation function (Prohibit Public Access)

This control checks whether S3 buckets have bucket-level public access blocks applied.
S3.2 blocks public access on S3 buckets by enabling all public access block settings
unless the bucket has a specific exemption tag.

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
    get_s32_basic_finding,
    get_s32_exemption_tag_finding,
    get_s32_cross_account_finding,
    get_s32_nonexistent_bucket_finding,
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
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_s32'))
from functions.auto_remediations.auto_remediate_s32.app import lambda_handler, has_tag


class TestInternalFunctions:
    """Test internal functions in isolation"""

    class TestHasTag:
        """Test the has_tag() function"""

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
            """Test that tag search is case sensitive"""
            tags = [
                {'Key': 'ALLOW-PUBLIC-ACCESS', 'Value': 'true'}
            ]
            result = has_tag('allow-public-access', tags)
            assert result is False


class TestS32BasicFunctionality:
    """Test basic S3.2 remediation functionality"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_successful_remediation_no_tags(self, mock_get_client):
        """Test successful S3.2 remediation when no exemption tag present"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Create ASFF data without exemption tags
        asff_data = prepare_s3_test_data(get_s32_basic_finding, tags=[])

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify client was called correctly
        mock_get_client.assert_called_once_with('s3', '123456789012', 'us-east-1')
        mock_s3_client.put_public_access_block.assert_called_once_with(
            Bucket='test-bucket-no-public-block',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        # Verify response
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is False
        assert "Public access has been disabled" in result['messages']['actions_taken']
        assert "allow-public-access" in result['messages']['actions_taken']
        assert "allow-public-access" in result['messages']['actions_required']

    @mock_aws 
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_exemption_tag_suppression(self, mock_get_client):
        """Test S3.2 finding suppression when exemption tag is present"""
        # Setup mock S3 client (should not be called)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client

        # Create ASFF data with exemption tag
        exemption_tags = [
            {'Key': 'Environment', 'Value': 'prod'},
            {'Key': 'allow-public-access', 'Value': 'true'}
        ]
        asff_data = prepare_s3_test_data(get_s32_exemption_tag_finding, tags=exemption_tags)

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify S3 client was not called for remediation
        mock_s3_client.put_public_access_block.assert_not_called()

        # Verify finding suppression
        assert result['actions']['suppress_finding'] is True
        assert result['actions']['autoremediation_not_done'] is False

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_cross_account_remediation(self, mock_get_client):
        """Test S3.2 remediation with cross-account bucket"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Create ASFF data for cross-account scenario
        asff_data = prepare_s3_test_data(get_s32_cross_account_finding, tags=[])

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '555666777888', 'us-west-2')
        mock_s3_client.put_public_access_block.assert_called_once_with(
            Bucket='cross-account-test-bucket',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is False


class TestS32ErrorHandling:
    """Test S3.2 error handling scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_nosuchbucket_error_suppression(self, mock_get_client):
        """Test S3.2 handles NoSuchBucket error by suppressing finding"""
        # Setup mock S3 client to raise NoSuchBucket error
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'The specified bucket does not exist'}}
        mock_s3_client.put_public_access_block.side_effect = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')

        # Create ASFF data
        asff_data = prepare_s3_test_data(get_s32_nonexistent_bucket_finding, tags=[])

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify finding suppression
        assert result['actions']['suppress_finding'] is True
        assert result['actions']['autoremediation_not_done'] is False
        assert "Unable to block public access: NoSuchBucket" in result['messages']['actions_taken']
        assert "This finding has been suppressed" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_access_denied_error_suppression(self, mock_get_client):
        """Test S3.2 handles AccessDenied error by suppressing finding"""
        # Setup mock S3 client to raise AccessDenied error
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}}
        mock_s3_client.put_public_access_block.side_effect = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')

        # Create ASFF data
        asff_data = prepare_s3_test_data(get_s32_basic_finding, tags=[])

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify finding suppression
        assert result['actions']['suppress_finding'] is True
        assert result['actions']['autoremediation_not_done'] is False
        assert "Unable to block public access: AccessDenied" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_other_error_handling(self, mock_get_client):
        """Test S3.2 handles other API errors by marking remediation as failed"""
        # Setup mock S3 client to raise other error
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        error_response = {'Error': {'Code': 'InvalidRequest', 'Message': 'Invalid request'}}
        mock_s3_client.put_public_access_block.side_effect = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')

        # Create ASFF data
        asff_data = prepare_s3_test_data(get_s32_basic_finding, tags=[])

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify remediation failure (not suppression)
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is True
        assert "Failed to block public access: InvalidRequest" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_api_throttling_error(self, mock_get_client):
        """Test S3.2 handles API throttling errors"""
        # Setup mock S3 client to raise throttling error
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        error_response = {'Error': {'Code': 'Throttling', 'Message': 'Rate exceeded'}}
        mock_s3_client.put_public_access_block.side_effect = botocore.exceptions.ClientError(error_response, 'PutPublicAccessBlock')

        # Create ASFF data
        asff_data = prepare_s3_test_data(get_s32_basic_finding, tags=[])

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Verify remediation failure
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is True
        assert "Failed to block public access: Throttling" in result['messages']['actions_taken']


class TestS32EdgeCases:
    """Test S3.2 edge cases and boundary conditions"""

    def test_s32_malformed_bucket_arn(self):
        """Test S3.2 handles malformed bucket ARN"""
        # Create ASFF data with malformed ARN
        asff_data = prepare_s3_test_data(get_s32_malformed_arn_finding, tags=[])

        # Call the lambda handler - should handle ARN parsing gracefully
        with pytest.raises(IndexError):
            # The split(':::', 1)[1] will fail on malformed ARN
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_empty_resources_array(self, mock_get_client):
        """Test S3.2 handles empty Resources array"""
        # Create ASFF data with empty resources
        asff_data = prepare_s3_test_data(get_s3_empty_resources_finding, tags=[])

        # Call the lambda handler - should fail gracefully
        with pytest.raises(IndexError):
            # finding['Resources'][0] will fail on empty array
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_tag_value_variations(self, mock_get_client):
        """Test S3.2 tag detection with various tag values"""
        # Setup mock S3 client (should not be called for any of these)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client

        # Test various tag values - function only checks for key existence
        tag_variations = [
            [{'Key': 'allow-public-access', 'Value': 'true'}],
            [{'Key': 'allow-public-access', 'Value': 'false'}],  # Value doesn't matter
            [{'Key': 'allow-public-access', 'Value': ''}],       # Empty value still counts
            [{'Key': 'allow-public-access', 'Value': 'anything'}] # Any value counts
        ]

        for tags in tag_variations:
            asff_data = prepare_s3_test_data(get_s32_exemption_tag_finding, tags=tags)
            result = lambda_handler(asff_data, None)
            
            # All should suppress the finding
            assert result['actions']['suppress_finding'] is True
            mock_s3_client.put_public_access_block.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    def test_s32_multiple_similar_tags(self, mock_get_client):
        """Test S3.2 tag detection with multiple similar tags"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client

        # Tags with similar names but only exact match should work
        tags = [
            {'Key': 'allow-public-access-temp', 'Value': 'true'},
            {'Key': 'allow-public', 'Value': 'true'},
            {'Key': 'public-access', 'Value': 'true'}
        ]
        
        asff_data = prepare_s3_test_data(get_s32_basic_finding, tags=tags)
        mock_s3_client.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        
        result = lambda_handler(asff_data, None)
        
        # Should proceed with remediation since exact tag not found
        assert result['actions']['suppress_finding'] is False
        mock_s3_client.put_public_access_block.assert_called_once()


class TestS32AsffStructure:
    """Test S3.2 ASFF structure validation and parsing"""

    def test_s32_asff_data_structure(self):
        """Test S3.2 ASFF data structure validation"""
        asff_data = prepare_s3_test_data(get_s32_basic_finding, tags=[])
        
        # Validate ASFF structure
        assert 'finding' in asff_data
        assert 'tags' in asff_data
        assert 'actions' in asff_data
        assert 'messages' in asff_data
        
        # Validate finding structure
        finding = asff_data['finding']
        assert 'AwsAccountId' in finding
        assert 'Resources' in finding
        assert len(finding['Resources']) > 0
        
        # Validate resource structure
        resource = finding['Resources'][0]
        assert 'Id' in resource
        assert 'Region' in resource
        assert resource['Id'].startswith('arn:aws:s3:::')
        
        # Validate tags structure
        assert 'resource' in asff_data['tags']
        assert isinstance(asff_data['tags']['resource'], list)

    def test_s32_bucket_name_extraction(self):
        """Test bucket name extraction from various ARN formats"""
        test_cases = [
            ('arn:aws:s3:::test-bucket-name', 'test-bucket-name'),
            ('arn:aws:s3:::my-bucket-with-dashes', 'my-bucket-with-dashes'),
            ('arn:aws:s3:::bucket.with.dots', 'bucket.with.dots'),
            ('arn:aws:s3:::123-numeric-bucket', '123-numeric-bucket')
        ]
        
        for arn, expected_bucket_name in test_cases:
            # Extract bucket name using same logic as the function
            bucket_name = arn.split(':::', 1)[1]
            assert bucket_name == expected_bucket_name


class TestS32EnvironmentVariables:
    """Test S3.2 environment variable handling"""

    def test_s32_tag_environment_variable(self):
        """Test that TAG environment variable is used correctly"""
        # Verify the environment variable is set as expected
        assert os.environ.get('TAG') == 'allow-public-access'
        
        # Test with different tag values
        tags_with_match = [{'Key': 'allow-public-access', 'Value': 'true'}]
        tags_without_match = [{'Key': 'different-tag', 'Value': 'true'}]
        
        assert has_tag(os.environ['TAG'], tags_with_match) is True
        assert has_tag(os.environ['TAG'], tags_without_match) is False

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s32.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_s32.app.TAG', 'custom-exemption-tag')
    def test_s32_custom_tag_environment(self, mock_get_client):
        """Test S3.2 with custom TAG environment variable"""
        # Setup mock S3 client (should not be called)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client

        # Create tags with custom exemption tag
        custom_tags = [{'Key': 'custom-exemption-tag', 'Value': 'enabled'}]
        asff_data = prepare_s3_test_data(get_s32_exemption_tag_finding, tags=custom_tags)

        # Call the lambda handler
        result = lambda_handler(asff_data, None)

        # Should suppress finding with custom tag
        assert result['actions']['suppress_finding'] is True
        mock_s3_client.put_public_access_block.assert_not_called()