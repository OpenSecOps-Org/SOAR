"""
Unit tests for S3.10 auto-remediation function (Enable Lifecycle Configuration)

This control checks whether S3 buckets have lifecycle configuration to manage objects,
reducing storage costs and improving data management. S3.10 adds a lifecycle configuration
that deletes noncurrent versions after 365 days and aborts incomplete multipart uploads
after 1 day.

Test triggers:
- Bucket without lifecycle: aws s3api get-bucket-lifecycle-configuration --bucket bucket-name
- Bucket with versioning: aws s3api get-bucket-versioning --bucket bucket-name

The auto-remediation applies lifecycle rules for cost optimization and data management.
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
    get_s310_basic_finding,
    get_s310_cross_account_finding,
    get_s310_nonexistent_bucket_finding,
    get_s32_malformed_arn_finding,
    get_s3_missing_details_finding,
    get_s3_empty_resources_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_s310'))
from functions.auto_remediations.auto_remediate_s310.app import lambda_handler


class TestS310SuccessScenarios:
    """Test successful lifecycle configuration scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_basic_lifecycle_configuration(self, mock_get_client):
        """Test successful lifecycle configuration application"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock successful lifecycle configuration response
        mock_s3_client.put_bucket_lifecycle_configuration.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}
        }
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify remediation was successful
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is False
        assert "lifecycle configuration has been added" in result['messages']['actions_taken']
        assert "Noncurrent versions will be deleted after a year" in result['messages']['actions_taken']
        assert "incomplete uploads after a day" in result['messages']['actions_taken']
        
        # Verify correct S3 API call with expected lifecycle configuration
        mock_s3_client.put_bucket_lifecycle_configuration.assert_called_once_with(
            Bucket='test-bucket-lifecycle-needed',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'DeleteNoncurrentAndIncomplete',
                        'Status': 'Enabled',
                        'Filter': {
                            'Prefix': '',
                        },
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 365,
                            'NewerNoncurrentVersions': 1
                        },
                        'AbortIncompleteMultipartUpload': {
                            'DaysAfterInitiation': 1
                        }
                    },
                ],
            },
        )
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '123456789012', 'us-east-1')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_cross_account_lifecycle(self, mock_get_client):
        """Test successful lifecycle configuration for cross-account bucket"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock successful response
        mock_s3_client.put_bucket_lifecycle_configuration.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}
        }
        
        # Prepare cross-account test data
        asff_data = prepare_s3_test_data(get_s310_cross_account_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert "lifecycle configuration has been added" in result['messages']['actions_taken']
        
        # Verify correct cross-account parameters
        mock_s3_client.put_bucket_lifecycle_configuration.assert_called_once_with(
            Bucket='cross-account-lifecycle-bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'DeleteNoncurrentAndIncomplete',
                        'Status': 'Enabled',
                        'Filter': {
                            'Prefix': '',
                        },
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 365,
                            'NewerNoncurrentVersions': 1
                        },
                        'AbortIncompleteMultipartUpload': {
                            'DaysAfterInitiation': 1
                        }
                    },
                ],
            },
        )
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '555666777888', 'us-west-2')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_lifecycle_rule_configuration_details(self, mock_get_client):
        """Test detailed lifecycle rule configuration parameters"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock successful response
        mock_s3_client.put_bucket_lifecycle_configuration.return_value = {}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Extract the lifecycle configuration that was called
        call_args = mock_s3_client.put_bucket_lifecycle_configuration.call_args
        lifecycle_config = call_args[1]['LifecycleConfiguration']
        rule = lifecycle_config['Rules'][0]
        
        # Verify specific rule configuration details
        assert rule['ID'] == 'DeleteNoncurrentAndIncomplete'
        assert rule['Status'] == 'Enabled'
        assert rule['Filter']['Prefix'] == ''
        assert rule['NoncurrentVersionExpiration']['NoncurrentDays'] == 365
        assert rule['NoncurrentVersionExpiration']['NewerNoncurrentVersions'] == 1
        assert rule['AbortIncompleteMultipartUpload']['DaysAfterInitiation'] == 1
        
        # Verify there's only one rule
        assert len(lifecycle_config['Rules']) == 1


class TestS310ErrorHandling:
    """Test error handling scenarios with generic exception catching"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_no_such_bucket_suppression(self, mock_get_client):
        """Test handling of NoSuchBucket error results in finding suppression"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock NoSuchBucket error
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'The specified bucket does not exist'}}
        mock_s3_client.put_bucket_lifecycle_configuration.side_effect = botocore.exceptions.ClientError(
            error_response, 'PutBucketLifecycleConfiguration'
        )
        
        # Prepare test data with non-existent bucket
        asff_data = prepare_s3_test_data(get_s310_nonexistent_bucket_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to generic exception handling
        assert result['actions']['suppress_finding'] is True
        assert result['actions']['autoremediation_not_done'] is False
        assert "Couldn't create a bucket lifecycle configuration" in result['messages']['actions_taken']
        assert "This finding will be suppressed" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_access_denied_suppression(self, mock_get_client):
        """Test handling of AccessDenied error results in finding suppression"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock AccessDenied error
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}}
        mock_s3_client.put_bucket_lifecycle_configuration.side_effect = botocore.exceptions.ClientError(
            error_response, 'PutBucketLifecycleConfiguration'
        )
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to generic exception handling
        assert result['actions']['suppress_finding'] is True
        assert "Couldn't create a bucket lifecycle configuration" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_invalid_bucket_configuration_suppression(self, mock_get_client):
        """Test handling of InvalidBucketState error results in finding suppression"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock InvalidBucketState error (e.g., bucket has incompatible configuration)
        error_response = {'Error': {'Code': 'InvalidBucketState', 'Message': 'Bucket configuration is invalid'}}
        mock_s3_client.put_bucket_lifecycle_configuration.side_effect = botocore.exceptions.ClientError(
            error_response, 'PutBucketLifecycleConfiguration'
        )
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to generic exception handling
        assert result['actions']['suppress_finding'] is True
        assert "Couldn't create a bucket lifecycle configuration" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_throttling_error_suppression(self, mock_get_client):
        """Test handling of throttling errors results in finding suppression"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock Throttling error
        error_response = {'Error': {'Code': 'Throttling', 'Message': 'Rate exceeded'}}
        mock_s3_client.put_bucket_lifecycle_configuration.side_effect = botocore.exceptions.ClientError(
            error_response, 'PutBucketLifecycleConfiguration'
        )
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to generic exception handling
        assert result['actions']['suppress_finding'] is True
        assert "Couldn't create a bucket lifecycle configuration" in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_generic_exception_suppression(self, mock_get_client):
        """Test handling of generic Python exceptions results in finding suppression"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock generic Python exception
        mock_s3_client.put_bucket_lifecycle_configuration.side_effect = RuntimeError("Unexpected error")
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should suppress finding due to generic exception handling
        assert result['actions']['suppress_finding'] is True
        assert "Couldn't create a bucket lifecycle configuration" in result['messages']['actions_taken']


class TestS310EdgeCases:
    """Test edge cases and malformed input scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_malformed_arn_exception(self, mock_get_client):
        """Test handling of malformed bucket ARN raises exception before API call"""
        # Setup mock S3 client (should not be called due to ARN parsing failure)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data with malformed ARN
        asff_data = prepare_s3_test_data(get_s32_malformed_arn_finding)
        
        # Should raise exception due to malformed ARN parsing
        with pytest.raises(IndexError):
            lambda_handler(asff_data, None)
        
        # Client should not be called due to ARN parsing failure
        mock_get_client.assert_not_called()
        mock_s3_client.put_bucket_lifecycle_configuration.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_missing_bucket_details_still_works(self, mock_get_client):
        """Test that missing bucket details doesn't prevent lifecycle configuration (function only needs ID and Region)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_bucket_lifecycle_configuration.return_value = {}
        
        # Prepare test data with missing details
        asff_data = prepare_s3_test_data(get_s3_missing_details_finding)
        
        # Should still work since function only needs bucket ID and region
        result = lambda_handler(asff_data, None)
        
        # Should succeed since Details section is not required
        assert result['actions']['suppress_finding'] is False
        assert "lifecycle configuration has been added" in result['messages']['actions_taken']
        
        # Verify bucket name was extracted correctly from ARN
        mock_s3_client.put_bucket_lifecycle_configuration.assert_called_once()
        call_args = mock_s3_client.put_bucket_lifecycle_configuration.call_args
        assert call_args[1]['Bucket'] == 'bucket-missing-details'

    @mock_aws  
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_empty_resources_exception(self, mock_get_client):
        """Test handling of empty resources array in ASFF finding"""
        # Setup mock S3 client (should not be called due to empty resources)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data with empty resources
        asff_data = prepare_s3_test_data(get_s3_empty_resources_finding)
        
        # Should raise exception due to empty resources array
        with pytest.raises(IndexError):
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_get_client_failure_propagates(self, mock_get_client):
        """Test that get_client failure propagates as exception (not caught by try-catch)"""
        # Mock get_client to raise an exception
        client_error = Exception("Failed to create S3 client")
        mock_get_client.side_effect = client_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Should raise exception since get_client is outside try-catch block
        with pytest.raises(Exception) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same exception from get_client
        assert exc_info.value == client_error
        assert str(exc_info.value) == "Failed to create S3 client"


class TestS310DataStructureHandling:
    """Test data structure preservation and message formatting"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_data_structure_preservation(self, mock_get_client):
        """Test that original data structure is preserved during successful remediation"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_bucket_lifecycle_configuration.return_value = {}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
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
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_success_message_formatting(self, mock_get_client):
        """Test proper formatting of success messages"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        mock_s3_client.put_bucket_lifecycle_configuration.return_value = {}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify success message content and format
        actions_taken = result['messages']['actions_taken']
        assert "A lifecycle configuration has been added to the bucket" in actions_taken
        assert "Noncurrent versions will be deleted after a year" in actions_taken
        assert "incomplete uploads after a day" in actions_taken
        
        # Verify no changes to other message fields
        assert result['messages']['actions_required'] == asff_data['messages']['actions_required']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_s310.app.get_client')
    def test_s310_error_message_formatting(self, mock_get_client):
        """Test proper formatting of error messages during suppression"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock exception to trigger suppression
        mock_s3_client.put_bucket_lifecycle_configuration.side_effect = Exception("Test error")
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s310_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify error message content and format
        actions_taken = result['messages']['actions_taken']
        assert "Couldn't create a bucket lifecycle configuration" in actions_taken
        assert "This finding will be suppressed" in actions_taken
        
        # Verify suppression flag is set
        assert result['actions']['suppress_finding'] is True