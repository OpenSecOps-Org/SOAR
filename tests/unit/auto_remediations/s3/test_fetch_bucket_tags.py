"""
Unit tests for fetch_bucket_tags function (S3 Tag Retrieval Helper)

This helper function retrieves S3 bucket tags to support tag-based exemption logic 
in S3 auto-remediation functions. It's used by S3.2 and S3.3 controls.

Test triggers:
- Bucket with tags: aws s3api get-bucket-tagging --bucket bucket-name
- Bucket without tags: aws s3api get-bucket-tagging --bucket bucket-name (NoSuchTagSet)
- Non-existent bucket: aws s3api get-bucket-tagging --bucket non-existent-bucket

The function gracefully handles expected errors and populates data['tags']['resource'].
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
    get_s32_cross_account_finding,
    get_s32_nonexistent_bucket_finding,
    get_s32_malformed_arn_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'fetch_bucket_tags'))
from functions.auto_remediations.fetch_bucket_tags.app import lambda_handler


class TestFetchBucketTagsSuccess:
    """Test successful tag retrieval scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_with_existing_tags(self, mock_get_client):
        """Test successful tag retrieval for bucket with tags"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock successful tag response
        mock_tags = [
            {'Key': 'Environment', 'Value': 'prod'},
            {'Key': 'Owner', 'Value': 'security-team'},
            {'Key': 'allow-public-access', 'Value': 'true'}
        ]
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': mock_tags}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify tags were added to data structure
        assert result['tags']['resource'] == mock_tags
        assert len(result['tags']['resource']) == 3
        
        # Verify correct S3 API call
        mock_s3_client.get_bucket_tagging.assert_called_once_with(
            Bucket='test-bucket-no-public-block',
            ExpectedBucketOwner='123456789012'
        )
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '123456789012', 'us-east-1')

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_cross_account(self, mock_get_client):
        """Test successful tag retrieval for cross-account bucket"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock successful tag response
        mock_tags = [{'Key': 'cross-account-tag', 'Value': 'enabled'}]
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': mock_tags}
        
        # Prepare cross-account test data
        asff_data = prepare_s3_test_data(get_s32_cross_account_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify tags were added correctly
        assert result['tags']['resource'] == mock_tags
        
        # Verify correct cross-account parameters
        mock_s3_client.get_bucket_tagging.assert_called_once_with(
            Bucket='cross-account-test-bucket',
            ExpectedBucketOwner='555666777888'
        )
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('s3', '555666777888', 'us-west-2')

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_empty_tagset(self, mock_get_client):
        """Test successful handling of bucket with empty tag set"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock empty tag response
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': []}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify empty tags were handled correctly
        assert result['tags']['resource'] == []
        
        # Verify S3 API call was made
        mock_s3_client.get_bucket_tagging.assert_called_once()


class TestFetchBucketTagsErrorHandling:
    """Test error handling scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_no_such_tagset(self, mock_get_client):
        """Test handling of NoSuchTagSet error (bucket has no tags)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock NoSuchTagSet error
        error_response = {'Error': {'Code': 'NoSuchTagSet', 'Message': 'The TagSet does not exist'}}
        mock_s3_client.get_bucket_tagging.side_effect = botocore.exceptions.ClientError(
            error_response, 'GetBucketTagging'
        )
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should return empty tag array for NoSuchTagSet
        assert result['tags']['resource'] == []
        
        # Verify S3 API call was attempted
        mock_s3_client.get_bucket_tagging.assert_called_once()

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_no_such_bucket(self, mock_get_client):
        """Test handling of NoSuchBucket error (bucket doesn't exist)"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock NoSuchBucket error
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'The specified bucket does not exist'}}
        mock_s3_client.get_bucket_tagging.side_effect = botocore.exceptions.ClientError(
            error_response, 'GetBucketTagging'
        )
        
        # Prepare test data with non-existent bucket
        asff_data = prepare_s3_test_data(get_s32_nonexistent_bucket_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should return empty tag array for NoSuchBucket
        assert result['tags']['resource'] == []
        
        # Verify S3 API call was attempted
        mock_s3_client.get_bucket_tagging.assert_called_once()

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_access_denied_reraises(self, mock_get_client):
        """Test that AccessDenied errors are re-raised for upstream handling"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock AccessDenied error
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}}
        access_denied_error = botocore.exceptions.ClientError(error_response, 'GetBucketTagging')
        mock_s3_client.get_bucket_tagging.side_effect = access_denied_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Should re-raise AccessDenied error
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same error that was raised
        assert exc_info.value == access_denied_error
        assert exc_info.value.response['Error']['Code'] == 'AccessDenied'

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_other_client_error_reraises(self, mock_get_client):
        """Test that other ClientErrors are re-raised for upstream handling"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock unexpected client error
        error_response = {'Error': {'Code': 'InternalError', 'Message': 'Internal Server Error'}}
        internal_error = botocore.exceptions.ClientError(error_response, 'GetBucketTagging')
        mock_s3_client.get_bucket_tagging.side_effect = internal_error
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Should re-raise the unexpected error
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same error that was raised
        assert exc_info.value == internal_error
        assert exc_info.value.response['Error']['Code'] == 'InternalError'


class TestFetchBucketTagsEdgeCases:
    """Test edge cases and malformed input scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_malformed_arn(self, mock_get_client):
        """Test handling of malformed bucket ARN"""
        # Setup mock S3 client (should not be called due to ARN parsing failure)
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Prepare test data with malformed ARN
        asff_data = prepare_s3_test_data(get_s32_malformed_arn_finding)
        
        # Should raise exception due to malformed ARN
        with pytest.raises(IndexError):
            lambda_handler(asff_data, None)
        
        # Client should not be called due to ARN parsing failure
        mock_get_client.assert_not_called()
        mock_s3_client.get_bucket_tagging.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_large_tagset(self, mock_get_client):
        """Test handling of bucket with large number of tags"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock large tag set (S3 supports up to 50 tags)
        large_tagset = [{'Key': f'tag-{i}', 'Value': f'value-{i}'} for i in range(50)]
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': large_tagset}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should handle large tag set correctly
        assert result['tags']['resource'] == large_tagset
        assert len(result['tags']['resource']) == 50

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_fetch_tags_special_characters(self, mock_get_client):
        """Test handling of tags with special characters and encoding"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock tags with special characters
        special_tags = [
            {'Key': 'unicode-tag', 'Value': 'value-with-émoji-🚀'},
            {'Key': 'spaces and/symbols!', 'Value': 'value@#$%^&*()'},
            {'Key': 'xml-chars', 'Value': '<tag>&value</tag>'}
        ]
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': special_tags}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should preserve special characters correctly
        assert result['tags']['resource'] == special_tags
        assert result['tags']['resource'][0]['Value'] == 'value-with-émoji-🚀'


class TestFetchBucketTagsDataIntegration:
    """Test data structure integration and downstream compatibility"""

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_data_structure_preservation(self, mock_get_client):
        """Test that original data structure is preserved and tags are added correctly"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock tag response
        mock_tags = [{'Key': 'test-tag', 'Value': 'test-value'}]
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': mock_tags}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        original_finding = asff_data['finding'].copy()
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify original data structure is preserved
        assert result['finding'] == original_finding
        assert result['account'] == asff_data['account']
        assert result['actions'] == asff_data['actions']
        assert result['messages'] == asff_data['messages']
        
        # Verify tags were added correctly
        assert result['tags']['resource'] == mock_tags
        assert 'resource' in result['tags']

    @mock_aws
    @patch('functions.auto_remediations.fetch_bucket_tags.app.get_client')
    def test_s32_s33_integration_compatibility(self, mock_get_client):
        """Test compatibility with S3.2 and S3.3 auto-remediation functions"""
        # Setup mock S3 client
        mock_s3_client = MagicMock()
        mock_get_client.return_value = mock_s3_client
        
        # Mock exemption tag (used by S3.2 and S3.3)
        exemption_tags = [{'Key': 'allow-public-access', 'Value': 'true'}]
        mock_s3_client.get_bucket_tagging.return_value = {'TagSet': exemption_tags}
        
        # Prepare test data
        asff_data = prepare_s3_test_data(get_s32_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify tag structure is compatible with S3.2/S3.3 has_tag() function
        tags = result['tags']['resource']
        assert isinstance(tags, list)
        assert all(isinstance(tag, dict) for tag in tags)
        assert all('Key' in tag and 'Value' in tag for tag in tags)
        
        # Verify exemption tag can be found (simulating S3.2/S3.3 logic)
        exemption_found = any(tag['Key'] == 'allow-public-access' for tag in tags)
        assert exemption_found is True