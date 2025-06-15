"""
Comprehensive tests for KMS.4 auto-remediation function.

Tests the KMS key rotation functionality including:
- Standard key rotation enablement
- Cross-account operations
- Key ARN parsing and ID extraction
- Sophisticated error handling scenarios
- Suppressible vs actionable error categorization
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore
import sys
import os

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.kms_findings import (
    get_kms4_finding_standard,
    get_kms4_finding_cross_account,
    get_kms4_finding_different_region,
    get_kms4_finding_different_key_format,
    get_kms4_finding_eu_region
)
from tests.fixtures.asff_data import prepare_kms_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_kms4.app import lambda_handler


class TestAutoRemediateKMS4:
    """Test suite for KMS.4 auto-remediation function."""

    @mock_aws
    def test_successful_key_rotation_enablement(self):
        """Test successful key rotation enablement for KMS key."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        key_arn = test_data['finding']['Resources'][0]['Id']
        expected_key_id = key_arn.rsplit('/', 1)[1]  # "12345678-1234-1234-1234-123456789012"
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock successful key rotation enablement
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Automatic yearly key rotation has been enabled."
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('kms', '123456789012', 'us-east-1')
            mock_kms.enable_key_rotation.assert_called_once_with(KeyId=expected_key_id)

    @mock_aws
    def test_access_denied_error_suppresses_finding(self):
        """Test that AccessDeniedException suppresses the finding."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock access denied error
            mock_kms.enable_key_rotation.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'Access denied'}},
                'EnableKeyRotation'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "Couldn't enable key rotation: AccessDeniedException" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_kms_invalid_state_error_suppresses_finding(self):
        """Test that KMSInvalidStateException suppresses the finding."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock invalid state error (key is disabled/deleted)
            mock_kms.enable_key_rotation.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'KMSInvalidStateException', 'Message': 'Key is in invalid state'}},
                'EnableKeyRotation'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "Couldn't enable key rotation: KMSInvalidStateException" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_not_found_error_suppresses_finding(self):
        """Test that NotFoundException suppresses the finding."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock key not found error
            mock_kms.enable_key_rotation.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'NotFoundException', 'Message': 'Key not found'}},
                'EnableKeyRotation'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "Couldn't enable key rotation: NotFoundException" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_actionable_error_creates_ticket(self):
        """Test that non-suppressible errors create tickets for manual intervention."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock API error that requires action
            mock_kms.enable_key_rotation.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'EnableKeyRotation'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify ticket creation
            assert "Failed to enable key rotation: InvalidParameterException" in result['messages']['actions_taken']
            assert result['actions']['autoremediation_not_done'] is True
            assert result['actions']['suppress_finding'] is False

    @mock_aws
    def test_unexpected_exception_suppresses_finding(self):
        """Test that unexpected exceptions suppress the finding."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock unexpected exception
            mock_kms.enable_key_rotation.side_effect = ValueError("Unexpected error")
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify suppression
            assert "Couldn't enable key rotation due to an unexpected error" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account key rotation enablement."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_cross_account)
        key_arn = test_data['finding']['Resources'][0]['Id']
        expected_key_id = key_arn.rsplit('/', 1)[1]  # "87654321-4321-4321-4321-210987654321"
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock successful configuration
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Automatic yearly key rotation has been enabled."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('kms', '555666777888', 'us-east-1')
            mock_kms.enable_key_rotation.assert_called_once_with(KeyId=expected_key_id)

    @mock_aws
    def test_different_region_operation(self):
        """Test key rotation enablement in different regions."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_different_region)
        key_arn = test_data['finding']['Resources'][0]['Id']
        expected_key_id = key_arn.rsplit('/', 1)[1]  # "abcdef12-3456-7890-abcd-ef1234567890"
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock successful configuration
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Automatic yearly key rotation has been enabled."
            
            # Verify different region client creation
            mock_get_client.assert_called_with('kms', '123456789012', 'us-west-2')
            mock_kms.enable_key_rotation.assert_called_once_with(KeyId=expected_key_id)

    @mock_aws
    def test_key_arn_parsing_different_formats(self):
        """Test key ARN parsing for different key ID formats."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_different_key_format)
        key_arn = test_data['finding']['Resources'][0]['Id']
        expected_key_id = key_arn.rsplit('/', 1)[1]  # "fedcba09-8765-4321-0fed-cba987654321"
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock successful configuration
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Automatic yearly key rotation has been enabled."
            
            # Verify correct key ID parsing
            mock_kms.enable_key_rotation.assert_called_once_with(KeyId=expected_key_id)
            assert expected_key_id == "fedcba09-8765-4321-0fed-cba987654321"

    @mock_aws
    def test_eu_region_operation(self):
        """Test key rotation enablement in EU regions."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_eu_region)
        key_arn = test_data['finding']['Resources'][0]['Id']
        expected_key_id = key_arn.rsplit('/', 1)[1]  # "11111111-2222-3333-4444-555555555555"
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock successful configuration
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Automatic yearly key rotation has been enabled."
            
            # Verify EU region client creation
            mock_get_client.assert_called_with('kms', '123456789012', 'eu-west-1')
            mock_kms.enable_key_rotation.assert_called_once_with(KeyId=expected_key_id)

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify original data sections are preserved
            assert result['account'] == original_account
            assert result['tags'] == original_tags
            assert result['db'] == original_db
            
            # Verify finding data is preserved
            assert result['finding'] == test_data['finding']

    @mock_aws
    def test_key_id_extraction_logic(self):
        """Test key ID extraction from various ARN formats."""
        test_cases = [
            {
                'arn': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                'expected': '12345678-1234-1234-1234-123456789012'
            },
            {
                'arn': 'arn:aws:kms:us-west-2:555666777888:key/abcdef12-3456-7890-abcd-ef1234567890',
                'expected': 'abcdef12-3456-7890-abcd-ef1234567890'
            },
            {
                'arn': 'arn:aws:kms:eu-west-1:999888777666:key/fedcba98-7654-3210-fedc-ba9876543210',
                'expected': 'fedcba98-7654-3210-fedc-ba9876543210'
            }
        ]
        
        for test_case in test_cases:
            key_id = test_case['arn'].rsplit('/', 1)[1]
            assert key_id == test_case['expected'], f"Failed for ARN: {test_case['arn']}"

    @mock_aws
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
            mock_kms = Mock()
            mock_get_client.return_value = mock_kms
            
            # Mock successful API response
            mock_kms.enable_key_rotation.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200,
                    'RequestId': 'test-request-id'
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify response structure
            assert 'messages' in result
            assert 'actions_taken' in result['messages']
            assert 'actions' in result
            assert 'finding' in result
            
            # Verify specific message content
            assert result['messages']['actions_taken'] == "Automatic yearly key rotation has been enabled."
            
            # Note: actions_required is not set in successful cases for this function

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        # Verify the test data has expected structure
        assert 'finding' in test_data
        assert 'Resources' in test_data['finding']
        assert len(test_data['finding']['Resources']) > 0
        assert 'Id' in test_data['finding']['Resources'][0]
        assert 'Region' in test_data['finding']['Resources'][0]
        assert 'AwsAccountId' in test_data['finding']
        
        # Verify the key ARN format
        key_arn = test_data['finding']['Resources'][0]['Id']
        assert key_arn.startswith('arn:aws:kms:')
        assert ':key/' in key_arn

    @mock_aws
    def test_error_categorization_comprehensive(self):
        """Test comprehensive error categorization (suppressible vs actionable)."""
        test_data = prepare_kms_test_data(get_kms4_finding_standard)
        
        # Test all suppressible error codes
        suppressible_errors = [
            'AccessDeniedException',
            'KMSInvalidStateException', 
            'NotFoundException'
        ]
        
        for error_code in suppressible_errors:
            with patch('functions.auto_remediations.auto_remediate_kms4.app.get_client') as mock_get_client:
                mock_kms = Mock()
                mock_get_client.return_value = mock_kms
                
                mock_kms.enable_key_rotation.side_effect = botocore.exceptions.ClientError(
                    {'Error': {'Code': error_code, 'Message': f'{error_code} message'}},
                    'EnableKeyRotation'
                )
                
                result = lambda_handler(test_data, {})
                
                # Verify suppression for all these error codes
                assert result['actions']['suppress_finding'] is True
                assert error_code in result['messages']['actions_taken']


if __name__ == '__main__':
    pytest.main([__file__])