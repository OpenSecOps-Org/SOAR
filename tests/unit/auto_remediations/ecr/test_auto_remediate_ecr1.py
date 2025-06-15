"""
Comprehensive tests for ECR.1 auto-remediation function.

Tests the ECR registry scanning configuration functionality including:
- Registry-wide enhanced scanning configuration
- Cross-account operations
- Different region operations
- Scan-on-push configuration with wildcard filters
- Error handling scenarios
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.ecr_findings import (
    get_ecr1_finding_standard,
    get_ecr1_finding_cross_account,
    get_ecr1_finding_different_region
)
from tests.fixtures.asff_data import prepare_ecr_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_ecr1.app import lambda_handler


class TestAutoRemediateECR1:
    """Test suite for ECR.1 auto-remediation function."""

    @mock_aws
    def test_successful_registry_scanning_configuration(self):
        """Test successful registry-wide scanning configuration."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful registry scanning configuration
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                },
                'registryScanningConfiguration': {
                    'scanType': 'ENHANCED',
                    'rules': [
                        {
                            'scanFrequency': 'SCAN_ON_PUSH',
                            'repositoryFilters': [
                                {
                                    'filter': '*',
                                    'filterType': 'WILDCARD'
                                }
                            ]
                        }
                    ]
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Images are now scanned on push using enhanced scanning."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('ecr', '123456789012', 'us-east-1')
            mock_ecr.put_registry_scanning_configuration.assert_called_once_with(
                scanType='ENHANCED',
                rules=[
                    {
                        'scanFrequency': 'SCAN_ON_PUSH',
                        'repositoryFilters': [
                            {
                                'filter': '*',
                                'filterType': 'WILDCARD'
                            }
                        ]
                    }
                ]
            )

    @mock_aws
    def test_registry_scanning_configuration_parameters(self):
        """Test that registry scanning configuration uses correct parameters."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify the configuration parameters
            call_args = mock_ecr.put_registry_scanning_configuration.call_args
            
            # Verify scan type is ENHANCED
            assert call_args[1]['scanType'] == 'ENHANCED'
            
            # Verify rules structure
            rules = call_args[1]['rules']
            assert len(rules) == 1
            
            rule = rules[0]
            assert rule['scanFrequency'] == 'SCAN_ON_PUSH'
            assert len(rule['repositoryFilters']) == 1
            
            repository_filter = rule['repositoryFilters'][0]
            assert repository_filter['filter'] == '*'
            assert repository_filter['filterType'] == 'WILDCARD'

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account registry scanning configuration."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_cross_account)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Images are now scanned on push using enhanced scanning."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('ecr', '555666777888', 'us-east-1')
            mock_ecr.put_registry_scanning_configuration.assert_called_once()

    @mock_aws
    def test_different_region_operation(self):
        """Test registry scanning configuration in different regions."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_different_region)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Images are now scanned on push using enhanced scanning."
            
            # Verify different region client creation
            mock_get_client.assert_called_with('ecr', '123456789012', 'us-west-2')
            mock_ecr.put_registry_scanning_configuration.assert_called_once()

    @mock_aws
    def test_api_error_handling_creates_ticket(self):
        """Test that API errors create tickets for manual intervention."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock API error
            mock_ecr.put_registry_scanning_configuration.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'PutRegistryScanningConfiguration'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify ticket creation
            assert result['messages']['actions_taken'] == "Could not configure registry scanning."
            assert result['actions']['autoremediation_not_done'] is True

    @mock_aws
    def test_access_denied_error_handling(self):
        """Test handling of access denied errors."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock access denied error
            mock_ecr.put_registry_scanning_configuration.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'Access denied'}},
                'PutRegistryScanningConfiguration'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify ticket creation
            assert result['messages']['actions_taken'] == "Could not configure registry scanning."
            assert result['actions']['autoremediation_not_done'] is True

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            mock_ecr.put_registry_scanning_configuration.return_value = {
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
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful API response
            mock_ecr.put_registry_scanning_configuration.return_value = {
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
            assert 'actions_required' in result['messages']
            assert 'actions' in result
            assert 'finding' in result
            
            # Verify specific message content
            assert result['messages']['actions_taken'] == "Images are now scanned on push using enhanced scanning."
            assert result['messages']['actions_required'] == "None"

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        # Verify the test data has expected structure
        assert 'finding' in test_data
        assert 'Resources' in test_data['finding']
        assert len(test_data['finding']['Resources']) > 0
        assert 'Region' in test_data['finding']['Resources'][0]
        assert 'AwsAccountId' in test_data['finding']

    @mock_aws
    def test_registry_level_operation_scope(self):
        """Test that this is a registry-level operation (not repository-specific)."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify that the function does NOT use repository-specific parameters
            call_args = mock_ecr.put_registry_scanning_configuration.call_args
            
            # Registry-level operation should not have repositoryName parameter
            assert 'repositoryName' not in call_args[1]
            
            # Should have registry-wide configuration
            assert 'scanType' in call_args[1]
            assert 'rules' in call_args[1]

    @mock_aws
    def test_enhanced_scanning_vs_basic(self):
        """Test that the function configures ENHANCED scanning (not BASIC)."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify ENHANCED scanning is configured
            call_args = mock_ecr.put_registry_scanning_configuration.call_args
            assert call_args[1]['scanType'] == 'ENHANCED'
            
            # Enhanced scanning provides more comprehensive vulnerability detection
            # including OS packages and language-specific packages

    @mock_aws
    def test_wildcard_filter_covers_all_repositories(self):
        """Test that the wildcard filter applies to all repositories."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr1_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr1.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            mock_ecr.put_registry_scanning_configuration.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify wildcard filter configuration
            call_args = mock_ecr.put_registry_scanning_configuration.call_args
            rules = call_args[1]['rules']
            
            repository_filter = rules[0]['repositoryFilters'][0]
            assert repository_filter['filter'] == '*'
            assert repository_filter['filterType'] == 'WILDCARD'
            
            # This configuration means ALL repositories in the registry will have scanning enabled


if __name__ == '__main__':
    pytest.main([__file__])