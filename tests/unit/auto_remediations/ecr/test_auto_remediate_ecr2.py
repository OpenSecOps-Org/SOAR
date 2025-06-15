"""
Comprehensive tests for ECR.2 auto-remediation function.

Tests the ECR repository tag immutability functionality including:
- Standard repository tag immutability configuration
- Cross-account operations
- Repository ARN parsing and name extraction
- Error handling scenarios
- Missing repository detection
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.ecr_findings import (
    get_ecr2_finding_standard,
    get_ecr2_finding_cross_account,
    get_ecr2_finding_with_slash_in_name,
    get_ecr2_finding_complex_name
)
from tests.fixtures.asff_data import prepare_ecr_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_ecr2.app import lambda_handler


class TestAutoRemediateECR2:
    """Test suite for ECR.2 auto-remediation function."""

    @mock_aws
    def test_successful_tag_immutability_configuration(self):
        """Test successful repository tag immutability configuration."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_standard)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "test-repo"
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful tag immutability configuration
            mock_ecr.put_image_tag_mutability.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Image tags have been set immutable."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('ecr', '123456789012', 'us-east-1')
            mock_ecr.put_image_tag_mutability.assert_called_once_with(
                repositoryName=expected_repo_name,
                imageTagMutability='IMMUTABLE'
            )

    @mock_aws
    def test_missing_repository_suppresses_finding(self):
        """Test that missing repository suppresses the finding."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock repository not found error
            mock_ecr.put_image_tag_mutability.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'RepositoryNotFoundException', 'Message': 'Repository not found'}},
                'PutImageTagMutability'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The ECR repository wasn't found" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account repository tag immutability configuration."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_cross_account)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "cross-account-repo"
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_image_tag_mutability.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Image tags have been set immutable."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('ecr', '555666777888', 'us-east-1')
            mock_ecr.put_image_tag_mutability.assert_called_once_with(
                repositoryName=expected_repo_name,
                imageTagMutability='IMMUTABLE'
            )

    @mock_aws
    def test_repository_arn_parsing_with_slash(self):
        """Test repository ARN parsing for repositories with slashes in name."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_with_slash_in_name)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "namespace/my-app"
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_image_tag_mutability.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Image tags have been set immutable."
            
            # Verify correct repository name parsing (should include namespace)
            mock_ecr.put_image_tag_mutability.assert_called_once_with(
                repositoryName=expected_repo_name,
                imageTagMutability='IMMUTABLE'
            )
            assert expected_repo_name == "namespace/my-app"

    @mock_aws
    def test_repository_arn_parsing_complex_name(self):
        """Test repository ARN parsing for complex naming patterns."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_complex_name)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "org/team/service-name"
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_image_tag_mutability.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Image tags have been set immutable."
            
            # Verify correct repository name parsing (should include full path)
            mock_ecr.put_image_tag_mutability.assert_called_once_with(
                repositoryName=expected_repo_name,
                imageTagMutability='IMMUTABLE'
            )
            assert expected_repo_name == "org/team/service-name"

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of API errors other than RepositoryNotFoundException."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock API error other than RepositoryNotFoundException
            mock_ecr.put_image_tag_mutability.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'PutImageTagMutability'
            )
            
            # Execute and verify exception is re-raised
            with pytest.raises(botocore.exceptions.ClientError):
                lambda_handler(test_data, {})

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            mock_ecr.put_image_tag_mutability.return_value = {
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
    def test_repository_name_extraction_logic(self):
        """Test repository name extraction from various ARN formats."""
        test_cases = [
            {
                'arn': 'arn:aws:ecr:us-east-1:123456789012:repository/simple-repo',
                'expected': 'simple-repo'
            },
            {
                'arn': 'arn:aws:ecr:us-east-1:123456789012:repository/namespace/repo',
                'expected': 'namespace/repo'
            },
            {
                'arn': 'arn:aws:ecr:us-east-1:123456789012:repository/org/team/service',
                'expected': 'org/team/service'
            },
            {
                'arn': 'arn:aws:ecr:us-west-2:555666777888:repository/my-app',
                'expected': 'my-app'
            }
        ]
        
        for test_case in test_cases:
            repository_name = test_case['arn'].split('/', 1)[1]
            assert repository_name == test_case['expected'], f"Failed for ARN: {test_case['arn']}"

    @mock_aws
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr2.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful API response
            mock_ecr.put_image_tag_mutability.return_value = {
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
            assert result['messages']['actions_taken'] == "Image tags have been set immutable."
            assert result['messages']['actions_required'] == "None"

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr2_finding_standard)
        
        # Verify the test data has expected structure
        assert 'finding' in test_data
        assert 'Resources' in test_data['finding']
        assert len(test_data['finding']['Resources']) > 0
        assert 'Id' in test_data['finding']['Resources'][0]
        assert 'Region' in test_data['finding']['Resources'][0]
        assert 'AwsAccountId' in test_data['finding']
        
        # Verify the repository ARN format
        repository_arn = test_data['finding']['Resources'][0]['Id']
        assert repository_arn.startswith('arn:aws:ecr:')
        assert ':repository/' in repository_arn


if __name__ == '__main__':
    pytest.main([__file__])