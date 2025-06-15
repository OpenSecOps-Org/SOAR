"""
Comprehensive tests for ECR.3 auto-remediation function.

Tests the ECR repository lifecycle policy functionality including:
- Standard repository lifecycle policy configuration
- Cross-account operations
- Repository ARN parsing and name extraction
- Lifecycle policy JSON structure validation
- Error handling scenarios
- Missing repository detection
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore
import json

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.ecr_findings import (
    get_ecr3_finding_standard,
    get_ecr3_finding_cross_account,
    get_ecr3_finding_with_slash_in_name,
    get_ecr3_finding_different_region
)
from tests.fixtures.asff_data import prepare_ecr_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_ecr3.app import (
    lambda_handler,
    LIFECYCLE_POLICY_TEXT
)


class TestAutoRemediateECR3:
    """Test suite for ECR.3 auto-remediation function."""

    @mock_aws
    def test_successful_lifecycle_policy_configuration(self):
        """Test successful repository lifecycle policy configuration."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_standard)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "test-repo"
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful lifecycle policy configuration
            mock_ecr.put_lifecycle_policy.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                },
                'registryId': '123456789012',
                'repositoryName': expected_repo_name,
                'lifecyclePolicyText': LIFECYCLE_POLICY_TEXT
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The lifecycle policy has been set to keep only the two latest ECR images."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('ecr', '123456789012', 'us-east-1')
            mock_ecr.put_lifecycle_policy.assert_called_once_with(
                repositoryName=expected_repo_name,
                lifecyclePolicyText=LIFECYCLE_POLICY_TEXT
            )

    @mock_aws
    def test_lifecycle_policy_structure_validation(self):
        """Test that the lifecycle policy has the correct structure."""
        # Parse the lifecycle policy JSON
        policy = json.loads(LIFECYCLE_POLICY_TEXT)
        
        # Verify policy structure
        assert 'rules' in policy
        assert len(policy['rules']) == 1
        
        rule = policy['rules'][0]
        assert rule['rulePriority'] == 1
        assert rule['description'] == "Keep only the two latest images."
        
        # Verify selection criteria
        selection = rule['selection']
        assert selection['tagStatus'] == 'any'
        assert selection['countType'] == 'imageCountMoreThan'
        assert selection['countNumber'] == 2
        
        # Verify action
        action = rule['action']
        assert action['type'] == 'expire'

    @mock_aws
    def test_missing_repository_suppresses_finding(self):
        """Test that missing repository suppresses the finding."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock repository not found error
            mock_ecr.put_lifecycle_policy.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'RepositoryNotFoundException', 'Message': 'Repository not found'}},
                'PutLifecyclePolicy'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The ECR repository wasn't found" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account repository lifecycle policy configuration."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_cross_account)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "cross-account-repo"
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_lifecycle_policy.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200},
                'registryId': '555666777888',
                'repositoryName': expected_repo_name
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The lifecycle policy has been set to keep only the two latest ECR images."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('ecr', '555666777888', 'us-east-1')
            mock_ecr.put_lifecycle_policy.assert_called_once_with(
                repositoryName=expected_repo_name,
                lifecyclePolicyText=LIFECYCLE_POLICY_TEXT
            )

    @mock_aws
    def test_repository_arn_parsing_with_slash(self):
        """Test repository ARN parsing for repositories with slashes in name."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_with_slash_in_name)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "namespace/my-service"
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_lifecycle_policy.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The lifecycle policy has been set to keep only the two latest ECR images."
            
            # Verify correct repository name parsing (should include namespace)
            mock_ecr.put_lifecycle_policy.assert_called_once_with(
                repositoryName=expected_repo_name,
                lifecyclePolicyText=LIFECYCLE_POLICY_TEXT
            )
            assert expected_repo_name == "namespace/my-service"

    @mock_aws
    def test_different_region_operation(self):
        """Test lifecycle policy configuration in different regions."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_different_region)
        repository_arn = test_data['finding']['Resources'][0]['Id']
        expected_repo_name = repository_arn.split('/', 1)[1]  # "west-service"
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful configuration
            mock_ecr.put_lifecycle_policy.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The lifecycle policy has been set to keep only the two latest ECR images."
            
            # Verify different region client creation
            mock_get_client.assert_called_with('ecr', '123456789012', 'us-west-2')
            mock_ecr.put_lifecycle_policy.assert_called_once_with(
                repositoryName=expected_repo_name,
                lifecyclePolicyText=LIFECYCLE_POLICY_TEXT
            )

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of API errors other than RepositoryNotFoundException."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock API error other than RepositoryNotFoundException
            mock_ecr.put_lifecycle_policy.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'PutLifecyclePolicy'
            )
            
            # Execute and verify exception is re-raised
            with pytest.raises(botocore.exceptions.ClientError):
                lambda_handler(test_data, {})

    @mock_aws
    def test_lifecycle_policy_text_format(self):
        """Test that the lifecycle policy text is valid JSON."""
        # Verify LIFECYCLE_POLICY_TEXT is valid JSON
        try:
            policy = json.loads(LIFECYCLE_POLICY_TEXT)
            assert isinstance(policy, dict)
        except json.JSONDecodeError:
            pytest.fail("LIFECYCLE_POLICY_TEXT is not valid JSON")
        
        # Verify the policy structure meets ECR requirements
        assert 'rules' in policy
        assert isinstance(policy['rules'], list)
        assert len(policy['rules']) > 0
        
        for rule in policy['rules']:
            # Each rule must have required fields
            assert 'rulePriority' in rule
            assert 'selection' in rule
            assert 'action' in rule
            assert isinstance(rule['rulePriority'], int)

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            mock_ecr.put_lifecycle_policy.return_value = {
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
                'arn': 'arn:aws:ecr:us-west-2:555666777888:repository/my-service',
                'expected': 'my-service'
            }
        ]
        
        for test_case in test_cases:
            repository_name = test_case['arn'].split('/', 1)[1]
            assert repository_name == test_case['expected'], f"Failed for ARN: {test_case['arn']}"

    @mock_aws
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecr3.app.get_client') as mock_get_client:
            mock_ecr = Mock()
            mock_get_client.return_value = mock_ecr
            
            # Mock successful API response
            mock_ecr.put_lifecycle_policy.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200,
                    'RequestId': 'test-request-id'
                },
                'registryId': '123456789012',
                'repositoryName': 'test-repo'
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
            assert result['messages']['actions_taken'] == "The lifecycle policy has been set to keep only the two latest ECR images."
            assert result['messages']['actions_required'] == "None"

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_ecr_test_data(get_ecr3_finding_standard)
        
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

    @mock_aws
    def test_lifecycle_policy_keeps_two_images(self):
        """Test that the lifecycle policy is configured to keep exactly 2 images."""
        # Parse the lifecycle policy
        policy = json.loads(LIFECYCLE_POLICY_TEXT)
        
        # Verify the rule configuration
        rule = policy['rules'][0]
        selection = rule['selection']
        
        # This rule should expire images when there are more than 2
        assert selection['countNumber'] == 2
        assert selection['countType'] == 'imageCountMoreThan'
        assert rule['action']['type'] == 'expire'
        
        # This means it keeps the 2 most recent images and expires older ones


if __name__ == '__main__':
    pytest.main([__file__])