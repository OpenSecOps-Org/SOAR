"""
Comprehensive tests for ECS.12 auto-remediation function.

Tests the ECS Container Insights functionality including:
- Standard cluster Container Insights enablement
- Cross-account operations
- Cluster ARN parsing and name extraction
- Error handling scenarios
- Missing cluster detection
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
from tests.fixtures.security_hub_findings.ecs_findings import (
    get_ecs12_finding_standard,
    get_ecs12_finding_cross_account,
    get_ecs12_finding_different_region,
    get_ecs12_finding_complex_name,
    get_ecs12_finding_with_hyphens
)
from tests.fixtures.asff_data import prepare_ecs_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_ecs12.app import lambda_handler


class TestAutoRemediateECS12:
    """Test suite for ECS.12 auto-remediation function."""

    @mock_aws
    def test_successful_container_insights_enablement(self):
        """Test successful Container Insights enablement for ECS cluster."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        cluster_arn = test_data['finding']['Resources'][0]['Id']
        expected_cluster_name = cluster_arn.split('/')[-1]  # "test-cluster"
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful Container Insights enablement
            mock_ecs.update_cluster.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                },
                'cluster': {
                    'clusterArn': cluster_arn,
                    'clusterName': expected_cluster_name,
                    'settings': [
                        {
                            'name': 'containerInsights',
                            'value': 'enabled'
                        }
                    ]
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS cluster has had Container Insights enabled."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('ecs', '123456789012', 'us-east-1')
            mock_ecs.update_cluster.assert_called_once_with(
                cluster=expected_cluster_name,
                settings=[
                    {
                        'name': 'containerInsights',
                        'value': 'enabled'
                    }
                ]
            )

    @mock_aws
    def test_missing_cluster_suppresses_finding(self):
        """Test that missing cluster suppresses the finding."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock cluster not found error
            mock_ecs.update_cluster.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'ClusterNotFoundException', 'Message': 'Cluster not found'}},
                'UpdateCluster'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The ECS cluster wasn't found" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account cluster Container Insights enablement."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_cross_account)
        cluster_arn = test_data['finding']['Resources'][0]['Id']
        expected_cluster_name = cluster_arn.split('/')[-1]  # "cross-account-cluster"
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_cluster.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200},
                'cluster': {
                    'clusterName': expected_cluster_name
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS cluster has had Container Insights enabled."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('ecs', '555666777888', 'us-east-1')
            mock_ecs.update_cluster.assert_called_once_with(
                cluster=expected_cluster_name,
                settings=[
                    {
                        'name': 'containerInsights',
                        'value': 'enabled'
                    }
                ]
            )

    @mock_aws
    def test_different_region_operation(self):
        """Test Container Insights enablement in different regions."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_different_region)
        cluster_arn = test_data['finding']['Resources'][0]['Id']
        expected_cluster_name = cluster_arn.split('/')[-1]  # "west-cluster"
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_cluster.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS cluster has had Container Insights enabled."
            
            # Verify different region client creation
            mock_get_client.assert_called_with('ecs', '123456789012', 'us-west-2')
            mock_ecs.update_cluster.assert_called_once_with(
                cluster=expected_cluster_name,
                settings=[
                    {
                        'name': 'containerInsights',
                        'value': 'enabled'
                    }
                ]
            )

    @mock_aws
    def test_cluster_arn_parsing_complex_name(self):
        """Test cluster ARN parsing for complex naming patterns."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_complex_name)
        cluster_arn = test_data['finding']['Resources'][0]['Id']
        expected_cluster_name = cluster_arn.split('/')[-1]  # "production-microservices-cluster-v2"
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_cluster.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS cluster has had Container Insights enabled."
            
            # Verify correct cluster name parsing
            mock_ecs.update_cluster.assert_called_once_with(
                cluster=expected_cluster_name,
                settings=[
                    {
                        'name': 'containerInsights',
                        'value': 'enabled'
                    }
                ]
            )
            assert expected_cluster_name == "production-microservices-cluster-v2"

    @mock_aws
    def test_cluster_arn_parsing_with_hyphens(self):
        """Test cluster ARN parsing for hyphenated cluster names."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_with_hyphens)
        cluster_arn = test_data['finding']['Resources'][0]['Id']
        expected_cluster_name = cluster_arn.split('/')[-1]  # "my-application-cluster"
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_cluster.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS cluster has had Container Insights enabled."
            
            # Verify correct cluster name parsing
            mock_ecs.update_cluster.assert_called_once_with(
                cluster=expected_cluster_name,
                settings=[
                    {
                        'name': 'containerInsights',
                        'value': 'enabled'
                    }
                ]
            )
            assert expected_cluster_name == "my-application-cluster"

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of API errors other than ClusterNotFoundException."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock API error other than ClusterNotFoundException
            mock_ecs.update_cluster.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'UpdateCluster'
            )
            
            # Execute and verify exception is re-raised
            with pytest.raises(botocore.exceptions.ClientError):
                lambda_handler(test_data, {})

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            mock_ecs.update_cluster.return_value = {
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
    def test_cluster_name_extraction_logic(self):
        """Test cluster name extraction from various ARN formats."""
        test_cases = [
            {
                'arn': 'arn:aws:ecs:us-east-1:123456789012:cluster/simple-cluster',
                'expected': 'simple-cluster'
            },
            {
                'arn': 'arn:aws:ecs:us-east-1:123456789012:cluster/production-cluster',
                'expected': 'production-cluster'
            },
            {
                'arn': 'arn:aws:ecs:us-west-2:555666777888:cluster/my-app-cluster',
                'expected': 'my-app-cluster'
            },
            {
                'arn': 'arn:aws:ecs:eu-west-1:999888777666:cluster/microservices-v2',
                'expected': 'microservices-v2'
            }
        ]
        
        for test_case in test_cases:
            cluster_name = test_case['arn'].split('/')[-1]
            assert cluster_name == test_case['expected'], f"Failed for ARN: {test_case['arn']}"

    @mock_aws
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful API response
            mock_ecs.update_cluster.return_value = {
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
            assert result['messages']['actions_taken'] == "The ECS cluster has had Container Insights enabled."
            assert result['messages']['actions_required'] == "None"

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        
        # Verify the test data has expected structure
        assert 'finding' in test_data
        assert 'Resources' in test_data['finding']
        assert len(test_data['finding']['Resources']) > 0
        assert 'Id' in test_data['finding']['Resources'][0]
        assert 'Region' in test_data['finding']['Resources'][0]
        assert 'AwsAccountId' in test_data['finding']
        
        # Verify the cluster ARN format
        cluster_arn = test_data['finding']['Resources'][0]['Id']
        assert cluster_arn.startswith('arn:aws:ecs:')
        assert ':cluster/' in cluster_arn

    @mock_aws
    def test_container_insights_setting_configuration(self):
        """Test that Container Insights is configured with correct settings."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs12_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs12.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            mock_ecs.update_cluster.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify the configuration parameters
            call_args = mock_ecs.update_cluster.call_args
            
            # Verify settings structure
            assert 'settings' in call_args[1]
            settings = call_args[1]['settings']
            assert len(settings) == 1
            
            setting = settings[0]
            assert setting['name'] == 'containerInsights'
            assert setting['value'] == 'enabled'


if __name__ == '__main__':
    pytest.main([__file__])