"""
Comprehensive tests for ECS.2 auto-remediation function.

Tests the ECS service public IP assignment functionality including:
- Standard service public IP disabling
- Cross-account operations
- Service and cluster ARN parsing
- Complex network configuration handling
- Detailed ASFF structure requirements
- Error handling scenarios for missing resources and configurations
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
    get_ecs2_finding_standard,
    get_ecs2_finding_cross_account,
    get_ecs2_finding_different_region,
    get_ecs2_finding_complex_names,
    get_ecs2_finding_with_hyphens,
    get_ecs2_finding_missing_details
)
from tests.fixtures.asff_data import prepare_ecs_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_ecs2.app import lambda_handler


class TestAutoRemediateECS2:
    """Test suite for ECS.2 auto-remediation function."""

    @mock_aws
    def test_successful_public_ip_disabling(self):
        """Test successful public IP assignment disabling for ECS service."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        service_arn = test_data['finding']['Resources'][0]['Id']
        expected_service_name = service_arn.split('/')[-1]  # "test-service"
        expected_cluster_name = "test-cluster"  # From Details.AwsEcsService.Cluster
        
        # Get expected network configuration from finding details
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        vpc_config = details['NetworkConfiguration']['AwsVpcConfiguration']
        expected_subnets = vpc_config['Subnets']
        expected_security_groups = vpc_config['SecurityGroups']
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful service update
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                },
                'service': {
                    'serviceArn': service_arn,
                    'serviceName': expected_service_name,
                    'networkConfiguration': {
                        'awsvpcConfiguration': {
                            'subnets': expected_subnets,
                            'securityGroups': expected_security_groups,
                            'assignPublicIp': 'DISABLED'
                        }
                    }
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS service has had assignPublicIp set to DISABLED."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('ecs', '123456789012', 'us-east-1')
            mock_ecs.update_service.assert_called_once_with(
                cluster=expected_cluster_name,
                service=expected_service_name,
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': expected_subnets,
                        'securityGroups': expected_security_groups,
                        'assignPublicIp': 'DISABLED'
                    }
                }
            )

    @mock_aws
    def test_missing_details_suppresses_finding(self):
        """Test that missing Details section suppresses the finding."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_missing_details)
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "No Details provided in the event" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True
            
            # Verify that update_service was NOT called
            mock_ecs.update_service.assert_not_called()

    @mock_aws
    def test_cluster_not_found_suppresses_finding(self):
        """Test that ClusterNotFoundException suppresses the finding."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock cluster not found error
            mock_ecs.update_service.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'ClusterNotFoundException', 'Message': 'Cluster not found'}},
                'UpdateService'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The ECS cluster wasn't found" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_service_not_found_suppresses_finding(self):
        """Test that ServiceNotFoundException suppresses the finding."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock service not found error
            mock_ecs.update_service.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'ServiceNotFoundException', 'Message': 'Service not found'}},
                'UpdateService'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The ECS service wasn't found" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_service_not_active_suppresses_finding(self):
        """Test that ServiceNotActiveException suppresses the finding."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock service not active error
            mock_ecs.update_service.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'ServiceNotActiveException', 'Message': 'Service not active'}},
                'UpdateService'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The ECS service wasn't active" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account service public IP disabling."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_cross_account)
        service_arn = test_data['finding']['Resources'][0]['Id']
        expected_service_name = service_arn.split('/')[-1]  # "cross-service"
        expected_cluster_name = "cross-cluster"
        
        # Get expected network configuration from finding details
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        vpc_config = details['NetworkConfiguration']['AwsVpcConfiguration']
        expected_subnets = vpc_config['Subnets']
        expected_security_groups = vpc_config['SecurityGroups']
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS service has had assignPublicIp set to DISABLED."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('ecs', '555666777888', 'us-east-1')
            mock_ecs.update_service.assert_called_once_with(
                cluster=expected_cluster_name,
                service=expected_service_name,
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': expected_subnets,
                        'securityGroups': expected_security_groups,
                        'assignPublicIp': 'DISABLED'
                    }
                }
            )

    @mock_aws
    def test_different_region_operation(self):
        """Test public IP disabling in different regions."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_different_region)
        service_arn = test_data['finding']['Resources'][0]['Id']
        expected_service_name = service_arn.split('/')[-1]  # "west-service"
        expected_cluster_name = "west-cluster"
        
        # Get expected network configuration from finding details
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        vpc_config = details['NetworkConfiguration']['AwsVpcConfiguration']
        expected_subnets = vpc_config['Subnets']
        expected_security_groups = vpc_config['SecurityGroups']
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS service has had assignPublicIp set to DISABLED."
            
            # Verify different region client creation
            mock_get_client.assert_called_with('ecs', '123456789012', 'us-west-2')
            mock_ecs.update_service.assert_called_once_with(
                cluster=expected_cluster_name,
                service=expected_service_name,
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': expected_subnets,
                        'securityGroups': expected_security_groups,
                        'assignPublicIp': 'DISABLED'
                    }
                }
            )

    @mock_aws
    def test_complex_service_names(self):
        """Test service ARN parsing for complex naming patterns."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_complex_names)
        service_arn = test_data['finding']['Resources'][0]['Id']
        expected_service_name = service_arn.split('/')[-1]  # "web-application-service"
        expected_cluster_name = "production-cluster"
        
        # Get expected network configuration from finding details
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        vpc_config = details['NetworkConfiguration']['AwsVpcConfiguration']
        expected_subnets = vpc_config['Subnets']
        expected_security_groups = vpc_config['SecurityGroups']
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS service has had assignPublicIp set to DISABLED."
            
            # Verify correct service name parsing
            mock_ecs.update_service.assert_called_once_with(
                cluster=expected_cluster_name,
                service=expected_service_name,
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': expected_subnets,
                        'securityGroups': expected_security_groups,
                        'assignPublicIp': 'DISABLED'
                    }
                }
            )
            assert expected_service_name == "web-application-service"

    @mock_aws
    def test_hyphenated_service_names(self):
        """Test service ARN parsing for hyphenated names."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_with_hyphens)
        service_arn = test_data['finding']['Resources'][0]['Id']
        expected_service_name = service_arn.split('/')[-1]  # "my-web-service"
        expected_cluster_name = "my-cluster"
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful configuration
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ECS service has had assignPublicIp set to DISABLED."
            assert expected_service_name == "my-web-service"

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of API errors other than the specific exceptions."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock API error other than the specific handled exceptions
            mock_ecs.update_service.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'UpdateService'
            )
            
            # Execute and verify exception is re-raised
            with pytest.raises(botocore.exceptions.ClientError):
                lambda_handler(test_data, {})

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            mock_ecs.update_service.return_value = {
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
    def test_network_configuration_preservation(self):
        """Test that existing network configuration is preserved except for assignPublicIp."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        # Get original network configuration from finding details
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        vpc_config = details['NetworkConfiguration']['AwsVpcConfiguration']
        original_subnets = vpc_config['Subnets']
        original_security_groups = vpc_config['SecurityGroups']
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify network configuration preservation
            call_args = mock_ecs.update_service.call_args[1]
            network_config = call_args['networkConfiguration']['awsvpcConfiguration']
            
            # Verify original subnets and security groups are preserved
            assert network_config['subnets'] == original_subnets
            assert network_config['securityGroups'] == original_security_groups
            
            # Verify only assignPublicIp is changed to DISABLED
            assert network_config['assignPublicIp'] == 'DISABLED'

    @mock_aws
    def test_service_name_extraction_logic(self):
        """Test service name extraction from various ARN formats."""
        test_cases = [
            {
                'arn': 'arn:aws:ecs:us-east-1:123456789012:service/simple-cluster/simple-service',
                'expected_service': 'simple-service',
                'expected_cluster': 'simple-cluster'
            },
            {
                'arn': 'arn:aws:ecs:us-west-2:555666777888:service/production-cluster/web-app-service',
                'expected_service': 'web-app-service', 
                'expected_cluster': 'production-cluster'
            },
            {
                'arn': 'arn:aws:ecs:eu-west-1:999888777666:service/my-cluster/microservice-v2',
                'expected_service': 'microservice-v2',
                'expected_cluster': 'my-cluster'
            }
        ]
        
        for test_case in test_cases:
            # Test service name extraction (last part after final slash)
            service_name = test_case['arn'].split('/')[-1]
            assert service_name == test_case['expected_service'], f"Service name failed for ARN: {test_case['arn']}"
            
            # Test cluster name extraction (second to last part)
            cluster_name = test_case['arn'].split('/')[-2]
            assert cluster_name == test_case['expected_cluster'], f"Cluster name failed for ARN: {test_case['arn']}"

    @mock_aws
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            # Mock successful API response
            mock_ecs.update_service.return_value = {
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
            assert result['messages']['actions_taken'] == "The ECS service has had assignPublicIp set to DISABLED."
            assert result['messages']['actions_required'] == "None"

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        # Verify the test data has expected structure
        assert 'finding' in test_data
        assert 'Resources' in test_data['finding']
        assert len(test_data['finding']['Resources']) > 0
        assert 'Id' in test_data['finding']['Resources'][0]
        assert 'Region' in test_data['finding']['Resources'][0]
        assert 'Details' in test_data['finding']['Resources'][0]
        assert 'AwsAccountId' in test_data['finding']
        
        # Verify the service ARN format
        service_arn = test_data['finding']['Resources'][0]['Id']
        assert service_arn.startswith('arn:aws:ecs:')
        assert ':service/' in service_arn
        
        # Verify the detailed network configuration structure
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        assert 'NetworkConfiguration' in details
        assert 'AwsVpcConfiguration' in details['NetworkConfiguration']
        vpc_config = details['NetworkConfiguration']['AwsVpcConfiguration']
        assert 'Subnets' in vpc_config
        assert 'SecurityGroups' in vpc_config
        assert 'AssignPublicIp' in vpc_config

    @mock_aws
    def test_cluster_name_extraction_from_details(self):
        """Test cluster name extraction from Details.AwsEcsService.Cluster."""
        # Setup
        test_data = prepare_ecs_test_data(get_ecs2_finding_standard)
        
        # Get cluster from Details section (this is how the function does it)
        details = test_data['finding']['Resources'][0]['Details']['AwsEcsService']
        cluster_arn = details['Cluster']
        expected_cluster_name = cluster_arn.split('/')[-1]  # "test-cluster"
        
        with patch('functions.auto_remediations.auto_remediate_ecs2.app.get_client') as mock_get_client:
            mock_ecs = Mock()
            mock_get_client.return_value = mock_ecs
            
            mock_ecs.update_service.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            lambda_handler(test_data, {})
            
            # Verify cluster name is extracted correctly from Details section
            call_args = mock_ecs.update_service.call_args[1]
            assert call_args['cluster'] == expected_cluster_name
            assert expected_cluster_name == "test-cluster"


if __name__ == '__main__':
    pytest.main([__file__])