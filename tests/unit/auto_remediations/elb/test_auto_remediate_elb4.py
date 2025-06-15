"""
Comprehensive tests for ELB.4 auto-remediation function.

Tests the ALB invalid HTTP header dropping functionality including:
- Standard ALB configuration
- Cross-account operations  
- Error handling scenarios
- Missing ALB detection
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.elb_findings import (
    get_elb4_finding_standard,
    get_elb4_finding_cross_account,
    get_elb4_finding_internal
)
from tests.fixtures.asff_data import prepare_elb_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_elb4.app import (
    lambda_handler,
    configure_alb_drop_invalid_headers
)


class TestAutoRemediateELB4:
    """Test suite for ELB.4 auto-remediation function."""

    @mock_aws
    def test_successful_drop_headers_configuration(self):
        """Test successful configuration of ALB to drop invalid headers."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_standard)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock successful modify_load_balancer_attributes call
            mock_elbv2.modify_load_balancer_attributes.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ALB was successfully configured to drop illegal HTTP headers."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('elbv2', '123456789012', 'us-east-1')
            mock_elbv2.modify_load_balancer_attributes.assert_called_once_with(
                LoadBalancerArn=alb_arn,
                Attributes=[
                    {
                        'Key': 'routing.http.drop_invalid_header_fields.enabled',
                        'Value': 'true'
                    }
                ]
            )

    @mock_aws
    def test_missing_alb_suppresses_finding(self):
        """Test that missing ALB suppresses the finding."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_standard)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB not found error
            mock_elbv2.modify_load_balancer_attributes.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'AccessPointNotFoundException', 'Message': 'Load balancer not found'}},
                'ModifyLoadBalancerAttributes'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "ALB not found. This finding has been suppressed."
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account ALB header dropping configuration."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_cross_account)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock successful configuration
            mock_elbv2.modify_load_balancer_attributes.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ALB was successfully configured to drop illegal HTTP headers."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('elbv2', '555666777888', 'us-east-1')

    @mock_aws
    def test_internal_alb_configuration(self):
        """Test that internal ALBs are also configured (both schemes need this setting)."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_internal)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock successful configuration
            mock_elbv2.modify_load_balancer_attributes.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify internal ALBs are also configured (unlike ELB.1)
            assert result['messages']['actions_taken'] == "The ALB was successfully configured to drop illegal HTTP headers."
            assert result['messages']['actions_required'] == "None"

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of API errors during configuration."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_standard)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock API error other than AccessPointNotFoundException
            mock_elbv2.modify_load_balancer_attributes.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid parameter'}},
                'ModifyLoadBalancerAttributes'
            )
            
            # Execute and verify exception is re-raised
            with pytest.raises(botocore.exceptions.ClientError):
                lambda_handler(test_data, {})

    @mock_aws
    def test_unsuccessful_configuration_creates_ticket(self):
        """Test that non-200 response creates ticket."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_standard)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock unsuccessful response (non-200)
            mock_elbv2.modify_load_balancer_attributes.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 400
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['actions']['autoremediation_not_done'] is True
            assert "The ALB could not be configured to drop illegal HTTP headers" in result['messages']['actions_taken']
            assert "Please update the ALB to drop illegal HTTP headers" in result['messages']['actions_required']

    def test_configure_alb_drop_invalid_headers_helper_function(self):
        """Test the configure_alb_drop_invalid_headers helper function directly."""
        mock_elbv2 = Mock()
        
        # Test successful configuration
        mock_elbv2.modify_load_balancer_attributes.return_value = {
            'ResponseMetadata': {
                'HTTPStatusCode': 200
            }
        }
        
        result = configure_alb_drop_invalid_headers(mock_elbv2, 'test-alb-arn')
        assert result is True
        
        # Verify proper attribute configuration
        mock_elbv2.modify_load_balancer_attributes.assert_called_once_with(
            LoadBalancerArn='test-alb-arn',
            Attributes=[
                {
                    'Key': 'routing.http.drop_invalid_header_fields.enabled',
                    'Value': 'true'
                }
            ]
        )
        
        # Test ALB not found
        mock_elbv2.modify_load_balancer_attributes.side_effect = botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessPointNotFoundException', 'Message': 'Not found'}},
            'ModifyLoadBalancerAttributes'
        )
        
        result = configure_alb_drop_invalid_headers(mock_elbv2, 'test-alb-arn')
        assert result == "NotFound"
        
        # Test other errors are re-raised
        mock_elbv2.modify_load_balancer_attributes.side_effect = botocore.exceptions.ClientError(
            {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid parameter'}},
            'ModifyLoadBalancerAttributes'
        )
        
        with pytest.raises(botocore.exceptions.ClientError):
            configure_alb_drop_invalid_headers(mock_elbv2, 'test-alb-arn')

    @mock_aws 
    def test_unsuccessful_http_status_code(self):
        """Test handling of unsuccessful HTTP status codes."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock non-200 HTTP response
            mock_elbv2.modify_load_balancer_attributes.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 500
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify ticket creation
            assert result['actions']['autoremediation_not_done'] is True
            assert "None. The ALB could not be configured" in result['messages']['actions_taken']

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_elb_test_data(get_elb4_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_elb4.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            mock_elbv2.modify_load_balancer_attributes.return_value = {
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


if __name__ == '__main__':
    pytest.main([__file__])