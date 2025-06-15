"""
Comprehensive tests for ELB.1 auto-remediation function.

Tests the ALB HTTP to HTTPS redirection functionality including:
- Internet-facing ALB configuration
- Internal ALB suppression  
- Cross-account operations
- SSL certificate validation
- Error handling scenarios
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.elb_findings import (
    get_elb1_finding_internet_facing,
    get_elb1_finding_internal, 
    get_elb1_finding_cross_account
)
from tests.fixtures.asff_data import prepare_elb_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_elb1.app import (
    lambda_handler,
    alb_exists,
    redirect_http_to_https
)


class TestAutoRemediateELB1:
    """Test suite for ELB.1 auto-remediation function."""

    @mock_aws
    def test_internet_facing_alb_successful_redirection(self):
        """Test successful HTTP to HTTPS redirection for internet-facing ALB."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_internet_facing)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        # Create ELBv2 client and mock ALB with listeners
        client = boto3.client('elbv2', region_name='us-east-1')
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB exists and is internet-facing
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            # Mock listeners with both HTTP and HTTPS
            mock_elbv2.describe_listeners.return_value = {
                'Listeners': [
                    {
                        'Port': 80,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb/1234567890abcdef/1234567890abcdef'
                    },
                    {
                        'Port': 443,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb/1234567890abcdef/1234567890abcdef'
                    }
                ]
            }
            
            mock_elbv2.modify_listener.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ALB was successfully configured to redirect HTTP to HTTPS."
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('elbv2', '123456789012', 'us-east-1')
            mock_elbv2.describe_load_balancers.assert_called_once_with(LoadBalancerArns=[alb_arn])
            mock_elbv2.describe_listeners.assert_called_once_with(LoadBalancerArn=alb_arn)
            
            # Verify redirect configuration
            modify_call = mock_elbv2.modify_listener.call_args
            redirect_action = modify_call[1]['DefaultActions'][0]
            assert redirect_action['Type'] == 'redirect'
            assert redirect_action['RedirectConfig']['Protocol'] == 'HTTPS'
            assert redirect_action['RedirectConfig']['Port'] == '443'
            assert redirect_action['RedirectConfig']['StatusCode'] == 'HTTP_301'

    @mock_aws
    def test_internal_alb_suppresses_finding(self):
        """Test that internal ALBs suppress the finding (no redirection needed)."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_internal)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB exists and is internal
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internal'
                }]
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "ALB is internal. This finding has been suppressed."
            assert result['actions']['suppress_finding'] is True
            
            # Verify no listener modification attempted
            mock_elbv2.describe_listeners.assert_not_called()
            mock_elbv2.modify_listener.assert_not_called()

    @mock_aws
    def test_missing_ssl_certificate_creates_ticket(self):
        """Test that missing SSL certificate (no HTTPS listener) creates ticket."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_internet_facing)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB exists and is internet-facing
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            # Mock listeners with only HTTP (no HTTPS/SSL)
            mock_elbv2.describe_listeners.return_value = {
                'Listeners': [
                    {
                        'Port': 80,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb/1234567890abcdef/1234567890abcdef'
                    }
                ]
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['actions']['autoremediation_not_done'] is True
            assert "no certificate was found" in result['messages']['actions_taken']
            assert "Please add a certificate" in result['messages']['actions_required']
            
            # Verify no listener modification attempted
            mock_elbv2.modify_listener.assert_not_called()

    @mock_aws
    def test_missing_http_listener_creates_ticket(self):
        """Test that missing HTTP listener creates ticket."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_internet_facing)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB exists and is internet-facing
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            # Mock listeners with only HTTPS (no HTTP)
            mock_elbv2.describe_listeners.return_value = {
                'Listeners': [
                    {
                        'Port': 443,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb/1234567890abcdef/1234567890abcdef'
                    }
                ]
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['actions']['autoremediation_not_done'] is True
            assert "The ALB could not be configured to redirect HTTP to HTTPS" in result['messages']['actions_taken']
            assert "Please add a certificate and update the ALB" in result['messages']['actions_required']

    @mock_aws
    def test_missing_alb_suppresses_finding(self):
        """Test that missing ALB suppresses the finding."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_internet_facing)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB does not exist
            mock_elbv2.describe_load_balancers.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'LoadBalancerNotFound', 'Message': 'Load balancer not found'}},
                'DescribeLoadBalancers'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "ALB not found. This finding has been suppressed."
            assert result['actions']['suppress_finding'] is True

    @mock_aws 
    def test_cross_account_operation(self):
        """Test cross-account ALB redirection."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_cross_account)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB exists and is internet-facing
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            # Mock listeners with both HTTP and HTTPS
            mock_elbv2.describe_listeners.return_value = {
                'Listeners': [
                    {
                        'Port': 80,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:555666777888:listener/app/cross-account/1234567890abcdef/1234567890abcdef'
                    },
                    {
                        'Port': 443,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:555666777888:listener/app/cross-account/1234567890abcdef/1234567890abcdef'
                    }
                ]
            }
            
            mock_elbv2.modify_listener.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "The ALB was successfully configured to redirect HTTP to HTTPS."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('elbv2', '555666777888', 'us-east-1')

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of various API errors during redirection."""
        # Setup
        test_data = prepare_elb_test_data(get_elb1_finding_internet_facing)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Mock ALB exists and is internet-facing
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            # Mock listeners configuration
            mock_elbv2.describe_listeners.return_value = {
                'Listeners': [
                    {
                        'Port': 80,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb/1234567890abcdef/1234567890abcdef'
                    },
                    {
                        'Port': 443,
                        'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-alb/1234567890abcdef/1234567890abcdef'
                    }
                ]
            }
            
            # Mock modify_listener failure
            mock_elbv2.modify_listener.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid parameter'}},
                'ModifyListener'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['actions']['autoremediation_not_done'] is True
            assert "The ALB could not be configured to redirect HTTP to HTTPS" in result['messages']['actions_taken']

    def test_alb_exists_helper_function(self):
        """Test the alb_exists helper function."""
        with patch('functions.auto_remediations.auto_remediate_elb1.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Test existing ALB
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            result = alb_exists(mock_elbv2, 'test-arn')
            assert result == 'internet-facing'
            
            # Test missing ALB
            mock_elbv2.describe_load_balancers.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'LoadBalancerNotFound', 'Message': 'Not found'}},
                'DescribeLoadBalancers'
            )
            
            result = alb_exists(mock_elbv2, 'test-arn')
            assert result is False

    def test_redirect_http_to_https_helper_function(self):
        """Test the redirect_http_to_https helper function."""
        mock_elbv2 = Mock()
        
        # Test successful redirection
        mock_elbv2.describe_listeners.return_value = {
            'Listeners': [
                {
                    'Port': 80,
                    'ListenerArn': 'http-listener-arn'
                },
                {
                    'Port': 443, 
                    'ListenerArn': 'https-listener-arn'
                }
            ]
        }
        mock_elbv2.modify_listener.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        
        result = redirect_http_to_https(mock_elbv2, 'test-alb-arn')
        assert result is True
        
        # Test missing HTTPS listener
        mock_elbv2.describe_listeners.return_value = {
            'Listeners': [
                {
                    'Port': 80,
                    'ListenerArn': 'http-listener-arn'
                }
            ]
        }
        
        result = redirect_http_to_https(mock_elbv2, 'test-alb-arn')
        assert result is False
        
        # Test missing HTTP listener  
        mock_elbv2.describe_listeners.return_value = {
            'Listeners': [
                {
                    'Port': 443,
                    'ListenerArn': 'https-listener-arn'
                }
            ]
        }
        
        result = redirect_http_to_https(mock_elbv2, 'test-alb-arn')
        assert result is False


if __name__ == '__main__':
    pytest.main([__file__])