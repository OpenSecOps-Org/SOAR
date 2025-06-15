"""
Comprehensive tests for ELB.5 auto-remediation function.

Tests the ALB/CLB access logging functionality including:
- S3 bucket creation and configuration
- Access logging enablement
- Cross-account operations
- Error handling scenarios
- Regional ELB service account mapping
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore
import json

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.elb_findings import (
    get_elb5_finding_application_lb,
    get_elb5_finding_classic_lb,
    get_elb5_finding_cross_account,
    get_elb5_finding_different_region
)
from tests.fixtures.asff_data import prepare_elb_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_elb5.app import (
    lambda_handler,
    ELB_ACCOUNTS
)


class TestAutoRemediateELB5:
    """Test suite for ELB.5 auto-remediation function."""

    @mock_aws
    def test_successful_alb_access_logging_setup(self):
        """Test successful S3 bucket creation and ALB access logging enablement."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        alb_arn = test_data['finding']['Resources'][0]['Id']
        expected_bucket_name = "lb-logs-for-test-alb-123456789"
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                
            mock_get_client.side_effect = client_side_effect
            
            # Mock ALB exists
            mock_elbv2.describe_load_balancers.return_value = {
                'LoadBalancers': [{
                    'Scheme': 'internet-facing'
                }]
            }
            
            # Mock S3 operations success
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Mock ELB access logging configuration success
            mock_elbv2.modify_load_balancer_attributes.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify success message
            assert f"The bucket {expected_bucket_name} was successfully created and configured" in result['messages']['actions_taken']
            assert result['messages']['actions_required'] == "None"
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify S3 bucket creation with correct region constraint
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': 'us-east-1'
                }
            )
            
            # Verify bucket versioning enabled
            mock_s3.put_bucket_versioning.assert_called_once_with(
                Bucket=expected_bucket_name,
                VersioningConfiguration={
                    'MFADelete': 'Disabled',
                    'Status': 'Enabled'
                }
            )
            
            # Verify public access block
            mock_s3.put_public_access_block.assert_called_once_with(
                Bucket=expected_bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            # Verify encryption enabled
            mock_s3.put_bucket_encryption.assert_called_once_with(
                Bucket=expected_bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                }
            )
            
            # Verify bucket policy with correct ELB service account
            expected_elb_account = ELB_ACCOUNTS['us-east-1']  # 127311923021
            bucket_policy_call = mock_s3.put_bucket_policy.call_args
            policy_doc = json.loads(bucket_policy_call[1]['Policy'])
            
            assert policy_doc['Statement'][0]['Principal']['AWS'] == f"arn:aws:iam::{expected_elb_account}:root"
            assert policy_doc['Statement'][0]['Action'] == "s3:PutObject"
            assert policy_doc['Statement'][0]['Resource'] == f"arn:aws:s3:::{expected_bucket_name}/AWSLogs/123456789012/*"
            
            assert policy_doc['Statement'][1]['Principal']['Service'] == "logdelivery.elb.amazonaws.com"
            assert policy_doc['Statement'][1]['Action'] == "s3:GetBucketAcl"
            
            # Verify ALB access logging enabled
            mock_elbv2.modify_load_balancer_attributes.assert_called_once_with(
                Attributes=[
                    {'Key': 'access_logs.s3.enabled', 'Value': 'true'},
                    {'Key': 'access_logs.s3.bucket', 'Value': expected_bucket_name},
                    {'Key': 'access_logs.s3.prefix', 'Value': ''}
                ],
                LoadBalancerArn=alb_arn
            )

    @mock_aws
    def test_missing_load_balancer_suppresses_finding(self):
        """Test that missing load balancer suppresses the finding."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_elbv2 = Mock()
            mock_get_client.return_value = mock_elbv2
            
            # Create a proper exception class
            class LoadBalancerNotFoundException(Exception):
                pass
            
            mock_elbv2.exceptions.LoadBalancerNotFoundException = LoadBalancerNotFoundException
            
            # Mock load balancer not found during initial check
            mock_elbv2.describe_load_balancers.side_effect = LoadBalancerNotFoundException("Load balancer not found")
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "Load balancer not found" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account load balancer access logging setup."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_cross_account)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful operations
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify cross-account client creation
            calls = mock_get_client.call_args_list
            s3_call = calls[0]
            elbv2_call = calls[1]
            
            assert s3_call[0] == ('s3', '555666777888', 'us-east-1')
            assert elbv2_call[0] == ('elbv2', '555666777888', 'us-east-1')
            
            # Verify success
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_different_region_elb_account_mapping(self):
        """Test correct ELB service account mapping for different regions."""
        # Setup for us-west-2 region
        test_data = prepare_elb_test_data(get_elb5_finding_different_region)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful operations
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify correct ELB service account for us-west-2
            expected_elb_account = ELB_ACCOUNTS['us-west-2']  # 797873946194
            bucket_policy_call = mock_s3.put_bucket_policy.call_args
            policy_doc = json.loads(bucket_policy_call[1]['Policy'])
            
            assert expected_elb_account == '797873946194'
            assert policy_doc['Statement'][0]['Principal']['AWS'] == f"arn:aws:iam::{expected_elb_account}:root"

    @mock_aws
    def test_existing_bucket_handling(self):
        """Test handling of existing S3 buckets (both cases)."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock bucket already exists (owned by someone else)
            mock_s3.create_bucket.side_effect = mock_s3.exceptions.BucketAlreadyExists()
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify continues with configuration despite existing bucket
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_bucket_owned_by_you_handling(self):
        """Test handling when bucket is already owned by you."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock bucket already owned by you
            mock_s3.create_bucket.side_effect = mock_s3.exceptions.BucketAlreadyOwnedByYou()
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify continues with configuration
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_load_balancer_modification_error_suppresses_finding(self):
        """Test that errors during load balancer modification suppress the finding."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Create proper exception class for LoadBalancerNotFoundException
            class LoadBalancerNotFoundException(Exception):
                pass
            
            mock_elbv2.exceptions.LoadBalancerNotFoundException = LoadBalancerNotFoundException
            
            # Mock successful S3 setup but ALB modification failure
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Mock ALB modification error
            mock_elbv2.modify_load_balancer_attributes.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid parameter'}},
                'ModifyLoadBalancerAttributes'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "Error modifying load balancer attributes" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_classic_load_balancer_support(self):
        """Test that Classic Load Balancers are handled properly."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_classic_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful operations
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify Classic LB is processed (uses same ELBv2 API)
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_load_balancer_not_found_during_modification(self):
        """Test handling when load balancer is not found during modification."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Create a proper exception class
            class LoadBalancerNotFoundException(Exception):
                pass
            
            mock_elbv2.exceptions.LoadBalancerNotFoundException = LoadBalancerNotFoundException
            
            # Mock successful S3 setup and initial LB check
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Mock LB not found during modification
            mock_elbv2.modify_load_balancer_attributes.side_effect = LoadBalancerNotFoundException("Load balancer not found")
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "Load balancer not found during modification" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_bucket_name_generation(self):
        """Test correct bucket name generation from ALB DNS name."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        # The DNS name in the test fixture is 'test-alb-123456789.us-east-1.elb.amazonaws.com'
        # Expected bucket name should be 'lb-logs-for-test-alb-123456789' (first 50 chars of DNS prefix)
        expected_bucket = "lb-logs-for-test-alb-123456789"
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = Mock()
            mock_elbv2 = Mock()
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful operations
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_encryption.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify correct bucket name used
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket,
                CreateBucketConfiguration={'LocationConstraint': 'us-east-1'}
            )


if __name__ == '__main__':
    pytest.main([__file__])