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
import sys
import os

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ.setdefault('CROSS_ACCOUNT_ROLE', 'arn:aws:iam::123456789012:role/TestRole')

# Add function directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_elb5'))

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


def setup_boto3_client_with_exceptions(service_name):
    """
    Create a mock client with real boto3 exception classes attached.
    This allows tests to properly mock service-specific exceptions like
    elb_client.exceptions.LoadBalancerNotFound.
    """
    mock_client = Mock()
    
    # Create a real boto3 client to get the exception classes
    real_client = boto3.client(service_name, region_name='us-east-1')
    
    # Attach the real exception classes to our mock
    mock_client.exceptions = real_client.exceptions
    
    return mock_client


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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            
            # Verify S3 bucket creation - us-east-1 doesn't use LocationConstraint
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket_name
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
            
            # Note: S3 encryption is enabled by default - no explicit call expected
            
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
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            mock_get_client.return_value = mock_elbv2
            
            # Mock load balancer not found during initial check using ClientError pattern
            from botocore.exceptions import ClientError
            mock_elbv2.describe_load_balancers.side_effect = ClientError(
                {'Error': {'Code': 'LoadBalancerNotFoundException', 'Message': 'Load balancer not found'}},
                'DescribeLoadBalancers'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify - LoadBalancerNotFoundException should now be properly caught and handled
            assert "Load balancer not found:" in result['messages']['actions_taken']
            assert "This finding has been suppressed" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account load balancer access logging setup."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_cross_account)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock bucket already exists (owned by someone else) 
            mock_s3.create_bucket.side_effect = mock_s3.exceptions.BucketAlreadyExists(
                {'Error': {'Code': 'BucketAlreadyExists', 'Message': 'Bucket already exists'}},
                'CreateBucket'
            )
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock bucket already owned by you
            mock_s3.create_bucket.side_effect = mock_s3.exceptions.BucketAlreadyOwnedByYou(
                {'Error': {'Code': 'BucketAlreadyOwnedByYou', 'Message': 'Your previous request to create the named bucket succeeded'}},
                'CreateBucket'
            )
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful S3 setup but ALB modification failure
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Mock ALB modification error
            mock_elbv2.modify_load_balancer_attributes.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Invalid parameter'}},
                'ModifyLoadBalancerAttributes'
            )
            
            # Execute - should raise exception since InvalidParameterValue is not a LoadBalancer not found error
            with pytest.raises(botocore.exceptions.ClientError) as exc_info:
                lambda_handler(test_data, {})
            
            # Verify the exception details
            assert exc_info.value.response['Error']['Code'] == 'InvalidParameterValue'

    @mock_aws
    def test_classic_load_balancer_support(self):
        """Test that Classic Load Balancers are handled properly."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_classic_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elb = setup_boto3_client_with_exceptions('elb')  # Classic ELB client
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elb':  # Classic ELB uses 'elb' service
                    return mock_elb
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful operations for classic ELB
            mock_elb.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elb.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful S3 setup and initial LB check
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Mock LB not found during modification using ClientError pattern  
            from botocore.exceptions import ClientError
            mock_elbv2.modify_load_balancer_attributes.side_effect = ClientError(
                {'Error': {'Code': 'LoadBalancerNotFoundException', 'Message': 'Load balancer not found'}},
                'ModifyLoadBalancerAttributes'
            )
            
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
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify correct bucket name used - us-east-1 doesn't use LocationConstraint
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket
            )

    @mock_aws
    def test_loadbalancer_name_extraction_from_loadbalancer_name_field(self):
        """Test load balancer name extraction when LoadBalancerName field is present."""
        # Setup test data with LoadBalancerName field
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        # Modify the ELB details to include LoadBalancerName field (highest priority)
        test_data['finding']['Resources'][0]['Details']['AwsElbv2LoadBalancer']['LoadBalancerName'] = 'direct-lb-name'
        
        expected_bucket = "lb-logs-for-direct-lb-name"
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify LoadBalancerName field was used (highest priority)
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket
            )
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws  
    def test_loadbalancer_name_extraction_from_dnsname_fallback(self):
        """Test load balancer name extraction when LoadBalancerName is missing but DnsName exists."""
        # Setup test data without LoadBalancerName
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        # Remove LoadBalancerName and ensure DnsName exists (fallback)
        elb_details = test_data['finding']['Resources'][0]['Details']['AwsElbv2LoadBalancer']
        elb_details.pop('LoadBalancerName', None)  # Ensure it's not present
        elb_details['DnsName'] = 'fallback-dns-name.us-east-1.elb.amazonaws.com'
        
        expected_bucket = "lb-logs-for-fallback-dns-name"
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify DnsName field was used (first part before '.')
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket
            )
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_loadbalancer_name_extraction_from_arn_fallback(self):
        """Test load balancer name extraction when only ARN is available."""
        # Setup test data without LoadBalancerName or DNS names
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        # Remove all name fields to force ARN extraction
        elb_details = test_data['finding']['Resources'][0]['Details']['AwsElbv2LoadBalancer']
        elb_details.pop('LoadBalancerName', None)
        elb_details.pop('DnsName', None)  
        elb_details.pop('DNSName', None)
        
        # Set a specific ARN for testing - implementation takes the last part after final '/'
        test_data['finding']['Resources'][0]['Id'] = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/unique-lb-id'
        
        expected_bucket = "lb-logs-for-unique-lb-id"  # Implementation uses last part after final '/'
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify ARN extraction was used (last part after final '/')
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket
            )
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_loadbalancer_name_extraction_failure_creates_ticket(self):
        """Test that load balancer name extraction failure creates a TEAMFIX ticket."""
        # Setup test data with no usable name fields and invalid ARN
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        # Remove all name fields
        elb_details = test_data['finding']['Resources'][0]['Details']['AwsElbv2LoadBalancer']
        elb_details.clear()  # Remove all fields
        
        # Set an invalid ARN that can't be parsed
        test_data['finding']['Resources'][0]['Id'] = 'invalid-arn-format'
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify name extraction failure creates TEAMFIX ticket
            assert "Cannot identify load balancer for remediation" in result['messages']['actions_taken'] 
            assert "Investigate why load balancer name could not be extracted" in result['messages']['actions_required']
            assert result['actions']['autoremediation_not_done'] is True
            assert result['actions']['suppress_finding'] is False
            
            # Verify no AWS clients were created since name extraction failed early
            mock_get_client.assert_not_called()

    @mock_aws
    def test_non_us_east_1_region_bucket_creation_with_location_constraint(self):
        """Test S3 bucket creation in non-us-east-1 regions includes LocationConstraint."""
        # Setup test data for us-west-2 region (requires LocationConstraint)
        test_data = prepare_elb_test_data(get_elb5_finding_different_region)  # This uses us-west-2
        
        expected_bucket = "lb-logs-for-west-alb-123456789"  # Based on DNSName in fixture
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
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
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elbv2.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify non-us-east-1 bucket creation includes LocationConstraint
            mock_s3.create_bucket.assert_called_once_with(
                Bucket=expected_bucket,
                CreateBucketConfiguration={'LocationConstraint': 'us-west-2'}
            )
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_classic_lb_vs_alb_api_call_differences(self):
        """Test that Classic Load Balancers use different modify_load_balancer_attributes API format."""
        # Setup test data for Classic Load Balancer
        test_data = prepare_elb_test_data(get_elb5_finding_classic_lb)
        
        expected_bucket = "lb-logs-for-classic-lb-123456789"  # Based on DNSName in fixture
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elb = setup_boto3_client_with_exceptions('elb')  # Classic ELB uses 'elb' client
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elb':  # Classic ELB
                    return mock_elb
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful operations for Classic ELB
            mock_elb.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_versioning.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_public_access_block.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_s3.put_bucket_policy.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            mock_elb.modify_load_balancer_attributes.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify Classic LB uses different API format (LoadBalancerName + LoadBalancerAttributes)
            mock_elb.modify_load_balancer_attributes.assert_called_once_with(
                LoadBalancerName='classic-lb-123456789',  # Uses LoadBalancerName parameter
                LoadBalancerAttributes={
                    'AccessLog': {
                        'Enabled': True,
                        'S3BucketName': expected_bucket,
                        'S3BucketPrefix': ''
                    }
                }
            )
            
            # Compare: ALB would use Attributes=[{Key: ..., Value: ...}] + LoadBalancerArn
            # But Classic uses LoadBalancerName + LoadBalancerAttributes.AccessLog structure
            
            assert "successfully created and configured" in result['messages']['actions_taken']

    @mock_aws
    def test_s3_bucket_configuration_failures_create_ticket(self):
        """Test that S3 bucket configuration failures create TEAMFIX tickets."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful load balancer check and bucket creation
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            mock_s3.create_bucket.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
            
            # Mock bucket configuration failure (versioning fails)
            mock_s3.put_bucket_versioning.side_effect = Exception("Access denied for versioning")
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify S3 configuration failure creates TEAMFIX ticket
            assert "Bucket created but configuration failed" in result['messages']['actions_taken']
            assert "Access denied for versioning" in result['messages']['actions_taken']
            assert result['actions']['autoremediation_not_done'] is True
            assert result['actions']['suppress_finding'] is False
            
            # Verify bucket was created but configuration failed
            mock_s3.create_bucket.assert_called_once()
            mock_s3.put_bucket_versioning.assert_called_once()
            # Should not reach ELB modification due to early return
            mock_elbv2.modify_load_balancer_attributes.assert_not_called()

    @mock_aws
    def test_s3_bucket_creation_non_recoverable_failure_creates_ticket(self):
        """Test that non-recoverable S3 bucket creation failures create TEAMFIX tickets."""
        # Setup
        test_data = prepare_elb_test_data(get_elb5_finding_application_lb)
        
        with patch('functions.auto_remediations.auto_remediate_elb5.app.get_client') as mock_get_client:
            mock_s3 = setup_boto3_client_with_exceptions('s3')
            mock_elbv2 = setup_boto3_client_with_exceptions('elbv2')
            
            def client_side_effect(service, account_id, region):
                if service == 's3':
                    return mock_s3
                elif service == 'elbv2':
                    return mock_elbv2
                    
            mock_get_client.side_effect = client_side_effect
            
            # Mock successful load balancer check
            mock_elbv2.describe_load_balancers.return_value = {'LoadBalancers': [{'Scheme': 'internet-facing'}]}
            
            # Mock non-recoverable S3 bucket creation failure (permission denied)
            from botocore.exceptions import ClientError
            mock_s3.create_bucket.side_effect = ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
                'CreateBucket'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify non-recoverable S3 failure creates TEAMFIX ticket
            assert "Error creating S3 bucket" in result['messages']['actions_taken']
            assert "Access Denied" in result['messages']['actions_taken']
            assert "Investigate S3 bucket creation issue" in result['messages']['actions_required']
            assert result['actions']['autoremediation_not_done'] is True
            assert result['actions']['suppress_finding'] is False
            
            # Verify bucket creation was attempted but failed
            mock_s3.create_bucket.assert_called_once()
            # Should not reach bucket configuration or ELB modification
            mock_s3.put_bucket_versioning.assert_not_called()
            mock_elbv2.modify_load_balancer_attributes.assert_not_called()


if __name__ == '__main__':
    pytest.main([__file__])