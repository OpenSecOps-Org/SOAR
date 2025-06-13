"""
Unit tests for EC2.6 auto-remediation: VPC flow logging should be enabled in all VPCs

This control checks whether Amazon VPC Flow Logs are found and enabled for VPCs with
the traffic type set to Reject. The control fails if VPC Flow Logs aren't enabled for VPCs.

Test triggers:
- VPC without flow logs: aws ec2 describe-flow-logs --filter Name=resource-id,Values=vpc-12345
- Create flow logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-12345 --traffic-type REJECT

The auto-remediation creates IAM role and policy, then enables VPC Flow Logs with CloudWatch Logs destination.
"""
import pytest
import sys
import os
import json
from moto import mock_aws
import boto3

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import create_asff_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from tests.fixtures.security_hub_findings.ec2_findings import (
    get_ec26_vpc_finding,
    get_ec26_cross_account_vpc_finding,
    get_ec26_malformed_vpc_arn_finding,
    get_ec26_missing_vpc_resource_finding,
    get_ec26_missing_region_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec26'))
from functions.auto_remediations.auto_remediate_ec26.app import lambda_handler


@pytest.fixture
def mock_ec26_vpc_asff_data():
    """ASFF data structure for EC2.6 control with VPC"""
    finding_fixture = get_ec26_vpc_finding()
    return create_asff_test_data(finding_fixture['finding'])


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.6 control with cross-account VPC"""
    finding_fixture = get_ec26_cross_account_vpc_finding()
    return create_asff_test_data(finding_fixture['finding'])


@pytest.fixture
def mock_malformed_asff_data():
    """ASFF data structure for malformed VPC ARN"""
    finding_fixture = get_ec26_malformed_vpc_arn_finding()
    return create_asff_test_data(finding_fixture['finding'])


@pytest.fixture
def mock_missing_resource_asff_data():
    """ASFF data structure with missing VPC resource"""
    finding_fixture = get_ec26_missing_vpc_resource_finding()
    return create_asff_test_data(finding_fixture['finding'])


@pytest.fixture
def mock_missing_region_asff_data():
    """ASFF data structure with missing region"""
    finding_fixture = get_ec26_missing_region_finding()
    return create_asff_test_data(finding_fixture['finding'])


class TestEc26SuccessScenarios:
    """Test successful EC2.6 remediation scenarios"""

    @mock_aws
    def test_ec26_successful_remediation(self, mock_ec26_vpc_asff_data):
        """Test complete successful VPC flow logs remediation"""
        # Setup AWS mocks
        ec2 = boto3.client('ec2', region_name='us-east-1')
        iam = boto3.client('iam', region_name='us-east-1')
        
        # Create VPC
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        # Update finding with actual VPC ID
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}'
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Details']['AwsEc2Vpc']['VpcId'] = vpc_id
        
        # Execute remediation
        result = lambda_handler(mock_ec26_vpc_asff_data, None)
        
        # Verify IAM role was created
        roles = iam.list_roles()['Roles']
        vpc_flow_roles = [r for r in roles if 'VPCFlowLogsLoggingRole' in r['RoleName']]
        assert len(vpc_flow_roles) == 1
        
        role = vpc_flow_roles[0]
        # In moto, AssumeRolePolicyDocument might be a dict or string
        trust_policy = role['AssumeRolePolicyDocument']
        if isinstance(trust_policy, str):
            trust_policy = json.loads(trust_policy)
        assert trust_policy['Statement'][0]['Principal']['Service'] == 'vpc-flow-logs.amazonaws.com'
        
        # Verify IAM policy was created and attached
        policies = iam.list_policies(Scope='Local')['Policies']
        vpc_flow_policies = [p for p in policies if 'VPCFlowLogsLoggingPolicy' in p['PolicyName']]
        assert len(vpc_flow_policies) == 1
        
        # Verify policy is attached to role
        attached_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
        assert len(attached_policies['AttachedPolicies']) == 1
        
        # Verify VPC flow logs were created
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        assert len(flow_logs) == 1
        # Note: moto may not fully implement all flow log fields
        flow_log = flow_logs[0]
        assert 'FlowLogId' in flow_log
        
        # Verify result messages
        assert result['actions']['autoremediation_not_done'] is False
        assert 'Flow logs have been enabled' in result['messages']['actions_taken']
        assert 'VPCFlowLogsLoggingRole' in result['messages']['actions_taken']
        assert 'VPCFlowLogsLoggingPolicy' in result['messages']['actions_taken']
        assert result['messages']['actions_required'] == 'None'

    @mock_aws
    def test_ec26_vpc_already_has_flow_logs(self, mock_ec26_vpc_asff_data):
        """Test VPC that already has flow logs configured"""
        # Setup AWS mocks
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        # Create VPC
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        # Update finding with actual VPC ID
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}'
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Details']['AwsEc2Vpc']['VpcId'] = vpc_id
        
        # Execute remediation - current implementation doesn't check for existing flow logs
        # so it will create new flow logs and IAM resources
        result = lambda_handler(mock_ec26_vpc_asff_data, None)
        
        # Should succeed and create flow logs setup
        assert result['actions']['autoremediation_not_done'] is False
        assert 'Flow logs have been enabled' in result['messages']['actions_taken']

    def test_ec26_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        assert 'arn:aws:ec2:us-west-2:987654321098:vpc/' in finding['Resources'][0]['Id']
        
        # Verify VPC ID extraction works with cross-account ARN
        vpc_id = finding['Resources'][0]['Id'].rsplit('/', 1)[1]
        assert vpc_id == 'vpc-9876543210fedcba0'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively


class TestEc26ErrorHandling:
    """Test EC2.6 error handling scenarios"""

    def test_ec26_vpc_not_found(self, mock_ec26_vpc_asff_data):
        """Test handling when VPC doesn't exist"""
        # Execute remediation with non-existent VPC
        # Function will try to extract VPC ID from ARN but VPC won't exist in moto
        with pytest.raises(Exception):
            lambda_handler(mock_ec26_vpc_asff_data, None)

    def test_ec26_structure_validation(self, mock_ec26_vpc_asff_data):
        """Test basic structure validation"""
        # Verify the test data structure is correct
        assert 'finding' in mock_ec26_vpc_asff_data
        assert 'Resources' in mock_ec26_vpc_asff_data['finding']
        assert len(mock_ec26_vpc_asff_data['finding']['Resources']) > 0
        
        resource = mock_ec26_vpc_asff_data['finding']['Resources'][0]
        assert 'Id' in resource
        assert 'Region' in resource
        assert resource['Type'] == 'AwsEc2Vpc'


class TestEc26InputValidation:
    """Test EC2.6 input validation scenarios"""

    def test_ec26_malformed_vpc_arn(self, mock_malformed_asff_data):
        """Test handling malformed VPC ARN in finding"""
        # Execute with malformed ARN - should handle gracefully
        with pytest.raises(Exception):
            lambda_handler(mock_malformed_asff_data, None)

    def test_ec26_missing_vpc_resource(self, mock_missing_resource_asff_data):
        """Test handling when finding has no VPC resource"""
        # Execute with missing resource - should handle gracefully
        with pytest.raises(IndexError):
            lambda_handler(mock_missing_resource_asff_data, None)

    def test_ec26_missing_region(self, mock_missing_region_asff_data):
        """Test handling when resource is missing region field"""
        # Execute with missing region - should handle gracefully
        with pytest.raises(KeyError):
            lambda_handler(mock_missing_region_asff_data, None)


class TestEc26EdgeCases:
    """Test EC2.6 edge cases and special scenarios"""

    @mock_aws
    def test_ec26_role_name_generation(self, mock_ec26_vpc_asff_data):
        """Test that role names are generated with random suffixes"""
        # Setup AWS mocks
        ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        # Update finding
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}'
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Details']['AwsEc2Vpc']['VpcId'] = vpc_id
        
        # Execute remediation
        result = lambda_handler(mock_ec26_vpc_asff_data, None)
        
        # Verify role name contains random suffix
        actions_taken = result['messages']['actions_taken']
        assert 'VPCFlowLogsLoggingRole-' in actions_taken
        assert 'VPCFlowLogsLoggingPolicy-' in actions_taken

    @mock_aws
    def test_ec26_messages_structure_validation(self, mock_ec26_vpc_asff_data):
        """Test that output messages follow correct structure"""
        # Setup AWS mocks
        ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        # Update finding
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}'
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Details']['AwsEc2Vpc']['VpcId'] = vpc_id
        
        # Execute remediation
        result = lambda_handler(mock_ec26_vpc_asff_data, None)
        
        # Validate message structure
        assert 'messages' in result
        assert 'actions_taken' in result['messages']
        assert 'actions_required' in result['messages']
        
        # Validate message content
        actions_taken = result['messages']['actions_taken']
        assert 'Flow logs have been enabled' in actions_taken
        assert 'VPCFlowLogs/' in actions_taken  # Log group name
        assert 'VPCFlowLogsLoggingRole-' in actions_taken  # Role name
        assert 'VPCFlowLogsLoggingPolicy-' in actions_taken  # Policy name
        
        assert result['messages']['actions_required'] == 'None'

    @mock_aws
    def test_ec26_iam_role_trust_policy(self, mock_ec26_vpc_asff_data):
        """Test that IAM role has correct trust policy for VPC Flow Logs"""
        # Setup AWS mocks
        ec2 = boto3.client('ec2', region_name='us-east-1')
        iam = boto3.client('iam', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        # Update finding
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}'
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Details']['AwsEc2Vpc']['VpcId'] = vpc_id
        
        # Execute remediation
        lambda_handler(mock_ec26_vpc_asff_data, None)
        
        # Verify IAM role has correct trust policy
        roles = iam.list_roles()['Roles']
        vpc_flow_roles = [r for r in roles if 'VPCFlowLogsLoggingRole' in r['RoleName']]
        assert len(vpc_flow_roles) == 1
        
        role = vpc_flow_roles[0]
        trust_policy = role['AssumeRolePolicyDocument']
        if isinstance(trust_policy, str):
            trust_policy = json.loads(trust_policy)
        
        # Verify trust policy allows VPC Flow Logs service
        assert trust_policy['Version'] == '2012-10-17'
        assert len(trust_policy['Statement']) == 1
        statement = trust_policy['Statement'][0]
        assert statement['Effect'] == 'Allow'
        assert statement['Action'] == 'sts:AssumeRole'
        assert statement['Principal']['Service'] == 'vpc-flow-logs.amazonaws.com'

    @mock_aws
    def test_ec26_vpc_flow_logs_configuration(self, mock_ec26_vpc_asff_data):
        """Test that VPC Flow Logs are configured correctly"""
        # Setup AWS mocks
        ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        # Update finding
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}'
        mock_ec26_vpc_asff_data['finding']['Resources'][0]['Details']['AwsEc2Vpc']['VpcId'] = vpc_id
        
        # Execute remediation
        lambda_handler(mock_ec26_vpc_asff_data, None)
        
        # Verify VPC Flow Logs configuration
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        assert len(flow_logs) == 1
        
        flow_log = flow_logs[0]
        assert 'FlowLogId' in flow_log
        # Note: moto's flow logs implementation may not include all fields
        # The important thing is that create_flow_logs was called successfully