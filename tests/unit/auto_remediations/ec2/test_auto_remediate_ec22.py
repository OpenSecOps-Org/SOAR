"""
Unit tests for EC2.2 auto-remediation: VPC default security group should not allow inbound and outbound traffic

This control checks that the default security group of a VPC does not allow inbound or outbound traffic.
AWS default security groups come with an inbound rule that allows all traffic from the security group itself,
and an outbound rule that allows all traffic to all destinations (0.0.0.0/0).

Test triggers:
- Default security group with default rules: aws ec2 describe-security-groups --group-names default
- Check instances using default SG: aws ec2 describe-instances --filters "Name=instance.group-name,Values=default"

The auto-remediation removes default rules from unused default security groups.
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from moto import mock_aws
import boto3
import botocore.exceptions

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_ec2_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from tests.fixtures.security_hub_findings.ec2_22_findings import (
    get_ec22_default_sg_pristine_finding,
    get_ec22_default_sg_in_use_finding,
    get_ec22_default_sg_modified_finding,
    get_ec22_default_sg_no_rules_finding,
    get_ec22_default_sg_missing_details_finding,
    get_ec22_default_sg_cross_account_finding,
    get_ec22_default_sg_egress_modified_finding,
    get_ec22_default_sg_partial_failure_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler and internal functions
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec22'))
from functions.auto_remediations.auto_remediate_ec22.app import (
    lambda_handler, security_group_in_use, ingress_modified, egress_modified, 
    revoke_ingress, revoke_egress, get_details
)


class TestInternalFunctions:
    """Test internal functions in isolation"""

    class TestSecurityGroupInUse:
        """Test the security_group_in_use() function"""

        @mock_aws
        def test_security_group_not_in_use(self):
            """Test security group not attached to any instances"""
            ec2_client = boto3.client('ec2', region_name='us-east-1')
            
            # Create VPC and security group but no instances
            vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
            sg = ec2_client.create_security_group(
                GroupName='test-sg',
                Description='Test security group',
                VpcId=vpc['Vpc']['VpcId']
            )
            
            result = security_group_in_use(ec2_client, sg['GroupId'])
            assert result is False

        @mock_aws
        def test_security_group_in_use_by_instance(self):
            """Test security group attached to an instance"""
            ec2_client = boto3.client('ec2', region_name='us-east-1')
            
            # Create VPC, subnet, and security group
            vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
            subnet = ec2_client.create_subnet(VpcId=vpc['Vpc']['VpcId'], CidrBlock='10.0.1.0/24')
            sg = ec2_client.create_security_group(
                GroupName='test-sg',
                Description='Test security group',
                VpcId=vpc['Vpc']['VpcId']
            )
            
            # Launch instance with the security group
            ec2_client.run_instances(
                ImageId='ami-12345678',
                MinCount=1,
                MaxCount=1,
                SecurityGroupIds=[sg['GroupId']],
                SubnetId=subnet['Subnet']['SubnetId']
            )
            
            result = security_group_in_use(ec2_client, sg['GroupId'])
            assert result is True

        @mock_aws 
        def test_security_group_in_use_multiple_instances(self):
            """Test security group attached to multiple instances"""
            ec2_client = boto3.client('ec2', region_name='us-east-1')
            
            # Create VPC, subnet, and security group
            vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
            subnet = ec2_client.create_subnet(VpcId=vpc['Vpc']['VpcId'], CidrBlock='10.0.1.0/24')
            sg = ec2_client.create_security_group(
                GroupName='test-sg',
                Description='Test security group',
                VpcId=vpc['Vpc']['VpcId']
            )
            
            # Launch multiple instances with the security group
            for i in range(3):
                ec2_client.run_instances(
                    ImageId='ami-12345678',
                    MinCount=1,
                    MaxCount=1,
                    SecurityGroupIds=[sg['GroupId']],
                    SubnetId=subnet['Subnet']['SubnetId']
                )
            
            result = security_group_in_use(ec2_client, sg['GroupId'])
            assert result is True

    class TestIngressModified:
        """Test the ingress_modified() function"""

        def test_ingress_pristine_default_rule(self):
            """Test pristine default ingress rule - self-referencing all traffic"""
            sg_id = 'sg-12345'
            owner_id = '123456789012'
            perms = [{
                'IpProtocol': '-1',
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'UserId': owner_id
                }]
            }]
            
            result = ingress_modified(perms, sg_id, owner_id)
            assert result is False

        def test_ingress_no_rules(self):
            """Test no ingress rules - should not be considered modified"""
            perms = []
            
            result = ingress_modified(perms, 'sg-12345', '123456789012')
            assert result is False

        def test_ingress_multiple_rules(self):
            """Test multiple ingress rules - should be considered modified"""
            sg_id = 'sg-12345'
            owner_id = '123456789012'
            perms = [
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{
                        'GroupId': sg_id,
                        'UserId': owner_id
                    }]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
            
            result = ingress_modified(perms, sg_id, owner_id)
            assert result is True

        def test_ingress_wrong_protocol(self):
            """Test wrong protocol - should be considered modified"""
            sg_id = 'sg-12345'
            owner_id = '123456789012'
            perms = [{
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'UserId': owner_id
                }]
            }]
            
            result = ingress_modified(perms, sg_id, owner_id)
            assert result is True

        def test_ingress_wrong_group_reference(self):
            """Test wrong group reference - should be considered modified"""
            sg_id = 'sg-12345'
            owner_id = '123456789012'
            perms = [{
                'IpProtocol': '-1',
                'UserIdGroupPairs': [{
                    'GroupId': 'sg-different',
                    'UserId': owner_id
                }]
            }]
            
            result = ingress_modified(perms, sg_id, owner_id)
            assert result is True

        def test_ingress_wrong_user_id(self):
            """Test wrong user ID - should be considered modified"""
            sg_id = 'sg-12345'
            owner_id = '123456789012'
            perms = [{
                'IpProtocol': '-1',
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'UserId': '987654321098'
                }]
            }]
            
            result = ingress_modified(perms, sg_id, owner_id)
            assert result is True

        def test_ingress_multiple_group_pairs(self):
            """Test multiple group pairs - should be considered modified"""
            sg_id = 'sg-12345'
            owner_id = '123456789012'
            perms = [{
                'IpProtocol': '-1',
                'UserIdGroupPairs': [
                    {
                        'GroupId': sg_id,
                        'UserId': owner_id
                    },
                    {
                        'GroupId': 'sg-other',
                        'UserId': owner_id
                    }
                ]
            }]
            
            result = ingress_modified(perms, sg_id, owner_id)
            assert result is True

    class TestEgressModified:
        """Test the egress_modified() function"""

        def test_egress_pristine_default_rule(self):
            """Test pristine default egress rule - all traffic to 0.0.0.0/0"""
            perms = [{
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
            
            result = egress_modified(perms)
            assert result is False

        def test_egress_no_rules(self):
            """Test no egress rules - should not be considered modified"""
            perms = []
            
            result = egress_modified(perms)
            assert result is False

        def test_egress_multiple_rules(self):
            """Test multiple egress rules - should be considered modified"""
            perms = [
                {
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
                }
            ]
            
            result = egress_modified(perms)
            assert result is True

        def test_egress_wrong_protocol(self):
            """Test wrong protocol - should be considered modified"""
            perms = [{
                'IpProtocol': 'tcp',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
            
            result = egress_modified(perms)
            assert result is True

        def test_egress_wrong_cidr(self):
            """Test wrong CIDR - should be considered modified"""
            perms = [{
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
            }]
            
            result = egress_modified(perms)
            assert result is True

        def test_egress_multiple_ip_ranges(self):
            """Test multiple IP ranges - should be considered modified"""
            perms = [{
                'IpProtocol': '-1',
                'IpRanges': [
                    {'CidrIp': '0.0.0.0/0'},
                    {'CidrIp': '10.0.0.0/8'}
                ]
            }]
            
            result = egress_modified(perms)
            assert result is True

        def test_egress_no_ip_ranges(self):
            """Test no IP ranges - should be considered modified"""
            perms = [{
                'IpProtocol': '-1'
            }]
            
            result = egress_modified(perms)
            assert result is True


@pytest.fixture
def mock_pristine_default_sg_asff_data():
    """ASFF data structure for EC2.2 control with pristine default security group"""
    return prepare_ec2_test_data(get_ec22_default_sg_pristine_finding)


@pytest.fixture
def mock_in_use_default_sg_asff_data():
    """ASFF data structure for EC2.2 control with default security group in use"""
    return prepare_ec2_test_data(get_ec22_default_sg_in_use_finding)


@pytest.fixture
def mock_modified_default_sg_asff_data():
    """ASFF data structure for EC2.2 control with modified default security group"""
    return prepare_ec2_test_data(get_ec22_default_sg_modified_finding)


@pytest.fixture
def mock_no_rules_default_sg_asff_data():
    """ASFF data structure for EC2.2 control with no rules"""
    return prepare_ec2_test_data(get_ec22_default_sg_no_rules_finding)


@pytest.fixture
def mock_missing_details_asff_data():
    """ASFF data structure for EC2.2 control with missing details"""
    return prepare_ec2_test_data(get_ec22_default_sg_missing_details_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.2 control with cross-account"""
    return prepare_ec2_test_data(get_ec22_default_sg_cross_account_finding)


@pytest.fixture
def mock_egress_modified_asff_data():
    """ASFF data structure for EC2.2 control with modified egress rules"""
    return prepare_ec2_test_data(get_ec22_default_sg_egress_modified_finding)


@pytest.fixture
def mock_partial_failure_asff_data():
    """ASFF data structure for EC2.2 control with partial failure scenario"""
    return prepare_ec2_test_data(get_ec22_default_sg_partial_failure_finding)


class TestEc22SuccessScenarios:
    """Test successful EC2.2 remediation scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_pristine_unused_default_sg_remediation(self, mock_get_client, mock_pristine_default_sg_asff_data):
        """Test successful remediation of pristine unused default security group"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC (automatically creates default security group)
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        
        # Get the default security group that was automatically created
        sgs = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['default']},
                {'Name': 'vpc-id', 'Values': [vpc['Vpc']['VpcId']]}
            ]
        )
        sg_id = sgs['SecurityGroups'][0]['GroupId']
        
        # Add default ingress rule (self-reference)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': '-1',
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'UserId': '123456789012'
                }]
            }]
        )
        
        # Note: Default egress rule (0.0.0.0/0) is automatically created
        
        # Update finding with actual SG ID and fix the UserIdGroupPairs reference
        mock_pristine_default_sg_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        mock_pristine_default_sg_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['OwnerId'] = '123456789012'
        mock_pristine_default_sg_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['IpPermissions'][0]['UserIdGroupPairs'][0]['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_pristine_default_sg_asff_data, None)
        
        # Verify remediation was successful
        assert result['actions']['autoremediation_not_done'] is False
        assert 'All ingress rules have been removed' in result['messages']['actions_taken']
        assert 'All egress rules have been removed' in result['messages']['actions_taken']
        assert result['messages']['actions_required'] == 'None.'
        
        # Verify rules were actually removed
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        assert len(sg_details['IpPermissions']) == 0
        assert len(sg_details['IpPermissionsEgress']) == 0

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_no_rules_already_clean(self, mock_get_client, mock_no_rules_default_sg_asff_data):
        """Test handling of default security group that already has no rules"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC (automatically creates default security group)
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        
        # Get the default security group that was automatically created
        sgs = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['default']},
                {'Name': 'vpc-id', 'Values': [vpc['Vpc']['VpcId']]}
            ]
        )
        sg_id = sgs['SecurityGroups'][0]['GroupId']
        
        # Remove default egress rule to simulate clean state
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        if sg_details['IpPermissionsEgress']:
            ec2_client.revoke_security_group_egress(
                GroupId=sg_id,
                IpPermissions=sg_details['IpPermissionsEgress']
            )
        
        # Update finding with actual SG ID
        mock_no_rules_default_sg_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_no_rules_default_sg_asff_data, None)
        
        # Verify no remediation was needed
        assert result['actions']['autoremediation_not_done'] is True
        assert 'The ingress and egress rules could not be revoked' in result['messages']['actions_taken']


class TestEc22PreventionScenarios:
    """Test scenarios where EC2.2 remediation should be prevented"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_default_sg_in_use_prevention(self, mock_get_client, mock_in_use_default_sg_asff_data):
        """Test prevention when default security group is in use by instances"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC and subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(VpcId=vpc['Vpc']['VpcId'], CidrBlock='10.0.1.0/24')
        
        # Get the default security group that was automatically created
        sgs = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['default']},
                {'Name': 'vpc-id', 'Values': [vpc['Vpc']['VpcId']]}
            ]
        )
        sg_id = sgs['SecurityGroups'][0]['GroupId']
        
        # Launch instance using the default security group
        ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[sg_id],
            SubnetId=subnet['Subnet']['SubnetId']
        )
        
        # Update finding with actual SG ID
        mock_in_use_default_sg_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_in_use_default_sg_asff_data, None)
        
        # Verify remediation was prevented due to usage
        assert result['actions']['autoremediation_not_done'] is True
        assert 'None, as the security group is in use' in result['messages']['actions_taken']
        assert 'Please update your infrastructure not to use the VPC default security group' in result['messages']['actions_required']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_modified_default_sg_prevention(self, mock_get_client, mock_modified_default_sg_asff_data):
        """Test prevention when default security group has been modified"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC (automatically creates default security group)
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        
        # Get the default security group that was automatically created
        sgs = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['default']},
                {'Name': 'vpc-id', 'Values': [vpc['Vpc']['VpcId']]}
            ]
        )
        sg_id = sgs['SecurityGroups'][0]['GroupId']
        
        # Add modified rules (additional HTTP rule)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{
                        'GroupId': sg_id,
                        'UserId': '123456789012'
                    }]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        
        # Update finding with actual SG ID
        mock_modified_default_sg_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_modified_default_sg_asff_data, None)
        
        # Verify remediation was prevented due to modification
        assert result['actions']['autoremediation_not_done'] is True
        assert 'None, as the security group no longer is in its pristine state' in result['messages']['actions_taken']
        assert 'Please update your infrastructure not to use the VPC default security group' in result['messages']['actions_required']


class TestEc22ErrorHandling:
    """Test EC2.2 error handling scenarios"""

    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_missing_security_group_details(self, mock_get_client, mock_missing_details_asff_data):
        """Test handling when security group details are missing from ASFF"""
        # Setup mock that simulates SG not found when get_details is called
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock describe_security_groups to raise InvalidGroup.NotFound
        error_response = {'Error': {'Code': 'InvalidGroup.NotFound'}}
        ec2_client.describe_security_groups.side_effect = botocore.exceptions.ClientError(
            error_response, 'DescribeSecurityGroups'
        )
        
        # Execute remediation with missing details
        result = lambda_handler(mock_missing_details_asff_data, None)
        
        # Verify finding is suppressed when details lookup fails
        assert result['actions']['suppress_finding'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_security_group_not_found(self, mock_get_client, mock_missing_details_asff_data):
        """Test handling when security group cannot be found"""
        # Setup mock that returns empty results
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock describe_security_groups to raise InvalidGroup.NotFound
        error_response = {'Error': {'Code': 'InvalidGroup.NotFound'}}
        ec2_client.describe_security_groups.side_effect = botocore.exceptions.ClientError(
            error_response, 'DescribeSecurityGroups'
        )
        
        # Execute remediation
        result = lambda_handler(mock_missing_details_asff_data, None)
        
        # Verify finding is suppressed when SG not found
        assert result['actions']['suppress_finding'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_revoke_permission_not_found(self, mock_get_client, mock_pristine_default_sg_asff_data):
        """Test handling InvalidPermission.NotFound during rule revocation"""
        # Setup mock that raises InvalidPermission.NotFound
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock revoke operations to raise InvalidPermission.NotFound
        error_response = {'Error': {'Code': 'InvalidPermission.NotFound'}}
        ec2_client.revoke_security_group_ingress.side_effect = botocore.exceptions.ClientError(
            error_response, 'RevokeSecurityGroupIngress'
        )
        ec2_client.revoke_security_group_egress.side_effect = botocore.exceptions.ClientError(
            error_response, 'RevokeSecurityGroupEgress'
        )
        
        # Execute remediation
        result = lambda_handler(mock_pristine_default_sg_asff_data, None)
        
        # Verify error is handled gracefully
        assert result['actions']['autoremediation_not_done'] is True


class TestEc22EdgeCases:
    """Test EC2.2 edge cases and special scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_partial_success_scenario(self, mock_get_client, mock_partial_failure_asff_data):
        """Test scenario where only ingress OR egress rules can be removed"""
        # Setup mock for partial success
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful ingress revoke but failed egress revoke
        ec2_client.revoke_security_group_ingress.return_value = {'Return': True}
        ec2_client.revoke_security_group_egress.return_value = {'Return': False}
        
        # Execute remediation
        result = lambda_handler(mock_partial_failure_asff_data, None)
        
        # Verify partial success is handled
        assert 'All ingress rules have been removed' in result['messages']['actions_taken']
        assert 'All egress rules have been removed' not in result['messages']['actions_taken']
        assert result['messages']['actions_required'] == 'None.'

    def test_ec22_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        
        # Verify security group ID extraction works with cross-account ARN
        sg_id = finding['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId']
        assert sg_id == 'sg-cross123456789'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec22.app.get_client')
    def test_ec22_egress_only_modification(self, mock_get_client, mock_egress_modified_asff_data):
        """Test handling when only egress rules have been modified"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC (automatically creates default security group)
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        
        # Get the default security group that was automatically created
        sgs = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['default']},
                {'Name': 'vpc-id', 'Values': [vpc['Vpc']['VpcId']]}
            ]
        )
        sg_id = sgs['SecurityGroups'][0]['GroupId']
        
        # Add pristine ingress rule but modified egress rules
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': '-1',
                'UserIdGroupPairs': [{
                    'GroupId': sg_id,
                    'UserId': '123456789012'
                }]
            }]
        )
        
        # Add additional egress rule (modifying the default state)
        ec2_client.authorize_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
            }]
        )
        
        # Update finding with actual SG ID
        mock_egress_modified_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_egress_modified_asff_data, None)
        
        # Verify remediation was prevented due to egress modification
        assert result['actions']['autoremediation_not_done'] is True
        assert 'None, as the security group no longer is in its pristine state' in result['messages']['actions_taken']