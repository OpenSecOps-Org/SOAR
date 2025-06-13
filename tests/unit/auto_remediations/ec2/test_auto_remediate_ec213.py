"""
Unit tests for EC2.13 auto-remediation: Security groups should not allow ingress from 0.0.0.0/0 to port 22

This control checks whether security groups allow unrestricted incoming traffic on SSH port 22.
The control fails if security groups have inbound rules that allow SSH access from 0.0.0.0/0.

Test triggers:
- Security group with 0.0.0.0/0 on port 22: aws ec2 describe-security-groups --group-ids sg-12345
- Create SG rule: aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0

The auto-remediation removes 0.0.0.0/0 (and ::/0) from SSH rules while preserving specific IP ranges.
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
from tests.fixtures.security_hub_findings.ec2_findings import (
    get_ec213_ssh_open_finding,
    get_ec213_ssh_mixed_finding,
    get_ec213_ssh_secure_finding,
    get_ec213_all_protocols_finding,
    get_ec213_missing_details_finding,
    get_ec213_cross_account_finding,
    get_ec213_ipv6_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler and internal functions
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec213'))
from functions.auto_remediations.auto_remediate_ec213.app import lambda_handler, improve_perm, revoke, authorize


class TestImprovePermFunction:
    """Test the improve_perm() internal function logic in isolation"""

    def test_ssh_tcp_port_22_with_open_access_only(self):
        """Test TCP port 22 rule with only 0.0.0.0/0 - should return True (full removal)"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
        
        result = improve_perm(perm)
        assert result is True

    def test_ssh_tcp_port_22_with_mixed_ranges(self):
        """Test TCP port 22 rule with 0.0.0.0/0 + specific IPs - should return modified rule"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [
                {'CidrIp': '0.0.0.0/0'},
                {'CidrIp': '10.0.0.0/8'},
                {'CidrIp': '192.168.1.0/24'}
            ]
        }
        
        result = improve_perm(perm)
        assert isinstance(result, dict)
        assert result['IpProtocol'] == 'tcp'
        assert result['FromPort'] == 22
        assert result['ToPort'] == 22
        # Should only contain the specific IP ranges, not 0.0.0.0/0
        expected_ranges = [{'CidrIp': '10.0.0.0/8'}, {'CidrIp': '192.168.1.0/24'}]
        assert result['IpRanges'] == expected_ranges

    def test_ssh_tcp_port_22_secure_ranges_only(self):
        """Test TCP port 22 rule without 0.0.0.0/0 - should return False (no change needed)"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [
                {'CidrIp': '10.0.0.0/8'},
                {'CidrIp': '192.168.1.0/24'}
            ]
        }
        
        result = improve_perm(perm)
        assert result is False

    def test_protocol_all_with_open_access(self):
        """Test protocol -1 (all) with 0.0.0.0/0 - should return True (includes SSH)"""
        perm = {
            'IpProtocol': '-1',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
        
        result = improve_perm(perm)
        assert result is True

    def test_tcp_port_range_including_ssh(self):
        """Test TCP port range 20-25 (includes 22) with 0.0.0.0/0 - should return True"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 20,
            'ToPort': 25,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
        
        result = improve_perm(perm)
        assert result is True

    def test_tcp_port_range_not_including_ssh(self):
        """Test TCP port range 80-443 (doesn't include 22) with 0.0.0.0/0 - should return False"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
        
        result = improve_perm(perm)
        assert result is False

    def test_non_tcp_protocol_with_open_access(self):
        """Test UDP protocol with 0.0.0.0/0 - should return False (not SSH)"""
        perm = {
            'IpProtocol': 'udp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
        
        result = improve_perm(perm)
        assert result is False

    def test_ipv6_ranges_with_open_access(self):
        """Test IPv6 ::/0 on SSH port - should remove IPv6 range"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.0.0/8'}],
            'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
        }
        
        result = improve_perm(perm)
        assert isinstance(result, dict)
        assert result['IpRanges'] == [{'CidrIp': '10.0.0.0/8'}]
        assert 'Ipv6Ranges' not in result  # Should be removed

    def test_mixed_ipv4_ipv6_with_open_access(self):
        """Test both IPv4 0.0.0.0/0 and IPv6 ::/0 removal"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [
                {'CidrIp': '0.0.0.0/0'},
                {'CidrIp': '10.0.0.0/8'}
            ],
            'Ipv6Ranges': [
                {'CidrIpv6': '::/0'},
                {'CidrIpv6': '2001:db8::/32'}
            ]
        }
        
        result = improve_perm(perm)
        assert isinstance(result, dict)
        assert result['IpRanges'] == [{'CidrIp': '10.0.0.0/8'}]
        assert result['Ipv6Ranges'] == [{'CidrIpv6': '2001:db8::/32'}]

    def test_no_ip_ranges_in_permission(self):
        """Test permission with no IP ranges - should return False"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22
        }
        
        result = improve_perm(perm)
        assert result is False

    def test_all_ranges_removed_returns_true(self):
        """Test when all IP ranges are removed - should return True for full removal"""
        perm = {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
            'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
        }
        
        result = improve_perm(perm)
        assert result is True


@pytest.fixture
def mock_ssh_open_asff_data():
    """ASFF data structure for EC2.13 control with SSH open to world"""
    return prepare_ec2_test_data(get_ec213_ssh_open_finding)


@pytest.fixture
def mock_ssh_mixed_asff_data():
    """ASFF data structure for EC2.13 control with SSH mixed IPs"""
    return prepare_ec2_test_data(get_ec213_ssh_mixed_finding)


@pytest.fixture
def mock_ssh_secure_asff_data():
    """ASFF data structure for EC2.13 control with SSH secure (no 0.0.0.0/0)"""
    return prepare_ec2_test_data(get_ec213_ssh_secure_finding)


@pytest.fixture
def mock_all_protocols_asff_data():
    """ASFF data structure for EC2.13 control with protocol -1"""
    return prepare_ec2_test_data(get_ec213_all_protocols_finding)




@pytest.fixture
def mock_missing_details_asff_data():
    """ASFF data structure for EC2.13 control with missing SG details"""
    return prepare_ec2_test_data(get_ec213_missing_details_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.13 control with cross-account SG"""
    return prepare_ec2_test_data(get_ec213_cross_account_finding)


@pytest.fixture
def mock_ipv6_asff_data():
    """ASFF data structure for EC2.13 control with IPv6 ::/0"""
    return prepare_ec2_test_data(get_ec213_ipv6_finding)


class TestEc213SuccessScenarios:
    """Test successful EC2.13 remediation scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_ssh_rule_complete_removal(self, mock_get_client, mock_ssh_open_asff_data):
        """Test complete removal of SSH rule with only 0.0.0.0/0"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create security group
        sg = ec2_client.create_security_group(
            GroupName='test-ssh-open-sg',
            Description='Test SSH open security group'
        )
        sg_id = sg['GroupId']
        
        # Add SSH rule with 0.0.0.0/0
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        
        # Update finding with actual SG ID
        mock_ssh_open_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_ssh_open_asff_data, None)
        
        # Verify result
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The ingress rule has been modified or deleted' in result['messages']['actions_taken']
        
        # Verify SSH rule was removed
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        ssh_rules = [rule for rule in sg_details['IpPermissions'] 
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22]
        assert len(ssh_rules) == 0

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_ssh_rule_partial_modification(self, mock_get_client, mock_ssh_mixed_asff_data):
        """Test partial modification of SSH rule removing 0.0.0.0/0 but keeping specific IPs"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create security group
        sg = ec2_client.create_security_group(
            GroupName='test-ssh-mixed-sg',
            Description='Test SSH mixed security group'
        )
        sg_id = sg['GroupId']
        
        # Add SSH rule with mixed IPs
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [
                    {'CidrIp': '0.0.0.0/0'},
                    {'CidrIp': '10.0.0.0/8'},
                    {'CidrIp': '192.168.1.0/24'}
                ]
            }]
        )
        
        # Update finding with actual SG ID
        mock_ssh_mixed_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_ssh_mixed_asff_data, None)
        
        # Verify result
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The ingress rule has been modified or deleted' in result['messages']['actions_taken']
        
        # Verify SSH rule was modified (0.0.0.0/0 removed, specific IPs remain)
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        ssh_rules = [rule for rule in sg_details['IpPermissions'] 
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22]
        assert len(ssh_rules) == 1
        
        ip_ranges = ssh_rules[0]['IpRanges']
        cidr_blocks = [ip_range['CidrIp'] for ip_range in ip_ranges]
        assert '0.0.0.0/0' not in cidr_blocks
        assert '10.0.0.0/8' in cidr_blocks
        assert '192.168.1.0/24' in cidr_blocks

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_secure_ssh_rule_no_change(self, mock_get_client, mock_ssh_secure_asff_data):
        """Test SSH rule without 0.0.0.0/0 remains unchanged"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create security group
        sg = ec2_client.create_security_group(
            GroupName='test-ssh-secure-sg',
            Description='Test SSH secure security group'
        )
        sg_id = sg['GroupId']
        
        # Add secure SSH rule (no 0.0.0.0/0)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [
                    {'CidrIp': '10.0.0.0/8'},
                    {'CidrIp': '192.168.1.0/24'}
                ]
            }]
        )
        
        # Update finding with actual SG ID
        mock_ssh_secure_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_ssh_secure_asff_data, None)
        
        # Verify action was taken - the function recognizes the rule is already secure
        # and marks the validation as successful (no actual AWS API calls made)
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The ingress rule has been modified or deleted' in result['messages']['actions_taken']
        
        # Verify SSH rule unchanged
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        ssh_rules = [rule for rule in sg_details['IpPermissions'] 
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22]
        assert len(ssh_rules) == 1
        
        ip_ranges = ssh_rules[0]['IpRanges']
        cidr_blocks = [ip_range['CidrIp'] for ip_range in ip_ranges]
        assert '10.0.0.0/8' in cidr_blocks
        assert '192.168.1.0/24' in cidr_blocks



class TestEc213ErrorHandling:
    """Test EC2.13 error handling scenarios"""

    def test_ec213_missing_security_group_details(self, mock_missing_details_asff_data):
        """Test handling when security group details are missing"""
        # Execute remediation with missing details
        result = lambda_handler(mock_missing_details_asff_data, None)
        
        # Verify finding is suppressed
        assert result['actions']['suppress_finding'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_invalid_permission_not_found(self, mock_get_client, mock_ssh_open_asff_data):
        """Test handling InvalidPermission.NotFound error during revoke"""
        # Setup mock that raises InvalidPermission.NotFound
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock the revoke operation to raise InvalidPermission.NotFound
        error_response = {'Error': {'Code': 'InvalidPermission.NotFound'}}
        ec2_client.revoke_security_group_ingress.side_effect = botocore.exceptions.ClientError(
            error_response, 'RevokeSecurityGroupIngress'
        )
        
        # Execute remediation
        result = lambda_handler(mock_ssh_open_asff_data, None)
        
        # Verify error is handled gracefully
        assert result['actions']['autoremediation_not_done'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_rollback_on_authorize_failure(self, mock_get_client, mock_ssh_mixed_asff_data):
        """Test rollback mechanism when authorize fails after successful revoke"""
        # Setup mock for rollback scenario
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful revoke but failed authorize
        ec2_client.revoke_security_group_ingress.return_value = {'Return': True}
        
        # First authorize call fails with a specific error that gets caught, second (rollback) succeeds
        authorize_calls = [
            botocore.exceptions.ClientError({'Error': {'Code': 'InvalidPermission.Duplicate'}}, 'AuthorizeSecurityGroupIngress'),
            {'Return': True}  # Rollback succeeds
        ]
        ec2_client.authorize_security_group_ingress.side_effect = authorize_calls
        
        # Execute remediation
        result = lambda_handler(mock_ssh_mixed_asff_data, None)
        
        # Verify rollback was attempted (2 authorize calls: failed + rollback)
        assert ec2_client.authorize_security_group_ingress.call_count == 2
        
        # Verify final state - since authorize returned False, did_something remains False
        # (did_something only gets set True if BOTH revoke AND authorize succeed)
        assert result['actions']['autoremediation_not_done'] is True


class TestEc213EdgeCases:
    """Test EC2.13 edge cases and special scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_protocol_all_with_open_access(self, mock_get_client, mock_all_protocols_asff_data):
        """Test protocol -1 (all) with 0.0.0.0/0 is removed"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create security group
        sg = ec2_client.create_security_group(
            GroupName='test-all-protocols-sg',
            Description='Test all protocols security group'
        )
        sg_id = sg['GroupId']
        
        # Add rule with protocol -1 (all)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        
        # Update finding with actual SG ID
        mock_all_protocols_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_all_protocols_asff_data, None)
        
        # Verify rule was removed
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The ingress rule has been modified or deleted' in result['messages']['actions_taken']
        
        # Verify protocol -1 rule was removed
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        all_protocol_rules = [rule for rule in sg_details['IpPermissions'] 
                             if rule.get('IpProtocol') == '-1']
        assert len(all_protocol_rules) == 0

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec213.app.get_client')
    def test_ec213_ipv6_range_removal(self, mock_get_client, mock_ipv6_asff_data):
        """Test IPv6 ::/0 range removal while preserving IPv4 ranges"""
        # Setup AWS mocks  
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create security group
        sg = ec2_client.create_security_group(
            GroupName='test-ipv6-sg',
            Description='Test IPv6 security group'
        )
        sg_id = sg['GroupId']
        
        # Add SSH rule with IPv4 + IPv6 ranges
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '10.0.0.0/8'}],
                'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
            }]
        )
        
        # Update finding with actual SG ID
        mock_ipv6_asff_data['finding']['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'] = sg_id
        
        # Execute remediation
        result = lambda_handler(mock_ipv6_asff_data, None)
        
        # Verify rule was modified
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The ingress rule has been modified or deleted' in result['messages']['actions_taken']
        
        # Verify IPv6 ::/0 was removed but IPv4 10.0.0.0/8 remains
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        ssh_rules = [rule for rule in sg_details['IpPermissions'] 
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22]
        assert len(ssh_rules) == 1
        
        # Should have IPv4 range but no IPv6 ranges
        assert len(ssh_rules[0]['IpRanges']) == 1
        assert ssh_rules[0]['IpRanges'][0]['CidrIp'] == '10.0.0.0/8'
        assert 'Ipv6Ranges' not in ssh_rules[0] or len(ssh_rules[0].get('Ipv6Ranges', [])) == 0

    def test_ec213_cross_account_data_parsing(self, mock_cross_account_asff_data):
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