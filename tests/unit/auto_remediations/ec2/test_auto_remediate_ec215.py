"""
Unit tests for EC2.15 auto-remediation: VPC subnets should not automatically assign public IP addresses

This control checks that VPC subnets do not automatically assign public IP addresses 
to instances launched within them. Automatic public IP assignment can expose instances
to the internet unintentionally, creating security risks.

Test triggers:
- Subnet with public IP auto-assignment enabled: aws ec2 describe-subnets --subnet-ids subnet-12345
- Check MapPublicIpOnLaunch status: aws ec2 describe-subnets --filters "Name=map-public-ip-on-launch,Values=true"

The auto-remediation disables automatic public IP assignment (MapPublicIpOnLaunch=False).
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
from tests.fixtures.security_hub_findings.ec2_15_findings import (
    get_ec215_subnet_public_ip_assignment_finding,
    get_ec215_subnet_missing_details_finding,
    get_ec215_subnet_cross_account_finding,
    get_ec215_subnet_error_handling_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec215'))
from functions.auto_remediations.auto_remediate_ec215.app import lambda_handler


@pytest.fixture
def mock_subnet_public_ip_asff_data():
    """ASFF data structure for EC2.15 control with subnet public IP auto-assignment enabled"""
    return prepare_ec2_test_data(get_ec215_subnet_public_ip_assignment_finding)


@pytest.fixture
def mock_missing_details_asff_data():
    """ASFF data structure for EC2.15 control with missing subnet details"""
    return prepare_ec2_test_data(get_ec215_subnet_missing_details_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.15 control with cross-account subnet"""
    return prepare_ec2_test_data(get_ec215_subnet_cross_account_finding)


@pytest.fixture
def mock_error_handling_asff_data():
    """ASFF data structure for EC2.15 control for error handling scenarios"""
    return prepare_ec2_test_data(get_ec215_subnet_error_handling_finding)


class TestEc215SuccessScenarios:
    """Test successful EC2.15 remediation scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_subnet_disable_public_ip_assignment(self, mock_get_client, mock_subnet_public_ip_asff_data):
        """Test successful remediation of subnet with public IP auto-assignment enabled"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC and subnet with public IP auto-assignment enabled
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )
        subnet_id = subnet['Subnet']['SubnetId']
        
        # Enable public IP auto-assignment
        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={'Value': True}
        )
        
        # Verify initial state - public IP assignment should be enabled
        initial_subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
        assert initial_subnet['MapPublicIpOnLaunch'] is True
        
        # Update finding with actual subnet ID
        mock_subnet_public_ip_asff_data['finding']['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId'] = subnet_id
        
        # Execute remediation
        result = lambda_handler(mock_subnet_public_ip_asff_data, None)
        
        # Verify remediation was successful
        assert result['actions']['autoremediation_not_done'] is False
        assert 'MapPublicIpOnLaunch has been set to FALSE for the subnet' in result['messages']['actions_taken']
        assert result['messages']['actions_required'] == 'None'
        
        # Verify subnet attribute was actually changed
        remediated_subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
        assert remediated_subnet['MapPublicIpOnLaunch'] is False

    @mock_aws  
    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_subnet_already_disabled_public_ip(self, mock_get_client, mock_subnet_public_ip_asff_data):
        """Test remediation when subnet already has public IP auto-assignment disabled"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC and subnet with public IP auto-assignment disabled (default)
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )
        subnet_id = subnet['Subnet']['SubnetId']
        
        # Verify initial state - public IP assignment should be disabled (default)
        initial_subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
        assert initial_subnet['MapPublicIpOnLaunch'] is False
        
        # Update finding with actual subnet ID
        mock_subnet_public_ip_asff_data['finding']['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId'] = subnet_id
        
        # Execute remediation (should succeed even if already disabled)
        result = lambda_handler(mock_subnet_public_ip_asff_data, None)
        
        # Verify remediation was successful
        assert result['actions']['autoremediation_not_done'] is False
        assert 'MapPublicIpOnLaunch has been set to FALSE for the subnet' in result['messages']['actions_taken']
        assert result['messages']['actions_required'] == 'None'
        
        # Verify subnet attribute remains disabled
        remediated_subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
        assert remediated_subnet['MapPublicIpOnLaunch'] is False


class TestEc215ErrorHandling:
    """Test EC2.15 error handling scenarios"""

    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_subnet_not_found_suppression(self, mock_get_client, mock_error_handling_asff_data):
        """Test handling when subnet cannot be found (InvalidSubnetID.NotFound)"""
        # Setup mock that raises InvalidSubnetID.NotFound
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'InvalidSubnetID.NotFound'}}
        ec2_client.modify_subnet_attribute.side_effect = botocore.exceptions.ClientError(
            error_response, 'ModifySubnetAttribute'
        )
        
        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify finding is suppressed when subnet not found
        assert result['actions']['suppress_finding'] is True
        assert 'The subnet cannot be found. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_invalid_subnet_suppression(self, mock_get_client, mock_error_handling_asff_data):
        """Test handling when subnet is invalid (InvalidSubnet)"""
        # Setup mock that raises InvalidSubnet
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'InvalidSubnet'}}
        ec2_client.modify_subnet_attribute.side_effect = botocore.exceptions.ClientError(
            error_response, 'ModifySubnetAttribute'
        )
        
        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify finding is suppressed when subnet is invalid
        assert result['actions']['suppress_finding'] is True
        assert 'The subnet cannot be found. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_unexpected_error_propagation(self, mock_get_client, mock_error_handling_asff_data):
        """Test that unexpected errors are properly propagated"""
        # Setup mock that raises an unexpected error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'UnauthorizedOperation'}}
        ec2_client.modify_subnet_attribute.side_effect = botocore.exceptions.ClientError(
            error_response, 'ModifySubnetAttribute'
        )
        
        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'UnauthorizedOperation'

    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_missing_subnet_details_keyerror(self, mock_get_client, mock_missing_details_asff_data):
        """Test handling when subnet details are missing from ASFF (KeyError)"""
        # Setup mock client to bypass AWS authentication
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # This test verifies that missing subnet details in ASFF cause appropriate errors
        # The function should fail gracefully when subnet details are not provided
        with pytest.raises(KeyError):
            lambda_handler(mock_missing_details_asff_data, None)


class TestEc215EdgeCases:
    """Test EC2.15 edge cases and special scenarios"""

    def test_ec215_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        
        # Verify subnet ID extraction works with cross-account ARN
        subnet_id = finding['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId']
        assert subnet_id == 'subnet-cross12345'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_multiple_subnets_individual_remediation(self, mock_get_client, mock_subnet_public_ip_asff_data):
        """Test that each subnet is remediated individually (single subnet per finding)"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create VPC and multiple subnets
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet1 = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )
        subnet2 = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.2.0/24',
            AvailabilityZone='us-east-1b'
        )
        
        # Enable public IP auto-assignment for both subnets
        for subnet in [subnet1, subnet2]:
            ec2_client.modify_subnet_attribute(
                SubnetId=subnet['Subnet']['SubnetId'],
                MapPublicIpOnLaunch={'Value': True}
            )
        
        # Test remediation of first subnet only (function processes one finding at a time)
        mock_subnet_public_ip_asff_data['finding']['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId'] = subnet1['Subnet']['SubnetId']
        
        # Execute remediation
        result = lambda_handler(mock_subnet_public_ip_asff_data, None)
        
        # Verify only the targeted subnet was remediated
        remediated_subnet1 = ec2_client.describe_subnets(SubnetIds=[subnet1['Subnet']['SubnetId']])['Subnets'][0]
        unchanged_subnet2 = ec2_client.describe_subnets(SubnetIds=[subnet2['Subnet']['SubnetId']])['Subnets'][0]
        
        assert remediated_subnet1['MapPublicIpOnLaunch'] is False  # This was remediated
        assert unchanged_subnet2['MapPublicIpOnLaunch'] is True   # This remains unchanged
        assert result['actions']['autoremediation_not_done'] is False

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec215.app.get_client')
    def test_ec215_subnet_in_different_vpc(self, mock_get_client, mock_subnet_public_ip_asff_data):
        """Test remediation works correctly across different VPCs"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client
        
        # Create multiple VPCs with subnets
        vpc1 = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        vpc2 = ec2_client.create_vpc(CidrBlock='172.16.0.0/16')
        
        # Create subnets in different VPCs
        ec2_client.create_subnet(
            VpcId=vpc1['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )
        subnet_vpc2 = ec2_client.create_subnet(
            VpcId=vpc2['Vpc']['VpcId'],
            CidrBlock='172.16.1.0/24',
            AvailabilityZone='us-east-1a'
        )
        
        # Enable public IP auto-assignment for subnet in VPC2
        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_vpc2['Subnet']['SubnetId'],
            MapPublicIpOnLaunch={'Value': True}
        )
        
        # Test remediation of subnet in VPC2
        mock_subnet_public_ip_asff_data['finding']['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId'] = subnet_vpc2['Subnet']['SubnetId']
        
        # Execute remediation
        result = lambda_handler(mock_subnet_public_ip_asff_data, None)
        
        # Verify remediation was successful
        assert result['actions']['autoremediation_not_done'] is False
        
        # Verify the correct subnet was remediated
        remediated_subnet = ec2_client.describe_subnets(SubnetIds=[subnet_vpc2['Subnet']['SubnetId']])['Subnets'][0]
        assert remediated_subnet['MapPublicIpOnLaunch'] is False
        assert remediated_subnet['VpcId'] == vpc2['Vpc']['VpcId']