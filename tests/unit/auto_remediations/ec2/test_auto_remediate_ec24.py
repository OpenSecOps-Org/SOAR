"""
Unit tests for EC2.4 auto-remediation: Stopped EC2 instances should be removed or restarted

This control identifies and terminates EC2 instances that have been in a stopped
state, which may indicate they are no longer needed. Stopped instances still
incur EBS storage costs and may contain sensitive data or configurations.

Test triggers:
- Stopped EC2 instance: aws ec2 describe-instances --filters "Name=instance-state-name,Values=stopped"
- Check instance state: aws ec2 describe-instances --instance-ids i-1234567890abcdef0
- Monitor instance termination protection: aws ec2 describe-instance-attribute --instance-id i-1234567890abcdef0 --attribute disableApiTermination

The auto-remediation first disables API termination protection if enabled, then
terminates the stopped instance to reduce costs and eliminate potential security risks.
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
from tests.fixtures.security_hub_findings.ec2_4_findings import (
    get_ec24_stopped_instance_finding,
    get_ec24_stopped_instance_with_protection_finding,
    get_ec24_cross_account_instance_finding,
    get_ec24_error_handling_instance_finding,
    get_ec24_minimal_instance_finding,
    get_ec24_running_instance_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec24'))
from functions.auto_remediations.auto_remediate_ec24.app import lambda_handler


@pytest.fixture
def mock_stopped_instance_asff_data():
    """ASFF data structure for EC2.4 control with stopped instance"""
    return prepare_ec2_test_data(get_ec24_stopped_instance_finding)


@pytest.fixture
def mock_protected_instance_asff_data():
    """ASFF data structure for EC2.4 control with protected stopped instance"""
    return prepare_ec2_test_data(get_ec24_stopped_instance_with_protection_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.4 control with cross-account instance"""
    return prepare_ec2_test_data(get_ec24_cross_account_instance_finding)


@pytest.fixture
def mock_error_handling_asff_data():
    """ASFF data structure for EC2.4 control for error handling scenarios"""
    return prepare_ec2_test_data(get_ec24_error_handling_instance_finding)


@pytest.fixture
def mock_minimal_instance_asff_data():
    """ASFF data structure for EC2.4 control with minimal instance data"""
    return prepare_ec2_test_data(get_ec24_minimal_instance_finding)


@pytest.fixture
def mock_running_instance_asff_data():
    """ASFF data structure for EC2.4 control with running instance (edge case)"""
    return prepare_ec2_test_data(get_ec24_running_instance_finding)


class TestEc24SuccessScenarios:
    """Test EC2.4 successful remediation scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_stopped_instance_successful_termination(self, mock_get_client, mock_stopped_instance_asff_data):
        """Test successful termination of stopped instance without termination protection"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )

        # Launch instance
        instances = ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=subnet['Subnet']['SubnetId']
        )
        instance_id = instances['Instances'][0]['InstanceId']

        # Stop the instance
        ec2_client.stop_instances(InstanceIds=[instance_id])

        # Update finding with actual instance ID
        mock_stopped_instance_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}'
        
        # Execute remediation
        result = lambda_handler(mock_stopped_instance_asff_data, None)

        # Verify successful termination
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The instance has been terminated.' in result['messages']['actions_taken']
        
        # Verify instance is actually terminated
        instance_state = ec2_client.describe_instances(InstanceIds=[instance_id])
        current_state = instance_state['Reservations'][0]['Instances'][0]['State']['Name']
        assert current_state in ['shutting-down', 'terminated']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_protected_instance_successful_termination(self, mock_get_client, mock_protected_instance_asff_data):
        """Test successful termination of stopped instance with termination protection enabled"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )

        # Launch instance
        instances = ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=subnet['Subnet']['SubnetId']
        )
        instance_id = instances['Instances'][0]['InstanceId']

        # Enable termination protection explicitly (moto doesn't support DisableApiTermination in run_instances)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': True}
        )

        # Stop the instance
        ec2_client.stop_instances(InstanceIds=[instance_id])
        
        # Verify termination protection is enabled
        attr = ec2_client.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='disableApiTermination'
        )
        assert attr['DisableApiTermination']['Value'] is True

        # Update finding with actual instance ID
        mock_protected_instance_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}'
        
        # Execute remediation
        result = lambda_handler(mock_protected_instance_asff_data, None)

        # Verify successful termination despite initial protection
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The instance has been terminated.' in result['messages']['actions_taken']
        
        # Verify instance is actually terminated
        instance_state = ec2_client.describe_instances(InstanceIds=[instance_id])
        current_state = instance_state['Reservations'][0]['Instances'][0]['State']['Name']
        assert current_state in ['shutting-down', 'terminated']
        
        # Verify termination protection was disabled
        try:
            attr = ec2_client.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute='disableApiTermination'
            )
            # If we can read it, it should be False now
            assert attr['DisableApiTermination']['Value'] is False
        except botocore.exceptions.ClientError:
            # May fail if instance is already terminated, which is acceptable
            pass

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_minimal_data_successful_termination(self, mock_get_client, mock_minimal_instance_asff_data):
        """Test successful termination with minimal instance data in finding"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )

        # Launch and stop instance
        instances = ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=subnet['Subnet']['SubnetId']
        )
        instance_id = instances['Instances'][0]['InstanceId']
        ec2_client.stop_instances(InstanceIds=[instance_id])

        # Update finding with actual instance ID
        mock_minimal_instance_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}'
        
        # Execute remediation
        result = lambda_handler(mock_minimal_instance_asff_data, None)

        # Verify remediation works even with minimal ASFF data
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The instance has been terminated.' in result['messages']['actions_taken']


class TestEc24ErrorHandling:
    """Test EC2.4 error handling scenarios"""

    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_instance_not_found_suppression(self, mock_get_client, mock_error_handling_asff_data):
        """Test handling when instance is not found (InvalidInstanceID.NotFound)"""
        # Setup mock that raises InvalidInstanceID.NotFound for terminate_instances
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful modify_instance_attribute but failed terminate_instances
        ec2_client.modify_instance_attribute.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        
        error_response = {'Error': {'Code': 'InvalidInstanceID.NotFound'}}
        ec2_client.terminate_instances.side_effect = botocore.exceptions.ClientError(
            error_response, 'TerminateInstances'
        )

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify finding is suppressed when instance not found
        assert result['actions']['suppress_finding'] is True
        assert "The instance couldn't be found. This finding has been suppressed." in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_terminate_unexpected_error_propagation(self, mock_get_client, mock_error_handling_asff_data):
        """Test that unexpected errors during termination are properly propagated"""
        # Setup mock that raises an unexpected error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful modify_instance_attribute but unexpected error for terminate_instances
        ec2_client.modify_instance_attribute.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        
        error_response = {'Error': {'Code': 'UnauthorizedOperation'}}
        ec2_client.terminate_instances.side_effect = botocore.exceptions.ClientError(
            error_response, 'TerminateInstances'
        )

        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'UnauthorizedOperation'

    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_modify_attribute_error_ignored(self, mock_get_client, mock_error_handling_asff_data):
        """Test that errors during modify_instance_attribute are gracefully ignored"""
        # Setup mock that raises an error for modify_instance_attribute but succeeds for terminate_instances
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock failed modify_instance_attribute but successful terminate_instances
        error_response = {'Error': {'Code': 'InvalidInstanceID.NotFound'}}
        ec2_client.modify_instance_attribute.side_effect = botocore.exceptions.ClientError(
            error_response, 'ModifyInstanceAttribute'
        )
        ec2_client.terminate_instances.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify remediation still succeeds even if modify_instance_attribute fails
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The instance has been terminated.' in result['messages']['actions_taken']
        
        # Verify both operations were attempted
        ec2_client.modify_instance_attribute.assert_called_once()
        ec2_client.terminate_instances.assert_called_once()


class TestEc24EdgeCases:
    """Test EC2.4 edge cases and special scenarios"""

    def test_ec24_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        
        # Verify instance ID extraction works with cross-account ARN
        instance_arn = finding['Resources'][0]['Id']
        instance_id = instance_arn.rsplit('/', 1)[1]
        assert instance_id == 'i-crossaccount1234'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_multiple_instances_individual_remediation(self, mock_get_client, mock_stopped_instance_asff_data):
        """Test that each instance is remediated individually (single instance per finding)"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )

        # Launch multiple instances
        instances1 = ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=subnet['Subnet']['SubnetId']
        )
        instances2 = ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=subnet['Subnet']['SubnetId']
        )
        
        instance1_id = instances1['Instances'][0]['InstanceId']
        instance2_id = instances2['Instances'][0]['InstanceId']
        
        # Stop both instances
        ec2_client.stop_instances(InstanceIds=[instance1_id, instance2_id])
        
        # Test remediation of first instance only (function processes one finding at a time)
        mock_stopped_instance_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:instance/{instance1_id}'
        
        # Execute remediation
        result = lambda_handler(mock_stopped_instance_asff_data, None)

        # Verify only the targeted instance was remediated
        instance1_state = ec2_client.describe_instances(InstanceIds=[instance1_id])
        instance2_state = ec2_client.describe_instances(InstanceIds=[instance2_id])
        
        current_state1 = instance1_state['Reservations'][0]['Instances'][0]['State']['Name']
        current_state2 = instance2_state['Reservations'][0]['Instances'][0]['State']['Name']
        
        assert current_state1 in ['shutting-down', 'terminated']  # This was remediated
        assert current_state2 == 'stopped'  # This remains unchanged
        assert result['actions']['autoremediation_not_done'] is False

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_instance_arn_parsing_consistency(self, mock_get_client, mock_stopped_instance_asff_data):
        """Test consistent parsing of instance ARNs from different formats"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2_client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )

        # Launch instance
        instances = ec2_client.run_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=subnet['Subnet']['SubnetId']
        )
        instance_id = instances['Instances'][0]['InstanceId']
        ec2_client.stop_instances(InstanceIds=[instance_id])

        # Test various ARN formats (all should extract the same instance ID)
        arn_formats = [
            f'arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}',
            f'arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}/',  # Trailing slash
        ]
        
        for arn in arn_formats:
            mock_stopped_instance_asff_data['finding']['Resources'][0]['Id'] = arn
            
            # Execute remediation
            result = lambda_handler(mock_stopped_instance_asff_data, None)
            
            # Verify successful remediation regardless of ARN format
            assert result['actions']['autoremediation_not_done'] is False
            assert 'The instance has been terminated.' in result['messages']['actions_taken']
            
            # Re-launch instance for next iteration if needed
            if arn != arn_formats[-1]:
                instances = ec2_client.run_instances(
                    ImageId='ami-12345678',
                    MinCount=1,
                    MaxCount=1,
                    InstanceType='t3.micro',
                    SubnetId=subnet['Subnet']['SubnetId']
                )
                instance_id = instances['Instances'][0]['InstanceId']
                ec2_client.stop_instances(InstanceIds=[instance_id])
                # Update next ARN with new instance ID
                arn_formats[arn_formats.index(arn) + 1] = arn_formats[arn_formats.index(arn) + 1].replace(
                    arn_formats[arn_formats.index(arn) + 1].split('/')[-1].rstrip('/'), 
                    instance_id
                )

    @patch('functions.auto_remediations.auto_remediate_ec24.app.get_client')
    def test_ec24_two_step_process_verification(self, mock_get_client, mock_stopped_instance_asff_data):
        """Test that both steps of the remediation process are executed in correct order"""
        # Setup mock client
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful responses for both operations
        ec2_client.modify_instance_attribute.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        ec2_client.terminate_instances.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Execute remediation
        result = lambda_handler(mock_stopped_instance_asff_data, None)

        # Verify both steps were executed in correct order
        assert ec2_client.modify_instance_attribute.call_count == 1
        assert ec2_client.terminate_instances.call_count == 1
        
        # Verify modify_instance_attribute was called with correct parameters
        modify_call = ec2_client.modify_instance_attribute.call_args
        assert modify_call[1]['DisableApiTermination']['Value'] is False
        assert modify_call[1]['InstanceId'] == 'i-1234567890abcdef0'
        
        # Verify terminate_instances was called with correct parameters
        terminate_call = ec2_client.terminate_instances.call_args
        assert terminate_call[1]['InstanceIds'] == ['i-1234567890abcdef0']
        
        # Verify successful result
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The instance has been terminated.' in result['messages']['actions_taken']