"""
Unit tests for EC2.22 auto-remediation: Unused security groups should be removed

This control checks whether security groups that are not attached to any instances 
or network interfaces are removed. Unused security groups can clutter the environment 
and may pose security risks if they contain overly permissive rules.

Test triggers:
- Unused security group for over 24 hours: aws ec2 describe-security-groups --group-ids sg-12345678
- Check security group usage: aws ec2 describe-instances --filters "Name=instance.group-id,Values=sg-12345678"
- Monitor security group first observed time: Check finding FirstObservedAt timestamp

The auto-remediation deletes security groups that have been unused for more than
24 hours, reducing security risks and cleaning up orphaned network configurations.
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from moto import mock_aws
import boto3
import botocore.exceptions
from datetime import datetime, timezone, timedelta
import datetime as dt

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_ec2_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from tests.fixtures.security_hub_findings.ec2_222_findings import (
    get_ec222_unused_sg_finding,
    get_ec222_unused_sg_old_finding,
    get_ec222_sg_cross_account_finding,
    get_ec222_sg_error_handling_finding,
    get_ec222_sg_with_rules_finding,
    get_ec222_sg_minimal_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec222'))
from functions.auto_remediations.auto_remediate_ec222.app import lambda_handler


@pytest.fixture
def mock_unused_sg_asff_data():
    """ASFF data structure for EC2.22 control with unused security group (recent finding)"""
    return prepare_ec2_test_data(get_ec222_unused_sg_finding)


@pytest.fixture
def mock_unused_sg_old_asff_data():
    """ASFF data structure for EC2.22 control with unused security group (old enough for remediation)"""
    return prepare_ec2_test_data(get_ec222_unused_sg_old_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.22 control with cross-account security group"""
    return prepare_ec2_test_data(get_ec222_sg_cross_account_finding)


@pytest.fixture
def mock_error_handling_asff_data():
    """ASFF data structure for EC2.22 control for error handling scenarios"""
    return prepare_ec2_test_data(get_ec222_sg_error_handling_finding)


@pytest.fixture
def mock_sg_with_rules_asff_data():
    """ASFF data structure for EC2.22 control with security group containing rules"""
    return prepare_ec2_test_data(get_ec222_sg_with_rules_finding)


@pytest.fixture
def mock_sg_minimal_asff_data():
    """ASFF data structure for EC2.22 control with minimal security group data"""
    return prepare_ec2_test_data(get_ec222_sg_minimal_finding)


class TestEc222TimeBasedRemediation:
    """Test EC2.22 time-based remediation logic"""

    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_sg_too_young_defer_remediation(self, mock_dt, mock_get_client, mock_unused_sg_asff_data):
        """Test that security group younger than 24 hours is deferred for later remediation"""
        # Mock current time to make the security group too young (within 24 hours)
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)  # 12 hours after FirstObservedAt
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock client (shouldn't be called for young security groups)
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client

        # Execute remediation
        result = lambda_handler(mock_unused_sg_asff_data, None)

        # Verify remediation was deferred
        assert result['actions']['reconsider_later'] is True
        
        # Verify EC2 client was not called for delete_security_group
        ec2_client.delete_security_group.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_sg_old_enough_successful_deletion(self, mock_dt, mock_get_client, mock_unused_sg_old_asff_data):
        """Test successful security group deletion when older than 24 hours"""
        # Mock current time to make the security group old enough (over 24 hours)
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)  # Way past 24 hours
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and security group
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2_client.create_security_group(
            GroupName='test-unused-sg',
            Description='Test unused security group',
            VpcId=vpc['Vpc']['VpcId']
        )
        sg_id = sg['GroupId']

        # Update finding with actual security group ID
        mock_unused_sg_old_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}'
        
        # Execute remediation
        result = lambda_handler(mock_unused_sg_old_asff_data, None)

        # Verify remediation was successful
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The security group has been deleted.' in result['messages']['actions_taken']
        assert 'Unused security groups will be deleted after 24 hours' in result['messages']['actions_required']
        
        # Verify security group was actually deleted (describe should fail)
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            ec2_client.describe_security_groups(GroupIds=[sg_id])
        assert exc_info.value.response['Error']['Code'] == 'InvalidGroup.NotFound'


class TestEc222SecurityGroupTypes:
    """Test EC2.22 remediation with different security group types"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_sg_with_rules_successful_deletion(self, mock_dt, mock_get_client, mock_sg_with_rules_asff_data):
        """Test successful deletion of security group that contains rules"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and security group with rules
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2_client.create_security_group(
            GroupName='sg-with-rules',
            Description='Security group with rules',
            VpcId=vpc['Vpc']['VpcId']
        )
        sg_id = sg['GroupId']
        
        # Add some rules to the security group
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
            }]
        )

        # Update finding with actual security group ID
        mock_sg_with_rules_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}'
        
        # Execute remediation
        result = lambda_handler(mock_sg_with_rules_asff_data, None)

        # Verify successful deletion even with rules present
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The security group has been deleted.' in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_sg_minimal_data_successful_deletion(self, mock_dt, mock_get_client, mock_sg_minimal_asff_data):
        """Test successful deletion with minimal security group data in finding"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and security group
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2_client.create_security_group(
            GroupName='minimal-sg',
            Description='Minimal security group',
            VpcId=vpc['Vpc']['VpcId']
        )
        sg_id = sg['GroupId']

        # Update finding with actual security group ID
        mock_sg_minimal_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}'
        
        # Execute remediation
        result = lambda_handler(mock_sg_minimal_asff_data, None)

        # Verify remediation works even with minimal ASFF data
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The security group has been deleted.' in result['messages']['actions_taken']


class TestEc222ErrorHandling:
    """Test EC2.22 error handling scenarios"""

    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_sg_not_found_suppression(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test handling when security group is not found (InvalidGroup.NotFound)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises InvalidGroup.NotFound
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'InvalidGroup.NotFound'}}
        ec2_client.delete_security_group.side_effect = botocore.exceptions.ClientError(
            error_response, 'DeleteSecurityGroup'
        )

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify finding is suppressed when security group not found
        assert result['actions']['suppress_finding'] is True
        assert 'The security group cannot be found. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_dependency_violation_suppression(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test handling when security group has dependencies (DependencyViolation)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises DependencyViolation
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'DependencyViolation'}}
        ec2_client.delete_security_group.side_effect = botocore.exceptions.ClientError(
            error_response, 'DeleteSecurityGroup'
        )

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify finding is suppressed when security group is now in use
        assert result['actions']['suppress_finding'] is True
        assert 'The security group is now in use. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_unexpected_error_propagation(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test that unexpected errors are properly propagated"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises an unexpected error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'UnauthorizedOperation'}}
        ec2_client.delete_security_group.side_effect = botocore.exceptions.ClientError(
            error_response, 'DeleteSecurityGroup'
        )

        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'UnauthorizedOperation'


class TestEc222EdgeCases:
    """Test EC2.22 edge cases and special scenarios"""

    def test_ec222_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        
        # Verify security group ID extraction works with cross-account ARN
        sg_arn = finding['Resources'][0]['Id']
        sg_id = sg_arn.rsplit('/', 1)[1]
        assert sg_id == 'sg-cross12345'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_multiple_sgs_individual_remediation(self, mock_dt, mock_get_client, mock_unused_sg_old_asff_data):
        """Test that each security group is remediated individually (single SG per finding)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and multiple security groups
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        sg1 = ec2_client.create_security_group(
            GroupName='unused-sg-1',
            Description='First unused security group',
            VpcId=vpc['Vpc']['VpcId']
        )
        sg2 = ec2_client.create_security_group(
            GroupName='unused-sg-2',
            Description='Second unused security group',
            VpcId=vpc['Vpc']['VpcId']
        )
        
        # Test remediation of first security group only (function processes one finding at a time)
        mock_unused_sg_old_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:security-group/{sg1["GroupId"]}'
        
        # Execute remediation
        result = lambda_handler(mock_unused_sg_old_asff_data, None)

        # Verify only the targeted security group was remediated
        with pytest.raises(botocore.exceptions.ClientError):
            ec2_client.describe_security_groups(GroupIds=[sg1['GroupId']])  # Should be deleted
        
        # Verify second security group still exists
        sg2_status = ec2_client.describe_security_groups(GroupIds=[sg2['GroupId']])
        assert len(sg2_status['SecurityGroups']) == 1  # Still exists
        assert result['actions']['autoremediation_not_done'] is False

    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_time_calculation_precision(self, mock_dt, mock_get_client, mock_unused_sg_asff_data):
        """Test precise time calculation around 24-hour boundary"""
        # Setup mock client (for defer case, shouldn't be called)
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client

        # Test exactly 24 hours (should be old enough)
        mock_now_exact = datetime(2024, 6, 13, 0, 0, 0, tzinfo=timezone.utc)  # Exactly 24 hours
        mock_dt.datetime.now.return_value = mock_now_exact
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Execute remediation
        result = lambda_handler(mock_unused_sg_asff_data, None)
        
        # With exactly 24 hours, should proceed with remediation (not be deferred)
        assert result['actions']['reconsider_later'] is False
        ec2_client.delete_security_group.assert_called_once()

        # Reset mock for next test
        ec2_client.reset_mock()

        # Test just under 24 hours (should be deferred)
        mock_now_under = datetime(2024, 6, 12, 23, 59, 59, tzinfo=timezone.utc)  # Just under 24 hours
        mock_dt.datetime.now.return_value = mock_now_under

        # Execute remediation
        result2 = lambda_handler(mock_unused_sg_asff_data, None)
        
        # Should defer for later
        assert result2['actions']['reconsider_later'] is True
        ec2_client.delete_security_group.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec222.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec222.app.dt')
    def test_ec222_sg_arn_parsing_consistency(self, mock_dt, mock_get_client, mock_unused_sg_old_asff_data):
        """Test consistent parsing of security group ARNs from different formats"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create VPC and security group
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2_client.create_security_group(
            GroupName='arn-test-sg',
            Description='Security group for ARN parsing test',
            VpcId=vpc['Vpc']['VpcId']
        )
        sg_id = sg['GroupId']

        # Test various ARN formats (all should extract the same SG ID)
        arn_formats = [
            f'arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}',
            f'arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}/',  # Trailing slash
        ]
        
        for arn in arn_formats:
            # Reset security group for each test
            if sg_id not in [sg['GroupId'] for sg in ec2_client.describe_security_groups()['SecurityGroups']]:
                sg = ec2_client.create_security_group(
                    GroupName=f'arn-test-sg-{arn_formats.index(arn)}',
                    Description='Security group for ARN parsing test',
                    VpcId=vpc['Vpc']['VpcId']
                )
                sg_id = sg['GroupId']
                arn = arn.replace(arn.split('/')[-1].rstrip('/'), sg_id)
            
            mock_unused_sg_old_asff_data['finding']['Resources'][0]['Id'] = arn
            
            # Execute remediation
            result = lambda_handler(mock_unused_sg_old_asff_data, None)
            
            # Verify successful remediation regardless of ARN format
            assert result['actions']['autoremediation_not_done'] is False
            assert 'The security group has been deleted.' in result['messages']['actions_taken']