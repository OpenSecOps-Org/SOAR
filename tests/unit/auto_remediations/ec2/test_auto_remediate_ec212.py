"""
Unit tests for EC2.12 auto-remediation: Unused EC2 EIPs should be removed

This control checks whether Elastic IP addresses that are allocated to a VPC are 
attached to EC2 instances or in-use elastic network interfaces (ENIs). Unattached 
Elastic IPs incur unnecessary costs and may indicate abandoned resources.

Test triggers:
- Unused EIP for over 30 days: aws ec2 describe-addresses --filters "Name=domain,Values=vpc"
- Check EIP association status: aws ec2 describe-addresses --allocation-ids eipalloc-12345678
- Monitor EIP first observed time: Check finding FirstObservedAt timestamp

The auto-remediation releases Elastic IP addresses that have been unused for more than
30 days, reducing costs and cleaning up orphaned network resources.
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
from tests.fixtures.security_hub_findings.ec2_12_findings import (
    get_ec212_unused_eip_finding,
    get_ec212_unused_eip_old_finding,
    get_ec212_eip_no_details_finding,
    get_ec212_eip_product_fields_only_finding,
    get_ec212_eip_cross_account_finding,
    get_ec212_eip_error_handling_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec212'))
from functions.auto_remediations.auto_remediate_ec212.app import lambda_handler


@pytest.fixture
def mock_unused_eip_asff_data():
    """ASFF data structure for EC2.12 control with unused EIP (recent finding)"""
    return prepare_ec2_test_data(get_ec212_unused_eip_finding)


@pytest.fixture
def mock_unused_eip_old_asff_data():
    """ASFF data structure for EC2.12 control with unused EIP (old enough for remediation)"""
    return prepare_ec2_test_data(get_ec212_unused_eip_old_finding)


@pytest.fixture
def mock_eip_no_details_asff_data():
    """ASFF data structure for EC2.12 control with EIP missing ASFF Details"""
    return prepare_ec2_test_data(get_ec212_eip_no_details_finding)


@pytest.fixture
def mock_eip_product_fields_asff_data():
    """ASFF data structure for EC2.12 control with EIP via ProductFields only"""
    return prepare_ec2_test_data(get_ec212_eip_product_fields_only_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.12 control with cross-account EIP"""
    return prepare_ec2_test_data(get_ec212_eip_cross_account_finding)


@pytest.fixture
def mock_error_handling_asff_data():
    """ASFF data structure for EC2.12 control for error handling scenarios"""
    return prepare_ec2_test_data(get_ec212_eip_error_handling_finding)


class TestEc212TimeBasedRemediation:
    """Test EC2.12 time-based remediation logic"""

    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_eip_too_young_defer_remediation(self, mock_dt, mock_get_client, mock_unused_eip_asff_data):
        """Test that EIP younger than 30 days is deferred for later remediation"""
        # Mock current time to make the EIP too young (within 30 days)
        mock_now = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)  # 15 days after FirstObservedAt
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone  # Use actual timezone
        mock_dt.timedelta = dt.timedelta  # Use actual timedelta

        # Setup mock client (shouldn't be called for young EIPs)
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client

        # Execute remediation
        result = lambda_handler(mock_unused_eip_asff_data, None)

        # Verify remediation was deferred
        assert result['actions']['reconsider_later'] is True
        
        # Verify EC2 client was not called for release_address
        ec2_client.release_address.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_eip_old_enough_successful_release(self, mock_dt, mock_get_client, mock_unused_eip_old_asff_data):
        """Test successful EIP release when older than 30 days"""
        # Mock current time to make the EIP old enough (over 30 days)
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)  # Way past 30 days
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create and allocate EIP
        response = ec2_client.allocate_address(Domain='vpc')
        allocation_id = response['AllocationId']

        # Update finding with actual allocation ID
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Details']['AwsEc2Eip']['AllocationId'] = allocation_id
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'
        mock_unused_eip_old_asff_data['finding']['ProductFields']['Resources:0/Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'

        # Execute remediation
        result = lambda_handler(mock_unused_eip_old_asff_data, None)

        # Verify remediation was successful
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The Elastic IP has been released.' in result['messages']['actions_taken']
        assert 'Unused Elastic IPs will be released after 30 days' in result['messages']['actions_required']
        
        # Verify EIP was actually released (describe should fail)
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            ec2_client.describe_addresses(AllocationIds=[allocation_id])
        assert exc_info.value.response['Error']['Code'] == 'InvalidAllocationID.NotFound'


class TestEc212ResourceIdExtraction:
    """Test EC2.12 resource ID extraction from different ASFF sources"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_allocation_id_from_asff_details(self, mock_dt, mock_get_client, mock_unused_eip_old_asff_data):
        """Test allocation ID extraction from ASFF Details section"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create EIP and update finding
        response = ec2_client.allocate_address(Domain='vpc')
        allocation_id = response['AllocationId']
        
        # Verify ASFF Details path is used
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Details']['AwsEc2Eip']['AllocationId'] = allocation_id
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Type'] = 'AwsEc2Eip'
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'
        mock_unused_eip_old_asff_data['finding']['ProductFields']['Resources:0/Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'

        # Execute remediation
        result = lambda_handler(mock_unused_eip_old_asff_data, None)

        # Verify successful remediation using ASFF Details
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The Elastic IP has been released.' in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_allocation_id_from_resource_id(self, mock_dt, mock_get_client, mock_eip_no_details_asff_data):
        """Test allocation ID extraction from Resource ID when Details missing"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create EIP and update finding
        response = ec2_client.allocate_address(Domain='vpc')
        allocation_id = response['AllocationId']
        
        # Set up for Resource ID extraction path (Type=AwsEc2Eip, no Details, no allocation_id found from details)
        mock_eip_no_details_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'
        mock_eip_no_details_asff_data['finding']['Resources'][0]['Type'] = 'AwsEc2Eip'
        mock_eip_no_details_asff_data['finding']['ProductFields']['Resources:0/Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'
        # Remove Details section to ensure allocation_id is False from details check
        if 'Details' in mock_eip_no_details_asff_data['finding']['Resources'][0]:
            del mock_eip_no_details_asff_data['finding']['Resources'][0]['Details']

        # Execute remediation
        result = lambda_handler(mock_eip_no_details_asff_data, None)

        # Verify successful remediation using Resource ID
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The Elastic IP has been released.' in result['messages']['actions_taken']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_allocation_id_from_product_fields(self, mock_dt, mock_get_client, mock_eip_product_fields_asff_data):
        """Test allocation ID extraction from ProductFields when other methods fail"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create EIP and update finding
        response = ec2_client.allocate_address(Domain='vpc')
        allocation_id = response['AllocationId']
        
        # Set up for ProductFields extraction path (Type != AwsEc2Eip)
        mock_eip_product_fields_asff_data['finding']['Resources'][0]['Type'] = 'NotAwsEc2Eip'  # Force ProductFields path
        mock_eip_product_fields_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'
        mock_eip_product_fields_asff_data['finding']['ProductFields']['Resources:0/Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{allocation_id}'

        # Execute remediation
        result = lambda_handler(mock_eip_product_fields_asff_data, None)

        # Verify successful remediation using ProductFields
        assert result['actions']['autoremediation_not_done'] is False
        assert 'The Elastic IP has been released.' in result['messages']['actions_taken']


class TestEc212ErrorHandling:
    """Test EC2.12 error handling scenarios"""

    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_eip_in_use_suppression(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test handling when EIP is now in use (InvalidIPAddress.InUse)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises InvalidIPAddress.InUse
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'InvalidIPAddress.InUse'}}
        ec2_client.release_address.side_effect = botocore.exceptions.ClientError(
            error_response, 'ReleaseAddress'
        )

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify finding is suppressed when EIP is now in use
        assert result['actions']['suppress_finding'] is True
        assert 'The EIP is now in use. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_auth_failure_suppression(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test handling of authentication failures (AuthFailure)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises AuthFailure
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'AuthFailure'}}
        ec2_client.release_address.side_effect = botocore.exceptions.ClientError(
            error_response, 'ReleaseAddress'
        )

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify finding is suppressed on authentication failure
        assert result['actions']['suppress_finding'] is True
        assert 'Authentication failure. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_eip_not_found_suppression(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test handling when EIP is not found (InvalidAllocationID.NotFound)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises InvalidAllocationID.NotFound
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'InvalidAllocationID.NotFound'}}
        ec2_client.release_address.side_effect = botocore.exceptions.ClientError(
            error_response, 'ReleaseAddress'
        )

        # Execute remediation
        result = lambda_handler(mock_error_handling_asff_data, None)

        # Verify finding is suppressed when EIP not found
        assert result['actions']['suppress_finding'] is True
        assert 'EIP not found. This finding has been suppressed.' in result['messages']['actions_taken']

    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_unexpected_error_propagation(self, mock_dt, mock_get_client, mock_error_handling_asff_data):
        """Test that unexpected errors are properly propagated"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup mock that raises an unexpected error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'UnauthorizedOperation'}}
        ec2_client.release_address.side_effect = botocore.exceptions.ClientError(
            error_response, 'ReleaseAddress'
        )

        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'UnauthorizedOperation'


class TestEc212EdgeCases:
    """Test EC2.12 edge cases and special scenarios"""

    def test_ec212_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        
        # Verify allocation ID extraction works with cross-account ARN
        allocation_id = finding['Resources'][0]['Details']['AwsEc2Eip']['AllocationId']
        assert allocation_id == 'eipalloc-cross12345'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_multiple_eips_individual_remediation(self, mock_dt, mock_get_client, mock_unused_eip_old_asff_data):
        """Test that each EIP is remediated individually (single EIP per finding)"""
        # Mock time to be old enough
        mock_now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create multiple EIPs
        eip1 = ec2_client.allocate_address(Domain='vpc')
        eip2 = ec2_client.allocate_address(Domain='vpc')
        
        # Test remediation of first EIP only (function processes one finding at a time)
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Details']['AwsEc2Eip']['AllocationId'] = eip1['AllocationId']
        mock_unused_eip_old_asff_data['finding']['Resources'][0]['Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{eip1["AllocationId"]}'
        mock_unused_eip_old_asff_data['finding']['ProductFields']['Resources:0/Id'] = f'arn:aws:ec2:us-east-1:123456789012:eip/{eip1["AllocationId"]}'
        
        # Execute remediation
        result = lambda_handler(mock_unused_eip_old_asff_data, None)

        # Verify only the targeted EIP was remediated
        with pytest.raises(botocore.exceptions.ClientError):
            ec2_client.describe_addresses(AllocationIds=[eip1['AllocationId']])  # Should be released
        
        # Verify second EIP still exists
        eip2_status = ec2_client.describe_addresses(AllocationIds=[eip2['AllocationId']])
        assert len(eip2_status['Addresses']) == 1  # Still exists
        assert result['actions']['autoremediation_not_done'] is False

    @patch('functions.auto_remediations.auto_remediate_ec212.app.get_client')
    @patch('functions.auto_remediations.auto_remediate_ec212.app.dt')
    def test_ec212_time_calculation_precision(self, mock_dt, mock_get_client, mock_unused_eip_asff_data):
        """Test precise time calculation around 30-day boundary"""
        # Setup mock client (for defer case, shouldn't be called)
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client

        # Test exactly 30 days (should be old enough)
        mock_now_exact = datetime(2024, 1, 31, 0, 0, 0, tzinfo=timezone.utc)  # Exactly 30 days
        mock_dt.datetime.now.return_value = mock_now_exact
        mock_dt.timezone = dt.timezone
        mock_dt.timedelta = dt.timedelta

        # Execute remediation
        result = lambda_handler(mock_unused_eip_asff_data, None)
        
        # With exactly 30 days, should proceed with remediation (not be deferred)
        assert result['actions']['reconsider_later'] is False
        ec2_client.release_address.assert_called_once()

        # Reset mock for next test
        ec2_client.reset_mock()

        # Test just under 30 days (should be deferred)
        mock_now_under = datetime(2024, 1, 30, 23, 59, 59, tzinfo=timezone.utc)  # Just under 30 days
        mock_dt.datetime.now.return_value = mock_now_under

        # Execute remediation
        result2 = lambda_handler(mock_unused_eip_asff_data, None)
        
        # Should defer for later
        assert result2['actions']['reconsider_later'] is True
        ec2_client.release_address.assert_not_called()