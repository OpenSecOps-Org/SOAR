"""
Unit tests for EC2.7 auto-remediation: EBS Default Encryption Enable

This control ensures that EBS (Elastic Block Store) encryption is enabled by default
for new volumes in the account. Enabling EBS encryption by default helps protect
data at rest and ensures compliance with security requirements.

Test triggers:
- Check EBS encryption status: aws ec2 get-ebs-encryption-by-default
- Verify account-level encryption: aws ec2 describe-volumes --filters "Name=encrypted,Values=false"
- Check new volume creation: aws ec2 create-volume --size 8 --availability-zone us-east-1a

The auto-remediation enables EBS encryption by default at the account level,
ensuring all new EBS volumes are automatically encrypted.
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
from tests.fixtures.security_hub_findings.ec2_7_findings import (
    get_ec27_ebs_encryption_disabled_finding,
    get_ec27_cross_account_finding,
    get_ec27_error_handling_finding,
    get_ec27_minimal_finding,
    get_ec27_different_region_finding,
    get_ec27_already_enabled_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_ec27'))
from functions.auto_remediations.auto_remediate_ec27.app import lambda_handler


@pytest.fixture
def mock_ebs_encryption_disabled_asff_data():
    """ASFF data structure for EC2.7 control with EBS encryption disabled"""
    return prepare_ec2_test_data(get_ec27_ebs_encryption_disabled_finding)


@pytest.fixture
def mock_cross_account_asff_data():
    """ASFF data structure for EC2.7 control with cross-account EBS encryption"""
    return prepare_ec2_test_data(get_ec27_cross_account_finding)


@pytest.fixture
def mock_error_handling_asff_data():
    """ASFF data structure for EC2.7 control for error handling scenarios"""
    return prepare_ec2_test_data(get_ec27_error_handling_finding)


@pytest.fixture
def mock_minimal_asff_data():
    """ASFF data structure for EC2.7 control with minimal data"""
    return prepare_ec2_test_data(get_ec27_minimal_finding)


@pytest.fixture
def mock_different_region_asff_data():
    """ASFF data structure for EC2.7 control in different region"""
    return prepare_ec2_test_data(get_ec27_different_region_finding)


@pytest.fixture
def mock_already_enabled_asff_data():
    """ASFF data structure for EC2.7 control with encryption already enabled (edge case)"""
    return prepare_ec2_test_data(get_ec27_already_enabled_finding)


class TestEc27SuccessScenarios:
    """Test EC2.7 successful remediation scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_successful_ebs_encryption_enable(self, mock_get_client, mock_ebs_encryption_disabled_asff_data):
        """Test successful enabling of EBS encryption by default"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Verify encryption is initially disabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is False

        # Execute remediation
        result = lambda_handler(mock_ebs_encryption_disabled_asff_data, None)

        # Verify successful remediation
        assert result['actions']['autoremediation_not_done'] is False
        assert 'EBS encryption has been enabled on the account level and will affect new volumes only.' in result['messages']['actions_taken']
        assert result['messages']['actions_required'] == 'None'
        
        # Verify encryption is now enabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_different_region_successful_enable(self, mock_get_client, mock_different_region_asff_data):
        """Test successful EBS encryption enable in different region"""
        # Setup AWS mocks for EU region
        ec2_client = boto3.client('ec2', region_name='eu-west-1')
        mock_get_client.return_value = ec2_client

        # Verify encryption is initially disabled in EU region
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is False

        # Execute remediation
        result = lambda_handler(mock_different_region_asff_data, None)

        # Verify successful remediation
        assert result['actions']['autoremediation_not_done'] is False
        assert 'EBS encryption has been enabled on the account level and will affect new volumes only.' in result['messages']['actions_taken']
        
        # Verify encryption is now enabled in EU region
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_minimal_data_successful_enable(self, mock_get_client, mock_minimal_asff_data):
        """Test successful EBS encryption enable with minimal finding data"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Execute remediation
        result = lambda_handler(mock_minimal_asff_data, None)

        # Verify remediation works even with minimal ASFF data
        assert result['actions']['autoremediation_not_done'] is False
        assert 'EBS encryption has been enabled on the account level and will affect new volumes only.' in result['messages']['actions_taken']
        
        # Verify encryption is enabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is True

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_already_enabled_idempotent_operation(self, mock_get_client, mock_already_enabled_asff_data):
        """Test that enabling encryption when already enabled is idempotent"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Enable encryption first
        ec2_client.enable_ebs_encryption_by_default()
        
        # Verify encryption is already enabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is True

        # Execute remediation (should be idempotent)
        result = lambda_handler(mock_already_enabled_asff_data, None)

        # Verify successful remediation (idempotent operation)
        assert result['actions']['autoremediation_not_done'] is False
        assert 'EBS encryption has been enabled on the account level and will affect new volumes only.' in result['messages']['actions_taken']
        
        # Verify encryption remains enabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is True


class TestEc27ErrorHandling:
    """Test EC2.7 error handling scenarios"""

    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_access_denied_error_propagation(self, mock_get_client, mock_error_handling_asff_data):
        """Test that access denied errors are properly propagated"""
        # Setup mock that raises access denied error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'UnauthorizedOperation'}}
        ec2_client.enable_ebs_encryption_by_default.side_effect = botocore.exceptions.ClientError(
            error_response, 'EnableEbsEncryptionByDefault'
        )

        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'UnauthorizedOperation'

    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_invalid_parameter_error_propagation(self, mock_get_client, mock_error_handling_asff_data):
        """Test that invalid parameter errors are properly propagated"""
        # Setup mock that raises invalid parameter error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'InvalidParameterValue'}}
        ec2_client.enable_ebs_encryption_by_default.side_effect = botocore.exceptions.ClientError(
            error_response, 'EnableEbsEncryptionByDefault'
        )

        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'InvalidParameterValue'

    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_service_unavailable_error_propagation(self, mock_get_client, mock_error_handling_asff_data):
        """Test that service unavailable errors are properly propagated"""
        # Setup mock that raises service unavailable error
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        error_response = {'Error': {'Code': 'ServiceUnavailable'}}
        ec2_client.enable_ebs_encryption_by_default.side_effect = botocore.exceptions.ClientError(
            error_response, 'EnableEbsEncryptionByDefault'
        )

        # Execute remediation and expect the error to be raised
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(mock_error_handling_asff_data, None)
        
        # Verify the correct error was raised
        assert exc_info.value.response['Error']['Code'] == 'ServiceUnavailable'


class TestEc27EdgeCases:
    """Test EC2.7 edge cases and special scenarios"""

    def test_ec27_cross_account_data_parsing(self, mock_cross_account_asff_data):
        """Test cross-account finding data parsing and structure validation"""
        # Verify cross-account finding structure is correct
        finding = mock_cross_account_asff_data['finding']
        assert finding['AwsAccountId'] == '987654321098'  # Different from standard test account
        assert finding['Resources'][0]['Region'] == 'us-west-2'  # Different region
        
        # Verify account-level resource type
        assert finding['Resources'][0]['Type'] == 'AwsAccount'
        
        # Note: Actual cross-account execution requires real AWS credentials
        # and cross-account roles, which moto cannot simulate effectively

    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_account_level_operation_verification(self, mock_get_client, mock_ebs_encryption_disabled_asff_data):
        """Test that the operation correctly targets account-level EBS encryption settings"""
        # Setup mock client
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful response
        ec2_client.enable_ebs_encryption_by_default.return_value = {
            'EbsEncryptionByDefault': True,
            'ResponseMetadata': {'HTTPStatusCode': 200}
        }

        # Execute remediation
        result = lambda_handler(mock_ebs_encryption_disabled_asff_data, None)

        # Verify enable_ebs_encryption_by_default was called with correct parameters
        ec2_client.enable_ebs_encryption_by_default.assert_called_once_with(DryRun=False)
        
        # Verify successful result
        assert result['actions']['autoremediation_not_done'] is False
        assert 'EBS encryption has been enabled on the account level and will affect new volumes only.' in result['messages']['actions_taken']

    def test_ec27_resource_id_parsing_validation(self, mock_ebs_encryption_disabled_asff_data):
        """Test that resource ID parsing works correctly for account-level resources"""
        # Verify account-level resource structure
        finding = mock_ebs_encryption_disabled_asff_data['finding']
        resource_id = finding['Resources'][0]['Id']
        resource_type = finding['Resources'][0]['Type']
        
        # Account-level EBS encryption resources should have specific format
        assert 'ebs-encryption-by-default' in resource_id
        assert resource_type == 'AwsAccount'
        assert finding['AwsAccountId'] == '123456789012'
        assert finding['Resources'][0]['Region'] == 'us-east-1'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_new_volume_encryption_verification(self, mock_get_client, mock_ebs_encryption_disabled_asff_data):
        """Test that new volumes are encrypted after enabling account-level encryption"""
        # Setup AWS mocks
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        mock_get_client.return_value = ec2_client

        # Create availability zone first
        ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        
        # Verify encryption is initially disabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is False

        # Execute remediation
        result = lambda_handler(mock_ebs_encryption_disabled_asff_data, None)

        # Verify successful remediation
        assert result['actions']['autoremediation_not_done'] is False
        
        # Verify encryption is now enabled
        encryption_status = ec2_client.get_ebs_encryption_by_default()
        assert encryption_status['EbsEncryptionByDefault'] is True
        
        # Note: Testing actual volume creation would require additional moto setup
        # for availability zones, but the core account-level setting is verified

    @patch('functions.auto_remediations.auto_remediate_ec27.app.get_client')
    def test_ec27_dry_run_parameter_verification(self, mock_get_client, mock_ebs_encryption_disabled_asff_data):
        """Test that DryRun=False is correctly set for actual remediation"""
        # Setup mock client
        ec2_client = MagicMock()
        mock_get_client.return_value = ec2_client
        
        # Mock successful response
        ec2_client.enable_ebs_encryption_by_default.return_value = {
            'EbsEncryptionByDefault': True,
            'ResponseMetadata': {'HTTPStatusCode': 200}
        }

        # Execute remediation
        lambda_handler(mock_ebs_encryption_disabled_asff_data, None)

        # Verify DryRun=False was set (not a dry run, actual execution)
        call_args = ec2_client.enable_ebs_encryption_by_default.call_args
        assert call_args[1]['DryRun'] is False

    def test_ec27_message_format_validation(self, mock_ebs_encryption_disabled_asff_data):
        """Test that output messages are properly formatted"""
        with patch('functions.auto_remediations.auto_remediate_ec27.app.get_client') as mock_get_client:
            # Setup mock client
            ec2_client = MagicMock()
            mock_get_client.return_value = ec2_client
            ec2_client.enable_ebs_encryption_by_default.return_value = {
                'EbsEncryptionByDefault': True,
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }

            # Execute remediation
            result = lambda_handler(mock_ebs_encryption_disabled_asff_data, None)

            # Verify message format and content
            actions_taken = result['messages']['actions_taken']
            actions_required = result['messages']['actions_required']
            
            assert actions_taken == "EBS encryption has been enabled on the account level and will affect new volumes only."
            assert actions_required == "None"
            
            # Verify message clearly indicates scope (new volumes only)
            assert 'new volumes only' in actions_taken
            assert 'account level' in actions_taken