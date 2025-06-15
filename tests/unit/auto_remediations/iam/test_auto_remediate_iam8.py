"""
Unit tests for IAM.8 auto-remediation function (Remove Unused IAM User Credentials)

This control checks whether IAM user credentials have not been used within the past 90 days.
IAM.8 removes unused IAM user credentials by deleting login passwords and access keys while
preserving the user account for potential reactivation.

CRITICAL SECURITY FUNCTION: This function removes authentication mechanisms across all AWS accounts.

Test triggers:
- User with login password: aws iam create-login-profile --user-name test-user
- User with access keys: aws iam create-access-key --user-name test-user
- Check credentials: aws iam get-login-profile --user-name test-user

The auto-remediation deletes login passwords and all active access keys for the user.
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
from asff_data import prepare_iam_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from iam_findings import (
    get_iam8_basic_finding,
    get_iam8_cross_account_finding,
    get_iam8_user_with_permissions_boundary,
    get_iam8_nonexistent_user_finding,
    get_iam8_malformed_arn_finding,
    get_iam8_missing_details_finding,
    get_iam8_empty_resources_finding,
    get_iam8_service_user_finding
)

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Import the lambda handler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_iam8'))
from functions.auto_remediations.auto_remediate_iam8.app import lambda_handler


class TestIam8SuccessScenarios:
    """Test successful IAM credential removal scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_basic_credential_removal(self, mock_get_client):
        """Test successful removal of login password and access keys"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock successful operations
        mock_iam_client.delete_login_profile.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        mock_iam_client.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAEXAMPLE1234567890',
                    'Status': 'Active',
                    'CreateDate': '2023-01-15T10:30:00Z'
                },
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAEXAMPLE0987654321',
                    'Status': 'Active',
                    'CreateDate': '2023-02-01T14:20:00Z'
                }
            ]
        }
        mock_iam_client.delete_access_key.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert result['actions']['autoremediation_not_done'] is False
        assert "The IAM User remains, but password and access keys have been deleted" in result['messages']['actions_taken']
        assert "Delete the user or contact an administrator to reactivate access" in result['messages']['actions_required']
        
        # Verify IAM API calls
        mock_iam_client.delete_login_profile.assert_called_once_with(UserName='unused-test-user')
        mock_iam_client.list_access_keys.assert_called_once_with(UserName='unused-test-user')
        
        # Verify both access keys were deleted
        expected_delete_calls = [
            {'UserName': 'unused-test-user', 'AccessKeyId': 'AKIAEXAMPLE1234567890'},
            {'UserName': 'unused-test-user', 'AccessKeyId': 'AKIAEXAMPLE0987654321'}
        ]
        assert mock_iam_client.delete_access_key.call_count == 2
        for call_args in mock_iam_client.delete_access_key.call_args_list:
            assert call_args[1] in expected_delete_calls
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('iam', '123456789012', 'us-east-1')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_cross_account_remediation(self, mock_get_client):
        """Test successful credential removal for cross-account IAM user"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock successful operations
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        
        # Prepare cross-account test data
        asff_data = prepare_iam_test_data(get_iam8_cross_account_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify correct cross-account parameters
        mock_iam_client.delete_login_profile.assert_called_once_with(UserName='cross-account-unused-user')
        mock_iam_client.list_access_keys.assert_called_once_with(UserName='cross-account-unused-user')
        
        # Verify cross-account client creation
        mock_get_client.assert_called_once_with('iam', '555666777888', 'us-west-2')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_user_with_inactive_access_keys(self, mock_get_client):
        """Test handling of user with mix of active and inactive access keys"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock operations with mixed active/inactive keys
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAACTIVE123456789',
                    'Status': 'Active',
                    'CreateDate': '2023-01-15T10:30:00Z'
                },
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAINACTIVE987654321',
                    'Status': 'Inactive',
                    'CreateDate': '2023-02-01T14:20:00Z'
                },
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAACTIVE555666777',
                    'Status': 'Active',
                    'CreateDate': '2023-03-01T09:15:00Z'
                }
            ]
        }
        mock_iam_client.delete_access_key.return_value = {}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify only active access keys were deleted (2 out of 3)
        assert mock_iam_client.delete_access_key.call_count == 2
        deleted_key_ids = [call[1]['AccessKeyId'] for call in mock_iam_client.delete_access_key.call_args_list]
        assert 'AKIAACTIVE123456789' in deleted_key_ids
        assert 'AKIAACTIVE555666777' in deleted_key_ids
        assert 'AKIAINACTIVE987654321' not in deleted_key_ids

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_user_with_no_access_keys(self, mock_get_client):
        """Test handling of user with no access keys (only login password)"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock operations with no access keys
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify login profile deletion was attempted
        mock_iam_client.delete_login_profile.assert_called_once_with(UserName='unused-test-user')
        mock_iam_client.list_access_keys.assert_called_once_with(UserName='unused-test-user')
        
        # Verify no access key deletion calls (empty list)
        mock_iam_client.delete_access_key.assert_not_called()

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_service_user_remediation(self, mock_get_client):
        """Test remediation of service account user with specific path"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock successful operations
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {
                    'UserName': 'ci-cd-service-user',
                    'AccessKeyId': 'AKIASERVICE123456789',
                    'Status': 'Active',
                    'CreateDate': '2023-01-01T00:00:00Z'
                }
            ]
        }
        mock_iam_client.delete_access_key.return_value = {}
        
        # Prepare test data for service user
        asff_data = prepare_iam_test_data(get_iam8_service_user_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify successful remediation
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify correct user name was used
        mock_iam_client.delete_login_profile.assert_called_once_with(UserName='ci-cd-service-user')
        mock_iam_client.list_access_keys.assert_called_once_with(UserName='ci-cd-service-user')
        mock_iam_client.delete_access_key.assert_called_once_with(
            UserName='ci-cd-service-user',
            AccessKeyId='AKIASERVICE123456789'
        )


class TestIam8ErrorHandling:
    """Test error handling scenarios and edge cases"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_no_login_profile_graceful_handling(self, mock_get_client):
        """Test graceful handling when user has no login profile"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock NoSuchEntityException for login profile deletion
        mock_iam_client.delete_login_profile.side_effect = mock_iam_client.exceptions.NoSuchEntityException(
            {'Error': {'Code': 'NoSuchEntity', 'Message': 'Login Profile for User unused-test-user cannot be found'}},
            'DeleteLoginProfile'
        )
        mock_iam_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should succeed despite NoSuchEntityException
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify exception was handled gracefully
        mock_iam_client.delete_login_profile.assert_called_once_with(UserName='unused-test-user')
        mock_iam_client.list_access_keys.assert_called_once_with(UserName='unused-test-user')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_list_access_keys_error_unhandled(self, mock_get_client):
        """Test that list_access_keys errors are not handled (CRITICAL GAP)"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock successful login profile deletion
        mock_iam_client.delete_login_profile.return_value = {}
        
        # Mock error in list_access_keys
        access_denied_error = botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'User not authorized to perform iam:ListAccessKeys'}},
            'ListAccessKeys'
        )
        mock_iam_client.list_access_keys.side_effect = access_denied_error
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same AccessDenied error
        assert exc_info.value == access_denied_error
        assert exc_info.value.response['Error']['Code'] == 'AccessDenied'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_delete_access_key_error_unhandled(self, mock_get_client):
        """Test that delete_access_key errors are not handled (CRITICAL GAP)"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock successful operations up to access key deletion
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAEXAMPLE1234567890',
                    'Status': 'Active'
                }
            ]
        }
        
        # Mock error in delete_access_key
        access_denied_error = botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'User not authorized to perform iam:DeleteAccessKey'}},
            'DeleteAccessKey'
        )
        mock_iam_client.delete_access_key.side_effect = access_denied_error
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Should raise unhandled exception due to missing error handling
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same AccessDenied error
        assert exc_info.value == access_denied_error
        assert exc_info.value.response['Error']['Code'] == 'AccessDenied'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_nonexistent_user_error_unhandled(self, mock_get_client):
        """Test that nonexistent user errors are not handled (CRITICAL GAP)"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock NoSuchEntityException for login profile (handled)
        mock_iam_client.delete_login_profile.side_effect = mock_iam_client.exceptions.NoSuchEntityException(
            {'Error': {'Code': 'NoSuchEntity', 'Message': 'User nonexistent-user does not exist'}},
            'DeleteLoginProfile'
        )
        
        # Mock NoSuchEntityException for list_access_keys (not handled)
        no_such_entity_error = botocore.exceptions.ClientError(
            {'Error': {'Code': 'NoSuchEntity', 'Message': 'The user with name nonexistent-user cannot be found'}},
            'ListAccessKeys'
        )
        mock_iam_client.list_access_keys.side_effect = no_such_entity_error
        
        # Prepare test data with nonexistent user
        asff_data = prepare_iam_test_data(get_iam8_nonexistent_user_finding)
        
        # Should raise unhandled exception for list_access_keys
        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the NoSuchEntity error from list_access_keys
        assert exc_info.value == no_such_entity_error
        assert exc_info.value.response['Error']['Code'] == 'NoSuchEntity'

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_get_client_failure_unhandled(self, mock_get_client):
        """Test that get_client failure causes unhandled exception"""
        # Mock get_client to raise an exception
        client_error = Exception("Failed to create IAM client")
        mock_get_client.side_effect = client_error
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Should raise unhandled exception since get_client is not in try-catch
        with pytest.raises(Exception) as exc_info:
            lambda_handler(asff_data, None)
        
        # Verify it's the same exception from get_client
        assert exc_info.value == client_error
        assert str(exc_info.value) == "Failed to create IAM client"


class TestIam8EdgeCases:
    """Test edge cases and malformed input scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_malformed_arn_exception(self, mock_get_client):
        """Test handling of malformed IAM user ARN"""
        # Setup mock IAM client (should not be called due to parsing failure)
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Prepare test data with malformed ARN
        asff_data = prepare_iam_test_data(get_iam8_malformed_arn_finding)
        
        # Should work fine since function only needs UserName from Details, not ARN parsing
        result = lambda_handler(asff_data, None)
        
        # Should succeed since ARN parsing is not required
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify function used UserName from Details section
        mock_iam_client.delete_login_profile.assert_called_once_with(UserName='malformed-arn-user')

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_missing_iam_user_details_exception(self, mock_get_client):
        """Test handling of missing IAM user details in ASFF finding"""
        # Setup mock IAM client (should not be called due to missing data)
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Prepare test data with missing details
        asff_data = prepare_iam_test_data(get_iam8_missing_details_finding)
        
        # Should raise exception due to missing Details section
        with pytest.raises(KeyError):
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_empty_resources_exception(self, mock_get_client):
        """Test handling of empty resources array"""
        # Setup mock IAM client (should not be called due to empty resources)
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Prepare test data with empty resources
        asff_data = prepare_iam_test_data(get_iam8_empty_resources_finding)
        
        # Should raise exception due to empty resources array
        with pytest.raises(IndexError):
            lambda_handler(asff_data, None)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_user_with_many_access_keys(self, mock_get_client):
        """Test handling of user with maximum number of access keys"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        
        # Mock operations with 2 access keys (AWS maximum per user)
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAKEY1234567890',
                    'Status': 'Active',
                    'CreateDate': '2023-01-15T10:30:00Z'
                },
                {
                    'UserName': 'unused-test-user',
                    'AccessKeyId': 'AKIAKEY0987654321',
                    'Status': 'Active',
                    'CreateDate': '2023-02-01T14:20:00Z'
                }
            ]
        }
        mock_iam_client.delete_access_key.return_value = {}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Should handle multiple keys successfully
        assert result['actions']['suppress_finding'] is False
        assert "password and access keys have been deleted" in result['messages']['actions_taken']
        
        # Verify both access keys were processed
        assert mock_iam_client.delete_access_key.call_count == 2


class TestIam8DataStructureAndIntegration:
    """Test data structure preservation and integration scenarios"""

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_data_structure_preservation(self, mock_get_client):
        """Test that original data structure is preserved during remediation"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_basic_finding)
        original_finding = asff_data['finding'].copy()
        original_actions = asff_data['actions'].copy()
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify original data structure is preserved
        assert result['finding'] == original_finding
        assert result['account'] == asff_data['account']
        assert result['tags'] == asff_data['tags']
        assert result['db'] == asff_data['db']
        
        # Verify actions remain unchanged (no suppression or failure flags)
        assert result['actions']['suppress_finding'] == original_actions['suppress_finding']
        assert result['actions']['autoremediation_not_done'] == original_actions['autoremediation_not_done']
        assert result['actions']['reconsider_later'] == original_actions['reconsider_later']

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_message_formatting(self, mock_get_client):
        """Test proper message formatting during successful remediation"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        
        # Prepare test data
        asff_data = prepare_iam_test_data(get_iam8_user_with_permissions_boundary)
        
        # Call the lambda handler
        result = lambda_handler(asff_data, None)
        
        # Verify message content and format
        actions_taken = result['messages']['actions_taken']
        actions_required = result['messages']['actions_required']
        
        assert "The IAM User remains, but password and access keys have been deleted" in actions_taken
        assert "Delete the user or contact an administrator to reactivate access" in actions_required
        
        # Verify messages are properly formatted strings
        assert isinstance(actions_taken, str)
        assert isinstance(actions_required, str)

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_iam8.app.get_client')
    def test_iam8_username_extraction_accuracy(self, mock_get_client):
        """Test accurate username extraction from different ASFF finding formats"""
        # Setup mock IAM client
        mock_iam_client = MagicMock()
        mock_get_client.return_value = mock_iam_client
        mock_iam_client.delete_login_profile.return_value = {}
        mock_iam_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        
        # Test different user scenarios
        test_cases = [
            (get_iam8_basic_finding, 'unused-test-user'),
            (get_iam8_cross_account_finding, 'cross-account-unused-user'),
            (get_iam8_user_with_permissions_boundary, 'boundary-test-user'),
            (get_iam8_service_user_finding, 'ci-cd-service-user')
        ]
        
        for finding_function, expected_username in test_cases:
            # Reset mock call history
            mock_iam_client.reset_mock()
            
            # Prepare test data
            asff_data = prepare_iam_test_data(finding_function)
            
            # Call the lambda handler
            result = lambda_handler(asff_data, None)
            
            # Verify correct username was extracted and used
            mock_iam_client.delete_login_profile.assert_called_once_with(UserName=expected_username)
            mock_iam_client.list_access_keys.assert_called_once_with(UserName=expected_username)
            
            # Verify successful processing
            assert result['actions']['suppress_finding'] is False
            assert "password and access keys have been deleted" in result['messages']['actions_taken']