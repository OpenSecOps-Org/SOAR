import pytest
from unittest.mock import patch, MagicMock
import os
import sys

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

from functions.findings.account_reassignment_preprocessor.app import lambda_handler, must_recreate_in_other_account, recreate_asff_finding
from tests.fixtures.preprocessing_test_data import get_guardduty_finding_no_correction, get_access_analyzer_finding_needs_correction_1, get_finding_not_in_security_adm_account


# Global mocking fixture to prevent AWS API calls
@pytest.fixture(autouse=True)
def mock_aws_services():
    """Prevents ALL AWS API calls - MANDATORY for all test files."""
    patches = [
        patch('aws_utils.clients.get_client', side_effect=mock_get_client),
        patch('functions.findings.account_reassignment_preprocessor.app.get_client', side_effect=mock_get_client),
    ]
    
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in patches:
            p.stop()


# SERVICE_MOCK_CONFIGS for data-driven mocking
SERVICE_MOCK_CONFIGS = {
    'securityhub': {
        'batch_import_findings': {'FailedCount': 0, 'SuccessCount': 1},
        'get_paginator': []
    }
}


def mock_get_client(service, account_id=None, region=None, role_name=None):
    """Return a pure mock client configured from SERVICE_MOCK_CONFIGS."""
    client = MagicMock()
    config = SERVICE_MOCK_CONFIGS.get(service, {})
    
    for method_name, response in config.items():
        if isinstance(response, Exception):
            setattr(client, method_name, MagicMock(side_effect=response))
        else:
            setattr(client, method_name, MagicMock(return_value=response))
    
    return client


class TestAccountReassignmentPreprocessor:
    """Test class for Account Reassignment Preprocessor function."""

    def test_lambda_handler_returns_input_unchanged_noop(self):
        """Test that NOOP implementation returns data unchanged."""
        test_data = {
            'account': {'account_id': '123456789012'},
            'finding': {'Id': 'test-finding-id', 'AwsAccountId': '123456789012'},
            'tags': {},
            'actions': {},
            'messages': {},
            'db': {'tickets': {}}
        }
        
        result = lambda_handler(test_data, None)
        
        assert result == test_data
        assert 'terminate_for_reprocessing' not in result

    @patch.dict(os.environ, {'SECURITY_ADM_ACCOUNT': '111111111111'})
    def test_security_adm_account_environment_variable_available(self):
        """Test that Security-Adm account number is available as environment variable."""
        test_data = {
            'account': {'account_id': '123456789012'},
            'finding': {'Id': 'test-finding-id', 'AwsAccountId': '111111111111'},
            'tags': {},
            'actions': {},
            'messages': {},
            'db': {'tickets': {}}
        }
        
        result = lambda_handler(test_data, None)
        
        # Should still return unchanged for NOOP, but env var should be accessible
        assert result == test_data
        assert os.environ.get('SECURITY_ADM_ACCOUNT') == '111111111111'

    @patch.dict(os.environ, {'SECURITY_ADM_ACCOUNT': '111111111111'})
    def test_security_adm_account_matches_expected_value(self):
        """Test that Security-Adm account ID matches the expected delegated admin account."""
        test_data = {
            'account': {'account_id': '123456789012'},
            'finding': {
                'Id': 'test-finding-id', 
                'AwsAccountId': '111111111111',  # This should match SECURITY_ADM_ACCOUNT
                'ProductFields': {'ResourceOwnerAccount': '222222222222'}
            },
            'tags': {},
            'actions': {},
            'messages': {},
            'db': {'tickets': {}}
        }
        
        result = lambda_handler(test_data, None)
        
        # Should still return unchanged for NOOP
        assert result == test_data
        
        # Verify the Security-Adm account matches the finding's AwsAccountId for delegated findings
        security_adm_account = os.environ.get('SECURITY_ADM_ACCOUNT')
        finding_account = test_data['finding']['AwsAccountId']
        assert security_adm_account == finding_account == '111111111111'

    def test_function_returns_data_unchanged(self):
        """Test that the function returns the data structurally unchanged."""
        test_data = {
            'account': {'account_id': '123456789012', 'region': 'us-east-1'},
            'finding': {
                'Id': 'test-finding-id', 
                'AwsAccountId': '111111111111',
                'ProductFields': {'ResourceOwnerAccount': '222222222222'},
                'Resources': [{'Id': 'arn:aws:iam::222222222222:role/test-role'}]
            },
            'tags': {'env': 'test'},
            'actions': {'auto_remediation': False},
            'messages': {'notifications': []},
            'db': {'tickets': {'current': None}},
            'ASFF_decision': 'incident',
            'ASFF_decision_reason': 'test case'
        }
        
        result = lambda_handler(test_data, None)
        
        # Test that the data structure is unchanged
        assert result == test_data

    def test_must_recreate_in_other_account_function_exists(self):
        """Test that must_recreate_in_other_account function exists and is callable."""
        # Given: The function should exist
        # When: Importing and checking the function
        # Then: Function should exist and be callable
        assert callable(must_recreate_in_other_account)

    def test_must_recreate_in_other_account_returns_false_for_no_correction_needed(self):
        """Test that must_recreate_in_other_account returns False for finding that doesn't need correction."""
        # Given: A finding where resource account matches finding account (no correction needed)
        data = get_guardduty_finding_no_correction()
        
        # When: Checking if correction is needed
        result = must_recreate_in_other_account(data)
        
        # Then: Should return False (no correction needed)
        assert result is False

    def test_must_recreate_in_other_account_returns_target_account_for_correction_needed(self):
        """Test that must_recreate_in_other_account returns target account ID when correction is needed."""
        # Given: An IAM Access Analyzer finding where ResourceOwnerAccount differs from AwsAccountId
        data = get_access_analyzer_finding_needs_correction_1()
        
        # When: Checking if correction is needed
        result = must_recreate_in_other_account(data)
        
        # Then: Should return the target account ID (222222222222)
        assert result == '222222222222'

    def test_must_recreate_in_other_account_extracts_account_from_arn_when_no_resource_owner_account(self):
        """Test that account extraction works from ARN when ResourceOwnerAccount is not present."""
        # Given: A finding with no ResourceOwnerAccount but with resource ARN containing account ID
        data = get_access_analyzer_finding_needs_correction_1()
        # Remove ResourceOwnerAccount to test ARN parsing fallback
        del data['finding']['ProductFields']['ResourceOwnerAccount']
        
        # When: Checking if correction is needed
        result = must_recreate_in_other_account(data)
        
        # Then: Should still return the target account ID extracted from ARN (222222222222)
        assert result == '222222222222'

    def test_must_recreate_in_other_account_returns_false_when_no_account_extractable(self):
        """Test that function returns False when no account can be extracted from finding."""
        # Given: A finding with no ResourceOwnerAccount and no valid ARN
        data = get_guardduty_finding_no_correction()
        # Remove ResourceOwnerAccount if it exists
        data['finding']['ProductFields'].pop('ResourceOwnerAccount', None)
        # Replace resource with non-ARN format
        data['finding']['Resources'] = [{'Type': 'AwsIamAccessKey', 'Id': 'ASIATEST123456789'}]
        
        # When: Checking if correction is needed
        result = must_recreate_in_other_account(data)
        
        # Then: Should return False (no account could be extracted)
        assert result is False

    @patch.dict(os.environ, {'SECURITY_ADM_ACCOUNT': '111111111111'})
    def test_lambda_handler_returns_immediately_when_finding_not_in_security_adm_account(self):
        """Test that lambda_handler returns immediately when finding is not in security-adm account."""
        # Given: A finding that is NOT in the security-adm account
        data = get_finding_not_in_security_adm_account()
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should return data unchanged (no processing)
        assert result == data
        # And: Should not have any termination flag
        assert 'terminate_for_reprocessing' not in result

    def test_must_recreate_in_other_account_expects_finding_to_exist(self):
        """Test that function expects finding field to exist and fails with KeyError if missing."""
        # Given: Data with no finding field
        data = {'account': {}, 'actions': {}}
        
        # When: Checking if correction is needed
        # Then: Should raise KeyError because finding is expected to exist
        with pytest.raises(KeyError):
            must_recreate_in_other_account(data)

    def test_must_recreate_in_other_account_handles_empty_finding_gracefully(self):
        """Test that function handles empty finding field gracefully."""
        # Given: Data with empty finding field
        data = {'finding': {}, 'account': {}, 'actions': {}}
        
        # When: Checking if correction is needed
        result = must_recreate_in_other_account(data)
        
        # Then: Should return False (no correction needed)
        assert result is False

    def test_lambda_handler_handles_missing_finding_gracefully(self):
        """Test that lambda_handler handles missing finding field gracefully and returns data unchanged."""
        # Given: Data with no finding field (critical error condition)
        data = {'account': {}, 'actions': {}, 'messages': {}}
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should return data unchanged (no processing)
        assert result == data
        # And: Should not have any termination flag
        assert 'terminate_for_reprocessing' not in result

    def test_lambda_handler_handles_empty_finding_gracefully(self):
        """Test that lambda_handler handles empty finding field gracefully and returns data unchanged."""
        # Given: Data with empty finding field (critical error condition)
        data = {'finding': {}, 'account': {}, 'actions': {}, 'messages': {}}
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should return data unchanged (no processing)
        assert result == data
        # And: Should not have any termination flag
        assert 'terminate_for_reprocessing' not in result

    def test_must_recreate_in_other_account_handles_missing_aws_account_id_gracefully(self):
        """Test that function handles missing AwsAccountId field gracefully."""
        # Given: Data with finding but no AwsAccountId
        data = {
            'finding': {
                'Id': 'test-finding-id',
                'ProductFields': {'ResourceOwnerAccount': '222222222222'}
            }
        }
        
        # When: Checking if correction is needed
        result = must_recreate_in_other_account(data)
        
        # Then: Should return False (no correction needed)
        assert result is False

    @patch.dict(os.environ, {'SECURITY_ADM_ACCOUNT': '111111111111'})
    @patch('functions.findings.account_reassignment_preprocessor.app.recreate_asff_finding')
    def test_lambda_handler_sets_suppress_finding_flag_when_correction_needed(self, mock_recreate):
        """Test that lambda_handler sets actions.suppress_finding flag when account reassignment is needed and recreation succeeds."""
        # Given: Finding needing account reassignment and successful recreation
        mock_recreate.return_value = True  # Recreation succeeds
        data = get_access_analyzer_finding_needs_correction_1()
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should set actions.suppress_finding flag
        assert result['actions']['suppress_finding'] is True
        # And: Should not set terminate_for_reprocessing flag (obsolete pattern)
        assert 'terminate_for_reprocessing' not in result

    @patch.dict(os.environ, {'SECURITY_ADM_ACCOUNT': '111111111111'})
    def test_lambda_handler_does_not_set_suppress_finding_flag_when_no_correction_needed(self):
        """Test that lambda_handler does not set suppress_finding flag when no correction needed."""
        # Given: Finding not needing account reassignment (no ResourceOwnerAccount mismatch)
        data = get_guardduty_finding_no_correction()
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should not set actions.suppress_finding flag
        assert result['actions'].get('suppress_finding') is not True
        # And: Should not set terminate_for_reprocessing flag
        assert 'terminate_for_reprocessing' not in result

    def test_recreate_asff_finding_function_exists(self):
        """Test that recreate_asff_finding function exists and is callable."""
        # Given: The function should exist
        # When: Importing and checking the function
        # Then: Function should exist and be callable
        assert callable(recreate_asff_finding)

    def test_recreate_asff_finding_accepts_correct_parameters(self):
        """Test that recreate_asff_finding accepts account_id and data parameters."""
        # Given: Test data
        test_data = get_access_analyzer_finding_needs_correction_1()
        
        # When: Calling recreate_asff_finding with correct parameters
        # Then: Should not raise an exception about parameters
        try:
            result = recreate_asff_finding('222222222222', test_data)
            # Should return boolean (True/False)
            assert isinstance(result, bool)
        except TypeError as e:
            # Should not have parameter-related errors
            assert 'argument' not in str(e).lower()

    @patch('functions.findings.account_reassignment_preprocessor.app.recreate_asff_finding')
    def test_lambda_handler_calls_recreate_asff_finding_when_correction_needed(self, mock_recreate):
        """Test that lambda_handler calls recreate_asff_finding when correction is needed."""
        # Given: Function that needs correction and mock that returns True
        mock_recreate.return_value = True
        data = get_access_analyzer_finding_needs_correction_1()
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should call recreate_asff_finding with correct parameters
        mock_recreate.assert_called_once_with('222222222222', data)
        # And: Should set suppress_finding flag when recreate succeeds
        assert result['actions']['suppress_finding'] is True

    @patch('functions.findings.account_reassignment_preprocessor.app.recreate_asff_finding')
    def test_lambda_handler_does_not_set_suppress_flag_when_recreate_fails(self, mock_recreate):
        """Test that lambda_handler does not set suppress flag when recreate_asff_finding returns False."""
        # Given: Function that needs correction but mock that returns False (failure)
        mock_recreate.return_value = False
        data = get_access_analyzer_finding_needs_correction_1()
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should call recreate_asff_finding with correct parameters
        mock_recreate.assert_called_once_with('222222222222', data)
        # And: Should NOT set suppress_finding flag when recreate fails
        assert result['actions'].get('suppress_finding') is not True

    @patch('functions.findings.account_reassignment_preprocessor.app.recreate_asff_finding')
    def test_lambda_handler_does_not_call_recreate_when_no_correction_needed(self, mock_recreate):
        """Test that lambda_handler does not call recreate_asff_finding when no correction is needed."""
        # Given: Function that doesn't need correction
        data = get_guardduty_finding_no_correction()
        
        # When: Calling lambda_handler
        result = lambda_handler(data, None)
        
        # Then: Should not call recreate_asff_finding
        mock_recreate.assert_not_called()
        # And: Should not set suppress_finding flag
        assert result['actions'].get('suppress_finding') is not True

    def test_recreate_asff_finding_calls_batch_import_findings(self):
        """Test that recreate_asff_finding calls BatchImportFindings with corrected finding."""
        # Given: Mock Security Hub client configured through SERVICE_MOCK_CONFIGS
        
        # And: Test data with finding needing correction
        test_data = get_access_analyzer_finding_needs_correction_1()
        target_account = '222222222222'
        
        # When: Calling recreate_asff_finding
        result = recreate_asff_finding(target_account, test_data)
        
        # Then: Should return True for success (when implemented)
        # Note: Currently returns False because it's a stub
        
        # And: Should return True for success
        assert result is True

    @patch('functions.findings.account_reassignment_preprocessor.app.get_client')
    def test_recreate_asff_finding_returns_false_when_batch_import_fails(self, mock_get_client):
        """Test that recreate_asff_finding returns False when BatchImportFindings fails."""
        # Given: Mock Security Hub client with failed BatchImportFindings
        mock_client = MagicMock()
        mock_client.batch_import_findings.return_value = {
            'FailedCount': 1, 
            'SuccessCount': 0,
            'FailedFindings': [{'ErrorCode': 'InvalidInput', 'ErrorMessage': 'Test error'}]
        }
        mock_get_client.return_value = mock_client
        
        # And: Test data
        test_data = get_access_analyzer_finding_needs_correction_1()
        target_account = '222222222222'
        
        # When: Calling recreate_asff_finding
        result = recreate_asff_finding(target_account, test_data)
        
        # Then: Should return False for failure
        assert result is False

    @patch('functions.findings.account_reassignment_preprocessor.app.get_client')
    def test_recreate_asff_finding_returns_false_when_get_client_fails(self, mock_get_client):
        """Test that recreate_asff_finding returns False when get_client raises exception."""
        # Given: Mock get_client that raises exception
        mock_get_client.side_effect = Exception("Cross-account access failed")
        
        # And: Test data
        test_data = get_access_analyzer_finding_needs_correction_1()
        target_account = '222222222222'
        
        # When: Calling recreate_asff_finding
        result = recreate_asff_finding(target_account, test_data)
        
        # Then: Should return False for failure
        assert result is False

