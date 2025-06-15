"""
Comprehensive tests for DynamoDB.2 auto-remediation function.

Tests the DynamoDB point-in-time recovery functionality including:
- Standard table point-in-time recovery enablement
- Cross-account operations
- Table ARN parsing and name extraction
- Tag-based exemption with pagination
- Environment variable configuration
- Error handling scenarios
"""

import pytest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
import botocore
import sys
import os

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['DYNAMODB_NO_PIT_RECOVERY_TAG'] = 'no-pit-recovery'

# Import test fixtures and data helpers
from tests.fixtures.security_hub_findings.dynamodb_findings import (
    get_dynamodb2_finding_standard,
    get_dynamodb2_finding_cross_account,
    get_dynamodb2_finding_different_region,
    get_dynamodb2_finding_complex_name,
    get_dynamodb2_finding_with_hyphens,
    get_dynamodb2_finding_eu_region
)
from tests.fixtures.asff_data import prepare_dynamodb_test_data

# Import the function under test
from functions.auto_remediations.auto_remediate_dynamodb2.app import lambda_handler


class TestAutoRemediateDynamoDB2:
    """Test suite for DynamoDB.2 auto-remediation function."""

    @mock_aws
    def test_successful_point_in_time_recovery_enablement(self):
        """Test successful point-in-time recovery enablement for DynamoDB table."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        table_arn = test_data['finding']['Resources'][0]['Id']
        expected_table_name = table_arn.rsplit('/', 1)[1]  # "test-table"
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag found)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Environment', 'Value': 'Production'}]}
            ]
            
            # Mock successful point-in-time recovery enablement
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                },
                'ContinuousBackupsDescription': {
                    'ContinuousBackupsStatus': 'ENABLED',
                    'PointInTimeRecoveryDescription': {
                        'PointInTimeRecoveryStatus': 'ENABLED'
                    }
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Point-in-time recovery has been enabled."
            assert result['actions']['suppress_finding'] is False
            assert result['actions']['autoremediation_not_done'] is False
            
            # Verify proper client calls
            mock_get_client.assert_called_with('dynamodb', '123456789012', 'us-east-1')
            mock_dynamodb.get_paginator.assert_called_with('list_tags_of_resource')
            mock_paginator.paginate.assert_called_with(ResourceArn=table_arn)
            mock_dynamodb.update_continuous_backups.assert_called_once_with(
                TableName=expected_table_name,
                PointInTimeRecoverySpecification={
                    'PointInTimeRecoveryEnabled': True
                }
            )

    @mock_aws
    def test_exemption_tag_suppresses_remediation(self):
        """Test that exemption tag suppresses the auto-remediation."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        table_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (exemption tag found)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [
                    {'Key': 'Environment', 'Value': 'Production'},
                    {'Key': 'no-pit-recovery', 'Value': 'true'}
                ]}
            ]
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The tag no-pit-recovery is present, suppressing the auto-remediation" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True
            
            # Verify that update_continuous_backups was NOT called
            mock_dynamodb.update_continuous_backups.assert_not_called()

    @mock_aws
    def test_exemption_tag_pagination_multiple_pages(self):
        """Test exemption tag detection across multiple pagination pages."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        table_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags across multiple pages (exemption tag on second page)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [
                    {'Key': 'Environment', 'Value': 'Production'},
                    {'Key': 'Owner', 'Value': 'TeamA'}
                ]},
                {'Tags': [
                    {'Key': 'Project', 'Value': 'WebApp'},
                    {'Key': 'no-pit-recovery', 'Value': 'exempt'}
                ]}
            ]
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The tag no-pit-recovery is present, suppressing the auto-remediation" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_missing_table_suppresses_finding(self):
        """Test that missing table suppresses the finding."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        table_arn = test_data['finding']['Resources'][0]['Id']
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Environment', 'Value': 'Production'}]}
            ]
            
            # Mock table not found error
            mock_dynamodb.update_continuous_backups.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'TableNotFoundException', 'Message': 'Table not found'}},
                'UpdateContinuousBackups'
            )
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The DynamoDB table wasn't found. Suppressing the finding" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True

    @mock_aws
    def test_cross_account_operation(self):
        """Test cross-account table point-in-time recovery enablement."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_cross_account)
        table_arn = test_data['finding']['Resources'][0]['Id']
        expected_table_name = table_arn.rsplit('/', 1)[1]  # "cross-account-table"
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Environment', 'Value': 'CrossAccount'}]}
            ]
            
            # Mock successful configuration
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Point-in-time recovery has been enabled."
            
            # Verify cross-account client creation
            mock_get_client.assert_called_with('dynamodb', '555666777888', 'us-east-1')
            mock_dynamodb.update_continuous_backups.assert_called_once_with(
                TableName=expected_table_name,
                PointInTimeRecoverySpecification={
                    'PointInTimeRecoveryEnabled': True
                }
            )

    @mock_aws
    def test_different_region_operation(self):
        """Test point-in-time recovery enablement in different regions."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_different_region)
        table_arn = test_data['finding']['Resources'][0]['Id']
        expected_table_name = table_arn.rsplit('/', 1)[1]  # "west-table"
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Region', 'Value': 'West'}]}
            ]
            
            # Mock successful configuration
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Point-in-time recovery has been enabled."
            
            # Verify different region client creation
            mock_get_client.assert_called_with('dynamodb', '123456789012', 'us-west-2')
            mock_dynamodb.update_continuous_backups.assert_called_once_with(
                TableName=expected_table_name,
                PointInTimeRecoverySpecification={
                    'PointInTimeRecoveryEnabled': True
                }
            )

    @mock_aws
    def test_table_arn_parsing_complex_name(self):
        """Test table ARN parsing for complex naming patterns."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_complex_name)
        table_arn = test_data['finding']['Resources'][0]['Id']
        expected_table_name = table_arn.rsplit('/', 1)[1]  # "production-user-sessions-v2"
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Application', 'Value': 'UserSessions'}]}
            ]
            
            # Mock successful configuration
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Point-in-time recovery has been enabled."
            
            # Verify correct table name parsing
            mock_dynamodb.update_continuous_backups.assert_called_once_with(
                TableName=expected_table_name,
                PointInTimeRecoverySpecification={
                    'PointInTimeRecoveryEnabled': True
                }
            )
            assert expected_table_name == "production-user-sessions-v2"

    @mock_aws
    def test_table_arn_parsing_with_hyphens(self):
        """Test table ARN parsing for hyphenated table names."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_with_hyphens)
        table_arn = test_data['finding']['Resources'][0]['Id']
        expected_table_name = table_arn.rsplit('/', 1)[1]  # "my-application-data"
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'DataType', 'Value': 'Application'}]}
            ]
            
            # Mock successful configuration
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert result['messages']['actions_taken'] == "Point-in-time recovery has been enabled."
            assert expected_table_name == "my-application-data"

    @mock_aws
    def test_api_error_handling(self):
        """Test handling of API errors other than TableNotFoundException."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Environment', 'Value': 'Test'}]}
            ]
            
            # Mock API error other than TableNotFoundException
            mock_dynamodb.update_continuous_backups.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid parameter'}},
                'UpdateContinuousBackups'
            )
            
            # Execute and verify exception is re-raised
            with pytest.raises(botocore.exceptions.ClientError):
                lambda_handler(test_data, {})

    @mock_aws
    def test_data_structure_integrity(self):
        """Test that the function preserves data structure integrity."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        original_account = test_data['account'].copy()
        original_tags = test_data['tags'].copy()
        original_db = test_data['db'].copy()
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Environment', 'Value': 'Test'}]}
            ]
            
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify original data sections are preserved
            assert result['account'] == original_account
            assert result['tags'] == original_tags
            assert result['db'] == original_db
            
            # Verify finding data is preserved
            assert result['finding'] == test_data['finding']

    @mock_aws
    def test_table_name_extraction_logic(self):
        """Test table name extraction from various ARN formats."""
        test_cases = [
            {
                'arn': 'arn:aws:dynamodb:us-east-1:123456789012:table/simple-table',
                'expected': 'simple-table'
            },
            {
                'arn': 'arn:aws:dynamodb:us-west-2:555666777888:table/production-data',
                'expected': 'production-data'
            },
            {
                'arn': 'arn:aws:dynamodb:eu-west-1:999888777666:table/user-sessions-v2',
                'expected': 'user-sessions-v2'
            }
        ]
        
        for test_case in test_cases:
            table_name = test_case['arn'].rsplit('/', 1)[1]
            assert table_name == test_case['expected'], f"Failed for ARN: {test_case['arn']}"

    @mock_aws
    def test_successful_response_format(self):
        """Test that successful responses follow the expected format."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (no exemption tag)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [{'Key': 'Environment', 'Value': 'Test'}]}
            ]
            
            # Mock successful API response
            mock_dynamodb.update_continuous_backups.return_value = {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200,
                    'RequestId': 'test-request-id'
                }
            }
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify response structure
            assert 'messages' in result
            assert 'actions_taken' in result['messages']
            assert 'actions' in result
            assert 'finding' in result
            
            # Verify specific message content
            assert result['messages']['actions_taken'] == "Point-in-time recovery has been enabled."

    @mock_aws
    def test_input_data_validation(self):
        """Test function behavior with various input data scenarios."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        
        # Verify the test data has expected structure
        assert 'finding' in test_data
        assert 'Resources' in test_data['finding']
        assert len(test_data['finding']['Resources']) > 0
        assert 'Id' in test_data['finding']['Resources'][0]
        assert 'Region' in test_data['finding']['Resources'][0]
        assert 'AwsAccountId' in test_data['finding']
        
        # Verify the table ARN format
        table_arn = test_data['finding']['Resources'][0]['Id']
        assert table_arn.startswith('arn:aws:dynamodb:')
        assert ':table/' in table_arn

    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_dynamodb2.app.DYNAMODB_NO_PIT_RECOVERY_TAG', 'custom-exemption-tag')
    def test_custom_environment_variable_tag(self):
        """Test that custom environment variable tag is respected."""
        # Setup
        test_data = prepare_dynamodb_test_data(get_dynamodb2_finding_standard)
        
        with patch('functions.auto_remediations.auto_remediate_dynamodb2.app.get_client') as mock_get_client:
            mock_dynamodb = Mock()
            mock_get_client.return_value = mock_dynamodb
            
            # Mock pagination for tags (custom exemption tag found)
            mock_paginator = Mock()
            mock_dynamodb.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {'Tags': [
                    {'Key': 'Environment', 'Value': 'Production'},
                    {'Key': 'custom-exemption-tag', 'Value': 'exempt'}
                ]}
            ]
            
            # Execute
            result = lambda_handler(test_data, {})
            
            # Verify
            assert "The tag custom-exemption-tag is present, suppressing the auto-remediation" in result['messages']['actions_taken']
            assert result['actions']['suppress_finding'] is True


if __name__ == '__main__':
    pytest.main([__file__])