"""
Tests for AWS Health Reclassifier function.

This function reclassifies AWS Health informational notifications from HIGH/MEDIUM/LOW/CRITICAL 
to INFORMATIONAL severity to prevent false positives in SOAR processing.

Test Coverage:
- Environment variable control (RECLASSIFY_AWS_HEALTH_INCIDENTS)
- AWS Health notification pattern detection
- Notification type classification (OPERATIONAL vs SECURITY)
- Security Hub API integration
- Error handling and fallback scenarios
- Termination vs continuation logic
"""

import pytest
import json
import sys
import os
import importlib
from unittest.mock import patch, MagicMock, call
import botocore.exceptions

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock default environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'
os.environ['PRODUCT_NAME'] = 'OpenSecOps SOAR'
os.environ['RECLASSIFY_AWS_HEALTH_INCIDENTS'] = 'No'

from tests.fixtures.asff_data import create_asff_test_data


class TestAWSHealthReclassifier:
    """Test AWS Health Reclassifier core functionality"""
    
    @pytest.fixture
    def mock_env_disabled(self, monkeypatch):
        """Environment with reclassification disabled"""
        monkeypatch.setenv('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'No')
        monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')
        monkeypatch.setenv('CROSS_ACCOUNT_ROLE', 'AWSControlTowerExecution')
        # Re-import the module to pick up new environment variables
        import importlib
        if 'functions.findings.aws_health_reclassifier.app' in sys.modules:
            importlib.reload(sys.modules['functions.findings.aws_health_reclassifier.app'])
    
    @pytest.fixture
    def mock_env_enabled(self, monkeypatch):
        """Environment with reclassification enabled"""
        monkeypatch.setenv('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'Yes')
        monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')
        monkeypatch.setenv('CROSS_ACCOUNT_ROLE', 'AWSControlTowerExecution')
        # Re-import the module to pick up new environment variables
        import importlib
        if 'functions.findings.aws_health_reclassifier.app' in sys.modules:
            importlib.reload(sys.modules['functions.findings.aws_health_reclassifier.app'])

    @pytest.fixture
    def aws_health_operational_finding(self):
        """AWS Health operational notification (should be reclassified)"""
        return {
            'Id': 'arn:aws:health:global:123456789012:event/INSPECTOR/AWS_INSPECTOR_OPERATIONAL_NOTIFICATION/test-event-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {
                'Label': 'MEDIUM',
                'Normalized': 40
            },
            'AwsAccountId': '123456789012',
            'Title': 'AWS Health - AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Description': 'You are receiving this message because you have enabled the Amazon Inspector service...'
        }

    @pytest.fixture
    def aws_health_security_finding(self):
        """AWS Health security notification (should be reclassified)"""
        return {
            'Id': 'arn:aws:health:global:123456789012:event/CONTROLTOWER/AWS_CONTROLTOWER_SECURITY_NOTIFICATION/test-event-id',
            'ProductArn': 'arn:aws:securityhub:eu-north-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_CONTROLTOWER_SECURITY_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {
                'Label': 'HIGH',
                'Normalized': 70
            },
            'AwsAccountId': '123456789012',
            'Title': 'AWS Health - AWS_CONTROLTOWER_SECURITY_NOTIFICATION',
            'Description': 'You are receiving this notification because you have at least one AWS Control Tower control enabled...'
        }

    @pytest.fixture
    def non_aws_health_finding(self):
        """Non-AWS Health finding (should not be reclassified)"""
        return {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
            'ProductName': 'GuardDuty',
            'CompanyName': 'AWS',
            'GeneratorId': 'GuardDuty',
            'Types': ['TTPs'],
            'Severity': {
                'Label': 'HIGH',
                'Normalized': 70
            },
            'AwsAccountId': '123456789012',
            'Title': 'Cryptocurrency mining activity',
            'Description': 'EC2 instance is communicating with a cryptocurrency mining pool...'
        }

    @pytest.fixture
    def aws_health_informational_finding(self):
        """AWS Health finding already INFORMATIONAL (should not be reclassified)"""
        return {
            'Id': 'arn:aws:health:global:123456789012:event/INSPECTOR/AWS_INSPECTOR_OPERATIONAL_NOTIFICATION/test-event-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {
                'Label': 'INFORMATIONAL',
                'Normalized': 1
            },
            'AwsAccountId': '123456789012',
            'Title': 'AWS Health - AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Description': 'You are receiving this message because you have enabled the Amazon Inspector service...'
        }

    def test_reclassifier_disabled_no_action(self, mock_env_disabled):
        """Test that reclassifier does nothing when disabled"""
        # Import after environment setup
        from functions.findings.aws_health_reclassifier.app import lambda_handler
        
        # Create test data with AWS Health finding
        finding_data = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'HIGH', 'Normalized': 70},
            'AwsAccountId': '123456789012'
        }
        
        asff_data = create_asff_test_data(finding_data)
        
        # Call function
        result = lambda_handler(asff_data, None)
        
        # Verify no reclassification occurred when disabled
        # No API update means no termination needed
        assert result['terminate_for_reprocessing'] is False
        assert result['finding']['Severity']['Label'] == 'HIGH'

    def test_operational_notification_reclassified(self, aws_health_operational_finding):
        """Test that operational notifications are reclassified to INFORMATIONAL"""
        
        # Set environment variable and reload module
        with patch.dict('os.environ', {'RECLASSIFY_AWS_HEALTH_INCIDENTS': 'Yes'}):
            with patch('aws_utils.clients.STS_CLIENT') as mock_sts, \
                 patch('boto3.client') as mock_boto_client:
                
                # Setup mock STS assume_role response
                mock_sts.assume_role.return_value = {
                    'Credentials': {
                        'AccessKeyId': 'MOCK_ACCESS_KEY',
                        'SecretAccessKey': 'MOCK_SECRET_KEY',
                        'SessionToken': 'MOCK_SESSION_TOKEN'
                    }
                }
                
                # Setup mock Security Hub client
                mock_client = MagicMock()
                mock_client.batch_update_findings.return_value = {
                    'ProcessedFindings': [{'Id': aws_health_operational_finding['Id']}],
                    'UnprocessedFindings': []
                }
                mock_boto_client.return_value = mock_client
                
                import functions.findings.aws_health_reclassifier.app
                importlib.reload(functions.findings.aws_health_reclassifier.app)
                from functions.findings.aws_health_reclassifier.app import lambda_handler
                
                asff_data = create_asff_test_data(aws_health_operational_finding)
                
                # Call function
                result = lambda_handler(asff_data, None)
                
                # Verify reclassification triggers termination for reprocessing
                # This follows the architecture: API Update → Event Trigger → Reprocessing
                assert result['terminate_for_reprocessing'] is True
                
                # Verify Security Hub API was called correctly
                mock_client.batch_update_findings.assert_called_once()
                
                # Check call arguments
                call_args = mock_client.batch_update_findings.call_args[1]
                assert call_args['FindingIdentifiers'][0]['Id'] == aws_health_operational_finding['Id']
                assert call_args['Severity']['Label'] == 'INFORMATIONAL'
                assert call_args['Severity']['Normalized'] == 1

    def test_security_notification_reclassified(self, aws_health_security_finding):
        """Test that security notifications are reclassified to INFORMATIONAL"""
        
        # Set environment variable and reload module
        with patch.dict('os.environ', {'RECLASSIFY_AWS_HEALTH_INCIDENTS': 'Yes'}):
            with patch('aws_utils.clients.STS_CLIENT') as mock_sts, \
                 patch('boto3.client') as mock_boto_client:
                
                # Setup mock STS assume_role response
                mock_sts.assume_role.return_value = {
                    'Credentials': {
                        'AccessKeyId': 'MOCK_ACCESS_KEY',
                        'SecretAccessKey': 'MOCK_SECRET_KEY',
                        'SessionToken': 'MOCK_SESSION_TOKEN'
                    }
                }
                
                # Setup mock Security Hub client
                mock_client = MagicMock()
                mock_client.batch_update_findings.return_value = {
                    'ProcessedFindings': [{'Id': aws_health_security_finding['Id']}],
                    'UnprocessedFindings': []
                }
                mock_boto_client.return_value = mock_client
                
                import functions.findings.aws_health_reclassifier.app
                importlib.reload(functions.findings.aws_health_reclassifier.app)
                from functions.findings.aws_health_reclassifier.app import lambda_handler
                
                asff_data = create_asff_test_data(aws_health_security_finding)
                
                # Call function
                result = lambda_handler(asff_data, None)
                
                # Verify reclassification triggers termination for reprocessing
                # This follows the architecture: API Update → Event Trigger → Reprocessing
                assert result['terminate_for_reprocessing'] is True
                
                # Verify Security Hub API was called correctly
                mock_client.batch_update_findings.assert_called_once()

    def test_non_aws_health_finding_ignored(self, mock_env_enabled, non_aws_health_finding):
        """Test that non-AWS Health findings are not reclassified"""
        # Import after environment setup
        from functions.findings.aws_health_reclassifier.app import lambda_handler
        
        asff_data = create_asff_test_data(non_aws_health_finding)
        
        # Call function
        result = lambda_handler(asff_data, None)
        
        # Verify no reclassification occurred - continue processing normally
        # No API update means no termination needed
        assert result['terminate_for_reprocessing'] is False

    def test_informational_finding_ignored(self, mock_env_enabled, aws_health_informational_finding):
        """Test that already INFORMATIONAL findings are not reclassified"""
        # Import after environment setup
        from functions.findings.aws_health_reclassifier.app import lambda_handler
        
        asff_data = create_asff_test_data(aws_health_informational_finding)
        
        # Call function
        result = lambda_handler(asff_data, None)
        
        # Verify no reclassification occurred - continue processing normally
        # Finding already INFORMATIONAL, no API update needed
        assert result['terminate_for_reprocessing'] is False

    def test_api_error_continues_processing(self, mock_env_enabled, aws_health_operational_finding):
        """Test that API errors result in continued processing with original severity"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            # Setup mock Security Hub client with error
            mock_client = MagicMock()
            mock_client.batch_update_findings.side_effect = Exception("Security Hub API error")
            mock_get_client.return_value = mock_client
            
            # Import after environment setup
            from functions.findings.aws_health_reclassifier.app import lambda_handler
            
            asff_data = create_asff_test_data(aws_health_operational_finding)
            
            # Call function
            result = lambda_handler(asff_data, None)
            
            # Verify processing continues with original severity (no termination)
            # This follows the architecture: if Security Hub update fails, continue processing
            assert result['terminate_for_reprocessing'] is False
            
            # Verify Security Hub API was attempted
            mock_get_client.assert_called_once_with('securityhub', aws_health_operational_finding['AwsAccountId'])
            mock_client.batch_update_findings.assert_called_once()


class TestAWSHealthNotificationDetection:
    """Test AWS Health notification pattern detection logic"""
    
    @pytest.fixture
    def mock_env_enabled(self, monkeypatch):
        """Environment with reclassification enabled"""
        monkeypatch.setenv('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'Yes')
        monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')

    def test_is_aws_health_notification_valid(self, mock_env_enabled):
        """Test valid AWS Health notification detection"""
        from functions.findings.aws_health_reclassifier.app import is_aws_health_notification
        
        finding = {
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks']
        }
        
        result = is_aws_health_notification(finding)
        
        assert result['is_aws_health'] is True
        assert 'AWS Health notification confirmed' in result['reason']

    def test_is_aws_health_notification_wrong_product_arn(self, mock_env_enabled):
        """Test detection fails with wrong ProductArn"""
        from functions.findings.aws_health_reclassifier.app import is_aws_health_notification
        
        finding = {
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks']
        }
        
        result = is_aws_health_notification(finding)
        
        assert result['is_aws_health'] is False
        assert 'Not AWS Health ProductArn' in result['reason']

    def test_is_aws_health_notification_wrong_product_name(self, mock_env_enabled):
        """Test detection fails with wrong ProductName"""
        from functions.findings.aws_health_reclassifier.app import is_aws_health_notification
        
        finding = {
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'GuardDuty',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks']
        }
        
        result = is_aws_health_notification(finding)
        
        assert result['is_aws_health'] is False
        assert 'ProductName is not Health' in result['reason']

    def test_is_aws_health_notification_wrong_types(self, mock_env_enabled):
        """Test detection fails with wrong Types"""
        from functions.findings.aws_health_reclassifier.app import is_aws_health_notification
        
        finding = {
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['TTPs']
        }
        
        result = is_aws_health_notification(finding)
        
        assert result['is_aws_health'] is False
        assert 'Types do not match AWS Health pattern' in result['reason']


class TestNotificationTypeClassification:
    """Test notification type classification logic"""
    
    @pytest.fixture
    def mock_env_enabled(self, monkeypatch):
        """Environment with reclassification enabled"""
        monkeypatch.setenv('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'Yes')
        monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')

    def test_operational_notification_classification(self, mock_env_enabled):
        """Test OPERATIONAL_NOTIFICATION is classified for reclassification"""
        from functions.findings.aws_health_reclassifier.app import should_reclassify_finding
        
        finding = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'MEDIUM', 'Normalized': 40}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is True
        assert 'AWS Health operational notification detected' in result['reason']

    def test_security_notification_classification(self, mock_env_enabled):
        """Test SECURITY_NOTIFICATION is classified for reclassification"""
        from functions.findings.aws_health_reclassifier.app import should_reclassify_finding
        
        finding = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_CONTROLTOWER_SECURITY_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'HIGH', 'Normalized': 70}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is True
        assert 'AWS Health security notification (typically informational)' in result['reason']

    def test_unknown_notification_conservative(self, mock_env_enabled):
        """Test unknown notification types are handled conservatively"""
        from functions.findings.aws_health_reclassifier.app import should_reclassify_finding
        
        finding = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_SOMESERVICE_UNKNOWN_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'HIGH', 'Normalized': 70}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is False
        assert 'Unknown AWS Health notification type, keeping original severity' in result['reason']

    def test_non_notification_pattern(self, mock_env_enabled):
        """Test non-notification patterns are not reclassified"""
        from functions.findings.aws_health_reclassifier.app import should_reclassify_finding
        
        finding = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_SOMESERVICE_ALERT',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'HIGH', 'Normalized': 70}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is False
        assert 'AWS Health finding but not a notification pattern' in result['reason']


class TestSecurityHubIntegration:
    """Test Security Hub API integration"""
    
    @pytest.fixture
    def mock_env_enabled(self, monkeypatch):
        """Environment with reclassification enabled"""
        monkeypatch.setenv('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'Yes')
        monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')
        monkeypatch.setenv('CROSS_ACCOUNT_ROLE', 'AWSControlTowerExecution')

    def test_successful_security_hub_update(self, mock_env_enabled):
        """Test successful Security Hub severity update"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            from functions.findings.aws_health_reclassifier.app import update_security_hub_severity
            
            # Mock Security Hub client
            mock_client = MagicMock()
            mock_client.batch_update_findings.return_value = {
                'ProcessedFindings': [{'Id': 'test-finding-id'}],
                'UnprocessedFindings': []
            }
            mock_get_client.return_value = mock_client
            
            finding = {
                'Id': 'test-finding-id',
                'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
                'AwsAccountId': '123456789012',
                'Severity': {'Label': 'HIGH', 'Normalized': 70}
            }
            
            # Call function
            update_security_hub_severity(finding)
            
            # Verify API call
            mock_get_client.assert_called_once_with('securityhub', '123456789012')
            mock_client.batch_update_findings.assert_called_once()
            
            # Check call arguments
            call_args = mock_client.batch_update_findings.call_args
            assert call_args[1]['FindingIdentifiers'][0]['Id'] == 'test-finding-id'
            assert call_args[1]['Severity']['Label'] == 'INFORMATIONAL'
            assert call_args[1]['Severity']['Normalized'] == 1
            assert 'HIGH to INFORMATIONAL' in call_args[1]['Note']['Text']

    def test_security_hub_unprocessed_findings_error(self, mock_env_enabled):
        """Test handling of unprocessed findings from Security Hub"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            from functions.findings.aws_health_reclassifier.app import update_security_hub_severity
            
            # Mock Security Hub client with unprocessed findings
            mock_client = MagicMock()
            mock_client.batch_update_findings.return_value = {
                'ProcessedFindings': [],
                'UnprocessedFindings': [{'Id': 'test-finding-id', 'ErrorCode': 'InvalidInput'}]
            }
            mock_get_client.return_value = mock_client
            
            finding = {
                'Id': 'test-finding-id',
                'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
                'AwsAccountId': '123456789012',
                'Severity': {'Label': 'HIGH', 'Normalized': 70}
            }
            
            # Should raise exception for unprocessed findings
            with pytest.raises(Exception) as exc_info:
                update_security_hub_severity(finding)
            
            assert 'Unprocessed findings' in str(exc_info.value)

    def test_security_hub_throttling_error(self, mock_env_enabled):
        """Test handling of Security Hub throttling"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            from functions.findings.aws_health_reclassifier.app import update_security_hub_severity
            
            # Mock Security Hub client with throttling error
            mock_client = MagicMock()
            throttling_error = botocore.exceptions.ClientError(
                error_response={'Error': {'Code': 'TooManyRequestsException'}},
                operation_name='BatchUpdateFindings'
            )
            mock_client.batch_update_findings.side_effect = throttling_error
            mock_get_client.return_value = mock_client
            
            finding = {
                'Id': 'test-finding-id',
                'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
                'AwsAccountId': '123456789012',
                'Severity': {'Label': 'HIGH', 'Normalized': 70}
            }
            
            # Should raise specific exception for throttling
            with pytest.raises(Exception) as exc_info:
                update_security_hub_severity(finding)
            
            assert 'TooManyRequestsException' in str(exc_info.value)

    def test_security_hub_generic_error(self, mock_env_enabled):
        """Test handling of generic Security Hub errors"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            from functions.findings.aws_health_reclassifier.app import update_security_hub_severity
            
            # Mock Security Hub client with generic error
            mock_client = MagicMock()
            generic_error = botocore.exceptions.ClientError(
                error_response={'Error': {'Code': 'InvalidParameter'}},
                operation_name='BatchUpdateFindings'
            )
            mock_client.batch_update_findings.side_effect = generic_error
            mock_get_client.return_value = mock_client
            
            finding = {
                'Id': 'test-finding-id',
                'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
                'AwsAccountId': '123456789012',
                'Severity': {'Label': 'HIGH', 'Normalized': 70}
            }
            
            # Should raise exception with API error details
            with pytest.raises(Exception) as exc_info:
                update_security_hub_severity(finding)
            
            assert 'Security Hub API error' in str(exc_info.value)


class TestRealWorldScenarios:
    """Test with real-world AWS Health notification examples"""
    
    @pytest.fixture
    def mock_env_enabled(self, monkeypatch):
        """Environment with reclassification enabled"""
        monkeypatch.setenv('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'Yes')
        monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')

    def test_control_tower_metadata_update(self, mock_env_enabled):
        """Test Control Tower metadata update notification (from our examples)"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            # Setup mock Security Hub client
            mock_client = MagicMock()
            mock_client.batch_update_findings.return_value = {
                'ProcessedFindings': [{'Id': 'test-finding-id'}],
                'UnprocessedFindings': []
            }
            mock_get_client.return_value = mock_client
            
            from functions.findings.aws_health_reclassifier.app import lambda_handler
            
            # Real-world Control Tower notification
            finding_data = {
                'Id': 'arn:aws:health:global:515966493378:event/CONTROLTOWER/AWS_CONTROLTOWER_SECURITY_NOTIFICATION/test-event-id',
                'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
                'ProductName': 'Health',
                'CompanyName': 'AWS',
                'GeneratorId': 'AWS_CONTROLTOWER_SECURITY_NOTIFICATION',
                'Types': ['Software and Configuration Checks'],
                'Severity': {'Label': 'HIGH', 'Normalized': 70},
                'AwsAccountId': '515966493378',
                'Title': 'AWS Health - AWS_CONTROLTOWER_SECURITY_NOTIFICATION',
                'Description': 'You are receiving this notification because you have at least one AWS Control Tower control enabled. We are excited to announce significant improvements to our control metadata definitions...'
            }
            
            asff_data = create_asff_test_data(finding_data)
            
            # Call function
            result = lambda_handler(asff_data, None)
            
            # Verify reclassification triggered
            assert result['terminate_for_reprocessing'] is True
            
            # Verify Security Hub API was called correctly
            mock_get_client.assert_called_once_with('securityhub', '515966493378')
            mock_client.batch_update_findings.assert_called_once()

    def test_iam_identity_center_cloudtrail_changes(self, mock_env_enabled):
        """Test IAM Identity Center CloudTrail changes notification (from our examples)"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            # Setup mock Security Hub client
            mock_client = MagicMock()
            mock_client.batch_update_findings.return_value = {
                'ProcessedFindings': [{'Id': 'test-finding-id'}],
                'UnprocessedFindings': []
            }
            mock_get_client.return_value = mock_client
            
            from functions.findings.aws_health_reclassifier.app import lambda_handler
            
            # Real-world IAM Identity Center notification
            finding_data = {
                'Id': 'arn:aws:health:eu-north-1:515966493378:event/IAMIDENTITYCENTER/AWS_IAMIDENTITYCENTER_SECURITY_NOTIFICATION/test-event-id',
                'ProductArn': 'arn:aws:securityhub:eu-north-1::product/aws/health',
                'ProductName': 'Health',
                'CompanyName': 'AWS',
                'GeneratorId': 'AWS_IAMIDENTITYCENTER_SECURITY_NOTIFICATION',
                'Types': ['Software and Configuration Checks'],
                'Severity': {'Label': 'HIGH', 'Normalized': 70},
                'AwsAccountId': '515966493378',
                'Title': 'AWS Health - AWS_IAMIDENTITYCENTER_SECURITY_NOTIFICATION',
                'Description': 'You are receiving this notification because you have an AWS IAM Identity Center instance. We are reminding you of previously announced changes to AWS CloudTrail fields...'
            }
            
            asff_data = create_asff_test_data(finding_data)
            
            # Call function
            result = lambda_handler(asff_data, None)
            
            # Verify reclassification triggered
            assert result['terminate_for_reprocessing'] is True
            
            # Verify Security Hub API was called correctly
            mock_get_client.assert_called_once_with('securityhub', '515966493378')
            mock_client.batch_update_findings.assert_called_once()

    def test_inspector_retention_policy_change(self, mock_env_enabled):
        """Test Inspector retention policy change notification (from our examples)"""
        
        with patch('functions.findings.aws_health_reclassifier.app.get_client') as mock_get_client:
            # Setup mock Security Hub client
            mock_client = MagicMock()
            mock_client.batch_update_findings.return_value = {
                'ProcessedFindings': [{'Id': 'test-finding-id'}],
                'UnprocessedFindings': []
            }
            mock_get_client.return_value = mock_client
            
            from functions.findings.aws_health_reclassifier.app import lambda_handler
            
            # Real-world Inspector notification  
            finding_data = {
                'Id': 'arn:aws:health:global:650251698273:event/INSPECTOR/AWS_INSPECTOR_OPERATIONAL_NOTIFICATION/test-event-id',
                'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
                'ProductName': 'Health',
                'CompanyName': 'AWS',
                'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
                'Types': ['Software and Configuration Checks'],
                'Severity': {'Label': 'MEDIUM', 'Normalized': 40},
                'AwsAccountId': '650251698273',
                'Title': 'AWS Health - AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
                'Description': 'You are receiving this message because you have enabled the Amazon Inspector service in one or more regions. On June 23, 2025, the retention period for closed findings will decrease to 3 days...'
            }
            
            asff_data = create_asff_test_data(finding_data)
            
            # Call function
            result = lambda_handler(asff_data, None)
            
            # Verify reclassification triggered
            assert result['terminate_for_reprocessing'] is True
            
            # Verify Security Hub API was called correctly
            mock_get_client.assert_called_once_with('securityhub', '650251698273')
            mock_client.batch_update_findings.assert_called_once()