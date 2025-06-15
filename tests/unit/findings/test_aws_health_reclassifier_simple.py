"""
Simple focused tests for AWS Health Reclassifier core logic.

This approach tests the core decision logic without complex environment/import issues.
"""

import pytest
import sys
import os

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'
os.environ['PRODUCT_NAME'] = 'OpenSecOps SOAR'
os.environ['RECLASSIFY_AWS_HEALTH_INCIDENTS'] = 'Yes'

from functions.findings.aws_health_reclassifier.app import should_reclassify_finding, is_aws_health_notification


class TestCoreLogic:
    """Test core decision logic without complex mocking"""

    def test_should_reclassify_operational_notification(self):
        """Test that operational notifications should be reclassified"""
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
        assert 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION' in result['reason']

    def test_should_reclassify_security_notification(self):
        """Test that security notifications should be reclassified"""
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
        assert 'AWS_CONTROLTOWER_SECURITY_NOTIFICATION' in result['reason']

    def test_should_not_reclassify_informational_finding(self):
        """Test that already INFORMATIONAL findings are not reclassified"""
        finding = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'INFORMATIONAL', 'Normalized': 1}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is False
        assert 'Finding already has INFORMATIONAL severity' in result['reason']

    def test_should_not_reclassify_non_aws_health_finding(self):
        """Test that non-AWS Health findings are not reclassified"""
        finding = {
            'Id': 'test-finding-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
            'ProductName': 'GuardDuty',
            'CompanyName': 'AWS',
            'GeneratorId': 'GuardDuty',
            'Types': ['TTPs'],
            'Severity': {'Label': 'HIGH', 'Normalized': 70}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is False
        assert 'Not AWS Health ProductArn' in result['reason']

    def test_should_not_reclassify_unknown_notification_type(self):
        """Test that unknown notification types are handled conservatively"""
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

    def test_should_not_reclassify_non_notification_pattern(self):
        """Test that non-notification patterns are not reclassified"""
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

    def test_is_aws_health_notification_valid(self):
        """Test valid AWS Health notification detection"""
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

    def test_is_aws_health_notification_invalid_product_arn(self):
        """Test invalid ProductArn detection"""
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

    def test_is_aws_health_notification_invalid_product_name(self):
        """Test invalid ProductName detection"""
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

    def test_is_aws_health_notification_invalid_company_name(self):
        """Test invalid CompanyName detection"""
        finding = {
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'SomeOtherCompany',
            'GeneratorId': 'AWS_INSPECTOR_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks']
        }
        
        result = is_aws_health_notification(finding)
        
        assert result['is_aws_health'] is False
        assert 'CompanyName is not AWS' in result['reason']

    def test_is_aws_health_notification_invalid_types(self):
        """Test invalid Types detection"""
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


class TestRealWorldExamples:
    """Test with real-world AWS Health notification examples"""

    def test_control_tower_metadata_update_classification(self):
        """Test Control Tower metadata update from our examples"""
        finding = {
            'Id': 'arn:aws:health:global:515966493378:event/CONTROLTOWER/AWS_CONTROLTOWER_SECURITY_NOTIFICATION/test-event-id',
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

    def test_iam_identity_center_cloudtrail_changes_classification(self):
        """Test IAM Identity Center CloudTrail changes from our examples"""
        finding = {
            'Id': 'arn:aws:health:eu-north-1:515966493378:event/IAMIDENTITYCENTER/AWS_IAMIDENTITYCENTER_SECURITY_NOTIFICATION/test-event-id',
            'ProductArn': 'arn:aws:securityhub:eu-north-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_IAMIDENTITYCENTER_SECURITY_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'HIGH', 'Normalized': 70}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is True
        assert 'AWS Health security notification (typically informational)' in result['reason']

    def test_inspector_retention_policy_change_classification(self):
        """Test Inspector retention policy change from our examples"""
        finding = {
            'Id': 'arn:aws:health:global:650251698273:event/INSPECTOR/AWS_INSPECTOR_OPERATIONAL_NOTIFICATION/test-event-id',
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

    def test_security_hub_operational_notification_classification(self):
        """Test Security Hub operational notification from our examples"""
        finding = {
            'Id': 'arn:aws:health:global:650251698273:event/SECURITYHUB/AWS_SECURITYHUB_OPERATIONAL_NOTIFICATION/test-event-id',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/health',
            'ProductName': 'Health',
            'CompanyName': 'AWS',
            'GeneratorId': 'AWS_SECURITYHUB_OPERATIONAL_NOTIFICATION',
            'Types': ['Software and Configuration Checks'],
            'Severity': {'Label': 'MEDIUM', 'Normalized': 40}
        }
        
        result = should_reclassify_finding(finding)
        
        assert result['should_reclassify'] is True
        assert 'AWS Health operational notification detected' in result['reason']