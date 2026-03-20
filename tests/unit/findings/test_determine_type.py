"""
Tests for the determine_type function.

This function classifies incidents into types (EC2, IAMUser, S3, EKS, Generic)
and decides whether to suppress, notify, terminate, or open tickets based on
severity and product type.

It only processes findings already classified as incidents by get_ticket_and_decide
(i.e., findings WITHOUT Compliance.SecurityControlId).
"""

import os

# Set environment variables before importing the module (module-level reads)
os.environ['GUARD_DUTY_EC2_TERMINATION_SEVERITIES'] = 'HIGH,CRITICAL'
os.environ['GUARD_DUTY_EC2_NOTIFICATION_SEVERITIES'] = 'INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL'
os.environ['GUARD_DUTY_IAM_USER_NOTIFICATION_SEVERITIES'] = 'INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL'
os.environ['GUARD_DUTY_S3_NOTIFICATION_SEVERITIES'] = 'INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL'
os.environ['GUARD_DUTY_EKS_NOTIFICATION_SEVERITIES'] = 'INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL'
os.environ['GENERIC_NOTIFICATION_SEVERITIES'] = 'INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL'
os.environ['SOC_TICKET_SEVERITIES'] = 'LOW,MEDIUM,HIGH,CRITICAL'
os.environ['IGNORE_PRODUCTS'] = 'none'

from functions.findings.determine_type.app import lambda_handler


def make_finding(**overrides):
    """Build a minimal incident finding with sensible defaults."""
    finding = {
        'AwsAccountId': '123456789012',
        'Severity': {'Label': 'HIGH', 'Normalized': 70},
        'ProductFields': {'aws/securityhub/ProductName': 'N/A'},
        'GeneratorId': 'generic-generator',
        'Title': 'Test finding title',
        'Description': 'Test finding description',
        'Types': ['Software and Configuration Checks'],
        'Resources': [{'Type': 'AwsEc2Instance', 'Id': 'i-1234567890', 'Region': 'us-east-1'}],
    }
    finding.update(overrides)
    return finding


def make_event(finding):
    """Wrap a finding in the SOAR scratchpad structure."""
    return {'finding': finding}


# ---------------------------------------------------------------------------
#  Compliance check (line 37) - THE BUG
# ---------------------------------------------------------------------------

class TestComplianceCheck:
    """
    Findings reaching determine_type are already classified as incidents
    (no SecurityControlId). Some may still carry partial Compliance data
    (e.g. a Status field). The current code suppresses any finding with
    truthy Compliance, which is wrong.
    """

    def test_finding_with_compliance_status_but_no_control_id_is_not_suppressed(self):
        """Incidents with Compliance metadata but no SecurityControlId must not be suppressed."""
        finding = make_finding(Compliance={'Status': 'FAILED'})
        result = lambda_handler(make_event(finding), None)
        assert result['type'] == 'Generic'
        assert result['suppress'] is False

    def test_finding_with_empty_compliance_is_not_suppressed(self):
        """Empty Compliance dict is falsy - finding passes through."""
        finding = make_finding(Compliance={})
        result = lambda_handler(make_event(finding), None)
        assert result.get('suppress') is not True or result.get('type') is not None

    def test_finding_with_no_compliance_is_not_suppressed(self):
        """No Compliance field at all - finding passes through normally."""
        finding = make_finding()
        result = lambda_handler(make_event(finding), None)
        assert result.get('type') == 'Generic'


# ---------------------------------------------------------------------------
#  IGNORE_PRODUCTS
# ---------------------------------------------------------------------------

class TestIgnoreProducts:

    def test_ignored_product_is_suppressed(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.IGNORE_PRODUCTS',
            ['SomeProduct']
        )
        finding = make_finding(
            ProductFields={'aws/securityhub/ProductName': 'SomeProduct'}
        )
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_non_ignored_product_is_not_suppressed(self):
        finding = make_finding(
            ProductFields={'aws/securityhub/ProductName': 'OtherProduct'}
        )
        result = lambda_handler(make_event(finding), None)
        assert result.get('type') == 'Generic'


# ---------------------------------------------------------------------------
#  GuardDuty EC2
# ---------------------------------------------------------------------------

class TestGuardDutyEC2:

    def _ec2_finding(self, severity='HIGH', types=None):
        return make_finding(
            Severity={'Label': severity, 'Normalized': 70},
            ProductFields={'aws/securityhub/ProductName': 'GuardDuty'},
            GeneratorId='arn:aws:guardduty:us-east-1:123456789012:detector/abc',
            Types=types or ['TTPs/Command and Control/EC2-MaliciousIPCaller'],
        )

    def test_ec2_high_severity_terminates_and_notifies(self):
        result = lambda_handler(make_event(self._ec2_finding('HIGH')), None)
        assert result['type'] == 'EC2'
        assert result['terminate'] is True
        assert result['suppress'] is False
        assert result['open_ticket'] is True

    def test_ec2_medium_severity_notifies_without_termination(self):
        result = lambda_handler(make_event(self._ec2_finding('MEDIUM')), None)
        assert result['type'] == 'EC2'
        assert result['terminate'] is False
        assert result['suppress'] is False

    def test_ec2_severity_not_in_notification_list_is_suppressed(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.GUARD_DUTY_EC2_NOTIFICATION_SEVERITIES',
            ['HIGH', 'CRITICAL']
        )
        monkeypatch.setattr(
            'functions.findings.determine_type.app.GUARD_DUTY_EC2_TERMINATION_SEVERITIES',
            ['CRITICAL']
        )
        result = lambda_handler(make_event(self._ec2_finding('LOW')), None)
        assert result['type'] == 'EC2'
        assert result['suppress'] is True

    def test_ec2_finding_type_is_extracted(self):
        result = lambda_handler(make_event(self._ec2_finding()), None)
        assert result['finding_type'] == 'TTPs/Command and Control/EC2-MaliciousIPCaller'


# ---------------------------------------------------------------------------
#  GuardDuty EKS
# ---------------------------------------------------------------------------

class TestGuardDutyEKS:

    def _eks_finding(self, severity='HIGH'):
        return make_finding(
            Severity={'Label': severity, 'Normalized': 70},
            ProductFields={'aws/securityhub/ProductName': 'GuardDuty'},
            GeneratorId='arn:aws:guardduty:us-east-1:123456789012:detector/abc',
            Types=['TTPs/Execution/Kubernetes-SuccessfulAnonymousAccess'],
        )

    def test_eks_notified_when_severity_in_list(self):
        result = lambda_handler(make_event(self._eks_finding('HIGH')), None)
        assert result['type'] == 'EKS'
        assert result['suppress'] is False
        assert result['terminate'] is False

    def test_eks_suppressed_when_severity_not_in_list(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.GUARD_DUTY_EKS_NOTIFICATION_SEVERITIES',
            ['HIGH', 'CRITICAL']
        )
        result = lambda_handler(make_event(self._eks_finding('LOW')), None)
        assert result['type'] == 'EKS'
        assert result['suppress'] is True


# ---------------------------------------------------------------------------
#  GuardDuty IAMUser
# ---------------------------------------------------------------------------

class TestGuardDutyIAMUser:

    def _iam_finding(self, severity='HIGH'):
        return make_finding(
            Severity={'Label': severity, 'Normalized': 70},
            ProductFields={'aws/securityhub/ProductName': 'GuardDuty'},
            GeneratorId='arn:aws:guardduty:us-east-1:123456789012:detector/abc',
            Types=['TTPs/Persistence/IAMUser-AnomalousBehavior'],
        )

    def test_iam_notified_when_severity_in_list(self):
        result = lambda_handler(make_event(self._iam_finding('HIGH')), None)
        assert result['type'] == 'IAMUser'
        assert result['suppress'] is False

    def test_iam_suppressed_when_severity_not_in_list(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.GUARD_DUTY_IAM_USER_NOTIFICATION_SEVERITIES',
            ['HIGH', 'CRITICAL']
        )
        result = lambda_handler(make_event(self._iam_finding('LOW')), None)
        assert result['type'] == 'IAMUser'
        assert result['suppress'] is True

    def test_iam_open_ticket_based_on_soc_severities(self):
        result = lambda_handler(make_event(self._iam_finding('HIGH')), None)
        assert result['open_ticket'] is True


# ---------------------------------------------------------------------------
#  GuardDuty S3
# ---------------------------------------------------------------------------

class TestGuardDutyS3:

    def _s3_finding(self, severity='HIGH'):
        return make_finding(
            Severity={'Label': severity, 'Normalized': 70},
            ProductFields={'aws/securityhub/ProductName': 'GuardDuty'},
            GeneratorId='arn:aws:guardduty:us-east-1:123456789012:detector/abc',
            Types=['TTPs/Exfiltration/S3-MaliciousIPCaller'],
        )

    def test_s3_notified_when_severity_in_list(self):
        result = lambda_handler(make_event(self._s3_finding('HIGH')), None)
        assert result['type'] == 'S3'
        assert result['suppress'] is False

    def test_s3_suppressed_when_severity_not_in_list(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.GUARD_DUTY_S3_NOTIFICATION_SEVERITIES',
            ['HIGH', 'CRITICAL']
        )
        result = lambda_handler(make_event(self._s3_finding('LOW')), None)
        assert result['type'] == 'S3'
        assert result['suppress'] is True


# ---------------------------------------------------------------------------
#  CIS Alarms
# ---------------------------------------------------------------------------

class TestCISAlarms:

    def _cis_finding(self):
        return make_finding(
            GeneratorId='CIS-3.1',
            ProductFields={'aws/securityhub/ProductName': 'CloudWatch'},
        )

    def test_cis_alarm_suppressed_when_in_ignore_products(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.IGNORE_PRODUCTS',
            ['cis-alarms']
        )
        result = lambda_handler(make_event(self._cis_finding()), None)
        assert result == {'suppress': True}

    def test_cis_alarm_becomes_generic_with_generator_as_finding_type(self):
        result = lambda_handler(make_event(self._cis_finding()), None)
        assert result['type'] == 'Generic'
        assert result['finding_type'] == 'CIS-3.1'


# ---------------------------------------------------------------------------
#  Access Analyzer false positive suppressions
# ---------------------------------------------------------------------------

class TestAccessAnalyzer:

    def _aa_finding(self, title, description='Some description'):
        return make_finding(
            GeneratorId='aws/access-analyzer',
            Title=title,
            Description=description,
            ProductFields={'aws/securityhub/ProductName': 'IAM Access Analyzer'},
        )

    def test_sso_cross_account_is_suppressed(self):
        finding = self._aa_finding('AwsIamRole/AWSReservedSSO_Admin allows cross-account access')
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_s3_cross_account_is_suppressed(self):
        finding = self._aa_finding('AwsS3Bucket/my-bucket allows cross-account access')
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_iam_federated_cross_account_is_suppressed(self):
        finding = self._aa_finding(
            'AwsIamRole/MyRole allows cross-account access',
            description='Federated access from external IdP'
        )
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_kms_cross_account_is_suppressed(self):
        finding = self._aa_finding('AwsKmsKey/key-id allows cross-account access')
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_ecr_cross_account_is_suppressed(self):
        finding = self._aa_finding('Other/arn:aws:ecr:us-east-1:111:repo allows cross-account access')
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_kms_public_access_is_suppressed(self):
        finding = self._aa_finding('AwsKmsKey/key-id allows public access')
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_non_matching_access_analyzer_is_not_suppressed(self):
        finding = self._aa_finding('AwsLambdaFunction/my-func allows cross-account access')
        result = lambda_handler(make_event(finding), None)
        assert result['type'] == 'Generic'
        assert result.get('suppress') is not True or result.get('type') is not None

    def test_access_analyzer_without_cross_account_title(self):
        finding = self._aa_finding('Some other Access Analyzer finding')
        result = lambda_handler(make_event(finding), None)
        assert result['type'] == 'Generic'


# ---------------------------------------------------------------------------
#  Macie false positive
# ---------------------------------------------------------------------------

class TestMacie:

    def test_macie_s3_external_share_is_suppressed(self):
        finding = make_finding(
            ProductFields={'aws/securityhub/ProductName': 'Macie'},
            GeneratorId='macie-generator',
            Types=['Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-S3BucketSharedExternally'],
        )
        result = lambda_handler(make_event(finding), None)
        assert result == {'suppress': True}

    def test_other_macie_finding_is_generic(self):
        finding = make_finding(
            ProductFields={'aws/securityhub/ProductName': 'Macie'},
            GeneratorId='macie-generator',
            Types=['Sensitive Data Identifications/PII/SensitiveData:S3Object-Financial'],
        )
        result = lambda_handler(make_event(finding), None)
        assert result['type'] == 'Generic'


# ---------------------------------------------------------------------------
#  Generic fallback
# ---------------------------------------------------------------------------

class TestGenericFallback:

    def test_generic_type_and_finding_type(self):
        finding = make_finding(
            Types=['Effects/Data Exposure/UnusualBehavior'],
        )
        result = lambda_handler(make_event(finding), None)
        assert result['type'] == 'Generic'
        assert result['finding_type'] == 'Effects/Data Exposure/UnusualBehavior'

    def test_generic_not_suppressed_when_severity_in_notification_list(self):
        finding = make_finding(Severity={'Label': 'HIGH', 'Normalized': 70})
        result = lambda_handler(make_event(finding), None)
        assert result['suppress'] is False

    def test_generic_suppressed_when_severity_not_in_notification_list(self, monkeypatch):
        monkeypatch.setattr(
            'functions.findings.determine_type.app.GENERIC_NOTIFICATION_SEVERITIES',
            ['HIGH', 'CRITICAL']
        )
        finding = make_finding(Severity={'Label': 'LOW', 'Normalized': 20})
        result = lambda_handler(make_event(finding), None)
        assert result['type'] == 'Generic'
        assert result['suppress'] is True

    def test_generic_opens_ticket_when_severity_in_soc_list(self):
        finding = make_finding(Severity={'Label': 'HIGH', 'Normalized': 70})
        result = lambda_handler(make_event(finding), None)
        assert result['open_ticket'] is True

    def test_generic_no_ticket_when_severity_not_in_soc_list(self):
        finding = make_finding(Severity={'Label': 'INFORMATIONAL', 'Normalized': 1})
        result = lambda_handler(make_event(finding), None)
        assert result['open_ticket'] is False
