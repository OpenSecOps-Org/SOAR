"""
Unit tests for get_ticket_and_decide Lambda function

This function determines what action to take based on finding state:
- close_ticket: Finding is resolved and has an open ticket
- failed_control: Security control has failed
- incident: Non-control finding that needs processing
- suppress_finding: Compliance evaluation error
- do_nothing: All other cases

CRITICAL: These tests lock down existing behavior before refactoring.
Tests are organized to match decision flow in the actual code.
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add lambda layers to Python path
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables before importing the function
os.environ['TICKETS_TABLE_NAME'] = 'test-tickets-table'

# Import the function after environment setup
from functions.findings.get_ticket_and_decide.app import lambda_handler


# ============================================================================
# INLINE FIXTURES - Following enrich_cloudwatch_context pattern
# ============================================================================

def create_test_data(finding_data, soar_enabled='Yes', defer_incidents='No'):
    """
    Create test data structure matching asff_processor.asl.yaml lines 8-29
    """
    return {
        'SOAREnabled': soar_enabled,
        'DeferIncidents': defer_incidents,
        'finding': finding_data,
        'db': {'tickets': {}}  # Will be populated by test or get_ticket()
    }


def get_basic_finding():
    """Minimal finding for testing"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/test-finding',
        'AwsAccountId': '123456789012',
        'Title': 'Test Finding',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ACTIVE',
        'Compliance': {'Status': 'FAILED'}
    }


def get_archived_finding_with_userdefined_ticket():
    """ARCHIVED finding with open ticket in UserDefinedFields"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/archived-with-ticket',
        'AwsAccountId': '123456789012',
        'Title': 'Archived Finding With Ticket',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ARCHIVED',
        'Compliance': {'Status': 'FAILED'},
        'UserDefinedFields': {
            'TicketOpen': 'Yes',
            'TicketId': 'TICKET-12345'
        }
    }


def get_archived_finding_without_userdefined_ticket():
    """ARCHIVED finding without UserDefinedFields ticket (for DB ticket test)"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/archived-no-userdefined',
        'AwsAccountId': '123456789012',
        'Title': 'Archived Finding Without UserDefinedFields',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ARCHIVED',
        'Compliance': {'Status': 'FAILED'}
        # No UserDefinedFields - will check DB instead
    }


def get_archived_finding_no_ticket():
    """ARCHIVED finding with no ticket anywhere"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/archived-no-ticket',
        'AwsAccountId': '123456789012',
        'Title': 'Archived Finding No Ticket',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ARCHIVED',
        'Compliance': {'Status': 'FAILED'}
        # No UserDefinedFields, DB will return empty
    }


def get_notified_finding_failed_compliance():
    """NOTIFIED finding with FAILED compliance (normal case)"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/notified-failed',
        'AwsAccountId': '123456789012',
        'Title': 'Notified Finding Still Failed',
        'Workflow': {'Status': 'NOTIFIED'},
        'RecordState': 'ACTIVE',
        'Compliance': {'Status': 'FAILED'}
    }


def get_notified_finding_passed_compliance_with_ticket():
    """
    NOTIFIED finding with PASSED compliance and open ticket.

    THIS IS THE BUG: AWS changed behavior on July 3, 2025.
    Before: Finding would be ARCHIVED when fixed
    After: Finding stays ACTIVE with NOTIFIED + PASSED

    Current code returns do_nothing (WRONG)
    Should return close_ticket (CORRECT after fix)
    """
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/notified-passed-bug',
        'AwsAccountId': '123456789012',
        'Title': 'Notified Finding Now Passed',
        'Workflow': {'Status': 'NOTIFIED'},
        'RecordState': 'ACTIVE',
        'Compliance': {'Status': 'PASSED'},
        'UserDefinedFields': {
            'TicketOpen': 'Yes',
            'TicketId': 'TICKET-BUG-99999'
        }
    }


def get_compliance_warning_finding():
    """Finding with compliance evaluation WARNING status"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/compliance-warning',
        'AwsAccountId': '123456789012',
        'Title': 'Compliance Evaluation Warning',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ACTIVE',
        'Compliance': {'Status': 'WARNING'}
    }


def get_compliance_not_available_finding():
    """Finding with compliance evaluation NOT_AVAILABLE status"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/compliance-not-available',
        'AwsAccountId': '123456789012',
        'Title': 'Compliance Evaluation Not Available',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ACTIVE',
        'Compliance': {'Status': 'NOT_AVAILABLE'}
    }


def get_passed_control_finding():
    """Security control with PASSED compliance status"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/control-passed',
        'AwsAccountId': '123456789012',
        'Title': 'S3.2 S3 buckets should prohibit public access',
        'Workflow': {'Status': 'NEW'},  # Must be NEW to reach control logic (not RESOLVED)
        'RecordState': 'ACTIVE',
        'Compliance': {
            'Status': 'PASSED',
            'SecurityControlId': 'S3.2'
        }
    }


def get_failed_control_finding():
    """Security control with FAILED compliance status"""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/control-failed',
        'AwsAccountId': '123456789012',
        'Title': 'EC2.2 VPC default security group should not allow inbound traffic',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ACTIVE',
        'Compliance': {
            'Status': 'FAILED',
            'SecurityControlId': 'EC2.2'
        }
    }


def get_incident_finding():
    """
    Incident finding (non-control finding like GuardDuty, Inspector, etc.)

    Identified by absence of SecurityControlId in Compliance.
    """
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/guardduty-incident',
        'AwsAccountId': '123456789012',
        'Title': 'GuardDuty: Cryptocurrency mining activity detected',
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ACTIVE',
        'Compliance': {
            'Status': 'FAILED'
            # No SecurityControlId - this makes it an incident
        }
    }


# ============================================================================
# TEST CLASS 1: SOAR Disabled
# ============================================================================

class TestSOARDisabled:
    """Test SOAR disabled scenario (lines 12-17 in app.py)"""

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_soar_disabled(self, mock_table):
        """When SOAR disabled, return do_nothing immediately"""
        # Setup
        test_data = create_test_data(
            get_basic_finding(),
            soar_enabled='No'
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - should return do_nothing without calling DynamoDB
        assert result['ASFF_decision'] == 'do_nothing'
        assert result['ASFF_decision_reason'] == 'SOAR is disabled'

        # Verify DynamoDB was NOT called (early return)
        mock_table.get_item.assert_not_called()


# ============================================================================
# TEST CLASS 2: Ticket Closure (ARCHIVED/SUPPRESSED/RESOLVED)
# ============================================================================

class TestTicketClosure:
    """Test ticket closure scenarios (lines 28-47 in app.py)"""

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_archived_finding_with_userdefined_ticket(self, mock_table):
        """ARCHIVED finding with ticket in UserDefinedFields should close ticket"""
        # Setup
        mock_table.get_item.return_value = {}  # DB returns no ticket

        test_data = create_test_data(
            get_archived_finding_with_userdefined_ticket()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - should close ticket using UserDefinedFields
        assert result['ASFF_decision'] == 'close_ticket'
        assert result['ASFF_decision_reason'] == 'Finding resolved'
        assert result['ticket_id'] == 'TICKET-12345'

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_archived_finding_with_db_ticket(self, mock_table):
        """ARCHIVED finding with ticket in DB should close ticket"""
        # Setup - Mock DB returning open ticket
        mock_table.get_item.return_value = {
            'Item': {
                'ticket_id': {'S': 'DB-TICKET-789'},
                'closed_at': 'NULL#open'  # Open ticket marker
            }
        }

        test_data = create_test_data(
            get_archived_finding_without_userdefined_ticket()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - should close ticket using DB data
        assert result['ASFF_decision'] == 'close_ticket'
        assert result['ASFF_decision_reason'] == 'Finding resolved'
        assert result['ticket_id'] == 'DB-TICKET-789'

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_archived_finding_no_ticket(self, mock_table):
        """ARCHIVED finding with no ticket should return do_nothing"""
        # Setup - Mock DB returning no ticket
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_archived_finding_no_ticket()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - should return do_nothing
        assert result['ASFF_decision'] == 'do_nothing'
        assert result['ASFF_decision_reason'] == 'No ticket for resolved issue'


# ============================================================================
# TEST CLASS 3: NOTIFIED Workflow (THE BUG IS HERE)
# ============================================================================

class TestNotifiedWorkflow:
    """
    Test NOTIFIED workflow status scenarios (lines 49-53 in app.py)

    CRITICAL: AWS changed behavior on July 3, 2025:
    - Before: Fixed findings were ARCHIVED
    - After: Fixed findings stay ACTIVE with NOTIFIED + PASSED

    This breaks ticket closure logic.
    """

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_notified_with_failed_compliance_returns_do_nothing(self, mock_table):
        """NOTIFIED with FAILED compliance returns do_nothing (current correct behavior)"""
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_notified_finding_failed_compliance()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - NOTIFIED means notification already sent, do nothing
        assert result['ASFF_decision'] == 'do_nothing'
        assert result['ASFF_decision_reason'] == 'Notification has been done'

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_notified_with_passed_compliance_closes_ticket(self, mock_table):
        """
        NOTIFIED with PASSED compliance closes ticket (AWS behavior change fix)

        AWS changed behavior on July 3, 2025:
        - Before: Fixed findings were ARCHIVED
        - After: Fixed findings stay ACTIVE with NOTIFIED + PASSED

        This test verifies the fix handles the new AWS behavior correctly.
        """
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_notified_finding_passed_compliance_with_ticket()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - NOTIFIED + PASSED with open ticket should close the ticket
        assert result['ASFF_decision'] == 'close_ticket'
        assert result['ticket_id'] == 'TICKET-BUG-99999'
        assert result['ASFF_decision_reason'] == 'Finding resolved'


# ============================================================================
# TEST CLASS 4: Compliance Evaluation Errors
# ============================================================================

class TestComplianceErrors:
    """Test compliance evaluation error scenarios (lines 55-59 in app.py)"""

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_compliance_warning_suppressed(self, mock_table):
        """Compliance status WARNING should suppress finding"""
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_compliance_warning_finding()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - WARNING compliance should be suppressed
        assert result['ASFF_decision'] == 'suppress_finding'
        assert result['ASFF_decision_reason'] == 'Compliance evaluation error'

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_compliance_not_available_suppressed(self, mock_table):
        """Compliance status NOT_AVAILABLE should suppress finding"""
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_compliance_not_available_finding()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - NOT_AVAILABLE compliance should be suppressed
        assert result['ASFF_decision'] == 'suppress_finding'
        assert result['ASFF_decision_reason'] == 'Compliance evaluation error'


# ============================================================================
# TEST CLASS 5: Security Controls
# ============================================================================

class TestControls:
    """Test security control scenarios (lines 61-72 in app.py)"""

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_passed_control_do_nothing(self, mock_table):
        """Security control with PASSED compliance returns do_nothing"""
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_passed_control_finding()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - PASSED control should do nothing
        assert result['ASFF_decision'] == 'do_nothing'
        assert result['ASFF_decision_reason'] == 'PASSED control'

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_failed_control_decision(self, mock_table):
        """Security control with FAILED compliance returns failed_control"""
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_failed_control_finding()
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - FAILED control should return failed_control decision
        assert result['ASFF_decision'] == 'failed_control'
        assert result['ASFF_decision_reason'] == 'FAILED control'


# ============================================================================
# TEST CLASS 6: Incidents (Non-Control Findings)
# ============================================================================

class TestIncidents:
    """Test incident processing scenarios (lines 74-82 in app.py)"""

    @patch('functions.findings.get_ticket_and_decide.app.table')
    def test_incident_processed(self, mock_table):
        """Incident finding with DeferIncidents=No returns incident decision"""
        # Setup
        mock_table.get_item.return_value = {}

        test_data = create_test_data(
            get_incident_finding(),
            defer_incidents='No'
        )

        # Execute
        result = lambda_handler(test_data, None)

        # Verify - incident should be processed
        assert result['ASFF_decision'] == 'incident'
        assert result['ASFF_decision_reason'] == 'Finding is an incident'

