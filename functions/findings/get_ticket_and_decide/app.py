import os
import boto3

TICKETS_TABLE_NAME = os.environ['TICKETS_TABLE_NAME']

# Initialize a DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TICKETS_TABLE_NAME)


def lambda_handler(data, _context):
    # If the SOAR isn't enabled, return 'do_nothing' at once
    SOAREnabled = data['SOAREnabled']
    if SOAREnabled != 'Yes':
        data['ASFF_decision'] = 'do_nothing'
        data['ASFF_decision_reason'] = 'SOAR is disabled'
        return data
    
    # For convenience 
    finding = data['finding']
    workflow_status = finding['Workflow']['Status']
    compliance = finding.get('Compliance', {})
    compliance_status = compliance.get('Status')
                                    
    # Retrieve the ticket from DynamoDB using the finding ID and assign it to data['db']['tickets']
    data['db']['tickets'] = get_ticket(finding['Id'])

    # Check if finding is resolved - this can happen multiple ways:
    # 1. RecordState = ARCHIVED (old AWS behavior for fixed findings)
    # 2. WorkflowStatus = SUPPRESSED or RESOLVED (explicit resolution)
    # 3. WorkflowStatus = NOTIFIED + ComplianceStatus = PASSED (new AWS behavior since July 3, 2025)
    is_resolved = (
        finding['RecordState'] == 'ARCHIVED' or
        workflow_status in ['SUPPRESSED', 'RESOLVED'] or
        (workflow_status == 'NOTIFIED' and compliance_status == 'PASSED')
    )

    if is_resolved:
        # Finding is resolved - check if there's an open ticket to close
        ticket_id = get_open_ticket_id(finding, data['db']['tickets'])
        if ticket_id:
            data['ticket_id'] = ticket_id
            data['ASFF_decision'] = 'close_ticket'
            data['ASFF_decision_reason'] = 'Finding resolved'
            return data

        # No ticket to close
        data['ASFF_decision'] = 'do_nothing'
        data['ASFF_decision_reason'] = 'No ticket for resolved issue'
        return data

    # NOTIFIED but not PASSED (already handled above if PASSED)
    if workflow_status == 'NOTIFIED':
        data['ASFF_decision'] = 'do_nothing'
        data['ASFF_decision_reason'] = 'Notification has been done'
        return data
    
    # Compliance evaluation error?
    if compliance_status and compliance_status in ['WARNING', 'NOT_AVAILABLE']:
        data['ASFF_decision'] = 'suppress_finding'
        data['ASFF_decision_reason'] = 'Compliance evaluation error'
        return data
    
    # Is it a control?
    if compliance.get('SecurityControlId'):
        # It is a control. Is it PASSED?
        if compliance_status == 'PASSED':
            # If passed, do nothing
            data['ASFF_decision'] = 'do_nothing'
            data['ASFF_decision_reason'] = 'PASSED control'
        else:
            # It's a failed control
            data['ASFF_decision'] = 'failed_control'
            data['ASFF_decision_reason'] = 'FAILED control'
        return data

    # Not a control, must be an incident. Deferred processing?
    if data['DeferIncidents'] == 'Yes':
        data['ASFF_decision'] = 'do_nothing'
        data['ASFF_decision_reason'] = 'Incident processing is deferred'
    else:
        # Not deferred, process the incident
        data['ASFF_decision'] = 'incident'
        data['ASFF_decision_reason'] = 'Finding is an incident'
    return data


def get_ticket(finding_id):
    # Attempt to get the item from DynamoDB
    response = table.get_item(
        Key={
            'id': finding_id  # Just pass the finding_id directly as a string
        }
    )

    # Return a dictionary with 'Item' if found, otherwise an empty dictionary
    return {'Item': response.get('Item')} if 'Item' in response else {}


def get_open_ticket_id(finding, db_tickets):
    """
    Get the ticket ID if there's an open ticket for this finding.
    Checks both UserDefinedFields and DynamoDB.

    Args:
        finding: The Security Hub finding
        db_tickets: DynamoDB tickets response from get_ticket()

    Returns:
        str: Ticket ID if found
        None: No open ticket
    """
    # Check UserDefinedFields first
    if finding.get('UserDefinedFields', {}).get('TicketOpen') == 'Yes':
        return finding['UserDefinedFields']['TicketId']

    # Check DynamoDB for open tickets (closed_at starts with "NULL#" means open)
    if db_tickets.get('Item', {}).get('closed_at', '').startswith("NULL#"):
        return db_tickets['Item']['ticket_id']['S']

    return None

