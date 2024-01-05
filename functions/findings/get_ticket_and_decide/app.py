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
    
    # Retrieve the ticket from DynamoDB using the finding ID and assign it to data['db']['tickets']
    data['db']['tickets'] = get_ticket(finding['Id'])

    # If ARCHIVED, SUPPRESSED, or RESOLVED, we must check for ticket closure
    if finding['RecordState'] == 'ARCHIVED' or workflow_status in ['SUPPRESSED', 'RESOLVED']:
        # If there's an open ticket in the finding, set up ticket_id accordingly
        if finding.get('UserDefinedFields', {}).get('TicketOpen') == 'Yes':
            data['ticket_id'] = finding['UserDefinedFields']['TicketId']
            data['ASFF_decision'] = 'close_ticket'
            data['ASFF_decision_reason'] = 'Finding has open ticket'
            return data

        # If there's an open ticket in the db, get the ticket_id from there
        if data['db']['tickets'].get('Item', {}).get('closed_at', '').startswith("NULL#"):
            data['ticket_id'] = data['db']['tickets']['Item']['ticket_id']['S']
            data['ASFF_decision'] = 'close_ticket'
            data['ASFF_decision_reason'] = 'DB has open ticket'
            return data

        # If no ticket, just return do_nothing 
        data['ASFF_decision'] = 'do_nothing'
        data['ASFF_decision_reason'] = 'No ticket for ARCHIVED, SUPPRESSED, or RESOLVED issue'
        return data

    # NOTIFIED?
    if workflow_status == 'NOTIFIED':
        data['ASFF_decision'] = 'do_nothing'
        data['ASFF_decision_reason'] = 'Notification has been done'
        return data
    
    # Compliance evaluation error?
    compliance_status = finding['Compliance']['Status']
    if compliance_status in ['WARNING', 'NOT_AVAILABLE']:
        data['ASFF_decision'] = 'suppress_finding'
        data['ASFF_decision_reason'] = 'Compliance evaluation error'
        return data
    
    # Is it a control?
    if finding['Compliance'].get('SecurityControlId'):
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

