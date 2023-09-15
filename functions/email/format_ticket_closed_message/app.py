import os
import yaml

PRODUCT_NAME = os.environ['PRODUCT_NAME']


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resources = {"Resources": finding['Resources']}
    product_fields = {"ProductFields": finding['ProductFields']}

    finding_id = finding['Id']
    organizational_unit = data['account']['OrganizationalUnit']
    title = finding['Title']
    title_short = title.split(' ', 1)[1] if ' ' in title else title
    description = finding['Description']
    annotation = finding['ProductFields'].get(
        'aws/securityhub/annotation', False)
    description_and_annotation = description
    if annotation:
        description_and_annotation += f"\n\n{annotation}"

    account_id = finding['AwsAccountId']
    account_name = data['account']['Name']
    severity = finding['Severity']['Label']
    issue_type = finding['Types'][0]
    resource_type = finding['Resources'][0]['Type']
    resource_arn = finding['Resources'][0]['Id']
    resource_region = finding['Resources'][0].get('Region', 'N/A')
    first_observed_at = finding['FirstObservedAt']
    last_observed_at = finding['LastObservedAt']

    workflow_status = finding['Workflow']['Status']

    compliance = finding['Compliance']
    compliance_status = compliance['Status']
    compliance_status_reasons = compliance.get('StatusReasons', [{}])
    compliance_status_reasons_description = compliance_status_reasons[0].get(
        'Description', None)
    compliance_status_reasons_reason_code = compliance_status_reasons[0].get(
        'ReasonCode', None)

    reason = "There are four possible reasons: (1) The issue may have been fixed, (2) the infrastructure itself may have been deleted, (3) the finding may have been suppressed, or (4) the control may have been disabled."

    if compliance_status_reasons_description:
        reason = f"{compliance_status_reasons_description} (Code: {compliance_status_reasons_reason_code})"

    user_defined_fields = finding.get('UserDefinedFields', {})
    ticket_open = user_defined_fields.get('TicketOpen', None)
    ticket_id = user_defined_fields.get('TicketId', None)
    ticket = f"Ticket ID: {ticket_id}\n\n" if ticket_open == 'Yes' else ''

    team_email = data['account']['TeamEmail']
    account_data = data['account']

    subject = f"CLOSED: {title_short}"
    body = f'''\
{severity} issue CLOSED in account "{account_name}" ({account_id}, OU: {organizational_unit}), region {resource_region}:

{title}

{description_and_annotation}

Resource ARN: {resource_arn}
Resource type: {resource_type}

Type: {issue_type}

Finding ID: {finding_id}
First observed: {first_observed_at}
Last observed: {last_observed_at}

Email sent by {PRODUCT_NAME} to: {team_email}

{ticket}
Workflow Status: {workflow_status}
Compliance Status: {compliance_status}

Reason for closing: {reason}

ACTIONS REQUIRED ON YOUR PART: None

Thank you.

/ {PRODUCT_NAME}


=============================================================
{yaml.dump(resources)}
=============================================================
{yaml.dump(product_fields)}
=============================================================
{yaml.dump(account_data)}
=============================================================
'''

    messages = data.get('messages', {})
    messages['email'] = {
        'subject': subject,
        'body': body,
        'html': ''
    }
    data['messages'] = messages

    return data
