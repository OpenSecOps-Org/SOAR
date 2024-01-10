import os

PRODUCT_NAME = os.environ['PRODUCT_NAME']


def lambda_handler(data, _context):
    print(data)

    ticket_id = data['ticket_id']           # UUID
    finding_id = data['id']                 # ARN

    account_name = data.get('Account')      # Alphanumeric
    account_id = finding_id.split(':')[4]   # 12-digit string
    region = finding_id.split(':')[3]
    severity = data['severity_label']
    title = data['Title']
    control_id = data['SecurityControlId']
    age_txt = data['age_txt']
    environment = data['Environment']
    team = data['Team']

    subject = f"OVERDUE TEAM FIX: {control_id}: {title}"
    body = f'''\
OVERDUE TEAM FIX in account {account_name}

A ticket is overdue to be fixed.

Title: {control_id}: {title}
Age: {age_txt}
Severity: {severity}
Environment: {environment}

Region: {region}
Team: {team}
Account: {account_name} ({account_id})

Ticket ID: {ticket_id}
Finding ID: {finding_id}

It is of vital importance for the integrity and compliance of the system that security issues are fixed within their allotted time frame.

Please attend to fixing the ticket immediately. Thank you for your swift cooperation.

/ {PRODUCT_NAME}

'''

    messages = data.get('messages', {})
    messages['email'] = {
        'subject': subject,
        'body': body,
        'html': ''
    }
    data['messages'] = messages

    return data
