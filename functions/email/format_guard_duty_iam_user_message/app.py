import os
import yaml

PRODUCT_NAME = os.environ['PRODUCT_NAME']


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resources = {"Resources": finding['Resources']}
    product_name = finding['ProductFields'].get(
        'aws/securityhub/ProductName', 'N/A')
    product_fields = {"ProductFields": finding['ProductFields']}

    finding_id = finding['Id']
    organizational_unit = data['account']['OrganizationalUnit']
    title = finding['Title']
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
    created_at = finding['CreatedAt']

    actions_taken = "None."
    if severity == 'INFORMATIONAL':
        actions_required = "None."
    elif severity == 'LOW':
        actions_required = "None required as severity is LOW. However, you may want to investigate anyway."
    else:
        actions_required = "Please investigate."

    team_email = data['account']['TeamEmail']
    account_data = data['account']

    subject = f"INCIDENT: {title}"
    body = f'''\
{severity} IAM-related INCIDENT in account "{account_name}" ({account_id}, OU: {organizational_unit}), region {resource_region}:

{title}

{description_and_annotation}

Resource ARN: {resource_arn}
Resource type: {resource_type}

Type: {issue_type}

Product name: {product_name}
Finding ID: {finding_id}
Created at: {created_at}

Email sent by {PRODUCT_NAME} to: {team_email}

- - -

ACTIONS TAKEN: {actions_taken}
ACTIONS REQUIRED: {actions_required}

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
