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
    remediation_url = finding['Remediation']['Recommendation']['Url']
    resource_type = finding['Resources'][0]['Type']
    resource_arn = finding['Resources'][0]['Id']
    resource_region = finding['Resources'][0].get('Region', 'N/A')
    first_observed_at = finding['FirstObservedAt']
    last_observed_at = finding['LastObservedAt']

    actions_taken = data['messages']['actions_taken']
    if actions_taken != "":
        actions_taken = f"ACTIONS TAKEN: {actions_taken}\n\n"

    actions_required = data['messages']['actions_required']
    if actions_required != "":
        actions_required = f"ACTIONS REQUIRED ON YOUR PART: {actions_required}\n"

    team_email = data['account']['TeamEmail']
    account_data = data['account']

    subject = f"AUTOFIXED: {title_short}"
    body = f'''\
{severity} issue AUTOREMEDIATED in account "{account_name}" ({account_id}, OU: {organizational_unit}), region {resource_region}:

{title}

{description_and_annotation}

Resource ARN: {resource_arn}
Resource type: {resource_type}

Type: {issue_type}

Finding ID: {finding_id}
First observed: {first_observed_at}
Last observed: {last_observed_at}

Email sent by {PRODUCT_NAME} to: {team_email}

The issue has been resolved according to the following principles:
{remediation_url}

{actions_taken}{actions_required} 

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
