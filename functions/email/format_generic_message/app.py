"""
SOAR Email Formatting: Generic Security Hub Finding Message

This Lambda function formats Security Hub findings into email messages for incident
notification. Creates human-readable email content with all relevant finding details,
account information, and remediation guidance.

Email Content Includes:
- Incident severity and classification
- Resource details (ARN, type, region)
- Finding description and annotations
- Account metadata (name, ID, organizational unit)
- Team contact information
- Remediation instructions and required actions
- Technical details in YAML format for advanced users

Message Formatting:
- Subject line with severity and incident type
- Structured body with clear sections
- Actions required based on severity level
- Product branding and contact information
- Machine-readable technical appendix

Target Use: Security incident email notifications to development teams
Integration: Part of SOAR notification pipeline for Security Hub findings
"""

import yaml
import os

PRODUCT_NAME = os.environ['PRODUCT_NAME']


def lambda_handler(data, _context):
    """
    Main Lambda handler for formatting Security Hub findings as email messages.
    
    Args:
        data: SOAR finding data containing Security Hub finding and account information
        _context: Lambda context (unused)
        
    Returns:
        dict: Input data enhanced with formatted email message in messages.email
        
    Email Structure:
        - Subject: Severity-based incident notification
        - Body: Human-readable finding details with remediation guidance
        - Technical appendix: YAML dumps of resources, product fields, and account data
        
    Severity Handling:
        - INFORMATIONAL: No action required
        - LOW: Investigation optional
        - MEDIUM/HIGH/CRITICAL: Investigation required with remediation guidance
    """
    print(data)

    finding = data['finding']
    resources = {"Resources": finding['Resources']}
    product_name = finding['ProductFields'].get(
        'aws/securityhub/ProductName', 'N/A')
    product_fields = {"ProductFields": finding['ProductFields']}
    remediation = finding.get('Remediation', {})
    remediation_recommendation = remediation.get('Recommendation', {})
    remediation_text = remediation_recommendation.get('Text', False)
    remediation_url = remediation_recommendation.get('Url', False)

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

    if severity == 'INFORMATIONAL':
        actions_required = "None."
    elif remediation_text:
        actions_required = remediation_text
        if remediation_url:
            actions_required += "\n\nRemediation instructions can also be found here: " + remediation_url
    elif severity == 'LOW':
        actions_required = "None required as severity is LOW. However, you may want to investigate anyway."
    else:
        actions_required = "Please investigate."

    team_email = data['account']['TeamEmail']
    account_data = data['account']

    subject = f"INCIDENT: {title}"
    body = f'''\
{severity} INCIDENT in account "{account_name}" ({account_id}, OU: {organizational_unit}), region {resource_region}:

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
