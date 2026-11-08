"""Every finding formatter writes the layout send_email relies on.

send_email's body_to_html finds a finding's description by its position in the formatter's plain-text
body: after the title, before the first field, "Resource ARN: ". This runs each formatter's real output
through body_to_html, so a formatter that changes its layout fails here instead of silently hiding
descriptions in emails.
"""
import os
import sys
from importlib import import_module
from unittest.mock import MagicMock, patch

import pytest
from bs4 import BeautifulSoup

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
SEND_EMAIL_DIR = os.path.join(ROOT, 'functions', 'email', 'send_email')

FORMATTERS = [
    'format_generic_message',
    'format_guard_duty_ec2_message',
    'format_guard_duty_eks_message',
    'format_guard_duty_iam_user_message',
    'format_guard_duty_s3_message',
    'format_remediation_message',
    'format_ticket_closed_message',
    'format_ticketing_message',
]

# A description with ": " in it, and a second paragraph, as alarm findings have
FIRST_PARAGRAPH = 'EC2 instance i-0123 is querying a domain name: example.com.'
SECOND_PARAGRAPH = 'Alarm state reason: Threshold Crossed: 1 datapoint [1.0] was >= the threshold (1.0).'


@pytest.fixture(scope='module')
def send_email():
    env = {'SEND_EMAIL': 'Yes', 'EMAIL_SENDER': 'sender@example.com', 'EMAIL_CC': '', 'EMAIL_BCC': '',
           'EMAIL_RETURN_PATH': 'bounces@example.com', 'PRODUCT_NAME': 'OpenSecOps SOAR'}
    cwd = os.getcwd()
    os.chdir(SEND_EMAIL_DIR)  # the logo is read from a path relative to the function
    try:
        with patch.dict(os.environ, env), patch('boto3.client', return_value=MagicMock()):
            sys.modules.pop('functions.email.send_email.app', None)
            from functions.email.send_email import app as module
    finally:
        os.chdir(cwd)
    return module


def scratchpad():
    """Input with every field any of the finding formatters reads."""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:eu-north-1:111111111111:finding/example',
            'Title': 'Example finding title',
            'Description': f'{FIRST_PARAGRAPH}\n\n{SECOND_PARAGRAPH}',
            'Resources': [{'Type': 'AwsEc2Instance', 'Id': 'arn:aws:ec2:eu-north-1:111111111111:instance/i-0123',
                           'Region': 'eu-north-1'}],
            'ProductFields': {'aws/securityhub/ProductName': 'GuardDuty'},
            'Severity': {'Label': 'HIGH'},
            'Types': ['TTPs/Command and Control/Backdoor:EC2-C&CActivity.B!DNS'],
            'CreatedAt': '2026-11-08T10:00:00.000Z',
            'FirstObservedAt': '2026-11-08T10:00:00.000Z',
            'LastObservedAt': '2026-11-08T10:05:00.000Z',
            'AwsAccountId': '111111111111',
            'Remediation': {'Recommendation': {'Text': 'Isolate the instance.', 'Url': 'https://example.com/fix'}},
            'Compliance': {'Status': 'PASSED'},
            'Workflow': {'Status': 'RESOLVED'},
            'UserDefinedFields': {},
        },
        'account': {'Name': 'example-account', 'OrganizationalUnit': 'Workloads', 'TeamEmail': 'team@example.com'},
        'messages': {'actions_taken': 'None.', 'actions_required': 'Investigate.'},
        'incident': {'terminate': False},
    }


@pytest.mark.parametrize('formatter', FORMATTERS)
def test_formatter_output_shows_the_whole_description_as_text(formatter, send_email, monkeypatch):
    monkeypatch.setenv('PRODUCT_NAME', 'OpenSecOps SOAR')
    name = f'functions.email.{formatter}.app'
    sys.modules.pop(name, None)
    try:
        body = import_module(name).lambda_handler(scratchpad(), None)['messages']['email']['body']
    finally:
        sys.modules.pop(name, None)  # the formatters read PRODUCT_NAME at import; leave no copy for other tests

    for ai_html in ('', '<p>Analysis.</p>'):
        html = send_email.body_to_html(body, '', ai_html)
        texts = [row.text for row in BeautifulSoup(html, 'html.parser').find_all('tr')]
        assert FIRST_PARAGRAPH in texts, (formatter, ai_html)
        assert SECOND_PARAGRAPH in texts, (formatter, ai_html)
        assert texts.index(FIRST_PARAGRAPH) < texts.index(SECOND_PARAGRAPH)
        assert '<b>EC2 instance i-0123 is querying a domain name</b>' not in html
