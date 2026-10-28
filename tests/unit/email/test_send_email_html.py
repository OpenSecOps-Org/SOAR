"""
How send_email turns a ticket, autoremediation or incident, and the AI text about it, into the email's HTML,
and how it sends the weekly report's HTML.

clean_ai_html was written for models that mixed markdown into their HTML: it turns **bold** into <strong>,
dash lines into lists and blank lines into <br><br>. Claude Sonnet 4.5 and Claude Opus 5.5 write HTML only,
with newlines and indentation for readability and code snippets in <pre>. Applied to that, the markdown
conversion broke the code: blank lines became <br><br> and YAML list items ("- Effect: Allow") became
<ul><li> bullets inside the CloudFormation templates. Code blocks are now never touched, and output that is
already HTML gets only the **bold** conversion.
"""

import email
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from bs4 import BeautifulSoup

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
FUNCTION_DIR = os.path.join(ROOT, 'functions', 'email', 'send_email')

QUERY_AI_ENV = {'AI_PROVIDER': 'BEDROCK', 'AI_IAC_SNIPPETS': 'Cloudformation YAML',
                'AI_ANONYMIZE_ACCOUNT_NUMBERS': 'No', 'AI_ANONYMIZE_HEX_STRINGS': 'No', 'AI_REMOVE_ARNS': 'No',
                'AI_REMOVE_EMAIL_ADDRESSES': 'No', 'AI_CONFIG_PARAMETER': '/soar/ai/resolved-config',
                'AI_PROMPTS_TABLE': 'ai-prompts',
                'FALLBACK_SNS_TOPIC_ARN': 'arn:aws:sns:eu-north-1:111111111111:OpenSecOpsSOARAIFallbacks'}


@pytest.fixture(scope='module')
def query_ai():
    with patch.dict(os.environ, QUERY_AI_ENV):
        from functions.ai.query_ai import app as module
    return module


@pytest.fixture(scope='module')
def app():
    env = {'SEND_EMAIL': 'Yes', 'EMAIL_SENDER': 'sender@example.com', 'EMAIL_CC': '', 'EMAIL_BCC': '',
           'EMAIL_RETURN_PATH': 'bounces@example.com', 'PRODUCT_NAME': 'OpenSecOps SOAR'}
    cwd = os.getcwd()
    os.chdir(FUNCTION_DIR)  # the logo is read from a path relative to the function
    try:
        with patch.dict(os.environ, env), patch('boto3.client', return_value=MagicMock()):
            sys.modules.pop('functions.email.send_email.app', None)
            from functions.email.send_email import app as module
    finally:
        os.chdir(cwd)
    return module


YAML = """<pre style="background-color: #030204;">AWSTemplateFormatVersion: '2010-09-09'
Description: Example

Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
</pre>"""

HTML_OUTPUT = f"""<div style="font-family: Verdana, sans-serif; font-size:16px;">

<h3>Summary</h3>
<p>GuardDuty detected <strong>i-0123456789abcdef0</strong> resolving a mining pool - see below.</p>

<h3>Prevention</h3>
<p>Deploy this template:</p>
{YAML}
<ul>
  <li><strong>Patch</strong> the AMI.</li>
  <li>Restrict egress.</li>
</ul>
</div>"""


class TestCurrentModels:

    def test_code_blocks_are_left_exactly_as_written(self, app):
        assert YAML in app.clean_ai_html(HTML_OUTPUT)

    def test_html_output_gets_no_line_breaks_bullets_or_lists_added(self, app):
        result = app.clean_ai_html(HTML_OUTPUT)
        assert '<br>' not in result
        assert '•' not in result
        assert result.count('<ul>') == 1 and result.count('<li>') == 2

    def test_html_output_is_otherwise_unchanged(self, app):
        assert app.clean_ai_html(HTML_OUTPUT) == HTML_OUTPUT

    def test_stray_markdown_bold_is_still_converted(self, app):
        assert app.clean_ai_html('<p>This is **important**.</p>') == '<p>This is <strong>important</strong>.</p>'

    def test_markdown_bold_inside_code_is_left_alone(self, app):
        code = '<pre>echo "**not bold**"</pre>'
        assert app.clean_ai_html(f'<p>Run:</p>{code}') == f'<p>Run:</p>{code}'

    def test_code_block_cut_off_by_the_token_limit_is_left_alone(self, app):
        truncated = '<h3>Fix</h3>\n<pre>Statement:\n  - Effect: Allow\n\n  - Effect: **Deny'
        assert app.clean_ai_html(truncated) == truncated


class TestOlderModels:
    """Markdown-mixed output, as clean_ai_html was written for, is converted as before."""

    def test_bold(self, app):
        assert app.clean_ai_html('This is **important**.') == 'This is <strong>important</strong>.'

    def test_paragraphs(self, app):
        assert app.clean_ai_html('First paragraph.\n\nSecond paragraph.') == 'First paragraph.<br><br>Second paragraph.'

    def test_dash_lists(self, app):
        assert app.clean_ai_html('Steps:\n- one\n- two') == 'Steps:\n<ul>\n<li>one</li>\n<li>two</li>\n</ul>'

    def test_code_blocks_in_markdown_output_are_left_alone(self, app):
        code = '<pre>Statement:\n  - Effect: Allow\n\n  - Effect: Deny</pre>'
        result = app.clean_ai_html(f'Use **this**:\n\n{code}\n\n- one\n- two')
        assert code in result
        assert '<strong>this</strong>' in result and '<li>one</li>' in result


class TestEmailLayout:

    BODY = '\n'.join(['HIGH INCIDENT: Example', 'Example description', 'Account: 111111111111',
                      '====================', 'Finding ID: example'])

    def test_long_words_wrap_instead_of_widening_the_email(self, app):
        html = app.body_to_html(self.BODY, '', '<p>UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration</p>')
        ai_cell = next(line for line in html.splitlines() if 'InstanceCredentialExfiltration' in line)
        assert 'overflow-wrap: anywhere' in ai_cell and 'word-break: break-word' in ai_cell


# The plain-text body format_ticketing_message writes (shortened)
TICKET_BODY = '''\
HIGH issue in account "example-account" (111111111111, OU: Workloads), region eu-north-1:

EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22

This control checks whether security groups allow unrestricted SSH.

Resource ARN: arn:aws:ec2:eu-north-1:111111111111:security-group/sg-0123456789abcdef0
Resource type: AwsEc2SecurityGroup

- - -

ACTIONS REQUIRED ON YOUR PART: Restrict port 22 to known addresses.

Thank you for your immediate attention to this security issue.

/ OpenSecOps SOAR


=============================================================
- Id: sg-0123456789abcdef0
=============================================================
'''


def rows(html):
    return BeautifulSoup(html, 'html.parser').find_all('tr')


class TestPlainTextBody:
    """body_to_html: the formatter's plain-text body becomes the email's table layout."""

    @pytest.mark.parametrize('severity,colour', [('CRITICAL', '#800080'), ('HIGH', '#A00000'), ('MEDIUM', '#FFB060'),
                                                 ('LOW', '#EEEEC0'), ('INFORMATIONAL', '#F6F6F6')])
    def test_the_top_bar_has_the_severity_colour(self, app, severity, colour):
        html = app.body_to_html(TICKET_BODY.replace('HIGH', severity, 1), '', '')
        assert f'background-color:{colour}' in str(rows(html)[0])

    def test_the_first_line_is_the_title_and_the_second_the_heading(self, app):
        html = app.body_to_html(TICKET_BODY, '', '')
        assert rows(html)[1].h1.text.startswith('HIGH issue in account "example-account"')
        assert rows(html)[2].h2.text == 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22'

    def test_key_value_lines_become_label_rows(self, app):
        html = app.body_to_html(TICKET_BODY, '', '')
        assert ("<tr><td style='font-size:14px;'><b>Resource type</b></td>"
                "<td style='font-size:14px;'>AwsEc2SecurityGroup</td></tr>") in html

    def test_without_ai_text_the_description_and_actions_are_shown(self, app):
        html = app.body_to_html(TICKET_BODY, '', '')
        assert 'This control checks whether security groups allow unrestricted SSH.' in html
        assert 'ACTIONS REQUIRED ON YOUR PART: Restrict port 22 to known addresses.' in html

    def test_the_ai_text_takes_the_place_of_the_description_and_actions(self, app):
        html = app.body_to_html(TICKET_BODY, '', '<h3>Summary</h3><p>Port 22 is open to the internet.</p>')
        assert '<h3>Summary</h3><p>Port 22 is open to the internet.</p>' in html
        assert 'This control checks' not in html and 'ACTIONS REQUIRED' not in html

    def test_the_finding_data_after_the_separator_is_shown_in_grey(self, app):
        html = app.body_to_html(TICKET_BODY, '', '')
        grey = [row for row in rows(html) if 'background-color: #F0F0F0' in str(row)]
        assert grey[0].hr
        assert any(row.b and row.b.text == '- Id' and 'sg-0123456789abcdef0' in row.text for row in grey)


def sent_html(app, data):
    app.client.send_raw_email.reset_mock()
    app.lambda_handler(data, None)
    message = email.message_from_string(app.client.send_raw_email.call_args.kwargs['RawMessage']['Data'])
    part = next(part for part in message.walk() if part.get_content_type() == 'text/html')
    return part.get_payload(decode=True).decode()


class TestSentEmail:
    """lambda_handler: what goes out, for the weekly report's HTML and for a ticket with AI text."""

    REPORT = '<div><h1>Weekly report</h1><p>There were <strong>2 open tickets</strong>.</p><pre>a\n\n- b</pre></div>'

    def test_report_html_is_sent_as_written_with_the_logo_on_top(self, app):
        html = sent_html(app, {'Recipient': 'team@example.com', 'Subject': 'Weekly report', 'Html': self.REPORT})
        assert html == f'<html><head></head><body>{app.LOGO_HTML}{self.REPORT}</body></html>'

    def test_report_html_from_s3_is_sent_as_written_with_the_logo_on_top(self, app):
        page = f'<html><head></head><body>{self.REPORT}</body></html>'
        with patch.object(app, 'get_html_from_bucket', return_value=page):
            html = sent_html(app, {'Recipient': 'team@example.com', 'Subject': 'Weekly report',
                                   'HtmlArn': 'arn:aws:s3:::example-bucket/weekly-security-report-2026-10-26.html'})
        assert html == f'<html><head></head><body>{app.LOGO_HTML}{self.REPORT}</body></html>'

    def test_ticket_email_carries_the_ticket_id_and_the_ai_text(self, app):
        html = sent_html(app, {'Recipient': 'team@example.com', 'Subject': 'TEAM FIX: EC2.13', 'Body': TICKET_BODY,
                               'AiHtml': HTML_OUTPUT, 'AiPlaintext': '', 'TicketId': 'SEC-123'})
        assert "<b>Ticket ID</b></td><td style='font-size:14px;'>SEC-123</td>" in html
        assert YAML in html


# What Claude Opus 5.5 writes for an incident, shortened: bold, a list, a table, a dash used as punctuation,
# a long unbroken URL, and a CloudFormation snippet with YAML list items and a blank line
MODEL_OUTPUT = '''<div style="font-family: Verdana, sans-serif; font-size:16px;">
<h3>Summary</h3>
<p>The function <strong>example-function</strong> reported <strong>12 errors</strong> - all of them timeouts.</p>

<h3>Analysis</h3>
<ul>
  <li><strong>Cause:</strong> <code>https://api.example.com/v1/a/very/long/path/without/any/spaces/in/it</code> was slow.</li>
  <li>Retries doubled the load.</li>
</ul>
<table><tr><th>Severity</th><th>Errors</th></tr><tr><td>HIGH</td><td>12</td></tr></table>

<h3>Prevention</h3>
<p>Add an alarm:</p>
<pre>Resources:
  ErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      Dimensions:
        - Name: FunctionName
          Value: example-function

      Threshold: 1
</pre>
</div>'''


class TestIncidentEmailFromModelOutput:
    """The whole path: QueryAI styles the answer, send_email puts it in the email."""

    @pytest.fixture
    def rendered(self, app, query_ai):
        html = query_ai.format_pre_sections(query_ai.format_tables_inline(MODEL_OUTPUT))
        return BeautifulSoup(app.body_to_html(TICKET_BODY, '', html), 'html.parser')

    def test_the_code_reads_exactly_as_the_model_wrote_it(self, rendered):
        assert rendered.pre.get_text() == BeautifulSoup(MODEL_OUTPUT, 'html.parser').pre.get_text()
        assert rendered.pre['style'] == 'background-color: #030204; padding: 12px; color: #f8f9d2;'

    def test_bold_list_and_punctuation_are_unchanged(self, rendered):
        source = BeautifulSoup(MODEL_OUTPUT, 'html.parser')
        assert [str(tag) for tag in rendered.find_all('strong')] == [str(tag) for tag in source.find_all('strong')]
        assert [li.get_text() for li in rendered.find_all('li')] == [li.get_text() for li in source.find_all('li')]
        assert '12 errors</strong> - all of them timeouts.' in str(rendered)
        assert not rendered.find('br') and '•' not in str(rendered)

    def test_the_table_is_styled_and_the_severity_coloured(self, rendered):
        assert 'border: 1px solid black' in rendered.find('table', style=lambda s: 'EEEEEE' in (s or ''))['style']
        assert 'background-color: #FF0000' in rendered.find('td', string='HIGH')['style']

    def test_the_ai_text_sits_in_a_cell_that_wraps_long_words(self, rendered):
        cell = rendered.find('h3', string='Summary').find_parent('td')
        assert 'overflow-wrap: anywhere' in cell['style']
