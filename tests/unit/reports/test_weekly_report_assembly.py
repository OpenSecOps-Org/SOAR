"""
The weekly report's steps around postprocess_html: store_account_summary turns each account section's Summary
into text for the recommendations prompt, setup_to_send_to_account makes an account section into that
account's own email, and stitch_together_segments puts the sections together into the report that is sent.
"""

import importlib
import os
import re
import sys
from unittest.mock import MagicMock, patch

from bs4 import BeautifulSoup

ENV = {'AI_REPORT_TABLE': 'ai-report', 'BUCKET': 'example-report-bucket', 'PRODUCT_NAME': 'OpenSecOps SOAR'}


def load(name):
    with patch.dict(os.environ, ENV), patch('boto3.resource', return_value=MagicMock()), \
            patch('boto3.client', return_value=MagicMock()):
        sys.modules.pop(f'functions.reports.{name}.app', None)
        return importlib.import_module(f'functions.reports.{name}.app')


store_account_summary = load('store_account_summary')
setup_to_send_to_account = load('setup_to_send_to_account')
stitch_together_segments = load('stitch_together_segments')

# An account section as postprocess_html leaves it, shortened
ACCOUNT_SECTION = ('<h3>example-account</h3><p>A <strong>DEV</strong> account in the Sandbox OU.</p>'
                   '<h3>Tickets</h3><table><tr><td>HIGH</td></tr></table><p>One ticket.</p>'
                   '<h3>Summary</h3><p>One <strong>HIGH</strong> ticket, otherwise quiet.</p>')


class TestAccountSummary:

    def test_the_summary_subsection_becomes_text(self):
        assert store_account_summary.extract_summary(ACCOUNT_SECTION) == 'One **HIGH** ticket, otherwise quiet.'

    def test_without_a_summary_heading_the_whole_section_becomes_text(self):
        assert store_account_summary.extract_summary('<h3>example-account</h3><p>Quiet.</p>') == \
            '### example-account\n\nQuiet.'

    def test_the_summary_is_stored_under_the_account_name(self):
        with patch.object(store_account_summary, 'write_db_item') as write:
            store_account_summary.lambda_handler({'account': 'example-account', 'html': ACCOUNT_SECTION}, None)
        write.assert_called_once_with(store_account_summary.openai_report, 'Summary#example-account',
                                      'One **HIGH** ticket, otherwise quiet.')


class TestAccountEmail:

    def test_the_account_heading_gets_the_account_id_and_the_section_is_otherwise_unchanged(self):
        data = {'account': 'example-account', 'base_title': 'Weekly Security Report 2026-10-26',
                'bb': {'account_map': {'example-account': {'Id': '111111111111', 'Email': 'root@example.com',
                                                           'TeamEmail': 'team@example.com',
                                                           'TeamEmailApp': 'team@example.com'}}},
                'messages': {'report': {'html': ACCOUNT_SECTION}}}
        html = setup_to_send_to_account.lambda_handler(data, None)['email_html']
        assert html == ('<div style="font-family: Verdana, sans-serif; font-size:16px;">'
                        "<h1>Account 'example-account' Weekly Security Report 2026-10-26</h1>"
                        '<h2>example-account (111111111111)</h2>'
                        + ACCOUNT_SECTION.removeprefix('<h3>example-account</h3>') + '</div>')


class TestReport:

    def test_sections_are_put_together_in_order_with_headings_and_separators(self):
        sections = {'overview': '<p>Overview text.</p>', 'recommendations': '<p>Recommendations text.</p>',
                    'account-a': '<h3>account-a</h3>', 'account-b': '<h3>account-b</h3>'}
        with patch.object(stitch_together_segments, 'retrieve_db_item',
                          side_effect=lambda _table, key: {'html': sections[key]}), \
                patch.object(stitch_together_segments, 'write_to_s3', return_value='arn:aws:s3:::bucket/key') as write:
            stitch_together_segments.lambda_handler({'bb': {'accounts_with_issues': ['account-a', 'account-b']}},
                                                    None)
        report = write.call_args.args[0]
        h2 = stitch_together_segments.h2
        separator = '<hr style="border: none; border-top: 50px solid #d9c8e3; margin: 50px 0;">'
        assert re.fullmatch(
            re.escape('<div style="font-family: Verdana, sans-serif; font-size:16px;">'
                      '<h1>OpenSecOps SOAR Weekly Security Report ') + r'\d{4}-\d{2}-\d{2}' + re.escape(
                          f'</h1>{h2}Overview</h2><p>Overview text.</p>'
                          f'{h2}Recommendations</h2><p>Recommendations text.</p>'
                          f'{h2}Accounts with Issues This Week</h2><h3>account-a</h3>{separator}<h3>account-b</h3>'
                          '</div>'),
            report)

    def test_the_report_is_well_formed_html(self):
        with patch.object(stitch_together_segments, 'retrieve_db_item', return_value={'html': ACCOUNT_SECTION}), \
                patch.object(stitch_together_segments, 'write_to_s3', return_value='arn:aws:s3:::bucket/key') as write:
            stitch_together_segments.lambda_handler({'bb': {'accounts_with_issues': ['example-account']}}, None)
        report = write.call_args.args[0]
        assert str(BeautifulSoup(report, 'html.parser')) == report
