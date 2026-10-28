"""
postprocess_html turns the AI's HTML for one weekly-report section into the HTML that goes into the email.

The paragraph wrapping put every text node that was not directly inside p/h1-h6/td/th into a <p> of its own,
including the text inside <strong>, so "There were <strong>0 open tickets</strong> and ..." became
"There were <strong><p>0 open tickets</p></strong> and ..." and every figure stood on a line of its own. Every
bold in the reports sent since October 2025 was broken this way. It showed every week once SOAR 4.0.0 moved to
Claude Opus 5.5, which uses bold far more than Claude Sonnet 4.5 did, whatever the prompts say about bold.
Claude Opus 5.5 also puts the table placeholders inside <p>, which put tables inside paragraphs.
"""

import os
import re
import sys

from bs4 import BeautifulSoup

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from functions.reports.postprocess_html.app import (format_pre_sections, format_tables_inline, lambda_handler,
                                                    process_html_substitutions, wrap_unwrapped_text)

TABLE = '<table><thead><tr><th>Severity</th><th>This week</th></tr></thead><tbody><tr><td>HIGH</td><td></td></tr></tbody></table>'


def process(html, substitutions=None):
    data = {'messages': {'ai': {'html': html}}, 'html_substitutions': substitutions or {}}
    return lambda_handler(data, None)['messages']['report']['html']


# ---------------------------------------------------------------------------
# What Claude Opus 5.5 writes
# ---------------------------------------------------------------------------

def test_bold_text_inside_a_paragraph_stays_inline():
    html = '<p>There were <strong>0 open tickets</strong> and <strong>0 overdue tickets</strong> this week.</p>'
    assert process(html) == html


def test_loose_text_and_inline_tags_become_one_paragraph():
    assert wrap_unwrapped_text('This week there were <strong>0 autoremediations</strong>, spread over '
                               '<strong>0 accounts</strong>.') == \
        '<p>This week there were <strong>0 autoremediations</strong>, spread over <strong>0 accounts</strong>.</p>'


def test_inline_tags_are_never_given_paragraphs_of_their_own():
    for tag in ('strong', 'b', 'em', 'i', 'a', 'span', 'code'):
        assert f'<{tag}><p>' not in wrap_unwrapped_text(f'<p>Some <{tag}>text</{tag}> here</p>')
        assert f'<{tag}><p>' not in wrap_unwrapped_text(f'Some <{tag}>text</{tag}> here')


def test_a_placeholder_paragraph_does_not_put_the_table_inside_a_paragraph():
    html = '<h3>Tickets</h3><p>Two tickets.</p><p>[[INSERT open_tickets_table]]</p>'
    result = process(html, {'open_tickets_table': TABLE})
    assert '<p><table' not in result and '</table></p>' not in result
    assert result.startswith('<h3>Tickets</h3><p>Two tickets.</p><table') and result.endswith('</table>')


def test_list_items_with_bold_text_read_as_one_line_each():
    assert wrap_unwrapped_text('<ul><li><strong>Infra:</strong> enable logging.</li><li>Rotate keys.</li></ul>') == \
        '<ul><li><p><strong>Infra:</strong> enable logging.</p></li><li><p>Rotate keys.</p></li></ul>'


# ---------------------------------------------------------------------------
# What Claude Sonnet 4.5 wrote renders as it did
# ---------------------------------------------------------------------------

def test_plain_paragraphs_headings_and_tables_are_unchanged():
    html = '<h3>Tickets</h3>\n<p>There were no open tickets this week.</p>\n' + TABLE + '\n<h3>Outlook</h3>\n<p>Quiet.</p>'
    assert wrap_unwrapped_text(html) == html


def test_list_items_get_a_paragraph_as_before():
    assert wrap_unwrapped_text('<ol><li>Review policies</li><li>Verify coverage</li></ol>') == \
        '<ol><li><p>Review policies</p></li><li><p>Verify coverage</p></li></ol>'


def test_loose_text_between_blocks_is_wrapped_as_before():
    assert wrap_unwrapped_text('<h3>Outlook</h3>Continue monitoring.<h3>Next</h3>') == \
        '<h3>Outlook</h3><p>Continue monitoring.</p><h3>Next</h3>'


def test_table_cells_and_preformatted_text_are_left_alone():
    html = TABLE + '<pre>code here</pre>'
    assert wrap_unwrapped_text(html) == html


def test_whitespace_is_not_wrapped():
    assert '<p>' not in wrap_unwrapped_text('<h3>A</h3>\n\n<h3>B</h3>')


# ---------------------------------------------------------------------------
# The other steps: table placeholders, table styling, code blocks
# ---------------------------------------------------------------------------

def test_placeholders_are_replaced_by_their_tables_and_unknown_ones_are_left():
    html = '<h3>Tickets</h3>[[INSERT open_tickets_table]]<h3>Incidents</h3>[[INSERT incidents_table]]'
    assert process_html_substitutions(html, {'open_tickets_table': TABLE, 'unused_table': '<table></table>'}) == \
        f'<h3>Tickets</h3>{TABLE}<h3>Incidents</h3>[[INSERT incidents_table]]'


def test_tables_get_inline_styles_because_email_clients_ignore_style_sheets():
    soup = BeautifulSoup(format_tables_inline(TABLE), 'html.parser')
    assert 'border: 1px solid black' in soup.table['style']
    assert all('background-color: grey' in th['style'] for th in soup.find_all('th'))
    assert all('border: 1px solid black' in td['style'] for td in soup.find_all('td'))


def test_severity_and_overdue_cells_are_coloured():
    rows = ''.join(f'<tr><td>{text}</td></tr>' for text in
                   ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'OVERDUE by 3 days', 'Open'))
    cells = BeautifulSoup(format_tables_inline(f'<table>{rows}</table>'), 'html.parser').find_all('td')
    colours = [re.search(r'background-color: (#?\w+);?$', td['style']) for td in cells]
    assert [colour.group(1) if colour else None for colour in colours] == \
        ['#FAACF9', '#FF9D96', '#FFB060', '#EEEEC0', '#F6F6F6', 'red', None]


def test_style_already_on_a_cell_is_kept():
    td = BeautifulSoup(format_tables_inline('<table><tr><td style="width: 40%">x</td></tr></table>'),
                       'html.parser').td
    assert td['style'].startswith('width: 40%;') and 'border: 1px solid black' in td['style']


def test_code_blocks_get_the_dark_style_and_their_content_is_unchanged():
    code = 'Resources:\n  Bucket:\n    Properties:\n      Tags:\n        - Key: team\n\n# end'
    result = format_pre_sections(f'<p>Deploy:</p><pre>{code}</pre>')
    assert result == f'<p>Deploy:</p><pre style="background-color: #030204; padding: 12px; color: #f8f9d2;">{code}</pre>'


def test_code_blocks_the_model_styled_itself_are_left_as_written():
    html = '<pre style="background-color: #f4f4f4;">x = 1</pre>'
    assert format_pre_sections(html) == html


def test_a_whole_section_keeps_its_code_and_bold_through_every_step():
    code = 'aws s3api put-bucket-versioning \\\n  --bucket example-bucket\n\n- not a list item'
    html = (f'<h3>Summary</h3>\n<p>There were <strong>2 open tickets</strong> this week.</p>\n'
            f'<p>[[INSERT open_tickets_table]]</p>\n<pre>{code}</pre>\nKeep monitoring <em>daily</em>.')
    soup = BeautifulSoup(process(html, {'open_tickets_table': TABLE}), 'html.parser')
    assert soup.pre.get_text() == code
    assert soup.find('p').decode_contents() == 'There were <strong>2 open tickets</strong> this week.'
    assert soup.table.parent.name == '[document]'
    assert str(soup).endswith('<p>Keep monitoring <em>daily</em>.</p>')
