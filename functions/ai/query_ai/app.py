"""
QueryAI: SOAR's one Lambda that calls Claude on Amazon Bedrock.

Each call reads the resolved AI config (written at deploy by the AI config resolver) from SSM and the
`system` prompt from the prompts table, sends SOAR's Converse request (D2) to the primary model, and asks
the fallback model once if the primary declines. A fallback that answers is published to the fallback
topic, which is not an error topic.

QueryAI never retries and publishes no errors (D8). It raises typed errors and the state machine that
invoked it retries AITransientError and publishes every failure to the error topic once.
"""

import json
import logging
import os
import re

import boto3
import html2text
from bs4 import BeautifulSoup
from botocore.config import Config
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

AI_PROVIDER = os.environ['AI_PROVIDER']
AI_IAC_SNIPPETS = os.environ['AI_IAC_SNIPPETS']
AI_ANONYMIZE_ACCOUNT_NUMBERS = os.environ['AI_ANONYMIZE_ACCOUNT_NUMBERS']
AI_ANONYMIZE_HEX_STRINGS = os.environ['AI_ANONYMIZE_HEX_STRINGS']
AI_REMOVE_ARNS = os.environ['AI_REMOVE_ARNS']
AI_REMOVE_EMAIL_ADDRESSES = os.environ['AI_REMOVE_EMAIL_ADDRESSES']
AI_CONFIG_PARAMETER = os.environ['AI_CONFIG_PARAMETER']
AI_PROMPTS_TABLE = os.environ['AI_PROMPTS_TABLE']
FALLBACK_SNS_TOPIC_ARN = os.environ['FALLBACK_SNS_TOPIC_ARN']

TRANSIENT_ERRORS = {'ThrottlingException', 'ServiceUnavailableException', 'InternalServerException',
                    'ModelTimeoutException', 'ModelNotReadyException'}
READ_TIMEOUT_MARGIN_S = 30


class AITransientError(Exception):
    """A transient Bedrock error or timeout. The state machine retries it."""


class AIResponseDeclined(Exception):
    """The model declined (no text, or content_filtered) and the fallback did not answer either."""


class AIRequestError(Exception):
    """Bedrock rejected the request (validation, access, missing resource). Not retried."""


def lambda_handler(data, context):
    if AI_PROVIDER == 'NONE':
        return data

    config = read_config()
    system_text = build_system_text(data, read_system_prompt())
    user_text = build_user_text(data)

    remaining_s = context.get_remaining_time_in_millis() / 1000
    runtime = boto3.client('bedrock-runtime', region_name=config['region'], config=Config(
        read_timeout=max(10, int(remaining_s - READ_TIMEOUT_MARGIN_S)), connect_timeout=10,
        retries={'total_max_attempts': 1, 'mode': 'standard'}))

    html = query(runtime, config, system_text, user_text, data)

    if not data.get('no_html_post_processing'):
        html = format_tables_inline(html)
        html = format_pre_sections(html)

    data.setdefault('messages', {})
    data['messages']['ai'] = {'plaintext': html2text.html2text(html), 'html': html}
    return data


# ---------------------------------------------------------------------------
# Inputs: config, system text (D11), user text
# ---------------------------------------------------------------------------

def read_config():
    """The resolved AI config; read on every call, so a deploy takes effect at once."""
    value = boto3.client('ssm').get_parameter(Name=AI_CONFIG_PARAMETER)['Parameter']['Value']
    return json.loads(value)


def read_system_prompt():
    """ai-prompts/system.txt as synced to the prompts table: it goes first in every call (D11)."""
    item = boto3.client('dynamodb').get_item(TableName=AI_PROMPTS_TABLE, Key={'id': {'S': 'system'}})
    return item['Item']['instructions']['S']


def build_system_text(data, system_prompt):
    """system.txt, then the call's own prompts: the weekly report's `system`, or the finding's instructions."""
    own = data.get('system') or data.get('instructions') or (data.get('nested_instructions') or {}).get('instructions', '')
    return f'{system_prompt.rstrip()}\n\n{own}'.replace('[[IAC_SNIPPETS]]', AI_IAC_SNIPPETS)


def build_user_text(data):
    return data.get('user') or anonymise(data['messages']['email']['body'].split('====================')[0])


# ---------------------------------------------------------------------------
# The Bedrock call, declines and the fallback (§3.3)
# ---------------------------------------------------------------------------

def request_body(profile_id, config, system_text, user_text):
    """SOAR's one Converse request for every supported model (D2)."""
    return {
        'modelId': profile_id,
        'system': [{'text': system_text}],
        'messages': [{'role': 'user', 'content': [{'text': user_text}]}],
        'inferenceConfig': {'maxTokens': config['maxTokens']},
        'additionalModelRequestFields': {
            'thinking': {'type': 'adaptive'},
            'output_config': {'effort': config['effort']},
        },
        'additionalModelResponseFieldPaths': ['/stop_details'],
    }


def extract_text(response):
    """Every text block, in order; reasoning blocks are ignored. Never content[0]."""
    blocks = response.get('output', {}).get('message', {}).get('content', [])
    return ''.join(b['text'] for b in blocks if 'text' in b)


def stop_details(response):
    return (response.get('additionalModelResponseFields') or {}).get('stop_details') or {}


def converse(runtime, model, body):
    """One Bedrock call, no retries. Errors become typed exceptions for the state machine."""
    try:
        response = runtime.converse(**body)
    except ClientError as error:
        code = error.response.get('Error', {}).get('Code', '')
        message = error.response.get('Error', {}).get('Message', '')
        if code in TRANSIENT_ERRORS:
            raise AITransientError(f'{model["modelId"]} ({model["profileId"]}): {code}: {message}') from error
        raise AIRequestError(f'{model["modelId"]} ({model["profileId"]}): {code}: {message}') from error
    except (ReadTimeoutError, ConnectTimeoutError) as error:
        raise AITransientError(f'{model["modelId"]} ({model["profileId"]}): {type(error).__name__}: {error}') from error

    logger.info('%s: stopReason %s, usage %s, latencyMs %s, stop_details %s', model['profileId'],
                response.get('stopReason'), response.get('usage'), response.get('metrics', {}).get('latencyMs'),
                stop_details(response) or None)
    return response


def answer_of(response):
    """The answer text, or '' for a decline. Partial text of a content_filtered response is discarded."""
    if response.get('stopReason') == 'content_filtered':
        return ''
    return extract_text(response)


def query(runtime, config, system_text, user_text, data):
    primary, fallback = config['primary'], config.get('fallback')

    response = converse(runtime, primary, request_body(primary['profileId'], config, system_text, user_text))
    text = answer_of(response)
    if not text and fallback:
        declined = response
        logger.warning('%s declined (stopReason %s, stop_details %s); asking %s', primary['modelId'],
                       declined.get('stopReason'), stop_details(declined) or None, fallback['modelId'])
        response = converse(runtime, fallback, request_body(fallback['profileId'], config, system_text, user_text))
        text = answer_of(response)
        if text:
            publish_fallback(data, primary, fallback, declined)

    if not text:
        last = fallback if fallback else primary
        raise AIResponseDeclined(
            f'{primary["modelId"]} declined' + (f' and {fallback["modelId"]} declined too' if fallback else ', no fallback')
            + f' (last stopReason {response.get("stopReason")!r}, stop_details {stop_details(response) or None}, '
            f'model {last["modelId"]})')

    if response.get('stopReason') == 'max_tokens':
        logger.warning('Output reached maxTokens (%s); keeping the truncated text', config['maxTokens'])
    return text


def call_site(data):
    """What the analysis was for: the email subject (TEAM FIX:, AUTOFIXED:, CLOSED:, INCIDENT:) or the weekly report."""
    subject = ((data.get('messages') or {}).get('email') or {}).get('subject')
    return subject or 'weekly report section'


def publish_fallback(data, primary, fallback, declined):
    """A fallback that answered: worth tracking, not an error. A publishing problem must not lose the answer."""
    finding = data.get('finding') or {}
    details = stop_details(declined)
    message = '\n'.join([
        'The primary AI model declined and the fallback model answered.',
        f'Call site: {call_site(data)}',
        f'Finding: {finding.get("Title", "n/a")} ({finding.get("Id", "n/a")})',
        f'Primary model: {primary["modelId"]} ({primary["profileId"]})',
        f'Primary stopReason: {declined.get("stopReason")}',
        f'Classifier category: {details.get("category", "n/a")}',
        f'Fallback model: {fallback["modelId"]} ({fallback["profileId"]})',
    ])
    try:
        boto3.client('sns').publish(TopicArn=FALLBACK_SNS_TOPIC_ARN, Subject='SOAR AI fallback used', Message=message)
    except Exception:  # noqa: BLE001 - informational only
        logger.exception('Could not publish to the fallback topic')


# ---------------------------------------------------------------------------
# Input anonymisation and HTML post-processing (unchanged)
# ---------------------------------------------------------------------------

def anonymise(input):
    if AI_ANONYMIZE_ACCOUNT_NUMBERS == 'Yes':
        aws_account_number_pattern = r"\b\d{12}\b"
        input = re.sub(aws_account_number_pattern, '[suppressed-account]', input)

    if AI_REMOVE_ARNS == 'Yes':
        aws_arn_pattern = r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9-\.\_]*):([a-zA-Z0-9-\.\_]*):([0-9]*):([a-zA-Z0-9-\.\_\/]*)"
        input = re.sub(aws_arn_pattern, '[suppressed-arn]', input)

    if AI_REMOVE_EMAIL_ADDRESSES == 'Yes':
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        input = re.sub(email_pattern, '[suppressed-email]', input)

    if AI_ANONYMIZE_HEX_STRINGS == 'Yes':
        uuid_pattern = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        input = re.sub(uuid_pattern, '[suppressed-uuid]', input)

        hex_pattern = r"\b[0-9A-Fa-f]{5,}\b"
        input = re.sub(hex_pattern, '[suppressed-hex]', input)

    return input


# Add inline styling to all tables, as email clients are dodgy with HEAD style and classes
def format_tables_inline(html):
    soup = BeautifulSoup(html, 'html.parser')

    for table in soup.find_all('table'):
        table['style'] = 'border: 1px solid black; border-collapse: collapse; padding: 4px; background-color: #EEEEEE; font-size: 14px;'

    for th in soup.find_all('th'):
        th['style'] = 'background-color: grey; color: white; border: 1px solid black; border-collapse: collapse; padding: 4px;'

    for td in soup.find_all('td'):
        if 'style' in td.attrs:
            td['style'] += '; border: 1px solid black; border-collapse: collapse; padding: 4px;'
        else:
            td['style'] = 'border: 1px solid black; border-collapse: collapse; padding: 4px;'

        if 'OVERDUE' in td.text:
            td['style'] += '; background-color: red;'

        if td.text in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            bgcolour = {"CRITICAL": "FF00FF", "HIGH": "FF0000", "MEDIUM": "FF8000",
                        "LOW": "FFFF00", "INFORMATIONAL": "E0E0E0"}[td.text]
            td['style'] += f'; background-color: #{bgcolour};'

    return str(soup)


def format_pre_sections(html):
    style = 'style="background-color: #030204; padding: 12px; color: #f8f9d2;"'
    return re.sub(r'<pre>', f'<pre {style}>', html)
