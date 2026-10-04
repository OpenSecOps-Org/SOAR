"""
Live smoke test of the AI code against real Amazon Bedrock (opt-in; TESTING.md Rule #1).

Skipped unless RUN_REAL_AWS_TESTS=true. Uses the AWS profile in LIVE_AWS_PROFILE (default: Org) and
Bedrock in LIVE_AI_REGION (default: us-east-1). Run before a release:

    RUN_REAL_AWS_TESTS=true pytest tests/live -v -s

Cost: about 5 Bedrock calls on Opus 5.5 and Opus 4.8 (two short probes, a ticket analysis, a weekly
section, a declined call and its fallback); roughly USD 0.60 at list prices. Approved by the
maintainer (2026-10-04).
Side effects: none beyond Bedrock usage. SSM, DynamoDB and SNS are faked locally; nothing is written.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from time import monotonic
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('RUN_REAL_AWS_TESTS', '').lower() != 'true',
                                reason='live AWS test; set RUN_REAL_AWS_TESTS=true to run')

ROOT = Path(__file__).parent.parent.parent
PROMPTS = ROOT / 'ai-prompts'
FIXTURES = Path(__file__).parent / 'fixtures'
PROFILE = os.environ.get('LIVE_AWS_PROFILE', 'Org')
REGION = os.environ.get('LIVE_AI_REGION', 'us-east-1')

SETTINGS = {'AIModel': 'anthropic.claude-opus-5-5', 'AIFallbackModel': 'anthropic.claude-opus-4-8',
            'AIRegion': REGION, 'AILocality': 'regional', 'AIEffort': 'high', 'AIMaxTokens': 128000}

# v3.1.11's hardcoded preamble, and an input the v3.1.11 prompts were declined on in 3 of 3 Phase 0 runs
V3_1_11_PREAMBLE = (
    "You are a helpful security assistant offering detailed expert advice and answers on AWS security controls and incidents.\n\n"
    "Context: Severity levels are INFORMATIONAL, requiring no attention; LOW, requiring attention when convenient; MEDIUM, requiring attention within the current sprint; HIGH, requiring attention within a few hours; and CRITICAL, a show-stopper requiring immediate attention.\n\n"
    'The output is HTML. Output your results as HTML inside a <div style="font-family: Verdana, sans-serif; font-size:16px;"> ... </div>.\n\n'
    "Clearly header your output using as few words as possible. For instance, 'Analysis' is better than 'Detailed Expert Analysis of the Security Issue' or 'Detailed Expert Analysis'.\n")
C2_INCIDENT = (
    'HIGH EC2-related INCIDENT in account "Example-Payments-Prod" (123456789012, OU: Workloads/Prod), region eu-north-1:\n\n'
    'EC2 instance i-0a1b2c3d4e5f60718 is querying an IP address associated with a known command and control server.\n\n'
    'EC2 instance i-0a1b2c3d4e5f60718 is communicating outbound with IP address 203.0.113.77 on port 8443, which is '
    'associated with a known command and control server.\n\n'
    'Resource ARN: arn:aws:ec2:eu-north-1:123456789012:instance/i-0a1b2c3d4e5f60718\nResource type: AwsEc2Instance\n\n'
    'Type: TTPs/Command and Control/Backdoor:EC2-C&CActivity.B\n\nProduct name: GuardDuty\n'
    'Finding ID: arn:aws:guardduty:eu-north-1:123456789012:detector/0ab1c2d3e4f5/finding/9f8e7d6c5b4a\n'
    'Created at: 2026-09-29T02:47:13.000Z\n\nEmail sent by OpenSecOps SOAR to: payments-team@example.com\n\n- - -\n\n'
    'ACTIONS TAKEN: The instance has been terminated and stake-holders have been informed.\n'
    'ACTIONS REQUIRED: Please investigate.\n\nThank you.\n\n/ OpenSecOps SOAR\n\n\n')
EC2_13_TICKET = (
    'HIGH issue in account "Example-Payments-Prod" (123456789012, OU: Workloads/Prod), region us-east-1:\n\n'
    'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22\n\n'
    'This control checks whether security groups allow unrestricted incoming traffic on port 22.\n\n'
    'Resource ARN: arn:aws:ec2:us-east-1:123456789012:security-group/sg-1234567890abcdef0\n'
    'Resource type: AwsEc2SecurityGroup\n\n')


def load_module(name, path, env):
    for key, value in env.items():
        os.environ[key] = value
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def session():
    import boto3
    return boto3.Session(profile_name=PROFILE)


@pytest.fixture(scope='module')
def query_ai():
    for name in ('html2text', 'bs4'):  # Lambda-only dependencies; post-processing is skipped below
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = type(sys)(name)
                stub.html2text = lambda html: html
                stub.BeautifulSoup = object
                sys.modules[name] = stub
    env = {'AI_PROVIDER': 'BEDROCK', 'AI_IAC_SNIPPETS': 'Cloudformation YAML, Terraform, and Python CDK',
           'AI_ANONYMIZE_ACCOUNT_NUMBERS': 'No', 'AI_ANONYMIZE_HEX_STRINGS': 'No', 'AI_REMOVE_ARNS': 'No',
           'AI_REMOVE_EMAIL_ADDRESSES': 'No', 'AI_CONFIG_PARAMETER': '/soar/ai/resolved-config',
           'AI_PROMPTS_TABLE': 'ai-prompts', 'FALLBACK_SNS_TOPIC_ARN': 'arn:aws:sns:eu-north-1:111111111111:fallbacks'}
    return load_module('query_ai_live', ROOT / 'functions' / 'ai' / 'query_ai' / 'app.py', env)


@pytest.fixture(scope='module')
def resolved(session):
    """Test 1: the resolver against real Bedrock, with SSM faked. Its config feeds the QueryAI tests."""
    sys.modules.setdefault('cfnresponse', SimpleNamespace(SUCCESS='SUCCESS', FAILED='FAILED', send=MagicMock()))
    resolver = load_module('resolver_live', ROOT / 'functions' / 'ai' / 'ai_config_resolver' / 'app.py',
                           {'CONFIG_PARAMETER': '/soar/ai/resolved-config'})
    from botocore.config import Config
    bedrock = session.client('bedrock', region_name=REGION)
    runtime = session.client('bedrock-runtime', region_name=REGION, config=Config(
        read_timeout=200, connect_timeout=10, retries={'total_max_attempts': 1, 'mode': 'standard'}))
    ssm = MagicMock()
    config = resolver.resolve(dict(SETTINGS), bedrock, runtime, ssm, deadline=monotonic() + 220)
    assert json.loads(ssm.put_parameter.call_args.kwargs['Value']) == config
    return config


def run_query_ai(query_ai, session, config, data, system_prompt):
    """QueryAI's handler with real Bedrock; SSM, the prompts table and SNS faked."""
    ssm = MagicMock(**{'get_parameter.return_value': {'Parameter': {'Value': json.dumps(config)}}})
    dynamodb = MagicMock(**{'get_item.return_value': {'Item': {'instructions': {'S': system_prompt}}}})
    sns = MagicMock()

    def client(service, **kwargs):
        if service == 'bedrock-runtime':
            return session.client(service, **kwargs)
        return {'ssm': ssm, 'dynamodb': dynamodb, 'sns': sns}[service]

    with patch('boto3.client', side_effect=client):
        result = query_ai.lambda_handler(data, SimpleNamespace(get_remaining_time_in_millis=lambda: 900_000))
    return result, sns


def test_resolver_finds_profiles_and_probes_both_models(resolved):
    assert resolved['primary'] == {'modelId': 'anthropic.claude-opus-5-5', 'profileId': f'{REGION[:2]}.anthropic.claude-opus-5-5'}
    assert resolved['fallback'] == {'modelId': 'anthropic.claude-opus-4-8', 'profileId': f'{REGION[:2]}.anthropic.claude-opus-4-8'}
    assert resolved['effort'] == 'high' and resolved['maxTokens'] == 128000


def test_query_ai_ticket_path(query_ai, session, resolved):
    data = {'nested_instructions': {'instructions': (PROMPTS / 'ticket_opened.txt').read_text()},
            'no_html_post_processing': 'True',
            'messages': {'email': {'subject': 'TEAM FIX: EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
                                   'body': EC2_13_TICKET + '====================\n'}}}
    result, sns = run_query_ai(query_ai, session, resolved, data, (PROMPTS / 'system.txt').read_text())
    html = result['messages']['ai']['html']
    assert html.lstrip().startswith('<') and len(html) > 500
    assert '**' not in html.split('<pre')[0]
    sns.publish.assert_not_called()


def test_query_ai_weekly_path(query_ai, session, resolved):
    common = (PROMPTS / 'weekly_ai_report_0_common.txt').read_text()
    section = (PROMPTS / 'weekly_ai_report_3_recommendations.txt').read_text()
    data = {'system': common + '\n' + section, 'no_html_post_processing': 'True',
            'user': json.dumps({'account_summaries': '[ACCOUNT Example-Payments-Prod]:\nExample-Payments-Prod:\n'
                                                     'One open HIGH ticket: EC2.13 SSH open to the internet.'})}
    result, sns = run_query_ai(query_ai, session, resolved, data, (PROMPTS / 'system.txt').read_text())
    html = result['messages']['ai']['html']
    assert '<h3' in html and '<h1' not in html and '<h2' not in html
    sns.publish.assert_not_called()


def test_query_ai_fallback_path(query_ai, session, resolved):
    data = {'nested_instructions': {'instructions': (FIXTURES / 'incident_infra_v3.1.11.txt').read_text()},
            'no_html_post_processing': 'True',
            'finding': {'Title': 'EC2 instance is querying an IP address associated with a known command and control server.',
                        'Id': 'arn:aws:guardduty:eu-north-1:123456789012:detector/0ab1c2d3e4f5/finding/9f8e7d6c5b4a'},
            'messages': {'email': {'subject': 'INCIDENT: EC2 instance is querying a known C&C server',
                                   'body': C2_INCIDENT + '====================\n'}}}
    result, sns = run_query_ai(query_ai, session, resolved, data, V3_1_11_PREAMBLE)
    if not sns.publish.called:
        pytest.skip('the primary model answered this time (declines are not deterministic); fallback path not exercised')
    message = sns.publish.call_args.kwargs['Message']
    assert 'anthropic.claude-opus-5-5' in message and 'anthropic.claude-opus-4-8' in message
    assert 'INCIDENT:' in message
    assert len(result['messages']['ai']['html']) > 500
    print('\nFallback-topic message:\n' + message)
