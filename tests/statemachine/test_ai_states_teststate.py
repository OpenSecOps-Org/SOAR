"""
Error handling of the AI states, level 2: Step Functions itself evaluates each case (opt-in).

Skipped unless RUN_REAL_AWS_TESTS=true (TESTING.md Rule #1). Uses the Step Functions TestState API with
every service integration mocked (QueryAI, SNS) and no execution role:

    RUN_REAL_AWS_TESTS=true pytest tests/statemachine -v

Cost: none ("TestState API calls are included with AWS Step Functions at no additional charge").
Side effects: none; nothing is invoked or published. Credentials: LIVE_AWS_PROFILE (default Org).

The same cases as the offline level-1 tests (tests/unit/test_ai_state_machines.py), per AI state:
success; restarts of transient errors and exhaustion; Lambda service errors; errors caught immediately;
the publish task, including a failing publish; the weekly report's notice.
"""

import json
import os
import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.skipif(os.environ.get('RUN_REAL_AWS_TESTS', '').lower() != 'true',
                                reason='calls the AWS Step Functions TestState API; set RUN_REAL_AWS_TESTS=true to run')

ROOT = Path(__file__).parent.parent.parent
PROFILE = os.environ.get('LIVE_AWS_PROFILE', 'Org')
REGION = os.environ.get('LIVE_SFN_REGION', 'eu-north-1')
TOPIC = 'arn:aws:sns:eu-north-1:111111111111:OpenSecOpsSOARExternalCallFailures'
NOTICE = 'This section could not be generated; the failure has been reported.'

# Same table as level 1: AI state -> where it continues
AI_STATES = {
    'asff_processor': {'AddAiDataForOpenedTickets': 'Send Ticketing Email',
                       'AddAiDataForAutoremediation': 'Send Remediation Email',
                       'AddAiDataForClosedTickets': 'Send Ticket Closed Email'},
    'incidents': {'AddAiDataForAppIncident': 'Send APP email',
                  'AddAiDataForInfraIncident': 'Send INFRA email'},
    'weekly_ai_report': {'Create Overview Section': 'Postprocess Overview Section',
                         'Create Account Segment': 'Store Account Segment Summary',
                         'Create Recommendations Section': 'Postprocess Recommendations Section'},
}
CASES = [(sm, state, cont) for sm, states in AI_STATES.items() for state, cont in states.items()]
IDS = [f'{sm}:{state}' for sm, state, _ in CASES]
INPUT = {'messages': {'ai': {'plaintext': '', 'html': ''}, 'email': {'subject': 'INCIDENT: example'}},
         'finding': {'Id': 'example-finding'}}


def substitute(match):
    name = match.group(1)
    if name.endswith('FunctionArn'):
        return f'arn:aws:lambda:eu-north-1:111111111111:function:{name[:-3]}'
    if name == 'ExternalCallFailureSNSTopicArn':
        return TOPIC
    return 'example'


DEFINITIONS = {sm: json.dumps(yaml.safe_load(re.sub(r'\$\{(\w+)\}', substitute,
                                                    (ROOT / 'statemachines' / f'{sm}.asl.yaml').read_text())))
               for sm in AI_STATES}


@pytest.fixture(scope='module')
def sfn():
    import boto3
    from botocore.config import Config
    return boto3.Session(profile_name=PROFILE).client('stepfunctions', region_name=REGION,
                                                      config=Config(retries={'max_attempts': 10, 'mode': 'adaptive'}))


def run_state(sfn, sm, state_name, mock=None, retry_count=None, data=INPUT):
    """One TestState call on a state of the given state machine's full definition."""
    kwargs = {'definition': DEFINITIONS[sm], 'stateName': state_name, 'input': json.dumps(data),
              'inspectionLevel': 'DEBUG'}
    if mock is not None:
        kwargs['mock'] = mock
    if retry_count is not None:
        kwargs['stateConfiguration'] = {'retrierRetryCount': retry_count}
    response = sfn.test_state(**kwargs)
    response.pop('ResponseMetadata', None)
    return response


def error(name, cause='example cause'):
    return {'errorOutput': {'error': name, 'cause': cause}}


def after_publish(sm, ai_state, continuation):
    return f'{ai_state} Failure Notice' if sm == 'weekly_ai_report' else continuation


@pytest.mark.parametrize('sm, ai_state, continuation', CASES, ids=IDS)
class TestAIState:

    def test_success_continues_without_publishing(self, sfn, sm, ai_state, continuation):
        r = run_state(sfn, sm, ai_state, {'result': json.dumps({**INPUT, 'messages': {'ai': {'html': '<div>ok</div>'}}})})
        assert r['status'] == 'SUCCEEDED' and r['nextState'] == continuation

    @pytest.mark.parametrize('attempt', [0, 1, 2])
    def test_transient_error_is_restarted_with_backoff(self, sfn, sm, ai_state, continuation, attempt):
        r = run_state(sfn, sm, ai_state, error('AITransientError', 'ThrottlingException: slow down'), attempt)
        assert r['status'] == 'RETRIABLE'
        details = r['inspectionData']['errorDetails']
        assert details['retryIndex'] == 0
        assert 0 <= details['retryBackoffIntervalSeconds'] <= 10 * 2 ** attempt

    def test_transient_error_is_caught_when_restarts_are_exhausted(self, sfn, sm, ai_state, continuation):
        r = run_state(sfn, sm, ai_state, error('AITransientError', 'ThrottlingException: slow down'), 3)
        assert r['status'] == 'CAUGHT_ERROR' and r['nextState'] == f'Report {ai_state} Failure'
        output = json.loads(r['output'])
        assert output['error'] == {'Error': 'AITransientError', 'Cause': 'ThrottlingException: slow down'}
        assert output['messages']['ai'] == INPUT['messages']['ai']

    @pytest.mark.parametrize('name', ['Lambda.TooManyRequestsException', 'Lambda.ServiceException'])
    def test_lambda_service_error_is_restarted_then_caught(self, sfn, sm, ai_state, continuation, name):
        r = run_state(sfn, sm, ai_state, error(name), 0)
        assert r['status'] == 'RETRIABLE' and r['inspectionData']['errorDetails']['retryIndex'] == 1
        r = run_state(sfn, sm, ai_state, error(name), 25)
        assert r['status'] == 'CAUGHT_ERROR' and r['nextState'] == f'Report {ai_state} Failure'

    @pytest.mark.parametrize('name', ['AIResponseDeclined', 'AIRequestError', 'States.Timeout', 'KeyError',
                                      'Sandbox.Timedout'])
    def test_other_errors_are_caught_immediately(self, sfn, sm, ai_state, continuation, name):
        r = run_state(sfn, sm, ai_state, error(name), 0)
        assert r['status'] == 'CAUGHT_ERROR', f'{name} must not be restarted'
        assert r['nextState'] == f'Report {ai_state} Failure'
        assert json.loads(r['output'])['error']['Error'] == name


@pytest.mark.parametrize('sm, ai_state, continuation', CASES, ids=IDS)
class TestPublish:

    def failed(self, ai_state):
        return {**INPUT, 'error': {'Error': 'AIResponseDeclined', 'Cause': 'anthropic.claude-opus-5-5 declined'}}

    def test_publishes_once_and_continues(self, sfn, sm, ai_state, continuation):
        r = run_state(sfn, sm, f'Report {ai_state} Failure', {'result': '{"MessageId": "example"}'},
                       data=self.failed(ai_state))
        assert r['status'] == 'SUCCEEDED' and r['nextState'] == after_publish(sm, ai_state, continuation)
        parameters = json.loads(r['inspectionData']['afterParameters'])
        assert parameters['TopicArn'] == TOPIC
        for part in (ai_state, 'AIResponseDeclined', 'anthropic.claude-opus-5-5 declined', 'arn:aws:states:'):
            assert part in parameters['Message']
        assert json.loads(r['output']) == self.failed(ai_state)

    def test_a_failing_publish_still_continues(self, sfn, sm, ai_state, continuation):
        r = run_state(sfn, sm, f'Report {ai_state} Failure', error('SNS.AuthorizationErrorException', 'denied'),
                       data=self.failed(ai_state))
        assert r['status'] == 'CAUGHT_ERROR' and r['nextState'] == after_publish(sm, ai_state, continuation)
        assert json.loads(r['output']) == self.failed(ai_state)


@pytest.mark.parametrize('ai_state, continuation', list(AI_STATES['weekly_ai_report'].items()))
def test_weekly_notice_replaces_the_section(sfn, ai_state, continuation):
    r = run_state(sfn, 'weekly_ai_report', f'{ai_state} Failure Notice',
                   data={'messages': {'report': {'html': ''}}, 'error': {'Error': 'AITransientError', 'Cause': 'x'}})
    assert r['status'] == 'SUCCEEDED' and r['nextState'] == continuation
    assert json.loads(r['output'])['messages']['ai'] == {'html': f'<p>{NOTICE}</p>', 'plaintext': NOTICE}
