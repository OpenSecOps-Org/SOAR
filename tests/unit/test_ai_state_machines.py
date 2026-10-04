"""
Error handling of the AI states in the state machines (ticket D8, §3.4, Phase 4), level 1: offline.

Every AI state (a Task on QueryAI) must:
- retry AITransientError with backoff and jitter (QueryAI never retries itself), and the Lambda service
  errors as before; nothing else is retried;
- catch everything else at once (States.ALL, ResultPath $.error) and go to its publish task;
- publish the error once to the failure topic, from a task that has its own catch, then continue to
  where the AI state would have gone (weekly report: via a Pass state that puts a notice in the section);
- time out above the Lambda's 900 s, so QueryAI reports its own timeout first.

The cases are evaluated with Step Functions' matching rules (first matching retrier/catcher wins;
States.ALL matches every error; States.TaskFailed matches every error except States.Timeout). The opt-in
TestState suite (tests/statemachine/) has Step Functions itself evaluate the same cases.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent.parent
FAILURE_TOPIC = '${ExternalCallFailureSNSTopicArn}'
NOTICE = 'This section could not be generated; the failure has been reported.'

# AI state -> where it continues, per state machine
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

TRANSIENT = 'AITransientError'
LAMBDA_SERVICE_ERRORS = ['Lambda.TooManyRequestsException', 'Lambda.ServiceException']
IMMEDIATE_ERRORS = ['AIResponseDeclined', 'AIRequestError', 'States.Timeout', 'KeyError', 'Sandbox.Timedout',
                    'Lambda.Unknown', 'States.TaskFailed']


def all_states(states):
    """Every state, including those inside Map iterators and Parallel branches."""
    found = {}
    for name, state in states.items():
        found[name] = state
        for key in ('Iterator', 'ItemProcessor'):
            if key in state:
                found.update(all_states(state[key]['States']))
        for branch in state.get('Branches', []):
            found.update(all_states(branch['States']))
    return found


def load(sm):
    return all_states(yaml.safe_load((ROOT / 'statemachines' / f'{sm}.asl.yaml').read_text())['States'])


DEFINITIONS = {sm: load(sm) for sm in AI_STATES}


def matches(error_equals, error):
    if 'States.ALL' in error_equals:
        return True
    if 'States.TaskFailed' in error_equals and error != 'States.Timeout':
        return True
    return error in error_equals


def outcome(state, error, attempt):
    """What Step Functions does with `error` on the given attempt (0 = first failure).

    Returns ('retry', retrier) or ('catch', catcher) or ('fail', None).
    """
    for retrier in state.get('Retry', []):
        if matches(retrier['ErrorEquals'], error):
            if attempt < retrier.get('MaxAttempts', 3):
                return 'retry', retrier
            break  # this retrier is exhausted; on to the catchers
    for catcher in state.get('Catch', []):
        if matches(catcher['ErrorEquals'], error):
            return 'catch', catcher
    return 'fail', None


def publish_state(sm, ai_state):
    return DEFINITIONS[sm][f'Report {ai_state} Failure']


def after_publish(sm, ai_state, continuation):
    return f'{ai_state} Failure Notice' if sm == 'weekly_ai_report' else continuation


# ---------------------------------------------------------------------------
# The AI state itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sm, ai_state, continuation', CASES, ids=IDS)
class TestAIState:

    def test_invokes_query_ai_and_continues_on_success(self, sm, ai_state, continuation):
        state = DEFINITIONS[sm][ai_state]
        assert state['Resource'] == '${QueryAIFunctionArn}'
        assert state['Next'] == continuation

    def test_times_out_after_the_lambda(self, sm, ai_state, continuation):
        assert DEFINITIONS[sm][ai_state]['TimeoutSeconds'] >= 930

    @pytest.mark.parametrize('attempt', [0, 1, 2])
    def test_transient_error_is_restarted_with_backoff(self, sm, ai_state, continuation, attempt):
        action, retrier = outcome(DEFINITIONS[sm][ai_state], TRANSIENT, attempt)
        assert action == 'retry'
        assert retrier['ErrorEquals'] == [TRANSIENT]
        assert (retrier['IntervalSeconds'], retrier['MaxAttempts'], retrier['BackoffRate'], retrier['JitterStrategy']) \
            == (10, 3, 2, 'FULL')

    def test_transient_error_is_caught_when_restarts_are_exhausted(self, sm, ai_state, continuation):
        action, catcher = outcome(DEFINITIONS[sm][ai_state], TRANSIENT, attempt=3)
        assert action == 'catch' and catcher['Next'] == f'Report {ai_state} Failure'

    @pytest.mark.parametrize('error', LAMBDA_SERVICE_ERRORS)
    def test_lambda_service_errors_are_restarted_then_caught(self, sm, ai_state, continuation, error):
        state = DEFINITIONS[sm][ai_state]
        action, retrier = outcome(state, error, attempt=0)
        assert action == 'retry' and TRANSIENT not in retrier['ErrorEquals']
        action, catcher = outcome(state, error, attempt=retrier['MaxAttempts'])
        assert action == 'catch' and catcher['Next'] == f'Report {ai_state} Failure'

    @pytest.mark.parametrize('error', IMMEDIATE_ERRORS)
    def test_other_errors_are_caught_immediately(self, sm, ai_state, continuation, error):
        action, catcher = outcome(DEFINITIONS[sm][ai_state], error, attempt=0)
        assert action == 'catch', f'{error} must not be retried'
        assert catcher['Next'] == f'Report {ai_state} Failure'

    def test_catch_keeps_the_input_and_adds_the_error(self, sm, ai_state, continuation):
        assert DEFINITIONS[sm][ai_state]['Catch'] == [
            {'ErrorEquals': ['States.ALL'], 'ResultPath': '$.error', 'Next': f'Report {ai_state} Failure'}]

    def test_nothing_else_is_retried(self, sm, ai_state, continuation):
        retried = {e for r in DEFINITIONS[sm][ai_state]['Retry'] for e in r['ErrorEquals']}
        assert retried == {TRANSIENT, *LAMBDA_SERVICE_ERRORS}


# ---------------------------------------------------------------------------
# The publish task and what follows it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sm, ai_state, continuation', CASES, ids=IDS)
class TestPublish:

    def test_publishes_the_error_to_the_failure_topic(self, sm, ai_state, continuation):
        state = publish_state(sm, ai_state)
        assert state['Type'] == 'Task' and state['Resource'] == 'arn:aws:states:::sns:publish'
        parameters = state['Parameters']
        assert parameters['TopicArn'] == FAILURE_TOPIC
        message = parameters['Message.$']
        assert message.startswith('States.Format(')
        for part in (ai_state, '$$.Execution.Id', '$.error.Error', '$.error.Cause'):
            assert part in message

    def test_keeps_the_data_and_continues(self, sm, ai_state, continuation):
        state = publish_state(sm, ai_state)
        assert state['ResultPath'] is None
        assert state['Next'] == after_publish(sm, ai_state, continuation)

    def test_a_failing_publish_still_continues(self, sm, ai_state, continuation):
        state = publish_state(sm, ai_state)
        for error in ['SNS.AuthorizationErrorException', 'States.TaskFailed', 'States.Timeout']:
            action, catcher = outcome(state, error, attempt=0)
            assert action == 'catch' and catcher['Next'] == after_publish(sm, ai_state, continuation)
        assert state['Catch'][0]['ResultPath'] is None


@pytest.mark.parametrize('ai_state, continuation', list(AI_STATES['weekly_ai_report'].items()))
def test_weekly_failure_puts_a_notice_in_the_section(ai_state, continuation):
    notice = DEFINITIONS['weekly_ai_report'][f'{ai_state} Failure Notice']
    assert notice['Type'] == 'Pass'
    assert notice['ResultPath'] == '$.messages.ai'
    assert NOTICE in notice['Result']['html'] and notice['Result']['plaintext'] == NOTICE
    assert notice['Next'] == continuation


def test_every_query_ai_task_is_covered():
    """A new AI state must be added here, so its error handling is tested too."""
    for sm, states in DEFINITIONS.items():
        tasks = {name for name, s in states.items() if s.get('Resource') == '${QueryAIFunctionArn}'}
        assert tasks == set(AI_STATES[sm])


# ---------------------------------------------------------------------------
# Template: the state machines may publish to the failure topic
# ---------------------------------------------------------------------------

class CfnLoader(yaml.SafeLoader):
    pass


CfnLoader.add_multi_constructor(
    '!', lambda loader, suffix, node: {f'!{suffix}': loader.construct_scalar(node)
                                      if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)})


@pytest.mark.parametrize('resource', ['SOARASFFProcessor', 'SOARIncidents', 'SOARWeeklyAIReport'])
def test_state_machine_can_publish_to_the_failure_topic(resource):
    properties = yaml.load((ROOT / 'template.yaml').read_text(), Loader=CfnLoader)['Resources'][resource]['Properties']
    assert properties['DefinitionSubstitutions']['ExternalCallFailureSNSTopicArn'] == {'!Ref': 'ExternalCallFailureSNSTopic'}
    assert {'SNSPublishMessagePolicy': {'TopicName': {'!GetAtt': 'ExternalCallFailureSNSTopic.TopicName'}}} \
        in properties['Policies']
