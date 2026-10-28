"""
Retry rules of every state in every SOAR state machine, and the Lambdas they invoke.

A burst of findings (a scan) throttles the AWS APIs and the ticketing system. Lambdas do not retry; the
state machines do, and only errors they can name:
- every Lambda a state machine invokes decorates its handler with transient_aws_errors, so throttling, AWS-side
  failures and connection problems leave it as AWSTransientError;
- every Lambda state retries AWSTransientError and the Lambda service errors with one rule: 5 s, doubling,
  at most 300 s apart, full jitter, 20 attempts; the ticketing Lambdas also retry TicketingTransientError;
- the QueryAI states have their own rules (tests/unit/test_ai_state_machines.py);
- nothing is retried on a wildcard (States.ALL, States.TaskFailed), so errors not named are never retried;
- every retrier, of any state, has full jitter and waits at most 300 s, so concurrent executions do not
  retry in lockstep and backoff does not grow without bound.
"""

import ast
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent.parent
STATE_MACHINES = sorted((ROOT / 'statemachines').glob('*.asl.yaml'))

LAMBDA_SERVICE_ERRORS = {'Lambda.ServiceException', 'Lambda.AWSLambdaException', 'Lambda.SdkClientException',
                         'Lambda.TooManyRequestsException'}
TICKETING_FUNCTIONS = {'OpenTicketFunction', 'CloseTicketFunction', 'SaveToSentinelFunction'}
LAMBDA_RULE = {'IntervalSeconds': 5, 'MaxAttempts': 20, 'BackoffRate': 2, 'MaxDelaySeconds': 300,
               'JitterStrategy': 'FULL'}
# What Step Functions reports for an optimized DynamoDB task: 'DynamoDB.' + the AWS SDK for Java v1 exception
# class for the error code, or the base class AmazonDynamoDBException for a code without one (established
# with TestState in October 2026: ValidationException -> DynamoDB.AmazonDynamoDBException,
# ConditionalCheckFailedException -> DynamoDB.ConditionalCheckFailedException). The v1 SDK has no
# ThrottlingException class, which is what on-demand tables (all of SOAR's) throttle with, so throttling can
# only be retried under the base name; that also retries permanent DynamoDB errors until the rule gives up.
DYNAMODB_TRANSIENT = {'DynamoDB.ProvisionedThroughputExceededException',   # provisioned tables
                      'DynamoDB.RequestLimitExceededException',           # account throughput limit
                      'DynamoDB.AmazonDynamoDBException',                 # on-demand ThrottlingException
                      'DynamoDB.InternalServerErrorException'}            # HTTP 500
NEVER_EMITTED = {'DynamoDB.ThrottlingException', 'DynamoDB.RequestLimitExceeded'}
NEVER_RETRIED = ['SecurityHubUpdateRejected', 'TicketingRequestError', 'KeyError', 'ClientError',
                 'Sandbox.Timedout', 'Lambda.Unknown', 'States.TaskFailed']


class CfnLoader(yaml.SafeLoader):
    pass


CfnLoader.add_multi_constructor(
    '!', lambda loader, suffix, node: {f'!{suffix}': loader.construct_scalar(node)
                                      if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)
                                      if isinstance(node, yaml.SequenceNode) else loader.construct_mapping(node)})

TEMPLATE = yaml.load((ROOT / 'template.yaml').read_text(), Loader=CfnLoader)['Resources']


def functions_by_substitution():
    """'${XFunctionArn}' -> logical function name, from every state machine's DefinitionSubstitutions."""
    found = {}
    for resource in TEMPLATE.values():
        if resource.get('Type') != 'AWS::Serverless::StateMachine':
            continue
        for key, value in (resource['Properties'].get('DefinitionSubstitutions') or {}).items():
            if isinstance(value, dict) and '!GetAtt' in value:
                found['${' + key + '}'] = value['!GetAtt'].split('.')[0]
    return found


FUNCTIONS = functions_by_substitution()


def all_states(states, prefix=''):
    for name, state in states.items():
        yield prefix + name, state
        for key in ('Iterator', 'ItemProcessor'):
            if key in state:
                yield from all_states(state[key]['States'], f'{prefix}{name} > ')
        for branch in state.get('Branches', []):
            yield from all_states(branch['States'], f'{prefix}{name} > ')


STATES = [(sm.name.split('.')[0], name, state)
          for sm in STATE_MACHINES
          for name, state in all_states(yaml.safe_load(sm.read_text())['States'])]
RETRYING = [s for s in STATES if s[2].get('Retry')]
LAMBDA_STATES = [(sm, name, state, FUNCTIONS[state['Resource']]) for sm, name, state in STATES
                 if state.get('Type') == 'Task' and state.get('Resource') in FUNCTIONS
                 and FUNCTIONS[state['Resource']] != 'QueryAIFunction']
DYNAMODB_STATES = [s for s in STATES if str(s[2].get('Resource', '')).startswith('arn:aws:states:::dynamodb:')]


def ids(cases):
    return [f'{case[0]}:{case[1]}' for case in cases]


def matches(error_equals, error):
    if 'States.ALL' in error_equals:
        return True
    if 'States.TaskFailed' in error_equals and error != 'States.Timeout':
        return True
    return error in error_equals


def retried(state, error, attempt):
    """Whether Step Functions retries `error` on the given attempt (0 = first failure)."""
    for retrier in state.get('Retry', []):
        if matches(retrier['ErrorEquals'], error):
            return attempt < retrier.get('MaxAttempts', 3)
    return False


def test_the_scan_finds_the_states():
    """Guard against the tests silently matching nothing."""
    assert len(STATE_MACHINES) == 6
    assert len(LAMBDA_STATES) > 80
    assert {'SuppressFindingFunction', 'UpdateTicketedFindingFunction', 'OpenTicketFunction'} \
        <= {function for *_, function in LAMBDA_STATES}
    assert len(DYNAMODB_STATES) >= 8


# ---------------------------------------------------------------------------
# Every retrier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sm, name, state', RETRYING, ids=ids(RETRYING))
def test_every_retrier_has_full_jitter_and_waits_at_most_300_seconds(sm, name, state):
    for retrier in state['Retry']:
        assert retrier.get('JitterStrategy') == 'FULL', retrier
        assert retrier.get('MaxDelaySeconds') == 300, retrier


@pytest.mark.parametrize('sm, name, state', RETRYING, ids=ids(RETRYING))
def test_nothing_is_retried_on_a_wildcard(sm, name, state):
    for retrier in state['Retry']:
        assert not {'States.ALL', 'States.TaskFailed'} & set(retrier['ErrorEquals']), retrier


# ---------------------------------------------------------------------------
# Lambda states (QueryAI excepted)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sm, name, state, function', LAMBDA_STATES, ids=ids(LAMBDA_STATES))
class TestLambdaState:

    def test_has_one_retry_rule(self, sm, name, state, function):
        assert len(state.get('Retry', [])) == 1

    def test_retries_transient_aws_errors_and_lambda_service_errors(self, sm, name, state, function):
        errors = set(state['Retry'][0]['ErrorEquals'])
        assert {'AWSTransientError', *LAMBDA_SERVICE_ERRORS} <= errors

    def test_ticketing_lambdas_also_retry_transient_ticketing_errors(self, sm, name, state, function):
        errors = set(state['Retry'][0]['ErrorEquals'])
        assert ('TicketingTransientError' in errors) == (function in TICKETING_FUNCTIONS)

    def test_retries_nothing_else(self, sm, name, state, function):
        """In particular no DynamoDB.* names: a Lambda that calls DynamoDB never raises them."""
        allowed = {'AWSTransientError', 'TicketingTransientError', 'States.Timeout', *LAMBDA_SERVICE_ERRORS}
        assert set(state['Retry'][0]['ErrorEquals']) <= allowed

    def test_backs_off_from_5_seconds_to_at_most_300_with_jitter_20_times(self, sm, name, state, function):
        rule = {k: v for k, v in state['Retry'][0].items() if k != 'ErrorEquals'}
        assert rule == LAMBDA_RULE

    @pytest.mark.parametrize('attempt', [0, 19])
    def test_a_throttled_aws_call_is_retried(self, sm, name, state, function, attempt):
        assert retried(state, 'AWSTransientError', attempt)

    def test_and_given_up_after_20_attempts(self, sm, name, state, function):
        assert not retried(state, 'AWSTransientError', 20)

    @pytest.mark.parametrize('error', NEVER_RETRIED)
    def test_other_errors_are_not_retried(self, sm, name, state, function, error):
        assert not retried(state, error, 0)


# ---------------------------------------------------------------------------
# Direct DynamoDB integrations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sm, name, state', DYNAMODB_STATES, ids=ids(DYNAMODB_STATES))
def test_dynamodb_integrations_retry_dynamodb_throttling(sm, name, state):
    errors = {e for retrier in state.get('Retry', []) for e in retrier['ErrorEquals']}
    assert DYNAMODB_TRANSIENT <= errors
    assert not NEVER_EMITTED & errors, 'names Step Functions never reports'
    assert not {e for e in errors if e.startswith('Lambda.')}, 'Lambda errors never occur in a DynamoDB task'


# ---------------------------------------------------------------------------
# The Lambdas
# ---------------------------------------------------------------------------

INVOKED = sorted({function for sm, name, state in STATES
                  for function in [FUNCTIONS.get(state.get('Resource'))] if function})


def handler_source(function):
    return ROOT / TEMPLATE[function]['Properties']['CodeUri'] / 'app.py'


@pytest.mark.parametrize('function', INVOKED)
def test_every_invoked_lambda_names_its_transient_aws_errors(function):
    tree = ast.parse(handler_source(function).read_text())
    handler = next(node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == 'lambda_handler')
    decorators = [d.id if isinstance(d, ast.Name) else getattr(d, 'attr', None) for d in handler.decorator_list]
    assert 'transient_aws_errors' in decorators


def test_the_unused_set_to_notified_function_is_gone():
    """It was deployed, could update any member account's findings, and no state machine invoked it."""
    assert 'SetToNotifiedFunction' not in TEMPLATE
    assert not (ROOT / 'functions' / 'findings' / 'update_as_notified_finding').exists()
