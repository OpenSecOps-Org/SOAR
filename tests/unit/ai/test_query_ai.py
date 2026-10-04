"""
Tests for functions/ai/query_ai/app.py (ticket §3.3, D2, D8, D10, D11).

QueryAI reads the resolved config from SSM and the system prompt from the prompts table on every call,
sends SOAR's Converse request to the primary model, asks the fallback once if the primary declines,
publishes a successful fallback to the fallback topic, and raises typed errors without publishing
anything to the error topic and without retrying. All AWS calls are mocked.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

APP = Path(__file__).parent.parent.parent.parent / 'functions' / 'ai' / 'query_ai' / 'app.py'

CONFIG = {
    'region': 'us-east-1', 'effort': 'high', 'maxTokens': 128000,
    'primary': {'modelId': 'anthropic.claude-opus-5-5', 'profileId': 'us.anthropic.claude-opus-5-5'},
    'fallback': {'modelId': 'anthropic.claude-opus-4-8', 'profileId': 'us.anthropic.claude-opus-4-8'},
}
SYSTEM_PROMPT = '[PURPOSE]\nYou are the analysis component of OpenSecOps SOAR.\n'
FALLBACK_TOPIC = 'arn:aws:sns:eu-north-1:111111111111:OpenSecOpsSOARAIFallbacks'

ENV = {
    'AI_PROVIDER': 'BEDROCK',
    'AI_IAC_SNIPPETS': 'Cloudformation YAML, Terraform, and Python CDK',
    'AI_ANONYMIZE_ACCOUNT_NUMBERS': 'No',
    'AI_ANONYMIZE_HEX_STRINGS': 'No',
    'AI_REMOVE_ARNS': 'No',
    'AI_REMOVE_EMAIL_ADDRESSES': 'No',
    'AI_CONFIG_PARAMETER': '/soar/ai/resolved-config',
    'AI_PROMPTS_TABLE': 'ai-prompts',
    'FALLBACK_SNS_TOPIC_ARN': FALLBACK_TOPIC,
}


# ---------------------------------------------------------------------------
# Loading and fakes
# ---------------------------------------------------------------------------

def _install_stubs(monkeypatch):
    """Lambda-only dependencies that are not installed in the test environment."""
    if 'html2text' not in sys.modules:
        html2text = type(sys)('html2text')
        html2text.html2text = lambda html: f'plain:{html}'
        monkeypatch.setitem(sys.modules, 'html2text', html2text)
    if 'bs4' not in sys.modules:
        bs4 = type(sys)('bs4')

        class Soup:
            def __init__(self, html, parser):
                self._html = html

            def find_all(self, _tag):
                return []

            def __str__(self):
                return self._html

        bs4.BeautifulSoup = Soup
        monkeypatch.setitem(sys.modules, 'bs4', bs4)


def load(monkeypatch, **env):
    _install_stubs(monkeypatch)
    for key, value in {**ENV, **env}.items():
        monkeypatch.setenv(key, value)
    spec = importlib.util.spec_from_file_location('query_ai_app', APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def app(monkeypatch):
    return load(monkeypatch)


def answer(text='<div>analysis</div>', stop='end_turn', category=None):
    content = [{'reasoningContent': {'reasoningText': {'text': 'thinking'}}}]
    if text:
        content.append({'text': text})
    response = {'output': {'message': {'role': 'assistant', 'content': content}}, 'stopReason': stop,
                'usage': {'inputTokens': 100, 'outputTokens': 50}, 'metrics': {'latencyMs': 1234}}
    if category:
        response['additionalModelResponseFields'] = {'stop_details': {'type': 'refusal', 'category': category}}
    return response


def client_error(code, message='boom'):
    return ClientError({'Error': {'Code': code, 'Message': message}}, 'Converse')


class Clients:
    """The boto3 clients QueryAI creates, with the config and system prompt preloaded."""

    def __init__(self, responses=None, config=CONFIG, system_prompt=SYSTEM_PROMPT):
        self.runtime = MagicMock()
        if isinstance(responses, list):
            self.runtime.converse.side_effect = responses
        else:
            self.runtime.converse.return_value = responses or answer()
        self.ssm = MagicMock(**{'get_parameter.return_value': {'Parameter': {'Value': json.dumps(config)}}})
        self.dynamodb = MagicMock(**{'get_item.return_value': {'Item': {'instructions': {'S': system_prompt}}}})
        self.sns = MagicMock()
        self.calls = []

    def factory(self, service, **kwargs):
        self.calls.append((service, kwargs))
        return {'bedrock-runtime': self.runtime, 'ssm': self.ssm, 'dynamodb': self.dynamodb, 'sns': self.sns}[service]

    @property
    def bodies(self):
        return [call.kwargs for call in self.runtime.converse.call_args_list]


def context(remaining_ms=900_000):
    return SimpleNamespace(get_remaining_time_in_millis=lambda: remaining_ms)


def finding_data(**extra):
    """Ticket/incident path: instructions from the prompts table, email built by a formatter."""
    data = {
        'nested_instructions': {'instructions': 'Analyse the finding. Include [[IAC_SNIPPETS]] snippets.'},
        'finding': {'Id': 'arn:aws:securityhub:eu-north-1:111111111111:finding/example', 'Title': 'Example finding'},
        'messages': {'email': {'subject': 'INCIDENT: Example finding',
                               'body': 'HIGH incident in 111111111111\n\n====================\nResources: ...'}},
    }
    data.update(extra)
    return data


def run(app, data, clients, remaining_ms=900_000):
    with patch('boto3.client', side_effect=clients.factory):
        return app.lambda_handler(data, context(remaining_ms))


# ---------------------------------------------------------------------------
# AIProvider NONE
# ---------------------------------------------------------------------------

def test_provider_none_returns_data_unchanged_without_calls(monkeypatch):
    app = load(monkeypatch, AI_PROVIDER='NONE')
    clients = Clients()
    data = finding_data()
    assert run(app, dict(data), clients) == data
    assert clients.calls == []


# ---------------------------------------------------------------------------
# Request: config, system text, user text, body, client
# ---------------------------------------------------------------------------

class TestRequest:

    def test_reads_config_and_system_prompt_on_every_call(self, app):
        clients = Clients()
        run(app, finding_data(), clients)
        run(app, finding_data(), clients)
        assert clients.ssm.get_parameter.call_count == 2
        clients.ssm.get_parameter.assert_called_with(Name='/soar/ai/resolved-config')
        assert clients.dynamodb.get_item.call_count == 2
        clients.dynamodb.get_item.assert_called_with(TableName='ai-prompts', Key={'id': {'S': 'system'}})

    def test_finding_system_text_is_system_prompt_then_instructions(self, app):
        clients = Clients()
        run(app, finding_data(), clients)
        system = clients.bodies[0]['system'][0]['text']
        assert system == (SYSTEM_PROMPT.rstrip() + '\n\n'
                          + 'Analyse the finding. Include Cloudformation YAML, Terraform, and Python CDK snippets.')

    def test_weekly_system_text_is_system_prompt_then_weekly_prompts(self, app):
        clients = Clients()
        run(app, {'system': '[INTRODUCTION]\nWeekly section.', 'user': '{"global_data": {}}',
                  'no_html_post_processing': 'True'}, clients)
        body = clients.bodies[0]
        assert body['system'][0]['text'] == SYSTEM_PROMPT.rstrip() + '\n\n[INTRODUCTION]\nWeekly section.'
        assert body['messages'] == [{'role': 'user', 'content': [{'text': '{"global_data": {}}'}]}]

    def test_user_text_is_the_email_body_before_the_separator(self, app):
        clients = Clients()
        run(app, finding_data(), clients)
        user = clients.bodies[0]['messages'][0]['content'][0]['text']
        assert user == 'HIGH incident in 111111111111\n\n'

    def test_anonymisation_still_applies(self, monkeypatch):
        app = load(monkeypatch, AI_ANONYMIZE_ACCOUNT_NUMBERS='Yes')
        clients = Clients()
        run(app, finding_data(), clients)
        assert '111111111111' not in clients.bodies[0]['messages'][0]['content'][0]['text']

    def test_sends_the_d2_body_to_the_primary_profile(self, app):
        clients = Clients()
        run(app, finding_data(), clients)
        body = clients.bodies[0]
        assert body['modelId'] == 'us.anthropic.claude-opus-5-5'
        assert body['inferenceConfig'] == {'maxTokens': 128000}
        assert body['additionalModelRequestFields'] == {'thinking': {'type': 'adaptive'},
                                                        'output_config': {'effort': 'high'}}
        assert body['additionalModelResponseFieldPaths'] == ['/stop_details']
        assert set(body) == {'modelId', 'system', 'messages', 'inferenceConfig',
                             'additionalModelRequestFields', 'additionalModelResponseFieldPaths'}

    def test_runtime_client_uses_config_region_without_retries(self, app):
        clients = Clients()
        run(app, finding_data(), clients, remaining_ms=600_000)
        kwargs = next(kw for service, kw in clients.calls if service == 'bedrock-runtime')
        assert kwargs['region_name'] == 'us-east-1'
        assert kwargs['config'].retries == {'total_max_attempts': 1, 'mode': 'standard'}
        assert kwargs['config'].read_timeout <= 570


# ---------------------------------------------------------------------------
# Response: text extraction and output
# ---------------------------------------------------------------------------

class TestResponse:

    def test_reasoning_plus_text_gives_only_the_text(self, app):
        result = run(app, finding_data(no_html_post_processing='True'), Clients(answer('<div>only this</div>')))
        assert result['messages']['ai']['html'] == '<div>only this</div>'
        assert result['messages']['ai']['plaintext'] == 'plain:<div>only this</div>'

    def test_several_text_blocks_are_concatenated_in_order(self, app):
        response = answer('<div>one</div>')
        response['output']['message']['content'].append({'text': '<div>two</div>'})
        result = run(app, finding_data(no_html_post_processing='True'), Clients(response))
        assert result['messages']['ai']['html'] == '<div>one</div><div>two</div>'

    def test_max_tokens_keeps_the_text(self, app):
        result = run(app, finding_data(no_html_post_processing='True'), Clients(answer('<div>cut</div>', stop='max_tokens')))
        assert result['messages']['ai']['html'] == '<div>cut</div>'

    def test_other_data_is_preserved(self, app):
        data = finding_data()
        result = run(app, data, Clients())
        assert result['finding'] == data['finding']
        assert result['messages']['email']['subject'] == 'INCIDENT: Example finding'


# ---------------------------------------------------------------------------
# Declines and the fallback
# ---------------------------------------------------------------------------

class TestDeclines:

    @pytest.mark.parametrize('declined', [answer(text=None, stop='end_turn'),
                                          answer('<div>partial</div>', stop='content_filtered', category='cyber')],
                             ids=['reasoning-only', 'content-filtered-partial-text'])
    def test_decline_asks_the_fallback_with_the_same_body(self, app, declined):
        clients = Clients([declined, answer('<div>from fallback</div>')])
        result = run(app, finding_data(no_html_post_processing='True'), clients)
        primary, fallback = clients.bodies
        assert fallback['modelId'] == 'us.anthropic.claude-opus-4-8'
        assert {k: v for k, v in fallback.items() if k != 'modelId'} == {k: v for k, v in primary.items() if k != 'modelId'}
        assert result['messages']['ai']['html'] == '<div>from fallback</div>'

    def test_successful_fallback_is_published_to_the_fallback_topic_only(self, app):
        clients = Clients([answer('<div>p</div>', stop='content_filtered', category='cyber'), answer()])
        run(app, finding_data(), clients)
        clients.sns.publish.assert_called_once()
        kwargs = clients.sns.publish.call_args.kwargs
        assert kwargs['TopicArn'] == FALLBACK_TOPIC
        message = kwargs['Message']
        for expected in ['INCIDENT: Example finding', 'Example finding', 'anthropic.claude-opus-5-5',
                         'content_filtered', 'cyber', 'anthropic.claude-opus-4-8']:
            assert expected in message

    def test_weekly_fallback_names_the_weekly_report(self, app):
        clients = Clients([answer(text=None), answer()])
        run(app, {'system': 'Weekly.', 'user': '{}', 'no_html_post_processing': 'True'}, clients)
        assert 'weekly report' in clients.sns.publish.call_args.kwargs['Message']

    def test_fallback_topic_failure_does_not_lose_the_answer(self, app):
        clients = Clients([answer(text=None), answer('<div>kept</div>')])
        clients.sns.publish.side_effect = client_error('AuthorizationError')
        result = run(app, finding_data(no_html_post_processing='True'), clients)
        assert result['messages']['ai']['html'] == '<div>kept</div>'

    def test_fallback_decline_raises_declined_without_publishing(self, app):
        clients = Clients([answer(text=None), answer('<div>p</div>', stop='content_filtered', category='cyber')])
        with pytest.raises(app.AIResponseDeclined) as e:
            run(app, finding_data(), clients)
        assert 'anthropic.claude-opus-4-8' in str(e.value)
        clients.sns.publish.assert_not_called()

    def test_decline_without_fallback_raises_after_one_call(self, app):
        clients = Clients(answer(text=None), config={**CONFIG, 'fallback': None})
        with pytest.raises(app.AIResponseDeclined):
            run(app, finding_data(), clients)
        assert clients.runtime.converse.call_count == 1
        clients.sns.publish.assert_not_called()


# ---------------------------------------------------------------------------
# Errors: typed, not retried, not published (D8)
# ---------------------------------------------------------------------------

class TestErrors:

    @pytest.mark.parametrize('code', ['ThrottlingException', 'ServiceUnavailableException', 'InternalServerException',
                                      'ModelTimeoutException', 'ModelNotReadyException'])
    def test_transient_bedrock_error_raises_transient_after_one_call(self, app, code):
        clients = Clients([client_error(code, 'try again')])
        with pytest.raises(app.AITransientError) as e:
            run(app, finding_data(), clients)
        assert code in str(e.value) and 'anthropic.claude-opus-5-5' in str(e.value)
        assert clients.runtime.converse.call_count == 1
        clients.sns.publish.assert_not_called()

    def test_read_timeout_is_transient(self, app):
        clients = Clients([ReadTimeoutError(endpoint_url='https://bedrock-runtime.us-east-1.amazonaws.com')])
        with pytest.raises(app.AITransientError):
            run(app, finding_data(), clients)
        assert clients.runtime.converse.call_count == 1

    def test_transient_error_on_the_fallback_is_transient(self, app):
        clients = Clients([answer(text=None), client_error('ThrottlingException')])
        with pytest.raises(app.AITransientError) as e:
            run(app, finding_data(), clients)
        assert 'anthropic.claude-opus-4-8' in str(e.value)

    @pytest.mark.parametrize('code', ['ValidationException', 'AccessDeniedException', 'ResourceNotFoundException'])
    def test_other_bedrock_error_raises_request_error(self, app, code):
        clients = Clients([client_error(code, 'Bedrock explains')])
        with pytest.raises(app.AIRequestError) as e:
            run(app, finding_data(), clients)
        assert code in str(e.value) and 'Bedrock explains' in str(e.value)
        assert clients.runtime.converse.call_count == 1
        clients.sns.publish.assert_not_called()

    def test_exception_outside_bedrock_propagates_unchanged(self, app):
        clients = Clients()
        clients.ssm.get_parameter.side_effect = RuntimeError('ssm down')
        with pytest.raises(RuntimeError, match='ssm down'):
            run(app, finding_data(), clients)
        clients.runtime.converse.assert_not_called()

    def test_error_types_are_distinct_for_the_state_machine(self, app):
        names = {app.AITransientError.__name__, app.AIResponseDeclined.__name__, app.AIRequestError.__name__}
        assert names == {'AITransientError', 'AIResponseDeclined', 'AIRequestError'}
