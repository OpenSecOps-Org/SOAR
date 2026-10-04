"""
Tests for functions/ai/ai_config_resolver/app.py, the deploy-time AI resolver (ticket §3.1, §3.2).

All AWS calls are mocked: Bedrock (control plane and runtime), SSM and cfnresponse.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

APP = Path(__file__).parent.parent.parent.parent / 'functions' / 'ai' / 'ai_config_resolver' / 'app.py'
CONFIG_PARAMETER = '/soar/ai/resolved-config'

OPUS_55 = 'anthropic.claude-opus-5-5'
OPUS_48 = 'anthropic.claude-opus-4-8'

# ListInferenceProfiles(typeEquals=SYSTEM_DEFINED) as seen from us-east-1 (Phase 0, HiQ)
US_EAST_1 = ['us.anthropic.claude-opus-5-5', 'global.anthropic.claude-opus-5-5',
             'us.anthropic.claude-opus-4-8', 'global.anthropic.claude-opus-4-8',
             'us.amazon.nova-pro-v1:0', 'us.meta.llama4-maverick-17b-instruct-v1:0']
# ... and from ap-southeast-1, where only global profiles exist for these models
AP_SOUTHEAST_1 = ['global.anthropic.claude-opus-5-5', 'global.anthropic.claude-opus-4-8',
                  'apac.amazon.nova-pro-v1:0']

PROPERTIES = {
    'ServiceToken': 'arn:aws:lambda:eu-north-1:111111111111:function:resolver',
    'ServiceTimeout': '300',
    'AIProvider': 'BEDROCK',
    'AIModel': OPUS_55,
    'AIFallbackModel': OPUS_48,
    'AIRegion': 'us-east-1',
    'AILocality': 'regional',
    'AIEffort': 'high',
    'AIMaxTokens': '128000',
}


# ---------------------------------------------------------------------------
# Loading and fakes
# ---------------------------------------------------------------------------

@pytest.fixture
def app(monkeypatch):
    """Import app.py by path with cfnresponse stubbed."""
    cfnresponse = SimpleNamespace(SUCCESS='SUCCESS', FAILED='FAILED', send=MagicMock())
    monkeypatch.setitem(sys.modules, 'cfnresponse', cfnresponse)
    monkeypatch.setenv('CONFIG_PARAMETER', CONFIG_PARAMETER)
    spec = importlib.util.spec_from_file_location('ai_config_resolver_app', APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.sleep = MagicMock()  # no real waiting in retry tests
    return module


def bedrock_with(*pages):
    """A bedrock control-plane client whose paginator yields the given pages of profile IDs."""
    bedrock = MagicMock()
    bedrock.get_paginator.return_value.paginate.return_value = [
        {'inferenceProfileSummaries': [{'inferenceProfileId': p} for p in page]} for page in pages]
    return bedrock


def answer(text='OK', stop='end_turn'):
    content = [{'reasoningContent': {'reasoningText': {'text': 'thinking'}}}] + ([{'text': text}] if text else [])
    return {'output': {'message': {'role': 'assistant', 'content': content}}, 'stopReason': stop}


def client_error(code, message, operation='Converse'):
    return ClientError({'Error': {'Code': code, 'Message': message}}, operation)


def context(remaining_ms=240_000):
    return SimpleNamespace(log_stream_name='2026/10/04/[$LATEST]abc', get_remaining_time_in_millis=lambda: remaining_ms)


def cfn_event(request_type='Create', properties=None, physical_id=None):
    e = {'RequestType': request_type, 'ResponseURL': 'https://example.invalid/response',
         'StackId': 'arn:aws:cloudformation:eu-north-1:111111111111:stack/INFRA-SOAR/1',
         'RequestId': 'req-1', 'LogicalResourceId': 'AIConfigResolverCustomResource',
         'ResourceProperties': dict(PROPERTIES, **(properties or {}))}
    if physical_id:
        e['PhysicalResourceId'] = physical_id
    return e


def run_handler(app, event, bedrock=None, runtime=None, ssm=None, remaining_ms=240_000):
    """Run lambda_handler with boto3.client returning the given fakes; returns (status, kwargs, clients)."""
    bedrock = bedrock or bedrock_with(US_EAST_1)
    runtime = runtime or MagicMock(**{'converse.return_value': answer()})
    ssm = ssm or MagicMock()
    clients = {'bedrock': bedrock, 'bedrock-runtime': runtime, 'ssm': ssm}
    with patch('boto3.client', side_effect=lambda service, **kw: clients[service]) as factory:
        app.lambda_handler(event, context(remaining_ms))
    args, kwargs = app.cfnresponse.send.call_args
    return args[2], kwargs, SimpleNamespace(bedrock=bedrock, runtime=runtime, ssm=ssm, factory=factory)


# ---------------------------------------------------------------------------
# Model IDs and the fallback
# ---------------------------------------------------------------------------

class TestModelIds:

    def test_anthropic_model_id_is_accepted(self, app):
        app.check_model_id(OPUS_55, 'AIModel')

    @pytest.mark.parametrize('model_id', ['us.anthropic.claude-opus-5-5', 'global.anthropic.claude-opus-4-8',
                                          'eu.anthropic.claude-opus-5-5'])
    def test_model_id_with_prefix_is_rejected(self, app, model_id):
        with pytest.raises(app.ResolverError, match='without a prefix'):
            app.check_model_id(model_id, 'AIModel')

    @pytest.mark.parametrize('model_id', ['amazon.nova-pro-v1:0', 'meta.llama4-maverick-17b-instruct-v1:0', ''])
    def test_non_anthropic_model_id_is_rejected(self, app, model_id):
        with pytest.raises(app.ResolverError, match='Claude models only'):
            app.check_model_id(model_id, 'AIModel')

    @pytest.mark.parametrize('fallback', ['none', 'None', 'NONE', OPUS_55])
    def test_fallback_none_or_same_model_means_no_fallback(self, app, fallback):
        assert app.fallback_model(OPUS_55, fallback) is None

    def test_other_fallback_is_kept(self, app):
        assert app.fallback_model(OPUS_55, OPUS_48) == OPUS_48


# ---------------------------------------------------------------------------
# Profile lookup (§3.1)
# ---------------------------------------------------------------------------

class TestProfileLookup:

    def test_lists_system_defined_profiles_across_pages(self, app):
        bedrock = bedrock_with(US_EAST_1[:3], US_EAST_1[3:])
        assert app.list_profile_ids(bedrock) == US_EAST_1
        bedrock.get_paginator.assert_called_once_with('list_inference_profiles')
        bedrock.get_paginator.return_value.paginate.assert_called_once_with(typeEquals='SYSTEM_DEFINED')

    def test_regional_profile(self, app):
        assert app.choose_profile(US_EAST_1, OPUS_55, 'regional', 'us-east-1') == 'us.anthropic.claude-opus-5-5'

    def test_global_profile(self, app):
        assert app.choose_profile(US_EAST_1, OPUS_48, 'global', 'us-east-1') == 'global.anthropic.claude-opus-4-8'

    def test_regional_requested_where_only_global_exists(self, app):
        with pytest.raises(app.ResolverError) as e:
            app.choose_profile(AP_SOUTHEAST_1, OPUS_55, 'regional', 'ap-southeast-1')
        assert 'no regional profile for anthropic.claude-opus-5-5 in ap-southeast-1' in str(e.value)
        assert 'global.anthropic.claude-opus-5-5' in str(e.value)

    def test_model_without_any_profile_lists_anthropic_models_there(self, app):
        with pytest.raises(app.ResolverError) as e:
            app.choose_profile(US_EAST_1, 'anthropic.claude-sonnet-9', 'regional', 'us-east-1')
        message = str(e.value)
        assert 'no inference profile for anthropic.claude-sonnet-9 in us-east-1' in message
        assert OPUS_55 in message and OPUS_48 in message
        assert 'nova' not in message and 'llama' not in message

    def test_model_id_must_match_exactly(self, app):
        with pytest.raises(app.ResolverError):
            app.choose_profile(['us.anthropic.claude-opus-5-5'], 'anthropic.claude-opus-5', 'regional', 'us-east-1')

    def test_two_regional_profiles_are_ambiguous(self, app):
        ids = ['us.anthropic.claude-opus-5-5', 'apac.anthropic.claude-opus-5-5']
        with pytest.raises(app.ResolverError, match='more than one regional profile'):
            app.choose_profile(ids, OPUS_55, 'regional', 'us-east-1')


# ---------------------------------------------------------------------------
# The probe and Bedrock errors (§3.2)
# ---------------------------------------------------------------------------

class TestProbe:

    def probe(self, app, runtime, deadline_s=200):
        return app.probe(runtime, 'us.anthropic.claude-opus-5-5', OPUS_55, 'us-east-1', 'high', 128000,
                         deadline=app.monotonic() + deadline_s)

    def test_sends_the_production_body(self, app):
        runtime = MagicMock(**{'converse.return_value': answer()})
        self.probe(app, runtime)
        body = runtime.converse.call_args.kwargs
        assert body['modelId'] == 'us.anthropic.claude-opus-5-5'
        assert body['messages'] == [{'role': 'user', 'content': [{'text': 'Reply with the single word OK.'}]}]
        assert body['inferenceConfig'] == {'maxTokens': 128000}
        assert body['additionalModelRequestFields'] == {'thinking': {'type': 'adaptive'},
                                                        'output_config': {'effort': 'high'}}
        assert body['additionalModelResponseFieldPaths'] == ['/stop_details']
        assert 'temperature' not in body['inferenceConfig'] and 'system' not in body

    def test_text_after_reasoning_passes(self, app):
        self.probe(app, MagicMock(**{'converse.return_value': answer('OK')}))

    def test_no_text_fails(self, app):
        runtime = MagicMock(**{'converse.return_value': answer(text=None, stop='content_filtered')})
        with pytest.raises(app.ResolverError, match='no text.*content_filtered'):
            self.probe(app, runtime)

    def test_use_case_form_missing(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error(
            'AccessDeniedException', 'Model use case details have not been submitted for this account.')})
        with pytest.raises(app.ResolverError) as e:
            self.probe(app, runtime)
        assert 'use-case form' in str(e.value) and 'put-use-case-for-model-access' in str(e.value)

    def test_other_access_denied(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error(
            'AccessDeniedException', 'You do not have access to the model with the specified model ID.')})
        with pytest.raises(app.ResolverError) as e:
            self.probe(app, runtime)
        message = str(e.value)
        assert 'aws-marketplace:Subscribe' in message and 'permission boundary' in message
        assert 'You do not have access' in message

    def test_max_tokens_above_model_limit(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error(
            'ValidationException', 'The maximum tokens you requested exceeds the model limit of 128000. '
                                   'Try again with a maximum tokens value that is lower than 128000.')})
        with pytest.raises(app.ResolverError) as e:
            self.probe(app, runtime)
        assert 'AIMaxTokens' in str(e.value) and OPUS_55 in str(e.value) and 'model limit of 128000' in str(e.value)

    def test_resource_not_found(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error('ResourceNotFoundException', 'Model not found.')})
        with pytest.raises(app.ResolverError) as e:
            self.probe(app, runtime)
        assert 'us.anthropic.claude-opus-5-5' in str(e.value) and 'us-east-1' in str(e.value)

    def test_validation_naming_the_model(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error(
            'ValidationException', 'The provided model identifier is invalid.')})
        with pytest.raises(app.ResolverError, match='cannot be used from us-east-1'):
            self.probe(app, runtime)

    def test_other_validation_error_is_a_request_mismatch(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error(
            'ValidationException', 'output_config.effort: Input should be low, medium, high, xhigh or max')})
        with pytest.raises(app.ResolverError) as e:
            self.probe(app, runtime)
        assert "doesn't accept SOAR's request" in str(e.value) and 'output_config.effort' in str(e.value)

    @pytest.mark.parametrize('code', ['ThrottlingException', 'ServiceUnavailableException', 'ModelTimeoutException',
                                      'ModelNotReadyException', 'InternalServerException'])
    def test_transient_error_is_retried(self, app, code):
        runtime = MagicMock(**{'converse.side_effect': [client_error(code, 'try again'), answer()]})
        self.probe(app, runtime)
        assert runtime.converse.call_count == 2
        app.sleep.assert_called_once()

    def test_transient_error_fails_when_time_runs_out(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error('ThrottlingException', 'Too many requests')})
        with pytest.raises(app.ResolverError, match='transient'):
            self.probe(app, runtime, deadline_s=5)

    def test_unknown_client_error_passes_the_code_and_message_through(self, app):
        runtime = MagicMock(**{'converse.side_effect': client_error('SomethingNewException', 'new failure mode')})
        with pytest.raises(app.ResolverError) as e:
            self.probe(app, runtime)
        assert 'SomethingNewException' in str(e.value) and 'new failure mode' in str(e.value)


# ---------------------------------------------------------------------------
# The handler: CloudFormation contract and the resolved config
# ---------------------------------------------------------------------------

class TestHandler:

    def test_create_probes_both_models_and_writes_the_config(self, app):
        status, kwargs, c = run_handler(app, cfn_event('Create'))
        assert status == 'SUCCESS'
        assert kwargs['physicalResourceId'] == 'ai-config-resolver'
        probed = [call.kwargs['modelId'] for call in c.runtime.converse.call_args_list]
        assert probed == ['us.anthropic.claude-opus-5-5', 'us.anthropic.claude-opus-4-8']
        put = c.ssm.put_parameter.call_args.kwargs
        assert put['Name'] == CONFIG_PARAMETER and put['Overwrite'] is True and put['Type'] == 'String'
        assert json.loads(put['Value']) == {
            'region': 'us-east-1', 'effort': 'high', 'maxTokens': 128000,
            'primary': {'modelId': OPUS_55, 'profileId': 'us.anthropic.claude-opus-5-5'},
            'fallback': {'modelId': OPUS_48, 'profileId': 'us.anthropic.claude-opus-4-8'}}

    def test_bedrock_clients_use_ai_region(self, app):
        _, _, c = run_handler(app, cfn_event('Create', {'AIRegion': 'eu-north-1'}),
                              bedrock=bedrock_with(['eu.anthropic.claude-opus-5-5', 'eu.anthropic.claude-opus-4-8']))
        regions = {call.args[0]: call.kwargs.get('region_name') for call in c.factory.call_args_list}
        assert regions['bedrock'] == 'eu-north-1' and regions['bedrock-runtime'] == 'eu-north-1'

    def test_update_echoes_the_existing_physical_id(self, app):
        status, kwargs, _ = run_handler(app, cfn_event('Update', physical_id='held-by-cloudformation'))
        assert status == 'SUCCESS' and kwargs['physicalResourceId'] == 'held-by-cloudformation'

    def test_no_fallback_probes_once_and_writes_null(self, app):
        status, _, c = run_handler(app, cfn_event('Create', {'AIFallbackModel': 'none'}))
        assert status == 'SUCCESS' and c.runtime.converse.call_count == 1
        assert json.loads(c.ssm.put_parameter.call_args.kwargs['Value'])['fallback'] is None

    def test_delete_succeeds_without_calls(self, app):
        status, kwargs, c = run_handler(app, cfn_event('Delete', physical_id='held-by-cloudformation'))
        assert status == 'SUCCESS' and kwargs['physicalResourceId'] == 'held-by-cloudformation'
        c.runtime.converse.assert_not_called()
        c.ssm.put_parameter.assert_not_called()

    def test_provider_none_succeeds_without_calls(self, app):
        status, _, c = run_handler(app, cfn_event('Create', {'AIProvider': 'NONE'}))
        assert status == 'SUCCESS'
        c.runtime.converse.assert_not_called()
        c.ssm.put_parameter.assert_not_called()

    def test_failure_reports_the_reason_and_writes_nothing(self, app):
        status, kwargs, c = run_handler(app, cfn_event('Create', {'AIModel': 'us.anthropic.claude-opus-5-5'}))
        assert status == 'FAILED'
        assert 'without a prefix' in kwargs['reason']
        assert kwargs['physicalResourceId'] == 'ai-config-resolver'
        c.ssm.put_parameter.assert_not_called()

    def test_fallback_failure_fails_the_deploy(self, app):
        runtime = MagicMock(**{'converse.side_effect': [answer(), client_error(
            'AccessDeniedException', 'You do not have access to the model with the specified model ID.')]})
        status, kwargs, c = run_handler(app, cfn_event('Create'), runtime=runtime)
        assert status == 'FAILED' and OPUS_48 in kwargs['reason']
        c.ssm.put_parameter.assert_not_called()

    def test_unexpected_exception_still_answers_cloudformation(self, app):
        bedrock = MagicMock()
        bedrock.get_paginator.side_effect = RuntimeError('boom')
        status, kwargs, _ = run_handler(app, cfn_event('Create'), bedrock=bedrock)
        assert status == 'FAILED' and 'boom' in kwargs['reason']

    @pytest.mark.parametrize('properties, expected', [
        ({'AILocality': 'nearby'}, 'AILocality'),
        ({'AIMaxTokens': 'lots'}, 'AIMaxTokens'),
        ({'AIMaxTokens': '0'}, 'AIMaxTokens'),
        ({'AIEffort': ''}, 'AIEffort'),
    ])
    def test_invalid_properties_fail(self, app, properties, expected):
        status, kwargs, _ = run_handler(app, cfn_event('Create', properties))
        assert status == 'FAILED' and expected in kwargs['reason']

    def test_runtime_read_timeout_fits_the_remaining_time(self, app):
        _, _, c = run_handler(app, cfn_event('Create'), remaining_ms=120_000)
        config = next(call.kwargs['config'] for call in c.factory.call_args_list if call.args[0] == 'bedrock-runtime')
        assert config.read_timeout <= 90
        assert config.retries == {'total_max_attempts': 1, 'mode': 'standard'}
