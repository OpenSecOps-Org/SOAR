"""Smoke tests for functions/ai/query_ai/app.py."""
import json
import sys
from importlib import import_module
from unittest.mock import MagicMock, patch

import pytest


QUERY_AI_ENV = {
    'AI_PROVIDER': 'BEDROCK',
    'AI_IAC_SNIPPETS': 'terraform',
    'AI_ANONYMIZE_ACCOUNT_NUMBERS': 'Yes',
    'AI_ANONYMIZE_HEX_STRINGS': 'No',
    'AI_REMOVE_ARNS': 'No',
    'AI_REMOVE_EMAIL_ADDRESSES': 'No',
    'BEDROCK_REGION': 'us-east-1',
    'BEDROCK_MODEL': 'anthropic.claude-3-sonnet',
    'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:111111111111:soar-ai-errors',
}


def _install_lambda_dep_stubs():
    """Stub Lambda-only deps that aren't installed in the test env."""
    if 'html2text' not in sys.modules:
        html2text_stub = type(sys)('html2text')
        html2text_stub.html2text = lambda html: html
        sys.modules['html2text'] = html2text_stub

    if 'bs4' not in sys.modules:
        bs4_stub = type(sys)('bs4')

        class _Soup:
            def __init__(self, html, parser):
                self._html = html
            def find_all(self, _tag):
                return []
            def __str__(self):
                return self._html

        bs4_stub.BeautifulSoup = _Soup
        sys.modules['bs4'] = bs4_stub


def _load_app(provider):
    """Import functions.ai.query_ai.app with env + boto3 mocked."""
    env = {**QUERY_AI_ENV, 'AI_PROVIDER': provider}
    query_ai_dir = '/Users/pjotr/ProjectCode/AWS/OPENSECOPS-DEV/SOAR/functions/ai/query_ai'
    if query_ai_dir not in sys.path:
        sys.path.insert(0, query_ai_dir)

    _install_lambda_dep_stubs()

    mock_bedrock = MagicMock()
    mock_sns = MagicMock()

    def fake_client(service, **kwargs):
        if service == 'bedrock-runtime':
            return mock_bedrock
        if service == 'sns':
            return mock_sns
        return MagicMock()

    with patch.dict('os.environ', env, clear=False), \
         patch('boto3.client', side_effect=fake_client):
        if 'app' in sys.modules:
            del sys.modules['app']
        app = import_module('app')

    return app, mock_bedrock, mock_sns


class TestQueryAiSmoke:
    def test_none_provider_returns_data_unchanged(self):
        app, _, _ = _load_app('NONE')
        data = {'user': 'hi', 'instructions': 'do thing'}
        result = app.lambda_handler(dict(data), None)
        assert result == data

    def test_bedrock_provider_invokes_model_and_populates_ai_message(self):
        app, mock_bedrock, _ = _load_app('BEDROCK')

        body_stream = MagicMock()
        body_stream.read.return_value = json.dumps({
            'content': [{'text': '<div>hello</div>'}]
        }).encode('utf-8')
        mock_bedrock.invoke_model.return_value = {'body': body_stream}

        data = {'user': 'question text', 'instructions': 'be helpful', 'no_html_post_processing': True}
        result = app.lambda_handler(data, None)

        mock_bedrock.invoke_model.assert_called_once()
        call_kwargs = mock_bedrock.invoke_model.call_args.kwargs
        assert call_kwargs['modelId'] == 'anthropic.claude-3-sonnet'

        assert result['messages']['ai']['html'] == '<div>hello</div>'
        assert 'hello' in result['messages']['ai']['plaintext']

    def test_bedrock_error_sends_sns_and_raises(self):
        app, mock_bedrock, mock_sns = _load_app('BEDROCK')
        mock_bedrock.invoke_model.side_effect = RuntimeError('boom')

        with pytest.raises(RuntimeError):
            app.lambda_handler({'user': 'q', 'instructions': 'i'}, None)

        mock_sns.publish.assert_called_once()
