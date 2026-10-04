"""
Custom-resource Lambdas must report a stable PhysicalResourceId.

Without one, cfnresponse falls back to the Lambda's log stream name, which changes between invocations.
CloudFormation then treats every update as a replacement and sends a Delete for the old ID during
cleanup (HiQ, 2026-10-04: a Delete against broken code hung the cleanup). Update and Delete must echo
the ID CloudFormation holds; Create must return a fixed name.
"""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

FUNCTIONS = Path(__file__).parent.parent.parent / 'functions'

ISSUE_TABLES_ENV = {
    'LOCAL_CONTROL_AUTOREMEDIATION_SUPPRESSIONS_TABLE': 'autorem-suppressions',
    'LOCAL_CONTROL_SUPPRESSIONS_TABLE': 'control-suppressions',
    'LOCAL_INCIDENTS_SUPPRESSIONS_TABLE': 'incident-suppressions',
    'REMEDIATABLE_SEC_HUB_CONTROLS_TABLE': 'remediatable-controls',
    'SECURITY_ADM_ACCOUNT_ID': '111111111111',
    'ORG_ACCOUNT_ID': '222222222222',
    'AFT_MANAGEMENT_ACCOUNT_ID': '333333333333',
    'LOG_ARCHIVE_ACCOUNT_ID': '444444444444',
}

CASES = [
    # (function directory, module env, Create's fixed physical ID)
    ('ai/ai-prompts-syncer', {'AI_PROMPTS_TABLE': 'ai-prompts'}, 'ai-prompts-syncer'),
    ('setup/issue_tables_setup', ISSUE_TABLES_ENV, 'issue-tables-setup'),
]


def load_app(function_dir, env, monkeypatch):
    """Import a function's app.py by path with cfnresponse stubbed and DynamoDB mocked."""
    cfnresponse = SimpleNamespace(SUCCESS='SUCCESS', FAILED='FAILED', send=MagicMock())
    monkeypatch.setitem(sys.modules, 'cfnresponse', cfnresponse)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    table = MagicMock()
    table.scan.return_value = {'Items': [{'id': 'existing'}]}  # tables already populated: no writes
    with patch('boto3.resource') as resource:
        resource.return_value.Table.return_value = table
        spec = importlib.util.spec_from_file_location(f'app_{function_dir.replace("/", "_")}',
                                                      FUNCTIONS / function_dir / 'app.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module, cfnresponse.send, table


def event(request_type, physical_id=None):
    e = {'RequestType': request_type, 'ResponseURL': 'https://example.invalid/response',
         'StackId': 'arn:aws:cloudformation:eu-north-1:111111111111:stack/test/1',
         'RequestId': 'req-1', 'LogicalResourceId': 'CustomResource', 'ResourceProperties': {}}
    if physical_id:
        e['PhysicalResourceId'] = physical_id
    return e


def context(stream):
    return SimpleNamespace(log_stream_name=stream)


def physical_id_sent(send):
    _, kwargs = send.call_args
    return kwargs.get('physicalResourceId')


@pytest.mark.parametrize('function_dir, env, fixed_id', CASES, ids=[c[0] for c in CASES])
class TestPhysicalResourceId:

    def test_create_returns_fixed_id(self, function_dir, env, fixed_id, monkeypatch):
        monkeypatch.chdir(FUNCTIONS / function_dir)
        app, send, _ = load_app(function_dir, env, monkeypatch)
        app.lambda_handler(event('Create'), context('2026/10/04/[$LATEST]stream-a'))
        assert physical_id_sent(send) == fixed_id

    @pytest.mark.parametrize('request_type', ['Update', 'Delete'])
    def test_update_and_delete_echo_existing_id(self, function_dir, env, fixed_id, request_type, monkeypatch):
        monkeypatch.chdir(FUNCTIONS / function_dir)
        app, send, _ = load_app(function_dir, env, monkeypatch)
        app.lambda_handler(event(request_type, 'id-held-by-cloudformation'), context('2026/10/04/[$LATEST]stream-b'))
        assert physical_id_sent(send) == 'id-held-by-cloudformation'

    def test_failure_reports_the_same_id(self, function_dir, env, fixed_id, monkeypatch):
        monkeypatch.chdir(FUNCTIONS / function_dir)
        app, send, table = load_app(function_dir, env, monkeypatch)
        table.put_item.side_effect = RuntimeError('boom')
        table.scan.side_effect = RuntimeError('boom')
        app.lambda_handler(event('Create'), context('2026/10/04/[$LATEST]stream-c'))
        assert send.call_args.args[2] == 'FAILED'
        assert physical_id_sent(send) == fixed_id
