"""
Function dependency tests: modules a function imports must be in its deployment package.

`cfnresponse` is provided by AWS only for Lambda code written inline in a template (`ZipFile`).
SAM-packaged functions, which is all of SOAR's, must bundle it through their requirements.
When it was missing, the custom-resource Lambdas failed at import (`No module named 'cfnresponse'`),
CloudFormation never got a response, and the stack waited an hour before rolling back.
"""

import re
from pathlib import Path

import pytest

FUNCTIONS = Path(__file__).parent.parent.parent / 'functions'


def functions_importing(module):
    """Function directories whose app.py imports the given top-level module."""
    pattern = re.compile(rf'^\s*(import\s+{module}\b|from\s+{module}\b)', re.MULTILINE)
    return sorted(app.parent for app in FUNCTIONS.rglob('app.py') if pattern.search(app.read_text()))


CFNRESPONSE_USERS = functions_importing('cfnresponse')


def test_custom_resource_functions_are_found():
    """Guard against the scan silently matching nothing."""
    names = {d.name for d in CFNRESPONSE_USERS}
    assert {'ai-prompts-syncer', 'issue_tables_setup'} <= names


@pytest.mark.parametrize('function_dir', CFNRESPONSE_USERS, ids=lambda d: d.name)
def test_cfnresponse_is_declared_and_hash_pinned(function_dir):
    requirements_in = (function_dir / 'requirements.in').read_text()
    assert re.search(r'^cfnresponse\b', requirements_in, re.MULTILINE), \
        f'{function_dir.name}: requirements.in must declare cfnresponse'

    lock = (function_dir / 'requirements.txt').read_text()
    pinned = re.search(r'^cfnresponse==\S+ \\\n\s+--hash=sha256:[0-9a-f]{64}', lock, re.MULTILINE)
    assert pinned, f'{function_dir.name}: requirements.txt must pin cfnresponse with a hash'
