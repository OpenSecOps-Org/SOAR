"""
Function source tests: every Python file under functions/ compiles.

Most functions are imported by their own tests, but some are not (custom-resource Lambdas such as
issue_tables_setup), and a syntax error there surfaced only when CloudFormation invoked the function
during a deploy: v2.4.1 shipped `{'id': 'S3.10'}.` in issue_tables_setup/app.py.
"""

import subprocess
from pathlib import Path

import pytest

FUNCTIONS = Path(__file__).parent.parent.parent / 'functions'
SOURCES = sorted(p for p in FUNCTIONS.rglob('*.py') if '__pycache__' not in p.parts)


def test_sources_are_found():
    """Guard against the scan silently matching nothing."""
    assert FUNCTIONS / 'setup' / 'issue_tables_setup' / 'app.py' in SOURCES


@pytest.mark.parametrize('source', SOURCES, ids=lambda p: str(p.relative_to(FUNCTIONS)))
def test_function_source_compiles(source):
    compile(source.read_text(), str(source), 'exec')


@pytest.mark.skipif(not (FUNCTIONS.parent / '.git').exists(), reason='not a git checkout')
def test_no_function_source_is_git_ignored():
    """Layer sources live under python/lib/, which the generic Python `lib/` ignore rule matched: a new layer
    module (aws_utils/errors.py) existed locally, passed every test, and would not have been committed."""
    result = subprocess.run(['git', 'check-ignore', '--no-index', *map(str, SOURCES)],
                            cwd=FUNCTIONS.parent, capture_output=True, text=True)
    assert result.stdout == '', f'git-ignored function sources:\n{result.stdout}'
