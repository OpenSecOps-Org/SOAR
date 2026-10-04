"""
Function source tests: every Python file under functions/ compiles.

Most functions are imported by their own tests, but some are not (custom-resource Lambdas such as
issue_tables_setup), and a syntax error there surfaced only when CloudFormation invoked the function
during a deploy: v2.4.1 shipped `{'id': 'S3.10'}.` in issue_tables_setup/app.py.
"""

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
