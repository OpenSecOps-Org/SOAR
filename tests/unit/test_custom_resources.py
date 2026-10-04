"""
Custom resource tests: every custom resource sets a short ServiceTimeout.

Without ServiceTimeout, CloudFormation waits 3600 s for a custom resource that never responds, and a
rollback that calls the same broken Lambda waits another hour. The backing Lambdas time out after 30 s;
300 s leaves room for Lambda's two asynchronous retries.
"""

from pathlib import Path

import pytest
import yaml

TEMPLATE = Path(__file__).parent.parent.parent / 'template.yaml'
MAX_SERVICE_TIMEOUT = 300


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that accepts CloudFormation tags (!Ref, !GetAtt, !Sub, ...) without resolving them."""


CfnLoader.add_multi_constructor('!', lambda loader, suffix, node: None)


def custom_resources():
    resources = yaml.load(TEMPLATE.read_text(), Loader=CfnLoader)['Resources']
    return {name: r for name, r in resources.items()
            if r['Type'] == 'AWS::CloudFormation::CustomResource' or r['Type'].startswith('Custom::')}


CUSTOM_RESOURCES = custom_resources()


def test_custom_resources_are_found():
    """Guard against the scan silently matching nothing."""
    assert {'AIPromptsSyncerCustomResource', 'IssueTablesSetupCustomResource'} <= set(CUSTOM_RESOURCES)


@pytest.mark.parametrize('name', sorted(CUSTOM_RESOURCES))
def test_custom_resource_sets_short_service_timeout(name):
    timeout = CUSTOM_RESOURCES[name]['Properties'].get('ServiceTimeout')
    assert timeout is not None, f'{name}: set ServiceTimeout (default is 3600 s)'
    assert 1 <= int(timeout) <= MAX_SERVICE_TIMEOUT, f'{name}: ServiceTimeout {timeout} must be 1..{MAX_SERVICE_TIMEOUT}'
