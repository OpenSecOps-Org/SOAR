"""
template.yaml: the AI settings (ticket D3, D8, D9, §3.2).

Six required AI parameters with no defaults replace BedrockModel/BedrockRegion; the resolver custom
resource receives them all; QueryAI reads the resolved config and publishes no errors.
"""

from pathlib import Path

import pytest
import yaml

TEMPLATE = Path(__file__).parent.parent.parent / 'template.yaml'
AI_PARAMETERS = ['AIModel', 'AIFallbackModel', 'AIRegion', 'AILocality', 'AIEffort', 'AIMaxTokens']


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that keeps CloudFormation tags as {'!Tag': value} so references can be checked."""


CfnLoader.add_multi_constructor(
    '!', lambda loader, suffix, node: {f'!{suffix}': loader.construct_scalar(node)
                                      if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)})

T = yaml.load(TEMPLATE.read_text(), Loader=CfnLoader)
PARAMS, RESOURCES = T['Parameters'], T['Resources']


@pytest.mark.parametrize('name', AI_PARAMETERS)
def test_ai_parameter_exists_without_default(name):
    assert name in PARAMS
    assert 'Default' not in PARAMS[name], f'{name} must have no default (D3, D9)'


def test_old_bedrock_parameters_are_gone():
    assert 'BedrockModel' not in PARAMS and 'BedrockRegion' not in PARAMS


def test_parameter_types():
    assert PARAMS['AILocality']['AllowedValues'] == ['regional', 'global']
    assert PARAMS['AIMaxTokens']['Type'] == 'Number'


def test_resolver_receives_every_ai_setting():
    properties = RESOURCES['AIConfigResolverCustomResource']['Properties']
    for name in AI_PARAMETERS + ['AIProvider']:
        assert properties[name] == {'!Ref': name}


def test_resolver_finishes_inside_its_service_timeout():
    timeout = RESOURCES['AIConfigResolverFunction']['Properties']['Timeout']
    service_timeout = int(RESOURCES['AIConfigResolverCustomResource']['Properties']['ServiceTimeout'])
    assert timeout + 30 <= service_timeout


def test_resolver_and_query_ai_share_the_config_parameter():
    resolver_env = RESOURCES['AIConfigResolverFunction']['Properties']['Environment']['Variables']
    query_ai_env = RESOURCES['QueryAIFunction']['Properties']['Environment']['Variables']
    assert resolver_env['CONFIG_PARAMETER'] == {'!Ref': 'AIResolvedConfigParameter'}
    assert query_ai_env['AI_CONFIG_PARAMETER'] == {'!Ref': 'AIResolvedConfigParameter'}


def test_query_ai_publishes_no_errors():
    """QueryAI raises typed errors; the state machines publish them (D8)."""
    query_ai = RESOURCES['QueryAIFunction']['Properties']
    env = query_ai['Environment']['Variables']
    assert 'SNS_TOPIC_ARN' not in env
    assert not any(k.startswith('BEDROCK_') for k in env)
    assert env['FALLBACK_SNS_TOPIC_ARN'] == {'!Ref': 'AIFallbackSNSTopic'}
    statements = [s for p in query_ai['Policies'] if 'Statement' in p for s in p['Statement']]
    published = [s['Resource'] for s in statements if 'sns:Publish' in s['Action']]
    assert published == [{'!Ref': 'AIFallbackSNSTopic'}]


def test_fallback_topic_has_no_subscriptions():
    assert RESOURCES['AIFallbackSNSTopic']['Properties']['TopicName'] == 'OpenSecOpsSOARAIFallbacks'
    assert not any(r['Type'] == 'AWS::SNS::Subscription' for r in RESOURCES.values())
