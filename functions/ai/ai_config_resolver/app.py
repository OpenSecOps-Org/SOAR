"""
AI config resolver: a CloudFormation custom resource that runs on every deploy changing the AI settings.

It looks up the Bedrock inference profiles for the configured Claude models (AIModel, AIFallbackModel)
in AIRegion by locality, probes each model once with SOAR's production request, and writes the resolved
config to SSM for QueryAI. Any problem fails the deploy with a message that says what to fix.
SOAR stores no model or region lists: everything is asked of Bedrock at deploy time.
"""

import json
import logging
import os
import re
from time import monotonic, sleep

import boto3
import cfnresponse
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CONFIG_PARAMETER = os.environ['CONFIG_PARAMETER']

# Keep the ID CloudFormation already holds; cfnresponse's default (the log stream name) changes
# between invocations, which makes every update look like a replacement followed by a Delete.
FIXED_PHYSICAL_ID = 'ai-config-resolver'

PROBE_PROMPT = 'Reply with the single word OK.'
LOCALITIES = ('regional', 'global')
TRANSIENT_ERRORS = {'ThrottlingException', 'ServiceUnavailableException', 'ModelTimeoutException',
                    'ModelNotReadyException', 'InternalServerException'}
GEO_PREFIX = re.compile(r'^[a-z]{2,6}\.anthropic\.')

RESPONSE_MARGIN_S = 15   # time kept back to answer CloudFormation
MIN_CALL_S = 10          # don't start a probe with less time than this left


class ResolverError(Exception):
    """A configuration or access problem the operator must fix; its message becomes the deploy error."""


# ---------------------------------------------------------------------------
# Model IDs and profiles (ticket §3.1)
# ---------------------------------------------------------------------------

def check_model_id(model_id, key):
    if GEO_PREFIX.match(model_id) or model_id.startswith('global.anthropic.'):
        raise ResolverError(f'{key}: give the model ID without a prefix (got {model_id}); '
                            f'AILocality chooses the inference profile')
    if not model_id.startswith('anthropic.'):
        raise ResolverError(f'{key}: SOAR supports Claude models only (anthropic.*); got {model_id!r}')


def fallback_model(model_id, fallback_id):
    """The fallback model ID, or None when the fallback is disabled or the same as the model."""
    if fallback_id.lower() == 'none' or fallback_id == model_id:
        return None
    return fallback_id


def list_profile_ids(bedrock):
    paginator = bedrock.get_paginator('list_inference_profiles')
    return [p['inferenceProfileId']
            for page in paginator.paginate(typeEquals='SYSTEM_DEFINED')
            for p in page['inferenceProfileSummaries']]


def choose_profile(profile_ids, model_id, locality, region):
    """The one profile for model_id that matches the locality: global. for global, any other for regional."""
    mine = [p for p in profile_ids if p.split('.', 1)[-1] == model_id]
    if not mine:
        anthropic = sorted({p.split('.', 1)[-1] for p in profile_ids if p.split('.', 1)[-1].startswith('anthropic.')})
        raise ResolverError(f'no inference profile for {model_id} in {region}; '
                            f'Anthropic models with profiles there: {", ".join(anthropic) or "none"}')
    if locality == 'global':
        wanted = [p for p in mine if p.startswith('global.')]
    else:
        wanted = [p for p in mine if not p.startswith('global.')]
    if not wanted:
        raise ResolverError(f'no {locality} profile for {model_id} in {region}; available: {", ".join(mine)}')
    if len(wanted) > 1:
        raise ResolverError(f'more than one {locality} profile for {model_id} in {region}: {", ".join(wanted)}')
    return wanted[0]


# ---------------------------------------------------------------------------
# The probe (ticket §3.2)
# ---------------------------------------------------------------------------

def request_body(profile_id, effort, max_tokens, user_text):
    """SOAR's production Converse request (D2), as QueryAI sends it."""
    return {
        'modelId': profile_id,
        'messages': [{'role': 'user', 'content': [{'text': user_text}]}],
        'inferenceConfig': {'maxTokens': max_tokens},
        'additionalModelRequestFields': {
            'thinking': {'type': 'adaptive'},
            'output_config': {'effort': effort},
        },
        'additionalModelResponseFieldPaths': ['/stop_details'],
    }


def extract_text(response):
    blocks = response.get('output', {}).get('message', {}).get('content', [])
    return ''.join(b['text'] for b in blocks if 'text' in b)


def explain_client_error(error, model_id, profile_id, region):
    """Turn a Bedrock ClientError into a message that says what to fix. Codes first; messages are undocumented."""
    code = error.response.get('Error', {}).get('Code', '')
    message = error.response.get('Error', {}).get('Message', '')
    where = f'{model_id} ({profile_id})'
    lowered = message.lower()

    if code == 'AccessDeniedException':
        if 'use case' in lowered or 'use-case' in lowered:
            return (f'{where}: Anthropic\'s use-case form has not been submitted for this account. Submit it once '
                    f'(at the management account, it is inherited by the organisation) in the Bedrock console '
                    f'(Model catalog, any Anthropic model) or with `aws bedrock put-use-case-for-model-access '
                    f'--form-data <base64 JSON>`. Bedrock said: {message}')
        return (f'{where}: access denied. Likely causes: missing aws-marketplace:Subscribe, '
                f'aws-marketplace:Unsubscribe or aws-marketplace:ViewSubscriptions on the resolver role (needed for '
                f'a model\'s first use), the model\'s access criteria, or a permission boundary. Bedrock said: {message}')
    if code == 'ValidationException' and 'exceeds the model limit' in lowered:
        return f'{where}: AIMaxTokens is above this model\'s limit. Bedrock said: {message}'
    if code == 'ResourceNotFoundException' or (
            code == 'ValidationException' and re.search(r'model identifier|model id|inference profile', lowered)):
        return f'{where}: the profile cannot be used from {region}. Bedrock said: {message}'
    if code == 'ValidationException':
        return f'{where}: the model doesn\'t accept SOAR\'s request (for example the AIEffort value). Bedrock said: {message}'
    return f'{where}: {code}: {message}'


def probe(runtime, profile_id, model_id, region, effort, max_tokens, deadline):
    """Call the model once with the production body; retry transient errors while time allows."""
    backoff = 2
    while True:
        try:
            response = runtime.converse(**request_body(profile_id, effort, max_tokens, PROBE_PROMPT))
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', '')
            if code in TRANSIENT_ERRORS:
                if deadline - monotonic() < backoff + MIN_CALL_S:
                    raise ResolverError(f'{model_id} ({profile_id}): transient Bedrock error that did not clear '
                                        f'in time ({code}: {error.response["Error"].get("Message", "")}); '
                                        f'deploy again') from error
                logger.info('Transient %s from %s; retrying in %s s', code, profile_id, backoff)
                sleep(backoff)
                backoff *= 2
                continue
            raise ResolverError(explain_client_error(error, model_id, profile_id, region)) from error
        if not extract_text(response):
            raise ResolverError(f'{model_id} ({profile_id}): the probe returned no text '
                                f'(stopReason {response.get("stopReason")!r})')
        logger.info('Probe of %s passed (stopReason %s)', profile_id, response.get('stopReason'))
        return


# ---------------------------------------------------------------------------
# Resolution and the CloudFormation handler
# ---------------------------------------------------------------------------

def read_properties(properties):
    settings = {}
    for key in ('AIModel', 'AIFallbackModel', 'AIRegion', 'AILocality', 'AIEffort', 'AIMaxTokens'):
        value = str(properties.get(key, '')).strip()
        if not value:
            raise ResolverError(f'{key} is required')
        settings[key] = value
    if settings['AILocality'] not in LOCALITIES:
        raise ResolverError(f'AILocality must be regional or global; got {settings["AILocality"]!r}')
    try:
        settings['AIMaxTokens'] = int(settings['AIMaxTokens'])
    except ValueError:
        raise ResolverError(f'AIMaxTokens must be a whole number; got {settings["AIMaxTokens"]!r}') from None
    if settings['AIMaxTokens'] < 1:
        raise ResolverError(f'AIMaxTokens must be at least 1; got {settings["AIMaxTokens"]}')
    return settings


def resolve(settings, bedrock, runtime, ssm, deadline):
    """Look up and probe the models, then write the resolved config to SSM. Returns the config."""
    model_id = settings['AIModel']
    check_model_id(model_id, 'AIModel')
    fallback_id = fallback_model(model_id, settings['AIFallbackModel'])
    if fallback_id:
        check_model_id(fallback_id, 'AIFallbackModel')

    region, locality = settings['AIRegion'], settings['AILocality']
    profile_ids = list_profile_ids(bedrock)
    models = [m for m in (model_id, fallback_id) if m]
    profiles = {m: choose_profile(profile_ids, m, locality, region) for m in models}

    for m in models:
        probe(runtime, profiles[m], m, region, settings['AIEffort'], settings['AIMaxTokens'], deadline)

    config = {
        'region': region,
        'effort': settings['AIEffort'],
        'maxTokens': settings['AIMaxTokens'],
        'primary': {'modelId': model_id, 'profileId': profiles[model_id]},
        'fallback': {'modelId': fallback_id, 'profileId': profiles[fallback_id]} if fallback_id else None,
    }
    ssm.put_parameter(Name=CONFIG_PARAMETER, Value=json.dumps(config), Type='String', Overwrite=True)
    logger.info('Wrote %s: %s', CONFIG_PARAMETER, config)
    return config


def lambda_handler(event, context):
    physical_id = event.get('PhysicalResourceId', FIXED_PHYSICAL_ID)
    try:
        logger.info('Received event: %s', {k: v for k, v in event.items() if k != 'ResponseURL'})
        properties = event.get('ResourceProperties', {})

        if event.get('RequestType') == 'Delete':
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, physicalResourceId=physical_id)
            return
        if str(properties.get('AIProvider', '')).upper() == 'NONE':
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, physicalResourceId=physical_id,
                             reason='AIProvider is NONE; nothing resolved')
            return

        settings = read_properties(properties)
        remaining_s = context.get_remaining_time_in_millis() / 1000
        deadline = monotonic() + remaining_s - RESPONSE_MARGIN_S
        region = settings['AIRegion']
        bedrock = boto3.client('bedrock', region_name=region)
        runtime = boto3.client('bedrock-runtime', region_name=region, config=Config(
            read_timeout=max(MIN_CALL_S, int(remaining_s - 30)), connect_timeout=10,
            retries={'total_max_attempts': 1, 'mode': 'standard'}))
        ssm = boto3.client('ssm')

        config = resolve(settings, bedrock, runtime, ssm, deadline)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, physicalResourceId=physical_id,
                         reason=f'Resolved {config["primary"]["profileId"]}'
                                + (f' with fallback {config["fallback"]["profileId"]}' if config['fallback'] else ''))

    except ResolverError as e:
        logger.error('AI config resolution failed: %s', e)
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, physicalResourceId=physical_id, reason=str(e))
    except Exception as e:  # noqa: BLE001 - CloudFormation must get an answer on every path
        logger.exception('Unexpected error')
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, physicalResourceId=physical_id,
                         reason=f'Unexpected error: {type(e).__name__}: {e}')
