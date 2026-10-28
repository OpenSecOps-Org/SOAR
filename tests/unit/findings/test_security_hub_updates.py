"""
The four Lambdas that update a finding with BatchUpdateFindings at the end of a workflow.

A burst of findings (a scan) throttles BatchUpdateFindings, and Security Hub reports ConcurrentUpdateError
while the scanner is still importing the same findings. Both must leave the Lambda as AWSTransientError,
which the state machines retry. A finding that no longer exists needs no update. Anything else fails with
its own name and is not retried.
"""

import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'functions', 'layers', 'aws_utils',
                                'python', 'lib', 'python3.12', 'site-packages'))
os.environ.setdefault('PRODUCT_NAME', 'OpenSecOps SOAR')

from aws_utils.errors import AWSTransientError
from aws_utils.security_hub import SecurityHubUpdateRejected

# module -> the workflow status it sets (None: the status is left alone)
LAMBDAS = {
    'functions.findings.suppress_finding.app': 'SUPPRESSED',
    'functions.findings.update_ticketed_finding.app': 'NOTIFIED',
    'functions.findings.update_remediated_finding.app': 'RESOLVED',
    'functions.findings.update_closed_finding.app': None,
}
FINDING = {'Id': 'arn:aws:inspector2:eu-north-1:111111111111:finding/test', 'AwsAccountId': '111111111111',
           'ProductArn': 'arn:aws:securityhub:eu-north-1::product/aws/inspector',
           'UserDefinedFields': {'TicketOpen': 'Yes', 'TicketId': 'TEST-1'}}


def scratchpad():
    return {'finding': dict(FINDING), 'account': {'Id': '111111111111', 'Name': 'test'},
            'ticket': {'TicketOpen': 'Yes', 'TicketId': 'TEST-1'}, 'actions': {}}


def client_error(code, status):
    return botocore.exceptions.ClientError(
        {'Error': {'Code': code, 'Message': 'test'}, 'ResponseMetadata': {'HTTPStatusCode': status}},
        'BatchUpdateFindings')


def unprocessed(code):
    return {'ProcessedFindings': [], 'UnprocessedFindings': [
        {'ErrorCode': code, 'ErrorMessage': 'test', 'FindingIdentifier': {'Id': FINDING['Id']}}]}


def run(module_name, response=None, error=None):
    module = importlib.import_module(module_name)
    client = MagicMock()
    if error is not None:
        client.batch_update_findings.side_effect = error
    else:
        client.batch_update_findings.return_value = response
    with patch.object(module, 'get_client', return_value=client) as get_client:
        data = scratchpad()
        result = module.lambda_handler(data, None)
    return result, data, client, get_client


@pytest.mark.parametrize('module_name, status', LAMBDAS.items(), ids=lambda v: str(v).split('.')[-2]
                         if isinstance(v, str) and '.' in v else str(v))
class TestSecurityHubUpdate:

    def test_updates_the_finding_in_its_own_account(self, module_name, status):
        result, data, client, get_client = run(module_name, {'ProcessedFindings': [{'Id': FINDING['Id']}],
                                                             'UnprocessedFindings': []})
        assert result is data
        get_client.assert_called_once_with('securityhub', '111111111111')
        kwargs = client.batch_update_findings.call_args.kwargs
        assert kwargs['FindingIdentifiers'] == [{'Id': FINDING['Id'], 'ProductArn': FINDING['ProductArn']}]
        assert kwargs.get('Workflow', {}).get('Status') == status

    @pytest.mark.parametrize('code, http', [('TooManyRequestsException', 429), ('LimitExceededException', 429),
                                            ('ThrottlingException', 400), ('InternalException', 500)])
    def test_throttling_and_server_errors_leave_as_aws_transient_error(self, module_name, status, code, http):
        with pytest.raises(AWSTransientError) as raised:
            run(module_name, error=client_error(code, http))
        assert type(raised.value).__name__ == 'AWSTransientError'
        assert code in str(raised.value)

    @pytest.mark.parametrize('code', ['ConcurrentUpdateError', 'InternalFailure'])
    def test_a_concurrent_update_or_internal_failure_leaves_as_aws_transient_error(self, module_name, status, code):
        with pytest.raises(AWSTransientError):
            run(module_name, unprocessed(code))

    def test_a_finding_that_no_longer_exists_is_not_an_error(self, module_name, status):
        result, data, _, _ = run(module_name, unprocessed('FindingNotFound'))
        assert result is data

    @pytest.mark.parametrize('code', ['InvalidInput', 'FindingSizeExceeded', 'DuplicatedFindingIdentifier'])
    def test_a_rejected_update_fails_and_is_not_retried(self, module_name, status, code):
        with pytest.raises(SecurityHubUpdateRejected):
            run(module_name, unprocessed(code))

    @pytest.mark.parametrize('code, http', [('AccessDeniedException', 403), ('InvalidAccessException', 401)])
    def test_other_aws_errors_keep_their_own_name(self, module_name, status, code, http):
        with pytest.raises(botocore.exceptions.ClientError) as raised:
            run(module_name, error=client_error(code, http))
        assert not isinstance(raised.value, AWSTransientError)
