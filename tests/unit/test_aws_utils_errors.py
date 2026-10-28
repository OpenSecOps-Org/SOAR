"""
The named errors the state machines retry (aws_utils.errors) and the BatchUpdateFindings result check
(aws_utils.security_hub).

Lambdas run by a state machine do not retry; the state machine does, and it can only retry an error it can
name. Step Functions names a Lambda error after the exception's class, so a transient AWS error must leave
the Lambda as AWSTransientError, and every other error must keep its own name.
"""

import os
import sys

import botocore.exceptions
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'functions', 'layers', 'aws_utils',
                                'python', 'lib', 'python3.12', 'site-packages'))

from aws_utils.errors import (AWSTransientError, TicketingRequestError, TicketingTransientError, is_transient,
                              is_transient_status, transient_aws_errors)
from aws_utils.security_hub import SecurityHubUpdateRejected, check_batch_update


def client_error(code, status=400):
    return botocore.exceptions.ClientError(
        {'Error': {'Code': code, 'Message': 'test'}, 'ResponseMetadata': {'HTTPStatusCode': status}},
        'BatchUpdateFindings')


THROTTLES = [('TooManyRequestsException', 429), ('ThrottlingException', 400), ('Throttling', 400),
             ('ProvisionedThroughputExceededException', 400), ('RequestLimitExceeded', 503),
             ('SlowDown', 503), ('LimitExceededException', 429)]
SERVER_SIDE = [('InternalException', 500), ('InternalServerError', 500), ('ServiceUnavailable', 503),
               ('RequestTimeout', 408)]
PERMANENT = [('AccessDeniedException', 403), ('InvalidAccessException', 401), ('InvalidInputException', 400),
             ('ResourceNotFoundException', 404), ('ValidationException', 400),
             ('LimitExceededException', 409)]  # without a 429, a hard quota rather than throttling


class TestIsTransient:

    @pytest.mark.parametrize('code, status', THROTTLES + SERVER_SIDE)
    def test_throttling_and_server_side_errors_are_transient(self, code, status):
        assert is_transient(client_error(code, status))

    @pytest.mark.parametrize('code, status', PERMANENT)
    def test_other_client_errors_are_not(self, code, status):
        assert not is_transient(client_error(code, status))

    @pytest.mark.parametrize('error', [
        botocore.exceptions.EndpointConnectionError(endpoint_url='https://securityhub'),
        botocore.exceptions.ConnectTimeoutError(endpoint_url='https://securityhub'),
        botocore.exceptions.ReadTimeoutError(endpoint_url='https://securityhub'),
        botocore.exceptions.ConnectionClosedError(endpoint_url='https://securityhub')])
    def test_connection_problems_are_transient(self, error):
        assert is_transient(error)

    def test_an_aws_transient_error_is_transient(self):
        assert is_transient(AWSTransientError('throttled'))

    @pytest.mark.parametrize('error', [KeyError('finding'), ValueError('bad'), Exception('anything'),
                                       botocore.exceptions.NoCredentialsError()])
    def test_other_errors_are_not(self, error):
        assert not is_transient(error)

    def test_a_client_error_without_response_metadata_is_judged_by_its_code(self):
        assert is_transient(botocore.exceptions.ClientError({'Error': {'Code': 'Throttling'}}, 'op'))
        assert not is_transient(botocore.exceptions.ClientError({'Error': {'Code': 'AccessDenied'}}, 'op'))


@pytest.mark.parametrize('status, transient', [(429, True), (500, True), (502, True), (503, True), (504, True),
                                               (599, True), (200, False), (400, False), (401, False),
                                               (403, False), (404, False), (409, False), (None, False)])
def test_is_transient_status(status, transient):
    assert is_transient_status(status) is transient


class TestTransientAwsErrors:

    def test_returns_what_the_handler_returns(self):
        handler = transient_aws_errors(lambda data, context: {'seen': data})
        assert handler('x', None) == {'seen': 'x'}

    @pytest.mark.parametrize('code, status', THROTTLES + SERVER_SIDE)
    def test_a_transient_aws_error_leaves_as_aws_transient_error(self, code, status):
        original = client_error(code, status)

        @transient_aws_errors
        def handler(data, context):
            raise original

        with pytest.raises(AWSTransientError) as raised:
            handler({}, None)
        assert type(raised.value).__name__ == 'AWSTransientError'  # the name Step Functions matches on
        assert raised.value.__cause__ is original
        assert code in str(raised.value)

    @pytest.mark.parametrize('code, status', PERMANENT)
    def test_other_aws_errors_keep_their_own_name(self, code, status):
        original = client_error(code, status)

        @transient_aws_errors
        def handler(data, context):
            raise original

        with pytest.raises(botocore.exceptions.ClientError) as raised:
            handler({}, None)
        assert raised.value is original

    @pytest.mark.parametrize('original', [KeyError('finding'), ValueError('bad'), TicketingTransientError('429'),
                                          TicketingRequestError('401')])
    def test_non_aws_errors_pass_through_unchanged(self, original):
        @transient_aws_errors
        def handler(data, context):
            raise original

        with pytest.raises(type(original)) as raised:
            handler({}, None)
        assert raised.value is original

    def test_an_aws_transient_error_raised_inside_passes_through_unchanged(self):
        original = AWSTransientError('ConcurrentUpdateError')

        @transient_aws_errors
        def handler(data, context):
            raise original

        with pytest.raises(AWSTransientError) as raised:
            handler({}, None)
        assert raised.value is original

    def test_keeps_the_handler_name(self):
        def lambda_handler(data, context):
            return data
        assert transient_aws_errors(lambda_handler).__name__ == 'lambda_handler'


def unprocessed(code, message='msg'):
    return {'ErrorCode': code, 'ErrorMessage': message,
            'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': 'arn:aws:securityhub:::product/aws/inspector'}}


class TestCheckBatchUpdate:

    def test_all_processed_is_an_update(self):
        assert check_batch_update({'ProcessedFindings': [{'Id': 'finding-1'}], 'UnprocessedFindings': []}) is True

    def test_a_finding_that_no_longer_exists_is_skipped_with_a_warning(self, capsys):
        assert check_batch_update({'ProcessedFindings': [], 'UnprocessedFindings': [unprocessed('FindingNotFound')]}) \
            is False
        assert 'FindingNotFound' in capsys.readouterr().out

    @pytest.mark.parametrize('code', ['ConcurrentUpdateError', 'InternalFailure'])
    def test_a_concurrent_update_or_internal_failure_is_retried(self, code):
        with pytest.raises(AWSTransientError) as raised:
            check_batch_update({'ProcessedFindings': [], 'UnprocessedFindings': [unprocessed(code)]})
        assert code in str(raised.value) and 'finding-1' in str(raised.value)

    @pytest.mark.parametrize('code', ['DuplicatedFindingIdentifier', 'FindingSizeExceeded', 'InvalidInput',
                                      'SomeFutureCode'])
    def test_anything_else_is_rejected_and_not_retried(self, code):
        with pytest.raises(SecurityHubUpdateRejected) as raised:
            check_batch_update({'ProcessedFindings': [], 'UnprocessedFindings': [unprocessed(code)]})
        assert type(raised.value).__name__ == 'SecurityHubUpdateRejected'
        assert code in str(raised.value) and 'finding-1' in str(raised.value)
        assert not is_transient(raised.value)
