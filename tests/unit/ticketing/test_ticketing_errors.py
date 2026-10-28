"""
Error handling of the ticketing Lambdas (open_ticket, close_ticket).

A burst of findings rate limits the ticketing system. A rate limit (429), a failure on the ticketing
system's side (5xx) or a connection problem leaves the Lambda as TicketingTransientError, which the state
machines retry. Opening a ticket that the ticketing system refuses for any other reason fails with
TicketingRequestError; no ticket ID is made up. Once a ticket has been created, later errors in the same
invocation are only logged: a retry would create the ticket again.

The tests make no network calls: JIRA, requests and SSM are replaced.
"""

import importlib
import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'functions', 'layers', 'aws_utils',
                                'python', 'lib', 'python3.12', 'site-packages'))

from aws_utils.errors import TicketingRequestError, TicketingTransientError


class FakeJIRAError(Exception):
    """Stands in for jira.JIRAError: a message and the HTTP status code."""

    def __init__(self, text=None, status_code=None, **kwargs):
        super().__init__(text)
        self.text = text
        self.status_code = status_code


ENV = {
    'TICKETING_SYSTEM': 'JIRA',
    'JIRA_SERVER_URL_PARAMETER_PATH': '/test/jira/url',
    'JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH': '/test/jira/user',
    'JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH': '/test/jira/token',
    'JIRA_DEFAULT_PROJECT_KEY': 'DEF',
    'JIRA_ISSUE_TYPE': 'Bug',
    'JIRA_PRIORITIES': 'Lowest,Low,Medium,High,Highest',
    'JIRA_INITIAL_STATES': 'To Do',
    'JIRA_FINAL_STATE': 'Done',
    'SERVICE_NOW_URL_PARAMETER_PATH': '/test/snow/url',
    'SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH': '/test/snow/user',
    'SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH': '/test/snow/password',
    'SERVICE_NOW_TABLE': 'u_incident',
    'SERVICE_NOW_DEFAULT_PROJECT_QUEUE': 'DEFAULT',
    'SERVICE_NOW_ISSUE_TYPE': 'Incident',
    'SERVICE_NOW_FINAL_STATE': '7',
    'SOC_JIRA_PROJECT_KEY_OR_SERVICE_NOW_QUEUE': 'SOC',
    'INCIDENTS_TO_SOC': 'NONE',
}


def load(module_name, ticketing_system):
    """Import a ticketing Lambda with SSM and the jira package replaced."""
    fake_jira = types.ModuleType('jira')
    fake_jira.JIRA = MagicMock(name='JIRA')
    fake_jira.JIRAError = FakeJIRAError
    ssm = MagicMock()
    ssm.get_parameter.return_value = {'Parameter': {'Value': 'https://ticketing.example.com'}}
    # Only the jira entry is swapped: the Lambda must share aws_utils.errors (and its classes) with this test
    real_jira = sys.modules.get('jira')
    sys.modules['jira'] = fake_jira
    try:
        with patch.dict(os.environ, {**ENV, 'TICKETING_SYSTEM': ticketing_system}), \
                patch('boto3.client', return_value=ssm):
            sys.modules.pop(module_name, None)
            module = importlib.import_module(module_name)
    finally:
        if real_jira is None:
            sys.modules.pop('jira', None)
        else:
            sys.modules['jira'] = real_jira
    return module


def ticket_scratchpad():
    return {'finding': {'Id': 'finding-1', 'Severity': {'Label': 'HIGH'}, 'ProductFields': {}},
            'account': {'ProjectId': 'TEAM', 'Name': 'test-account'},
            'messages': {'email': {'subject': 'Subject', 'body': 'Body'}}}


def response(status, json=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json if json is not None else {}
    r.text = 'body'
    if status >= 400:
        r.raise_for_status.side_effect = requests.exceptions.HTTPError(response=r)
    return r


TRANSIENT_STATUSES = [429, 500, 503]
REFUSED_STATUSES = [400, 401, 403]
CONNECTION_ERRORS = [requests.exceptions.ConnectionError('refused'), requests.exceptions.Timeout('timed out')]


# ---------------------------------------------------------------------------
# open_ticket, Jira
# ---------------------------------------------------------------------------

class TestOpenJiraTicket:

    @pytest.fixture
    def app(self):
        return load('functions.ticketing.open_ticket.app', 'JIRA')

    def jira(self, app):
        return app.JIRA.return_value

    def test_creates_the_ticket(self, app):
        self.jira(app).create_issue.return_value.key = 'TEAM-1'
        assert app.lambda_handler(ticket_scratchpad(), None) == {'TicketOpen': 'Yes', 'TicketId': 'TEAM-1'}

    @pytest.mark.parametrize('status', TRANSIENT_STATUSES)
    def test_a_rate_limited_create_is_retried(self, app, status):
        self.jira(app).create_issue.side_effect = FakeJIRAError('busy', status_code=status)
        with pytest.raises(TicketingTransientError):
            app.lambda_handler(ticket_scratchpad(), None)

    @pytest.mark.parametrize('status', REFUSED_STATUSES + [None])
    def test_a_refused_create_fails_and_no_ticket_id_is_made_up(self, app, status):
        self.jira(app).create_issue.side_effect = FakeJIRAError('refused', status_code=status)
        with pytest.raises(TicketingRequestError):
            app.lambda_handler(ticket_scratchpad(), None)

    @pytest.mark.parametrize('error', CONNECTION_ERRORS)
    def test_an_unreachable_jira_is_retried(self, app, error):
        self.jira(app).create_issue.side_effect = error
        with pytest.raises(TicketingTransientError):
            app.lambda_handler(ticket_scratchpad(), None)

    @pytest.mark.parametrize('status', TRANSIENT_STATUSES)
    def test_a_rate_limited_connect_is_retried(self, app, status):
        app.JIRA.side_effect = FakeJIRAError('busy', status_code=status)
        with pytest.raises(TicketingTransientError):
            app.lambda_handler(ticket_scratchpad(), None)

    def test_a_refused_connect_fails(self, app):
        app.JIRA.side_effect = FakeJIRAError('unauthorized', status_code=401)
        with pytest.raises(TicketingRequestError):
            app.lambda_handler(ticket_scratchpad(), None)

    @pytest.mark.parametrize('status', TRANSIENT_STATUSES)
    def test_a_rate_limited_project_check_is_retried_not_taken_as_a_missing_project(self, app, status):
        self.jira(app).project.side_effect = FakeJIRAError('busy', status_code=status)
        with pytest.raises(TicketingTransientError):
            app.lambda_handler(ticket_scratchpad(), None)
        self.jira(app).create_issue.assert_not_called()

    def test_a_missing_project_falls_back_to_the_default_project(self, app):
        self.jira(app).project.side_effect = FakeJIRAError('no such project', status_code=404)
        self.jira(app).create_issue.return_value.key = 'DEF-1'
        assert app.lambda_handler(ticket_scratchpad(), None)['TicketId'] == 'DEF-1'
        assert self.jira(app).create_issue.call_args.kwargs['project'] == 'DEF'

    @pytest.mark.parametrize('status', TRANSIENT_STATUSES + REFUSED_STATUSES)
    def test_errors_after_the_ticket_exists_are_only_logged(self, app, status):
        """A retry would create the ticket a second time."""
        self.jira(app).create_issue.return_value.key = 'TEAM-1'
        self.jira(app).transition_issue.side_effect = FakeJIRAError('busy', status_code=status)
        self.jira(app).add_comment.side_effect = FakeJIRAError('busy', status_code=status)
        assert app.lambda_handler(ticket_scratchpad(), None)['TicketId'] == 'TEAM-1'

    @pytest.mark.parametrize('error', [FakeJIRAError('busy', status_code=429),
                                       FakeJIRAError('refused', status_code=400)])
    def test_a_failed_soc_copy_does_not_fail_the_team_ticket(self, app, error):
        """The team ticket already exists; a retry would create it a second time."""
        created = MagicMock()
        created.key = 'TEAM-1'
        self.jira(app).create_issue.side_effect = [created, error]
        data = ticket_scratchpad()
        data['incident'] = {'type': 'test'}
        with patch.object(app, 'INCIDENTS_TO_SOC', 'ALL'):
            assert app.lambda_handler(data, None)['TicketId'] == 'TEAM-1'
        assert self.jira(app).create_issue.call_count == 2


# ---------------------------------------------------------------------------
# open_ticket, ServiceNow
# ---------------------------------------------------------------------------

class TestOpenServiceNowTicket:

    @pytest.fixture
    def app(self):
        return load('functions.ticketing.open_ticket.app', 'ServiceNow')

    def test_creates_the_ticket(self, app):
        created = response(201, {'result': [{'display_value': 'INC1', 'record_link': 'https://x/INC1'}]})
        with patch.object(app.requests, 'post', return_value=created):
            assert app.lambda_handler(ticket_scratchpad(), None)['TicketId'] == 'INC1,https://x/INC1'

    @pytest.mark.parametrize('status', TRANSIENT_STATUSES)
    def test_a_rate_limited_create_is_retried(self, app, status):
        with patch.object(app.requests, 'post', return_value=response(status)):
            with pytest.raises(TicketingTransientError):
                app.lambda_handler(ticket_scratchpad(), None)

    @pytest.mark.parametrize('status', REFUSED_STATUSES)
    def test_a_refused_create_fails(self, app, status):
        with patch.object(app.requests, 'post', return_value=response(status)):
            with pytest.raises(TicketingRequestError):
                app.lambda_handler(ticket_scratchpad(), None)

    @pytest.mark.parametrize('error', CONNECTION_ERRORS)
    def test_an_unreachable_service_now_is_retried(self, app, error):
        with patch.object(app.requests, 'post', side_effect=error):
            with pytest.raises(TicketingTransientError):
                app.lambda_handler(ticket_scratchpad(), None)


# ---------------------------------------------------------------------------
# close_ticket, Jira
# ---------------------------------------------------------------------------

class TestCloseJiraTicket:

    @pytest.fixture
    def app(self):
        return load('functions.ticketing.close_ticket.app', 'JIRA')

    def jira(self, app):
        return app.JIRA.return_value

    def test_closes_the_ticket(self, app):
        assert app.lambda_handler({'TicketId': 'TEAM-1'}, None) is True
        self.jira(app).transition_issue.assert_called_once()

    def test_a_ticket_that_no_longer_exists_needs_nothing_more(self, app):
        self.jira(app).issue.side_effect = FakeJIRAError('not found', status_code=404)
        assert app.lambda_handler({'TicketId': 'TEAM-1'}, None) is False

    @pytest.mark.parametrize('call', ['issue', 'transition_issue'])
    @pytest.mark.parametrize('status', TRANSIENT_STATUSES)
    def test_rate_limiting_is_retried_and_never_deletes_the_ticket(self, app, call, status):
        getattr(self.jira(app), call).side_effect = FakeJIRAError('busy', status_code=status)
        with pytest.raises(TicketingTransientError):
            app.lambda_handler({'TicketId': 'TEAM-1'}, None)
        self.jira(app).issue.return_value.delete.assert_not_called()

    @pytest.mark.parametrize('call', ['issue', 'transition_issue'])
    @pytest.mark.parametrize('error', CONNECTION_ERRORS)
    def test_an_unreachable_jira_is_retried_and_never_deletes_the_ticket(self, app, call, error):
        getattr(self.jira(app), call).side_effect = error
        with pytest.raises(TicketingTransientError):
            app.lambda_handler({'TicketId': 'TEAM-1'}, None)
        self.jira(app).issue.return_value.delete.assert_not_called()

    @pytest.mark.parametrize('status', [401, 403])
    def test_a_refused_lookup_fails(self, app, status):
        self.jira(app).issue.side_effect = FakeJIRAError('unauthorized', status_code=status)
        with pytest.raises(TicketingRequestError):
            app.lambda_handler({'TicketId': 'TEAM-1'}, None)

    @pytest.mark.parametrize('status', [400, 409, None])
    def test_a_refused_transition_leaves_the_ticket_alone(self, app, status):
        """Typically the team already closed the ticket by hand: it is neither deleted nor an error."""
        self.jira(app).transition_issue.side_effect = FakeJIRAError('transition not available', status_code=status)
        assert app.lambda_handler({'TicketId': 'TEAM-1'}, None) is False
        self.jira(app).issue.return_value.delete.assert_not_called()

    def test_a_rate_limited_comment_after_closing_is_only_logged(self, app):
        self.jira(app).add_comment.side_effect = FakeJIRAError('busy', status_code=429)
        assert app.lambda_handler({'TicketId': 'TEAM-1'}, None) is True


# ---------------------------------------------------------------------------
# close_ticket, ServiceNow
# ---------------------------------------------------------------------------

class TestCloseServiceNowTicket:

    @pytest.fixture
    def app(self):
        return load('functions.ticketing.close_ticket.app', 'ServiceNow')

    TICKET = {'TicketId': 'INC1,https://ticketing.example.com/INC1'}

    def test_closes_the_ticket(self, app):
        with patch.object(app.requests, 'get', return_value=response(200, {'result': {'number': 'INC1'}})), \
                patch.object(app.requests, 'post', return_value=response(201, {'result': []})) as post:
            assert app.lambda_handler(dict(self.TICKET), None) is True
        assert post.call_args.kwargs['json']['u_state'] == '7'

    def test_a_ticket_that_no_longer_exists_needs_nothing_more(self, app):
        with patch.object(app.requests, 'get', return_value=response(404)):
            assert app.lambda_handler(dict(self.TICKET), None) is False

    @pytest.mark.parametrize('call', ['get', 'post'])
    @pytest.mark.parametrize('status', TRANSIENT_STATUSES)
    def test_rate_limiting_is_retried(self, app, call, status):
        found = response(200, {'result': {'number': 'INC1'}})
        responses = {'get': found, 'post': response(201, {'result': []}), call: response(status)}
        with patch.object(app.requests, 'get', return_value=responses['get']), \
                patch.object(app.requests, 'post', return_value=responses['post']):
            with pytest.raises(TicketingTransientError):
                app.lambda_handler(dict(self.TICKET), None)

    @pytest.mark.parametrize('call', ['get', 'post'])
    @pytest.mark.parametrize('status', [401, 403])
    def test_a_refused_request_fails(self, app, call, status):
        found = response(200, {'result': {'number': 'INC1'}})
        responses = {'get': found, 'post': response(201, {'result': []}), call: response(status)}
        with patch.object(app.requests, 'get', return_value=responses['get']), \
                patch.object(app.requests, 'post', return_value=responses['post']):
            with pytest.raises(TicketingRequestError):
                app.lambda_handler(dict(self.TICKET), None)

    @pytest.mark.parametrize('error', CONNECTION_ERRORS)
    def test_an_unreachable_service_now_is_retried(self, app, error):
        with patch.object(app.requests, 'get', side_effect=error):
            with pytest.raises(TicketingTransientError):
                app.lambda_handler(dict(self.TICKET), None)
