# Import necessary libraries
import os
from contextlib import contextmanager
import boto3
from jira import JIRA
from jira import JIRAError
import requests
from requests.auth import HTTPBasicAuth
from aws_utils.errors import (TicketingRequestError, TicketingTransientError, is_transient_status,
                              transient_aws_errors)

# Get environment variables
TICKETING_SYSTEM = os.environ['TICKETING_SYSTEM']
JIRA_SERVER_URL_PARAMETER_PATH = os.environ['JIRA_SERVER_URL_PARAMETER_PATH']
JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH = os.environ['JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH']
JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH = os.environ['JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH']
JIRA_FINAL_STATE = os.environ['JIRA_FINAL_STATE']

SERVICE_NOW_URL_PARAMETER_PATH = os.environ['SERVICE_NOW_URL_PARAMETER_PATH']
SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH = os.environ[
    'SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH']
SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH = os.environ[
    'SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH']
SERVICE_NOW_TABLE = os.environ['SERVICE_NOW_TABLE']
SERVICE_NOW_FINAL_STATE = os.environ['SERVICE_NOW_FINAL_STATE']

# Create a client for AWS SSM (Simple Systems Manager)
client = boto3.client('ssm')

# Get the JIRA server URL, username, and token from AWS SSM
JIRA_SERVER_URL = client.get_parameter(Name=JIRA_SERVER_URL_PARAMETER_PATH)['Parameter']['Value']
JIRA_BASIC_AUTH_USERNAME = client.get_parameter(Name=JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH)['Parameter']['Value']
JIRA_BASIC_AUTH_TOKEN = client.get_parameter(Name=JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH)['Parameter']['Value']
JIRA_CREDS = [JIRA_SERVER_URL, JIRA_BASIC_AUTH_USERNAME, JIRA_BASIC_AUTH_TOKEN]

# Get the ServiceNow URL, username, and password from AWS SSM
SERVICE_NOW_URL = client.get_parameter(Name=SERVICE_NOW_URL_PARAMETER_PATH)['Parameter']['Value']
SERVICE_NOW_BASIC_AUTH_USERNAME = client.get_parameter(Name=SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH)['Parameter']['Value']
SERVICE_NOW_BASIC_AUTH_PASSWORD = client.get_parameter(Name=SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH)['Parameter']['Value']
SERVICE_NOW_CREDS = [SERVICE_NOW_URL, SERVICE_NOW_BASIC_AUTH_USERNAME, SERVICE_NOW_BASIC_AUTH_PASSWORD]


# Ticketing errors as named errors for the state machine: a rate limit (429), a failure on the ticketing
# system's side (5xx) or an unreachable system is retried; any other refusal fails the execution.
@contextmanager
def ticketing_errors(what):
    try:
        yield
    except JIRAError as err:
        if is_transient_status(err.status_code):
            raise TicketingTransientError(f"{what}: {err}") from err
        raise TicketingRequestError(f"{what}: {err}") from err
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as err:
        raise TicketingTransientError(f"{what}: {err}") from err


def check_response(response, what):
    if is_transient_status(response.status_code):
        raise TicketingTransientError(f"{what}: HTTP {response.status_code}: {response.text}")
    if not 200 <= response.status_code <= 299:
        raise TicketingRequestError(f"{what}: HTTP {response.status_code}: {response.text}")


# Define the main lambda handler function
@transient_aws_errors
def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Check the ticketing system and call the appropriate function
    if TICKETING_SYSTEM == 'JIRA':
        if 'REPLACE_ME' not in JIRA_CREDS:
            return use_jira(data)
        else:
            print("JIRA credentials not set up.")

    elif TICKETING_SYSTEM == 'ServiceNow':
        if 'REPLACE_ME' not in SERVICE_NOW_CREDS:
            return use_service_now(data)
        else:
            print("ServiceNow credentials not set up.")

    else:
        print("No ticketing system selected.")

    return True


# ---------------------------------------------------------------------
#
#   JIRA
#
# ---------------------------------------------------------------------

# Function to handle JIRA tickets
def use_jira(data):
    # Get the ticket ID from the input data
    ticket_id = data['TicketId']
    # Print a message indicating the ticket is being closed
    print(f"Closing JIRA ticket {ticket_id}...")

    # Create a JIRA object with the authentication details
    with ticketing_errors("Could not connect to JIRA"):
        jira = JIRA(basic_auth=(JIRA_BASIC_AUTH_USERNAME, JIRA_BASIC_AUTH_TOKEN),
                    options={'server': JIRA_SERVER_URL})

    # Initialize the issue variable
    issue = None

    try:
        # Get the JIRA issue using the ticket ID
        with ticketing_errors(f"Could not get issue {ticket_id}"):
            issue = jira.issue(ticket_id)
    except TicketingRequestError as err:
        if err.__cause__.status_code != 404:
            raise
        # If the issue cannot be found, print an error message and return False
        print(f"ERROR: Could not find issue {ticket_id}: {err}")
        return False

    try:
        # Transition the issue to the final state
        jira.transition_issue(issue, JIRA_FINAL_STATE)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as err:
        raise TicketingTransientError(f"Could not transition issue {ticket_id}: {err}") from err
    except JIRAError as err:
        if is_transient_status(err.status_code):
            raise TicketingTransientError(f"Could not transition issue {ticket_id}: {err}") from err
        # Typically the team has already closed the issue by hand: leave it alone
        print(
            f"ERROR: Could not transition issue {ticket_id} to '{JIRA_FINAL_STATE}', leaving it as it is: {err}.")
        return False

    try:
        # Add a comment to the issue indicating it was closed by automation
        jira.add_comment(issue, 'Closed by automation.')
    except (JIRAError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as err:
        # If adding the comment fails, print an error message
        print(f"ERROR: Could not comment on {ticket_id}: {err}")

    return True


# ---------------------------------------------------------------------
#
#   ServiceNow
#
# ---------------------------------------------------------------------

# Function to handle ServiceNow tickets
def use_service_now(data):
    # Get the ticket ID from the input data
    ticket_id = data['TicketId']
    # Print a message indicating the ticket is being closed
    print(f"Closing ServiceNow ticket {ticket_id}...")

    # Split the ticket ID into parts to extract the ticket URL
    parts = ticket_id.split(",", 1)
    if len(parts) != 2:
        # If the ticket ID is malformed, print an error message and return False
        print("Malformed ticket id, doing nothing.")
        return False

    ticket_url = parts[1]

    auth = HTTPBasicAuth(SERVICE_NOW_BASIC_AUTH_USERNAME, SERVICE_NOW_BASIC_AUTH_PASSWORD)

    # Send a GET request to the ticket URL with authentication
    with ticketing_errors(f"Could not get ServiceNow ticket {ticket_id}"):
        response = requests.get(ticket_url, auth=auth)
    if response.status_code == 404:
        # If the ticket cannot be found, print an error message and return False
        print("Ticket can't be found, doing nothing.")
        return False
    check_response(response, f"Could not get ServiceNow ticket {ticket_id}")

    # Parse the response JSON
    json = response.json()
    print(json)

    # Extract the necessary fields from the JSON
    body = json['result']
    body['u_number'] = body['number']
    body['u_state'] = SERVICE_NOW_FINAL_STATE

    # Send a POST request to import the updated ticket to ServiceNow
    with ticketing_errors(f"Could not close ServiceNow ticket {ticket_id}"):
        response = requests.post(
            f"{SERVICE_NOW_URL}/api/now/import/{SERVICE_NOW_TABLE}",
            json=body,
            auth=auth)
    check_response(response, f"Could not close ServiceNow ticket {ticket_id}")

    # Parse the response JSON
    json = response.json()
    print(json)

    return True