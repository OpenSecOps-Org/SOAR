# Import necessary libraries
import os
import boto3
from jira import JIRA
from jira import JIRAError
import requests
from requests.auth import HTTPBasicAuth

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

# Define the main lambda handler function
def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Check the ticketing system and call the appropriate function
    if TICKETING_SYSTEM == 'JIRA':
        return use_jira(data)

    if TICKETING_SYSTEM == 'ServiceNow':
        return use_service_now(data)

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

    # Get the JIRA server URL, username, and token from AWS SSM
    url = client.get_parameter(Name=JIRA_SERVER_URL_PARAMETER_PATH)[
        'Parameter']['Value']
    username = client.get_parameter(Name=JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH)[
        'Parameter']['Value']
    token = client.get_parameter(Name=JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH)[
        'Parameter']['Value']
    # Create a JIRA object with the authentication details
    jira = JIRA(basic_auth=(username, token), options={'server': url})

    # Initialize the issue variable
    issue = None

    try:
        # Get the JIRA issue using the ticket ID
        issue = jira.issue(ticket_id)
    except JIRAError as err:
        # If the issue cannot be found, print an error message and return False
        print(f"ERROR: Could not find issue {ticket_id}: {err}")
        return False

    try:
        # Transition the issue to the final state
        jira.transition_issue(issue, JIRA_FINAL_STATE)
    except JIRAError as err:
        # If the transition fails, print an error message and delete the issue
        print(
            f"ERROR: Could not transition issue {ticket_id} to '{JIRA_FINAL_STATE}': {err}.")
        print("Deleting the issue...")
        issue.delete()
        return False

    try:
        # Add a comment to the issue indicating it was closed by automation
        jira.add_comment(issue, 'Closed by automation.')
    except JIRAError as err:
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

    # Get the ServiceNow URL, username, and password from AWS SSM
    url = client.get_parameter(Name=SERVICE_NOW_URL_PARAMETER_PATH)[
        'Parameter']['Value']
    username = client.get_parameter(Name=SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH)[
        'Parameter']['Value']
    password = client.get_parameter(Name=SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH)[
        'Parameter']['Value']
    auth = HTTPBasicAuth(username, password)

    try:
        # Send a GET request to the ticket URL with authentication
        response = requests.get(ticket_url, auth=auth)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        # If the ticket cannot be found, print an error message and return False
        print("Ticket can't be found, doing nothing.")
        return False

    # Parse the response JSON
    json = response.json()
    print(json)

    # Extract the necessary fields from the JSON
    body = json['result']
    body['u_number'] = body['number']
    body['u_state'] = SERVICE_NOW_FINAL_STATE

    # Send a POST request to import the updated ticket to ServiceNow
    response = requests.post(
        f"{url}/api/now/import/{SERVICE_NOW_TABLE}",
        json=body,
        auth=auth)

    # Parse the response JSON
    json = response.json()
    print(json)

    return True