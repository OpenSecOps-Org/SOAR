import os
import uuid
import boto3
from jira import JIRA
from jira import JIRAError
import requests
from requests.auth import HTTPBasicAuth

# Get the TICKETING_SYSTEM environment variable
TICKETING_SYSTEM = os.environ['TICKETING_SYSTEM']

# Get the environment variables related to JIRA
JIRA_SERVER_URL_PARAMETER_PATH = os.environ['JIRA_SERVER_URL_PARAMETER_PATH']
JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH = os.environ['JIRA_BASIC_AUTH_USERNAME_PARAMETER_PATH']
JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH = os.environ['JIRA_BASIC_AUTH_TOKEN_PARAMETER_PATH']
JIRA_DEFAULT_PROJECT_KEY = os.environ['JIRA_DEFAULT_PROJECT_KEY']
JIRA_ISSUE_TYPE = os.environ['JIRA_ISSUE_TYPE']
JIRA_PRIORITIES = os.environ['JIRA_PRIORITIES']
JIRA_INITIAL_STATES = os.environ['JIRA_INITIAL_STATES']

# Get the environment variables related to ServiceNow
SERVICE_NOW_URL_PARAMETER_PATH = os.environ['SERVICE_NOW_URL_PARAMETER_PATH']
SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH = os.environ[
    'SERVICE_NOW_BASIC_AUTH_USERNAME_PARAMETER_PATH']
SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH = os.environ[
    'SERVICE_NOW_BASIC_AUTH_PASSWORD_PARAMETER_PATH']
SERVICE_NOW_TABLE = os.environ['SERVICE_NOW_TABLE']
SERVICE_NOW_DEFAULT_PROJECT_QUEUE = os.environ['SERVICE_NOW_DEFAULT_PROJECT_QUEUE']
SERVICE_NOW_ISSUE_TYPE = os.environ['SERVICE_NOW_ISSUE_TYPE']

# Get the environment variables related to SOC
SOC = os.environ['SOC_JIRA_PROJECT_KEY_OR_SERVICE_NOW_QUEUE']

# Get the environment variable INCIDENTS_TO_SOC
INCIDENTS_TO_SOC = os.environ['INCIDENTS_TO_SOC']

# Create a boto3 client for AWS SSM
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


# Define the lambda_handler function
def lambda_handler(data, _context):
    print(data)

    # The ticket destination defaults to TEAM. Can be TEAM or SOC.
    # The incident domain defaults to INFRA. Can be INFRA or APP.
    ticket_destination = data['finding']['ProductFields'].get(
        'TicketDestination', 'TEAM')
    incident_domain = data['finding']['ProductFields'].get(
        'IncidentDomain', 'INFRA')

    # TEAM+INFRA and TEAM+APP, respectively
    project_id = data['account']['ProjectId']
    project_id_app = data['account'].get('ProjectIdApp', project_id)

    # Check if the ticket should go to SOC
    ticket_to_soc = ticket_destination == 'SOC'

    # If the ticket should go to SOC, then just use the SOC project_id
    if ticket_to_soc:
        project_id = SOC
    else:
        # If destination is TEAM, then use INFRA by default, or APP if specified
        if incident_domain == 'APP':
            project_id = project_id_app

    # Check if this is an incident and if it should be sent to SOC
    is_incident = data.get('incident', False) is not False
    is_right_domain = (INCIDENTS_TO_SOC == 'ALL' or INCIDENTS_TO_SOC == incident_domain)
    also_to_soc = is_incident and not ticket_to_soc and is_right_domain

    # Do the thang
    if TICKETING_SYSTEM == 'JIRA':
        if 'REPLACE_ME' not in JIRA_CREDS:
            ticket_id = use_jira(data, project_id)
            if also_to_soc:
                use_jira(data, SOC)
        else:
            print("JIRA credentials not set up. Simulating Ticket ID.")
            ticket_id = str(uuid.uuid4())  # Simulate

    elif TICKETING_SYSTEM == 'ServiceNow':
        if 'REPLACE_ME' not in SERVICE_NOW_CREDS:
            ticket_id = use_service_now(data, project_id, ticket_to_soc)
            if also_to_soc:
                use_service_now(data, SOC, True)
        else:
            print("ServiceNow credentials not set up. Simulating Ticket ID.")
            ticket_id = str(uuid.uuid4())  # Simulate

    else:
        print("No ticketing system selected. Simulating Ticket ID.")
        ticket_id = str(uuid.uuid4())  # Simulate

    return {
        "TicketOpen": "Yes",
        "TicketId": ticket_id
    }


# ---------------------------------------------------------------------
#
#   JIRA
#
# ---------------------------------------------------------------------

# Define the use_jira function
def use_jira(data, project_id):
    severity = data['finding']['Severity']['Label']
    print(f"Creating JIRA ticket for project {project_id}...")

    # Create a JIRA object with the provided credentials
    jira = JIRA(basic_auth=(JIRA_BASIC_AUTH_USERNAME, JIRA_BASIC_AUTH_TOKEN), 
                options={'server': JIRA_SERVER_URL})

    # Check if the project_id is a valid JIRA project
    if nonexistent_jira_project(jira, project_id):
        project_id = JIRA_DEFAULT_PROJECT_KEY

    # Split the JIRA_PRIORITIES environment variable into a list of priorities
    prios = JIRA_PRIORITIES.split(',')

    # Create a dictionary to map severity labels to JIRA priorities
    prio_translations = {
        'INFORMATIONAL': prios[0].strip(),
        'LOW': prios[1].strip(),
        'MEDIUM': prios[2].strip(),
        'HIGH': prios[3].strip(),
        'CRITICAL': prios[4].strip()
    }

    # Get the priority for the current severity label
    prio = prio_translations[severity]

    # Get the email messages from the data
    messages = data['messages']
    texts = messages.get('email', False)

    try:
        # Create a new JIRA issue
        issue = jira.create_issue(
            project=project_id,
            issuetype={'name': JIRA_ISSUE_TYPE},
            summary=texts['subject'],
            description=texts['body'],
            priority={'name': prio}
        )
    except JIRAError as err:
        print(
            f"ERROR: Could not create new issue for project {project_id}: {err}.")
        return f"create-ticket-failed-{str(uuid.uuid4())}"  # Simulate

    # Get the key of the created issue
    ticket_id = issue.key
    print(f"Created JIRA ticket {ticket_id}")

    # Transition the issue to its initial state
    transition_to_initial_jira_state(jira, issue, ticket_id)

    try:
        # Add a comment to the issue
        jira.add_comment(issue, 'Opened by automation.')
    except JIRAError as err:
        print(f"ERROR: Could not comment on {ticket_id}: {err}")

    return ticket_id


# Define the nonexistent_jira_project function
def nonexistent_jira_project(jira, project_key):
    try:
        jira.project(project_key)
    except JIRAError:
        return True
    return False


# Define the transition_to_initial_jira_state function
def transition_to_initial_jira_state(jira, issue, ticket_id):
    for state in JIRA_INITIAL_STATES.split(','):
        try:
            jira.transition_issue(issue, state)
        except JIRAError as err:
            print(
                f"ERROR: Could not transition issue {ticket_id} to '{state}': {err}.")
            continue
        print(f"Ticket {ticket_id} transitioned to state '{state}'.")
        return
    print(
        f"Ticket {ticket_id} could not be transitioned from its initial state.")


# ---------------------------------------------------------------------
#
#   ServiceNow
#
# ---------------------------------------------------------------------

# Define the use_service_now function
def use_service_now(data, project_id, ticket_to_soc):
    print(f"Creating ServiceNow ticket for project {project_id}...")

    severity = data['finding']['Severity']['Label']

    # Get the impact and urgency based on the severity and ticket destination
    impact, urgency = severity_to_impact_and_urgency(severity, ticket_to_soc)

    auth = HTTPBasicAuth(SERVICE_NOW_BASIC_AUTH_USERNAME, SERVICE_NOW_BASIC_AUTH_PASSWORD)

    # Create the request body for creating a ServiceNow ticket
    body = {
        "u_number": "",
        "u_ticket_type": "Incident",
        "u_category": "Security",
        "u_sub_category": "Policy Violation",
        "u_caller_id": SERVICE_NOW_BASIC_AUTH_USERNAME,
        "u_contact_type": "5",      # "Event Monitoring"
        "sys_import_state": "1",    # "New"
        "u_impact": impact,
        "u_urgency": urgency,
        "u_affected_location": "Sweden",
        "u_assignment_group": project_id,
        "u_cmdb_ci": data['account']['Name'],
        "u_short_description": data['messages']['email']['subject'],
        "u_description": data['messages']['email']['body'],
        "u_external_ven__ticket_number": data['finding']['Id']
    }

    # Send a POST request to create a ServiceNow ticket
    response = requests.post(
        f"{SERVICE_NOW_URL}/api/now/import/{SERVICE_NOW_TABLE}",
        json=body,
        auth=auth)

    # Get the JSON response from the request
    json = response.json()
    print(json)
    display_value = json['result'][0]['display_value']
    record_link = json['result'][0]['record_link']
    ticket_id = f"{display_value},{record_link}"

    print(f"Created ServiceNow ticket {ticket_id}")

    return ticket_id


# Define the severity_to_impact_and_urgency function
def severity_to_impact_and_urgency(severity, ticket_to_soc):
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
    # Critical=0, High=1, Medium=2, Low=3, (Informational=4)
    val = min(severities.index(severity), 3)  # Eliminate INFORMATIONAL

    if ticket_to_soc:
        # Restrict ServiceNow Priority to Prio 2, 3, or 4
        impact = 2                 # Moderate - Limited
        urgency = val              # 0, 1, 2, 3
    else:
        # Restrict ServiceNow Priority to Prio 3 or 4
        impact = 3                 # Minor - Localised
        urgency = val              # 0, 1, 2, 3

    return impact, urgency
