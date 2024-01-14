import os
import boto3
from datetime import datetime, timezone, timedelta
from dateutil import parser
import humanize
import datetime as dt


# Get environment variables
TICKETS_TABLE = os.environ['TICKETS_TABLE']

SEVERITY_ALLOWED_AGE_IN_HOURS_CRITICAL = int(os.environ['SEVERITY_ALLOWED_AGE_IN_HOURS_CRITICAL'])
SEVERITY_ALLOWED_AGE_IN_HOURS_HIGH = int(os.environ['SEVERITY_ALLOWED_AGE_IN_HOURS_HIGH'])
SEVERITY_ALLOWED_AGE_IN_HOURS_MEDIUM = int(os.environ['SEVERITY_ALLOWED_AGE_IN_HOURS_MEDIUM'])
SEVERITY_ALLOWED_AGE_IN_HOURS_LOW = int(os.environ['SEVERITY_ALLOWED_AGE_IN_HOURS_LOW'])

SEVERITY_ALLOWED_AGE_IN_HOURS = {
    'CRITICAL': SEVERITY_ALLOWED_AGE_IN_HOURS_CRITICAL,
    'HIGH': SEVERITY_ALLOWED_AGE_IN_HOURS_HIGH,
    'MEDIUM': SEVERITY_ALLOWED_AGE_IN_HOURS_MEDIUM,
    'LOW': SEVERITY_ALLOWED_AGE_IN_HOURS_LOW
}

ACCOUNT_TEAM_EMAIL_TAG = os.environ['ACCOUNT_TEAM_EMAIL_TAG']         # soar:team:email
ACCOUNT_TEAM_EMAIL_TAG_APP = os.environ['ACCOUNT_TEAM_EMAIL_TAG_APP'] # soar:team:email:app
DEFAULT_TEAM_EMAIL = os.environ['DEFAULT_TEAM_EMAIL']
ENVIRONMENT_TAG = os.environ['ENVIRONMENT_TAG']                       # soar:environment
CLIENT_TAG = os.environ['CLIENT_TAG']                                 # soar:organizations
PROJECT_TAG = os.environ['PROJECT_TAG']                               # soar:project
TEAM_TAG = os.environ['TEAM_TAG']                                     # soar:team

TICKETING_SYSTEM = os.environ['TICKETING_SYSTEM'] # 

JIRA_PROJECT_KEY_TAG = os.environ['JIRA_PROJECT_KEY_TAG']             # soar:jira:project-key
JIRA_PROJECT_KEY_TAG_APP = os.environ['JIRA_PROJECT_KEY_TAG_APP']     # soar:jira:project-key:app
JIRA_DEFAULT_PROJECT_KEY = os.environ['JIRA_DEFAULT_PROJECT_KEY']     # XXX

SERVICE_NOW_PROJECT_QUEUE_TAG = os.environ['SERVICE_NOW_PROJECT_QUEUE_TAG']         # soar:service-now:project-queue
SERVICE_NOW_PROJECT_QUEUE_TAG_APP = os.environ['SERVICE_NOW_PROJECT_QUEUE_TAG_APP'] # soar:service-now:project-queue:app
SERVICE_NOW_DEFAULT_PROJECT_QUEUE = os.environ['SERVICE_NOW_DEFAULT_PROJECT_QUEUE'] # XXX

ESCALATION_EMAIL_CC = os.environ['ESCALATION_EMAIL_CC']
ESCALATION_EMAIL_SEVERITIES = os.environ['ESCALATION_EMAIL_SEVERITIES'].split(',')

METRIC_NAMESPACE = os.environ['METRIC_NAMESPACE']


organizations = boto3.client('organizations')
dynamodb = boto3.resource('dynamodb')
tickets = dynamodb.Table(TICKETS_TABLE)
cloudwatch_client = boto3.client('cloudwatch')


# Lambda handler
def lambda_handler(_data, _context):
    # Retrieve all open tickets and set their age and overdue status
    open_tickets = set_age_and_overdue(retrieve_open_tickets())
    print(f"Open tickets ({len(open_tickets)}): {open_tickets}")
    
    # Filter out only the overdue tickets
    overdue_tickets = [ticket for ticket in open_tickets if ticket.get('is_overdue') == "Yes"]
    n_overdue_tickets = len(overdue_tickets)
    print(f"Overdue tickets ({n_overdue_tickets}): {overdue_tickets}")

    # Adorn any overdue tickets
    if (n_overdue_tickets > 0):
        # Get all account data
        account_data = get_all_account_data()
        # Adorn the overdue tickets with email recipient and AdditionalCC
        for ticket in overdue_tickets:
            account_name = ticket['Account']
            severity_label = ticket['severity_label']
            ticket['TeamEmail'] = account_data[account_name]['TeamEmail']
            ticket['AdditionalCC'] = ESCALATION_EMAIL_CC if severity_label in ESCALATION_EMAIL_SEVERITIES else ''

    # Emit metric for the total number of open tickets
    emit_cloudwatch_metric(
        metric_name='TotalTickets',
        metric_value=len(open_tickets),
        dimension_name='TicketStatus',
        dimension_value='Open'
    )

    # Emit metric for the total number of overdue tickets
    emit_cloudwatch_metric(
        metric_name='TotalTickets',
        metric_value=n_overdue_tickets,
        dimension_name='TicketStatus',
        dimension_value='Overdue'
    )

    # Emit metrics for each dimension for open tickets
    emit_metrics_for_dimension(open_tickets, 'Account', 'TotalOpenTicketsByAccount')
    emit_metrics_for_dimension(open_tickets, 'Environment', 'TotalOpenTicketsByEnvironment')
    emit_metrics_for_dimension(open_tickets, 'severity_label', 'TotalOpenTicketsBySeverity')
    emit_metrics_for_dimension(open_tickets, 'Team', 'TotalOpenTicketsByTeam')

    # Emit metrics for each dimension for overdue tickets
    emit_metrics_for_dimension(overdue_tickets, 'Account', 'TotalOverdueTicketsByAccount')
    emit_metrics_for_dimension(overdue_tickets, 'Environment', 'TotalOverdueTicketsByEnvironment')
    emit_metrics_for_dimension(overdue_tickets, 'severity_label', 'TotalOverdueTicketsBySeverity')
    emit_metrics_for_dimension(overdue_tickets, 'Team', 'TotalOverdueTicketsByTeam')

    return overdue_tickets


# Massage the tickets
def set_age_and_overdue(tickets):    
    current_time = datetime.now(timezone.utc)
    
    for ticket in tickets:
        opened_at = parser.isoparse(ticket['opened_at']).replace(tzinfo=timezone.utc)
        age_in_seconds = int((current_time - opened_at).total_seconds())
        humanized_age = humanize.precisedelta(age_in_seconds, minimum_unit='hours')
        
        ticket['age_in_seconds'] = age_in_seconds
        
        severity_label = ticket['severity_label']
        max_allowed_age_in_hours = SEVERITY_ALLOWED_AGE_IN_HOURS.get(severity_label, 0)

        if severity_label == "INFORMATIONAL" or max_allowed_age_in_hours < 0:
            ticket['is_overdue'] = "No"
            ticket['overdue_seconds'] = 0
            ticket['age_txt'] = humanized_age
        else:
            max_allowed_age_in_seconds = timedelta(hours=max_allowed_age_in_hours).total_seconds()
            if age_in_seconds > max_allowed_age_in_seconds:
                ticket['is_overdue'] = "Yes"
                ticket['overdue_seconds'] = age_in_seconds - max_allowed_age_in_seconds
                humanized_overdue = humanize.precisedelta(ticket['overdue_seconds'], minimum_unit='hours')
                ticket['age_txt'] = f"{humanized_age} (OVERDUE by {humanized_overdue})"
            else:
                ticket['is_overdue'] = "No"
                ticket['overdue_seconds'] = 0
                ticket['age_txt'] = humanized_age
    
    return tickets


# ----------------------------------------------------------------
#
#   AWS Organizations
#
# ----------------------------------------------------------------

# Get account data for all accounts in the organization
def get_all_account_data():
    # Get all accounts in the organization
    accounts = []
    paginator = organizations.get_paginator('list_accounts')
    response_iterator = paginator.paginate()
    for page in response_iterator:
        accounts.extend(page['Accounts'])

    # Retrieve account data for each account
    account_data = {}
    for account in accounts:
        account_id = account['Id']
        name, the_data = get_account_data(account_id)
        account_data[name] = the_data

    return account_data


# Get data for a specific account
def get_account_data(account_id):
    # Get account details
    acc = organizations.describe_account(
        AccountId=account_id
    )['Account']

    # Calculate account age
    account_joined = acc['JoinedTimestamp']
    now = dt.datetime.now(dt.timezone.utc)
    age = (now - account_joined).days

    # Get resource tags
    tags = get_resource_tags(account_id)

    # Get team email
    team_email = tags.get(ACCOUNT_TEAM_EMAIL_TAG, DEFAULT_TEAM_EMAIL)
    if team_email == '':
        team_email = acc['Email']
    team_email_app = tags.get(ACCOUNT_TEAM_EMAIL_TAG_APP, '')
    if team_email_app == '':
        team_email_app = team_email

    # Get organizations, project, team, and environment
    project_name = tags.get(PROJECT_TAG, 'Unspecified')
    team = tags.get(TEAM_TAG, 'Unspecified')
    environment = tags.get(ENVIRONMENT_TAG, 'Unspecified')

    # Get project ID based on ticketing system
    if TICKETING_SYSTEM == 'JIRA':
        project_id = tags.get(JIRA_PROJECT_KEY_TAG,
                              JIRA_DEFAULT_PROJECT_KEY)
        project_id_app = tags.get(JIRA_PROJECT_KEY_TAG_APP, project_id)
    elif TICKETING_SYSTEM == 'ServiceNow':
        project_id = tags.get(SERVICE_NOW_PROJECT_QUEUE_TAG,
                              SERVICE_NOW_DEFAULT_PROJECT_QUEUE)
        project_id_app = tags.get(
            SERVICE_NOW_PROJECT_QUEUE_TAG_APP, project_id)
    else:
        project_id = 'Unspecified'
        project_id_app = 'Unspecified'

    # Get organizational unit
    organizational_unit = get_organizational_unit(account_id)

    # Create result dictionary
    name = acc['Name']
    data =  {
        'Id': account_id,
        'Email': acc['Email'],
        'TeamEmail': team_email,
        'TeamEmailApp': team_email_app,
        'OrganizationalUnit': organizational_unit,
        'ProjectName': project_name,
        'ProjectId': project_id,
        'ProjectIdApp': project_id_app,
        'Team': team,
        'Environment': environment,
        'AccountAgeInDays': age
    }
    return name, data


# Get resource tags for an account
def get_resource_tags(account_id):
    tags = {}
    paginator = organizations.get_paginator('list_tags_for_resource')
    response_iterator = paginator.paginate(
        ResourceId=account_id,
        PaginationConfig={'MaxItems': 100}
    )
    for page in response_iterator:
        for item in page['Tags']:
            tags[item['Key']] = item['Value']

    return tags


# Get organizational unit for an account
def get_organizational_unit(account_id):
    organizational_unit = get_first_parent_ou(account_id)
    return organizational_unit


# Get first parent organizational unit for an account
def get_first_parent_ou(account_id):
    paginator = organizations.get_paginator('list_parents')
    response_iterator = paginator.paginate(
        ChildId=account_id,
        PaginationConfig={'MaxItems': 100}
    )
    for page in response_iterator:
        for item in page['Parents']:
            if item['Type'] == 'ORGANIZATIONAL_UNIT':
                response = organizations.describe_organizational_unit(
                    OrganizationalUnitId=item['Id']
                )
                return response['OrganizationalUnit']['Name']
            return 'ROOT'
    return 'UNKNOWN_OU'


# ----------------------------------------------------------------
#
#   DynamoDB queries
#
# ----------------------------------------------------------------

def query_with_paging(table, **kwargs):
    """Query DynamoDB with automatic handling of paging."""
    last_evaluated_key = None
    results = []

    while True:
        # Prepare query parameters
        query_parameters = dict(
            **kwargs
        )
        
        if last_evaluated_key:
            query_parameters['ExclusiveStartKey'] = last_evaluated_key

        response = table.query(**query_parameters)

        results.extend(response['Items'])

        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break

    return results


def retrieve_open_tickets():
    open_tickets = query_with_paging(
        tickets,
        IndexName='dummy-closed_at-index',
        KeyConditionExpression='dummy = :dummy_val AND begins_with(closed_at, :prefix)',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':prefix': 'NULL#'
        }
    )

    return open_tickets


# ----------------------------------------------------------------
#
#   CloudWatch metrics
#
# ----------------------------------------------------------------

def emit_cloudwatch_metric(metric_name, metric_value, dimension_name, dimension_value):
    """
    Emit a single data point to CloudWatch with a specified dimension.

    :param metric_name: The name of the metric.
    :param metric_value: The value for the metric.
    :param dimension_name: The name of the dimension.
    :param dimension_value: The value for the dimension.
    """
    cloudwatch_client.put_metric_data(
        Namespace=METRIC_NAMESPACE,       # 'DelegatSOAR' as passed in via an ENV var
        MetricData=[
            {
                'MetricName': metric_name,
                'Dimensions': [
                    {
                        'Name': dimension_name,
                        'Value': dimension_value
                    },
                ],
                'Value': metric_value,
                'Unit': 'Count'
            },
        ]
    )
    print(f"Metric emitted: {metric_name} - {dimension_name}: {dimension_value}, Value: {metric_value}")


# Helper function to emit metrics for each unique value in a dimension
def emit_metrics_for_dimension(tickets, dimension_name, metric_name):
    unique_values = set(ticket[dimension_name] for ticket in tickets)
    for value in unique_values:
        emit_cloudwatch_metric(
            metric_name=metric_name,
            metric_value=sum(1 for ticket in tickets if ticket[dimension_name] == value),
            dimension_name=dimension_name,
            dimension_value=value
        )
