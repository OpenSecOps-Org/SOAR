import os
import boto3
from datetime import datetime, timezone, timedelta
from dateutil import parser
import pandas as pd
import humanize
import json
import decimal


# Get environment variables
TICKETS_TABLE = os.environ['TICKETS_TABLE']
AUTOREMEDIATIONS_TABLE = os.environ['AUTOREMEDIATIONS_TABLE']
INCIDENTS_TABLE = os.environ['INCIDENTS_TABLE']
OPENAI_PROMPTS_TABLE = os.environ['OPENAI_PROMPTS_TABLE']

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

SEVERITY_ORDER = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFORMATIONAL': 4
}


# Clients and resources
organizations = boto3.client('organizations')

dynamodb = boto3.resource('dynamodb')
tickets = dynamodb.Table(TICKETS_TABLE)
autoremediations = dynamodb.Table(AUTOREMEDIATIONS_TABLE)
incidents = dynamodb.Table(INCIDENTS_TABLE)
openai_prompts = dynamodb.Table(OPENAI_PROMPTS_TABLE)


# Lambda handler
def lambda_handler(data, _context):
    system = retrieve_db_item(openai_prompts, 'weekly_ai_report_0_common')['instructions'] + "\n"
    system += retrieve_db_item(openai_prompts, 'weekly_ai_report_2_account')['instructions']

    account = data['account']
    data = data['input']

    account_data = data['bb']['account_map'][account]

    # Current UTC datetime
    current_time = datetime.utcnow()

    # UTC datetime one week before the current_time
    last_week = current_time - timedelta(weeks=1)
    two_weeks = current_time - timedelta(weeks=2)
    # three_weeks = current_time - timedelta(weeks=3)
    # four_weeks = current_time - timedelta(weeks=4)

    # This week
    TW_open_tickets = sort_on_severity(set_age_and_overdue(retrieve_open_tickets(account=account)))
    TW_n_open_tickets = len(TW_open_tickets)

    TW_n_overdue_tickets = count_overdue_tickets(TW_open_tickets)

    TW_opened_tickets = retrieve_opened_tickets_between(last_week, current_time, account=account)
    TW_n_opened_tickets = len(TW_opened_tickets)

    TW_total_penalty = sum_penalty_scores(TW_opened_tickets)
    TW_avg_penalty = TW_total_penalty / TW_n_opened_tickets if TW_n_opened_tickets > 0 else 0

    TW_closed_tickets = retrieve_closed_tickets_between(last_week, current_time, account=account)
    TW_closed_tickets_avg_duration, TW_closed_tickets_mdn_duration = closed_tickets_stats(TW_closed_tickets)
    TW_n_closed_tickets = len(TW_closed_tickets)

    TW_autoremediations = sort_on_severity(retrieve_autoremediations_between(last_week, current_time, account=account))
    TW_n_autoremediations = len(TW_autoremediations)

    TW_incidents = sort_on_severity(retrieve_incidents_between(last_week, current_time, account=account))
    TW_n_incidents = len(TW_incidents)

    open_tickets_html_table = get_ticket_html_table(TW_open_tickets)
    autoremediations_html_table = get_autoremediations_html_table(TW_autoremediations)
    incidents_html_table = get_incidents_html_table(TW_incidents)

    # Last week
    LW_open_tickets = sort_on_severity(set_age_and_overdue(retrieve_tickets_open_at_PIT(last_week, account=account)))
    LW_n_open_tickets = len(LW_open_tickets)

    LW_n_overdue_tickets = count_overdue_tickets(LW_open_tickets)
    LW_opened_tickets = retrieve_opened_tickets_between(two_weeks, last_week, account=account)
    LW_n_opened_tickets = len(LW_opened_tickets)

    LW_total_penalty = sum_penalty_scores(LW_opened_tickets)
    LW_avg_penalty = LW_total_penalty / LW_n_opened_tickets if LW_n_opened_tickets > 0 else 0

    LW_closed_tickets = retrieve_closed_tickets_between(two_weeks, last_week, account=account)
    LW_closed_tickets_avg_duration, LW_closed_tickets_mdn_duration = closed_tickets_stats(LW_closed_tickets)
    LW_n_closed_tickets = len(LW_closed_tickets)

    LW_autoremediations = sort_on_severity(retrieve_autoremediations_between(two_weeks, last_week, account=account))
    LW_n_autoremediations = len(LW_autoremediations)

    LW_incidents = sort_on_severity(retrieve_incidents_between(two_weeks, last_week, account=account))
    LW_n_incidents = len(LW_incidents)

    # Convert to CSV for compactness, to save tokens.
    TW_open_tickets = pd.DataFrame(TW_open_tickets).to_csv(index=False)
    TW_autoremediations = pd.DataFrame(TW_autoremediations).to_csv(index=False)
    TW_incidents = pd.DataFrame(TW_incidents).to_csv(index=False)

    # Prepare the return data
    data['messages']['report']['html'] = ''

    data['html_substitutions']['open_tickets_html_table'] = open_tickets_html_table
    data['html_substitutions']['autoremediations_html_table'] = autoremediations_html_table
    data['html_substitutions']['incidents_html_table'] = incidents_html_table

    data['system'] = system
    data['user'] = {
        "account": account,
        "account_organizational_unit": account_data['OrganizationalUnit'],
        "account_project_name": account_data['ProjectName'],
        "account_project_id": account_data['ProjectId'],
        "account_project_id_app": account_data['ProjectIdApp'],
        "account_team": account_data['Team'],
        "account_environment": account_data['Environment'],
        "account_age_in_days": account_data['AccountAgeInDays'],
        "is_admin_account": "True" if account == data['bb']['aws_organization_administrative_account_name'] else "False",
        "this_week": {
            "open_tickets": TW_open_tickets,
            "n_open_tickets": TW_n_open_tickets,
            "n_overdue_tickets": TW_n_overdue_tickets,
            "n_opened_tickets": TW_n_opened_tickets,
            "n_closed_tickets": TW_n_closed_tickets,
            "closed_tickets_avg_duration": TW_closed_tickets_avg_duration,
            "closed_tickets_mdn_duration": TW_closed_tickets_mdn_duration,
            "autoremediations": TW_autoremediations,
            "n_autoremediations": TW_n_autoremediations,
            "incidents": TW_incidents,
            "n_incidents": TW_n_incidents,
            "total_penalty": TW_total_penalty,
            "avg_penalty": TW_avg_penalty,
        },
        "last_week": {
            "n_open_tickets": LW_n_open_tickets,
            "n_overdue_tickets": LW_n_overdue_tickets,
            "n_opened_tickets": LW_n_opened_tickets,
            "n_closed_tickets": LW_n_closed_tickets,
            "closed_tickets_avg_duration": LW_closed_tickets_avg_duration,
            "closed_tickets_mdn_duration": LW_closed_tickets_mdn_duration,
            "n_autoremediations": LW_n_autoremediations,
            "n_incidents": LW_n_incidents,
            "total_penalty": LW_total_penalty,
            "avg_penalty": LW_avg_penalty,
        }
    }
    data['user'] = json.dumps(data['user'], default=decimal_default)
    data['account'] = account

    return data


def decimal_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)


# ----------------------------------------------------------------
#
#   Tickets, autoremediations, incidents
#
# ----------------------------------------------------------------

def get_ticket_html_table(tickets):
    if not tickets:
        return ''

    # Start the table and headers
    table_str = """
    <table border="1">
        <thead>
            <tr>
                <th>Ticket</th>
                <th>Severity</th>
                <th>Control</th>
                <th>Title</th>
                <th>Age</th>
            </tr>
        </thead>
        <tbody>
    """
    
    # Loop through each ticket to generate rows
    for ticket in tickets:
        table_str += f"""
        <tr>
            <td>{ticket['ticket_id']}</td>
            <td>{ticket['severity_label']}</td>
            <td>{ticket['SecurityControlId']}</td>
            <td>{ticket['Title']}</td>
            <td>{ticket['age_txt']}</td>
        </tr>
        """
    
    # End the table
    table_str += """
        </tbody>
    </table>
    """
    
    return table_str


def get_autoremediations_html_table(autoremediations):
    if not autoremediations:
        return ''

    # Start the table and headers
    table_str = """
    <table border="1">
        <thead>
            <tr>
                <th>Ticket</th>
                <th>Severity</th>
                <th>Control</th>
                <th>Title</th>
            </tr>
        </thead>
        <tbody>
    """
    
    # Loop through each autoremediation to generate rows
    for autoremediation in autoremediations:
        table_str += f"""
        <tr>
            <td>{autoremediation['ticket_id']}</td>
            <td>{autoremediation['severity_label']}</td>
            <td>{autoremediation['SecurityControlId']}</td>
            <td>{autoremediation['Title']}</td>
        </tr>
        """
    
    # End the table
    table_str += """
        </tbody>
    </table>
    """
    
    return table_str


def get_incidents_html_table(incidents):
    if not incidents:
        return ''

    # Start the table and headers
    table_str = """
    <table border="1">
        <thead>
            <tr>
                <th>Ticket</th>
                <th>Severity</th>
                <th>Title</th>
            </tr>
        </thead>
        <tbody>
    """
    
    # Loop through each incident to generate rows
    for incident in incidents:
        table_str += f"""
        <tr>
            <td>{incident['ticket_id']}</td>
            <td>{incident['severity_label']}</td>
            <td>{incident['Title']}</td>
        </tr>
        """
    
    # End the table
    table_str += """
        </tbody>
    </table>
    """
    
    return table_str



def sort_on_severity(tickets):
    sorted_tickets = sorted(tickets, key=lambda x: SEVERITY_ORDER[x['severity_label']])
    return sorted_tickets


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


def count_overdue_tickets(tickets):
    return sum(1 for ticket in tickets if ticket.get('is_overdue') == "Yes")


def sum_penalty_scores(data):
    """
    Sum the 'penalty_score' values from a list of dictionaries.

    :param data: List of dictionaries
    :return: Sum of 'penalty_score' values
    """
    return sum(float(item.get('penalty_score', 0)) for item in data)


def closed_tickets_stats(tickets):
    """
    Calculate the average and median duration of closed tickets.

    Args:
    - tickets (list): List of ticket dictionaries.

    Returns:
    - tuple: (average_duration, median_duration)
    """
    if not tickets:  # Return 0 if there are no tickets.
        return (0, 0)
    
    # Extract durations from the ticket dictionaries
    durations = [ticket['duration_sec'] for ticket in tickets]
    
    # Calculate average duration
    avg_duration = sum(durations) / len(durations)
    
    # Calculate median duration
    sorted_durations = sorted(durations)
    length = len(sorted_durations)
    if length % 2 == 0:  # even number of durations
        median_duration = (sorted_durations[length // 2 - 1] + sorted_durations[length // 2]) / 2
    else:  # odd number of durations
        median_duration = sorted_durations[length // 2]

    return avg_duration, median_duration


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


def retrieve_open_tickets(account=None):
    """Retrieve all tickets that are currently open.

    If 'account' parameter is present, only tickets with the 'Account'
    field equal to the value of 'account' (string) are returned.
    """
    open_tickets = query_with_paging(
        tickets,
        IndexName='dummy-closed_at-index',
        KeyConditionExpression='dummy = :dummy_val AND begins_with(closed_at, :prefix)',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':prefix': 'NULL#'
        }
    )

    if account:
        open_tickets = [ticket for ticket in open_tickets if ticket.get('Account') == account]

    return open_tickets


def retrieve_tickets_open_at_PIT(pit_time: datetime, window_duration_days=90, account=None):
    """Retrieve all tickets that are open at a specific point in time (PIT) 
    using a specified time window duration around the PIT."""
    
    # Calculate start_time based on window_duration_days
    start_time = pit_time - timedelta(days=window_duration_days)
    
    # Convert datetime objects to strings for querying
    start_time_str = start_time.isoformat()
    pit_time_str = pit_time.isoformat()

    results = query_with_paging(
        tickets,
        IndexName='dummy-opened_at-index',
        KeyConditionExpression='dummy = :dummy_val AND opened_at BETWEEN :start_time AND :pit_time',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':start_time': start_time_str,
            ':pit_time': pit_time_str
        }
    )

    # If account is specified, filter the results based on the 'Account' field
    if account:
        results = [item for item in results if item.get('Account') == account]

    # Filter the results further to identify tickets that were still open at PIT
    open_tickets = [
        item for item in results 
        if item['closed_at'].startswith('NULL#') or item['closed_at'] > pit_time_str
    ]

    return open_tickets


def retrieve_autoremediations_between(start_time: datetime, end_time: datetime, account=None):
    """Retrieve all autoremediations done between the given start_time and end_time."""
    
    # Convert datetime objects to strings for querying
    start_time_str = start_time.isoformat()
    end_time_str = end_time.isoformat()

    results = query_with_paging(
        autoremediations,
        IndexName='dummy-opened_at-index',
        KeyConditionExpression='dummy = :dummy_val AND opened_at BETWEEN :start_time AND :end_time',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':start_time': start_time_str,
            ':end_time': end_time_str
        }
    )

    # If account is specified, filter the results based on the 'Account' field
    if account:
        results = [item for item in results if item.get('Account') == account]

    return results


def retrieve_incidents_between(start_time: datetime, end_time: datetime, account=None):
    """Retrieve all incidents that occurred between the given start_time and end_time."""
    
    # Convert datetime objects to strings for querying
    start_time_str = start_time.isoformat()
    end_time_str = end_time.isoformat()

    results = query_with_paging(
        incidents,
        IndexName='dummy-opened_at-index',
        KeyConditionExpression='dummy = :dummy_val AND opened_at BETWEEN :start_time AND :end_time',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':start_time': start_time_str,
            ':end_time': end_time_str
        }
    )

    # Filter results by account if provided
    if account:
        results = [incident for incident in results if incident.get('Account') == account]
    
    return results


def retrieve_opened_tickets_between(start_time: datetime, end_time: datetime, account=None):
    """Retrieve all tickets that were opened between the given start and end dates."""
    
    # Convert datetime objects to strings for querying
    start_time_str = start_time.isoformat()
    end_time_str = end_time.isoformat()

    results = query_with_paging(
        tickets,
        IndexName='dummy-opened_at-index',
        KeyConditionExpression='dummy = :dummy_val AND opened_at BETWEEN :start_time AND :end_time',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':start_time': start_time_str,
            ':end_time': end_time_str
        }
    )

    # Filter results by account if provided
    if account:
        results = [ticket for ticket in results if ticket.get('Account') == account]

    return results


def retrieve_closed_tickets_between(start_time: datetime, end_time: datetime, account=None):
    """Retrieve all tickets that were closed between the given start and end dates."""

    # Convert datetime objects to strings for querying
    start_time_str = start_time.isoformat()
    end_time_str = end_time.isoformat()

    results = query_with_paging(
        tickets,
        IndexName='dummy-closed_at-index',
        KeyConditionExpression='dummy = :dummy_val AND closed_at BETWEEN :start_time AND :end_time',
        ExpressionAttributeValues={
            ':dummy_val': 'dummy',
            ':start_time': start_time_str,
            ':end_time': end_time_str
        }
    )

    # Filter results by 'Account' if the 'account' parameter is provided
    if account:
        results = [ticket for ticket in results if ticket.get('Account') == account]

    return results


def retrieve_db_item(table, key_value):
    """
    Retrieves an item from DynamoDB based on the given key value.

    Parameters:
        - table (resource): The DynamoDB table resource.
        - key_value (str): The primary key value to query the table with.

    Returns:
        - dict: The retrieved item data.
    """
    # Define the key dictionary based on assumed attribute name 'id'
    key_dict = {'id': key_value}
    
    # Retrieve the item from DynamoDB
    response = table.get_item(Key=key_dict)
    
    # Return the item data
    return response.get('Item')
