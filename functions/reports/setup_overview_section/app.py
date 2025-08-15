import os
import datetime as dt
import boto3
from datetime import datetime, timezone, timedelta, date
from dateutil import parser
import pandas as pd
import humanize
from collections import defaultdict
import json
import decimal


# Get environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

PRODUCT_NAME = os.environ['PRODUCT_NAME']
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

TICKETS_TABLE = os.environ['TICKETS_TABLE']
AUTOREMEDIATIONS_TABLE = os.environ['AUTOREMEDIATIONS_TABLE']
INCIDENTS_TABLE = os.environ['INCIDENTS_TABLE']
AI_PROMPTS_TABLE = os.environ['AI_PROMPTS_TABLE']

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

organizations = boto3.client('organizations')
securityhub = boto3.client('securityhub')

dynamodb = boto3.resource('dynamodb')
tickets = dynamodb.Table(TICKETS_TABLE)
autoremediations = dynamodb.Table(AUTOREMEDIATIONS_TABLE)
incidents = dynamodb.Table(INCIDENTS_TABLE)
ai_prompts = dynamodb.Table(AI_PROMPTS_TABLE)


# Lambda handler
def lambda_handler(data, _context):
    system = retrieve_db_item(ai_prompts, 'weekly_ai_report_0_common')['instructions'] + "\n"
    system += retrieve_db_item(ai_prompts, 'weekly_ai_report_1_overview')['instructions']

    # Current UTC datetime
    current_time = datetime.utcnow()

    # UTC datetime one week before the current_time
    last_week = current_time - timedelta(weeks=1)
    two_weeks = current_time - timedelta(weeks=2)
    three_weeks = current_time - timedelta(weeks=3)
    four_weeks = current_time - timedelta(weeks=4)

    # Retrieve account details for all accounts in the organisation
    account_data = get_all_account_data()
    n_accounts = len(account_data)

    # Retrieve the name of the organization account
    org_account_name = get_administrative_account()
    
    # THIS WEEK
    TW_open_tickets = sort_on_severity(set_age_and_overdue(retrieve_open_tickets()))
    TW_n_open_tickets = len(TW_open_tickets)
    TW_accounts_with_open_tickets = count_accounts(TW_open_tickets)
    TW_n_accounts_with_open_tickets = len(TW_accounts_with_open_tickets)

    TW_n_overdue_tickets = count_overdue_tickets(TW_open_tickets)
    TW_accounts_with_overdue_tickets = get_accounts_with_overdue_tickets(TW_open_tickets)
    TW_n_accounts_with_overdue_tickets = len(TW_accounts_with_overdue_tickets)

    TW_ticket_severity_level_breakdown = get_severity_level_breakdown(TW_open_tickets)
    TW_open_tickets_redux = get_security_control_data_redux(TW_open_tickets)

    TW_opened_tickets = retrieve_opened_tickets_between(last_week, current_time)
    TW_n_opened_tickets = len(TW_opened_tickets)

    TW_closed_tickets = retrieve_closed_tickets_between(last_week, current_time)
    TW_closed_tickets_avg_duration, TW_closed_tickets_mdn_duration = closed_tickets_stats(TW_closed_tickets)
    TW_n_closed_tickets = len(TW_closed_tickets)

    TW_autoremediations = retrieve_autoremediations_between(last_week, current_time)
    TW_n_autoremediations = len(TW_autoremediations)
    TW_autoremediations_severity_level_breakdown = get_severity_level_breakdown(TW_autoremediations)
    TW_accounts_with_autoremediations = count_accounts(TW_autoremediations)
    TW_n_accounts_with_autoremediations = len(TW_accounts_with_autoremediations)
    TW_autoremediations_redux = get_security_control_data_redux(TW_autoremediations)

    TW_incidents = retrieve_incidents_between(last_week, current_time, org_account_name)
    TW_n_incidents = len(TW_incidents)
    TW_incidents_severity_level_breakdown = get_severity_level_breakdown(TW_incidents)
    TW_accounts_with_incidents = count_accounts(TW_incidents)
    TW_n_accounts_with_incidents = len(TW_accounts_with_incidents)
    TW_incidents_redux = incidents_redux(TW_incidents)

    TW_accounts_with_issues, TW_accounts_breakdown_html_table = accounts_breakdown_html_table(
        TW_accounts_with_open_tickets, TW_accounts_with_overdue_tickets, 
        TW_accounts_with_autoremediations, TW_accounts_with_incidents,
        account_data, org_account_name
    )

    TW_total_penalty = sum_penalty_scores(TW_opened_tickets) + sum_penalty_scores(TW_incidents)  # + sum_penalty_scores(TW_autoremediations) 
    TW_n_issues = TW_n_opened_tickets + TW_n_incidents  # + TW_n_autoremediations
    TW_avg_penalty = TW_total_penalty / TW_n_issues if TW_n_issues > 0 else 0
    

    # LAST WEEK
    LW_open_tickets = sort_on_severity(set_age_and_overdue(retrieve_tickets_open_at_PIT(last_week)))
    LW_n_open_tickets = len(LW_open_tickets)
    LW_accounts_with_open_tickets = count_accounts(LW_open_tickets)
    LW_n_accounts_with_open_tickets = len(LW_accounts_with_open_tickets)

    LW_n_overdue_tickets = count_overdue_tickets(LW_open_tickets)
    LW_accounts_with_overdue_tickets = get_accounts_with_overdue_tickets(LW_open_tickets)
    LW_n_accounts_with_overdue_tickets = len(LW_accounts_with_overdue_tickets)

    LW_ticket_severity_level_breakdown = get_severity_level_breakdown(LW_open_tickets)

    LW_opened_tickets = retrieve_opened_tickets_between(two_weeks, last_week)
    LW_n_opened_tickets = len(LW_opened_tickets)

    LW_closed_tickets = retrieve_closed_tickets_between(two_weeks, last_week)
    LW_closed_tickets_avg_duration, LW_closed_tickets_mdn_duration = closed_tickets_stats(LW_closed_tickets)
    LW_n_closed_tickets = len(LW_closed_tickets)
 
    LW_autoremediations = retrieve_autoremediations_between(two_weeks, last_week)
    LW_n_autoremediations = len(LW_autoremediations)
    LW_autoremediations_severity_level_breakdown = get_severity_level_breakdown(LW_autoremediations)
    LW_accounts_with_autoremediations = count_accounts(LW_autoremediations)
    LW_n_accounts_with_autoremediations = len(LW_accounts_with_autoremediations)

    LW_incidents = retrieve_incidents_between(two_weeks, last_week, org_account_name)
    LW_n_incidents = len(LW_incidents)
    LW_incidents_severity_level_breakdown = get_severity_level_breakdown(LW_incidents)
    LW_accounts_with_incidents = count_accounts(LW_incidents)
    LW_n_accounts_with_incidents = len(LW_accounts_with_incidents)

    LW_total_penalty = sum_penalty_scores(LW_opened_tickets) + sum_penalty_scores(LW_incidents)  # + sum_penalty_scores(LW_autoremediations)
    LW_n_issues = LW_n_opened_tickets + LW_n_incidents  # + LW_n_autoremediations
    LW_avg_penalty = LW_total_penalty / LW_n_issues if LW_n_issues > 0 else 0


    # TWO WEEKS AGO
    L2W_open_tickets = sort_on_severity(set_age_and_overdue(retrieve_tickets_open_at_PIT(two_weeks)))
    L2W_ticket_severity_level_breakdown = get_severity_level_breakdown(L2W_open_tickets)
    L2W_autoremediations = retrieve_autoremediations_between(three_weeks, two_weeks)
    L2W_autoremediations_severity_level_breakdown = get_severity_level_breakdown(L2W_autoremediations)
    L2W_incidents = retrieve_incidents_between(three_weeks, two_weeks, org_account_name)
    L2W_incidents_severity_level_breakdown = get_severity_level_breakdown(L2W_incidents)


    # THREE WEEKS AGO
    L3W_open_tickets = sort_on_severity(set_age_and_overdue(retrieve_tickets_open_at_PIT(three_weeks)))
    L3W_ticket_severity_level_breakdown = get_severity_level_breakdown(L3W_open_tickets)
    L3W_autoremediations = retrieve_autoremediations_between(four_weeks, three_weeks)
    L3W_autoremediations_severity_level_breakdown = get_severity_level_breakdown(L3W_autoremediations)
    L3W_incidents = retrieve_incidents_between(four_weeks, three_weeks, org_account_name)
    L3W_incidents_severity_level_breakdown = get_severity_level_breakdown(L3W_incidents)


    # ALL WEEKS
    open_tickets_severity_level_breakdown_html_table = severity_breakdown_html_table(
        TW_ticket_severity_level_breakdown,
        LW_ticket_severity_level_breakdown,
        L2W_ticket_severity_level_breakdown,
        L3W_ticket_severity_level_breakdown
    )
    autoremediations_severity_level_breakdown_html_table = severity_breakdown_html_table(
        TW_autoremediations_severity_level_breakdown, 
        LW_autoremediations_severity_level_breakdown,
        L2W_autoremediations_severity_level_breakdown,
        L3W_autoremediations_severity_level_breakdown
    )
    incidents_severity_level_breakdown_html_table = severity_breakdown_html_table(
        TW_incidents_severity_level_breakdown, 
        LW_incidents_severity_level_breakdown,
        L2W_incidents_severity_level_breakdown,
        L3W_incidents_severity_level_breakdown
    )


    # Convert to CSV for compactness, to save tokens.
    TW_open_tickets_redux = pd.DataFrame(TW_open_tickets_redux).to_csv(index=False)
    TW_autoremediations_redux = pd.DataFrame(TW_autoremediations_redux).to_csv(index=False)
    TW_incidents_redux = pd.DataFrame(TW_incidents_redux).to_csv(index=False)

    # Modify the input and return it
    data['bb']['n_accounts'] = n_accounts
    data['bb']['aws_organization_administrative_account_name'] = org_account_name
    data['bb']['accounts_with_issues'] = TW_accounts_with_issues
    data['bb']['account_map'] = account_mapping(account_data, TW_accounts_with_issues)

    data['html_substitutions']['open_tickets_severity_level_breakdown_html_table'] = open_tickets_severity_level_breakdown_html_table
    data['html_substitutions']['autoremediations_severity_level_breakdown_html_table'] = autoremediations_severity_level_breakdown_html_table
    data['html_substitutions']['incidents_severity_level_breakdown_html_table'] = incidents_severity_level_breakdown_html_table
    data['html_substitutions']['accounts_breakdown_html_table'] = TW_accounts_breakdown_html_table

    data['system'] = system

    data['user'] = {
        "global_data": {
            'n_accounts': n_accounts,
            'aws_organization_administrative_account_name': org_account_name,
        },
        "this_week": {
            "total_penalty": TW_total_penalty,
            "avg_penalty": TW_avg_penalty,

            "n_open_tickets": TW_n_open_tickets,
            "accounts_with_open_tickets": TW_accounts_with_open_tickets,
            "n_accounts_with_open_tickets": TW_n_accounts_with_open_tickets,

            "n_overdue_tickets": TW_n_overdue_tickets,
            "accounts_with_overdue_tickets": TW_accounts_with_overdue_tickets,
            "n_accounts_with_overdue_tickets": TW_n_accounts_with_overdue_tickets,

            "open_tickets_redux": TW_open_tickets_redux,

            "n_opened_tickets": TW_n_opened_tickets,
            "n_closed_tickets": TW_n_closed_tickets,
            "closed_tickets_avg_duration_seconds": TW_closed_tickets_avg_duration,
            "closed_tickets_mdn_duration_seconds": TW_closed_tickets_mdn_duration,

            "autoremediations_redux": TW_autoremediations_redux,
            "n_autoremediations": TW_n_autoremediations,
            "n_accounts_with_autoremediations": TW_n_accounts_with_autoremediations,

            "incidents_redux": TW_incidents_redux,
            "n_incidents": TW_n_incidents,
            "n_accounts_with_incidents": TW_n_accounts_with_incidents,
        },
        "last_week": {
            "total_penalty": LW_total_penalty,
            "avg_penalty": LW_avg_penalty,

            "n_open_tickets": LW_n_open_tickets,
            "n_accounts_with_open_tickets": LW_n_accounts_with_open_tickets,

            "n_overdue_tickets": LW_n_overdue_tickets,
            "n_accounts_with_overdue_tickets": LW_n_accounts_with_overdue_tickets,

            "n_opened_tickets": LW_n_opened_tickets,
            "n_closed_tickets": LW_n_closed_tickets,
            "closed_tickets_avg_duration_seconds": LW_closed_tickets_avg_duration,
            "closed_tickets_mdn_duration_seconds": LW_closed_tickets_mdn_duration,

            "n_autoremediations": LW_n_autoremediations,
            "n_accounts_with_autoremediations": LW_n_accounts_with_autoremediations,

            "n_incidents": LW_n_incidents,
            "n_accounts_with_incidents": LW_n_accounts_with_incidents,
        }
    }
    # Convert to a string, since OpenAI requires strings for system and user messages.
    # Handle Decimal objects properly using a helper function.
    data['user'] = json.dumps(data['user'], default=decimal_default)

    # Add the current week number to the base_title if required
    data['base_title'] = maybe_add_week_number(data)

    return data


def decimal_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)


def maybe_add_week_number(data):
    base_title = data['base_title']
    add_week_number = data['add_week_number']
    
    if add_week_number == 'ISO':
        today = date.today()
        current_week_number = today.isocalendar().week
        base_title += f" (Wk {current_week_number})"

    return base_title


def account_mapping(account_data, accounts_with_issues):
    mappings = {}
    for account in accounts_with_issues:
        if account in account_data:
            mappings[account] = account_data[account]
    return mappings


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


def severity_breakdown_html_table(*weeks_data):
    # Number of weeks' data provided
    num_weeks = len(weeks_data)

    # Start of the table
    table_html = "<table><thead><tr><th>Severity</th>"
    # Add header columns for each week
    for i in range(num_weeks):
        if i == 0:
            table_html += '<th>This week</th>'
        else:
            table_html += f'<th>{i} week{"s" if i > 1 else ""} ago</th>'
    
    table_html += "</tr></thead><tbody>"

    # Assume that all dictionaries have the same keys (severity levels)
    # If not, this could lead to potential issues and should be handled accordingly
    severity_levels = list(weeks_data[0].keys())

    for severity in severity_levels:
        table_html += f"<tr><td>{severity}</td>"
        for week_data in weeks_data:
            count = week_data.get(severity, 0)  # Default to 0 if severity not present
            count = '' if count == 0 else count
            table_html += f"<td>{count}</td>"
        table_html += "</tr>"

    # Close off the table tags
    table_html += "</tbody></table>"

    return table_html


def accounts_breakdown_html_table(accounts_with_open_tickets, accounts_with_overdue_tickets, 
                                  accounts_with_autoremediations, accounts_with_incidents,
                                  account_data, aws_organization_administrative_account_name):
    # Combine all the keys (account names) from all the dictionaries
    all_accounts = set(accounts_with_open_tickets) | set(accounts_with_overdue_tickets) | \
                   set(accounts_with_autoremediations) | set(accounts_with_incidents)

    # Calculate the sum of counts for each account
    account_sums = {}
    for account in all_accounts:
        account_sums[account] = accounts_with_open_tickets.get(account, 0) + \
                                accounts_with_overdue_tickets.get(account, 0) + \
                                accounts_with_autoremediations.get(account, 0) + \
                                accounts_with_incidents.get(account, 0)
    
    # Filter to only include accounts that exist in account_data, then sort by sum
    existing_accounts = {account for account in all_accounts if account in account_data}
    sorted_accounts = sorted(existing_accounts, key=lambda x: account_sums[x], reverse=True)

    # Start of the table
    table_html = "<table><thead><tr><th>Account</th><th>Env</th><th>OU</th><th>Team</th>" + \
                 "<th>Tickets</th><th>Overdue</th><th>Autorem.</th>" + \
                 "<th>Incidents</th><th>Remarks</th></tr></thead><tbody>"
    
    # For each account, fetch the required data and construct the row
    for account in sorted_accounts:
        environment = account_data.get(account, {}).get('Environment', '[Unknown Environment]')
        ou = account_data.get(account, {}).get('OrganizationalUnit', '[Unknown OU]')
        team = account_data.get(account, {}).get('Team', '[Unknown Team]')
        remarks = "AWS Organizations administrative account" if account == aws_organization_administrative_account_name else ""
        awopt = accounts_with_open_tickets.get(account, 0)
        awopt = '' if awopt == 0 else awopt
        awodt = accounts_with_overdue_tickets.get(account, 0)
        awodt = '' if awodt == 0 else awodt
        awau = accounts_with_autoremediations.get(account, 0)
        awau = '' if awau == 0 else awau
        awin = accounts_with_incidents.get(account, 0)
        awin = '' if awin == 0 else awin
        table_html += f"<tr><td>{account}</td><td>{environment}</td><td>{ou}</td><td>{team}</td>" + \
                       f"<td>{awopt}</td>" + \
                       f"<td>{awodt}</td>" + \
                       f"<td>{awau}</td>" + \
                       f"<td>{awin}</td>" + \
                       f"<td>{remarks}</td>" + \
                       "</tr>"

    # Close the table tags
    table_html += "</tbody></table>"

    return sorted_accounts, table_html


def count_overdue_tickets(tickets):
    return sum(1 for ticket in tickets if ticket.get('is_overdue') == "Yes")


def sum_penalty_scores(data):
    """
    Sum the 'penalty_score' values from a list of dictionaries.

    :param data: List of dictionaries
    :return: Sum of 'penalty_score' values
    """
    return sum(float(item.get('penalty_score', 0)) for item in data)


def get_severity_level_breakdown(tickets):
    summary = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFORMATIONAL': 0
    }

    for ticket in tickets:
        severity_label = ticket.get('severity_label')
        if severity_label in summary:
            summary[severity_label] += 1

    return summary


def sort_on_severity(tickets):
    sorted_tickets = sorted(tickets, key=lambda x: SEVERITY_ORDER[x['severity_label']])
    return sorted_tickets


def count_accounts(list):
    accounts = defaultdict(int)
    for item in list:
        accounts[item['Account']] += 1
    return dict(accounts)


def get_accounts_with_overdue_tickets(tickets):
    overdue_accounts = defaultdict(int)
    for ticket in tickets:
        if ticket['overdue_seconds'] > 0:
            overdue_accounts[ticket['Account']] += 1
    return dict(overdue_accounts)


# Get info about the ticket or autoremediation controls
def get_security_control_data_redux(controls):
    # If no controls, return at once
    if not controls:
        return []

    # Create a dictionary to maintain the frequency of each SecurityControlId
    security_control_frequency = {}
    for control in controls:
        security_control_id = control['SecurityControlId']
        if security_control_id not in security_control_frequency:
            security_control_frequency[security_control_id] = 1
        else:
            security_control_frequency[security_control_id] += 1

    # Extract unique Security Control IDs from active tickets
    security_control_ids = list(security_control_frequency.keys())

    # Call batch_get_security_controls to retrieve data for the Security Control IDs
    response = securityhub.batch_get_security_controls(
        SecurityControlIds=security_control_ids
    )

    # Extract the desired fields for each SecurityControl 
    security_controls = [
        {
            'SecurityControlId': sc['SecurityControlId'],
            'Title': sc['Title'],
            'Description': sc['Description'],
            'Frequency': security_control_frequency[sc['SecurityControlId']]  # include frequency in the extracted data
        }
        for sc in response['SecurityControls']
    ]

    # Sort the security controls based on their frequency, in descending order
    sorted_security_controls = sorted(security_controls, key=lambda x: x['Frequency'], reverse=True)

    # Remove the 'Frequency' field before returning the result
    for control in sorted_security_controls:
        del control['Frequency']

    return sorted_security_controls


def incidents_redux(incidents):
    # Use a dictionary to track unique titles and their frequencies
    unique_incidents = {}

    for incident in incidents:
        title = incident['Title']
        if title not in unique_incidents:
            unique_incidents[title] = {
                'IncidentType': incident['IncidentType'],
                'Title': title,
                'Description': incident['Description'],
                'SOARFailure': incident.get('SOARFailure', False),
                'Frequency': 1  # add frequency to each incident
            }
        else:
            unique_incidents[title]['Frequency'] += 1

    # Sort incidents based on their frequency, in descending order
    sorted_incidents = sorted(unique_incidents.values(), key=lambda x: x['Frequency'], reverse=True)

    # For the result, you might not want to include the 'Frequency' field, 
    # so we can remove it while returning the sorted list
    for incident in sorted_incidents:
        del incident['Frequency']

    return sorted_incidents


# Massage the incidents
def massage_incidents(incidents, org_account_name):
    # Add SOAR failure field
    # - SOAR failures can be identified by ALL of the following being true:
    #   1. The account name is the same as the value of 'global_data.aws_organization_administrative_account_name'.
    #   2. The severity_label is not INFORMATIONAL.
    #   3. Its IncidentType must be exactly "Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms".
    #   4. Its Title or Description must contain the substring "SOAR".
    for incident in incidents:
        if (incident['Account'] == org_account_name and 
            incident['severity_label'] != 'INFORMATIONAL' and
            incident['IncidentType'] == 'Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms' and
            ('SOAR' in incident['Title'] or 'SOAR' in incident['Description'])
           ):
            incident['SOARFailure'] = True
        else:
            incident['SOARFailure'] = False
    return incidents


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

# Get the name of the administrative account
def get_administrative_account():
    response = organizations.describe_organization()
    master_account_id = response['Organization']['MasterAccountId']
    
    account = organizations.describe_account(AccountId=master_account_id)['Account']
    return account['Name']


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


def retrieve_tickets_open_at_PIT(pit_time: datetime, window_duration_days=90):
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


def retrieve_incidents_between(start_time: datetime, end_time: datetime, org_account_name, account=None):
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

    return massage_incidents(results, org_account_name)


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
