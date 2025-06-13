"""
AWS Account Data Management: Get Account Data with Caching

This Lambda function retrieves comprehensive account information including metadata,
tags, organizational structure, and team assignments. Uses DynamoDB caching to 
improve performance and reduce API calls to AWS Organizations.

Account Data Includes:
- Basic account information (ID, name, email, join date)
- Organizational unit placement and hierarchy
- Tag-based metadata (team, environment, client, project)
- Contact information and team email assignments
- Ticketing system integration details (Jira/ServiceNow)
- Account age and classification (new vs established)

Caching Strategy:
- Check DynamoDB cache first for existing account data
- Fetch fresh data from AWS Organizations if cache miss
- Store fresh data in cache for future requests
- Cache improves performance and reduces Organizations API throttling

Target Resources: AWS Organizations accounts and DynamoDB cache
Purpose: Centralized account metadata retrieval with performance optimization
"""

import os
import datetime as dt
import json
import boto3
from botocore.config import Config
from dateutil import parser

# SOAR Configuration
PRODUCT_NAME = os.environ['PRODUCT_NAME']

# Team Contact Configuration
ACCOUNT_TEAM_EMAIL_TAG = os.environ['ACCOUNT_TEAM_EMAIL_TAG']         # soar:team:email
ACCOUNT_TEAM_EMAIL_TAG_APP = os.environ['ACCOUNT_TEAM_EMAIL_TAG_APP'] # soar:team:email:app
DEFAULT_TEAM_EMAIL = os.environ['DEFAULT_TEAM_EMAIL']

# Account Classification Tags
ENVIRONMENT_TAG = os.environ['ENVIRONMENT_TAG']                       # soar:environment
CLIENT_TAG = os.environ['CLIENT_TAG']                                 # soar:client
PROJECT_TAG = os.environ['PROJECT_TAG']                               # soar:project
TEAM_TAG = os.environ['TEAM_TAG']                                     # soar:team

# Ticketing System Integration
TICKETING_SYSTEM = os.environ['TICKETING_SYSTEM']                    # JIRA or ServiceNow

# Jira Integration Configuration
JIRA_PROJECT_KEY_TAG = os.environ['JIRA_PROJECT_KEY_TAG']             # soar:jira:project-key
JIRA_PROJECT_KEY_TAG_APP = os.environ['JIRA_PROJECT_KEY_TAG_APP']     # soar:jira:project-key:app
JIRA_DEFAULT_PROJECT_KEY = os.environ['JIRA_DEFAULT_PROJECT_KEY']     # Default project key

# ServiceNow Integration Configuration
SERVICE_NOW_PROJECT_QUEUE_TAG = os.environ['SERVICE_NOW_PROJECT_QUEUE_TAG']         # soar:service-now:project-queue
SERVICE_NOW_PROJECT_QUEUE_TAG_APP = os.environ['SERVICE_NOW_PROJECT_QUEUE_TAG_APP'] # soar:service-now:project-queue:app
SERVICE_NOW_DEFAULT_PROJECT_QUEUE = os.environ['SERVICE_NOW_DEFAULT_PROJECT_QUEUE'] # Default queue

# Cache Configuration
CACHED_ACCOUNT_DATA_TABLE_NAME = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']
MIN_AGE_HOURS = int(os.environ['MIN_AGE_HOURS'])

# Configure Boto3 with minimal retries - let Step Functions handle retry logic
config = Config(
    retries={
        'total_max_attempts': 1  # Let Step Functions handle the retries
    }
)

# AWS Service Clients
client = boto3.client('organizations', config=config)
dynamodb = boto3.client('dynamodb')


def lambda_handler(account_id, _context):
    """
    Main Lambda handler for retrieving account data with caching.
    
    Args:
        account_id: AWS account ID to retrieve data for
        _context: Lambda context (unused)
        
    Returns:
        dict: Comprehensive account data including metadata, contacts, and classification
        
    Process:
        1. Check DynamoDB cache for existing account data
        2. If cache hit, return cached data immediately
        3. If cache miss, fetch fresh data from AWS Organizations
        4. Store fresh data in cache and return to caller
    """
    # STEP 1: Check cache first for performance optimization
    cached_account_data = get_cached_account_data(account_id)
    if cached_account_data:
        print(f"Account {account_id}: Using cache")
        return cached_account_data

    # STEP 2: Cache miss - fetch fresh data and update cache
    account_data = get_fresh_account_data(account_id)
    put_cached_account_data(account_id, account_data)
    return account_data


def get_cached_account_data(account_id):
    """
    Retrieve account data from DynamoDB cache.
    
    Args:
        account_id: AWS account ID to look up
        
    Returns:
        dict: Cached account data if found and valid, False otherwise
        
    Error Handling:
        Returns False for any cache misses, corruption, or JSON parsing errors.
        This ensures graceful fallback to fresh data fetching.
    """
    response = dynamodb.get_item(
        TableName=CACHED_ACCOUNT_DATA_TABLE_NAME,
        Key={
            'id': {'S': account_id}
        }
    )
    if not response.get('Item', False):
        return False

    json_data = response['Item'].get('data', False)
    if not json_data:
        return False

    try:
        data = json.loads(json_data['S'])
    except Exception:
        return False

    return data

def put_cached_account_data(account_id, account_data):
    """
    Store account data in DynamoDB cache for future requests.
    
    Args:
        account_id: AWS account ID as cache key
        account_data: Complete account data dictionary to cache
        
    Cache Format:
        Stores JSON-serialized account data with account ID as primary key.
        This enables fast lookup and reduces Organizations API calls.
    """
    response = dynamodb.put_item(
        TableName=CACHED_ACCOUNT_DATA_TABLE_NAME,
        Item={
            'id': {'S': account_id},
            'data': {'S': json.dumps(account_data)}
        }
    )
    print(response)


def get_fresh_account_data(account_id):
    """
    Fetch comprehensive account data from AWS Organizations and compile metadata.
    
    Args:
        account_id: AWS account ID to retrieve information for
        
    Returns:
        dict: Complete account data including:
            - Basic account info (ID, name, email, join date)
            - Organizational structure (OU placement)
            - Tag-based metadata (team, environment, client, project)
            - Contact information (team emails)
            - Ticketing integration (Jira/ServiceNow project mappings)
            - Account classification (new vs established)
            - Tallies for reporting and aggregation
            
    Data Sources:
        - AWS Organizations: Account details, tags, OU structure
        - Environment variables: Default values and tag mappings
        - Calculated fields: Account age, team assignments, project mappings
    """
    print(f"Account {account_id}: Fetching fresh data")

    # Get account details
    acc = client.describe_account(
        AccountId=account_id
    )['Account']

    print(acc)

    # Calculate account age
    account_joined = acc['JoinedTimestamp']
    now = dt.datetime.now(dt.timezone.utc)
    age = now - account_joined
    min_age = dt.timedelta(hours=MIN_AGE_HOURS)
    account_new = "Yes" if age < min_age else "No"

    # Get resource tags
    tags = get_resource_tags(account_id)

    # Get team email
    team_email = tags.get(ACCOUNT_TEAM_EMAIL_TAG, DEFAULT_TEAM_EMAIL)
    if team_email == '':
        team_email = acc['Email']
    team_email_app = tags.get(ACCOUNT_TEAM_EMAIL_TAG_APP, '')
    if team_email_app == '':
        team_email_app = team_email

    # Get client, project, team, and environment
    client_name = tags.get(CLIENT_TAG, 'Unspecified')
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

    # Create tallies
    tallies = [
        f"account:{account_id}:{acc['Name']}",
        f"ou:{organizational_unit}",
        f"client:{client_name}",
        f"project_name:{project_name}",
        f"project_id:{project_id}",
        f"team:{team}",
        f"environment:{environment}"
    ]

    # Create result dictionary
    result = {
        'Id': account_id,
        'Name': acc['Name'],
        'Email': acc['Email'],
        'TeamEmail': team_email,
        'TeamEmailApp': team_email_app,
        'OrganizationalUnit': organizational_unit,
        'Client': client_name,
        'ProjectName': project_name,
        'ProjectId': project_id,
        'ProjectIdApp': project_id_app,
        'Team': team,
        'Environment': environment,
        'Tags': tags,
        'Tallies': tallies,
        'AccountNew': account_new
    }
    return result

# Get resource tags for an account
def get_resource_tags(account_id):
    tags = {}

    print("Fetching fresh resource tags")
    paginator = client.get_paginator('list_tags_for_resource')
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
    print("Fetching fresh parent OUs")
    paginator = client.get_paginator('list_parents')
    response_iterator = paginator.paginate(
        ChildId=account_id,
        PaginationConfig={'MaxItems': 100}
    )
    for page in response_iterator:
        for item in page['Parents']:
            if item['Type'] == 'ORGANIZATIONAL_UNIT':
                response = client.describe_organizational_unit(
                    OrganizationalUnitId=item['Id']
                )
                return response['OrganizationalUnit']['Name']
            return 'ROOT'
    return 'UNKNOWN_OU'
