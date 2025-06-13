import os
import json
import pytest
from unittest.mock import patch, MagicMock
from moto import mock_aws
import boto3
from datetime import datetime, timedelta, timezone


@pytest.fixture
def mock_env_variables(monkeypatch):
    # Mock environment variables
    monkeypatch.setenv('PRODUCT_NAME', 'TestProduct')
    monkeypatch.setenv('ACCOUNT_TEAM_EMAIL_TAG', 'soar:team:email')
    monkeypatch.setenv('ACCOUNT_TEAM_EMAIL_TAG_APP', 'soar:team:email:app')
    monkeypatch.setenv('DEFAULT_TEAM_EMAIL', 'default-team-email@example.com')
    monkeypatch.setenv('ENVIRONMENT_TAG', 'soar:environment')
    monkeypatch.setenv('CLIENT_TAG', 'soar:client')
    monkeypatch.setenv('PROJECT_TAG', 'soar:project')
    monkeypatch.setenv('TEAM_TAG', 'soar:team')
    monkeypatch.setenv('TICKETING_SYSTEM', 'JIRA')
    monkeypatch.setenv('JIRA_PROJECT_KEY_TAG', 'soar:jira:project-key')
    monkeypatch.setenv('JIRA_PROJECT_KEY_TAG_APP', 'soar:jira:project-key:app')
    monkeypatch.setenv('JIRA_DEFAULT_PROJECT_KEY', 'DEFAULT_PROJECT')
    monkeypatch.setenv('SERVICE_NOW_PROJECT_QUEUE_TAG', 'soar:service-now:project-queue')
    monkeypatch.setenv('SERVICE_NOW_PROJECT_QUEUE_TAG_APP', 'soar:service-now:project-queue:app')
    monkeypatch.setenv('SERVICE_NOW_DEFAULT_PROJECT_QUEUE', 'DEFAULT_QUEUE')
    monkeypatch.setenv('CACHED_ACCOUNT_DATA_TABLE_NAME', 'mock_table')
    monkeypatch.setenv('MIN_AGE_HOURS', '24')


@pytest.fixture
def setup_dynamodb(mock_env_variables, aws_credentials):
    with mock_aws():
        # Create a mock DynamoDB table
        dynamodb = boto3.client('dynamodb')
        table_name = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'id',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )

        yield dynamodb


@mock_aws
@patch('boto3.client')
def test_lambda_handler_cached_data(mock_boto_client, setup_dynamodb):
    # Mock DynamoDB to return cached account data
    dynamodb = setup_dynamodb
    table_name = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']
    account_id = '123456789012'
    cached_data = {'Id': account_id, 'Name': 'Test Account'}
    
    dynamodb.put_item(
        TableName=table_name,
        Item={
            'id': {'S': account_id},
            'data': {'S': json.dumps(cached_data)}
        }
    )

    # Mock describe_account response with a real datetime object
    organizations = boto3.client('organizations')
    mock_boto_client.side_effect = lambda service, config=None: organizations if service == 'organizations' else dynamodb
    organizations.describe_account = lambda AccountId: {
        'Account': {
            'Id': AccountId,
            'Name': 'TestAccount',
            'Email': 'root-account-email@example.com',
            'JoinedTimestamp': datetime.now(timezone.utc) - timedelta(days=1)
        }
    }

    from functions.accounts.get_account_data.app import lambda_handler
    result = lambda_handler(account_id, None)

    assert result == cached_data


@mock_aws
@patch('boto3.client')
def test_lambda_handler_fresh_data(mock_boto_client, mock_env_variables, aws_credentials):
    # Setup mock clients
    dynamodb = boto3.client('dynamodb')
    organizations = boto3.client('organizations')

    mock_boto_client.side_effect = lambda service, config=None: organizations if service == 'organizations' else dynamodb

    # Create mock DynamoDB table
    table_name = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {
                'AttributeName': 'id',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'id',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    dynamodb.get_waiter('table_exists').wait(TableName=table_name)

    # Mock describe_account response
    organizations.describe_account = lambda AccountId: {
        'Account': {
            'Id': AccountId,
            'Name': 'TestAccount',
            'Email': 'root-account-email@example.com',
            'JoinedTimestamp': datetime.now(timezone.utc) - timedelta(days=1)
        }
    }

    # Mock list_tags_for_resource response
    organizations.get_paginator = lambda operation_name: {
        'list_tags_for_resource': MockPaginator([
            {'Tags': [{'Key': 'soar:team:email', 'Value': 'team@example.com'}]}
        ])
    }.get(operation_name, MockPaginator([]))

    # Mock list_parents response
    organizations.get_paginator = lambda operation_name: {
        'list_parents': MockPaginator([
            {'Parents': [{'Id': 'ou-1234', 'Type': 'ORGANIZATIONAL_UNIT'}]}
        ])
    }.get(operation_name, MockPaginator([]))

    organizations.describe_organizational_unit = lambda OrganizationalUnitId: {
        'OrganizationalUnit': {'Name': 'TestOU'}
    }

    from functions.accounts.get_account_data.app import lambda_handler
    account_id = '123456789012'
    
    # Ensure the DynamoDB client in the Lambda function uses the mocked client
    with patch('functions.accounts.get_account_data.app.dynamodb', dynamodb):
        result = lambda_handler(account_id, None)

    assert result['Id'] == account_id
    assert result['Name'] == 'TestAccount'
    assert result['Email'] == 'root-account-email@example.com'
    assert result['TeamEmail'] == 'default-team-email@example.com'


@mock_aws
@patch('boto3.client')
def test_put_cached_account_data(mock_boto_client, setup_dynamodb):
    from functions.accounts.get_account_data.app import put_cached_account_data

    account_id = '123456789012'
    account_data = {'Id': account_id, 'Name': 'Test Account'}

    put_cached_account_data(account_id, account_data)

    dynamodb = setup_dynamodb
    response = dynamodb.get_item(
        TableName=os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME'],
        Key={'id': {'S': account_id}}
    )

    assert 'Item' in response
    assert json.loads(response['Item']['data']['S']) == account_data


@mock_aws
@patch('boto3.client')
def test_get_fresh_account_data(mock_boto_client, mock_env_variables, aws_credentials):
    from functions.accounts.get_account_data.app import get_fresh_account_data

    account_id = '123456789012'
    account_data = {
        'Account': {
            'Id': account_id,
            'Name': 'Test Account',
            'Email': 'root-account-email@example.com',
            'JoinedTimestamp': datetime.now(timezone.utc) - timedelta(days=1)
        }
    }

    def mock_describe_account(AccountId):
        return account_data

    def mock_list_tags_for_resource(ResourceId, PaginationConfig):
        return {'Tags': [{'Key': 'soar:team:email', 'Value': 'team@example.com'}]}

    mock_boto_client.side_effect = lambda service, config=None: mock_aws_client(service, mock_describe_account, mock_list_tags_for_resource)

    result = get_fresh_account_data(account_id)

    assert result['Id'] == account_id
    assert result['Name'] == 'TestAccount'
    assert result['Email'] == 'root-account-email@example.com'
    assert result['TeamEmail'] == 'default-team-email@example.com'


def mock_aws_client(service, mock_describe_account, mock_list_tags_for_resource):
    if service == 'organizations':
        client = boto3.client(service)
        client.describe_account = mock_describe_account
        client.get_paginator = lambda operation: MockPaginator(mock_list_tags_for_resource)
        return client
    elif service == 'dynamodb':
        return boto3.client(service)
    return boto3.client(service)


class MockPaginator:
    def __init__(self, mock_list_tags_for_resource):
        self.mock_list_tags_for_resource = mock_list_tags_for_resource

    def paginate(self, **kwargs):
        return [self.mock_list_tags_for_resource(**kwargs)]


if __name__ == "__main__":
    pytest.main()