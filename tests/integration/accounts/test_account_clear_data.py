import os
import pytest
from importlib import import_module
from moto import mock_aws
import boto3
import json


@pytest.fixture
def mock_env_variables(monkeypatch):
    # Mock environment variables
    monkeypatch.setenv('CACHED_ACCOUNT_DATA_TABLE_NAME', 'mock_table')

@pytest.fixture
def setup_dynamodb(mock_env_variables, aws_credentials):
    with mock_aws():
        # Create a mock DynamoDB table
        dynamodb = boto3.resource('dynamodb')
        table_name = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']
        table = dynamodb.create_table(
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

        # Wait until the table exists
        table.meta.client.get_waiter('table_exists').wait(TableName=table_name)

        yield table


@pytest.fixture
def populate_dynamodb(setup_dynamodb):
    # Populate the mock DynamoDB table with some test data
    table = setup_dynamodb
    items = [{'id': f'account_{i}'} for i in range(1, 51)]
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    return table


@mock_aws
def test_lambda_handler(populate_dynamodb):
    # Import the lambda_handler function after setting environment variables
    from functions.accounts.clear_account_data.app import lambda_handler
    # Invoke the lambda_handler function
    lambda_handler(None, None)

    # Assertions
    table = populate_dynamodb
    response = table.scan()
    items = response['Items']

    # Check that the table is empty after the lambda_handler runs
    assert len(items) == 0


@mock_aws
def test_lambda_handler_empty_table(setup_dynamodb):
    # Import the lambda_handler function after setting environment variables
    from functions.accounts.clear_account_data.app import lambda_handler
    # Invoke the lambda_handler function
    lambda_handler(None, None)

    # Assertions
    table = setup_dynamodb
    response = table.scan()
    items = response['Items']

    # Check that the table is empty after the lambda_handler runs
    assert len(items) == 0


@mock_aws
def test_lambda_handler_small_number_of_items(setup_dynamodb):
    # Populate the mock DynamoDB table with fewer than 25 items
    table = setup_dynamodb
    items = [{'id': f'account_{i}'} for i in range(1, 10)]
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    # Import the lambda_handler function after setting environment variables
    from functions.accounts.clear_account_data.app import lambda_handler
    # Invoke the lambda_handler function
    lambda_handler(None, None)

    # Assertions
    response = table.scan()
    items = response['Items']

    # Check that the table is empty after the lambda_handler runs
    assert len(items) == 0


@mock_aws
def test_lambda_handler_large_number_of_items(setup_dynamodb):
    # Populate the mock DynamoDB table with more than 100 items
    table = setup_dynamodb
    items = [{'id': f'account_{i}'} for i in range(1, 151)]
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    # Import the lambda_handler function after setting environment variables
    from functions.accounts.clear_account_data.app import lambda_handler
    # Invoke the lambda_handler function
    lambda_handler(None, None)

    # Assertions
    response = table.scan()
    items = response['Items']

    # Check that the table is empty after the lambda_handler runs
    assert len(items) == 0


@mock_aws
def test_lambda_handler_with_unprocessed_items(setup_dynamodb, monkeypatch):
    # Populate the mock DynamoDB table with some test data
    table = setup_dynamodb
    items = [{'id': f'account_{i}'} for i in range(1, 51)]
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    # Mock the batch_write_item method to simulate unprocessed items
    original_batch_write_item = boto3.resource('dynamodb').batch_write_item

    def mock_batch_write_item(RequestItems):
        if 'mock_table' in RequestItems:
            unprocessed = RequestItems['mock_table'][:5]
            return {'UnprocessedItems': {'mock_table': unprocessed}}
        return original_batch_write_item(RequestItems)

    monkeypatch.setattr(boto3.resource('dynamodb'), 'batch_write_item', mock_batch_write_item)

    # Import the lambda_handler function after setting environment variables
    from functions.accounts.clear_account_data.app import lambda_handler
    # Invoke the lambda_handler function
    lambda_handler(None, None)

    # Assertions
    response = table.scan()
    items = response['Items']

    # Check that the table is empty after the lambda_handler runs
    assert len(items) == 0


if __name__ == "__main__":
    pytest.main()
    