import os
import pytest
from importlib import import_module


@pytest.fixture
def mock_env_variables(monkeypatch):
    # Mock environment variables
    monkeypatch.setenv('PRODUCT_NAME', 'TestProduct')


@pytest.fixture
def mock_input_data():
    # Mock input data
    return {
        'finding': {
            'Id': 'finding-id-123',
            'Title': 'Test Finding Title',
            'Description': 'Test Finding Description',
            'Resources': [{'Type': 'AWS::S3::Bucket', 'Id': 'arn:aws:s3:::example-bucket', 'Region': 'us-east-1'}],
            'ProductFields': {
                'aws/securityhub/ProductName': 'SecurityHub',
                'aws/securityhub/annotation': 'This is a test annotation.'
            },
            'Severity': {'Label': 'HIGH'},
            'Types': ['Software and Configuration Checks'],
            'CreatedAt': '2023-10-01T00:00:00Z',
            'AwsAccountId': '111111111111',
            'Remediation': {
                'Recommendation': {
                    'Text': 'Update your bucket policy to restrict access.',
                    'Url': 'https://example.com/remediation'
                }
            }
        },
        'account': {
            'OrganizationalUnit': 'TestOU',
            'Name': 'TestAccount',
            'TeamEmail': 'team@example.com'
        },
        'messages': {}
    }


@pytest.fixture
def mock_input_data_2():
    # Mock input data
    return {
        'finding': {
            'Id': 'finding-id-456',
            'Title': 'Another Test Finding Title',
            'Description': 'Another Test Finding Description',
            'Resources': [{'Type': 'AWS::S3::Bucket', 'Id': 'arn:aws:s3:::example-bucket', 'Region': 'eu-north-1'}],
            'ProductFields': {},
            'Severity': {'Label': 'LOW'},
            'Types': ['Software and Configuration Checks'],
            'CreatedAt': '2023-10-01T00:00:00Z',
            'AwsAccountId': '222222222222'
        },
        'account': {
            'OrganizationalUnit': 'TestOU',
            'Name': 'TestAccount',
            'TeamEmail': 'team@example.com'
        },
        'messages': {}
    }


def test_lambda_handler(mock_env_variables, mock_input_data):
    # Import the lambda_handler function after setting environment variables
    module = import_module('functions.email.format_generic_message.app')
    lambda_handler = module.lambda_handler
    # Invoke the lambda_handler function
    result = lambda_handler(mock_input_data, None)

    # Assertions
    assert 'messages' in result
    assert 'email' in result['messages']
    assert 'subject' in result['messages']['email']
    assert 'body' in result['messages']['email']

    # Check that the subject contains the title
    assert 'INCIDENT: Test Finding Title' in result['messages']['email']['subject']

    # Check that the body contains specific details
    body = result['messages']['email']['body']
    assert 'HIGH INCIDENT in account "TestAccount" (111111111111, OU: TestOU), region us-east-1' in body
    assert 'Test Finding Title' in body
    assert 'Test Finding Description' in body
    assert 'This is a test annotation.' in body
    assert 'arn:aws:s3:::example-bucket' in body
    assert 'AWS::S3::Bucket' in body
    assert 'Product name: SecurityHub'
    assert 'Finding ID: finding-id-123' in body
    assert 'Created at: 2023-10-01T00:00:00Z' in body
    assert 'ACTIONS REQUIRED: Update your bucket policy to restrict access.' in body
    assert 'Remediation instructions can also be found here: https://example.com/remediation' in body
    assert 'Email sent by TestProduct to: team@example.com' in body


def test_lambda_handler_2(mock_env_variables, mock_input_data_2):
    # Import the lambda_handler function after setting environment variables
    module = import_module('functions.email.format_generic_message.app')
    lambda_handler = module.lambda_handler
    # Invoke the lambda_handler function
    result = lambda_handler(mock_input_data_2, None)

    # Assertions
    assert 'messages' in result
    assert 'email' in result['messages']
    assert 'subject' in result['messages']['email']
    assert 'body' in result['messages']['email']

    # Check that the subject contains the title
    assert 'INCIDENT: Another Test Finding Title' in result['messages']['email']['subject']

    # Check that the body contains specific details
    body = result['messages']['email']['body']
    assert 'LOW INCIDENT in account "TestAccount" (222222222222, OU: TestOU), region eu-north-1' in body
    assert 'Another Test Finding Title' in body
    assert 'Another Test Finding Description' in body
    assert 'arn:aws:s3:::example-bucket' in body
    assert 'AWS::S3::Bucket' in body
    assert 'Product name: N/A' in body
    assert 'Finding ID: finding-id-456' in body
    assert 'Created at: 2023-10-01T00:00:00Z' in body
    assert 'Email sent by TestProduct to: team@example.com' in body
    assert 'ACTIONS REQUIRED: None required as severity is LOW. However, you may want to investigate anyway.' in body


@pytest.fixture
def mock_input_data_informational():
    return {
        'finding': {
            'Id': 'finding-id-789',
            'Title': 'Informational Finding Title',
            'Description': 'Informational Finding Description',
            'Resources': [{'Type': 'AWS::S3::Bucket', 'Id': 'arn:aws:s3:::example-bucket', 'Region': 'us-west-2'}],
            'ProductFields': {},
            'Severity': {'Label': 'INFORMATIONAL'},
            'Types': ['Software and Configuration Checks'],
            'CreatedAt': '2023-10-01T00:00:00Z',
            'AwsAccountId': '333333333333'
        },
        'account': {
            'OrganizationalUnit': 'TestOU',
            'Name': 'TestAccount',
            'TeamEmail': 'team@example.com'
        },
        'messages': {}
    }

def test_lambda_handler_informational(mock_env_variables, mock_input_data_informational):
    module = import_module('functions.email.format_generic_message.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_informational, None)

    assert 'messages' in result
    assert 'email' in result['messages']
    assert 'subject' in result['messages']['email']
    assert 'body' in result['messages']['email']

    body = result['messages']['email']['body']
    assert 'INFORMATIONAL INCIDENT in account "TestAccount" (333333333333, OU: TestOU), region us-west-2' in body
    assert 'ACTIONS REQUIRED: None.' in body


@pytest.fixture
def mock_input_data_missing_remediation():
    return {
        'finding': {
            'Id': 'finding-id-123',
            'Title': 'Test Finding Title',
            'Description': 'Test Finding Description',
            'Resources': [{'Type': 'AWS::S3::Bucket', 'Id': 'arn:aws:s3:::example-bucket', 'Region': 'us-east-1'}],
            'ProductFields': {
                'aws/securityhub/ProductName': 'SecurityHub',
                'aws/securityhub/annotation': 'This is a test annotation.'
            },
            'Severity': {'Label': 'HIGH'},
            'Types': ['Software and Configuration Checks'],
            'CreatedAt': '2023-10-01T00:00:00Z',
            'AwsAccountId': '111111111111'
        },
        'account': {
            'OrganizationalUnit': 'TestOU',
            'Name': 'TestAccount',
            'TeamEmail': 'team@example.com'
        },
        'messages': {}
    }


def test_lambda_handler_missing_remediation(mock_env_variables, mock_input_data_missing_remediation):
    module = import_module('functions.email.format_generic_message.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_missing_remediation, None)

    assert 'messages' in result
    assert 'email' in result['messages']
    assert 'subject' in result['messages']['email']
    assert 'body' in result['messages']['email']

    body = result['messages']['email']['body']
    assert 'ACTIONS REQUIRED: Please investigate.' in body


if __name__ == "__main__":
    pytest.main()
