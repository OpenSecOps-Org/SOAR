"""
DynamoDB Security Hub finding fixtures for testing auto-remediation functions.

This module provides standardized ASFF (AWS Security Finding Format) test data
for DynamoDB-related security controls including:

- DynamoDB.2: Point-in-time recovery configuration

Test scenarios include:
- Standard table configurations
- Cross-account tables
- Different regions
- Complex table naming patterns
- Error conditions (missing tables, etc.)
"""

import copy

# Base DynamoDB.2 finding for point-in-time recovery
DYNAMODB2_BASE_FINDING = {
    "AwsAccountId": "123456789012",
    "CreatedAt": "2023-09-15T10:30:00.000Z",
    "Description": "This control checks whether point-in-time recovery is enabled for Amazon DynamoDB tables.",
    "GeneratorId": "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard/v/1.0.0/DynamoDB.2",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0/DynamoDB.2/finding/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Resources": [
        {
            "Id": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table",
            "Partition": "aws",
            "Region": "us-east-1",
            "Type": "AwsDynamoDbTable"
        }
    ],
    "SchemaVersion": "2018-10-08",
    "Severity": {
        "Label": "MEDIUM",
        "Normalized": 40,
        "Original": "MEDIUM"
    },
    "Title": "DynamoDB tables should have point-in-time recovery enabled",
    "Type": "Software and Configuration Checks/AWS Security Best Practices",
    "UpdatedAt": "2023-09-15T10:30:00.000Z"
}


def get_dynamodb2_finding_standard():
    """Standard DynamoDB.2 finding for point-in-time recovery testing."""
    return {'finding': copy.deepcopy(DYNAMODB2_BASE_FINDING)}


def get_dynamodb2_finding_cross_account():
    """DynamoDB.2 finding for cross-account testing."""
    finding = copy.deepcopy(DYNAMODB2_BASE_FINDING)
    finding['AwsAccountId'] = "555666777888"
    finding['Resources'][0]['Id'] = "arn:aws:dynamodb:us-east-1:555666777888:table/cross-account-table"
    return {'finding': finding}


def get_dynamodb2_finding_different_region():
    """DynamoDB.2 finding for different region testing."""
    finding = copy.deepcopy(DYNAMODB2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:dynamodb:us-west-2:123456789012:table/west-table"
    finding['Resources'][0]['Region'] = "us-west-2"
    return {'finding': finding}


def get_dynamodb2_finding_complex_name():
    """DynamoDB.2 finding with complex table naming pattern."""
    finding = copy.deepcopy(DYNAMODB2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:dynamodb:us-east-1:123456789012:table/production-user-sessions-v2"
    return {'finding': finding}


def get_dynamodb2_finding_with_hyphens():
    """DynamoDB.2 finding with hyphenated table name."""
    finding = copy.deepcopy(DYNAMODB2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:dynamodb:us-east-1:123456789012:table/my-application-data"
    return {'finding': finding}


def get_dynamodb2_finding_eu_region():
    """DynamoDB.2 finding for EU region testing."""
    finding = copy.deepcopy(DYNAMODB2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:dynamodb:eu-west-1:123456789012:table/eu-customer-data"
    finding['Resources'][0]['Region'] = "eu-west-1"
    return {'finding': finding}