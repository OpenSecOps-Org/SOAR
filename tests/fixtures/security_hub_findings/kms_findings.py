"""
KMS Security Hub finding fixtures for testing auto-remediation functions.

This module provides standardized ASFF (AWS Security Finding Format) test data
for KMS-related security controls including:

- KMS.4: Key rotation enablement

Test scenarios include:
- Standard customer-managed keys
- Cross-account keys
- Different regions
- Complex key naming patterns
- Error conditions (missing keys, invalid states)
"""

import copy

# Base KMS.4 finding for key rotation
KMS4_BASE_FINDING = {
    "AwsAccountId": "123456789012",
    "CreatedAt": "2023-09-15T10:30:00.000Z",
    "Description": "This control checks whether rotation is enabled for AWS KMS keys.",
    "GeneratorId": "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard/v/1.0.0/KMS.4",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0/KMS.4/finding/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Resources": [
        {
            "Id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "Partition": "aws",
            "Region": "us-east-1",
            "Type": "AwsKmsKey"
        }
    ],
    "SchemaVersion": "2018-10-08",
    "Severity": {
        "Label": "MEDIUM",
        "Normalized": 40,
        "Original": "MEDIUM"
    },
    "Title": "KMS keys should have rotation enabled",
    "Type": "Software and Configuration Checks/AWS Security Best Practices",
    "UpdatedAt": "2023-09-15T10:30:00.000Z"
}


def get_kms4_finding_standard():
    """Standard KMS.4 finding for key rotation testing."""
    return {'finding': copy.deepcopy(KMS4_BASE_FINDING)}


def get_kms4_finding_cross_account():
    """KMS.4 finding for cross-account testing."""
    finding = copy.deepcopy(KMS4_BASE_FINDING)
    finding['AwsAccountId'] = "555666777888"
    finding['Resources'][0]['Id'] = "arn:aws:kms:us-east-1:555666777888:key/87654321-4321-4321-4321-210987654321"
    return {'finding': finding}


def get_kms4_finding_different_region():
    """KMS.4 finding for different region testing."""
    finding = copy.deepcopy(KMS4_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:kms:us-west-2:123456789012:key/abcdef12-3456-7890-abcd-ef1234567890"
    finding['Resources'][0]['Region'] = "us-west-2"
    return {'finding': finding}


def get_kms4_finding_different_key_format():
    """KMS.4 finding with different key ID format."""
    finding = copy.deepcopy(KMS4_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:kms:us-east-1:123456789012:key/fedcba09-8765-4321-0fed-cba987654321"
    return {'finding': finding}


def get_kms4_finding_eu_region():
    """KMS.4 finding for EU region testing."""
    finding = copy.deepcopy(KMS4_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    finding['Resources'][0]['Region'] = "eu-west-1"
    return {'finding': finding}