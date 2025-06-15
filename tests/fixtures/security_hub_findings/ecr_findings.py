"""
Test fixtures for ECR (Elastic Container Registry) Security Hub findings.

This module provides AWS Security Finding Format (ASFF) test data for:
- ECR.1: ECR registry scanning configuration
- ECR.2: ECR repository tag immutability 
- ECR.3: ECR repository lifecycle policies

These fixtures support comprehensive testing of ECR auto-remediation functions
with various scenarios including different repository states, cross-account
configurations, and registry-level operations.
"""

import copy
from datetime import datetime, timezone

# Base ECR.1 finding for registry scanning configuration
ECR1_BASE_FINDING = {
    "SchemaVersion": "2018-10-08",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012",
    "GeneratorId": "aws/securityhub",
    "AwsAccountId": "123456789012",
    "CreatedAt": datetime.now(timezone.utc).isoformat(),
    "UpdatedAt": datetime.now(timezone.utc).isoformat(),
    "Severity": {
        "Label": "MEDIUM",
        "Normalized": 40
    },
    "Title": "ECR.1 ECR repositories should have image scanning configured",
    "Description": "This control checks whether a repository has image scanning enabled.",
    "Remediation": {
        "Recommendation": {
            "Text": "Configure ECR repositories to scan images on push.",
            "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
        }
    },
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "Resources": [
        {
            "Type": "AwsEcrContainerImage",
            "Id": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
            "Partition": "aws",
            "Region": "us-east-1",
            "Details": {
                "AwsEcrContainerImage": {
                    "Name": "test-repo",
                    "RepositoryName": "test-repo",
                    "RegistryId": "123456789012",
                    "Architecture": "amd64"
                }
            }
        }
    ],
    "WorkflowState": "NEW",
    "Workflow": {
        "Status": "NEW"
    },
    "Compliance": {
        "Status": "FAILED",
        "SecurityControlId": "ECR.1"
    },
    "FindingProviderFields": {
        "Severity": {
            "Label": "MEDIUM",
            "Original": "MEDIUM"
        },
        "Types": [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
    }
}

# Base ECR.2 finding for repository tag immutability
ECR2_BASE_FINDING = {
    "SchemaVersion": "2018-10-08",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789013",
    "GeneratorId": "aws/securityhub",
    "AwsAccountId": "123456789012",
    "CreatedAt": datetime.now(timezone.utc).isoformat(),
    "UpdatedAt": datetime.now(timezone.utc).isoformat(),
    "Severity": {
        "Label": "MEDIUM",
        "Normalized": 40
    },
    "Title": "ECR.2 ECR repositories should have tag mutability configured as immutable",
    "Description": "This control checks whether a repository has tag mutability configured as immutable.",
    "Remediation": {
        "Recommendation": {
            "Text": "Configure ECR repositories to use immutable tags.",
            "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"
        }
    },
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "Resources": [
        {
            "Type": "AwsEcrRepository",
            "Id": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
            "Partition": "aws",
            "Region": "us-east-1",
            "Details": {
                "AwsEcrRepository": {
                    "Name": "test-repo",
                    "ImageTagMutability": "MUTABLE",
                    "RegistryId": "123456789012"
                }
            }
        }
    ],
    "WorkflowState": "NEW",
    "Workflow": {
        "Status": "NEW"
    },
    "Compliance": {
        "Status": "FAILED",
        "SecurityControlId": "ECR.2"
    },
    "FindingProviderFields": {
        "Severity": {
            "Label": "MEDIUM",
            "Original": "MEDIUM"
        },
        "Types": [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
    }
}

# Base ECR.3 finding for repository lifecycle policy
ECR3_BASE_FINDING = {
    "SchemaVersion": "2018-10-08",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789014",
    "GeneratorId": "aws/securityhub",
    "AwsAccountId": "123456789012",
    "CreatedAt": datetime.now(timezone.utc).isoformat(),
    "UpdatedAt": datetime.now(timezone.utc).isoformat(),
    "Severity": {
        "Label": "MEDIUM",
        "Normalized": 40
    },
    "Title": "ECR.3 ECR repositories should have at least one lifecycle policy configured",
    "Description": "This control checks whether a repository has at least one lifecycle policy configured.",
    "Remediation": {
        "Recommendation": {
            "Text": "Configure lifecycle policies for ECR repositories to manage image retention.",
            "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html"
        }
    },
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "Resources": [
        {
            "Type": "AwsEcrRepository",
            "Id": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
            "Partition": "aws",
            "Region": "us-east-1",
            "Details": {
                "AwsEcrRepository": {
                    "Name": "test-repo",
                    "RegistryId": "123456789012",
                    "ImageTagMutability": "MUTABLE"
                }
            }
        }
    ],
    "WorkflowState": "NEW",
    "Workflow": {
        "Status": "NEW"
    },
    "Compliance": {
        "Status": "FAILED",
        "SecurityControlId": "ECR.3"
    },
    "FindingProviderFields": {
        "Severity": {
            "Label": "MEDIUM",
            "Original": "MEDIUM"
        },
        "Types": [
            "Software and Configuration Checks/AWS Security Best Practices"
        ]
    }
}

def get_ecr1_finding_standard():
    """ECR.1 finding for standard registry scanning configuration."""
    finding = copy.deepcopy(ECR1_BASE_FINDING)
    return {'finding': finding}

def get_ecr1_finding_cross_account():
    """ECR.1 finding for cross-account registry scanning."""
    finding = copy.deepcopy(ECR1_BASE_FINDING)
    finding['AwsAccountId'] = '555666777888'
    finding['Id'] = "arn:aws:securityhub:us-east-1:555666777888:finding/12345678-1234-1234-1234-123456789015"
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-east-1:555666777888:repository/cross-account-repo"
    finding['Resources'][0]['Details']['AwsEcrContainerImage']['Name'] = 'cross-account-repo'
    finding['Resources'][0]['Details']['AwsEcrContainerImage']['RepositoryName'] = 'cross-account-repo'
    finding['Resources'][0]['Details']['AwsEcrContainerImage']['RegistryId'] = '555666777888'
    return {'finding': finding}

def get_ecr1_finding_different_region():
    """ECR.1 finding for registry scanning in different region (us-west-2)."""
    finding = copy.deepcopy(ECR1_BASE_FINDING)
    finding['Region'] = 'us-west-2'
    finding['Id'] = "arn:aws:securityhub:us-west-2:123456789012:finding/12345678-1234-1234-1234-123456789016"
    finding['Resources'][0]['Region'] = 'us-west-2'
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-west-2:123456789012:repository/west-repo"
    finding['Resources'][0]['Details']['AwsEcrContainerImage']['Name'] = 'west-repo'
    finding['Resources'][0]['Details']['AwsEcrContainerImage']['RepositoryName'] = 'west-repo'
    return {'finding': finding}

def get_ecr2_finding_standard():
    """ECR.2 finding for standard repository tag immutability configuration."""
    finding = copy.deepcopy(ECR2_BASE_FINDING)
    return {'finding': finding}

def get_ecr2_finding_cross_account():
    """ECR.2 finding for cross-account repository tag immutability."""
    finding = copy.deepcopy(ECR2_BASE_FINDING)
    finding['AwsAccountId'] = '555666777888'
    finding['Id'] = "arn:aws:securityhub:us-east-1:555666777888:finding/12345678-1234-1234-1234-123456789017"
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-east-1:555666777888:repository/cross-account-repo"
    finding['Resources'][0]['Details']['AwsEcrRepository']['Name'] = 'cross-account-repo'
    finding['Resources'][0]['Details']['AwsEcrRepository']['RegistryId'] = '555666777888'
    return {'finding': finding}

def get_ecr2_finding_with_slash_in_name():
    """ECR.2 finding for repository with slash in name (namespace/repo)."""
    finding = copy.deepcopy(ECR2_BASE_FINDING)
    finding['Id'] = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789018"
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-east-1:123456789012:repository/namespace/my-app"
    finding['Resources'][0]['Details']['AwsEcrRepository']['Name'] = 'namespace/my-app'
    return {'finding': finding}

def get_ecr2_finding_complex_name():
    """ECR.2 finding for repository with complex naming pattern."""
    finding = copy.deepcopy(ECR2_BASE_FINDING)
    finding['Id'] = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789019"
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-east-1:123456789012:repository/org/team/service-name"
    finding['Resources'][0]['Details']['AwsEcrRepository']['Name'] = 'org/team/service-name'
    return {'finding': finding}

def get_ecr3_finding_standard():
    """ECR.3 finding for standard repository lifecycle policy configuration."""
    finding = copy.deepcopy(ECR3_BASE_FINDING)
    return {'finding': finding}

def get_ecr3_finding_cross_account():
    """ECR.3 finding for cross-account repository lifecycle policy."""
    finding = copy.deepcopy(ECR3_BASE_FINDING)
    finding['AwsAccountId'] = '555666777888'
    finding['Id'] = "arn:aws:securityhub:us-east-1:555666777888:finding/12345678-1234-1234-1234-123456789020"
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-east-1:555666777888:repository/cross-account-repo"
    finding['Resources'][0]['Details']['AwsEcrRepository']['Name'] = 'cross-account-repo'
    finding['Resources'][0]['Details']['AwsEcrRepository']['RegistryId'] = '555666777888'
    return {'finding': finding}

def get_ecr3_finding_with_slash_in_name():
    """ECR.3 finding for repository with slash in name (namespace/repo)."""
    finding = copy.deepcopy(ECR3_BASE_FINDING)
    finding['Id'] = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789021"
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-east-1:123456789012:repository/namespace/my-service"
    finding['Resources'][0]['Details']['AwsEcrRepository']['Name'] = 'namespace/my-service'
    return {'finding': finding}

def get_ecr3_finding_different_region():
    """ECR.3 finding for repository lifecycle policy in different region (us-west-2)."""
    finding = copy.deepcopy(ECR3_BASE_FINDING)
    finding['Region'] = 'us-west-2'
    finding['Id'] = "arn:aws:securityhub:us-west-2:123456789012:finding/12345678-1234-1234-1234-123456789022"
    finding['Resources'][0]['Region'] = 'us-west-2'
    finding['Resources'][0]['Id'] = "arn:aws:ecr:us-west-2:123456789012:repository/west-service"
    finding['Resources'][0]['Details']['AwsEcrRepository']['Name'] = 'west-service'
    return {'finding': finding}

# Comprehensive test scenarios for each ECR control
ECR_FINDINGS = {
    # ECR.1 scenarios
    'ecr1_standard': get_ecr1_finding_standard(),
    'ecr1_cross_account': get_ecr1_finding_cross_account(),
    'ecr1_different_region': get_ecr1_finding_different_region(),
    
    # ECR.2 scenarios  
    'ecr2_standard': get_ecr2_finding_standard(),
    'ecr2_cross_account': get_ecr2_finding_cross_account(),
    'ecr2_with_slash_in_name': get_ecr2_finding_with_slash_in_name(),
    'ecr2_complex_name': get_ecr2_finding_complex_name(),
    
    # ECR.3 scenarios
    'ecr3_standard': get_ecr3_finding_standard(),
    'ecr3_cross_account': get_ecr3_finding_cross_account(),
    'ecr3_with_slash_in_name': get_ecr3_finding_with_slash_in_name(),
    'ecr3_different_region': get_ecr3_finding_different_region()
}