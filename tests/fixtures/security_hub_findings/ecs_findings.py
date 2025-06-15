"""
ECS Security Hub finding fixtures for testing auto-remediation functions.

This module provides standardized ASFF (AWS Security Finding Format) test data
for ECS-related security controls including:

- ECS.12: Container Insights monitoring
- ECS.2: Public IP assignment controls

Test scenarios include:
- Standard cluster configurations
- Cross-account clusters
- Different regions
- Complex cluster naming patterns
- Error conditions (missing clusters, etc.)
"""

import copy

# Base ECS.12 finding for Container Insights
ECS12_BASE_FINDING = {
    "AwsAccountId": "123456789012",
    "CreatedAt": "2023-09-15T10:30:00.000Z",
    "Description": "This control checks whether ECS clusters have Container Insights enabled.",
    "GeneratorId": "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard/v/1.0.0/ECS.12",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0/ECS.12/finding/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Resources": [
        {
            "Id": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
            "Partition": "aws",
            "Region": "us-east-1",
            "Type": "AwsEcsCluster"
        }
    ],
    "SchemaVersion": "2018-10-08",
    "Severity": {
        "Label": "MEDIUM",
        "Normalized": 40,
        "Original": "MEDIUM"
    },
    "Title": "ECS clusters should have Container Insights enabled",
    "Type": "Software and Configuration Checks/AWS Security Best Practices",
    "UpdatedAt": "2023-09-15T10:30:00.000Z"
}

# Base ECS.2 finding for Public IP assignment
ECS2_BASE_FINDING = {
    "AwsAccountId": "123456789012",
    "CreatedAt": "2023-09-15T10:30:00.000Z",
    "Description": "This control checks whether Amazon ECS services are configured to assign public IP addresses.",
    "GeneratorId": "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard/v/1.0.0/ECS.2",
    "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0/ECS.2/finding/a1b2c3d4-5678-90ab-cdef-EXAMPLE22222",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Resources": [
        {
            "Id": "arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service",
            "Partition": "aws",
            "Region": "us-east-1",
            "Type": "AwsEcsService",
            "Details": {
                "AwsEcsService": {
                    "Cluster": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsVpcConfiguration": {
                            "AssignPublicIp": "ENABLED",
                            "SecurityGroups": [
                                "sg-12345678",
                                "sg-87654321"
                            ],
                            "Subnets": [
                                "subnet-abc12345",
                                "subnet-def67890"
                            ]
                        }
                    },
                    "ServiceName": "test-service"
                }
            }
        }
    ],
    "SchemaVersion": "2018-10-08",
    "Severity": {
        "Label": "HIGH",
        "Normalized": 70,
        "Original": "HIGH"
    },
    "Title": "ECS services should not have public IP addresses assigned automatically",
    "Type": "Software and Configuration Checks/AWS Security Best Practices",
    "UpdatedAt": "2023-09-15T10:30:00.000Z"
}


def get_ecs12_finding_standard():
    """Standard ECS.12 finding for Container Insights testing."""
    return {'finding': copy.deepcopy(ECS12_BASE_FINDING)}


def get_ecs12_finding_cross_account():
    """ECS.12 finding for cross-account testing."""
    finding = copy.deepcopy(ECS12_BASE_FINDING)
    finding['AwsAccountId'] = "555666777888"
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-east-1:555666777888:cluster/cross-account-cluster"
    return {'finding': finding}


def get_ecs12_finding_different_region():
    """ECS.12 finding for different region testing."""
    finding = copy.deepcopy(ECS12_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-west-2:123456789012:cluster/west-cluster"
    finding['Resources'][0]['Region'] = "us-west-2"
    return {'finding': finding}


def get_ecs12_finding_complex_name():
    """ECS.12 finding with complex cluster naming pattern."""
    finding = copy.deepcopy(ECS12_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-east-1:123456789012:cluster/production-microservices-cluster-v2"
    return {'finding': finding}


def get_ecs12_finding_with_hyphens():
    """ECS.12 finding with hyphenated cluster name."""
    finding = copy.deepcopy(ECS12_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-east-1:123456789012:cluster/my-application-cluster"
    return {'finding': finding}


def get_ecs2_finding_standard():
    """Standard ECS.2 finding for public IP testing."""
    return {'finding': copy.deepcopy(ECS2_BASE_FINDING)}


def get_ecs2_finding_cross_account():
    """ECS.2 finding for cross-account testing."""
    finding = copy.deepcopy(ECS2_BASE_FINDING)
    finding['AwsAccountId'] = "555666777888"
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-east-1:555666777888:service/cross-cluster/cross-service"
    finding['Resources'][0]['Details']['AwsEcsService']['Cluster'] = "arn:aws:ecs:us-east-1:555666777888:cluster/cross-cluster"
    finding['Resources'][0]['Details']['AwsEcsService']['ServiceName'] = "cross-service"
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['SecurityGroups'] = ["sg-cross123", "sg-cross456"]
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['Subnets'] = ["subnet-cross789", "subnet-cross012"]
    return {'finding': finding}


def get_ecs2_finding_different_region():
    """ECS.2 finding for different region testing."""
    finding = copy.deepcopy(ECS2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-west-2:123456789012:service/west-cluster/west-service"
    finding['Resources'][0]['Region'] = "us-west-2"
    finding['Resources'][0]['Details']['AwsEcsService']['Cluster'] = "arn:aws:ecs:us-west-2:123456789012:cluster/west-cluster"
    finding['Resources'][0]['Details']['AwsEcsService']['ServiceName'] = "west-service"
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['SecurityGroups'] = ["sg-west123", "sg-west456"]
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['Subnets'] = ["subnet-west789", "subnet-west012"]
    return {'finding': finding}


def get_ecs2_finding_complex_names():
    """ECS.2 finding with complex cluster and service names."""
    finding = copy.deepcopy(ECS2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-east-1:123456789012:service/production-cluster/web-application-service"
    finding['Resources'][0]['Details']['AwsEcsService']['Cluster'] = "arn:aws:ecs:us-east-1:123456789012:cluster/production-cluster"
    finding['Resources'][0]['Details']['AwsEcsService']['ServiceName'] = "web-application-service"
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['SecurityGroups'] = ["sg-prod123", "sg-prod456"]
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['Subnets'] = ["subnet-prod789", "subnet-prod012"]
    return {'finding': finding}


def get_ecs2_finding_with_hyphens():
    """ECS.2 finding with hyphenated names."""
    finding = copy.deepcopy(ECS2_BASE_FINDING)
    finding['Resources'][0]['Id'] = "arn:aws:ecs:us-east-1:123456789012:service/my-cluster/my-web-service"
    finding['Resources'][0]['Details']['AwsEcsService']['Cluster'] = "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster"
    finding['Resources'][0]['Details']['AwsEcsService']['ServiceName'] = "my-web-service"
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['SecurityGroups'] = ["sg-mycluster1", "sg-mycluster2"]
    finding['Resources'][0]['Details']['AwsEcsService']['NetworkConfiguration']['AwsVpcConfiguration']['Subnets'] = ["subnet-private1", "subnet-private2"]
    return {'finding': finding}


def get_ecs2_finding_missing_details():
    """ECS.2 finding with missing Details section for error testing."""
    finding = copy.deepcopy(ECS2_BASE_FINDING)
    # Remove the Details section to test error handling
    del finding['Resources'][0]['Details']
    return {'finding': finding}