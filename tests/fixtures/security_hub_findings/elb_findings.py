"""
Test fixtures for ELB (Elastic Load Balancer) Security Hub findings.

This module provides AWS Security Finding Format (ASFF) test data for:
- ELB.1: ALB HTTP to HTTPS redirection 
- ELB.4: ALB drop invalid HTTP headers
- ELB.5: ALB/CLB access logging

These fixtures support comprehensive testing of ELB auto-remediation functions
with various scenarios including internet-facing vs internal ALBs, different
resource states, and cross-account configurations.
"""

import copy
from datetime import datetime, timezone

# Base ELB.1 finding for ALB HTTP to HTTPS redirection
ELB1_BASE_FINDING = {
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
    "Title": "ELB.1 Application Load Balancer should be configured to redirect all HTTP requests to HTTPS",
    "Description": "This control checks whether HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers.",
    "Remediation": {
        "Recommendation": {
            "Text": "Configure HTTP to HTTPS redirection on all HTTP listeners.",
            "Url": "https://docs.aws.amazon.com/console/elasticloadbalancing/redirect-http-https"
        }
    },
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "Resources": [
        {
            "Type": "AwsElbv2LoadBalancer",
            "Id": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef",
            "Partition": "aws",
            "Region": "us-east-1",
            "Details": {
                "AwsElbv2LoadBalancer": {
                    "DNSName": "test-alb-123456789.us-east-1.elb.amazonaws.com",
                    "IpAddressType": "ipv4",
                    "Scheme": "internet-facing",
                    "State": {
                        "Code": "active"
                    },
                    "Type": "application",
                    "VpcId": "vpc-12345678"
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
        "SecurityControlId": "ELB.1"
    },
    "FindingProviderFields": {
        "Severity": {
            "Label": "MEDIUM",
            "Original": "MEDIUM"
        },
        "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
        ]
    }
}

# Base ELB.4 finding for ALB dropping invalid headers
ELB4_BASE_FINDING = {
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
    "Title": "ELB.4 Application Load Balancer should be configured to drop http headers",
    "Description": "This control checks whether an Application Load Balancer (ALB) is configured to drop invalid HTTP headers.",
    "Remediation": {
        "Recommendation": {
            "Text": "Configure the Application Load Balancer to drop invalid HTTP headers.",
            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes"
        }
    },
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "Resources": [
        {
            "Type": "AwsElbv2LoadBalancer",
            "Id": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef",
            "Partition": "aws",
            "Region": "us-east-1",
            "Details": {
                "AwsElbv2LoadBalancer": {
                    "DNSName": "test-alb-123456789.us-east-1.elb.amazonaws.com",
                    "IpAddressType": "ipv4",
                    "Scheme": "internet-facing",
                    "State": {
                        "Code": "active"
                    },
                    "Type": "application",
                    "VpcId": "vpc-12345678"
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
        "SecurityControlId": "ELB.4"
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

# Base ELB.5 finding for ALB/CLB access logging
ELB5_BASE_FINDING = {
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
    "Title": "ELB.5 Application and Classic Load Balancers logging should be enabled",
    "Description": "This control checks whether the Application Load Balancer and the Classic Load Balancer have logging enabled.",
    "Remediation": {
        "Recommendation": {
            "Text": "Enable access logging for Application Load Balancers and Classic Load Balancers.",
            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"
        }
    },
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "ProductName": "Security Hub",
    "CompanyName": "AWS",
    "Region": "us-east-1",
    "Resources": [
        {
            "Type": "AwsElbv2LoadBalancer",
            "Id": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890abcdef",
            "Partition": "aws",
            "Region": "us-east-1",
            "Details": {
                "AwsElbv2LoadBalancer": {
                    "DNSName": "test-alb-123456789.us-east-1.elb.amazonaws.com",
                    "IpAddressType": "ipv4",
                    "Scheme": "internet-facing",
                    "State": {
                        "Code": "active"
                    },
                    "Type": "application",
                    "VpcId": "vpc-12345678"
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
        "SecurityControlId": "ELB.5"
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

def get_elb1_finding_internet_facing():
    """ELB.1 finding for internet-facing ALB requiring HTTP to HTTPS redirection."""
    finding = copy.deepcopy(ELB1_BASE_FINDING)
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['Scheme'] = 'internet-facing'
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'internet-alb-123456789.us-east-1.elb.amazonaws.com'
    return {'finding': finding}

def get_elb1_finding_internal():
    """ELB.1 finding for internal ALB (should suppress finding)."""
    finding = copy.deepcopy(ELB1_BASE_FINDING)
    finding['Id'] = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789015"
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/internal-alb/1234567890abcdef"
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['Scheme'] = 'internal'
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'internal-alb-123456789.us-east-1.elb.amazonaws.com'
    return {'finding': finding}

def get_elb1_finding_cross_account():
    """ELB.1 finding for cross-account ALB."""
    finding = copy.deepcopy(ELB1_BASE_FINDING)
    finding['AwsAccountId'] = '555666777888'
    finding['Id'] = "arn:aws:securityhub:us-east-1:555666777888:finding/12345678-1234-1234-1234-123456789016"
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-east-1:555666777888:loadbalancer/app/cross-account-alb/1234567890abcdef"
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'cross-account-alb-123456789.us-east-1.elb.amazonaws.com'
    return {'finding': finding}

def get_elb4_finding_standard():
    """ELB.4 finding for standard ALB requiring header dropping configuration."""
    return {'finding': copy.deepcopy(ELB4_BASE_FINDING)}

def get_elb4_finding_cross_account():
    """ELB.4 finding for cross-account ALB."""
    finding = copy.deepcopy(ELB4_BASE_FINDING)
    finding['AwsAccountId'] = '555666777888'
    finding['Id'] = "arn:aws:securityhub:us-east-1:555666777888:finding/12345678-1234-1234-1234-123456789017"
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-east-1:555666777888:loadbalancer/app/cross-account-alb/1234567890abcdef"
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'cross-account-alb-123456789.us-east-1.elb.amazonaws.com'
    return {'finding': finding}

def get_elb4_finding_internal():
    """ELB.4 finding for internal ALB."""
    finding = copy.deepcopy(ELB4_BASE_FINDING)
    finding['Id'] = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789018"
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/internal-alb/1234567890abcdef"
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['Scheme'] = 'internal'
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'internal-alb-123456789.us-east-1.elb.amazonaws.com'
    return {'finding': finding}

def get_elb5_finding_application_lb():
    """ELB.5 finding for Application Load Balancer access logging."""
    return {'finding': copy.deepcopy(ELB5_BASE_FINDING)}

def get_elb5_finding_classic_lb():
    """ELB.5 finding for Classic Load Balancer access logging."""
    finding = copy.deepcopy(ELB5_BASE_FINDING)
    finding['Id'] = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789019"
    finding['Resources'][0]['Type'] = 'AwsElbLoadBalancer'
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/classic-lb-123456"
    finding['Resources'][0]['Details'] = {
        "AwsElbLoadBalancer": {
            "DNSName": "classic-lb-123456789.us-east-1.elb.amazonaws.com",
            "Scheme": "internet-facing",
            "VpcId": "vpc-12345678"
        }
    }
    return {'finding': finding}

def get_elb5_finding_cross_account():
    """ELB.5 finding for cross-account ALB."""
    finding = copy.deepcopy(ELB5_BASE_FINDING)
    finding['AwsAccountId'] = '555666777888'
    finding['Id'] = "arn:aws:securityhub:us-east-1:555666777888:finding/12345678-1234-1234-1234-123456789020"
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-east-1:555666777888:loadbalancer/app/cross-account-alb/1234567890abcdef"
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'cross-account-alb-123456789.us-east-1.elb.amazonaws.com'
    return {'finding': finding}

def get_elb5_finding_different_region():
    """ELB.5 finding for ALB in different region (us-west-2)."""
    finding = copy.deepcopy(ELB5_BASE_FINDING)
    finding['Region'] = 'us-west-2'
    finding['Id'] = "arn:aws:securityhub:us-west-2:123456789012:finding/12345678-1234-1234-1234-123456789021"
    finding['Resources'][0]['Region'] = 'us-west-2'
    finding['Resources'][0]['Id'] = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/west-alb/1234567890abcdef"
    finding['Resources'][0]['Details']['AwsElbv2LoadBalancer']['DNSName'] = 'west-alb-123456789.us-west-2.elb.amazonaws.com'
    return {'finding': finding}

# Comprehensive test scenarios for each ELB control
ELB_FINDINGS = {
    # ELB.1 scenarios
    'elb1_internet_facing': get_elb1_finding_internet_facing(),
    'elb1_internal': get_elb1_finding_internal(),
    'elb1_cross_account': get_elb1_finding_cross_account(),
    
    # ELB.4 scenarios  
    'elb4_standard': get_elb4_finding_standard(),
    'elb4_cross_account': get_elb4_finding_cross_account(),
    'elb4_internal': get_elb4_finding_internal(),
    
    # ELB.5 scenarios
    'elb5_application_lb': get_elb5_finding_application_lb(), 
    'elb5_classic_lb': get_elb5_finding_classic_lb(),
    'elb5_cross_account': get_elb5_finding_cross_account(),
    'elb5_different_region': get_elb5_finding_different_region()
}