"""
Sample Security Hub findings for EC2.12 testing (Unused Elastic IP Address Cleanup)
"""

def get_ec212_unused_eip_finding():
    """Mock Security Hub finding for EC2.12 control - unused EIP via ASFF Details"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-12-unused-eip',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.12 Unused EC2 EIPs should be removed',
            'Description': 'This control checks whether Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs).',
            'FirstObservedAt': '2024-01-01T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-12345678',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Eip',
                'Details': {
                    'AwsEc2Eip': {
                        'AllocationId': 'eipalloc-12345678',
                        'Domain': 'vpc',
                        'PublicIp': '203.0.113.12',
                        'AssociationId': None,
                        'InstanceId': None,
                        'NetworkInterfaceId': None
                    }
                }
            }],
            'ProductFields': {
                'Resources:0/Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-12345678'
            },
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec212_unused_eip_old_finding():
    """Mock Security Hub finding for EC2.12 control - unused EIP older than 30 days"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-12-unused-eip-old',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.12 Unused EC2 EIPs should be removed',
            'Description': 'This control checks whether Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs).',
            'FirstObservedAt': '2023-01-01T00:00:00Z',  # Old enough for remediation
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-87654321',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Eip',
                'Details': {
                    'AwsEc2Eip': {
                        'AllocationId': 'eipalloc-87654321',
                        'Domain': 'vpc',
                        'PublicIp': '203.0.113.21',
                        'AssociationId': None,
                        'InstanceId': None,
                        'NetworkInterfaceId': None
                    }
                }
            }],
            'ProductFields': {
                'Resources:0/Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-87654321'
            },
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec212_eip_no_details_finding():
    """Mock Security Hub finding for EC2.12 control - EIP without ASFF Details"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-12-eip-no-details',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.12 Unused EC2 EIPs should be removed',
            'Description': 'This control checks whether Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs).',
            'FirstObservedAt': '2023-01-01T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-nodetails123',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Eip'
                # No Details section
            }],
            'ProductFields': {
                'Resources:0/Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-nodetails123'
            }
        }
    }

def get_ec212_eip_product_fields_only_finding():
    """Mock Security Hub finding for EC2.12 control - EIP via ProductFields only"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-12-eip-product-fields',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.12 Unused EC2 EIPs should be removed',
            'Description': 'This control checks whether Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs).',
            'FirstObservedAt': '2023-01-01T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-prodfields456',
                'Region': 'us-east-1',
                'Type': 'NotAwsEc2Eip'  # Different type to force ProductFields path
            }],
            'ProductFields': {
                'Resources:0/Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-prodfields456'
            }
        }
    }

def get_ec212_eip_cross_account_finding():
    """Mock Security Hub finding for EC2.12 control - cross-account EIP"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-12-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.12 Unused EC2 EIPs should be removed',
            'Description': 'This control checks whether Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs).',
            'FirstObservedAt': '2023-01-01T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:eip/eipalloc-cross12345',
                'Region': 'us-west-2',
                'Type': 'AwsEc2Eip',
                'Details': {
                    'AwsEc2Eip': {
                        'AllocationId': 'eipalloc-cross12345',
                        'Domain': 'vpc',
                        'PublicIp': '198.51.100.42',
                        'AssociationId': None,
                        'InstanceId': None,
                        'NetworkInterfaceId': None
                    }
                }
            }],
            'ProductFields': {
                'Resources:0/Id': 'arn:aws:ec2:us-west-2:987654321098:eip/eipalloc-cross12345'
            }
        }
    }

def get_ec212_eip_error_handling_finding():
    """Mock Security Hub finding for EC2.12 control - for error handling scenarios"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-12-error-test',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.12 Unused EC2 EIPs should be removed',
            'Description': 'This control checks whether Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs).',
            'FirstObservedAt': '2023-01-01T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-errortest123',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Eip',
                'Details': {
                    'AwsEc2Eip': {
                        'AllocationId': 'eipalloc-errortest123',
                        'Domain': 'vpc',
                        'PublicIp': '203.0.113.99',
                        'AssociationId': None,
                        'InstanceId': None,
                        'NetworkInterfaceId': None
                    }
                }
            }],
            'ProductFields': {
                'Resources:0/Id': 'arn:aws:ec2:us-east-1:123456789012:eip/eipalloc-errortest123'
            }
        }
    }