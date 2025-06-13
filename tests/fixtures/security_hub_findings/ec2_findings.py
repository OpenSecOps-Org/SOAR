"""
Sample Security Hub findings for EC2 testing
"""

def get_ec26_vpc_finding():
    """Mock Security Hub finding for EC2.6 control (VPC flow logging should be enabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-6-vpc-flow-logs',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.6 VPC flow logging should be enabled in all VPCs',
            'Description': 'This control checks whether Amazon VPC Flow Logs are found and enabled for VPCs.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1234567890abcdef0',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Vpc',
                'Details': {
                    'AwsEc2Vpc': {
                        'VpcId': 'vpc-1234567890abcdef0',
                        'State': 'available',
                        'CidrBlockAssociationSet': [
                            {
                                'CidrBlock': '10.0.0.0/16',
                                'CidrBlockState': 'associated'
                            }
                        ]
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec26_cross_account_vpc_finding():
    """Mock Security Hub finding for EC2.6 control with different account ID"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-6-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.6 VPC flow logging should be enabled in all VPCs',
            'Description': 'This control checks whether Amazon VPC Flow Logs are found and enabled for VPCs.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:vpc/vpc-9876543210fedcba0',
                'Region': 'us-west-2',
                'Type': 'AwsEc2Vpc',
                'Details': {
                    'AwsEc2Vpc': {
                        'VpcId': 'vpc-9876543210fedcba0',
                        'State': 'available'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec26_malformed_vpc_arn_finding():
    """Mock Security Hub finding with malformed VPC ARN"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-6-malformed',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.6 VPC flow logging should be enabled in all VPCs',
            'Resources': [{
                'Id': 'invalid-vpc-arn-format',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Vpc',
                'Details': {
                    'AwsEc2Vpc': {
                        'VpcId': 'vpc-invalid',
                        'State': 'available'
                    }
                }
            }]
        }
    }

def get_ec26_missing_vpc_resource_finding():
    """Mock Security Hub finding with missing VPC resource"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-6-missing-resource',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.6 VPC flow logging should be enabled in all VPCs',
            'Resources': []
        }
    }

def get_ec26_missing_region_finding():
    """Mock Security Hub finding with missing region"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-6-missing-region',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.6 VPC flow logging should be enabled in all VPCs',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1234567890abcdef0',
                'Type': 'AwsEc2Vpc',
                'Details': {
                    'AwsEc2Vpc': {
                        'VpcId': 'vpc-1234567890abcdef0',
                        'State': 'available'
                    }
                }
            }]
        }
    }

# EC2.13 Control Findings - SSH Security Group Rules

def get_ec213_ssh_open_finding():
    """Mock Security Hub finding for EC2.13 control - security group with 0.0.0.0/0 on SSH port 22"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-13-ssh-open',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Description': 'This control checks whether security groups allow unrestricted incoming traffic on port 22.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-1234567890abcdef0',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-1234567890abcdef0',
                        'GroupName': 'test-ssh-open-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec213_ssh_mixed_finding():
    """Mock Security Hub finding for EC2.13 - security group with 0.0.0.0/0 and specific IPs on SSH"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-13-ssh-mixed',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-mixed123456789',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-mixed123456789',
                        'GroupName': 'test-ssh-mixed-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'},
                                {'CidrIp': '10.0.0.0/8'},
                                {'CidrIp': '192.168.1.0/24'}
                            ]
                        }]
                    }
                }
            }]
        }
    }

def get_ec213_ssh_secure_finding():
    """Mock Security Hub finding for EC2.13 - security group without 0.0.0.0/0 on SSH (should not trigger)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-13-ssh-secure',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-secure1234567',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-secure1234567',
                        'GroupName': 'test-ssh-secure-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [
                                {'CidrIp': '10.0.0.0/8'},
                                {'CidrIp': '192.168.1.0/24'}
                            ]
                        }]
                    }
                }
            }]
        }
    }

def get_ec213_all_protocols_finding():
    """Mock Security Hub finding for EC2.13 - security group with protocol -1 (all) and 0.0.0.0/0"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-13-all-protocols',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-allproto12345',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-allproto12345',
                        'GroupName': 'test-all-protocols-sg',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }


def get_ec213_missing_details_finding():
    """Mock Security Hub finding for EC2.13 - missing security group details (should suppress)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-13-missing-details',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-nodetails1234',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup'
            }]
        }
    }

def get_ec213_cross_account_finding():
    """Mock Security Hub finding for EC2.13 - cross-account security group"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-13-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:security-group/sg-cross123456789',
                'Region': 'us-west-2',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-cross123456789',
                        'GroupName': 'test-cross-account-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }

def get_ec213_ipv6_finding():
    """Mock Security Hub finding for EC2.13 - security group with IPv6 ::/0 on SSH port"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-13-ipv6',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.13 Security groups should not allow ingress from 0.0.0.0/0 to port 22',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-ipv6123456789',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-ipv6123456789',
                        'GroupName': 'test-ipv6-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '10.0.0.0/8'}],
                            'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
                        }]
                    }
                }
            }]
        }
    }