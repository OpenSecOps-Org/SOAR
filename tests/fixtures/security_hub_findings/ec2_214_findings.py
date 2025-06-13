"""
Sample Security Hub findings for EC2.14 testing (RDP Security Group Rules)
"""

def get_ec214_rdp_open_finding():
    """Mock Security Hub finding for EC2.14 control - security group with 0.0.0.0/0 on RDP port 3389"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-14-rdp-open',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Description': 'This control checks whether security groups allow unrestricted incoming traffic on port 3389.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdp1234567890',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-rdp1234567890',
                        'GroupName': 'test-rdp-open-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
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

def get_ec214_rdp_mixed_finding():
    """Mock Security Hub finding for EC2.14 - security group with 0.0.0.0/0 and specific IPs on RDP"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-14-rdp-mixed',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdpmixed12345',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-rdpmixed12345',
                        'GroupName': 'test-rdp-mixed-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
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

def get_ec214_rdp_secure_finding():
    """Mock Security Hub finding for EC2.14 - security group without 0.0.0.0/0 on RDP (should not trigger)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-14-rdp-secure',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdpsecure1234',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-rdpsecure1234',
                        'GroupName': 'test-rdp-secure-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
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

def get_ec214_all_protocols_finding():
    """Mock Security Hub finding for EC2.14 - security group with protocol -1 (all) and 0.0.0.0/0"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-14-all-protocols',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdpallproto12',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-rdpallproto12',
                        'GroupName': 'test-rdp-all-protocols-sg',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }

def get_ec214_missing_details_finding():
    """Mock Security Hub finding for EC2.14 - missing security group details (should suppress)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-14-missing-details',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdpnodetails1',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup'
            }]
        }
    }

def get_ec214_cross_account_finding():
    """Mock Security Hub finding for EC2.14 - cross-account security group"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-14-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:security-group/sg-rdpcross12345',
                'Region': 'us-west-2',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-rdpcross12345',
                        'GroupName': 'test-rdp-cross-account-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }

def get_ec214_ipv6_finding():
    """Mock Security Hub finding for EC2.14 - security group with IPv6 ::/0 on RDP port"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-14-ipv6',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.14 Security groups should not allow ingress from 0.0.0.0/0 to port 3389',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdpipv6123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-rdpipv6123456',
                        'GroupName': 'test-rdp-ipv6-sg',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
                            'IpRanges': [{'CidrIp': '10.0.0.0/8'}],
                            'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
                        }]
                    }
                }
            }]
        }
    }