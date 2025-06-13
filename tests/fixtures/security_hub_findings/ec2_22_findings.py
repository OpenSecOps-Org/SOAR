"""
Sample Security Hub findings for EC2.2 testing (Default Security Group Rules)
"""

def get_ec22_default_sg_pristine_finding():
    """Mock Security Hub finding for EC2.2 control - default security group with pristine rules"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-default-sg-pristine',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Description': 'This control checks that the default security group does not allow inbound or outbound traffic.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-default123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-default123456',
                        'GroupName': 'default',
                        'OwnerId': '123456789012',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'UserIdGroupPairs': [{
                                'GroupId': 'sg-default123456',
                                'UserId': '123456789012'
                            }]
                        }],
                        'IpPermissionsEgress': [{
                            'IpProtocol': '-1',
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

def get_ec22_default_sg_in_use_finding():
    """Mock Security Hub finding for EC2.2 control - default security group in use by instances"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-default-sg-in-use',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-inuse123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-inuse123456',
                        'GroupName': 'default',
                        'OwnerId': '123456789012',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'UserIdGroupPairs': [{
                                'GroupId': 'sg-inuse123456',
                                'UserId': '123456789012'
                            }]
                        }],
                        'IpPermissionsEgress': [{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }

def get_ec22_default_sg_modified_finding():
    """Mock Security Hub finding for EC2.2 control - default security group with modified rules"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-default-sg-modified',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-modified123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-modified123456',
                        'GroupName': 'default',
                        'OwnerId': '123456789012',
                        'IpPermissions': [
                            {
                                'IpProtocol': '-1',
                                'UserIdGroupPairs': [{
                                    'GroupId': 'sg-modified123456',
                                    'UserId': '123456789012'
                                }]
                            },
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 80,
                                'ToPort': 80,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }
                        ],
                        'IpPermissionsEgress': [{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }

def get_ec22_default_sg_no_rules_finding():
    """Mock Security Hub finding for EC2.2 control - default security group with no rules (already clean)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-default-sg-no-rules',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-norules123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-norules123456',
                        'GroupName': 'default',
                        'OwnerId': '123456789012',
                        'IpPermissions': [],
                        'IpPermissionsEgress': []
                    }
                }
            }]
        }
    }

def get_ec22_default_sg_missing_details_finding():
    """Mock Security Hub finding for EC2.2 control - missing security group details"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-missing-details',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-nodetails12345',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup'
            }]
        }
    }

def get_ec22_default_sg_cross_account_finding():
    """Mock Security Hub finding for EC2.2 control - cross-account default security group"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-2-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:security-group/sg-cross123456789',
                'Region': 'us-west-2',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-cross123456789',
                        'GroupName': 'default',
                        'OwnerId': '987654321098',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'UserIdGroupPairs': [{
                                'GroupId': 'sg-cross123456789',
                                'UserId': '987654321098'
                            }]
                        }],
                        'IpPermissionsEgress': [{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }

def get_ec22_default_sg_egress_modified_finding():
    """Mock Security Hub finding for EC2.2 control - default security group with modified egress rules"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-egress-modified',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-egressmod12345',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-egressmod12345',
                        'GroupName': 'default',
                        'OwnerId': '123456789012',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'UserIdGroupPairs': [{
                                'GroupId': 'sg-egressmod12345',
                                'UserId': '123456789012'
                            }]
                        }],
                        'IpPermissionsEgress': [
                            {
                                'IpProtocol': '-1',
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            },
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 443,
                                'ToPort': 443,
                                'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
                            }
                        ]
                    }
                }
            }]
        }
    }

def get_ec22_default_sg_partial_failure_finding():
    """Mock Security Hub finding for EC2.2 control - scenario where only one rule type can be removed"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-2-partial-failure',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.2 VPC default security group should not allow inbound and outbound traffic',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-partial123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-partial123456',
                        'GroupName': 'default',
                        'OwnerId': '123456789012',
                        'IpPermissions': [{
                            'IpProtocol': '-1',
                            'UserIdGroupPairs': [{
                                'GroupId': 'sg-partial123456',
                                'UserId': '123456789012'
                            }]
                        }],
                        'IpPermissionsEgress': [{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    }
                }
            }]
        }
    }