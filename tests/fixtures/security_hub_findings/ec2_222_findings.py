"""
Sample Security Hub findings for EC2.22 testing (Unused Security Group Cleanup)
"""

def get_ec222_unused_sg_finding():
    """Mock Security Hub finding for EC2.22 control - unused security group (recent)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-22-unused-sg',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.22 Unused security groups should be removed',
            'Description': 'This control checks whether security groups that are not attached to any instances or network interfaces are removed.',
            'FirstObservedAt': '2024-06-12T00:00:00Z',  # Recent finding
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-12345678',
                        'GroupName': 'unused-test-sg',
                        'VpcId': 'vpc-12345678',
                        'Description': 'Test unused security group',
                        'IpPermissions': [],
                        'IpPermissionsEgress': []
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec222_unused_sg_old_finding():
    """Mock Security Hub finding for EC2.22 control - unused security group (old enough for remediation)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-22-unused-sg-old',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.22 Unused security groups should be removed',
            'Description': 'This control checks whether security groups that are not attached to any instances or network interfaces are removed.',
            'FirstObservedAt': '2024-06-10T00:00:00Z',  # Old enough for remediation
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-87654321',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-87654321',
                        'GroupName': 'old-unused-sg',
                        'VpcId': 'vpc-87654321',
                        'Description': 'Old unused security group ready for deletion',
                        'IpPermissions': [],
                        'IpPermissionsEgress': []
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec222_sg_cross_account_finding():
    """Mock Security Hub finding for EC2.22 control - cross-account security group"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-22-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.22 Unused security groups should be removed',
            'Description': 'This control checks whether security groups that are not attached to any instances or network interfaces are removed.',
            'FirstObservedAt': '2024-06-10T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:security-group/sg-cross12345',
                'Region': 'us-west-2',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-cross12345',
                        'GroupName': 'cross-account-unused-sg',
                        'VpcId': 'vpc-cross12345',
                        'Description': 'Cross-account unused security group',
                        'IpPermissions': [],
                        'IpPermissionsEgress': []
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec222_sg_error_handling_finding():
    """Mock Security Hub finding for EC2.22 control - for error handling scenarios"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-22-error-test',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.22 Unused security groups should be removed',
            'Description': 'This control checks whether security groups that are not attached to any instances or network interfaces are removed.',
            'FirstObservedAt': '2024-06-10T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-errortest123',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-errortest123',
                        'GroupName': 'error-test-sg',
                        'VpcId': 'vpc-errortest123',
                        'Description': 'Security group for error testing scenarios',
                        'IpPermissions': [],
                        'IpPermissionsEgress': []
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec222_sg_with_rules_finding():
    """Mock Security Hub finding for EC2.22 control - security group with rules"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-22-sg-with-rules',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.22 Unused security groups should be removed',
            'Description': 'This control checks whether security groups that are not attached to any instances or network interfaces are removed.',
            'FirstObservedAt': '2024-06-10T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-withrules123',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup',
                'Details': {
                    'AwsEc2SecurityGroup': {
                        'GroupId': 'sg-withrules123',
                        'GroupName': 'sg-with-rules',
                        'VpcId': 'vpc-withrules123',
                        'Description': 'Security group with inbound and outbound rules',
                        'IpPermissions': [{
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
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

def get_ec222_sg_minimal_finding():
    """Mock Security Hub finding for EC2.22 control - minimal security group data"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-22-minimal',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.22 Unused security groups should be removed',
            'Description': 'This control checks whether security groups that are not attached to any instances or network interfaces are removed.',
            'FirstObservedAt': '2024-06-10T00:00:00Z',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-minimal123',
                'Region': 'us-east-1',
                'Type': 'AwsEc2SecurityGroup'
                # Minimal details for edge case testing
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }