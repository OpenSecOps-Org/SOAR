"""
Sample Security Hub findings for EC2.4 testing (Stopped EC2 Instance Termination)
"""

def get_ec24_stopped_instance_finding():
    """Mock Security Hub finding for EC2.4 control - stopped EC2 instance"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-4-stopped-instance',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.4 Stopped EC2 instances should be removed or restarted',
            'Description': 'This control checks whether EC2 instances have been stopped for more than the allowed time.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Instance',
                'Details': {
                    'AwsEc2Instance': {
                        'InstanceId': 'i-1234567890abcdef0',
                        'Type': 't3.micro',
                        'State': {
                            'Code': 80,
                            'Name': 'stopped'
                        },
                        'LaunchedAt': '2024-06-01T12:00:00Z',
                        'SubnetId': 'subnet-12345678',
                        'VpcId': 'vpc-12345678'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec24_stopped_instance_with_protection_finding():
    """Mock Security Hub finding for EC2.4 control - stopped instance with termination protection"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-4-protected-instance',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.4 Stopped EC2 instances should be removed or restarted',
            'Description': 'This control checks whether EC2 instances have been stopped for more than the allowed time.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-protectedinstance12',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Instance',
                'Details': {
                    'AwsEc2Instance': {
                        'InstanceId': 'i-protectedinstance12',
                        'Type': 't3.small',
                        'State': {
                            'Code': 80,
                            'Name': 'stopped'
                        },
                        'LaunchedAt': '2024-06-01T12:00:00Z',
                        'SubnetId': 'subnet-protected123',
                        'VpcId': 'vpc-protected123'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec24_cross_account_instance_finding():
    """Mock Security Hub finding for EC2.4 control - cross-account stopped instance"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-4-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.4 Stopped EC2 instances should be removed or restarted',
            'Description': 'This control checks whether EC2 instances have been stopped for more than the allowed time.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:instance/i-crossaccount1234',
                'Region': 'us-west-2',
                'Type': 'AwsEc2Instance',
                'Details': {
                    'AwsEc2Instance': {
                        'InstanceId': 'i-crossaccount1234',
                        'Type': 't3.medium',
                        'State': {
                            'Code': 80,
                            'Name': 'stopped'
                        },
                        'LaunchedAt': '2024-06-01T12:00:00Z',
                        'SubnetId': 'subnet-cross12345',
                        'VpcId': 'vpc-cross12345'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec24_error_handling_instance_finding():
    """Mock Security Hub finding for EC2.4 control - for error handling scenarios"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-4-error-test',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.4 Stopped EC2 instances should be removed or restarted',
            'Description': 'This control checks whether EC2 instances have been stopped for more than the allowed time.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-errortest1234567',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Instance',
                'Details': {
                    'AwsEc2Instance': {
                        'InstanceId': 'i-errortest1234567',
                        'Type': 't3.nano',
                        'State': {
                            'Code': 80,
                            'Name': 'stopped'
                        },
                        'LaunchedAt': '2024-06-01T12:00:00Z',
                        'SubnetId': 'subnet-error123',
                        'VpcId': 'vpc-error123'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec24_minimal_instance_finding():
    """Mock Security Hub finding for EC2.4 control - minimal instance data"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-4-minimal',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.4 Stopped EC2 instances should be removed or restarted',
            'Description': 'This control checks whether EC2 instances have been stopped for more than the allowed time.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-minimal123456',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Instance'
                # Minimal details for edge case testing
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec24_running_instance_finding():
    """Mock Security Hub finding for EC2.4 control - instance that's now running (edge case)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-4-running',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.4 Stopped EC2 instances should be removed or restarted',
            'Description': 'This control checks whether EC2 instances have been stopped for more than the allowed time.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-runningnow12345',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Instance',
                'Details': {
                    'AwsEc2Instance': {
                        'InstanceId': 'i-runningnow12345',
                        'Type': 't3.micro',
                        'State': {
                            'Code': 16,
                            'Name': 'running'
                        },
                        'LaunchedAt': '2024-06-01T12:00:00Z',
                        'SubnetId': 'subnet-running123',
                        'VpcId': 'vpc-running123'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }