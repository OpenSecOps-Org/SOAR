"""
Sample Security Hub findings for EC2.15 testing (VPC Subnets Public IP Auto-Assignment)
"""

def get_ec215_subnet_public_ip_assignment_finding():
    """Mock Security Hub finding for EC2.15 control - subnet with public IP auto-assignment enabled"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-15-subnet-public-ip',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.15 VPC subnets should not automatically assign public IP addresses',
            'Description': 'This control checks that VPC subnets do not automatically assign public IP addresses to instances launched within them.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:subnet/subnet-12345678',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Subnet',
                'Details': {
                    'AwsEc2Subnet': {
                        'SubnetId': 'subnet-12345678',
                        'VpcId': 'vpc-12345678',
                        'CidrBlock': '10.0.1.0/24',
                        'AvailabilityZone': 'us-east-1a',
                        'MapPublicIpOnLaunch': True
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec215_subnet_missing_details_finding():
    """Mock Security Hub finding for EC2.15 control - missing subnet details"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-15-missing-details',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.15 VPC subnets should not automatically assign public IP addresses',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:subnet/subnet-nodetails12345',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Subnet'
            }]
        }
    }

def get_ec215_subnet_cross_account_finding():
    """Mock Security Hub finding for EC2.15 control - cross-account subnet"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-15-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.15 VPC subnets should not automatically assign public IP addresses',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:subnet/subnet-cross12345',
                'Region': 'us-west-2',
                'Type': 'AwsEc2Subnet',
                'Details': {
                    'AwsEc2Subnet': {
                        'SubnetId': 'subnet-cross12345',
                        'VpcId': 'vpc-cross12345',
                        'CidrBlock': '172.16.1.0/24',
                        'AvailabilityZone': 'us-west-2a',
                        'MapPublicIpOnLaunch': True
                    }
                }
            }]
        }
    }

def get_ec215_subnet_error_handling_finding():
    """Mock Security Hub finding for EC2.15 control - error handling scenario"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-15-error-test',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.15 VPC subnets should not automatically assign public IP addresses',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:subnet/subnet-errortest123',
                'Region': 'us-east-1',
                'Type': 'AwsEc2Subnet',
                'Details': {
                    'AwsEc2Subnet': {
                        'SubnetId': 'subnet-errortest123',
                        'VpcId': 'vpc-errortest123',
                        'CidrBlock': '192.168.1.0/24',
                        'AvailabilityZone': 'us-east-1b',
                        'MapPublicIpOnLaunch': True
                    }
                }
            }]
        }
    }