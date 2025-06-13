"""
Sample Security Hub findings for EC2.7 testing (EBS Default Encryption Enable)
"""

def get_ec27_ebs_encryption_disabled_finding():
    """Mock Security Hub finding for EC2.7 control - EBS default encryption disabled"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-7-ebs-encryption',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.7 EBS default encryption should be enabled',
            'Description': 'This control checks whether Amazon Elastic Block Store (Amazon EBS) encryption is enabled by default.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:ebs-encryption-by-default',
                'Region': 'us-east-1',
                'Type': 'AwsAccount',
                'Details': {
                    'Other': {
                        'EbsEncryptionByDefault': 'false'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec27_cross_account_finding():
    """Mock Security Hub finding for EC2.7 control - cross-account EBS encryption"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:987654321098:finding/ec2-7-cross-account',
            'AwsAccountId': '987654321098',
            'Title': 'EC2.7 EBS default encryption should be enabled',
            'Description': 'This control checks whether Amazon Elastic Block Store (Amazon EBS) encryption is enabled by default.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-west-2:987654321098:ebs-encryption-by-default',
                'Region': 'us-west-2',
                'Type': 'AwsAccount',
                'Details': {
                    'Other': {
                        'EbsEncryptionByDefault': 'false'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec27_error_handling_finding():
    """Mock Security Hub finding for EC2.7 control - for error handling scenarios"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-7-error-test',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.7 EBS default encryption should be enabled',
            'Description': 'This control checks whether Amazon Elastic Block Store (Amazon EBS) encryption is enabled by default.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:ebs-encryption-by-default',
                'Region': 'us-east-1',
                'Type': 'AwsAccount',
                'Details': {
                    'Other': {
                        'EbsEncryptionByDefault': 'false'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec27_minimal_finding():
    """Mock Security Hub finding for EC2.7 control - minimal data"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-7-minimal',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.7 EBS default encryption should be enabled',
            'Description': 'This control checks whether Amazon Elastic Block Store (Amazon EBS) encryption is enabled by default.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:ebs-encryption-by-default',
                'Region': 'us-east-1',
                'Type': 'AwsAccount'
                # Minimal details for edge case testing
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec27_different_region_finding():
    """Mock Security Hub finding for EC2.7 control - different region"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:eu-west-1:123456789012:finding/ec2-7-eu-west',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.7 EBS default encryption should be enabled',
            'Description': 'This control checks whether Amazon Elastic Block Store (Amazon EBS) encryption is enabled by default.',
            'Resources': [{
                'Id': 'arn:aws:ec2:eu-west-1:123456789012:ebs-encryption-by-default',
                'Region': 'eu-west-1',
                'Type': 'AwsAccount',
                'Details': {
                    'Other': {
                        'EbsEncryptionByDefault': 'false'
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }

def get_ec27_already_enabled_finding():
    """Mock Security Hub finding for EC2.7 control - encryption already enabled (edge case)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/ec2-7-already-enabled',
            'AwsAccountId': '123456789012',
            'Title': 'EC2.7 EBS default encryption should be enabled',
            'Description': 'This control checks whether Amazon Elastic Block Store (Amazon EBS) encryption is enabled by default.',
            'Resources': [{
                'Id': 'arn:aws:ec2:us-east-1:123456789012:ebs-encryption-by-default',
                'Region': 'us-east-1',
                'Type': 'AwsAccount',
                'Details': {
                    'Other': {
                        'EbsEncryptionByDefault': 'true'  # Already enabled
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'  # Still failed in finding (stale data)
            }
        }
    }