"""
Sample Security Hub findings for S3 testing
"""

def get_s32_basic_finding():
    """Mock Security Hub finding for S3.2 control - bucket without public access block"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-2-basic-finding',
            'AwsAccountId': '123456789012',
            'Title': 'S3.2 S3 buckets should prohibit public access',
            'Description': 'This control checks whether S3 buckets have bucket-level public access blocks applied.',
            'Resources': [{
                'Id': 'arn:aws:s3:::test-bucket-no-public-block',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'test-bucket-no-public-block',
                        'OwnerId': '123456789012',
                        'PublicAccessBlockConfiguration': {
                            'BlockPublicAcls': False,
                            'BlockPublicPolicy': False,
                            'IgnorePublicAcls': False,
                            'RestrictPublicBuckets': False
                        }
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }


def get_s32_exemption_tag_finding():
    """Mock Security Hub finding for S3.2 control - bucket with exemption tag"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-2-exemption-tag-finding',
            'AwsAccountId': '123456789012',
            'Title': 'S3.2 S3 buckets should prohibit public access',
            'Resources': [{
                'Id': 'arn:aws:s3:::test-bucket-with-exemption-tag',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'test-bucket-with-exemption-tag',
                        'OwnerId': '123456789012',
                        'PublicAccessBlockConfiguration': {
                            'BlockPublicAcls': False,
                            'BlockPublicPolicy': False,
                            'IgnorePublicAcls': False,
                            'RestrictPublicBuckets': False
                        }
                    }
                }
            }]
        }
    }


def get_s32_cross_account_finding():
    """Mock Security Hub finding for S3.2 control - cross-account bucket"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:555666777888:finding/s3-2-cross-account-finding',
            'AwsAccountId': '555666777888',
            'Title': 'S3.2 S3 buckets should prohibit public access',
            'Resources': [{
                'Id': 'arn:aws:s3:::cross-account-test-bucket',
                'Region': 'us-west-2',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'cross-account-test-bucket',
                        'OwnerId': '555666777888'
                    }
                }
            }]
        }
    }


def get_s32_nonexistent_bucket_finding():
    """Mock Security Hub finding for S3.2 control - bucket that doesn't exist"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-2-nonexistent-bucket',
            'AwsAccountId': '123456789012',
            'Title': 'S3.2 S3 buckets should prohibit public access',
            'Resources': [{
                'Id': 'arn:aws:s3:::nonexistent-bucket-test',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'nonexistent-bucket-test',
                        'OwnerId': '123456789012'
                    }
                }
            }]
        }
    }


def get_s32_malformed_arn_finding():
    """Mock Security Hub finding for S3.2 control - malformed bucket ARN"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-2-malformed-arn',
            'AwsAccountId': '123456789012',
            'Title': 'S3.2 S3 buckets should prohibit public access',
            'Resources': [{
                'Id': 'malformed-bucket-arn-without-colons',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'malformed-bucket-name',
                        'OwnerId': '123456789012'
                    }
                }
            }]
        }
    }


def get_s33_basic_finding():
    """Mock Security Hub finding for S3.3 control - bucket without public access block"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-3-basic-finding',
            'AwsAccountId': '123456789012',
            'Title': 'S3.3 S3 buckets should prohibit public access',
            'Description': 'This control checks whether S3 buckets have bucket-level public access blocks applied.',
            'Resources': [{
                'Id': 'arn:aws:s3:::test-bucket-s3-3-control',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'test-bucket-s3-3-control',
                        'OwnerId': '123456789012',
                        'PublicAccessBlockConfiguration': {
                            'BlockPublicAcls': False,
                            'BlockPublicPolicy': False,
                            'IgnorePublicAcls': False,
                            'RestrictPublicBuckets': False
                        }
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }


def get_s33_exemption_tag_finding():
    """Mock Security Hub finding for S3.3 control - bucket with exemption tag"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-3-exemption-tag-finding',
            'AwsAccountId': '123456789012',
            'Title': 'S3.3 S3 buckets should prohibit public access',
            'Resources': [{
                'Id': 'arn:aws:s3:::test-bucket-s3-3-exemption',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'test-bucket-s3-3-exemption',
                        'OwnerId': '123456789012'
                    }
                }
            }]
        }
    }


def get_s310_basic_finding():
    """Mock Security Hub finding for S3.10 control - bucket needing lifecycle configuration"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-10-basic-finding',
            'AwsAccountId': '123456789012',
            'Title': 'S3.10 S3 buckets should have lifecycle configuration',
            'Description': 'This control checks whether S3 buckets have lifecycle configuration to manage objects.',
            'Resources': [{
                'Id': 'arn:aws:s3:::test-bucket-lifecycle-needed',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'test-bucket-lifecycle-needed',
                        'OwnerId': '123456789012',
                        'VersioningConfiguration': {
                            'Status': 'Enabled'
                        }
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            }
        }
    }


def get_s310_cross_account_finding():
    """Mock Security Hub finding for S3.10 control - cross-account bucket"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:555666777888:finding/s3-10-cross-account',
            'AwsAccountId': '555666777888',
            'Title': 'S3.10 S3 buckets should have lifecycle configuration',
            'Resources': [{
                'Id': 'arn:aws:s3:::cross-account-lifecycle-bucket',
                'Region': 'us-west-2',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'cross-account-lifecycle-bucket',
                        'OwnerId': '555666777888'
                    }
                }
            }]
        }
    }


def get_s310_nonexistent_bucket_finding():
    """Mock Security Hub finding for S3.10 control - bucket that doesn't exist"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-10-nonexistent-bucket',
            'AwsAccountId': '123456789012',
            'Title': 'S3.10 S3 buckets should have lifecycle configuration',
            'Resources': [{
                'Id': 'arn:aws:s3:::nonexistent-lifecycle-bucket',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket',
                'Details': {
                    'AwsS3Bucket': {
                        'Name': 'nonexistent-lifecycle-bucket',
                        'OwnerId': '123456789012'
                    }
                }
            }]
        }
    }


def get_s3_missing_details_finding():
    """Mock Security Hub finding with missing S3 bucket details"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-missing-details',
            'AwsAccountId': '123456789012',
            'Title': 'S3 control with missing details',
            'Resources': [{
                'Id': 'arn:aws:s3:::bucket-missing-details',
                'Region': 'us-east-1',
                'Type': 'AwsS3Bucket'
                # Missing Details section
            }]
        }
    }


def get_s3_empty_resources_finding():
    """Mock Security Hub finding with empty resources array"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/s3-empty-resources',
            'AwsAccountId': '123456789012',
            'Title': 'S3 control with empty resources',
            'Resources': []
        }
    }