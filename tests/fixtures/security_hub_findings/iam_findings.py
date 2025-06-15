"""
Sample Security Hub findings for IAM testing
"""

def get_iam8_basic_finding():
    """Mock Security Hub finding for IAM.8 control - unused IAM user with credentials"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-basic-finding',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Description': 'This control checks whether your AWS account has IAM user credentials that have not been used within the past 90 days.',
            'Resources': [{
                'Id': 'arn:aws:iam::123456789012:user/unused-test-user',
                'Region': 'us-east-1',
                'Type': 'AwsIamUser',
                'Details': {
                    'AwsIamUser': {
                        'UserName': 'unused-test-user',
                        'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
                        'Path': '/',
                        'CreateDate': '2023-01-15T10:30:00.000Z',
                        'UserPolicyList': [],
                        'GroupList': [],
                        'AttachedManagedPolicies': [],
                        'PermissionsBoundary': {},
                        'MaxSessionDuration': 3600
                    }
                }
            }],
            'GeneratorId': 'arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard',
            'Compliance': {
                'Status': 'FAILED'
            },
            'Severity': {
                'Label': 'MEDIUM'
            }
        }
    }


def get_iam8_cross_account_finding():
    """Mock Security Hub finding for IAM.8 control - cross-account IAM user"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-west-2:555666777888:finding/iam-8-cross-account',
            'AwsAccountId': '555666777888',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': [{
                'Id': 'arn:aws:iam::555666777888:user/cross-account-unused-user',
                'Region': 'us-west-2',
                'Type': 'AwsIamUser',
                'Details': {
                    'AwsIamUser': {
                        'UserName': 'cross-account-unused-user',
                        'UserId': 'AIDACKCEVSQ6C2CROSS001',
                        'Path': '/',
                        'CreateDate': '2023-02-20T14:45:00.000Z',
                        'UserPolicyList': [
                            {
                                'PolicyName': 'InlineTestPolicy',
                                'PolicyDocument': '%7B%22Version%22%3A%222012-10-17%22%7D'
                            }
                        ],
                        'GroupList': ['TestGroup'],
                        'AttachedManagedPolicies': [
                            {
                                'PolicyName': 'ReadOnlyAccess',
                                'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'
                            }
                        ]
                    }
                }
            }]
        }
    }


def get_iam8_user_with_permissions_boundary():
    """Mock Security Hub finding for IAM.8 control - user with permissions boundary"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-permissions-boundary',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': [{
                'Id': 'arn:aws:iam::123456789012:user/boundary-test-user',
                'Region': 'us-east-1',
                'Type': 'AwsIamUser',
                'Details': {
                    'AwsIamUser': {
                        'UserName': 'boundary-test-user',
                        'UserId': 'AIDACKCEVSQ6C2BOUNDARY',
                        'Path': '/test-department/',
                        'CreateDate': '2023-03-10T09:15:00.000Z',
                        'PermissionsBoundary': {
                            'PermissionsBoundaryType': 'PermissionsBoundaryPolicy',
                            'PermissionsBoundaryArn': 'arn:aws:iam::123456789012:policy/DeveloperBoundary'
                        },
                        'Tags': [
                            {
                                'Key': 'Department',
                                'Value': 'Engineering'
                            },
                            {
                                'Key': 'Project',
                                'Value': 'TestProject'
                            }
                        ]
                    }
                }
            }]
        }
    }


def get_iam8_nonexistent_user_finding():
    """Mock Security Hub finding for IAM.8 control - user that doesn't exist"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-nonexistent-user',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': [{
                'Id': 'arn:aws:iam::123456789012:user/nonexistent-user',
                'Region': 'us-east-1',
                'Type': 'AwsIamUser',
                'Details': {
                    'AwsIamUser': {
                        'UserName': 'nonexistent-user',
                        'UserId': 'AIDACKCEVSQ6C2NOTEXIST',
                        'Path': '/'
                    }
                }
            }]
        }
    }


def get_iam8_malformed_arn_finding():
    """Mock Security Hub finding for IAM.8 control - malformed user ARN"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-malformed-arn',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': [{
                'Id': 'malformed-iam-user-arn-without-proper-format',
                'Region': 'us-east-1',
                'Type': 'AwsIamUser',
                'Details': {
                    'AwsIamUser': {
                        'UserName': 'malformed-arn-user'
                    }
                }
            }]
        }
    }


def get_iam8_missing_details_finding():
    """Mock Security Hub finding for IAM.8 control - missing IAM user details"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-missing-details',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': [{
                'Id': 'arn:aws:iam::123456789012:user/missing-details-user',
                'Region': 'us-east-1',
                'Type': 'AwsIamUser'
                # Missing Details section
            }]
        }
    }


def get_iam8_empty_resources_finding():
    """Mock Security Hub finding for IAM.8 control - empty resources array"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-empty-resources',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': []
        }
    }


def get_iam8_service_user_finding():
    """Mock Security Hub finding for IAM.8 control - service user with specific path"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/iam-8-service-user',
            'AwsAccountId': '123456789012',
            'Title': 'IAM.8 Unused IAM user credentials should be removed',
            'Resources': [{
                'Id': 'arn:aws:iam::123456789012:user/service-accounts/ci-cd-service-user',
                'Region': 'us-east-1',
                'Type': 'AwsIamUser',
                'Details': {
                    'AwsIamUser': {
                        'UserName': 'ci-cd-service-user',
                        'UserId': 'AIDACKCEVSQ6C2SERVICE',
                        'Path': '/service-accounts/',
                        'CreateDate': '2023-01-01T00:00:00.000Z',
                        'AttachedManagedPolicies': [
                            {
                                'PolicyName': 'PowerUserAccess',
                                'PolicyArn': 'arn:aws:iam::aws:policy/PowerUserAccess'
                            }
                        ],
                        'Tags': [
                            {
                                'Key': 'UserType',
                                'Value': 'ServiceAccount'
                            },
                            {
                                'Key': 'Application',
                                'Value': 'CI-CD-Pipeline'
                            }
                        ]
                    }
                }
            }]
        }
    }