"""
Test fixtures for preprocessing pipeline implementation.
Contains ASFF findings for testing account routing correction logic.
"""

def get_guardduty_finding_no_correction():
    """
    GuardDuty finding that does NOT need account routing correction.
    Resource appears to be in the same account as the finding.
    """
    return {
        'SOAREnabled': 'Yes',
        'DeferIncidents': 'No',
        'DeferAutoRemediations': 'No',
        'DeferTeamFixes': 'No',
        'DiskForensicsInvoke': 'No',
        'account': {},
        'finding': {
            'Id': 'arn:aws:guardduty:us-east-1:111111111111:detector/test-detector-id/finding/test-finding-id',
            'AwsAccountId': '111111111111',
            'AwsAccountName': 'Security-Adm',
            'Title': 'The user AssumedRole : AWSControlTowerExecution is anomalously invoking APIs commonly used in Discovery tactics.',
            'Description': 'APIs commonly used in Discovery tactics were invoked by user AssumedRole : AWSControlTowerExecution under unusual circumstances.',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
            'ProductName': 'GuardDuty',
            'CompanyName': 'Amazon',
            'GeneratorId': 'arn:aws:guardduty:us-east-1:111111111111:detector/test-detector-id',
            'Types': [
                'TTPs/Discovery/IAMUser-AnomalousBehavior'
            ],
            'Severity': {
                'Label': 'LOW',
                'Normalized': 40
            },
            'Resources': [
                {
                    'Type': 'AwsIamAccessKey',
                    'Id': 'AWS::IAM::AccessKey:ASIATEST123456789',
                    'Region': 'us-east-1',
                    'Details': {
                        'AwsIamAccessKey': {
                            'PrincipalId': 'AROATEST123456789:test-principal-name',
                            'PrincipalName': 'AWSControlTowerExecution',
                            'PrincipalType': 'AssumedRole'
                        }
                    }
                }
            ],
            'ProductFields': {
                'aws/securityhub/FindingId': 'arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:111111111111:detector/test-detector-id/finding/test-finding-id',
                'aws/securityhub/ProductName': 'GuardDuty',
                'aws/securityhub/CompanyName': 'Amazon'
            },
            'CreatedAt': '2025-01-01T12:00:00.000Z',
            'UpdatedAt': '2025-01-01T12:00:00.000Z',
            'ProcessedAt': '2025-01-01T12:00:00.000Z',
            'RecordState': 'ACTIVE',
            'WorkflowState': 'NEW',
            'Workflow': {
                'Status': 'NEW'
            },
            'SchemaVersion': '2018-10-08'
        },
        'tags': {},
        'actions': {
            'suppress_finding': False,
            'autoremediation_not_done': False,
            'reconsider_later': False
        },
        'messages': {
            'actions_taken': 'None.',
            'actions_required': 'Please update your infrastructural code to prevent this security issue from arising again at the next deployment.',
            'ai': {
                'plaintext': '',
                'html': ''
            }
        },
        'db': {
            'tickets': {}
        },
        'ASFF_decision': 'incident',
        'ASFF_decision_reason': 'Finding is an incident'
    }


def get_access_analyzer_finding_needs_correction_1():
    """
    IAM Access Analyzer finding that NEEDS account routing correction.
    Resource is in account 222222222222 but finding is attributed to Security-Adm.
    """
    return {
        'SOAREnabled': 'Yes',
        'DeferIncidents': 'No',
        'DeferAutoRemediations': 'No',
        'DeferTeamFixes': 'No',
        'DiskForensicsInvoke': 'No',
        'account': {},
        'finding': {
            'Id': 'arn:aws:access-analyzer:eu-west-1:111111111111:analyzer/UnusedAccess-test-analyzer/arn:aws:iam::222222222222:role/example-scheduler-role/UnusedIAMRole',
            'AwsAccountId': '111111111111',
            'AwsAccountName': 'Security-Adm',
            'Title': 'AwsIamRole/arn:aws:iam::222222222222:role/example-scheduler-role/ contains unused iam role',
            'Description': 'AWS::IAM::Role/arn:aws:iam::222222222222:role/example-scheduler-role/ contains unused iam role',
            'ProductArn': 'arn:aws:securityhub:eu-west-1::product/aws/access-analyzer',
            'ProductName': 'IAM Access Analyzer',
            'CompanyName': 'AWS',
            'GeneratorId': 'aws/access-analyzer',
            'Types': [
                'Software and Configuration Checks/AWS Security Best Practices/Unused IAM Role'
            ],
            'Severity': {
                'Label': 'MEDIUM',
                'Normalized': 40
            },
            'Resources': [
                {
                    'Type': 'AwsIamRole',
                    'Id': 'arn:aws:iam::222222222222:role/example-scheduler-role'
                }
            ],
            'ProductFields': {
                'findingId': 'test-finding-id-1',
                'findingType': 'UnusedIAMRole',
                'roleLastUsedTimestamp': '2025-01-01T12:00:00.000Z',
                'ResourceOwnerAccount': '222222222222',
                'aws/securityhub/FindingId': 'arn:aws:securityhub:eu-west-1::product/aws/access-analyzer/arn:aws:access-analyzer:eu-west-1:111111111111:analyzer/UnusedAccess-test-analyzer/arn:aws:iam::222222222222:role/example-scheduler-role/UnusedIAMRole',
                'aws/securityhub/ProductName': 'IAM Access Analyzer',
                'aws/securityhub/CompanyName': 'AWS'
            },
            'CreatedAt': '2025-01-01T12:00:00.000Z',
            'UpdatedAt': '2025-01-01T12:00:00.000Z',
            'ProcessedAt': '2025-01-01T12:00:00.000Z',
            'RecordState': 'ACTIVE',
            'WorkflowState': 'NEW',
            'Workflow': {
                'Status': 'NEW'
            },
            'SchemaVersion': '2018-10-08'
        },
        'tags': {},
        'actions': {
            'suppress_finding': False,
            'autoremediation_not_done': False,
            'reconsider_later': False
        },
        'messages': {
            'actions_taken': 'None.',
            'actions_required': 'Please update your infrastructural code to prevent this security issue from arising again at the next deployment.',
            'ai': {
                'plaintext': '',
                'html': ''
            }
        },
        'db': {
            'tickets': {}
        },
        'ASFF_decision': 'failed_control',
        'ASFF_decision_reason': 'FAILED control'
    }


def get_access_analyzer_finding_needs_correction_2():
    """
    IAM Access Analyzer finding that NEEDS account routing correction.
    Resource is in account 333333333333 but finding is attributed to Security-Adm.
    """
    return {
        'SOAREnabled': 'Yes',
        'DeferIncidents': 'No',
        'DeferAutoRemediations': 'No',
        'DeferTeamFixes': 'No',
        'DiskForensicsInvoke': 'No',
        'account': {},
        'finding': {
            'Id': 'arn:aws:access-analyzer:us-east-1:111111111111:analyzer/ExternalAccess-test-analyzer/arn:aws:iam::333333333333:role/example-sso-role',
            'AwsAccountId': '111111111111',
            'AwsAccountName': 'Security-Adm',
            'Title': 'AwsIamRole/arn:aws:iam::333333333333:role/example-sso-role/ allows cross-account access',
            'Description': 'AWS::IAM::Role/arn:aws:iam::333333333333:role/example-sso-role/ allows cross-account access from Federated arn:aws:iam::333333333333:saml-provider/ExampleSSOProvider',
            'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/access-analyzer',
            'ProductName': 'IAM Access Analyzer',
            'CompanyName': 'AWS',
            'GeneratorId': 'aws/access-analyzer',
            'Types': [
                'Software and Configuration Checks/AWS Security Best Practices/External Access Granted'
            ],
            'Severity': {
                'Label': 'LOW',
                'Normalized': 1
            },
            'Resources': [
                {
                    'Type': 'AwsIamRole',
                    'Id': 'arn:aws:iam::333333333333:role/example-sso-role',
                    'Details': {
                        'Other': {
                            'External Principal Type': 'Federated',
                            'Condition': 'none',
                            'Resource Control Policy Restriction Type': 'NOT_APPLICABLE',
                            'Action Granted': 'sts:TagSession,sts:AssumeRoleWithSAML',
                            'External Principal': 'arn:aws:iam::333333333333:saml-provider/ExampleSSOProvider'
                        }
                    }
                }
            ],
            'ProductFields': {
                'ResourceOwnerAccount': '333333333333',
                'aws/securityhub/FindingId': 'arn:aws:securityhub:us-east-1::product/aws/access-analyzer/arn:aws:access-analyzer:us-east-1:111111111111:analyzer/ExternalAccess-test-analyzer/arn:aws:iam::333333333333:role/example-sso-role',
                'aws/securityhub/ProductName': 'IAM Access Analyzer',
                'aws/securityhub/CompanyName': 'AWS'
            },
            'CreatedAt': '2025-01-01T12:00:00.000Z',
            'UpdatedAt': '2025-01-01T12:00:00.000Z',
            'ProcessedAt': '2025-01-01T12:00:00.000Z',
            'RecordState': 'ACTIVE',
            'WorkflowState': 'NEW',
            'Workflow': {
                'Status': 'NEW'
            },
            'SchemaVersion': '2018-10-08'
        },
        'tags': {},
        'actions': {
            'suppress_finding': False,
            'autoremediation_not_done': False,
            'reconsider_later': False
        },
        'messages': {
            'actions_taken': 'None.',
            'actions_required': 'Please update your infrastructural code to prevent this security issue from arising again at the next deployment.',
            'ai': {
                'plaintext': '',
                'html': ''
            }
        },
        'db': {
            'tickets': {}
        },
        'ASFF_decision': 'failed_control',
        'ASFF_decision_reason': 'FAILED control'
    }


def get_access_analyzer_finding_needs_correction_3():
    """
    IAM Access Analyzer finding that NEEDS account routing correction.
    Resource is in account 444444444444 but finding is attributed to Security-Adm.
    """
    return {
        'SOAREnabled': 'Yes',
        'DeferIncidents': 'No',
        'DeferAutoRemediations': 'No',
        'DeferTeamFixes': 'No',
        'DiskForensicsInvoke': 'No',
        'account': {},
        'finding': {
            'Id': 'arn:aws:access-analyzer:eu-west-1:111111111111:analyzer/ExternalAccess-test-analyzer/arn:aws:iam::444444444444:role/example-github-role',
            'AwsAccountId': '111111111111',
            'AwsAccountName': 'Security-Adm',
            'Title': 'AwsIamRole/arn:aws:iam::444444444444:role/example-github-role/ allows cross-account access',
            'Description': 'AWS::IAM::Role/arn:aws:iam::444444444444:role/example-github-role/ allows cross-account access from Federated arn:aws:iam::444444444444:oidc-provider/token.actions.githubusercontent.com',
            'ProductArn': 'arn:aws:securityhub:eu-west-1::product/aws/access-analyzer',
            'ProductName': 'IAM Access Analyzer',
            'CompanyName': 'AWS',
            'GeneratorId': 'aws/access-analyzer',
            'Types': [
                'Software and Configuration Checks/AWS Security Best Practices/External Access Granted'
            ],
            'Severity': {
                'Label': 'LOW',
                'Normalized': 1
            },
            'Resources': [
                {
                    'Type': 'AwsIamRole',
                    'Id': 'arn:aws:iam::444444444444:role/example-github-role',
                    'Details': {
                        'Other': {
                            'External Principal Type': 'Federated',
                            'Condition': 'none',
                            'Resource Control Policy Restriction Type': 'NOT_APPLICABLE',
                            'Action Granted': 'sts:AssumeRoleWithWebIdentity',
                            'External Principal': 'arn:aws:iam::444444444444:oidc-provider/token.actions.githubusercontent.com'
                        }
                    }
                }
            ],
            'ProductFields': {
                'ResourceOwnerAccount': '444444444444',
                'aws/securityhub/FindingId': 'arn:aws:securityhub:eu-west-1::product/aws/access-analyzer/arn:aws:access-analyzer:eu-west-1:111111111111:analyzer/ExternalAccess-test-analyzer/arn:aws:iam::444444444444:role/example-github-role',
                'aws/securityhub/ProductName': 'IAM Access Analyzer',
                'aws/securityhub/CompanyName': 'AWS'
            },
            'CreatedAt': '2025-01-01T12:00:00.000Z',
            'UpdatedAt': '2025-01-01T12:00:00.000Z',
            'ProcessedAt': '2025-01-01T12:00:00.000Z',
            'RecordState': 'ACTIVE',
            'WorkflowState': 'NEW',
            'Workflow': {
                'Status': 'NEW'
            },
            'SchemaVersion': '2018-10-08'
        },
        'tags': {},
        'actions': {
            'suppress_finding': False,
            'autoremediation_not_done': False,
            'reconsider_later': False
        },
        'messages': {
            'actions_taken': 'None.',
            'actions_required': 'Please update your infrastructural code to prevent this security issue from arising again at the next deployment.',
            'ai': {
                'plaintext': '',
                'html': ''
            }
        },
        'db': {
            'tickets': {}
        },
        'ASFF_decision': 'failed_control',
        'ASFF_decision_reason': 'FAILED control'
    }