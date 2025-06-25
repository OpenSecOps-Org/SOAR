"""
CloudWatch Alarm Security Hub Findings Test Data

This module provides standardized test data for CloudWatch alarm-based findings
used in SOAR CloudWatch context enrichment testing.

Following established SOAR fixture patterns for consistent test data generation.
"""


def get_stepfunctions_alarm_finding_standard():
    """Standard Step Functions alarm finding for state machine failures."""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/stepfunctions-alarm-standard',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-SOAR-ASFF-Processor-SM-Failure-HIGH',
        'Description': 'The SOARASFFProcessor state machine failed.',
        'Severity': {'Label': 'HIGH', 'Normalized': 70},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '123456789012',
        'Region': 'us-east-1',
        'CreatedAt': '2024-01-01T12:00:00.000Z',
        'UpdatedAt': '2024-01-01T12:00:00.000Z',
        'FirstObservedAt': '2024-01-01T11:59:45.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T11:59:45.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '123456789012',
                'Region': 'us-east-1'
            },
            {
                'Type': 'AwsStatesStateMachine',
                'Id': 'arn:aws:states:us-east-1:123456789012:stateMachine:SOARASFFProcessor',
                'Region': 'us-east-1'
            }
        ]
    }


def get_stepfunctions_alarm_finding_cross_account():
    """Cross-account Step Functions alarm finding."""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:555666777888:finding/stepfunctions-alarm-cross-account',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-SOAR-Incident-Processor-SM-Failure-CRITICAL',
        'Description': 'Step Function SOARIncidentProcessor execution failed in production account',
        'Severity': {'Label': 'CRITICAL', 'Normalized': 90},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '555666777888',
        'Region': 'us-east-1',
        'CreatedAt': '2024-01-01T14:30:00.000Z',
        'UpdatedAt': '2024-01-01T14:30:00.000Z',
        'FirstObservedAt': '2024-01-01T14:29:30.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T14:29:30.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '555666777888',
                'Region': 'us-east-1'
            },
            {
                'Type': 'AwsStatesStateMachine',
                'Id': 'arn:aws:states:us-east-1:555666777888:stateMachine:SOARIncidentProcessor',
                'Region': 'us-east-1'
            }
        ]
    }


def get_stepfunctions_alarm_finding_different_region():
    """Step Functions alarm finding in different AWS region."""
    return {
        'Id': 'arn:aws:securityhub:us-west-2:123456789012:finding/stepfunctions-alarm-west',
        'ProductArn': 'arn:aws:securityhub:us-west-2::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-SOAR-AutoRemediation-SM-Failure-HIGH',
        'Description': 'Step Function SOARAutoRemediation execution failed',
        'Severity': {'Label': 'HIGH', 'Normalized': 70},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '123456789012',
        'Region': 'us-west-2',
        'CreatedAt': '2024-01-01T16:15:00.000Z',
        'UpdatedAt': '2024-01-01T16:15:00.000Z',
        'FirstObservedAt': '2024-01-01T16:14:15.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T16:14:15.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '123456789012',
                'Region': 'us-west-2'
            },
            {
                'Type': 'AwsStatesStateMachine',
                'Id': 'arn:aws:states:us-west-2:123456789012:stateMachine:SOARAutoRemediation',
                'Region': 'us-west-2'
            }
        ]
    }


def get_lambda_alarm_finding_standard():
    """Standard Lambda function alarm finding for function errors."""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/lambda-alarm-standard',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-ProcessFindings-Lambda-Error-MEDIUM',
        'Description': 'Lambda function ProcessFindings failed with errors',
        'Severity': {'Label': 'MEDIUM', 'Normalized': 40},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '123456789012',
        'Region': 'us-east-1',
        'CreatedAt': '2024-01-01T13:45:00.000Z',
        'UpdatedAt': '2024-01-01T13:45:00.000Z',
        'FirstObservedAt': '2024-01-01T13:44:30.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T13:44:30.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '123456789012',
                'Region': 'us-east-1'
            },
            {
                'Type': 'AwsLambdaFunction',
                'Id': 'arn:aws:lambda:us-east-1:123456789012:function:ProcessFindings',
                'Region': 'us-east-1'
            }
        ]
    }


def get_lambda_alarm_finding_cross_account():
    """Cross-account Lambda function alarm finding."""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:999888777666:finding/lambda-alarm-cross-account',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-AutoRemediateEC2-Lambda-Error-HIGH',
        'Description': 'Lambda function AutoRemediateEC2 failed with critical errors',
        'Severity': {'Label': 'HIGH', 'Normalized': 70},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '999888777666',
        'Region': 'us-east-1',
        'CreatedAt': '2024-01-01T15:20:00.000Z',
        'UpdatedAt': '2024-01-01T15:20:00.000Z',
        'FirstObservedAt': '2024-01-01T15:19:15.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T15:19:15.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '999888777666',
                'Region': 'us-east-1'
            },
            {
                'Type': 'AwsLambdaFunction',
                'Id': 'arn:aws:lambda:us-east-1:999888777666:function:AutoRemediateEC2',
                'Region': 'us-east-1'
            }
        ]
    }


def get_lambda_alarm_finding_eu_region():
    """Lambda function alarm finding in EU region."""
    return {
        'Id': 'arn:aws:securityhub:eu-west-1:123456789012:finding/lambda-alarm-eu',
        'ProductArn': 'arn:aws:securityhub:eu-west-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-EnrichContext-Lambda-Error-MEDIUM',
        'Description': 'Lambda function EnrichContext failed with timeout errors',
        'Severity': {'Label': 'MEDIUM', 'Normalized': 40},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '123456789012',
        'Region': 'eu-west-1',
        'CreatedAt': '2024-01-01T17:00:00.000Z',
        'UpdatedAt': '2024-01-01T17:00:00.000Z',
        'FirstObservedAt': '2024-01-01T16:59:00.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T16:59:00.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '123456789012',
                'Region': 'eu-west-1'
            },
            {
                'Type': 'AwsLambdaFunction',
                'Id': 'arn:aws:lambda:eu-west-1:123456789012:function:EnrichContext',
                'Region': 'eu-west-1'
            }
        ]
    }


def get_generic_alarm_finding():
    """Generic CloudWatch alarm finding that doesn't match Step Functions or Lambda patterns."""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/generic-alarm',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms'],
        'Title': 'INFRA-SomeUnknownService-Error-MEDIUM',
        'Description': 'Unknown service alarm that does not match enrichment patterns',
        'Severity': {'Label': 'MEDIUM', 'Normalized': 40},
        'ProductFields': {
            'IncidentDomain': 'INFRA',
            'TicketDestination': 'TEAM'
        },
        'AwsAccountId': '123456789012',
        'Region': 'us-east-1',
        'CreatedAt': '2024-01-01T18:30:00.000Z',
        'UpdatedAt': '2024-01-01T18:30:00.000Z',
        'FirstObservedAt': '2024-01-01T18:29:15.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T18:29:15.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsAccountId',
                'Id': '123456789012',
                'Region': 'us-east-1'
            },
            {
                'Type': 'AwsCloudWatchAlarm',
                'Id': 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:SomeUnknownService-Error',
                'Region': 'us-east-1'
            }
        ]
    }


def get_non_cloudwatch_finding():
    """Non-CloudWatch finding for negative testing."""
    return {
        'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/guardduty-finding',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
        'Types': ['TTPs/Command and Control/CryptoCurrency:EC2-BitcoinTool.B!DNS'],
        'Title': 'Cryptocurrency mining activity',
        'Description': 'EC2 instance is communicating with a cryptocurrency mining pool',
        'Severity': {'Label': 'HIGH', 'Normalized': 70},
        'ProductFields': {
            'Service/ServiceName': 'guardduty',
            'Service/DetectorId': 'abcd1234efgh5678ijkl90mnop123456'
        },
        'AwsAccountId': '123456789012',
        'Region': 'us-east-1',
        'CreatedAt': '2024-01-01T10:00:00.000Z',
        'UpdatedAt': '2024-01-01T10:00:00.000Z',
        'FirstObservedAt': '2024-01-01T09:59:30.000Z',  # Actual alarm trigger time
        'LastObservedAt': '2024-01-01T09:59:30.000Z',   # Same as first observed for new alarms
        'Resources': [
            {
                'Type': 'AwsEc2Instance',
                'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
                'Region': 'us-east-1'
            }
        ]
    }


# AWS API Response Mock Data

def get_mock_stepfunctions_execution_details():
    """Mock Step Functions execution details response."""
    return {
        'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:test-execution-123',
        'stateMachineArn': 'arn:aws:states:us-east-1:123456789012:stateMachine:SOARASFFProcessor',
        'name': 'test-execution-123',
        'status': 'FAILED',
        'input': '{"finding": {"Id": "test-finding"}}',
        'output': None,
        'error': 'States.TaskFailed',
        'cause': 'Lambda function failed'
    }


def get_mock_stepfunctions_execution_history():
    """Mock Step Functions execution history response."""
    return {
        'events': [
            {
                'timestamp': '2024-01-01T12:00:00.000Z',
                'type': 'ExecutionStarted',
                'id': 1,
                'executionStartedEventDetails': {
                    'input': '{"finding": {"Id": "test-finding"}}'
                }
            },
            {
                'timestamp': '2024-01-01T12:00:30.000Z',
                'type': 'TaskFailed',
                'id': 5,
                'taskFailedEventDetails': {
                    'resourceType': 'lambda',
                    'resource': 'arn:aws:lambda:us-east-1:123456789012:function:ProcessFinding',
                    'error': 'RuntimeError',
                    'cause': 'Failed to process finding: Invalid ASFF structure'
                }
            },
            {
                'timestamp': '2024-01-01T12:00:35.000Z',
                'type': 'ExecutionFailed',
                'id': 6,
                'executionFailedEventDetails': {
                    'error': 'States.TaskFailed',
                    'cause': 'Lambda function failed'
                }
            }
        ]
    }


def get_mock_cloudwatch_logs_entries():
    """Mock CloudWatch Logs entries for failed Lambda."""
    return {
        'events': [
            {
                'timestamp': 1704110400000,  # 2024-01-01T12:00:00.000Z
                'message': '[ERROR] RuntimeError: Failed to process finding: Invalid ASFF structure',
                'logStreamName': '2024/01/01/[$LATEST]abc123'
            },
            {
                'timestamp': 1704110401000,
                'message': 'Traceback (most recent call last):',
                'logStreamName': '2024/01/01/[$LATEST]abc123'
            },
            {
                'timestamp': 1704110402000,
                'message': '  File "/var/task/app.py", line 45, in lambda_handler',
                'logStreamName': '2024/01/01/[$LATEST]abc123'
            },
            {
                'timestamp': 1704110403000,
                'message': '    raise RuntimeError("Failed to process finding: Invalid ASFF structure")',
                'logStreamName': '2024/01/01/[$LATEST]abc123'
            }
        ],
        'nextForwardToken': None
    }