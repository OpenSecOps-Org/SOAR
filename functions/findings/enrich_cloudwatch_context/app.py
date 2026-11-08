"""
CloudWatch Context Enrichment Function

This function enriches CloudWatch alarm-based incidents with detailed execution context,
logs, and historical pattern analysis before AI processing.

Purpose: Transform AI incident analysis from reactive debugging to pattern-aware,
context-rich incident intelligence.

Integration: SOARIncidents state machine between "Format Generic message" and "Email to Whom?"

Configuration Dependencies:
- CLOUDWATCH_ALARM_TYPE must match AlarmTypeForASFF parameter in SOAR-all-alarms-to-sec-hub
- Default: "soar-cloudwatch-alarms" for both repositories
- Change both parameters together to maintain compatibility
"""

import json
import os
import boto3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any

# Import aws_utils for cross-account client creation
from aws_utils.clients import get_client
from aws_utils.errors import transient_aws_errors

# Initialize DynamoDB client at module level for reuse across invocations
dynamodb_client = boto3.client('dynamodb')


@transient_aws_errors
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for CloudWatch context enrichment.
    
    Args:
        event: Standard SOAR scratchpad data structure
        context: Lambda context object
        
    Returns:
        Enhanced scratchpad with enriched context data
    """
    # Log the complete event for debugging purposes
    print(f"ENRICHER INPUT: {event}")
    
    finding = event.get('finding', {})
    
    # Check if this is a CloudWatch alarm finding that needs enrichment
    if not is_cloudwatch_alarm_finding(finding):
        # Not a CloudWatch alarm, return unchanged
        print("ENRICHMENT SKIPPED: Not a CloudWatch alarm finding")
        print(f"Finding Types: {finding.get('Types', [])}")
        return event
    
    # Extract service-specific context
    service_context = extract_service_context(finding)
    
    # Skip enrichment if not supported for this service type
    if not service_context.get('enrichment_enabled', False):
        print("ENRICHMENT SKIPPED: Service type not supported for enrichment")
        print(f"Service context: {service_context}")
        return event
    
    # Create enriched context structure
    enriched_context = {
        'service_type': service_context['service_type'],
        'enrichment_timestamp': datetime.now(timezone.utc).isoformat(),
        'alarm_correlation': {},
        'pattern_analysis': {},
        'failed_executions': []
    }
    
    # Add historical pattern analysis for better incident intelligence
    try:
        pattern_analysis = analyze_incident_patterns(finding)
        enriched_context['pattern_analysis'] = pattern_analysis
    except Exception as e:
        print(f"Pattern analysis failed: {str(e)}")
        enriched_context['pattern_analysis'] = {
            'error': str(e),
            'status': 'failed'
        }
    
    # Add service-specific context and perform enrichment
    try:
        if service_context['service_type'] == 'stepfunctions':
            enriched_context['state_machine_name'] = service_context['state_machine_name']
            # Perform Step Functions specific enrichment
            stepfunctions_enrichment = enrich_stepfunctions_context(finding, service_context)
            enriched_context.update(stepfunctions_enrichment)
        elif service_context['service_type'] == 'lambda':
            enriched_context['function_name'] = service_context['function_name']
            # Perform Lambda specific enrichment  
            lambda_enrichment = enrich_lambda_context(finding, service_context)
            enriched_context.update(lambda_enrichment)
    except Exception as e:
        # Graceful degradation - log error but continue with basic enrichment
        print(f"Warning: Enrichment failed for {service_context['service_type']}: {str(e)}")
    
    # Add enriched context to the scratchpad
    event['enriched_context'] = enriched_context
    
    # Log what was added for visibility
    print("ENRICHMENT COMPLETED: CloudWatch context successfully enriched")
    print(f"Service type: {service_context['service_type']}")
    print(f"Detection method: {service_context.get('detection_method', 'unknown')}")
    print(f"Failed executions found: {len(enriched_context.get('failed_executions', []))}")
    print(f"Pattern analysis status: {enriched_context.get('pattern_analysis', {}).get('pattern_classification', {}).get('pattern_type', 'unknown')}")
    print(f"Historical incidents analyzed: {enriched_context.get('pattern_analysis', {}).get('total_incidents_analyzed', 0)}")
    
    return event


def is_cloudwatch_alarm_finding(finding: Dict[str, Any]) -> bool:
    """
    Determine if finding is from CloudWatch alarm monitoring.
    
    Matches against the specific alarm type configured in SOAR-all-alarms-to-sec-hub.
    
    Args:
        finding: ASFF finding data
        
    Returns:
        True if finding is from CloudWatch alarms
    """
    # Get the configured CloudWatch alarm type (must match SOAR-all-alarms-to-sec-hub)
    cloudwatch_alarm_type = os.environ.get('CLOUDWATCH_ALARM_TYPE', 'soar-cloudwatch-alarms')
    
    # Check if finding has the expected CloudWatch alarm type
    types = finding.get('Types', [])
    expected_type = f"Software and Configuration Checks/CloudWatch Alarms/{cloudwatch_alarm_type}"
    
    is_cloudwatch = expected_type in types
    
    # Debug logging for CloudWatch alarm detection
    print(f"CloudWatch alarm check: Expected type: {expected_type}")
    print(f"CloudWatch alarm check: Found types: {types}")
    print(f"CloudWatch alarm check: Is CloudWatch alarm: {is_cloudwatch}")
    
    return is_cloudwatch


def extract_service_context(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract service-specific context from CloudWatch alarm finding.
    
    Only checks Resources array for supported AWS service types - no fallback heuristics.
    The alarm generator (SOAR-all-alarms-to-sec-hub) is responsible for providing
    accurate resource information in the ASFF Resources array.
    
    Args:
        finding: ASFF finding data
        
    Returns:
        Service context including type and enrichment parameters
    """
    resources = finding.get('Resources', [])
    
    # Ensure resources is a list and handle corrupted data gracefully
    if not isinstance(resources, list):
        resources = []
    
    for resource in resources:
        # Skip non-dictionary resource items
        if not isinstance(resource, dict):
            continue
            
        resource_type = resource.get('Type', '')
        resource_id = resource.get('Id', '')
        
        # Skip resources with empty/None/invalid IDs
        if not resource_id or not isinstance(resource_id, str) or not resource_id.strip():
            continue
        
        # Handle Step Functions state machines
        if resource_type == 'AwsStatesStateMachine':
            # Extract state machine name from ARN
            # arn:aws:states:region:account:stateMachine:StateMachineName
            state_machine_name = 'UnknownStateMachine'
            if ':stateMachine:' in resource_id:
                state_machine_name = resource_id.split(':stateMachine:')[-1]
            
            print(f"SERVICE DETECTED: Step Functions state machine: {state_machine_name}")
            print(f"Resource ARN: {resource_id}")
            
            return {
                'service_type': 'stepfunctions',
                'state_machine_name': state_machine_name,
                'state_machine_arn': resource_id,
                'enrichment_enabled': True,
                'detection_method': 'resource_arn'
            }
        
        # Handle Lambda functions
        elif resource_type == 'AwsLambdaFunction':
            # Extract function name from ARN
            # arn:aws:lambda:region:account:function:FunctionName
            function_name = 'UnknownFunction'
            if ':function:' in resource_id:
                function_name = resource_id.split(':function:')[-1]
                # Handle versioned function ARNs (function:name:version)
                if ':' in function_name:
                    function_name = function_name.split(':')[0]
            
            print(f"SERVICE DETECTED: Lambda function: {function_name}")
            print(f"Resource ARN: {resource_id}")
            
            return {
                'service_type': 'lambda',
                'function_name': function_name,
                'function_arn': resource_id,
                'enrichment_enabled': True,
                'detection_method': 'resource_arn'
            }
    
    # No supported resource found in Resources array - skip enrichment
    print("SERVICE DETECTION FAILED: No supported resource types found in ASFF Resources array")
    print(f"Available resources: {[r.get('Type', 'Unknown') for r in resources if isinstance(r, dict)]}")
    return {
        'service_type': 'generic',
        'enrichment_enabled': False,
        'error': 'No supported resource types found in ASFF Resources array',
        'detection_method': 'none'
    }


def enrich_stepfunctions_context(finding: Dict[str, Any], service_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich Step Functions alarm with execution details and failure context.
    
    Args:
        finding: ASFF finding data
        service_context: Service-specific context
        
    Returns:
        Enriched context with execution details and logs
    """
    account_id = finding.get('AwsAccountId')
    # Region must come from finding - no defaults
    region = finding.get('Region')
    if not region:
        raise ValueError(f"Region not found in finding: {finding.get('Id', 'Unknown')}")
    state_machine_name = service_context.get('state_machine_name', 'Unknown')
    
    enrichment = {
        'failed_executions': [],
        'alarm_correlation': {
            'evaluation_window': calculate_incident_time_window(get_incident_timestamp(finding)),
            'total_executions_in_window': 0
        }
    }
    
    try:
        # Use the actual state machine ARN from the service context
        state_machine_arn = service_context.get('state_machine_arn')
        if not state_machine_arn:
            # Fallback: build ARN from state machine name if not available
            state_machine_arn = f"arn:aws:states:{region}:{account_id}:stateMachine:{state_machine_name}"
        
        # Find failed executions within the alarm evaluation window
        failed_executions = list_executions_in_window(
            state_machine_arn, 
            enrichment['alarm_correlation']['evaluation_window'], 
            account_id, 
            region
        )
        
        enrichment['alarm_correlation']['total_executions_in_window'] = len(failed_executions)
        
        # Get detailed information for each failed execution
        stepfunctions_client = get_client('stepfunctions', account_id, region)
        
        for execution in failed_executions:
            execution_arn = execution['executionArn']
            
            try:
                # Get execution details and history
                execution_details = stepfunctions_client.describe_execution(executionArn=execution_arn)
                # Newest first: the failure is at the end of the history, so a long history cannot hide it
                execution_history = stepfunctions_client.get_execution_history(
                    executionArn=execution_arn, reverseOrder=True, maxResults=1000)
                
                # Extract failure details from execution history
                failure_details = extract_execution_failure_details(execution_history)
                
                # Get CloudWatch Logs for failed Lambda functions if any
                logs_summary = ""
                if failure_details.get('failed_lambda_arn'):
                    logs_client = get_client('logs', account_id, region)
                    logs_summary = extract_lambda_logs_summary(logs_client, failure_details['failed_lambda_arn'], get_incident_timestamp(finding))
                
                enrichment['failed_executions'].append({
                    'execution_arn': execution_arn,
                    'failure_details': failure_details,
                    'logs_summary': logs_summary,
                    'execution_status': execution_details.get('status', 'UNKNOWN'),
                    'start_date': execution_details.get('startDate', '').isoformat() if execution_details.get('startDate') else '',
                    'stop_date': execution_details.get('stopDate', '').isoformat() if execution_details.get('stopDate') else ''
                })
                
            except Exception as e:
                # If we can't get execution details for this specific execution, continue with others
                print(f"Could not retrieve execution details for {execution_arn}: {str(e)}")
            
    except Exception as e:
        print(f"Step Functions enrichment failed: {str(e)}")
        # Return basic enrichment structure even on failure
        
    return enrichment


def enrich_lambda_context(finding: Dict[str, Any], service_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich Lambda function alarm with invocation details and error logs.
    
    Args:
        finding: ASFF finding data
        service_context: Service-specific context
        
    Returns:
        Enriched context with invocation details and logs
    """
    account_id = finding.get('AwsAccountId')
    # Region must come from finding - no defaults
    region = finding.get('Region')
    if not region:
        raise ValueError(f"Region not found in finding: {finding.get('Id', 'Unknown')}")
    function_name = service_context.get('function_name', 'Unknown')
    
    enrichment = {
        'failed_executions': [],
        'alarm_correlation': {
            'evaluation_window': calculate_incident_time_window(get_incident_timestamp(finding)),
            'total_invocations_in_window': 0
        }
    }
    
    try:
        # Get CloudWatch Logs client for Lambda function logs
        logs_client = get_client('logs', account_id, region)
        
        # Use the actual Lambda ARN from service context (provided by alarm generator)
        lambda_arn = service_context.get('function_arn')
        if not lambda_arn:
            # Fallback: construct ARN if not available (should not happen with fixed alarm generator)
            lambda_arn = f"arn:aws:lambda:{region}:{account_id}:function:{function_name}"
        
        logs_summary = extract_lambda_logs_summary(logs_client, lambda_arn, get_incident_timestamp(finding))
        
        if logs_summary and 'No ERROR logs found' not in logs_summary:
            enrichment['failed_executions'].append({
                'function_arn': lambda_arn,
                'failure_details': {
                    'error_type': 'LambdaError',
                    'error_cause': 'See logs_summary for details'
                },
                'logs_summary': logs_summary,
                'invocation_type': 'ERROR'
            })
            
    except Exception as e:
        print(f"Lambda enrichment failed: {str(e)}")
        # Return basic enrichment structure even on failure
        
    return enrichment


def analyze_incident_patterns(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze historical incident patterns for similar alarm types.
    
    Args:
        finding: ASFF finding data
        
    Returns:
        Pattern analysis including frequency, trends, and classification
    """
    try:
        # Earlier incidents of the same alarm: for alarm findings, GeneratorId is the alarm name,
        # and Remember Incident Opened records it with each incident
        generator_id = finding.get('GeneratorId') or finding.get('Title', '')

        retention_days = int(os.environ.get('INCIDENT_EXPIRATION_DAYS', '365'))
        historical_incidents = query_dynamodb_incidents(generator_id, retention_days)
        
        # Classify the incident pattern based on historical data
        pattern_classification = classify_incident_pattern(historical_incidents)
        
        return {
            'historical_incidents': historical_incidents,
            'pattern_classification': pattern_classification,
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'generator_id_analyzed': generator_id,
            'retention_period_days': retention_days
        }
        
    except Exception as e:
        print(f"Pattern analysis failed: {str(e)}")
        return {
            'historical_incidents': [],
            'pattern_classification': {
                'pattern_type': 'analysis_failed',
                'error': str(e)
            },
            'analysis_timestamp': datetime.now(timezone.utc).isoformat()
        }


def get_incident_timestamp(finding: Dict[str, Any]) -> str:
    """
    Get the most accurate incident timestamp from Security Hub finding.
    
    Priority:
    1. FirstObservedAt - when the alarm condition was first detected
    2. LastObservedAt - when the alarm condition was most recently observed
    3. CreatedAt - when the Security Hub finding was created (fallback)
    
    Args:
        finding: ASFF Security Hub finding data
        
    Returns:
        ISO 8601 timestamp string
    """
    # Try FirstObservedAt first (actual detection time)
    first_observed = finding.get('FirstObservedAt')
    if first_observed:
        return first_observed
    
    # Fallback to LastObservedAt if available
    last_observed = finding.get('LastObservedAt')
    if last_observed:
        return last_observed
    
    # Final fallback to CreatedAt (finding creation time)
    created_at = finding.get('CreatedAt', '')
    return created_at


def calculate_incident_time_window(incident_time: str) -> Dict[str, Any]:
    """
    Calculate time window for data collection based on incident timestamp.
    
    Uses a 15-minute lookback window to find the first ERROR log entry.
    
    Args:
        incident_time: ISO 8601 timestamp from ASFF FirstObservedAt/LastObservedAt/CreatedAt field
        
    Returns:
        Time window with start/end times for data collection
    """
    # Handle empty or missing timestamp gracefully
    if not incident_time:
        # Use current time as fallback for missing timestamps
        incident_dt = datetime.now(timezone.utc)
    else:
        try:
            from dateutil import parser
            # Use dateutil parser for robust timestamp parsing
            incident_dt = parser.parse(incident_time)
            # Ensure timezone-aware datetime in UTC
            if incident_dt.tzinfo is None:
                incident_dt = incident_dt.replace(tzinfo=timezone.utc)
            else:
                incident_dt = incident_dt.astimezone(timezone.utc)
        except Exception as e:
            print(f"Warning: Failed to parse incident timestamp '{incident_time}': {e}. Using current time.")
            incident_dt = datetime.now(timezone.utc)
    
    # Use appropriate lookback window based on service type
    # Step Functions typically need longer windows due to execution duration
    lookback_seconds = 900  # 15-minute window for Step Functions and Lambda failures
    
    return {
        'start_time': (incident_dt - timedelta(seconds=lookback_seconds)).isoformat(),
        'end_time': incident_dt.isoformat()  # Use incident time or current time as end
    }


INCIDENTS_BY_GENERATOR_INDEX = 'GeneratorId-opened_at-index'


def query_dynamodb_incidents(generator_id: str, retention_days: int) -> List[Dict[str, Any]]:
    """
    Earlier incidents with this GeneratorId within the retention period, newest first.

    Uses the attributes Remember Incident Opened records: GeneratorId (the alarm name, for alarm
    findings) and opened_at (ISO 8601 UTC). A failing query raises, so the caller reports the
    analysis as failed instead of as "no history".

    Args:
        generator_id: GeneratorId of the finding
        retention_days: Days to look back for incidents

    Returns:
        Incidents as {incident_id, opened_at, severity, ticket_id}, at most 50
    """
    incidents_table_name = os.environ.get('INCIDENTS_TABLE_NAME', 'soar-incidents')

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=retention_days)

    response = dynamodb_client.query(
        TableName=incidents_table_name,
        IndexName=INCIDENTS_BY_GENERATOR_INDEX,
        KeyConditionExpression='GeneratorId = :generator_id AND opened_at BETWEEN :start AND :end',
        ExpressionAttributeValues={
            ':generator_id': {'S': generator_id},
            ':start': {'S': start.isoformat()},
            ':end': {'S': end.isoformat()}
        },
        ScanIndexForward=False,  # Most recent first
        Limit=50  # Reasonable limit for pattern analysis
    )

    return [
        {
            'incident_id': item.get('id', {}).get('S', ''),
            'opened_at': item.get('opened_at', {}).get('S', ''),
            'severity': item.get('severity_label', {}).get('S', 'UNKNOWN'),
            'ticket_id': item.get('ticket_id', {}).get('S', ''),
        }
        for item in response.get('Items', [])
    ]


OCCURRENCE_WINDOWS_DAYS = (7, 30, 90, 365)


def classify_incident_pattern(incidents: List[Dict[str, Any]], now: datetime = None) -> Dict[str, Any]:
    """
    How often, and when, earlier incidents of the same alarm occurred.

    Reports only what the incidents table records, which is when each incident was opened.
    Nothing records how or when incidents were resolved, so there are no resolution times,
    auto-resolution rates, trends or recommendations.

    pattern_type by the number of earlier incidents: 0 no_history, 1 isolated_occurrence,
    2 infrequent_recurring, 3-6 moderate_recurring, 7 or more frequent_recurring.
    The query returns at most 50 incidents, so the counts stop at 50.

    Args:
        incidents: Earlier incidents, each with an ISO 8601 opened_at
        now: Reference time for the occurrence windows (default: the current time)

    Returns:
        pattern_type, total_incidents_analyzed, occurrences per window, first and last occurrence
    """
    now = now or datetime.now(timezone.utc)
    count = len(incidents)

    if count == 0:
        pattern_type = 'no_history'
    elif count == 1:
        pattern_type = 'isolated_occurrence'
    elif count == 2:
        pattern_type = 'infrequent_recurring'
    elif count < 7:
        pattern_type = 'moderate_recurring'
    else:
        pattern_type = 'frequent_recurring'

    opened = []
    for incident in incidents:
        try:
            opened_at = datetime.fromisoformat(incident.get('opened_at', ''))
        except (TypeError, ValueError):
            continue  # an unreadable date still counts in the total, but in no window
        if opened_at.tzinfo is None:
            opened_at = opened_at.replace(tzinfo=timezone.utc)
        opened.append(opened_at)

    return {
        'pattern_type': pattern_type,
        'total_incidents_analyzed': count,
        'occurrences': {
            f'last_{days}_days': sum(1 for t in opened if t >= now - timedelta(days=days))
            for days in OCCURRENCE_WINDOWS_DAYS
        },
        'first_occurrence': min(opened).isoformat() if opened else None,
        'last_occurrence': max(opened).isoformat() if opened else None,
    }


def extract_execution_failure_details(execution_history: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract failure details from Step Functions execution history.
    
    Args:
        execution_history: Step Functions execution history response
        
    Returns:
        Failure details including error type, cause, and failed resources
    """
    failure_details = {
        'error_type': 'Unknown',
        'error_cause': 'Unknown',
        'failed_lambda_arn': None,
        'failure_step': 'Unknown'
    }
    
    # Oldest first, whatever order the history was read in
    events = sorted(execution_history.get('events', []), key=lambda e: e.get('id', 0))
    by_id = {event.get('id'): event for event in events}

    # The last failure of a state is the one that ended the execution (earlier ones were retried or caught)
    state_failure = None
    execution_failure = None
    for event in events:
        if event.get('type') in STATE_FAILURE_DETAILS:
            state_failure = event
        elif event.get('type') in EXECUTION_FAILURE_DETAILS:
            execution_failure = event

    failure = state_failure or execution_failure
    if failure is None:
        return failure_details

    details = failure.get({**STATE_FAILURE_DETAILS, **EXECUTION_FAILURE_DETAILS}[failure['type']], {})
    failure_details['error_type'] = details.get('error') or failure['type']
    failure_details['error_cause'] = details.get('cause') or 'Unknown cause'

    if state_failure is not None:
        scheduled, state_name = _origin_of_failure(state_failure, by_id)
        failure_details['failed_lambda_arn'] = _failed_lambda(state_failure, scheduled)
        if state_name:
            failure_details['failure_step'] = state_name

    return failure_details


# Failure events of a state, and the field holding their error and cause (Step Functions API model).
# A Lambda state written as `Resource: <function ARN>` records LambdaFunction* events; service
# integrations, including `arn:aws:states:::lambda:invoke`, record Task* events.
STATE_FAILURE_DETAILS = {
    'LambdaFunctionFailed': 'lambdaFunctionFailedEventDetails',
    'LambdaFunctionTimedOut': 'lambdaFunctionTimedOutEventDetails',
    'LambdaFunctionStartFailed': 'lambdaFunctionStartFailedEventDetails',
    'LambdaFunctionScheduleFailed': 'lambdaFunctionScheduleFailedEventDetails',
    'TaskFailed': 'taskFailedEventDetails',
    'TaskTimedOut': 'taskTimedOutEventDetails',
    'TaskStartFailed': 'taskStartFailedEventDetails',
    'TaskSubmitFailed': 'taskSubmitFailedEventDetails',
}
EXECUTION_FAILURE_DETAILS = {
    'ExecutionFailed': 'executionFailedEventDetails',
    'ExecutionTimedOut': 'executionTimedOutEventDetails',
    'ExecutionAborted': 'executionAbortedEventDetails',
}


def _origin_of_failure(failure: Dict[str, Any], by_id: Dict[Any, Dict[str, Any]]):
    """Follow previousEventId back from a failure to its scheduling event and the state it belongs to."""
    scheduled = None
    event = by_id.get(failure.get('previousEventId'))
    for _ in range(100):
        if event is None:
            break
        event_type = event.get('type', '')
        if scheduled is None and event_type in ('LambdaFunctionScheduled', 'TaskScheduled'):
            scheduled = event
        if event_type.endswith('StateEntered'):
            return scheduled, event.get('stateEnteredEventDetails', {}).get('name')
        event = by_id.get(event.get('previousEventId'))
    return scheduled, None


def _failed_lambda(failure: Dict[str, Any], scheduled: Dict[str, Any]):
    """The ARN or name of the Lambda function that failed, or None when the failing state was no Lambda."""
    if failure['type'].startswith('LambdaFunction'):
        if scheduled and scheduled.get('type') == 'LambdaFunctionScheduled':
            return scheduled.get('lambdaFunctionScheduledEventDetails', {}).get('resource')
        return None

    details = failure.get(STATE_FAILURE_DETAILS[failure['type']], {})
    if details.get('resourceType') != 'lambda':
        return None  # a DynamoDB, SNS or other service step: no Lambda logs to read
    resource = details.get('resource', '')
    if resource.startswith('arn:aws:lambda:'):
        return resource
    if scheduled and scheduled.get('type') == 'TaskScheduled':
        try:
            parameters = json.loads(scheduled.get('taskScheduledEventDetails', {}).get('parameters') or '{}')
        except ValueError:
            return None
        return parameters.get('FunctionName')
    return None


def list_executions_in_window(state_machine_arn: str, evaluation_window: Dict[str, Any], 
                             account_id: str, region: str) -> List[Dict[str, Any]]:
    """
    List Step Functions executions within the alarm evaluation window.
    
    Args:
        state_machine_arn: ARN of the Step Functions state machine
        evaluation_window: Time window with start_time and end_time
        account_id: AWS account ID for cross-account access
        region: AWS region
        
    Returns:
        List of executions within the evaluation window
    """
    try:
        stepfunctions_client = get_client('stepfunctions', account_id, region)
        
        # List failed executions (we focus on failed ones for alarm analysis)
        response = stepfunctions_client.list_executions(
            stateMachineArn=state_machine_arn,
            statusFilter='FAILED',
            maxResults=100
        )
        
        executions = response.get('executions', [])
        
        # Filter executions to those within the evaluation window
        return filter_failed_executions_in_window(executions, evaluation_window)
        
    except Exception as e:
        print(f"Failed to list executions for {state_machine_arn}: {str(e)}")
        return []


def filter_failed_executions_in_window(executions: List[Dict[str, Any]], 
                                     evaluation_window: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Filter executions to only failed ones within the time window.
    
    Args:
        executions: List of Step Functions executions
        evaluation_window: Time window with start_time and end_time
        
    Returns:
        List of failed executions within the time window
    """
    from dateutil.parser import parse
    
    start_time = parse(evaluation_window['start_time'])
    end_time = parse(evaluation_window['end_time'])
    
    filtered_executions = []
    for execution in executions:
        # Only include failed executions
        if execution.get('status') != 'FAILED':
            continue
            
        # An execution belongs to the window when it failed inside it, wherever it started.
        # stopDate is when it failed; startDate only stands in when stopDate is missing.
        failed_at = execution.get('stopDate') or execution.get('startDate')
        if failed_at:
            # Handle both datetime objects and ISO strings
            if isinstance(failed_at, str):
                failed_at = parse(failed_at)
            if start_time <= failed_at <= end_time:
                filtered_executions.append(execution)
    
    return filtered_executions


def extract_lambda_logs_summary(logs_client, lambda_arn: str, incident_time: str) -> str:
    """
    Extract the first ERROR log entry from Lambda function logs.
    
    Searches backwards 15 minutes from incident time for the first ERROR log entry.
    
    FUTURE ENHANCEMENT: For better correlation precision in high-volume scenarios:
    - Use Execution ARN from Step Functions to match specific Lambda invocations
    - Extract Request ID from Lambda logs for exact correlation
    - Use Log Stream Name timestamps for precise execution matching
    - Consider tighter temporal windows (30-60 seconds) for high-precision correlation
    - Match CloudWatch alarm dimensions to specific execution context
    
    Current approach is sufficient for most scenarios - if we have 100K+ incidents,
    correlation precision is less critical than overall system functionality.
    
    Args:
        logs_client: CloudWatch Logs client
        lambda_arn: Lambda function ARN
        incident_time: ISO 8601 timestamp from ASFF CreatedAt field
        
    Returns:
        First ERROR log entry or appropriate message
    """
    try:
        # Extract function name from ARN
        function_name = lambda_arn.split(':')[-1] if lambda_arn else 'unknown'
        log_group_name = f"/aws/lambda/{function_name}"
        
        # Use incident time with appropriate lookback window
        try:
            from dateutil import parser
            incident_dt = parser.parse(incident_time)
            if incident_dt.tzinfo is None:
                incident_dt = incident_dt.replace(tzinfo=timezone.utc)
            else:
                incident_dt = incident_dt.astimezone(timezone.utc)
        except Exception as e:
            print(f"Warning: Failed to parse incident timestamp for logs '{incident_time}': {e}. Using current time.")
            incident_dt = datetime.now(timezone.utc)
        lookback_seconds = 900  # 15-minute window for Lambda error correlation
        
        end_time = int(incident_dt.timestamp() * 1000)
        start_time = int((incident_dt - timedelta(seconds=lookback_seconds)).timestamp() * 1000)
        
        # Search specifically for ERROR entries
        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            startTime=start_time,
            endTime=end_time,
            filterPattern='ERROR'
        )
        
        # Find the first (most recent) ERROR entry
        events = response.get('events', [])
        if events:
            # Events are returned in chronological order, take the first one
            first_error = events[0]
            return first_error.get('message', '').strip()
        
        return 'No ERROR logs found in 15-minute window'
        
    except Exception as e:
        return f"Could not retrieve logs: {str(e)}"