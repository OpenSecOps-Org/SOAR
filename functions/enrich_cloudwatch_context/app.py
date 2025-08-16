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

import os
import boto3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any

# Import aws_utils for cross-account client creation
from aws_utils.clients import get_client

# Initialize DynamoDB client at module level for reuse across invocations
dynamodb_client = boto3.client('dynamodb')


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
                execution_history = stepfunctions_client.get_execution_history(executionArn=execution_arn)
                
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
        
        # For Lambda functions, we primarily get information from CloudWatch Logs
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
        # Extract alarm type from finding title for pattern matching
        alarm_title = finding.get('Title', '')
        # Remove severity suffix to get base alarm type for pattern matching
        alarm_type = '-'.join(alarm_title.split('-')[:-1]) if '-' in alarm_title else alarm_title
        
        # Query historical incidents for this alarm type
        retention_days = int(os.environ.get('INCIDENT_EXPIRATION_DAYS', '365'))
        historical_incidents = query_dynamodb_incidents(alarm_type, retention_days)
        
        # Classify the incident pattern based on historical data
        pattern_classification = classify_incident_pattern(historical_incidents)
        
        return {
            'historical_incidents': historical_incidents,
            'pattern_classification': pattern_classification,
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'alarm_type_analyzed': alarm_type,
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


def query_dynamodb_incidents(alarm_type: str, retention_days: int) -> List[Dict[str, Any]]:
    """
    Query DynamoDB incidents table for historical pattern analysis.
    
    Args:
        alarm_type: Type of alarm for pattern matching
        retention_days: Days to look back for incidents
        
    Returns:
        List of similar incidents within retention period
    """
    try:
        # Get table name from environment
        incidents_table_name = os.environ.get('INCIDENTS_TABLE_NAME', 'soar-incidents')
        
        # Use module-level DynamoDB client (runs in current region)
        
        # Calculate time range for query
        end_time = int(datetime.now(timezone.utc).timestamp())
        start_time = end_time - (retention_days * 24 * 60 * 60)  # retention_days ago
        
        # Query DynamoDB using GSI for alarm_type
        response = dynamodb_client.query(
            TableName=incidents_table_name,
            IndexName='alarm-type-timestamp-index',
            KeyConditionExpression='alarm_type = :alarm_type AND #ts BETWEEN :start_time AND :end_time',
            ExpressionAttributeNames={
                '#ts': 'timestamp'
            },
            ExpressionAttributeValues={
                ':alarm_type': {'S': alarm_type},
                ':start_time': {'N': str(start_time)},
                ':end_time': {'N': str(end_time)}
            },
            ScanIndexForward=False,  # Most recent first
            Limit=50  # Reasonable limit for pattern analysis
        )
        
        # Convert DynamoDB items to standard format
        incidents = []
        for item in response.get('Items', []):
            incident = {
                'incident_id': item.get('incident_id', {}).get('S', ''),
                'alarm_type': item.get('alarm_type', {}).get('S', ''),
                'timestamp': int(item.get('timestamp', {}).get('N', '0')),
                'severity': item.get('severity', {}).get('S', 'UNKNOWN'),
                'resolution_time_minutes': int(item.get('resolution_time_minutes', {}).get('N', '0')),
                'auto_resolved': item.get('auto_resolved', {}).get('BOOL', False)
            }
            incidents.append(incident)
        
        return incidents
        
    except Exception as e:
        print(f"Failed to query DynamoDB incidents: {str(e)}")
        return []


def classify_incident_pattern(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Classify incident pattern based on frequency and trends.
    
    Args:
        incidents: List of historical incidents
        
    Returns:
        Pattern classification and trend analysis
    """
    if not incidents:
        return {
            'pattern_type': 'no_history',
            'frequency_score': 0,
            'auto_resolution_rate': 0.0,
            'avg_resolution_time_minutes': 0,
            'trend': 'unknown',
            'recommendation': 'establish_baseline'
        }
    
    # Calculate frequency score (number of incidents)
    frequency_score = len(incidents)
    
    # Calculate auto-resolution rate
    auto_resolved_count = sum(1 for incident in incidents if incident.get('auto_resolved', False))
    auto_resolution_rate = auto_resolved_count / len(incidents) if incidents else 0.0
    
    # Calculate average resolution time
    resolution_times = [incident.get('resolution_time_minutes', 0) for incident in incidents]
    avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0
    avg_resolution_time = round(avg_resolution_time, 2)
    
    # Determine trend based on resolution time variance
    if len(resolution_times) > 1:
        # Calculate variance to determine trend stability
        mean_time = avg_resolution_time
        variance = sum((x - mean_time) ** 2 for x in resolution_times) / len(resolution_times)
        std_dev = variance ** 0.5
        
        # If standard deviation is small relative to mean, trend is stable
        coefficient_of_variation = std_dev / mean_time if mean_time > 0 else 0
        if coefficient_of_variation < 0.3:
            trend = 'stable'
        elif coefficient_of_variation < 0.6:
            trend = 'variable'
        else:
            trend = 'unstable'
    else:
        trend = 'unknown'
    
    # Classify pattern type based on frequency and characteristics
    if frequency_score == 1:
        pattern_type = 'isolated_occurrence'
        recommendation = 'investigate_thoroughly'
    elif frequency_score >= 7:  # High frequency (7+ incidents in retention period)
        pattern_type = 'frequent_recurring'
        if auto_resolution_rate >= 0.8:
            recommendation = 'monitor_for_root_cause'
        else:
            recommendation = 'improve_automation'
    elif frequency_score >= 3:  # Medium frequency
        pattern_type = 'moderate_recurring'
        if auto_resolution_rate >= 0.5:
            recommendation = 'optimize_response_time'
        else:
            recommendation = 'enhance_automation'
    else:  # Low frequency (2-3 incidents)
        pattern_type = 'infrequent_recurring'
        recommendation = 'document_resolution_steps'
    
    return {
        'pattern_type': pattern_type,
        'frequency_score': frequency_score,
        'auto_resolution_rate': auto_resolution_rate,
        'avg_resolution_time_minutes': avg_resolution_time,
        'trend': trend,
        'recommendation': recommendation,
        'total_incidents_analyzed': len(incidents),
        'analysis_period_days': 30  # Based on retention period
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
    
    events = execution_history.get('events', [])
    for event in events:
        event_type = event.get('type', '')
        
        if event_type == 'TaskFailed':
            task_failed = event.get('taskFailedEventDetails', {})
            failure_details['error_type'] = task_failed.get('error', 'TaskFailed')
            failure_details['error_cause'] = task_failed.get('cause', 'Unknown cause')
            failure_details['failed_lambda_arn'] = task_failed.get('resource', '')
            failure_details['failure_step'] = task_failed.get('resourceType', 'Unknown')
            
        elif event_type == 'ExecutionFailed':
            exec_failed = event.get('executionFailedEventDetails', {})
            failure_details['error_type'] = exec_failed.get('error', 'ExecutionFailed')
            failure_details['error_cause'] = exec_failed.get('cause', 'Unknown cause')
    
    return failure_details


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
            
        # Check if execution start time is within the evaluation window
        start_date = execution.get('startDate')
        if start_date:
            # Handle both datetime objects and ISO strings
            if isinstance(start_date, str):
                execution_start = parse(start_date)
            else:
                execution_start = start_date
                
            # Include if execution started within the evaluation window
            if start_time <= execution_start <= end_time:
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