import os
import boto3
from datetime import datetime, timezone, timedelta
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

INCIDENTS_TABLE_NAME = os.environ['INCIDENTS_TABLE_NAME']
EXPIRATION_DAYS = int(os.environ['EXPIRATION_DAYS'])
METRIC_NAMESPACE = os.environ['METRIC_NAMESPACE']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(INCIDENTS_TABLE_NAME)
cloudwatch_client = boto3.client('cloudwatch')


def lambda_handler(event, _context):
    logger.info(event)
    
    current_time = datetime.now(timezone.utc)
    
    # Calculate expire_at timestamp for TTL (epoch time)
    expire_at = int((current_time + timedelta(days=EXPIRATION_DAYS)).timestamp())
    
    item = {
        'id': event['Id'],
        'Account': event['Account'],
        'IncidentType': event['IncidentType'],
        'Title': event['Title'],
        'Description': event['Description'],
        'Environment': event['Environment'],
        'Team': event['Team'],
        'ProjectId': event['ProjectId'],
        'ProjectIdApp': event['ProjectIdApp'],
        'severity_label': event['SeverityLabel'],
        'penalty_score': event['PenaltyScore'],
        'opened_at': current_time.isoformat(),
        'ticket_id': event['TicketId'],
        'expire_at': expire_at,
        'dummy': 'dummy'  # This attribute helps with certain query patterns
    }
    
    table.put_item(Item=item)
    

    # CloudWatch metrics, main one
    emit_cloudwatch_metric(
        metric_name='Incident',
        metric_value=1,
        dimension_name='Action',
        dimension_value='Processed'
    )

    # In four different dimensions
    emit_cloudwatch_metric(
        metric_name='IncidentsByAccount',
        metric_value=1,
        dimension_name='Account',
        dimension_value=event['Account']
    )

    emit_cloudwatch_metric(
        metric_name='IncidentsByEnvironment',
        metric_value=1,
        dimension_name='Environment',
        dimension_value=event['Environment']
    )

    emit_cloudwatch_metric(
        metric_name='IncidentsBySeverity',
        metric_value=1,
        dimension_name='Severity',
        dimension_value=event['SeverityLabel']
    )

    emit_cloudwatch_metric(
        metric_name='IncidentsByTeam',
        metric_value=1,
        dimension_name='Team',
        dimension_value=event['Team']
    )


    return True


# ----------------------------------------------------------------
#
#   CloudWatch metrics
#
# ----------------------------------------------------------------

def emit_cloudwatch_metric(metric_name, metric_value, dimension_name, dimension_value):
    """
    Emit a single data point to CloudWatch with a specified dimension.

    :param metric_name: The name of the metric.
    :param metric_value: The value for the metric.
    :param dimension_name: The name of the dimension.
    :param dimension_value: The value for the dimension.
    """
    cloudwatch_client.put_metric_data(
        Namespace=METRIC_NAMESPACE,       # 'DelegatSOAR' as passed in via an ENV var
        MetricData=[
            {
                'MetricName': metric_name,
                'Dimensions': [
                    {
                        'Name': dimension_name,
                        'Value': dimension_value
                    },
                ],
                'Value': metric_value,
                'Unit': 'Count'
            },
        ]
    )
    print(f"Metric emitted: {metric_name} - {dimension_name}: {dimension_value}, Value: {metric_value}")
