import os
import boto3
from datetime import datetime, timezone


TICKETS_TABLE_NAME = os.environ['TICKETS_TABLE_NAME']
METRIC_NAMESPACE = os.environ['METRIC_NAMESPACE']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TICKETS_TABLE_NAME)
cloudwatch_client = boto3.client('cloudwatch')


def lambda_handler(event, _context):
    print(event)

    current_time = datetime.now(timezone.utc).isoformat()
    account = event['Account']
    
    item = {
        'id': event['Id'],
        'Account': account,
        'SecurityControlId': event['SecurityControlId'],
        'Title': event['Title'],
        'Environment': event['Environment'],
        'Team': event['Team'],
        'ProjectId': event['ProjectId'],
        'ProjectIdApp': event['ProjectIdApp'],
        'severity_label': event['SeverityLabel'],
        'penalty_score': event['PenaltyScore'],
        'opened_at': current_time,
        'closed_at': f"NULL#{current_time}",
        'ticket_id': event['TicketId'],
        'dummy': 'dummy'  # This attribute helps with certain query patterns
    }
    
    table.put_item(Item=item)

    emit_cloudwatch_metric(
        metric_name='Ticket',
        metric_value=1,
        dimension_name='Action',
        dimension_value='Opened'
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
