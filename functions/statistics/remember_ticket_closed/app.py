import os
import boto3
from datetime import datetime, timezone, timedelta
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

TICKETS_TABLE_NAME = os.environ['TICKETS_TABLE_NAME']
EXPIRATION_DAYS = int(os.environ['EXPIRATION_DAYS'])  # Read EXPIRATION_DAYS env var and convert to integer
METRIC_NAMESPACE = os.environ['METRIC_NAMESPACE']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TICKETS_TABLE_NAME)
cloudwatch_client = boto3.client('cloudwatch')


def lambda_handler(event, _context):
    logger.info(event)

    # Fetch the current UTC time and the ticket by its "id"
    current_time = datetime.now(timezone.utc)
    ticket_id = event['Id']

    response = table.get_item(Key={'id': ticket_id})
    if 'Item' not in response:
        logger.warning(f"Ticket with ID {ticket_id} not found")
        return True

    ticket = response['Item']
    account = ticket['Account']

    # If the ticket is already closed, do nothing.
    if not ticket['closed_at'].startswith("NULL#"):
        logger.info(f"Ticket with ID {ticket_id} is already closed")
        return True

    # Calculate duration in seconds
    closed_at = f"{current_time.isoformat()}#{account}"
    opened_at = datetime.fromisoformat(ticket['opened_at'])
    duration_sec = int((current_time - opened_at).total_seconds())

    # Calculate expire_at timestamp for TTL (epoch time)
    expire_at = int((current_time + timedelta(days=EXPIRATION_DAYS)).timestamp())

    # Update the ticket
    update_expression = "SET closed_at = :closed_at, duration_sec = :duration_sec, expire_at = :expire_at"
    expression_attribute_values = {
        ':closed_at': closed_at,
        ':duration_sec': duration_sec,
        ':expire_at': expire_at  # Set expire_at attribute
    }

    table.update_item(
        Key={'id': ticket_id},
        UpdateExpression=update_expression,
        ExpressionAttributeValues=expression_attribute_values
    )

    emit_cloudwatch_metric(
        metric_name='Ticket',
        metric_value=1,
        dimension_name='Action',
        dimension_value='Closed'
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
