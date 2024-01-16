import os
import boto3
from datetime import datetime, timezone, timedelta
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

TICKETS_TABLE_NAME = os.environ['TICKETS_TABLE_NAME']
EXPIRATION_DAYS = int(os.environ['EXPIRATION_DAYS'])  # Read EXPIRATION_DAYS env var and convert to integer

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TICKETS_TABLE_NAME)


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

    return True
