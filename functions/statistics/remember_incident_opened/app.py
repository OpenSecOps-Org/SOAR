import os
import boto3
from datetime import datetime, timezone, timedelta
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

INCIDENTS_TABLE_NAME = os.environ['INCIDENTS_TABLE_NAME']
EXPIRATION_DAYS = int(os.environ['EXPIRATION_DAYS'])

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(INCIDENTS_TABLE_NAME)


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
    
    return True
