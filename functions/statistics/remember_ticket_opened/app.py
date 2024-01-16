import os
import boto3
from datetime import datetime, timezone


TICKETS_TABLE_NAME = os.environ['TICKETS_TABLE_NAME']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TICKETS_TABLE_NAME)


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

    return True
