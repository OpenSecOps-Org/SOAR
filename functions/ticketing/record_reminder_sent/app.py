import os
import boto3

TICKETS_TABLE = os.environ['TICKETS_TABLE']

dynamodb = boto3.resource('dynamodb')
tickets = dynamodb.Table(TICKETS_TABLE)


# Lambda handler
def lambda_handler(data, _context):
    print(data)
    add_to_ticket(data, "Yes")
    return True



def add_to_ticket(ticket, reminder_sent_value):
    """
    Adds 'reminder_sent' field to a ticket with the given id.
    
    :param ticket: The ticket dictionary containing at least the 'id' key.
    :param reminder_sent_value: The numeric value to set for the 'reminder_sent' field.
    """
    ticket_id = ticket['id']
    update_response = tickets.update_item(
        Key={'id': ticket_id},
        UpdateExpression='SET reminder_sent = :val',
        ExpressionAttributeValues={
            ':val': reminder_sent_value
        },
        ReturnValues='UPDATED_NEW'
    )
    return update_response

