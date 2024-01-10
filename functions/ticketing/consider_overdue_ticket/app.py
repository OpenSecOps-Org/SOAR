

# Lambda handler
def lambda_handler(data, _context):
    print(data)

    # Send only one reminder
    if data.get('reminder_sent'):
        return "No"

    # No reminder sent, send one
    return "Yes"



# def add_to_ticket(ticket, reminder_sent_value):
#     """
#     Adds 'reminder_sent' field to a ticket with the given id.
    
#     :param ticket: The ticket dictionary containing at least the 'id' key.
#     :param reminder_sent_value: The numeric value to set for the 'reminder_sent' field.
#     """
#     ticket_id = ticket['id']
#     update_response = tickets.update_item(
#         Key={'id': ticket_id},
#         UpdateExpression='SET reminder_sent = :val',
#         ExpressionAttributeValues={
#             ':val': reminder_sent_value
#         },
#         ReturnValues='UPDATED_NEW'
#     )
#     return update_response

