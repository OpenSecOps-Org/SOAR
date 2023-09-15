import logging
from bs4 import BeautifulSoup

# Set the logging level to INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(data, context):
    account = data['account']
    account_data = data['bb']['account_map'][account]

    account_id = account_data['Id']

    account_email = account_data['Email']
    team_email = account_data['TeamEmail']
    app_email = account_data['TeamEmailApp']

    if not team_email and not app_email:
        recipients = account_email
    elif team_email == app_email:
        recipients = team_email
    else:
        recipients = f"{team_email},{app_email}"
    data['email_recipients'] = recipients

    data['email_title'] = f"Account '{account}' Delegat SOAR Weekly Security Report"

    html = data['messages']['report']['html']
    data['messages']['report']['html'] = ''

    soup = BeautifulSoup(html, 'html.parser')
    # Get the first h3 tag
    first_h3 = soup.find('h3')

    # Change the tag name to h2
    first_h3.name = 'h2'

    # Insert account_id before the closing tag
    first_h3.string = first_h3.text + ' (' + account_id + ')'

    data['email_html'] = '<div style="font-family: Verdana, sans-serif; font-size:16px;">'
    data['email_html'] += f"<h1>{data['email_title']}</h1>"
    data['email_html'] += str(soup)
    data['email_html'] += "</div>"

    # Return the blackboard
    return data

