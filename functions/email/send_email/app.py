import os
import boto3
import re
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
import html2text
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get environment variables
SEND_EMAIL = os.environ['SEND_EMAIL']
EMAIL_SENDER = os.environ['EMAIL_SENDER']
EMAIL_CC = os.environ['EMAIL_CC'].split(',')
EMAIL_BCC = os.environ['EMAIL_BCC'].split(',')
EMAIL_RETURN_PATH = os.environ['EMAIL_RETURN_PATH']

client = boto3.client('ses')

def load_logo_image():
    with open('logos/128.png', 'rb') as f:
        logo_data = f.read()
    logo_image = MIMEImage(logo_data)
    logo_image.add_header('Content-ID', '<logo>')
    logo_image.add_header('Content-Disposition', 'inline')
    
    # Create HTML code to reference the logo inline
    logo_html = '''
<table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #030204; height: 128px;">
    <tr>
        <td style="padding-left: 18px;">
            <img src="cid:logo" alt="Delegat SOAR logo" style="height: 128px;">
        </td>
        <td style="font-family: Arial, sans-serif; font-weight: bold; font-size: 48px; text-align: right; color: #232144; vertical-align: bottom; padding-right: 18px; padding-bottom: 10px;">
            DELEGAT SOAR
        </td>
    </tr>
</table>
'''
    return logo_image, logo_html

LOGO_IMAGE, LOGO_HTML = load_logo_image()


def lambda_handler(data, _context):
    global EMAIL_CC  # This tells Python to use the global variable

    logger.info(data)

    if SEND_EMAIL == 'No':
        print("Email disabled.")
        return data

    extra_cc = data.get('AdditionalCC')
    if extra_cc:
        extra_cc = extra_cc.split(',')
        EMAIL_CC = EMAIL_CC + extra_cc

    logger.info('EMAIL_SENDER: %s', EMAIL_SENDER)
    logger.info('EMAIL_CC: %s', EMAIL_CC)
    logger.info('EMAIL_BCC: %s', EMAIL_BCC)
    logger.info('EMAIL_RETURN_PATH: %s', EMAIL_RETURN_PATH)

    recipients = data['Recipient']
    subject = data['Subject']
    if len(subject) > 100:
        subject = subject[:97] + '...'

    body = data.get('Body')
    html = data.get('Html')

    # If we were given a HtmlUri, get the data from that S3 bucket and object
    html_arn = data.get('HtmlArn')
    if html_arn:
        html = get_html_from_bucket(html_arn)
        body = None

    ai_plaintext = data.get('AiPlaintext')
    ai_html = data.get('AiHtml')

    ticket_id = data.get('TicketId', False)

    if ticket_id:
        body = body.replace('- - -', f"Ticket ID: {ticket_id}", 1)

    message = MIMEMultipart('mixed')
    message['Subject'] = subject
    message['From'] = EMAIL_SENDER
    message['To'] = recipients
    message['Cc'] = ','.join(EMAIL_CC)
    # message['Bcc'] = ','.join(EMAIL_BCC)
    message['Return-Path'] = EMAIL_RETURN_PATH

    # Always attach the logo image
    message.attach(LOGO_IMAGE)

    if html:
        if "<html" not in html:
            html = f"<html><head></head><body>{html}</body></html>"
        if not body:
            body = html2text.html2text(html)
    else:
        html = body_to_html(body, ai_plaintext, ai_html)

    html = html.replace("<body>", f"<body>{LOGO_HTML}")

    message.attach(MIMEText(html, 'html'))

    all_recipients = [email.strip() for email in (recipients.split(',') + EMAIL_CC + EMAIL_BCC) if email.strip()]

    response = client.send_raw_email(
        Source=EMAIL_SENDER,
        Destinations=all_recipients,
        RawMessage={
            'Data': message.as_string()
        }
    )
    logger.info(response)

    return data


def get_html_from_bucket(s3_uri):
    # Extract bucket name and object key from the URI
    uri_parts = s3_uri.split("/")
    bucket_name = uri_parts[-2].replace('arn:aws:s3:::', '')
    object_key = uri_parts[-1]

    # Create S3 client and fetch the object
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        # Get the content of the object and return as string
        return response['Body'].read().decode('utf-8')
    except Exception as e:
        logger.error(f"An error occurred while fetching object from S3: {e}")
        return None


html_pre = '''
<html>
  <head></head>
  <body>
    <div style="font-family: Verdana, sans-serif; font-size:16px;">
      <table border="0" cellspacing="0" cellpadding="0">
'''

html_post = '''
      </table>
    </div>
  </body>
</html>
'''


def body_to_html(body, _ai_plaintext, ai_html):
    body = body.replace("\n\n\n", "\n")
    body = body.replace("\n\n", "\n")
    body = re.sub("={10,}", '<hr>', body)
    lines = body.split("\n")

    freeform = []
    pairs = []
    data_part = []

    severity = lines[0].split(' ')[0]
    if severity == "CRITICAL":
        bgcolour = "#800080"               # violet   #FF00FF
    elif severity == "HIGH":
        bgcolour = "#A00000"               # red      #FF0000
    elif severity == "MEDIUM":
        bgcolour = "#FFB060"               # orange   #FF8000
    elif severity == "LOW":
        bgcolour = "#EEEEC0"               # yellow   #FFFF00
    elif severity == "INFORMATIONAL":
        bgcolour = "#F6F6F6"               # gray     #E0E0E0
    else:
        bgcolour = "FFFFFF"               # white

    freeform.append(lines[0]) # The title line

    in_data_part = False
    in_action_part = False

    for line in lines[1:]:
        if line == '<hr>':
            in_data_part = True
            in_action_part = False
        if in_data_part:
            data_part.append(line)
            continue

        if line.find('ACTION') != -1:
            in_action_part = True
            line = '<br>' + line
        elif line.find('Thank you') != -1:
            in_action_part = False
            line = '<br>' + line
        if in_action_part:
            freeform.append(line)
            continue

        if line.find(': ') != -1 and line.find(' : ') == -1:
            pairs.append(line)
        else:
            freeform.append(line)

    html = html_pre

    html += f"          <tr><td colspan='2' style='height:8px; background-color:{bgcolour};'></td></tr>\n"

    html += f"          <tr><td colspan='2'><h1>{freeform[0]}</h1></td></tr>\n"
    html += f"          <tr><td colspan='2'><h2>{freeform[1]}</h2></td></tr>\n"

    if ai_html:
        html += f" <tr><td colspan='2' style='font-size:16px; padding-bottom:8px'>{ai_html}</td></tr>\n"
    else:
        for line in freeform[2:]:
            html += f"      <tr><td colspan='2' style='font-size:16px; padding-bottom:8px'>{line}</td></tr>\n"

    html += "      <tr><td colspan='2'>&nbsp;</td></tr>\n"
    html += "      <tr><td colspan='2'>&nbsp;</td></tr>\n"
    html += "      <tr><td colspan='2'><hr></td></tr>\n"

    for line in pairs:
        if line.find(': ') != -1:
            title, data = line.split(': ', 1)
            html += f"      <tr><td style='font-size:14px;'><b>{title}</b></td><td style='font-size:14px;'>{data}</td></tr>\n"
        else:
            html += f"      <tr><td colspan='2' style='font-size:14px;'>{line}</td></tr>\n"

    html += "      <tr><td colspan='2'>&nbsp;</td></tr>\n"
    html += "      <tr><td colspan='2'>&nbsp;</td></tr>\n"

    for line in data_part:
        if line.find(': ') != -1:
            title, data = line.split(': ', 1)
            html += f"      <tr style='background-color: #F0F0F0'><td style='font-size:12px;'><b>{title}</b></td><td style='font-size:12px;'>{data}</td></tr>\n"
        else:
            html += f"      <tr style='background-color: #F0F0F0'><td colspan='2' style='font-size:12px;'>{line}</td></tr>\n"

    html += html_post

    return html


