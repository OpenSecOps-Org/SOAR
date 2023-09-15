import logging
from bs4 import BeautifulSoup, NavigableString, Tag
import re

# Set the logging level to INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(data, context):
    # Extract HTML and substitutions
    html = data['messages']['ai']['html']
    html_substitutions = data.get("html_substitutions", {})

    # Massage the HTML
    html = process_html_substitutions(html, html_substitutions)
    html = format_tables_inline(html)
    html = format_pre_sections(html)
    html = wrap_unwrapped_text(html)

    # Put it in the messages section
    if not data.get("messages"):
        data["messages"] = {}
    if not data['messages'].get("report"):
        data["messages"]["report"] = {}

    data['messages']['report']['body'] = ''
    data['messages']['report']['html'] = html

    data['messages']['ai']['html'] = ''
    data['messages']['ai']['plaintext'] = ''

    data['html_substitutions'] = {}
    data['system'] = ''
    data['user'] = ''

    # Return the blackboard
    return data


def process_html_substitutions(html, html_substitutions):
    # Replace placeholders in the HTML with their corresponding values
    for key, value in html_substitutions.items():
        placeholder = f"[[INSERT {key}]]"
        if placeholder in html:
            html = html.replace(placeholder, value)
        # else:
        #     html += value

    return html


# Add inline styling to all tables, as email clients are dodgy with HEAD style and classes
def format_tables_inline(html):
    logger.info(html)

    # Create a BeautifulSoup object to parse the HTML
    soup = BeautifulSoup(html, 'html.parser')

    # Replace inline styling for table elements
    for table in soup.find_all('table'):
        table['style'] = 'border: 1px solid black; border-collapse: collapse; padding: 4px; background-color: #EEEEEE; font-size: 14px;'

    # Replace inline styling for th elements
    for th in soup.find_all('th'):
        th['style'] = 'background-color: grey; color: white; border: 1px solid black; border-collapse: collapse; padding: 4px;'

    # Add or replace inline styling in td elements
    for td in soup.find_all('td'):
        if 'style' in td.attrs:
            td['style'] += '; border: 1px solid black; border-collapse: collapse; padding: 4px;'
        else:
            td['style'] = 'border: 1px solid black; border-collapse: collapse; padding: 4px;'

        # Check if the contents of the <td> tag contain "OVERDUE"
        if 'OVERDUE' in td.text:
            td['style'] += '; background-color: red;'

        # Check if the contents of the <td> tag contain severity levels
        if td.text in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            severity = td.text

            # Set the background color based on the severity level
            if severity == "CRITICAL":
                bgcolour = "FAACF9"  # violet
            elif severity == "HIGH":
                bgcolour = "FF9D96"  # red
            elif severity == "MEDIUM":
                bgcolour = "FFB060"  # orange
            elif severity == "LOW":
                bgcolour = "EEEEC0"  # yellow
            elif severity == "INFORMATIONAL":
                bgcolour = "F6F6F6"  # light gray

            td['style'] += f'; background-color: #{bgcolour};'

    # Return the modified HTML
    html = str(soup)
    logger.info(html)
    return html


def wrap_unwrapped_text(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Check all navigable strings (text)
    for content in soup.find_all(text=True):
        if isinstance(content, NavigableString) and content.strip() and not content.parent.name in ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'td', 'th']:
            # If it's a NavigableString, and not just whitespace, and its parent is not one of the common text tags
            new_tag = soup.new_tag("p")
            new_tag.string = content.strip()
            content.replace_with(new_tag)

    return str(soup)


def format_pre_sections(html):
    # Define the style to be inserted
    style = 'style="background-color: #030204; padding: 12px; color: #f8f9d2;"'

    # Use a regular expression to search and replace all <pre> tags with the modified version
    updated_html = re.sub(r'<pre>', f'<pre {style}>', html)

    return updated_html

