'''
This lambda function is used to check whether a DynamoDB entry for the SecHub control has an additional column called 'disable_when'. If this column is not present or its string value is empty, the function returns False, indicating that the control should not be suppressed. If the string in 'disable_when' specifies a set of conditions that match the finding's account properties, then the function returns True, indicating that the finding should be suppressed. If none of the conditions are met, the function returns False.

The conditions can be built on the following account properties:

  * account_id          - the account in which the issue was created
  * region              - the region in which the issue was created
  * client              - the client with which that account is associated
  * environment         - the environment of that account
  * organizational_unit - the OU to which the account belongs
  * project_name        - the name of the project to which the account belongs
  * team                - the team/squad/group working in the account

The syntax for a condition line is as follows:

  <property> <operator> <value>

Examples:

  account_id = 111111111111

This means, "suppress the finding in account 111111111111".

  environment != PROD

The above means, "suppress the finding everywhere but in the PROD environment".

  organizational_unit = ROOT, INFRA, SANDBOXES

The above line demonstrates that it is possible to specify lists on the right hand side. The above means, "suppress the finding in organizational units ROOT, INFRA, and SANDBOXES. The equal sign thus means, "true if the value is in the list".

  environment != DEV, TEST

The above demonstrates non-equality with lists. It means, "suppress the finding in all other environments than DEV and TEST. Negation thus means, "true if the value is NOT in the list".

It is also possible to combine conditions using AND:

  environment = DEV AND team = Platform

which means, "suppress the finding in the DEV environment of the Platform team".

The value of 'disable_when' can be multiline. The lines form a logical OR: if any of them evaluate to True, True is returned, else False.

Examples:

  environment = DEV
  organizational_unit = INFRA AND account_id != 222222222222

The above means, "suppress the finding in all DEV environments and also throughout the entire OU INFRA except in account 222222222222".
'''

import re


def lambda_handler(data, _context):
    print(data)

    # Extract necessary data from input
    account_data = data['account']
    table = data['table']
    control = data['db'][table].get('Item', False)

    # If control is not found, return False
    if not control:
        return False

    # Get the value of 'disable_when' column
    disable_when = control.get('disable_when', False)

    # If 'disable_when' is not present or its value is not a string, return False
    if not disable_when or not isinstance(disable_when.get('S', False), str):
        return False

    # Get the region from input data
    region = data['region']

    # Process each line in 'disable_when' value
    for line in disable_when['S'].strip().splitlines():
        # Check if the line satisfies the conditions
        if process_line(line.strip(), account_data, region):
            return True

    return False


def process_line(line, account_data, region):
    if line == '':
        return False

    # Split the line into clauses using 'AND' as the separator
    clauses = line.split('AND')

    # Check if each clause is true
    for clause in clauses:
        clause = clause.strip()
        if not clause_true(clause, account_data, region):
            print(f"Clause '{clause}' was False")
            return False
        print(f"Clause '{clause}' was True")

    return True


def clause_true(clause, account_data, region):
    # Split the clause into parts using '=' or '!=' as the separator
    parts = re.split(r'(=|!=)', clause)

    # If the clause is not in the correct format, return False
    if len(parts) != 3 or parts[2] == '':
        print(
            f"Error: Malformed disabled_when clause: '{clause}'. Disregarded.")
        return False

    key = parts[0].strip()
    operator = parts[1].strip()
    values = [s.strip() for s in parts[2].split(',')]

    # Get the value corresponding to the key from account_data
    if key == 'account_id':
        value = account_data['Id']
    elif key == 'region':
        value = region
    elif key == 'client':
        value = account_data['Client']
    elif key == 'environment':
        value = account_data['Environment']
    elif key == 'organizational_unit':
        value = account_data['OrganizationalUnit']
    elif key == 'project_name':
        value = account_data['ProjectName']
    elif key == 'team':
        value = account_data['Team']
    else:
        print(
            f"Error: Unrecognised key in disabled_when clause: '{clause}'. Disregarded.")
        return False

    # Check if the value satisfies the condition
    if operator == '=':
        return value in values
    if operator == '!=':
        return value not in values
    print(
        f"Error: Unrecognised operator in disabled_when clause: '{clause}'. Disregarded.")
    return False