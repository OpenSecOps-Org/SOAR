#!/usr/bin/env python3

import os
import sys
import subprocess
import toml
import json
import boto3
import re
import botocore
from botocore.exceptions import ClientError
from botocore.exceptions import WaiterError
import time
import shutil
import argparse


# Create an STS client
STS_CLIENT = boto3.client('sts')


# ---------------------------------------------------------------------------------------
# 
# Common
# 
# ---------------------------------------------------------------------------------------

# Define colors
YELLOW = "\033[93m"
LIGHT_BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
GRAY = "\033[90m"
END = "\033[0m"
BOLD = "\033[1m"

def printc(color, string, **kwargs):
    print(f"{color}{string}\033[K{END}", **kwargs)


def check_aws_sso_session():
    try:
        # Try to get the user's identity
        subprocess.run(['aws', 'sts', 'get-caller-identity'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        # If the command failed, the user is not logged in
        printc(RED, "You do not have a valid AWS SSO session. Please run 'aws sso login' and try again.")
        return False

    # If the command succeeded, the user is logged in
    return True


def load_toml(toml_file):
    # Load the TOML file
    try:
        config = toml.load(toml_file)
    except Exception as e:
        printc(RED, f"Error loading {toml_file}: {str(e)}")
        return None

    return config


def get_account_data_from_toml(account_key, id_or_profile):
    toml_file = '../Delegat-Install/apps/accounts.toml'
    # Load the TOML file
    config = load_toml(toml_file)

    # Get the AWS SSO profile or id
    try:
        data = config[account_key][id_or_profile]
    except KeyError:
        printc(RED, f"Error: '{account_key}' account not found in {toml_file}")
        return None

    return data


def get_all_parameters(delegat_app):
    toml_file = f'../Delegat-Install/apps/{delegat_app}/parameters.toml'
    # Load and return the whole TOML file
    config = load_toml(toml_file)
    return config


def parameters_to_sam_string(params, repo_name):
    section = params[repo_name]['SAM']
    params_list = []
    for k, v in section.items():
        v = dereference(v, params)
        params_list.append(f'{k}="{v}"')
    return ' '.join(params_list)


def parameters_to_cloudformation_json(params, repo_name, template_name):
    section = params[repo_name][template_name]
    cf_params = []
    for k, v in section.items():
        v = dereference(v, params)
        cf_params.append({
            'ParameterKey': k,
            'ParameterValue': v
        })
    return cf_params


def script_parameters_to_dictionary(script_name, params, repo_name):
    section = params[repo_name][script_name]
    result = {}
    for k, v in section.items():
        v = dereference(v, params)
        result[k] = v
    return result


def dereference(value, params):
    # If not a string, just return
    if not isinstance(value, str):
        return value

    # Check if value is exactly '{all-regions}'
    if value == '{all-regions}':
        # Get main region and other regions
        main_region = params.get('main-region', '')
        other_regions = params.get('other-regions', [])
        
        # Add main region as a new first element
        all_regions = [main_region] + other_regions

        # Return a list of strings
        return all_regions

    # Check if value contains a reference
    elif "{" in value and "}" in value:
        def substitute(m):
            param = m.group(1)
            if param in params:
                return params[param]
            else:
                # If not found in params, try to get account data from TOML
                account_data = get_account_data_from_toml(param, 'id')
                if account_data is not None:
                    return account_data
                else:
                    raise ValueError(f"Parameter {param} not found")

        # Replace any string enclosed in braces with the corresponding parameter
        value = re.sub(r'\{(.+?)\}', substitute, value)

    return value



# ---------------------------------------------------------------------------------------
# 
# SAM
# 
# ---------------------------------------------------------------------------------------

def process_sam(sam, repo_name, params, dry_run, verbose):
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, "================================================")
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, f"  {repo_name} (SAM)")
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, "------------------------------------------------")
    printc(LIGHT_BLUE, "")

    sam_account = sam['profile']
    sam_regions = dereference(sam['regions'], params)
    if isinstance(sam_regions, str):
        sam_regions = [sam_regions]

    stack_name = sam['stack-name']
    capabilities = sam.get('capabilities', 'CAPABILITY_IAM')
    s3_prefix = sam.get('s3-prefix', stack_name)
    tags = 'infra:immutable="true"'

    # Get the AWS SSO profile
    sam_profile = get_account_data_from_toml(sam_account, 'profile')

    # Get the SAM parameter overrides
    sam_parameter_overrides = parameters_to_sam_string(params, repo_name)

    try:
        printc(LIGHT_BLUE, "Executing 'git pull'...")
        subprocess.run(['git', 'pull'], check=True)

        printc(LIGHT_BLUE, "")
        printc(LIGHT_BLUE, "Executing 'sam build'...")
    
        args = ['sam', 'build', '--parallel', '--cached']

        try:
            if verbose:
                subprocess.run(args, check=True)
            else:
                subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError:
            printc(RED, "An error occurred. Retrying after cleaning build directory...")

            # Remove the .aws-sam directory
            shutil.rmtree('.aws-sam', ignore_errors=True)

            # Retry the build command, always verbosely
            subprocess.run(args, check=True)

        for region in sam_regions:
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, "------------------------------------------------")
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, f"  Deploying {stack_name} to {region}...")
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, "------------------------------------------------")
            printc(LIGHT_BLUE, "")

            args = [
                    'sam', 'deploy', 
                    '--stack-name', stack_name,
                    '--capabilities', capabilities,
                    '--resolve-s3',
                    '--region', region,
                    '--profile', sam_profile, 
                    '--parameter-overrides', sam_parameter_overrides,
                    '--s3-prefix', s3_prefix,
                    '--tags', tags,
                    '--no-confirm-changeset', 
                    '--no-disable-rollback',
                    '--no-fail-on-empty-changeset', 
            ]
            if dry_run:
                args.append('--no-execute-changeset')
                printc(GREEN, "Executing 'sam deploy' with --no-execute-changeset...")
            else:
                printc(LIGHT_BLUE, "Executing 'sam deploy'...")

            if verbose:
                args.append('--debug')
                
            subprocess.run(args, check=True)

            printc(GREEN, "")
            printc(GREEN + BOLD, "Deployment completed successfully.")

    except subprocess.CalledProcessError as e:
        printc(RED, f"An error occurred while executing the command: {str(e)}")

    printc(GREEN, "")



# ---------------------------------------------------------------------------------------
# 
# Scripts
# 
# ---------------------------------------------------------------------------------------

def process_scripts(scripts, repo_name, params, dry_run, verbose):
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, "=================================================")
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, f"  {repo_name} (Scripts)")
    printc(LIGHT_BLUE, "")
    printc(LIGHT_BLUE, "-------------------------------------------------")
    printc(LIGHT_BLUE, "")

    for script in scripts:
        regions = script.get('regions', '{main-region}')
        regions = dereference(regions, params)
        if isinstance(regions, str):
            regions = [regions]

        account_str = script.get('account', '{admin-account}')
        account_id = dereference(account_str, params)
        if verbose:
            printc(GRAY, f"account_id:  {account_id}")

        profile = script.get('profile', 'admin-account')
        profile = get_account_data_from_toml(profile, 'profile')
        if verbose:
            printc(GRAY, f"profile:     {profile}")

        if verbose:
            printc(GRAY, f"script:      {script}")

        name = script['name']

        our_params = script_parameters_to_dictionary(name, params, repo_name)
        if verbose:
            printc(GRAY, f"our_params:  {our_params}")

        cmd = ['./' + name]

        if dry_run:
            cmd.append('--dry-run')

        for k, v in script.get('args', []):
            cmd.append(k)
            
            if isinstance(v, str) and v.endswith('.toml'):
                try:
                    # Read the TOML file
                    with open(v, 'r') as toml_file:
                        toml_data = toml.load(toml_file)

                    # Convert the TOML data to JSON
                    json_string = json.dumps(toml_data)

                except FileNotFoundError:
                    print(f"The file {v} does not exist.")
                except Exception as e:
                    print(f"An error occurred: {e}")
                cmd.append(json_string)
            
            else:
                cmd.append(dereference(v, our_params))

        if verbose:
            printc(GRAY, '')
            printc(GRAY, f"cmd: {cmd}")

        for region in regions:
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, "------------------------------------------------")
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, f"  Running script ./{name} in {region}...")
            printc(LIGHT_BLUE, "")
            printc(LIGHT_BLUE, "------------------------------------------------")
            printc(LIGHT_BLUE, "")

            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Command '{e.cmd}' returned non-zero exit status {e.returncode}.")



# ---------------------------------------------------------------------------------------
# 
# CloudFormation
# 
# ---------------------------------------------------------------------------------------

# Function to get a client for the specified service, account, and region
def get_client(client_type, account_id, region, role):
    # Assume the specified role in the specified account
    other_session = STS_CLIENT.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"deploy_cloudformation_{account_id}"
    )
    
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    
    # Create a client using the assumed role credentials and specified region
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )


def does_stack_exist(stack_name, account_id, region, role):
    try:
        # Get CloudFormation client for the specified account and region
        cf_client = get_client("cloudformation", account_id, region, role)
        
        # Describe the stack using the provided name
        cf_client.describe_stacks(StackName=stack_name)
        
        # If no exception is raised, the stack exists
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ValidationError' and 'does not exist' in e.response['Error']['Message']:
            return False
        else:
            raise e


def does_stackset_exist(stackset_name, account_id, region, role):
    try:
        # Get CloudFormation client for the specified account and region
        cf_client = get_client("cloudformation", account_id, region, role)
        
        # Describe the stack set using the provided name
        cf_client.describe_stack_set(StackSetName=stackset_name)
        
        # If no exception is raised, the stack set exists
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'StackSetNotFoundException':
            return False
        else:
            raise e


def read_cloudformation_template(path):
    """
    Reads the CloudFormation template from the specified path and checks for size constraints.
    
    Parameters:
    - path (str): Path to the CloudFormation template file.
    
    Returns:
    - template (str): Contents of the CloudFormation template file.
    
    Raises:
    - Exception if the file is missing or exceeds the size limit.
    """
    
    try:
        # Read the file content
        with open(path, 'r') as file:
            template = file.read()
            
        # Check for size constraints
        if len(template.encode('utf-8')) > 51200:  # CloudFormation string template size limit is 51,200 bytes
            raise Exception("The CloudFormation template exceeds the maximum size limit of 51,200 bytes.")
        
        return template
    
    except FileNotFoundError:
        raise Exception(f"The specified CloudFormation template at path '{path}' was not found.")


def process_stack(action, resource_type, name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose, **kwargs):
    op = 'Creating' if action == 'create' else 'Updating'
    dry_run_str = 'Dry run: NOT ' if dry_run else ''

    printc(YELLOW, f"{dry_run_str}{op} {resource_type} {name} in AWS account {account_id} in region {region}...")

    cf_client = get_client('cloudformation', account_id, region, role)

    tags = [{'Key': 'infra:immutable', 'Value': 'true'}]

    try:
        if resource_type == 'stack':
            # Create a change set
            change_set_name = 'ChangeSet-' + str(int(time.time()))
            if action == 'create':
                resources = parse_template(template_body)
                print_template_resources(resources)

                if dry_run:
                    return False
                
                printc(YELLOW, "Creating the stack...")
                response = cf_client.create_stack(
                    StackName=name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=[capabilities],
                    Tags=tags
                )


            elif action == 'update':
                response = cf_client.create_change_set(
                    StackName=name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=[capabilities],
                    Tags=tags,
                    ChangeSetName=change_set_name,
                )
                response = cf_client.describe_change_set(
                    StackName=name,
                    ChangeSetName=change_set_name,
                )
                if response['Status'] == 'FAILED' and "The submitted information didn't contain changes." in response['StatusReason']:
                    printc(GREEN, f"No changes.")
                    return False
                else:
                    # Wait for the change set to be created
                    printc(LIGHT_BLUE, "Waiting for changeset to be created...")
                    waiter = cf_client.get_waiter('change_set_create_complete')
                    waiter.wait(
                        StackName=name,
                        ChangeSetName=change_set_name,
                    )
                    # Display the changes
                    response = cf_client.describe_change_set(
                        StackName=name,
                        ChangeSetName=change_set_name,
                    )
                    print_change_set(response)

                    if dry_run:
                        return False
                    
                    # Execute the change set
                    printc(YELLOW, "Executing the changeset...")
                    return cf_client.execute_change_set(
                        StackName=name,
                        ChangeSetName=change_set_name,
                    )
                
        elif resource_type == 'stackset':
            if dry_run:
                return False
            if action == 'create':
                return cf_client.create_stack_set(StackSetName=name, TemplateBody=template_body, Parameters=parameters, Capabilities=[capabilities], Tags=tags, **kwargs)
            elif action == 'update':
                return cf_client.update_stack_set(StackSetName=name, TemplateBody=template_body, Parameters=parameters, Capabilities=[capabilities], Tags=tags, **kwargs)

        return True
    
    except botocore.exceptions.ClientError as e:
        if "No updates are to be performed" in str(e):
            printc(GREEN, f"{resource_type.capitalize()} {action}: No changes are needed.")
            return False
        else:
            raise e


def print_change_set(change_set):
    if change_set['Status'] == 'FAILED' and "The submitted information didn't contain changes." in change_set['StatusReason']:
        printc(GREEN, "None.")
    elif 'Changes' in change_set and change_set['Changes']:

        # Calculate the maximum length of each column
        max_resource_len = max(len(change['ResourceChange']['ResourceType']) for change in change_set['Changes'])
        max_action_len = max(len(change['ResourceChange']['Action']) for change in change_set['Changes'])
        max_id_len = max(len(change['ResourceChange']['LogicalResourceId']) for change in change_set['Changes'])
        dash_len = max_resource_len + max_action_len + max_id_len + 36

        printc(YELLOW, "-" * dash_len)
        printc(YELLOW, f"{'Action':<{max_action_len}}    {'LogicalResourceId':<{max_id_len}}    {'ResourceType':<{max_resource_len}}    Replacement")
        printc(YELLOW, "-" * dash_len)

        # Print the changes in fixed-width columns
        for change in change_set['Changes']:
            resource = change['ResourceChange']['ResourceType']
            action = change['ResourceChange']['Action']
            logical_id = change['ResourceChange']['LogicalResourceId']
            replacement = change.get('ResourceChange', {}).get('Replacement', '')

            printc(GREEN, f"{action:<{max_action_len}}    {logical_id:<{max_id_len}}    {resource:<{max_resource_len}}    {replacement}")

        printc(YELLOW, "-" * dash_len)
        printc(YELLOW, '')

    else:
        printc(GREEN, "No changes detected.")


def print_template_resources(template_resources):
    if not template_resources:
        printc(GREEN, "None.")
    else:
        # Calculate the maximum length of each column
        max_resource_len = max(len(resource[1]) for resource in template_resources)
        max_id_len = max(len(resource[0]) for resource in template_resources)
        dash_len = max_resource_len + max_id_len + 17

        printc(YELLOW, "")
        printc(LIGHT_BLUE, "Template Resources:")
        printc(YELLOW, "-" * dash_len)
        printc(YELLOW, f"Operation    {'LogicalResourceId':<{max_id_len}}    {'ResourceType':<{max_resource_len}}")
        printc(YELLOW, "-" * dash_len)

        # Print the resources in fixed-width columns
        for resource in template_resources:
            logical_id = resource[0]
            resource_type = resource[1]

            printc(GREEN, f"+ Add        {logical_id:<{max_id_len}}    {resource_type:<{max_resource_len}}")

        printc(YELLOW, "-" * dash_len)
        printc(YELLOW, '')


def parse_template(template):
    try:
        # Try to parse as JSON
        parsed = json.loads(template)
        # Extract the resources
        resources = parsed.get('Resources', {})

        # Create a list of tuples (logical name, type)
        resource_list = [(name, details.get('Type')) for name, details in resources.items()]
        return resource_list

    except json.JSONDecodeError as e:
        return parse_yaml_template(template)


def parse_yaml_template(template):
    # YAML. Split the template into lines
    lines = template.split('\n')

    # Remove all empty lines, all lines containing only whitespace, and all lines containing only whitespace followed by a #
    lines = [line for line in lines if line.strip() and not line.lstrip().startswith('#')]

    # Find the start of the Resources section
    resources_start = next((i for i, line in enumerate(lines) if line.startswith('Resources:')), None)
    if resources_start is None:
        print("No Resources section found.")
        return []
    
    # Find the end of the Resources section
    resources_end = next((i for i in range(resources_start + 1, len(lines)) if not lines[i].startswith(' ')), len(lines))

    # Extract the Resources section
    resources_section = lines[resources_start+1:resources_end]

    # Determine the number of spaces per indentation level
    spaces_per_indent = next((len(line) - len(line.lstrip(' ')) for line in resources_section if line.strip()), None)
    if spaces_per_indent is None:
        print("No resources found.")
        return []

    # Extract all logical resource names and their types
    resource_list = []
    logical_name = None
    for line in resources_section:
        stripped_line = line.lstrip(' ')
        indent_level = (len(line) - len(stripped_line)) // spaces_per_indent
        if indent_level == 1 and stripped_line.endswith(':'):
            logical_name = stripped_line[:-1]
        elif indent_level == 2 and stripped_line.startswith('Type:') and logical_name is not None:
            resource_type = stripped_line[len('Type:'):].strip(' "\'')
            resource_list.append((logical_name, resource_type))
            logical_name = None  # Reset logical_name

    return resource_list


def update_stack(stack_name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose):
    return process_stack('update', 'stack', stack_name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose)


def create_stack(stack_name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose):
    return process_stack('create', 'stack', stack_name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose)
                

def update_stack_set(stack_set_name, template_body, parameters, capabilities, regions, account_id, region, role, dry_run, verbose):
    return process_stack('update', 'stackset', stack_set_name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose,
                         OperationPreferences={
                             'RegionConcurrencyType': 'PARALLEL',
                             'FailureTolerancePercentage': 0,
                             'MaxConcurrentPercentage': 100,
                             'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
                         })


def create_stack_set(stack_set_name, template_body, parameters, capabilities, root_ou, deployment_regions, account_id, region, role, dry_run, verbose):
    return process_stack('create', 'stackset', stack_set_name, template_body, parameters, capabilities, account_id, region, role, dry_run, verbose,
                         PermissionModel='SERVICE_MANAGED',
                         AutoDeployment={
                             'Enabled': True,
                             'RetainStacksOnAccountRemoval': False
                         })


def create_stack_set_instances(stack_set_name, template_body, parameters, capabilities, root_ou, except_account, deployment_regions, account_id, region, role, dry_run, verbose):

    if dry_run:
        printc(YELLOW, f"Dry run enabled. Would have created instances of stack set {stack_set_name} in OU {root_ou} in regions {deployment_regions}.")
        return False

    cf_client = get_client('cloudformation', account_id, region, role)

    # Initialize args
    deployment_targets = {
        'OrganizationalUnitIds':[root_ou]
    }

    # Filter away an account if except_account is present
    if except_account:
        deployment_targets['Accounts'] = [except_account]
        deployment_targets['AccountFilterType'] = 'DIFFERENCE'

    args = {
        'StackSetName': stack_set_name,
        'DeploymentTargets': deployment_targets,
        'Regions': deployment_regions,
        'OperationPreferences': {
            'RegionConcurrencyType': 'PARALLEL',
            'FailureTolerancePercentage': 0,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        }
    }

    try:
        response = cf_client.create_stack_instances(**args)
        printc(GREEN, f"Created instances of stack set {stack_set_name} in OU {root_ou} in regions {deployment_regions}.")
        return True

    except botocore.exceptions.ClientError as e:
        printc(RED, f"Failed to create instances of stack set {stack_set_name} in OU {root_ou} in regions {deployment_regions}: {e}")
        raise e
    

def monitor_stack_until_complete(stack_name, account_id, region, role, dry_run, verbose):
    """
    Polls the specified CloudFormation stack until it reaches a terminal state.
    
    Parameters:
    - stack_name (str): Name of the CloudFormation stack to monitor.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the stack resides.
    - role (str): IAM Role to assume for cross-account access.
    """

    if dry_run:
        return
    
    if verbose:
        printc(GRAY, "Waiting for the stack to complete.")

    # Get the CloudFormation client using the get_client function
    cf_client = get_client('cloudformation', account_id, region, role)
    
    # Define terminal states for CloudFormation stacks and stack sets
    terminal_states = ["CREATE_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_COMPLETE", "CURRENT", "ACTIVE"]

    # Get the current stack status
    stack = cf_client.describe_stacks(StackName=stack_name)
    stack_status = stack['Stacks'][0]['StackStatus']
    
    # Return immediately if the stack is already in a terminal state
    if stack_status in terminal_states:
        return

    printc(LIGHT_BLUE, "Waiting for stack or stack set to complete...")
    
    while True:
        try:
            # Get the current stack status
            stack = cf_client.describe_stacks(StackName=stack_name)
            stack_status = stack['Stacks'][0]['StackStatus']
            
            # Print the stack status with the appropriate color and reset the color afterward
            if "ROLLBACK" in stack_status or "DELETE" in stack_status:
                printc(RED, f"Stack Status: {stack_status}", end="")
            elif "CREATE_COMPLETE" in stack_status or "UPDATE_COMPLETE" in stack_status:
                printc(GREEN, f"Stack Status: {stack_status}", end="")
            else:
                printc(YELLOW, f"Stack Status: {stack_status}", end="")
            
            # Exit loop if the stack is in a terminal state
            if stack_status in terminal_states:
                printc(YELLOW, '')  # Move to the next line after final state is reached
                time.sleep(5)
                break
            
            # Sleep for a shorter interval before checking again
            time.sleep(1)  # Shorter interval for more frequent checks
        except botocore.exceptions.WaiterError as ex:
            if ex.last_response.get('Error', {}).get('Code') == 'ThrottlingException':
                printc(RED, "API rate limit exceeded. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                raise
        except botocore.exceptions.OperationInProgressException as op_in_prog_ex:
            printc(RED, f"Another operation is in progress: {op_in_prog_ex}")
            printc(RED, "Retrying in 30 seconds...")
            time.sleep(30)


def monitor_stackset_until_complete(stackset_name, account_id, region, role, dry_run, verbose):
    """
    Polls the specified StackSet until it reaches a terminal state.
    
    Parameters:
    - stackset_name (str): Name of the StackSet to monitor.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the StackSet resides.
    - role (str): IAM Role to assume for cross-account access.
    """

    if dry_run:
        return

    if verbose:
        printc(GRAY, "Waiting for the stackset to complete.")

    # Get the CloudFormation client using the get_client function
    cf_client = get_client('cloudformation', account_id, region, role)
    
    # Define terminal states for CloudFormation StackSets
    terminal_states = ["CREATE_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_COMPLETE", "CURRENT", "ACTIVE"]

    # Get the current StackSet status
    stackset = cf_client.describe_stack_set(StackSetName=stackset_name)
    stackset_status = stackset['StackSet']['Status']
    
    # Return immediately if the StackSet is already in a terminal state
    if stackset_status in terminal_states:
        return

    printc(LIGHT_BLUE, "Waiting for StackSet deployment to complete...")

    while True:
        try:
            # Get the current StackSet status
            stackset = cf_client.describe_stack_set(StackSetName=stackset_name)
            stackset_status = stackset['StackSet']['Status']
            
            # Print the StackSet status with the appropriate color and reset the color afterward
            if "ROLLBACK" in stackset_status or "DELETE" in stackset_status:
                printc(RED, f"StackSet Status: {stackset_status}", end="")
            elif "CREATE_COMPLETE" in stackset_status or "UPDATE_COMPLETE" in stackset_status:
                printc(GREEN, f"StackSet Status: {stackset_status}", end="")
            else:
                printc(YELLOW, f"StackSet Status: {stackset_status}", end="")
            
            # Exit loop if the StackSet is in a terminal state
            if stackset_status in terminal_states:
                printc(YELLOW, '')  # Move to the next line after final state is reached
                time.sleep(5)
                break
            
            # Sleep for a shorter interval before checking again
            time.sleep(1)  # Shorter interval for more frequent checks
        
        except botocore.exceptions.WaiterError as ex:
            if ex.last_response.get('Error', {}).get('Code') == 'ThrottlingException':
                printc(RED, "API rate limit exceeded. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                raise
        except botocore.exceptions.BotoCoreError as error:
            printc(RED, f"An error occurred: {error}")
            printc(RED, "Retrying in 30 seconds...")
            time.sleep(30)


def monitor_stackset_stacks_until_complete(stackset_name, account_id, region, role, dry_run, verbose):
    """
    Polls the specified StackSet's stacks until they reach a terminal state.
    
    Parameters:
    - stackset_name (str): Name of the StackSet to monitor.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the StackSet resides.
    - role (str): IAM Role to assume for cross-account access.
    """

    if dry_run:
        return

    if verbose:
        printc(GRAY, "Waiting for the stackset stacks to complete.")
    
    # Get the CloudFormation client using the get_client function
    cf_client = get_client('cloudformation', account_id, region, role)
    
    # Define terminal states for CloudFormation stacks
    terminal_states = ["CREATE_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_COMPLETE", "CURRENT"]

    # Get the status of all stacks deployed by the StackSet
    stack_instances = cf_client.list_stack_instances(StackSetName=stackset_name)
    stack_statuses = [instance['Status'] for instance in stack_instances['Summaries']]
    
    # Return immediately if all stacks are already in a terminal state
    if all(status in terminal_states for status in stack_statuses):
        return

    printc(LIGHT_BLUE, "Waiting for stack set's deployment of its stacks to complete...")

    while True:
        try:
            # Get the status of all stacks deployed by the StackSet
            stack_instances = cf_client.list_stack_instances(StackSetName=stackset_name)
            stack_statuses = [instance['Status'] for instance in stack_instances['Summaries']]
            
            # Print the status of each stack instance
            for instance in stack_instances['Summaries']:
                stack_instance_identifier = f"{instance['Account']} {instance['Region']:<15}"
                stack_status = instance['Status']
                if stack_status in terminal_states:
                    printc(GREEN, f"{stack_instance_identifier} {stack_status}")
                else:
                    printc(YELLOW, f"{stack_instance_identifier} {stack_status}")
            
            # Move the cursor to the beginning of the line
            sys.stdout.write("\033[F" * (len(stack_instances['Summaries'])))
            
            # Check if any stack is not in a terminal state
            if any(status not in terminal_states for status in stack_statuses):
                # Sleep for a shorter interval before checking again
                time.sleep(1)  # Shorter interval for more frequent checks
                continue  # Continue monitoring if any stack is still in progress
            
            # All stacks are in a terminal state, exit the loop
            printc(YELLOW, '')  # Move to the next line after all stacks are complete
            time.sleep(5)
            break
        
        except botocore.exceptions.WaiterError as ex:
            if ex.last_response.get('Error', {}).get('Code') == 'ThrottlingException':
                printc(RED, "API rate limit exceeded. Retrying in 5 seconds...")
                time.sleep(5)
            else:
                raise
        except botocore.exceptions.BotoCoreError as error:
            printc(RED, f"An error occurred: {error}")
            printc(RED, "Retrying in 30 seconds...")
            time.sleep(30)


def process_cloudformation(jobs, repo_name, params, cross_account_role, dry_run, verbose):
    if not jobs:
        return
    
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, "================================================")
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, f"  CloudFormation")
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, "------------------------------------------------")
    printc(LIGHT_BLUE, f"")

    admin_account_id = get_account_data_from_toml('admin-account', 'id')
    root_ou = params['root-ou']
    main_region = params['main-region']

    index = 0
    for job in jobs:
        index += 1

        stack_name = job.get('name')
        template_path = job.get('template')
        account = dereference(job.get('account'), params)
        regions = dereference(job.get('regions'), params)
        capabilities = job.get('capabilities', 'CAPABILITY_IAM')
        except_account =  dereference(job.get('except-account'), params)
        separate_regions =  job.get('separate-regions')

        if isinstance(regions, str):
            regions = [regions]

        printc(YELLOW, '')
        stack_set = False
        if account == 'ALL':
            stack_set = True
            account = admin_account_id
            printc(LIGHT_BLUE, f"{index}. {stack_name} (StackSet):")
        else:
            printc(LIGHT_BLUE, f"{index}. {stack_name} (Stack):")
        printc(YELLOW, '')

        template_str = read_cloudformation_template(template_path)

        if not stack_set:
            handle_stack(repo_name, stack_name, template_str, params, capabilities, account, regions, cross_account_role, dry_run, verbose)

        elif not separate_regions:
            handle_stack_set(repo_name, stack_name, template_str, params, capabilities, account, regions, cross_account_role, dry_run, verbose, 
                             main_region, root_ou, except_account, admin_account_id)
        else:
            for region in regions:
                params['region'] = region
                handle_stack_set(repo_name, stack_name, template_str, params, capabilities, account, [region], cross_account_role, dry_run, verbose, 
                                 region, root_ou, except_account, admin_account_id)



def handle_stack(repo_name, stack_name, template_str, params, capabilities, account, regions, cross_account_role, dry_run, verbose):
    stack_parameters = parameters_to_cloudformation_json(params, repo_name, stack_name)

    for region in regions:
        exists = does_stack_exist(stack_name, account, region, cross_account_role)
        if exists:
            if verbose:
                printc(GRAY, f"Stack exists in {account} and {region}")
            monitor_stack_until_complete(stack_name, account, region, cross_account_role, False, verbose)
            changing = update_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role, dry_run, verbose)
            if changing:
                time.sleep(1)
                monitor_stack_until_complete(stack_name, account, region, cross_account_role, dry_run, verbose)
        else:
            if verbose:
                printc(GRAY, f"Stack does not exist in {account} and {region}")
            changing = create_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role, dry_run, verbose)
            if changing:
                time.sleep(1)
                monitor_stack_until_complete(stack_name, account, region, cross_account_role, dry_run, verbose)


def handle_stack_set(repo_name, stack_name, template_str, params, capabilities, account, regions, cross_account_role, dry_run, verbose, 
                      main_region, root_ou, except_account, admin_account_id):
    stack_parameters = parameters_to_cloudformation_json(params, repo_name, stack_name)

    exists = does_stackset_exist(stack_name, account, main_region, cross_account_role)
    if exists:
        if verbose:
            printc(GRAY, f"StackSet exists in {account} and {main_region}")
        monitor_stackset_until_complete(stack_name, account, main_region, cross_account_role, False, verbose)
        monitor_stackset_stacks_until_complete(stack_name, account, main_region, cross_account_role, False, verbose)
        changing = update_stack_set(stack_name, template_str, stack_parameters, capabilities, regions, account, main_region, cross_account_role, dry_run, verbose)
        if changing:
            time.sleep(1)
            monitor_stackset_until_complete(stack_name, account, main_region, cross_account_role, dry_run, verbose)
    else:
        if verbose:
            printc(GRAY, f"StackSet does not exist in {account} and {main_region}")
        create_stack_set(stack_name, template_str, stack_parameters, capabilities, root_ou, regions, account, main_region, cross_account_role, dry_run, verbose)
        monitor_stackset_until_complete(stack_name, account, main_region, cross_account_role, dry_run, verbose)
        create_stack_set_instances(stack_name, template_str, stack_parameters, capabilities, root_ou, except_account, regions, account, main_region, cross_account_role, dry_run, verbose)
        monitor_stackset_stacks_until_complete(stack_name, account, main_region, cross_account_role, dry_run, verbose)

    if except_account == admin_account_id:
        return

    # Check the Stack(s) in the admin account(s) as well
    for region in regions:
        exists = does_stack_exist(stack_name, admin_account_id, region, cross_account_role)
        if exists:
            if verbose:
                printc(GRAY, f"Also deployed as a single Stack in the AWS Organization admin account in {region}")
            monitor_stack_until_complete(stack_name, account, region, cross_account_role, False, verbose)
            changing = update_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role, dry_run, verbose)
            if changing:
                time.sleep(1)
                monitor_stack_until_complete(stack_name, account, region, cross_account_role, dry_run, verbose)
        else:
            if verbose:
                printc(GRAY, f"Not deployed as a single Stack in the AWS Organization admin account in {region}")
            changing = create_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role, dry_run, verbose)
            if changing:
                time.sleep(1)
                monitor_stack_until_complete(stack_name, account, region, cross_account_role, dry_run, verbose)


# ---------------------------------------------------------------------------------------
# 
# Entry point
# 
# ---------------------------------------------------------------------------------------

def deploy(dry_run, verbose):
    # Check if 'config-deploy.toml' exists at the root of the repo
    if not os.path.exists('config-deploy.toml'):
        printc(RED, "Error: 'config-deploy.toml' is missing.")
        printc(YELLOW, "Please create 'config-deploy.toml'.")
        return
    
    # Get the deployment configuration
    dpcf = load_toml('config-deploy.toml')
    delegat_app = dpcf['part-of']
    repo_name = dpcf['repo-name']

    # Get the parameters (all of them, for all repos)
    params = get_all_parameters(delegat_app)
    cross_account_role = params['cross-account-role']
    
    # Get the respective sections
    sam = dpcf.get('SAM')
    pre_sam = dpcf.get('pre-SAM-CloudFormation') or dpcf.get('pre-SAM')
    post_sam = dpcf.get('post-SAM-CloudFormation') or dpcf.get('post-SAM')
    cf = dpcf.get('CloudFormation')
    scripts = dpcf.get('Script')

    # Decide what to do
    if sam:
        process_cloudformation(pre_sam, repo_name, params, cross_account_role, dry_run, verbose)
        process_sam(sam, repo_name, params, dry_run, verbose)
        process_cloudformation(post_sam, repo_name, params, cross_account_role, dry_run, verbose)

    elif cf:
        process_cloudformation(cf, repo_name, params, cross_account_role, dry_run, verbose)

    elif scripts:
        process_scripts(scripts, repo_name, params, dry_run, verbose)

    else:
        printc(RED, "\nNo SAM, CloudFormation or script specs found.")


def main():
    # Check that the user is logged in
    if not check_aws_sso_session():
        return
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run of the deployments')
    parser.add_argument('--verbose', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    if args.dry_run:
        printc(GREEN, "\nThis is a dry run. No changes will be made.")

    deploy(args.dry_run, args.verbose)


if __name__ == '__main__':
    main()
