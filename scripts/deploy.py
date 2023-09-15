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
    toml_file = '../Delegat-Install/accounts.toml'
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

def process_sam(sam, repo_name, params):
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, "================================================")
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, f"  {repo_name} (SAM)")
    printc(LIGHT_BLUE, f"")
    printc(LIGHT_BLUE, "------------------------------------------------")
    printc(LIGHT_BLUE, f"")

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

        printc(LIGHT_BLUE, "Executing 'sam build'...")
        try:
            subprocess.run(['sam', 'build', '--parallel', '--cached'], check=True)
        except subprocess.CalledProcessError:
            printc(RED, "An error occurred. Retrying after cleaning build directory...")

            # Remove the .aws-sam directory
            shutil.rmtree('.aws-sam', ignore_errors=True)

            # Retry the build command
            subprocess.run(['sam', 'build', '--parallel', '--cached'], check=True)

        for region in sam_regions:
            printc(LIGHT_BLUE, f"")
            printc(LIGHT_BLUE, f"")
            printc(LIGHT_BLUE, "================================================")
            printc(LIGHT_BLUE, f"")
            printc(LIGHT_BLUE, f"  Deploying {stack_name} to {region}...")
            printc(LIGHT_BLUE, f"")
            printc(LIGHT_BLUE, "------------------------------------------------")
            printc(LIGHT_BLUE, f"")

            printc(LIGHT_BLUE, "Executing 'sam deploy'...")
            subprocess.run(
                [
                    'sam', 'deploy', 
                    '--stack-name', stack_name,
                    '--capabilities', capabilities,
                    '--resolve-s3',
                    '--region', region,
                    '--profile', sam_profile, 
                    '--parameter-overrides', sam_parameter_overrides,
                    '--s3-prefix', s3_prefix,
                    '--tags', tags,
                    #  '--no-execute-changeset', 
                    '--no-confirm-changeset', 
                    '--no-disable-rollback',
                    '--no-fail-on-empty-changeset', 
                ],
                check=True)

            printc(GREEN, "")
            printc(GREEN + BOLD, "Deployment completed successfully.")

    except subprocess.CalledProcessError as e:
        printc(RED, f"An error occurred while executing the command: {str(e)}")

    printc(GREEN, "")


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


def update_stack(stack_name, template_body, parameters, capabilities, account_id, region, role):
    """
    Update an existing AWS CloudFormation stack using the provided template and parameters.
    
    Parameters:
    - stack_name (str): Name of the CloudFormation stack to update.
    - template_body (str): CloudFormation template as a string.
    - parameters (list): List of parameters to override in the stack.   
    - capabilities (str): CloudFormation capabilities
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the stack resides.
    - role (str): IAM Role to assume for cross-account access.
    
    Returns:
    - response (dict): Response from the CloudFormation API.
    """

    printc(YELLOW, f"Updating stack {stack_name} in AWS account {account_id} in region {region}...")
    
    # Get the CloudFormation client using the get_client function
    cf_client = get_client('cloudformation', account_id, region, role)

    # Standard tags
    tags = [
        {
            'Key': 'infra:immutable',
            'Value': 'true'
        }
    ]

    try:
        # Update the stack
        response = cf_client.update_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=[capabilities],
            Tags=tags,
        )
        return True
    except botocore.exceptions.ClientError as e:
        if "No updates are to be performed" in str(e):
            printc(GREEN, "No changes.")
            return False
        else:
            raise e
        

def create_stack(stack_name, template_body, parameters, capabilities, account_id, region, role):
    """
    Create a new AWS CloudFormation stack using the provided template and parameters.
    
    Parameters:
    - stack_name (str): Name of the CloudFormation stack to update.
    - template_body (str): CloudFormation template as a string.
    - parameters (list): List of parameters to override in the stack.   
    - capabilities (str): CloudFormation capabilities
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the stack resides.
    - role (str): IAM Role to assume for cross-account access.
    
    Returns:
    - response (dict): Response from the CloudFormation API.
    """

    printc(YELLOW, f"Creating stack {stack_name} in AWS account {account_id} in region {region}...")

    # Get the CloudFormation client using the get_client function
    cf_client = get_client('cloudformation', account_id, region, role)

    # Standard tags
    tags = [
        {
            'Key': 'infra:immutable',
            'Value': 'true'
        }
    ]

    try:
        # Update the stack
        response = cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=[capabilities],
            Tags=tags,
        )
        return True
    except botocore.exceptions.ClientError as e:
        if "No updates are to be performed" in str(e):
            printc(GREEN, "No changes.")
            return False
        else:
            raise e
        

def update_stack_set(stack_set_name, template_body, parameters, capabilities, regions, account_id, region, role):
    """
    Update an existing AWS CloudFormation StackSet using the provided template and parameters.
    
    Parameters:
    - stack_set_name (str): Name of the StackSet to update.
    - template_body (str): CloudFormation template as a string.
    - parameters (list): List of parameters to override in the StackSet.
    - capabilities (str): CloudFormation capabilities.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the StackSet resides.
    - role (str): IAM Role to assume for cross-account access.
    
    Returns:
    - response (dict): Response from the CloudFormation API.
    """

    printc(YELLOW, f"Updating stack set {stack_set_name} in AWS account {account_id} in region {region}...")

    # Get the CloudFormation client using the get_client function
    cf_client = get_client('cloudformation', account_id, region, role)

    # Standard tags
    tags = [
        {
            'Key': 'infra:immutable',
            'Value': 'true'
        }
    ]

    try:
        # Update the StackSet
        response = cf_client.update_stack_set(
            StackSetName=stack_set_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=[capabilities],
            Tags=tags,
            OperationPreferences={
                'RegionConcurrencyType': 'PARALLEL',
            #    'RegionOrder': regions,
                'FailureTolerancePercentage': 0,
                'MaxConcurrentPercentage': 100
            },
        )
        return True
    except botocore.exceptions.ClientError as e:
        if "No updates are to be performed" in str(e):
            printc(YELLOW, "StackSet update: No changes are needed.")
            return False
        else:
            raise e


def create_stack_set(stack_set_name, template_body, parameters, capabilities, root_ou, deployment_regions, account_id, region, role):
    printc(YELLOW, f"Creating stack set {stack_set_name} in AWS account {account_id} in region {region}...")

    cf_client = get_client('cloudformation', account_id, region, role)

    tags = [
        {
            'Key': 'infra:immutable',
            'Value': 'true'
        }
    ]

    try:
        response = cf_client.create_stack_set(
            StackSetName=stack_set_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=[capabilities],
            PermissionModel='SERVICE_MANAGED',
            AutoDeployment={
                'Enabled': True,
                'RetainStacksOnAccountRemoval': False
            },
            Tags=tags,
            OperationPreferences={
                'RegionConcurrencyType': 'PARALLEL',
#                'RegionOrder': deployment_regions,
                'FailureTolerancePercentage': 0,
                'MaxConcurrentPercentage': 100
            },
        )

        monitor_stackset_until_complete(stack_set_name, account_id, region, role)

        cf_client.create_stack_instances(
            StackSetName=stack_set_name,
            DeploymentTargets={
                'OrganizationalUnitIds': [root_ou],
            },
            Regions=deployment_regions,
        )
        monitor_stackset_stacks_until_complete(stack_set_name, account_id, region, role)

        return response
    except botocore.exceptions.ClientError as e:
        if "AlreadyExistsException" in str(e):
            printc(RED, "StackSet already exists.")
        else:
            raise e


def monitor_stack_until_complete(stack_name, account_id, region, role):
    """
    Polls the specified CloudFormation stack until it reaches a terminal state.
    
    Parameters:
    - stack_name (str): Name of the CloudFormation stack to monitor.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the stack resides.
    - role (str): IAM Role to assume for cross-account access.
    """
    
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

    printc(YELLOW, "Waiting for stack or stack set to complete...")
    
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


def monitor_stackset_until_complete(stackset_name, account_id, region, role):
    """
    Polls the specified StackSet until it reaches a terminal state.
    
    Parameters:
    - stackset_name (str): Name of the StackSet to monitor.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the StackSet resides.
    - role (str): IAM Role to assume for cross-account access.
    """
    
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

    printc(YELLOW, "Waiting for StackSet deployment to complete...")

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


def monitor_stackset_stacks_until_complete(stackset_name, account_id, region, role):
    """
    Polls the specified StackSet's stacks until they reach a terminal state.
    
    Parameters:
    - stackset_name (str): Name of the StackSet to monitor.
    - account_id (str): AWS Account ID to assume the role from.
    - region (str): AWS Region where the StackSet resides.
    - role (str): IAM Role to assume for cross-account access.
    """
    
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

    printc(YELLOW, "Waiting for stack set's deployment of its stacks to complete...")

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


def process_cloudformation(jobs, repo_name, params, cross_account_role):
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
    #org_id = params['org-id']
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
        stack_parameters = parameters_to_cloudformation_json(params, repo_name, stack_name)

        if not stack_set:
            for region in regions:
                exists = does_stack_exist(stack_name, account, region, cross_account_role)
                if exists:
                    # printc(YELLOW, f"- Stack exists in {account} and {region}")
                    monitor_stack_until_complete(stack_name, account, region, cross_account_role)
                    changing = update_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role)
                    if changing:
                        time.sleep(1)
                        monitor_stack_until_complete(stack_name, account, region, cross_account_role)
                else:
                    # printc(YELLOW, f"- Stack does not exist in {account} and {region}")
                    changing = create_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role)
                    if changing:
                        time.sleep(1)
                        monitor_stack_until_complete(stack_name, account, region, cross_account_role)

        else:
            exists = does_stackset_exist(stack_name, account, main_region, cross_account_role)
            if exists:
                # printc(YELLOW, f"- StackSet exists in {account} and {main_region}")
                monitor_stackset_until_complete(stack_name, account, main_region, cross_account_role)
                monitor_stackset_stacks_until_complete(stack_name, account, main_region, cross_account_role)
                changing = update_stack_set(stack_name, template_str, stack_parameters, capabilities, regions, account, main_region, cross_account_role)
                if changing:
                    time.sleep(1)
                    monitor_stackset_until_complete(stack_name, account, main_region, cross_account_role)
            else:
                # printc(YELLOW, f"- StackSet does not exist in {account} and {main_region}")
                create_stack_set(stack_name, template_str, stack_parameters, capabilities, root_ou, regions, account, main_region, cross_account_role)
                monitor_stackset_stacks_until_complete(stack_name, account, main_region, cross_account_role)

            # Check the Stack(s) in the admin account(s) as well
            for region in regions:
                exists = does_stack_exist(stack_name, admin_account_id, region, cross_account_role)
                if exists:
                    # printc(YELLOW, f"- Also deployed as a single Stack in the AWS Organization admin account in {region}")
                    monitor_stack_until_complete(stack_name, account, region, cross_account_role)
                    changing = update_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role)
                    if changing:
                        time.sleep(1)
                        monitor_stack_until_complete(stack_name, account, region, cross_account_role)
                else:
                    # printc(YELLOW, f"- Not deployed as a single Stack in the AWS Organization admin account in {region}")
                    changing = create_stack(stack_name, template_str, stack_parameters, capabilities, account, region, cross_account_role)
                    if changing:
                        time.sleep(1)
                        monitor_stack_until_complete(stack_name, account, region, cross_account_role)


# ---------------------------------------------------------------------------------------
# 
# Entry point
# 
# ---------------------------------------------------------------------------------------

def deploy():
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

    # Decide what to do
    if sam:
        process_cloudformation(pre_sam, repo_name, params, cross_account_role)
        process_sam(sam, repo_name, params)
        process_cloudformation(post_sam, repo_name, params, cross_account_role)

    else:
        process_cloudformation(cf, repo_name, params, cross_account_role)


def main():
    # Check that the user is logged in
    if not check_aws_sso_session():
        return
    
    deploy()


if __name__ == '__main__':
    main()
