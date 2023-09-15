import os
import boto3
import botocore

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']
STS_CLIENT = boto3.client('sts')

def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    account_id = finding['AwsAccountId']
    resource = finding['Resources'][0]
    region = resource['Region']
    elb_type = resource['Type']

    alb_arn = resource['Id']
    alb_dns_name = resource['Details'][elb_type]['DNSName']
    alb_name = alb_dns_name.split('.')[0][0:50]

    print(f"alb_dns_name: {alb_dns_name}")
    print(f"alb_name: {alb_name}")

    elbv2_client = get_client('elbv2', account_id, region)

    alb_scheme = alb_exists(elbv2_client, alb_arn)
    
    if alb_scheme == 'internet-facing':
        result = redirect_http_to_https(elbv2_client, alb_arn)

        if result:
            print("The ALB was successfully configured to redirect HTTP to HTTPS.")
            data['messages']['actions_taken'] = "The ALB was successfully configured to redirect HTTP to HTTPS."
            data['messages']['actions_required'] = f"None"
            
        else:
            print("The ALB could not be configured to redirect HTTP to HTTPS. Create ticket to team to fix.")
            data['actions']['autoremediation_not_done'] = True
            data['messages']['actions_taken'] = "None. The ALB could not be configured to redirect HTTP to HTTPS as no certificate was found."
            data['messages']['actions_required'] = "Please add a certificate and update the ALB to redirect HTTP to HTTPS."

    elif alb_scheme == 'internal':
        print("The ALB is internal and does not require HTTP to HTTPS redirection.")
        data['messages']['actions_taken'] = "ALB is internal. This finding has been suppressed."
        data['actions']['suppress_finding'] = True

    else:
        print("The ALB could not be found.")
        data['messages']['actions_taken'] = "ALB not found. This finding has been suppressed."
        data['actions']['suppress_finding'] = True

    return data


def alb_exists(elbv2_client, alb_arn):
    try:
        response = elbv2_client.describe_load_balancers(LoadBalancerArns=[alb_arn])
        return response['LoadBalancers'][0]['Scheme']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            return False
        else:
            raise e


def redirect_http_to_https(elbv2_client, alb_arn):
    try:
        # Get the HTTPS listener
        response = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
        https_listener = next((listener for listener in response['Listeners'] if listener['Port'] == 443), None)

        # If no HTTPS listener is found, there's no SSL certificate installed
        if https_listener is None:
            print("No SSL certificate found.")
            return False

        # Get the HTTP listener
        http_listener = next((listener for listener in response['Listeners'] if listener['Port'] == 80), None)

        if http_listener is None:
            print("No HTTP listener found.")
            return False

        # Create a redirect action
        redirect_action = {
            'Type': 'redirect',
            'RedirectConfig': {
                'Protocol': 'HTTPS',
                'Port': '443',
                'StatusCode': 'HTTP_301'
            }
        }

        # Modify the HTTP listener to use the redirect action
        elbv2_client.modify_listener(
            ListenerArn=http_listener['ListenerArn'],
            DefaultActions=[redirect_action]
        )

        return True
    
    except botocore.exceptions.ClientError as e:
        print(f"An error occurred: {e}")
        return False


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = STS_CLIENT.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_elb1_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )
