"""
ELB.1 AUTOREMEDIATION - CONFIGURE ALB HTTP TO HTTPS REDIRECTION

This Lambda function automatically remediates AWS Security Hub findings for ELB.1
(Application Load Balancer should be configured to redirect all HTTP requests to HTTPS).

Target Resources:
- Application Load Balancers (ALBs) with HTTP listeners
- Only applies to internet-facing ALBs (internal ALBs are exempt)

Remediation Actions:
1. Verifies ALB exists and checks if it's internet-facing or internal
2. For internet-facing ALBs:
   - Checks for existing HTTPS listener (requires SSL certificate)
   - Locates HTTP listener on port 80
   - Configures HTTP listener to redirect to HTTPS with 301 status
3. For internal ALBs: Suppresses finding (internal ALBs don't require HTTPS redirection)

Validation Commands:
# Check ALB listeners
aws elbv2 describe-listeners --load-balancer-arn arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id

# Verify redirect configuration
aws elbv2 describe-listeners --load-balancer-arn <alb-arn> --query 'Listeners[?Port==`80`].DefaultActions[0].RedirectConfig'

Security Impact:
- Ensures all HTTP traffic is automatically redirected to HTTPS
- Prevents unencrypted data transmission over HTTP
- Requires existing SSL certificate on HTTPS listener

Error Handling:
- Missing SSL certificate: Creates ticket for manual intervention
- Missing ALB: Suppresses finding
- Internal ALB: Suppresses finding (compliant by design)
"""

import os
import boto3
import botocore
from aws_utils.clients import get_client

def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    account_id = finding['AwsAccountId']
    resource = finding['Resources'][0]
    region = resource['Region']
    alb_arn = resource['Id']

    print(f"alb_arn: {alb_arn}")

    elbv2_client = get_client('elbv2', account_id, region)

    alb_scheme = alb_exists(elbv2_client, alb_arn)
    
    if alb_scheme == 'internet-facing':
        result = redirect_http_to_https(elbv2_client, alb_arn)

        if result:
            print("The ALB was successfully configured to redirect HTTP to HTTPS.")
            data['messages']['actions_taken'] = "The ALB was successfully configured to redirect HTTP to HTTPS."
            data['messages']['actions_required'] = "None"
            
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
        if e.response['Error']['Code'] in ['LoadBalancerNotFound', 'ValidationError']:
            print(f"Load balancer not found: {e}")
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


