import os
import json
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

    result = configure_alb_drop_invalid_headers(elbv2_client, alb_arn)
    
    if result == "NotFound":
        print("The ALB could not be found.")
        data['messages']['actions_taken'] = "ALB not found. This finding has been suppressed."
        data['actions']['suppress_finding'] = True

    elif result:
        print("The ALB was successfully configured to drop illegal HTTP headers.")
        data['messages']['actions_taken'] = "The ALB was successfully configured to drop illegal HTTP headers."
        data['messages']['actions_required'] = f"None"

    else:
        print("The ALB could not be configured to drop illegal HTTP headers. Create ticket to team to fix.")
        data['actions']['autoremediation_not_done'] = True
        data['messages']['actions_taken'] = "None. The ALB could not be configured to drop illegal HTTP headers."
        data['messages']['actions_required'] = "Please update the ALB to drop illegal HTTP headers."

    return data


def configure_alb_drop_invalid_headers(elbv2_client, alb_arn):
    # Enable dropping invalid HTTP headers for the specified ALB
    try:
        # Enable dropping invalid HTTP headers for the specified ALB
        response = elbv2_client.modify_load_balancer_attributes(
            LoadBalancerArn=alb_arn,
            Attributes=[
                {
                    'Key': 'routing.http.drop_invalid_header_fields.enabled',
                    'Value': 'true'
                }
            ]
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessPointNotFoundException':
            return "NotFound"
        else:
            raise e

    # Check if the modification was successful
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = STS_CLIENT.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_elb4_{account_id}"
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
