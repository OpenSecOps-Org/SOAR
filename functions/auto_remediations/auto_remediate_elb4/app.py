import os
import json
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


