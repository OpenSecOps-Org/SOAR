import os
import boto3
import json
from botocore.exceptions import ClientError

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']

    cluster = resource['Id'].split('/')[-1]
    
    client = get_client('ecs', account_id, region)

    try:
        response = client.update_cluster(
            cluster=cluster,
            settings=[
                {
                    'name': 'containerInsights',
                    'value': 'enabled'
                }
            ]
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'ClusterNotFoundException':
            print("The ECS cluster wasn't found. Suppressing.")
            data['messages']['actions_taken'] = "The ECS cluster wasn't found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        raise error
    print(response)
    data['messages']['actions_taken'] = "The ECS cluster has had Container Insights enabled."
    data['messages']['actions_required'] = "None"
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ecs12_{account_id}"
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
