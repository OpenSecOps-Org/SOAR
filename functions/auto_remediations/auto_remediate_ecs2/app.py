import os
import boto3
import json
from botocore.exceptions import ClientError

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    account_id = finding['AwsAccountId']

    resource = finding['Resources'][0]
    region = resource['Region']
    service = resource['Id'].split('/')[-1]

    if not resource.get('Details'):
        print("No Details provided in the event. Suppressing.")
        data['messages']['actions_taken'] = "No Details provided in the event. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    details = resource['Details']['AwsEcsService']
    cluster = details['Cluster'].split('/')[-1]
    
    aws_vpc_configuration = details['NetworkConfiguration']['AwsVpcConfiguration']
    subnets = aws_vpc_configuration['Subnets']
    security_groups = aws_vpc_configuration['SecurityGroups']

    client = get_client('ecs', account_id, region)

    try:
        response = client.update_service(
            cluster=cluster,
            service=service,
            networkConfiguration={
                'awsvpcConfiguration': {
                    'subnets': subnets,
                    'securityGroups': security_groups,
                    'assignPublicIp': 'DISABLED'
                }
            }
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'ClusterNotFoundException':
            print("The ECS cluster wasn't found. Suppressing.")
            data['messages']['actions_taken'] = "The ECS cluster wasn't found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        if error.response['Error']['Code'] == 'ServiceNotFoundException':
            print("The ECS service wasn't found. Suppressing.")
            data['messages']['actions_taken'] = "The ECS service wasn't found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        if error.response['Error']['Code'] == 'ServiceNotActiveException':
            print("The ECS service wasn't active. Suppressing.")
            data['messages']['actions_taken'] = "The ECS service wasn't active. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        raise error
    print(response)
    data['messages']['actions_taken'] = "The ECS service has had assignPublicIp set to DISABLED."
    data['messages']['actions_required'] = "None"
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ecs2_{account_id}"
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
