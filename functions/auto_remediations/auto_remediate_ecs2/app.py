import os
import boto3
import json
from botocore.exceptions import ClientError
from aws_utils.clients import get_client


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


