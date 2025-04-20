import os
import boto3
import json
from botocore.exceptions import ClientError
from aws_utils.clients import get_client


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


