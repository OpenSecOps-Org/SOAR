"""
ECS.2 AUTOREMEDIATION - DISABLE PUBLIC IP ASSIGNMENT FOR ECS SERVICES

This Lambda function automatically remediates AWS Security Hub findings for ECS.2
(ECS services should not have public IP addresses assigned automatically).

Target Resources:
- Amazon ECS services running in Fargate launch type
- Services with awsvpcConfiguration network mode
- Services currently configured with public IP assignment

Remediation Actions:
1. Extracts service and cluster names from service ARN
2. Parses detailed network configuration from finding details
3. Updates service network configuration to disable public IP assignment
4. Preserves existing subnets and security groups configuration

Network Security Impact:
- Prevents services from receiving public IP addresses automatically
- Forces traffic routing through NAT gateways or VPC endpoints
- Enhances network security by removing direct internet connectivity
- Critical for services handling sensitive data in private subnets

Validation Commands:
# Check service network configuration
aws ecs describe-services --cluster <cluster-name> --services <service-name>

# Verify public IP assignment is disabled
aws ecs describe-services --cluster <cluster-name> --services <service-name> --query 'services[0].networkConfiguration.awsvpcConfiguration.assignPublicIp'

# Check service running tasks
aws ecs list-tasks --cluster <cluster-name> --service-name <service-name>

Complex Data Structure Requirements:
- Requires detailed ECS service information in ASFF Details section
- Parses nested AwsEcsService configuration
- Extracts VPC configuration including subnets and security groups
- Preserves existing network settings while modifying public IP assignment

Error Handling Categories:
1. **Missing Details**: Suppresses finding if ASFF Details section is missing
2. **ClusterNotFoundException**: Suppresses finding (cluster may be deleted)
3. **ServiceNotFoundException**: Suppresses finding (service may be deleted)
4. **ServiceNotActiveException**: Suppresses finding (service not in deployable state)
5. **Other API errors**: Re-raises for investigation

Service ARN Format:
- Input: arn:aws:ecs:region:account:service/cluster-name/service-name
- Extracted service: service-name (last part after final slash)
- Extracted cluster: cluster-name (from Details.AwsEcsService.Cluster)

Network Configuration Structure:
- Details.AwsEcsService.NetworkConfiguration.AwsVpcConfiguration.Subnets[]
- Details.AwsEcsService.NetworkConfiguration.AwsVpcConfiguration.SecurityGroups[]
- AssignPublicIp: Changed from ENABLED → DISABLED

Note: This function requires comprehensive ASFF details including network configuration.
Only works with services using awsvpcConfiguration (Fargate and EC2 with awsvpc network mode).
"""

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


