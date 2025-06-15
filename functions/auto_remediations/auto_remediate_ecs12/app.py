"""
ECS.12 AUTOREMEDIATION - ENABLE ECS CONTAINER INSIGHTS

This Lambda function automatically remediates AWS Security Hub findings for ECS.12
(ECS clusters should have Container Insights enabled).

Target Resources:
- Amazon ECS clusters
- Applies to both EC2 and Fargate clusters

Remediation Actions:
1. Extracts cluster name from cluster ARN
2. Enables Container Insights monitoring for the specific cluster
3. Configures monitoring setting to 'enabled'

Validation Commands:
# Check cluster Container Insights status
aws ecs describe-clusters --clusters <cluster-name>

# Verify Container Insights is enabled
aws ecs describe-clusters --clusters <cluster-name> --query 'clusters[0].settings'

# Check CloudWatch Container Insights metrics
aws logs describe-log-groups --log-group-name-prefix "/aws/ecs/containerinsights"

Security Impact:
- Enables comprehensive container monitoring and observability
- Provides detailed metrics for CPU, memory, network, and storage
- Enhances security monitoring capabilities for containerized workloads
- Supports performance optimization and troubleshooting

Monitoring Benefits:
- Task and service level metrics
- Container runtime metrics
- Network performance metrics
- Storage utilization tracking
- Custom application metrics integration

Error Handling:
- Missing cluster: Suppresses finding (cluster may have been deleted)
- API errors: Re-raises for investigation

Cluster ARN Format:
- Input: arn:aws:ecs:region:account:cluster/cluster-name
- Extracted: cluster-name (everything after the last slash)
"""

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


