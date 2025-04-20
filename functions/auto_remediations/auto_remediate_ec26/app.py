import os
import json
import logging
import random

import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client

logger = logging.getLogger(__name__)


def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Extract the necessary information from the data
    finding = data['finding']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    vpc_id = finding['Resources'][0]['Id'].rsplit('/', 1)[1]

    # Get the IAM client for the specified account and region
    iam = get_client('iam', account_id, region)

    # Generate a random number for role and policy names
    rnd = random.randint(100000, 999999)

    # Create a role for VPC Flow Logs with the specified allowed services
    role_name = f"VPCFlowLogsLoggingRole-{rnd}"
    create_role(iam, role_name, ['vpc-flow-logs.amazonaws.com'])

    # Create a policy for VPC Flow Logs with the necessary permissions
    policy_name = f"VPCFlowLogsLoggingPolicy-{rnd}"
    create_policy(
        iam,
        policy_name,
        'Gives VPC Flow Logs the permission to write to CloudWatch logs',
        [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
        ],
        '*'
    )

    # Attach the policy to the role
    attach_policy(
        iam,
        role_name,
        f"arn:aws:iam::{account_id}:policy/{policy_name}"
    )

    # Get the EC2 client for the specified account and region
    ec2 = get_client('ec2', account_id, region)

    # Create VPC Flow Logs with the specified configuration
    log_group_name = f"VPCFlowLogs/{vpc_id}"
    response = ec2.create_flow_logs(
        ResourceType='VPC',
        ResourceIds=[vpc_id],
        TrafficType='REJECT',
        LogDestinationType='cloud-watch-logs',
        LogGroupName=log_group_name,
        DeliverLogsPermissionArn=f"arn:aws:iam::{account_id}:role/{role_name}"
    )

    # Print the response from creating VPC Flow Logs
    print(response)

    # Update the messages in the input data to reflect the actions taken
    data['messages']['actions_taken'] = f"Flow logs have been enabled. The log group {log_group_name}, the role {role_name} and the policy {policy_name} have been created to support this."
    data['messages']['actions_required'] = "None"

    # Return the modified input data
    return data




def create_role(iam, role_name, allowed_services):
    # Create a role that allows the specified services to assume the role
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': service},
            'Action': 'sts:AssumeRole'
        } for service in allowed_services
        ]
    }

    try:
        # Create the role with the specified name and trust policy
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy))
        logger.info("Created role %s.", role_name)
    except ClientError:
        logger.exception("Couldn't create role %s.", role_name)
        raise
    else:
        return role


def attach_policy(iam, role_name, policy_arn):
    # Attach a policy to the specified role
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logger.info("Attached policy %s to role %s.", policy_arn, role_name)
    except ClientError:
        logger.exception(
            "Couldn't attach policy %s to role %s.", policy_arn, role_name)
        raise


def create_policy(iam, name, description, actions, resource_arn):
    # Create a policy with a single statement
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": resource_arn
            }
        ]
    }
    try:
        # Create the policy with the specified name, description, and document
        policy = iam.create_policy(
            PolicyName=name, Description=description,
            PolicyDocument=json.dumps(policy_doc))
        logger.info("Created policy %s.", name)
    except ClientError:
        logger.exception("Couldn't create policy %s.", name)
        raise
    else:
        return policy
