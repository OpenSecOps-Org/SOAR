"""
AWS Security Hub Auto-Remediation: EC2.6 - VPC Flow Logs Enable

This control checks that VPC flow logs are enabled in Amazon VPC. VPC flow logs 
capture network traffic information for traffic flowing to and from network interfaces 
in your VPC, providing visibility into network traffic patterns.

Test triggers:
- VPC without flow logs enabled: aws ec2 describe-vpcs --vpc-ids vpc-12345
- Check flow logs status: aws ec2 describe-flow-logs --filter "Name=resource-id,Values=vpc-12345"

The auto-remediation enables VPC flow logs for REJECT traffic to CloudWatch Logs,
creating the necessary IAM role and policy for log delivery.

Target Resources: AWS VPC without flow logs enabled
Remediation: Enable VPC flow logs with CloudWatch Logs destination for REJECT traffic
"""

import os
import json
import logging
import random

import boto3
from aws_utils.clients import get_client

logger = logging.getLogger(__name__)


def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.6 auto-remediation.
    
    Args:
        data: Security Hub finding data containing VPC details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract VPC ID from Security Hub finding
        2. Create IAM role for VPC Flow Logs service
        3. Create IAM policy with CloudWatch Logs permissions
        4. Attach policy to role for flow logs delivery
        5. Enable VPC flow logs for REJECT traffic to CloudWatch
    """
    print(data)

    # Extract VPC information from Security Hub finding
    finding = data['finding']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    vpc_id = finding['Resources'][0]['Id'].rsplit('/', 1)[1]  # Extract VPC ID from ARN

    # Get cross-account IAM client for role and policy creation
    iam = get_client('iam', account_id, region)

    # Generate unique suffix to avoid naming conflicts in concurrent executions
    rnd = random.randint(100000, 999999)

    # STEP 1: Create IAM role for VPC Flow Logs service
    # This role allows the VPC Flow Logs service to write to CloudWatch Logs
    role_name = f"VPCFlowLogsLoggingRole-{rnd}"
    create_role(iam, role_name, ['vpc-flow-logs.amazonaws.com'])

    # STEP 2: Create IAM policy with CloudWatch Logs permissions
    # Required permissions for VPC Flow Logs to write log streams and events
    policy_name = f"VPCFlowLogsLoggingPolicy-{rnd}"
    create_policy(
        iam,
        policy_name,
        'Gives VPC Flow Logs the permission to write to CloudWatch logs',
        [
            "logs:CreateLogGroup",       # Create log groups for VPC flow logs
            "logs:CreateLogStream",      # Create log streams within log groups
            "logs:PutLogEvents",         # Write flow log events to streams
            "logs:DescribeLogGroups",    # List and describe existing log groups
            "logs:DescribeLogStreams"    # List and describe existing log streams
        ],
        '*'  # Allow access to all CloudWatch Logs resources
    )

    # STEP 3: Attach policy to role to grant necessary permissions
    attach_policy(
        iam,
        role_name,
        f"arn:aws:iam::{account_id}:policy/{policy_name}"
    )

    # STEP 4: Enable VPC Flow Logs with CloudWatch Logs destination
    # Get cross-account EC2 client for flow logs creation
    ec2 = get_client('ec2', account_id, region)

    # Configure flow logs to capture REJECT traffic for security monitoring
    log_group_name = f"VPCFlowLogs/{vpc_id}"
    response = ec2.create_flow_logs(
        ResourceType='VPC',                     # Monitor entire VPC
        ResourceIds=[vpc_id],                   # Target VPC identifier
        TrafficType='REJECT',                   # Only log rejected traffic for security
        LogDestinationType='cloud-watch-logs',  # Send logs to CloudWatch
        LogGroupName=log_group_name,           # Organized by VPC ID
        DeliverLogsPermissionArn=f"arn:aws:iam::{account_id}:role/{role_name}"
    )

    print(response)

    # Update remediation status with details of created resources
    data['messages']['actions_taken'] = f"Flow logs have been enabled. The log group {log_group_name}, the role {role_name} and the policy {policy_name} have been created to support this."
    data['messages']['actions_required'] = "None"
    return data




def create_role(iam, role_name, allowed_services):
    """
    Create an IAM role that allows specified AWS services to assume it.
    
    Args:
        iam: IAM client for the target account
        role_name: Name for the new IAM role
        allowed_services: List of AWS service principals that can assume the role
        
    Returns:
        dict: Created role information
        
    Trust Policy:
        Allows the specified services (e.g., vpc-flow-logs.amazonaws.com) to assume
        the role and perform actions on behalf of the service.
    """
    # Create trust policy allowing specified services to assume the role
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': service},
            'Action': 'sts:AssumeRole'
        } for service in allowed_services
        ]
    }

    # Create role - let state machine handle any errors
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy))
    logger.info("Created role %s.", role_name)
    return role


def attach_policy(iam, role_name, policy_arn):
    """
    Attach an IAM policy to a role to grant specific permissions.
    
    Args:
        iam: IAM client for the target account
        role_name: Name of the role to attach policy to
        policy_arn: ARN of the policy to attach
        
    Error Handling:
        All errors bubble up to state machine for uniform ticketing fallback (v2.2.1+).
    """
    # Attach policy - let state machine handle any errors
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    logger.info("Attached policy %s to role %s.", policy_arn, role_name)


def create_policy(iam, name, description, actions, resource_arn):
    """
    Create an IAM policy with specified permissions.
    
    Args:
        iam: IAM client for the target account
        name: Name for the new policy
        description: Human-readable description of the policy
        actions: List of IAM actions to allow
        resource_arn: Resource ARN or wildcard for allowed resources
        
    Returns:
        dict: Created policy information
        
    Policy Structure:
        Creates a policy document with a single Allow statement granting
        the specified actions on the specified resources.
    """
    # Create policy document with Allow statement for specified actions
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
    # Create policy - let state machine handle any errors
    policy = iam.create_policy(
        PolicyName=name, Description=description,
        PolicyDocument=json.dumps(policy_doc))
    logger.info("Created policy %s.", name)
    return policy
