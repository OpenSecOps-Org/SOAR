"""
RDS.6 AUTOREMEDIATION - ENABLE ENHANCED MONITORING

This Lambda function automatically remediates AWS Security Hub findings for RDS.6 
(Enhanced monitoring should be configured for RDS DB instances).

Target Resources:
- RDS DB Instances
- RDS DB Clusters (Aurora)

Remediation Actions:
1. Creates an IAM role (rds-monitoring-role) with required permissions
2. Attaches the AmazonRDSEnhancedMonitoringRole policy to the role
3. Sets MonitoringInterval=60 (60 seconds) on DB instances and clusters
4. Associates the monitoring role with the DB instances and clusters

Test Trigger:
1. Create an RDS instance with enhanced monitoring disabled
2. Create an Aurora cluster instance with enhanced monitoring disabled
3. Verify the finding appears in Security Hub for RDS.6

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-6
"""

import os
import json
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client
from rds_remediation.utils import (
    get_engine_details,
    get_parameter_group_family,
    ensure_resource_available,
    modify_db_resource,
    handle_not_found_error
)

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']

    details = resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    db_cluster_identifier = details.get('DBClusterIdentifier')

    client = get_client('rds', account_id, region)
    iam = get_client('iam', account_id, region)

    # Define role details
    role_name = 'rds-monitoring-role'
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole'

    # Create and configure monitoring role
    create_role(iam, role_name, ['monitoring.rds.amazonaws.com'])
    attach_policy(iam, role_name, policy_arn)
    
    # Enhanced monitoring parameters
    params = {
        'MonitoringRoleArn': role_arn,
        'MonitoringInterval': 60
    }

    # Enable enhanced monitoring on instance or cluster as appropriate
    if not db_cluster_identifier:
        success = modify_db_resource(
            client, 
            'instance', 
            db_instance_identifier, 
            params, 
            data
        )
    else:
        success = modify_db_resource(
            client, 
            'cluster', 
            db_cluster_identifier, 
            params, 
            data
        )
        
    # If resource not found, the response will already be in data
    if 'suppress_finding' in data.get('actions', {}):
        return data
        
    data['messages']['actions_taken'] = "Enhanced monitoring has been enabled with a monitoring interval of 60 seconds."
    data['messages']['actions_required'] = "None"
    return data




###########################################################################
#
# Control-Specific Functions
#
###########################################################################

def create_role(iam, role_name, allowed_services):
    """Creates a role that lets a list of specified services assume the role."""
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
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy))
        print(f"Created role {role_name}")
    except ClientError as error:
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"The Role {role_name} already exists")
            return False
        print(f"Couldn't create role {role_name}: {str(error)}")
        raise error
    return role


def attach_policy(iam, role_name, policy_arn):
    """Attaches a policy to a role."""
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"Attached policy {policy_arn} to role {role_name}")
    except ClientError as error:
        if error.response['Error']['Code'] in ['EntityAlreadyExists', 'NoSuchEntityException']:
            print("The policy has already been attached or role doesn't exist")
            return False
        print(f"Couldn't attach policy {policy_arn} to role {role_name}: {str(error)}")
        raise error
    return True