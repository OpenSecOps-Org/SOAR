"""
RDS.2 AUTOREMEDIATION - DISABLE PUBLIC ACCESSIBILITY

This Lambda function automatically remediates AWS Security Hub findings for RDS.2 
(RDS DB Instances should not be publicly accessible).

Target Resources:
- RDS DB Instances
- Aurora DB Instances (part of RDS DB Clusters)

Remediation Action:
- Sets PubliclyAccessible=False on DB instances
- Changes take effect immediately (ApplyImmediately=True)

Test Trigger:
1. Create an RDS instance with public accessibility enabled
2. Create an Aurora DB instance as part of a cluster with public accessibility enabled

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-2
"""

import os
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

    client = get_client('rds', account_id, region)

    # PubliclyAccessible is only a valid parameter for DB instances, not DB clusters
    # Even for Aurora DB instances that are part of a cluster, we modify the instance directly
    success = modify_db_resource(
        client, 
        'instance', 
        db_instance_identifier, 
        {'PubliclyAccessible': False}, 
        data
    )
        
    # If resource not found, the response will already be in data
    if 'suppress_finding' in data.get('actions', {}):
        return data
        
    data['messages']['actions_taken'] = "Public access has been disabled."
    data['messages']['actions_required'] = "None"
    return data


