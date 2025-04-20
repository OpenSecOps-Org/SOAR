"""
RDS.17 AUTOREMEDIATION - ENABLE TAG COPYING TO SNAPSHOTS

This Lambda function automatically remediates AWS Security Hub findings for RDS.17 
(RDS instances should have tags copied to snapshots).

Target Resources:
- RDS DB Instances
- RDS DB Clusters (Aurora)

Remediation Action:
- Sets CopyTagsToSnapshot=True on DB instances and clusters
- Changes take effect immediately (ApplyImmediately=True)

Test Trigger:
1. Create an RDS instance with tag copying to snapshots disabled
2. Create an Aurora cluster with tag copying to snapshots disabled
3. Verify the finding appears in Security Hub for RDS.17

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-17
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
    db_cluster_identifier = details.get('DBClusterIdentifier')

    client = get_client('rds', account_id, region)

    # Enable tag copying to snapshots on instance or cluster as appropriate
    if not db_cluster_identifier:
        success = modify_db_resource(
            client, 
            'instance', 
            db_instance_identifier, 
            {'CopyTagsToSnapshot': True}, 
            data
        )
    else:
        success = modify_db_resource(
            client, 
            'cluster', 
            db_cluster_identifier, 
            {'CopyTagsToSnapshot': True}, 
            data
        )
        
    # If resource not found, the response will already be in data
    if 'suppress_finding' in data.get('actions', {}):
        return data
        
    data['messages']['actions_taken'] = "Tag copying to snapshots has been enabled."
    data['messages']['actions_required'] = "None"
    return data