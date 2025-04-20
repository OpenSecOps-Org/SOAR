"""
RDS.11 AUTOREMEDIATION - ENABLE AUTOMATIC BACKUPS

This Lambda function automatically remediates AWS Security Hub findings for RDS.11 
(RDS instances should have automatic backups enabled).

Target Resources:
- RDS DB Instances
- RDS DB Clusters (Aurora)

Remediation Action:
- Sets BackupRetentionPeriod=7 (7 days) on DB instances and clusters
- Changes take effect immediately (ApplyImmediately=True)

Test Trigger:
1. Create an RDS instance with automatic backups disabled (backup retention period set to 0)
2. Create an Aurora cluster with automatic backups disabled (backup retention period set to 0)
3. Verify the finding appears in Security Hub for RDS.11

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-11
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

    # Enable automatic backups (7 days) on instance or cluster as appropriate
    if not db_cluster_identifier:
        success = modify_db_resource(
            client, 
            'instance', 
            db_instance_identifier, 
            {'BackupRetentionPeriod': 7}, 
            data
        )
    else:
        success = modify_db_resource(
            client, 
            'cluster', 
            db_cluster_identifier, 
            {'BackupRetentionPeriod': 7}, 
            data
        )
        
    # If resource not found, the response will already be in data
    if 'suppress_finding' in data.get('actions', {}):
        return data
        
    data['messages']['actions_taken'] = "Automatic backups have been enabled. The retention period is 7 days."
    data['messages']['actions_required'] = "None"
    return data