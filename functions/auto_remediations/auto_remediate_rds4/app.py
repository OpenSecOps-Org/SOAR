"""
RDS.4 AUTOREMEDIATION - ENCRYPT RDS SNAPSHOTS

This Lambda function automatically remediates AWS Security Hub findings for RDS.4
(RDS DB snapshots should be encrypted at rest).

Target Resources:
- RDS DB Snapshots
- RDS DB Cluster Snapshots (Aurora)

Remediation Actions:
1. For unencrypted snapshots with data (AllocatedStorage > 0):
   - Creates an encrypted copy using AWS managed KMS key (aws/rds)
   - Deletes the original unencrypted snapshot
2. For empty snapshots (AllocatedStorage = 0):
   - Deletes the snapshot directly

Test Trigger:
1. Create an unencrypted RDS instance with storage encryption disabled
2. Take a manual snapshot of the unencrypted RDS instance
3. Create an unencrypted Aurora cluster with storage encryption disabled
4. Take a manual snapshot of the unencrypted Aurora cluster
5. Verify the finding appears in Security Hub for RDS.4

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-4
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
    """Main Lambda handler function."""
    print(data)

    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']
    
    # Get snapshot details from the resource
    resource_type = resource['Type']
    resource_arn = resource['Id']
    details = resource['Details'][resource_type]
    snapshot_type = details['SnapshotType']  # 'manual', etc
    snapshot_name = resource_arn.split(':')[-1]  # last part of the ARN
    
    client = get_client('rds', account_id, region)

    # Process the appropriate snapshot type
    if resource_type == 'AwsRdsDbClusterSnapshot':
        return process_cluster_snapshot(
            client, data, snapshot_name, snapshot_type
        )
    else:
        return process_instance_snapshot(
            client, data, snapshot_name, snapshot_type
        )


###########################################################################
#
# Control-Specific Functions
#
###########################################################################

def process_cluster_snapshot(client, data, snapshot_name, snapshot_type):
    """Process a DB cluster snapshot - copy with encryption."""
    # Copy the snapshot with encryption specified
    print(f"Copying cluster snapshot {snapshot_name} with encryption enabled...")
    snapshot_target_name = f'{snapshot_name}-encrypted'
    
    try:
        response = client.copy_db_cluster_snapshot(
            SourceDBClusterSnapshotIdentifier=snapshot_name,
            TargetDBClusterSnapshotIdentifier=snapshot_target_name,
            KmsKeyId='alias/aws/rds',
            CopyTags=True
        )
    except ClientError as error:
        if handle_not_found_error(error, 'cluster_snapshot', data):
            return data
            
        if error.response['Error']['Code'] == 'InvalidParameterValue':
            error_message = error.response['Error']['Message']
            if 'Copying unencrypted cluster with encryption is not supported' in error_message:
                print("The operation is not supported, team must fix.")
                data['actions']['autoremediation_not_done'] = True
                data['messages']['actions_taken'] = (
                    "Cannot encrypt this snapshot type automatically. "
                    "Manual action required."
                )
                return data
        raise error
    
    print(response)

    # Wait for the target (encrypted) snapshot to be available
    print(f"Waiting for encrypted cluster snapshot {snapshot_target_name} "
          f"to become available...")
    waiter = client.get_waiter('db_cluster_snapshot_available')
    waiter.wait(DBClusterSnapshotIdentifier=snapshot_target_name)
    print(f"Encrypted cluster snapshot {snapshot_target_name} is now available")

    # Delete the original snapshot
    print(f"Deleting the original unencrypted cluster snapshot {snapshot_name}...")
    try:
        response = client.delete_db_cluster_snapshot(
            DBClusterSnapshotIdentifier=snapshot_name
        )
        print(response)
    except ClientError as error:
        print(f"Failed to delete original cluster snapshot: {str(error)}")
        data['messages']['actions_taken'] = (
            f"Created encrypted snapshot '{snapshot_target_name}' but failed "
            f"to delete the original unencrypted snapshot '{snapshot_name}'. "
            f"Please delete it manually."
        )
        data['messages']['actions_required'] = (
            f"Delete unencrypted snapshot '{snapshot_name}' manually."
        )
        return data

    # Success
    data['messages']['actions_taken'] = (
        f"The snapshot has been copied to a new, encrypted snapshot "
        f"'{snapshot_target_name}'. The original snapshot has been deleted."
    )
    data['messages']['actions_required'] = "None"
    return data


def process_instance_snapshot(client, data, snapshot_name, snapshot_type):
    """Process a DB instance snapshot - copy with encryption."""
    # Copy the snapshot with encryption specified
    print(f"Copying instance snapshot {snapshot_name} with encryption enabled...")
    snapshot_target_name = f'{snapshot_name}-encrypted'
    
    try:
        response = client.copy_db_snapshot(
            SourceDBSnapshotIdentifier=snapshot_name,
            TargetDBSnapshotIdentifier=snapshot_target_name,
            KmsKeyId='alias/aws/rds',
            CopyTags=True
        )
    except ClientError as error:
        if handle_not_found_error(error, 'snapshot', data):
            return data
            
        if error.response['Error']['Code'] == 'InvalidParameterValue':
            error_message = error.response['Error']['Message']
            if 'with encryption is not supported' in error_message:
                print("The operation is not supported, team must fix.")
                data['actions']['autoremediation_not_done'] = True
                data['messages']['actions_taken'] = (
                    "Cannot encrypt this snapshot type automatically. "
                    "Manual action required."
                )
                return data
        raise error
    
    print(response)

    # Wait for the target (encrypted) snapshot to be available
    print(f"Waiting for encrypted instance snapshot {snapshot_target_name} "
          f"to become available...")
    waiter = client.get_waiter('db_snapshot_available')
    waiter.wait(DBSnapshotIdentifier=snapshot_target_name)
    print(f"Encrypted instance snapshot {snapshot_target_name} is now available")

    # Delete the original snapshot
    print(f"Deleting the original unencrypted instance snapshot {snapshot_name}...")
    try:
        response = client.delete_db_snapshot(
            DBSnapshotIdentifier=snapshot_name
        )
        print(response)
    except ClientError as error:
        print(f"Failed to delete original instance snapshot: {str(error)}")
        data['messages']['actions_taken'] = (
            f"Created encrypted snapshot '{snapshot_target_name}' but failed "
            f"to delete the original unencrypted snapshot '{snapshot_name}'. "
            f"Please delete it manually."
        )
        data['messages']['actions_required'] = (
            f"Delete unencrypted snapshot '{snapshot_name}' manually."
        )
        return data

    # Success
    data['messages']['actions_taken'] = (
        f"The snapshot has been copied to a new, encrypted snapshot "
        f"'{snapshot_target_name}'. The original snapshot has been deleted."
    )
    data['messages']['actions_required'] = "None"
    return data
