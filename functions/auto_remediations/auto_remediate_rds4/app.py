import os
import botocore
import boto3

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts_client = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']
    client = get_client('rds', account_id, region)

    resource_type = resource['Type']
    resource_arn = resource['Id']

    details = resource['Details'][resource_type]

    allocated_storage = details['AllocatedStorage']     # 0 or greater
    snapshot_type = details['SnapshotType']             # 'manual', etc
    snapshot_name = resource_arn.split(':')[-1]         # last part of the ARN

    if resource_type == 'AwsRdsDbClusterSnapshot':
       return process_cluster_snapshot(client, data, allocated_storage, snapshot_name, snapshot_type)
    return process_instance_snapshot(client, data, allocated_storage, snapshot_name, snapshot_type)


def process_cluster_snapshot(client, data, allocated_storage, snapshot_name, snapshot_type):
    # If the snapshot is empty, just delete it and return immediately
    if allocated_storage == 0:
        print("The cluster snapshot was empty. Deleting it...")
        try:
            response = client.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_name)
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'DBClusterSnapshotNotFound':
                print("The snapshot can't be found. Suppressing.")
                data['messages']['actions_taken'] = "The snapshot cannot be found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
        print(response)
        data['messages']['actions_taken'] = "The snapshot was empty and has been deleted."
        data['messages']['actions_required'] = "None"
        return data

    # Copy the snapshot with encryption specified
    print("Attempting to copy the cluster snapshot...")
    snapshot_target_name = f'{snapshot_name}-encrypted'
    try:
        response = client.copy_db_cluster_snapshot(
            SourceDBClusterSnapshotIdentifier=snapshot_name,
            TargetDBClusterSnapshotIdentifier=snapshot_target_name,
            KmsKeyId='aws/rds',
            CopyTags=True
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'DBClusterSnapshotNotFound':
            print("The snapshot can't be found. Suppressing.")
            data['messages']['actions_taken'] = "The snapshot cannot be found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        if error.response['Error']['Code'] == 'InvalidParameterValue':
            if 'Copying unencrypted cluster with encryption is not supported' in error.response['Error']['Message']:
                print("The operation is not supported, team must fix.")
                data['actions']['autoremediation_not_done'] = True
                return data
        raise error
    print(response)

    # Wait for the copy to complete
    print("Waiting for the cluster snapshot copy operation to complete...")
    waiter = client.get_waiter('db_cluster_snapshot_available')
    waiter.wait(
        DBClusterSnapshotIdentifier=snapshot_name,
        SnapshotType=snapshot_type
    )

    # Delete the original snapshot
    print("Deleting the original snapshot...")
    response = client.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_name)

    # Success
    data['messages']['actions_taken'] = "The snapshot has been copied to a new, encrypted snapshot '{snapshot_target_name}'. The original snapshot has been deleted."
    data['messages']['actions_required'] = "None"
    return data


def process_instance_snapshot(client, data, allocated_storage, snapshot_name, snapshot_type):
    # If the snapshot is empty, just delete it and return immediately
    if allocated_storage == 0:
        print("The instance snapshot was empty. Deleting it...")
        try:
            response = client.delete_db_cluster_snapshot(DBSnapshotIdentifier=snapshot_name)
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'DBSnapshotNotFound':
                print("The snapshot can't be found. Suppressing.")
                data['messages']['actions_taken'] = "The snapshot cannot be found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
        print(response)
        data['messages']['actions_taken'] = "The snapshot was empty and has been deleted."
        data['messages']['actions_required'] = "None"
        return data

    # Copy the snapshot with encryption specified
    print("Attempting to copy the instance snapshot...")
    snapshot_target_name = f'{snapshot_name}-encrypted'
    try:
        response = client.copy_db_snapshot(
            SourceDBSnapshotIdentifier=snapshot_name,
            TargetDBSnapshotIdentifier=snapshot_target_name,
            KmsKeyId='aws/rds',
            CopyTags=True
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'DBSnapshotNotFound':
            print("The snapshot can't be found. Suppressing.")
            data['messages']['actions_taken'] = "The snapshot cannot be found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        if error.response['Error']['Code'] == 'InvalidParameterValue':
            if 'with encryption is not supported' in error.response['Error']['Message']:
                print("The operation is not supported, team must fix.")
                data['actions']['autoremediation_not_done'] = True
                return data
        raise error
    print(response)

    # Wait for the copy to complete
    print("Waiting for the instance snapshot copy operation to complete...")
    waiter = client.get_waiter('db_snapshot_available')
    waiter.wait(
        DBSnapshotIdentifier=snapshot_name,
        SnapshotType=snapshot_type
    )

    # Delete the original snapshot
    print("Deleting the original snapshot...")
    response = client.delete_db_snapshot(DBSnapshotIdentifier=snapshot_name)

    # Success
    data['messages']['actions_taken'] = "The snapshot has been copied to a new, encrypted snapshot '{snapshot_target_name}'. The original snapshot has been deleted."
    data['messages']['actions_required'] = "None"
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_rds4_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )
