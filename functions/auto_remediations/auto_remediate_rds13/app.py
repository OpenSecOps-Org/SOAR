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

    details = resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    db_cluster_identifier = details.get('DBClusterIdentifier')

    client = get_client('rds', account_id, region)

    if not db_cluster_identifier:

        waiter = client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=db_instance_identifier)
        try:
            response = client.modify_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                ApplyImmediately=True,
                AutoMinorVersionUpgrade=True
            )
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'DBInstanceNotFoundFault':
                print("The DB instance wasn't found. Suppressing.")
                data['messages']['actions_taken'] = "The DB instance wasn't found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
            raise error
        print(response)

    else:

        waiter = client.get_waiter('db_cluster_available')
        waiter.wait(DBClusterIdentifier=db_cluster_identifier)
        try:
            response = client.modify_db_cluster(
                DBClusterIdentifier=db_cluster_identifier,
                ApplyImmediately=True,
                AutoMinorVersionUpgrade=True
            )
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'DBClusterNotFoundFault':
                print("The DB cluster wasn't found. Suppressing.")
                data['messages']['actions_taken'] = "The DB cluster wasn't found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
            raise error
        print(response)

    data['messages']['actions_taken'] = "RDS automatic minor version upgrades have been enabled."
    data['messages']['actions_required'] = "None"
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_rds13_{account_id}"
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
