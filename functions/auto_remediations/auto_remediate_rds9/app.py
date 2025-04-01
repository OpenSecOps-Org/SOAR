import os
import boto3
from botocore.exceptions import ClientError

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

ENGINE_LOG_TYPES = {
    'postgres':          ["postgresql", "upgrade"],
    'aurora-postgresql': ['postgresql']
}

ENGINE_PARAMETERS = {
    'postgres': [
        {
            'ApplyMethod': 'immediate',
            'ParameterName': 'log_statement',
            'ParameterValue': 'ddl',
        },
        {
            'ApplyMethod': 'immediate',
            'ParameterName': 'log_min_duration_statement',
            'ParameterValue': '-1',
        }
    ],
    'aurora-postgresql': [
        {
            'ApplyMethod': 'immediate',
            'ParameterName': 'log_statement',
            'ParameterValue': 'ddl',
        },
        {
            'ApplyMethod': 'immediate',
            'ParameterName': 'log_min_duration_statement',
            'ParameterValue': '-1',
        }
    ]
}

sts = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']

    instance_details =               resource['Details'].get('AwsRdsDbInstance')
    instance_db_cluster_identifier = resource['Details'].get('AwsRdsDbInstance', {}).get('DBClusterIdentifier')
    cluster_details =                resource['Details'].get('AwsRdsDbCluster')
    details = instance_details or cluster_details

    engine = details['Engine']
    logs = ENGINE_LOG_TYPES.get(engine)

    if not logs:
        print("Unsupported engine. Leaving to the team.")
        data['actions']['autoremediation_not_done'] = True
        return data

    client = get_client('rds', account_id, region)

    if instance_details and not instance_db_cluster_identifier:

        db_instance_identifier = details['DBInstanceIdentifier']
        db_parameter_group_name = details['DBParameterGroups'][0]['DBParameterGroupName']
        suffix = '-with-logging'
        family = db_parameter_group_name.split('.')[-1].replace(suffix, '')
        new_db_parameter_group_name = f'{family}{suffix}'

        ensure_new_db_parameter_group_exists(
            client, 
            new_db_parameter_group_name, 
            family,
            ENGINE_PARAMETERS[engine]
        )

        waiter = client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=db_instance_identifier)

        try:
            response = client.modify_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                ApplyImmediately=True,
                DBParameterGroupName=new_db_parameter_group_name,
                CloudwatchLogsExportConfiguration={
                    'EnableLogTypes': logs
                }
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'DBInstanceNotFoundFault':
                print("The DB instance wasn't found. Suppressing.")
                data['messages']['actions_taken'] = "The DB instance wasn't found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
            raise error
        print(response)

        response = client.reboot_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            ForceFailover=False
        )
        print(response)

    else:

        db_cluster_identifier = details['DBClusterIdentifier']

        if not instance_db_cluster_identifier:
            db_cluster_parameter_group_name = details['DBClusterParameterGroups'][0]['DBClusterParameterGroupName']
        else:
            db_cluster_parameter_group_name = get_cluster_db_parameter_group_name(client, instance_db_cluster_identifier)

        suffix = '-cluster-with-logging'
        family = db_cluster_parameter_group_name.split('.')[-1].replace(suffix, '')
        new_db_cluster_parameter_group_name = f'{family}{suffix}'

        ensure_new_db_cluster_parameter_group_exists(
            client, 
            new_db_cluster_parameter_group_name, 
            family,
            ENGINE_PARAMETERS[engine]
        )

        waiter = client.get_waiter('db_cluster_available')
        waiter.wait(DBClusterIdentifier=db_cluster_identifier)

        try:
            response = client.modify_db_cluster(
                DBClusterIdentifier=db_cluster_identifier,
                ApplyImmediately=True,
                DBClusterParameterGroupName=new_db_cluster_parameter_group_name,
                CloudwatchLogsExportConfiguration={
                    'EnableLogTypes': logs
                }
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'DBClusterNotFoundFault':
                print("The DB cluster wasn't found. Suppressing.")
                data['messages']['actions_taken'] = "The DB cluster wasn't found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
            raise error
        print(response)

        if not 'aurora' in engine:
            response = client.reboot_db_cluster(
                DBClusterIdentifier=db_cluster_identifier
            )
            print(response)

    # Wrap up and return
    data['messages']['actions_taken'] = "Logging has been enabled."
    data['messages']['actions_required'] = "None"
    return data


###########################################################################
#
# Parameter Groups
#
###########################################################################

def ensure_new_db_parameter_group_exists(rds, new_name, family, parameters):
    print(f"Creating {new_name} in the {family} family...")
    try:
        response = rds.create_db_parameter_group(
            DBParameterGroupName=new_name,
            DBParameterGroupFamily=family,
            Description=f'Same as default.{family} but with logging enabled'
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'DBParameterGroupAlreadyExistsFault':
            print("It already exists.")
            return
        raise error
    print(response)

    response = rds.modify_db_parameter_group(
        DBParameterGroupName=new_name,
        Parameters=parameters
    )
    print(response)


def ensure_new_db_cluster_parameter_group_exists(rds, new_name, family, parameters):
    print(f"Creating {new_name} in the {family} family...")
    try:
        response = rds.create_db_cluster_parameter_group(
            DBClusterParameterGroupName=new_name,
            DBParameterGroupFamily=family,
            Description=f'Same as default.{family} but with logging enabled'
        )
    except ClientError as error:
        if error.response['Error']['Code'] in ['DBParameterGroupAlreadyExistsFault', 'DBClusterParameterGroupAlreadyExistsFault']:
            print("It already exists.")
            return
        raise error
    print(response)

    response = rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=new_name,
        Parameters=parameters
    )
    print(response)


def get_cluster_db_parameter_group_name(rds, db_cluster_identifier):
    response = rds.describe_db_clusters(
        DBClusterIdentifier=db_cluster_identifier,
        IncludeShared=False
    )
    print(response)
    return response['DBClusters'][0]['DBClusterParameterGroup']


###########################################################################
#
# Cross-account clients
#
###########################################################################

def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_rds9_{account_id}"
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
