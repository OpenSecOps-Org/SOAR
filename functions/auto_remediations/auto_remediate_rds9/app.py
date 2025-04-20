"""
RDS.9 AUTOREMEDIATION - ENABLE DATABASE LOGGING

This Lambda function automatically remediates AWS Security Hub findings for RDS.9 
(RDS DB instances should have logging enabled).

Target Resources:
- PostgreSQL and Aurora PostgreSQL DB instances and clusters

Remediation Actions:
1. Creates a new parameter group with logging parameters enabled
2. Applies the new parameter group to the DB instance or cluster
3. Reboots the instance to activate the parameters
4. Enables CloudWatch log exports for the appropriate log types

Supported Engines:
- postgres
- aurora-postgresql

Parameter Configurations:
- log_statement = 'ddl'
- log_min_duration_statement = '-1'

Test Trigger:
1. Create a PostgreSQL instance with default parameter group (logging disabled)
2. Create an Aurora PostgreSQL cluster with default parameter group
3. Create an Aurora PostgreSQL Serverless v2 cluster with default parameter group
4. Verify the finding appears in Security Hub for RDS.9

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-9
"""

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

# Control-specific constants
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

def lambda_handler(data, _context):
    print(data)

    # Extract finding details and resource info
    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']
    
    # Generate a unique identifier for parameter groups (mitigates name collisions)
    # Use the finding ID to create a unique suffix
    finding_id = finding.get('Id', '')
    unique_suffix = ''
    if finding_id:
        # Extract the last 8 characters of the finding ID to use as a unique identifier
        unique_suffix = '-' + finding_id.split('/')[-1][-8:]
        
    # Extract resource details based on type (instance vs cluster)
    # CASE DETECTION: Three possible cases:
    # 1. Standalone DB instance: instance_details exists, instance_db_cluster_identifier is None
    # 2. DB cluster (direct finding): cluster_details exists, instance_details is None
    # 3. DB instance in a cluster: instance_details exists, instance_db_cluster_identifier has a value
    instance_details =               resource['Details'].get('AwsRdsDbInstance')
    instance_db_cluster_identifier = resource['Details'].get('AwsRdsDbInstance', {}).get('DBClusterIdentifier')
    cluster_details =                resource['Details'].get('AwsRdsDbCluster')
    details = instance_details or cluster_details

    # Determine supported engine type and log types
    engine = details['Engine']
    logs = ENGINE_LOG_TYPES.get(engine)

    if not logs:
        print("Unsupported engine. Leaving to the team.")
        data['actions']['autoremediation_not_done'] = True
        return data

    # Get RDS client for the account
    client = get_client('rds', account_id, region)

    # CASE #1: Standalone DB instance (not part of a cluster)
    if instance_details and not instance_db_cluster_identifier:
        # This is CASE #1: Standalone DB instance
        
        # Extract instance identifier and current parameter group from ASFF
        db_instance_identifier = details['DBInstanceIdentifier']
        db_parameter_group_name = details['DbParameterGroups'][0]['DbParameterGroupName']
        suffix = f'-with-logging{unique_suffix}'
        
        print(f"Original parameter group name: {db_parameter_group_name}")
        
        # Get instance details to determine correct family
        engine, engine_version = get_engine_details(client, 'instance', db_instance_identifier)
        print(f"Found engine: {engine}, version: {engine_version}")
        
        # Get parameter group family
        family = get_parameter_group_family(client, engine, engine_version, 'instance', db_instance_identifier)
        new_db_parameter_group_name = f'{family}{suffix}'
        print(f"New parameter group name will be: {new_db_parameter_group_name}")

        # Create parameter group if it doesn't exist
        ensure_new_db_parameter_group_exists(
            client, 
            new_db_parameter_group_name, 
            family,
            ENGINE_PARAMETERS[engine]
        )

        # Modify instance with new parameter group and enable logging
        params = {
            'DBParameterGroupName': new_db_parameter_group_name,
            'CloudwatchLogsExportConfiguration': {
                'EnableLogTypes': logs
            }
        }
        
        if not modify_db_resource(client, 'instance', db_instance_identifier, params, data):
            return data

        # Reboot instance to apply parameter group changes
        response = client.reboot_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            ForceFailover=False
        )
        print(response)

    else:
        # This is either:
        # - CASE #2: DB cluster (direct finding)
        # - CASE #3: DB instance that belongs to a cluster

        # Get cluster identifier - using safer .get() method
        db_cluster_identifier = details.get('DBClusterIdentifier')
        
        if not db_cluster_identifier:
            print("ERROR: Could not determine cluster identifier")
            data['actions']['autoremediation_not_done'] = True
            return data

        # Get cluster parameter group name
        if not instance_db_cluster_identifier:
            # CASE #2: Direct DB cluster finding
            # Try to get parameter group name from ASFF format
            try:
                db_cluster_parameter_group_name = details['DbClusterParameterGroups'][0]['DbClusterParameterGroupName']
                print("Using parameter group from ASFF finding")
            except (KeyError, IndexError):
                # Fallback to API if field is missing or has different name
                print("ASFF field not found, falling back to API call")
                db_cluster_parameter_group_name = get_cluster_db_parameter_group_name(client, db_cluster_identifier)
        else:
            # CASE #3: DB instance belonging to a cluster
            # Get parameter group via API call instead of ASFF
            print("DB instance in cluster - using API to get parameter group")
            db_cluster_parameter_group_name = get_cluster_db_parameter_group_name(client, instance_db_cluster_identifier)

        suffix = f'-cluster-with-logging{unique_suffix}'
        
        print(f"Original parameter group name: {db_cluster_parameter_group_name}")
        
        # Get cluster details to determine correct family
        engine, engine_version = get_engine_details(client, 'cluster', db_cluster_identifier)
        print(f"Found engine: {engine}, version: {engine_version}")
        
        # Get parameter group family
        family = get_parameter_group_family(client, engine, engine_version, 'cluster', db_cluster_identifier)
        new_db_cluster_parameter_group_name = f'{family}{suffix}'
        print(f"New parameter group name will be: {new_db_cluster_parameter_group_name}")

        # Create cluster parameter group if it doesn't exist
        ensure_new_db_cluster_parameter_group_exists(
            client, 
            new_db_cluster_parameter_group_name, 
            family,
            ENGINE_PARAMETERS[engine]
        )

        # Modify cluster with new parameter group and enable logging
        params = {
            'DBClusterParameterGroupName': new_db_cluster_parameter_group_name,
            'CloudwatchLogsExportConfiguration': {
                'EnableLogTypes': logs
            }
        }
        
        if not modify_db_resource(client, 'cluster', db_cluster_identifier, params, data):
            return data

        # Reboot if not Aurora (Aurora doesn't require reboot for parameter changes)
        if not 'aurora' in engine:
            print("Rebooting non-Aurora cluster to apply parameter changes")
            response = client.reboot_db_cluster(
                DBClusterIdentifier=db_cluster_identifier
            )
            print(response)
        else:
            print("Aurora cluster - no reboot required for parameter changes")

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
    """
    Creates a new DB parameter group with logging enabled if it doesn't already exist.
    Used for standalone DB instances.
    
    Args:
        rds: RDS client
        new_name: Name for the new parameter group
        family: Parameter group family (e.g., postgres13)
        parameters: List of parameters to set
    """
    print(f"Creating {new_name} in the {family} family...")
    
    # First check if parameter group already exists to avoid exceptions
    try:
        existing_groups = rds.describe_db_parameter_groups(
            DBParameterGroupName=new_name
        )
        print(f"Parameter group {new_name} already exists, skipping creation")
        # Group exists, just update parameters
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBParameterGroupNotFound':
            # Group doesn't exist, create it
            try:
                response = rds.create_db_parameter_group(
                    DBParameterGroupName=new_name,
                    DBParameterGroupFamily=family,
                    Description=f'Same as default.{family} but with logging enabled'
                )
                print(response)
            except ClientError as error:
                # Catch all errors during creation
                error_code = error.response.get('Error', {}).get('Code', '')
                if error_code == 'DBParameterGroupAlreadyExistsFault':
                    print(f"Parameter group {new_name} was created by another process, continuing...")
                else:
                    print(f"Error creating parameter group: {error}")
                    raise error
        else:
            # Handle other describe errors
            print(f"Error checking for parameter group: {e}")
            raise e
    
    # Always attempt to set parameters, regardless of whether we created the group or it existed
    try:
        response = rds.modify_db_parameter_group(
            DBParameterGroupName=new_name,
            Parameters=parameters
        )
        print(f"Successfully set parameters for {new_name}")
        print(response)
    except ClientError as error:
        print(f"Error setting parameters: {error}")
        raise error


def ensure_new_db_cluster_parameter_group_exists(rds, new_name, family, parameters):
    """
    Creates a new DB cluster parameter group with logging enabled if it doesn't already exist.
    Used for DB clusters.
    
    Args:
        rds: RDS client
        new_name: Name for the new cluster parameter group
        family: Parameter group family (e.g., aurora-postgresql13)
        parameters: List of parameters to set
    """
    print(f"Creating cluster parameter group {new_name} in the {family} family...")
    
    # First check if cluster parameter group already exists to avoid exceptions
    try:
        existing_groups = rds.describe_db_cluster_parameter_groups(
            DBClusterParameterGroupName=new_name
        )
        print(f"Cluster parameter group {new_name} already exists, skipping creation")
        # Group exists, just update parameters
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBParameterGroupNotFound' or e.response['Error']['Code'] == 'DBClusterParameterGroupNotFound':
            # Group doesn't exist, create it
            try:
                response = rds.create_db_cluster_parameter_group(
                    DBClusterParameterGroupName=new_name,
                    DBParameterGroupFamily=family,
                    Description=f'Same as default.{family} but with logging enabled'
                )
                print(response)
            except ClientError as error:
                # Catch all errors during creation
                error_code = error.response.get('Error', {}).get('Code', '')
                if error_code in ['DBParameterGroupAlreadyExistsFault', 'DBClusterParameterGroupAlreadyExistsFault']:
                    print(f"Cluster parameter group {new_name} was created by another process, continuing...")
                else:
                    print(f"Error creating cluster parameter group: {error}")
                    raise error
        else:
            # Handle other describe errors
            print(f"Error checking for cluster parameter group: {e}")
            raise e
    
    # Always attempt to set parameters, regardless of whether we created the group or it existed
    try:
        response = rds.modify_db_cluster_parameter_group(
            DBClusterParameterGroupName=new_name,
            Parameters=parameters
        )
        print(f"Successfully set parameters for cluster group {new_name}")
        print(response)
    except ClientError as error:
        print(f"Error setting cluster parameters: {error}")
        raise error


def get_cluster_db_parameter_group_name(rds, db_cluster_identifier):
    """
    Retrieves the current parameter group name for a DB cluster via direct API call.
    This is a reliable method that bypasses potential ASFF field name discrepancies.
    
    Args:
        rds: RDS client
        db_cluster_identifier: Identifier of the DB cluster
        
    Returns:
        The current DB cluster parameter group name
    """
    response = rds.describe_db_clusters(
        DBClusterIdentifier=db_cluster_identifier,
        IncludeShared=False
    )
    print(response)
    return response['DBClusters'][0]['DBClusterParameterGroup']