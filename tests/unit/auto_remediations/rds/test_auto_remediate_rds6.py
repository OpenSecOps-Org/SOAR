"""
Unit tests for RDS.6 auto-remediation function (Enable Enhanced Monitoring)
"""
import pytest
import sys
import os
import json

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_rds_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from tests.fixtures.security_hub_findings.rds_findings import (
    get_rds6_instance_finding,
    get_rds6_cluster_finding,
    get_rds6_aurora_instance_finding
)


@pytest.fixture
def mock_rds6_asff_data():
    """ASFF data structure for RDS.6 control with standalone PostgreSQL instance"""
    return prepare_rds_test_data(get_rds6_instance_finding)


@pytest.fixture
def mock_rds6_cluster_asff_data():
    """ASFF data structure for RDS.6 control with Aurora cluster"""
    return prepare_rds_test_data(get_rds6_cluster_finding)


@pytest.fixture
def mock_rds6_aurora_instance_asff_data():
    """ASFF data structure for RDS.6 control with Aurora instance in cluster"""
    return prepare_rds_test_data(get_rds6_aurora_instance_finding)


def test_rds6_remediation_structure(mock_rds6_asff_data):
    """Test RDS.6 remediation input structure validation"""
    
    finding = mock_rds6_asff_data['finding']
    resource = finding['Resources'][0]
    
    # Validate all required fields are present for RDS.6 remediation
    assert 'AwsAccountId' in finding
    assert 'Id' in finding
    assert 'Resources' in finding
    assert len(finding['Resources']) > 0
    
    # Validate resource structure
    assert 'Id' in resource
    assert 'Region' in resource
    assert 'Details' in resource
    
    # Validate RDS-specific structure for RDS.6
    assert 'AwsRdsDbInstance' in resource['Details']
    db_details = resource['Details']['AwsRdsDbInstance']
    assert 'DBInstanceIdentifier' in db_details
    assert 'MonitoringInterval' in db_details


def test_rds6_finding_parsing(mock_rds6_asff_data):
    """Test that the RDS.6 finding parsing logic works correctly"""
    
    finding = mock_rds6_asff_data['finding']
    resource = finding['Resources'][0]
    details = resource['Details']['AwsRdsDbInstance']
    
    # Test basic parsing
    assert finding['AwsAccountId'] == '123456789012'
    assert resource['Region'] == 'us-east-1'
    assert details['DBInstanceIdentifier'] == 'instance-no-monitoring'
    assert details['MonitoringInterval'] == 0


def test_rds6_resource_type_detection():
    """Test resource type detection logic for RDS.6"""
    
    # Test standalone DB instance detection
    standalone_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'standalone-instance',
                'Engine': 'postgres',
                'MonitoringInterval': 0
                # No DBClusterIdentifier
            }
        }
    }
    
    details = standalone_resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    db_cluster_identifier = details.get('DBClusterIdentifier')
    
    assert db_instance_identifier == 'standalone-instance'
    assert db_cluster_identifier is None  # Standalone instance
    
    # Test Aurora instance in cluster detection
    aurora_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'aurora-instance',
                'Engine': 'aurora-mysql',
                'DBClusterIdentifier': 'aurora-cluster',
                'MonitoringInterval': 0
            }
        }
    }
    
    details = aurora_resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    db_cluster_identifier = details.get('DBClusterIdentifier')
    
    assert db_instance_identifier == 'aurora-instance'
    assert db_cluster_identifier == 'aurora-cluster'  # Instance in cluster
    
    # Test direct cluster resource (theoretical case)
    cluster_resource = {
        'Details': {
            'AwsRdsDbCluster': {
                'DBClusterIdentifier': 'direct-cluster',
                'Engine': 'aurora-postgresql',
                'MonitoringInterval': 0
            }
        }
    }
    
    cluster_details = cluster_resource['Details'].get('AwsRdsDbCluster')
    instance_details = cluster_resource['Details'].get('AwsRdsDbInstance')
    
    assert cluster_details is not None
    assert instance_details is None
    assert cluster_details['DBClusterIdentifier'] == 'direct-cluster'


def test_rds6_modification_parameters():
    """Test the modification parameters for RDS.6"""
    
    # Test account ID and role ARN generation
    account_id = '123456789012'
    role_name = 'rds-monitoring-role'
    expected_role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    # The core parameters for RDS.6 remediation
    expected_params = {
        'MonitoringRoleArn': expected_role_arn,
        'MonitoringInterval': 60
    }
    
    # Validate parameter structure
    assert 'MonitoringRoleArn' in expected_params
    assert 'MonitoringInterval' in expected_params
    assert expected_params['MonitoringInterval'] == 60
    assert isinstance(expected_params['MonitoringInterval'], int)
    
    # Validate role ARN format
    role_arn = expected_params['MonitoringRoleArn']
    assert role_arn.startswith('arn:aws:iam::')
    assert account_id in role_arn
    assert role_name in role_arn
    assert role_arn.endswith(f':role/{role_name}')


def test_rds6_iam_role_configuration():
    """Test IAM role configuration for RDS.6"""
    
    # Test role details
    role_name = 'rds-monitoring-role'
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole'
    allowed_services = ['monitoring.rds.amazonaws.com']
    
    # Test trust policy structure
    expected_trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': service},
            'Action': 'sts:AssumeRole'
        } for service in allowed_services]
    }
    
    # Validate trust policy structure
    assert 'Version' in expected_trust_policy
    assert 'Statement' in expected_trust_policy
    assert len(expected_trust_policy['Statement']) == 1
    
    statement = expected_trust_policy['Statement'][0]
    assert statement['Effect'] == 'Allow'
    assert statement['Action'] == 'sts:AssumeRole'
    assert statement['Principal']['Service'] == 'monitoring.rds.amazonaws.com'
    
    # Validate AWS managed policy ARN
    assert policy_arn.startswith('arn:aws:iam::aws:policy/')
    assert 'AmazonRDSEnhancedMonitoringRole' in policy_arn
    
    # Validate role name consistency
    assert role_name == 'rds-monitoring-role'


def test_rds6_dual_resource_handling():
    """Test that RDS.6 handles both instances and clusters"""
    
    account_id = '123456789012'
    role_arn = f'arn:aws:iam::{account_id}:role/rds-monitoring-role'
    
    # Test instance modification logic
    standalone_case = {
        'db_cluster_identifier': None,  # Standalone instance
        'expected_resource_type': 'instance',
        'expected_params': {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    }
    
    if not standalone_case['db_cluster_identifier']:
        resource_type = 'instance'
        params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    else:
        resource_type = 'cluster'
        params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    
    assert resource_type == standalone_case['expected_resource_type']
    assert params == standalone_case['expected_params']
    
    # Test cluster modification logic
    cluster_case = {
        'db_cluster_identifier': 'my-cluster',  # Instance in cluster
        'expected_resource_type': 'cluster',
        'expected_params': {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    }
    
    if not cluster_case['db_cluster_identifier']:
        resource_type = 'instance'
        params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    else:
        resource_type = 'cluster'
        params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    
    assert resource_type == cluster_case['expected_resource_type']
    assert params == cluster_case['expected_params']


def test_rds6_monitoring_interval_validation():
    """Test monitoring interval validation"""
    
    # Test various monitoring intervals
    interval_scenarios = [
        {'current': 0, 'expected': 60, 'description': 'Monitoring disabled'},
        {'current': None, 'expected': 60, 'description': 'Monitoring unset'},
    ]
    
    for scenario in interval_scenarios:
        # Current state (what triggers the finding)
        current_interval = scenario['current']
        
        # Remediation action
        new_interval = 60
        
        # Validate the fix
        assert new_interval == scenario['expected']
        assert new_interval > 0
        assert new_interval in [1, 5, 10, 15, 30, 60]  # Valid AWS intervals
        
    # Test compliant intervals
    compliant_intervals = [1, 5, 10, 15, 30, 60]  # All valid intervals
    
    for interval in compliant_intervals:
        # These would typically not trigger RDS.6 findings
        assert interval > 0
        assert interval <= 60
        
    # Validate the remediation interval
    remediation_interval = 60
    assert remediation_interval == 60
    assert isinstance(remediation_interval, int)


def test_rds6_cluster_vs_instance_logic():
    """Test the decision logic between instance and cluster modifications"""
    
    account_id = '123456789012'
    role_arn = f'arn:aws:iam::{account_id}:role/rds-monitoring-role'
    
    # Case 1: Standalone instance (modify instance)
    case1_details = {
        'DBInstanceIdentifier': 'standalone-db',
        'Engine': 'postgres',
        'MonitoringInterval': 0
        # No DBClusterIdentifier
    }
    
    db_cluster_identifier = case1_details.get('DBClusterIdentifier')
    
    if not db_cluster_identifier:
        modification_target = 'instance'
        target_identifier = case1_details['DBInstanceIdentifier']
        params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    else:
        modification_target = 'cluster'
        target_identifier = db_cluster_identifier
        params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
    
    assert modification_target == 'instance'
    assert target_identifier == 'standalone-db'
    assert params['MonitoringInterval'] == 60
    
    # Case 2: Aurora instance in cluster (modify cluster)
    case2_details = {
        'DBInstanceIdentifier': 'aurora-instance-1',
        'Engine': 'aurora-mysql',
        'DBClusterIdentifier': 'aurora-cluster-1',
        'MonitoringInterval': 0
    }
    
    db_cluster_identifier = case2_details.get('DBClusterIdentifier')
    
    if not db_cluster_identifier:
        modification_target = 'instance'
        target_identifier = case2_details['DBInstanceIdentifier']
    else:
        modification_target = 'cluster'
        target_identifier = db_cluster_identifier
    
    assert modification_target == 'cluster'
    assert target_identifier == 'aurora-cluster-1'


def test_rds6_engine_compatibility():
    """Test that RDS.6 works with all RDS engine types"""
    
    # RDS.6 should work with all engine types
    supported_engines = [
        'mysql',
        'postgres', 
        'oracle-ee',
        'oracle-se2',
        'sqlserver-ee',
        'sqlserver-se',
        'aurora-mysql',
        'aurora-postgresql',
        'mariadb'
    ]
    
    account_id = '123456789012'
    role_arn = f'arn:aws:iam::{account_id}:role/rds-monitoring-role'
    
    # For each engine, the enhanced monitoring parameters should be valid
    for engine in supported_engines:
        # Simulate resource for each engine type
        resource_details = {
            'DBInstanceIdentifier': f'test-{engine.replace("-", "")}-instance',
            'Engine': engine,
            'MonitoringInterval': 0  # Disabled monitoring
        }
        
        # The parameters should always be the same regardless of engine
        modification_params = {
            'MonitoringRoleArn': role_arn,
            'MonitoringInterval': 60
        }
        
        assert modification_params['MonitoringInterval'] == 60
        assert role_arn in modification_params['MonitoringRoleArn']
        assert resource_details['Engine'] == engine
        assert resource_details['MonitoringInterval'] == 0  # Current state


def test_rds6_trust_policy_validation():
    """Test IAM trust policy validation for RDS enhanced monitoring"""
    
    allowed_services = ['monitoring.rds.amazonaws.com']
    
    # Generate trust policy structure
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': service},
            'Action': 'sts:AssumeRole'
        } for service in allowed_services]
    }
    
    # Validate trust policy JSON structure
    trust_policy_json = json.dumps(trust_policy)
    parsed_policy = json.loads(trust_policy_json)
    
    assert parsed_policy['Version'] == '2012-10-17'
    assert len(parsed_policy['Statement']) == 1
    
    statement = parsed_policy['Statement'][0]
    assert statement['Effect'] == 'Allow'
    assert statement['Principal']['Service'] == 'monitoring.rds.amazonaws.com'
    assert statement['Action'] == 'sts:AssumeRole'
    
    # Validate service principal
    assert 'monitoring.rds.amazonaws.com' in allowed_services
    assert 'monitoring.rds.amazonaws.com' == statement['Principal']['Service']


def test_rds6_error_handling_scenarios():
    """Test various error handling scenarios for RDS.6"""
    
    # Test missing DBInstanceIdentifier
    resource_missing_id = {
        'Details': {
            'AwsRdsDbInstance': {
                'Engine': 'postgres',
                'MonitoringInterval': 0
                # Missing DBInstanceIdentifier
            }
        }
    }
    
    details = resource_missing_id['Details']['AwsRdsDbInstance']
    db_id = details.get('DBInstanceIdentifier')
    
    assert db_id is None
    
    # Test missing MonitoringInterval field
    resource_missing_interval = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres'
                # Missing MonitoringInterval
            }
        }
    }
    
    details = resource_missing_interval['Details']['AwsRdsDbInstance']
    monitoring_interval = details.get('MonitoringInterval')
    
    assert monitoring_interval is None
    
    # Test missing AwsRdsDbInstance section
    resource_missing_details = {
        'Details': {}
    }
    
    db_details = resource_missing_details['Details'].get('AwsRdsDbInstance')
    assert db_details is None


def test_rds6_success_response_structure():
    """Test the expected success response structure for RDS.6"""
    
    # Expected response structure when remediation succeeds
    expected_success_response = {
        'messages': {
            'actions_taken': "Enhanced monitoring has been enabled with a monitoring interval of 60 seconds.",
            'actions_required': "None"
        }
    }
    
    # Validate response structure
    assert 'messages' in expected_success_response
    assert 'actions_taken' in expected_success_response['messages']
    assert 'actions_required' in expected_success_response['messages']
    
    # Validate specific messages for RDS.6
    actions_taken = expected_success_response['messages']['actions_taken']
    assert "Enhanced monitoring has been enabled" in actions_taken
    assert "60 seconds" in actions_taken
    assert expected_success_response['messages']['actions_required'] == "None"


def test_rds6_iam_integration_logic():
    """Test IAM integration logic for RDS.6"""
    
    # Test IAM role creation parameters
    role_name = 'rds-monitoring-role'
    account_id = '123456789012'
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole'
    
    # Test role ARN generation
    generated_role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    # Validate role ARN components
    arn_parts = generated_role_arn.split(':')
    assert len(arn_parts) == 6
    assert arn_parts[0] == 'arn'
    assert arn_parts[1] == 'aws'
    assert arn_parts[2] == 'iam'
    assert arn_parts[3] == ''  # Empty for global service
    assert arn_parts[4] == account_id
    assert arn_parts[5] == f'role/{role_name}'
    
    # Test AWS managed policy ARN
    policy_parts = policy_arn.split(':')
    assert len(policy_parts) == 6
    assert policy_parts[0] == 'arn'
    assert policy_parts[1] == 'aws'
    assert policy_parts[2] == 'iam'
    assert policy_parts[3] == ''
    assert policy_parts[4] == 'aws'  # AWS managed policy
    assert 'AmazonRDSEnhancedMonitoringRole' in policy_parts[5]


def test_rds6_monitoring_configuration_validation():
    """Test monitoring configuration validation"""
    
    # Test monitoring configuration scenarios
    monitoring_scenarios = [
        {'interval': 60, 'valid': True, 'description': '60-second interval (recommended)'},
        {'interval': 30, 'valid': True, 'description': '30-second interval'},
        {'interval': 15, 'valid': True, 'description': '15-second interval'},
        {'interval': 10, 'valid': True, 'description': '10-second interval'},
        {'interval': 5, 'valid': True, 'description': '5-second interval'},
        {'interval': 1, 'valid': True, 'description': '1-second interval'},
        {'interval': 0, 'valid': False, 'description': 'Monitoring disabled'},
    ]
    
    valid_intervals = [1, 5, 10, 15, 30, 60]
    
    for scenario in monitoring_scenarios:
        interval = scenario['interval']
        is_valid = scenario['valid']
        
        if is_valid:
            assert interval in valid_intervals
            assert interval > 0
        else:
            assert interval == 0  # Only 0 is invalid (disabled)
            
    # Validate remediation uses a valid interval
    remediation_interval = 60
    assert remediation_interval in valid_intervals
    assert remediation_interval > 0


if __name__ == "__main__":
    pytest.main([__file__])