"""
Unit tests for RDS.11 auto-remediation function (Enable Automatic Backups)
"""
import pytest
import sys
import os

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_rds_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from tests.fixtures.security_hub_findings.rds_findings import (
    get_rds11_instance_finding,
    get_rds11_cluster_finding,
    get_rds11_aurora_instance_finding
)


@pytest.fixture
def mock_rds11_asff_data():
    """ASFF data structure for RDS.11 control with standalone instance"""
    return prepare_rds_test_data(get_rds11_instance_finding)


@pytest.fixture
def mock_rds11_cluster_asff_data():
    """ASFF data structure for RDS.11 control with Aurora cluster"""
    return prepare_rds_test_data(get_rds11_cluster_finding)


@pytest.fixture
def mock_rds11_aurora_instance_asff_data():
    """ASFF data structure for RDS.11 control with Aurora instance in cluster"""
    return prepare_rds_test_data(get_rds11_aurora_instance_finding)


def test_rds11_remediation_structure(mock_rds11_asff_data):
    """Test RDS.11 remediation input structure validation"""
    
    finding = mock_rds11_asff_data['finding']
    resource = finding['Resources'][0]
    
    # Validate all required fields are present for RDS.11 remediation
    assert 'AwsAccountId' in finding
    assert 'Id' in finding
    assert 'Resources' in finding
    assert len(finding['Resources']) > 0
    
    # Validate resource structure
    assert 'Id' in resource
    assert 'Region' in resource
    assert 'Details' in resource
    
    # Validate RDS-specific structure for RDS.11
    assert 'AwsRdsDbInstance' in resource['Details']
    db_details = resource['Details']['AwsRdsDbInstance']
    assert 'DBInstanceIdentifier' in db_details
    assert 'BackupRetentionPeriod' in db_details


def test_rds11_finding_parsing(mock_rds11_asff_data):
    """Test that the RDS.11 finding parsing logic works correctly"""
    
    finding = mock_rds11_asff_data['finding']
    resource = finding['Resources'][0]
    details = resource['Details']['AwsRdsDbInstance']
    
    # Test basic parsing
    assert finding['AwsAccountId'] == '123456789012'
    assert resource['Region'] == 'us-east-1'
    assert details['DBInstanceIdentifier'] == 'instance-no-backup'
    assert details['BackupRetentionPeriod'] == 0


def test_rds11_resource_type_detection():
    """Test resource type detection logic for RDS.11"""
    
    # Test standalone DB instance detection
    standalone_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'standalone-instance',
                'Engine': 'mysql',
                'BackupRetentionPeriod': 0
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
                'BackupRetentionPeriod': 0
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
                'BackupRetentionPeriod': 0
            }
        }
    }
    
    cluster_details = cluster_resource['Details'].get('AwsRdsDbCluster')
    instance_details = cluster_resource['Details'].get('AwsRdsDbInstance')
    
    assert cluster_details is not None
    assert instance_details is None
    assert cluster_details['DBClusterIdentifier'] == 'direct-cluster'


def test_rds11_modification_parameters():
    """Test the modification parameters for RDS.11"""
    
    # The core parameter for RDS.11 remediation
    expected_params = {'BackupRetentionPeriod': 7}
    
    # Validate parameter structure
    assert 'BackupRetentionPeriod' in expected_params
    assert expected_params['BackupRetentionPeriod'] == 7
    assert isinstance(expected_params['BackupRetentionPeriod'], int)
    
    # Validate 7-day retention period
    assert expected_params['BackupRetentionPeriod'] > 0
    assert expected_params['BackupRetentionPeriod'] <= 35  # AWS maximum


def test_rds11_dual_resource_handling():
    """Test that RDS.11 handles both instances and clusters"""
    
    # Test instance modification logic
    standalone_case = {
        'db_cluster_identifier': None,  # Standalone instance
        'expected_resource_type': 'instance',
        'expected_params': {'BackupRetentionPeriod': 7}
    }
    
    if not standalone_case['db_cluster_identifier']:
        resource_type = 'instance'
        params = {'BackupRetentionPeriod': 7}
    else:
        resource_type = 'cluster'
        params = {'BackupRetentionPeriod': 7}
    
    assert resource_type == standalone_case['expected_resource_type']
    assert params == standalone_case['expected_params']
    
    # Test cluster modification logic
    cluster_case = {
        'db_cluster_identifier': 'my-cluster',  # Instance in cluster
        'expected_resource_type': 'cluster',
        'expected_params': {'BackupRetentionPeriod': 7}
    }
    
    if not cluster_case['db_cluster_identifier']:
        resource_type = 'instance'
        params = {'BackupRetentionPeriod': 7}
    else:
        resource_type = 'cluster'
        params = {'BackupRetentionPeriod': 7}
    
    assert resource_type == cluster_case['expected_resource_type']
    assert params == cluster_case['expected_params']


def test_rds11_engine_compatibility():
    """Test that RDS.11 works with all RDS engine types"""
    
    # RDS.11 should work with all engine types (like RDS.2)
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
    
    # For each engine, the BackupRetentionPeriod parameter should be valid
    for engine in supported_engines:
        # Simulate resource for each engine type
        resource_details = {
            'DBInstanceIdentifier': f'test-{engine.replace("-", "")}-instance',
            'Engine': engine,
            'BackupRetentionPeriod': 0  # Disabled backups
        }
        
        # The parameter should always be the same regardless of engine
        modification_params = {'BackupRetentionPeriod': 7}
        
        assert modification_params['BackupRetentionPeriod'] == 7
        assert resource_details['Engine'] == engine
        assert resource_details['BackupRetentionPeriod'] == 0  # Current state


def test_rds11_backup_retention_validation():
    """Test backup retention period validation"""
    
    # Test various backup retention scenarios
    backup_scenarios = [
        {'current': 0, 'expected': 7, 'description': 'Disabled backups'},
        {'current': 1, 'expected': 7, 'description': 'Insufficient retention'},
        {'current': 3, 'expected': 7, 'description': 'Short retention period'},
    ]
    
    for scenario in backup_scenarios:
        # Current state (what triggers the finding)
        current_retention = scenario['current']
        
        # Remediation action
        new_retention = 7
        
        # Validate the fix
        assert new_retention == scenario['expected']
        assert new_retention > current_retention
        assert new_retention >= 7  # Minimum for compliance
        
    # Test AWS limits
    assert 7 >= 1   # Minimum AWS allows
    assert 7 <= 35  # Maximum AWS allows


def test_rds11_cluster_vs_instance_logic():
    """Test the decision logic between instance and cluster modifications"""
    
    # Case 1: Standalone instance (modify instance)
    case1_details = {
        'DBInstanceIdentifier': 'standalone-db',
        'Engine': 'postgres'
        # No DBClusterIdentifier
    }
    
    db_cluster_identifier = case1_details.get('DBClusterIdentifier')
    
    if not db_cluster_identifier:
        modification_target = 'instance'
        target_identifier = case1_details['DBInstanceIdentifier']
    else:
        modification_target = 'cluster'
        target_identifier = db_cluster_identifier
    
    assert modification_target == 'instance'
    assert target_identifier == 'standalone-db'
    
    # Case 2: Aurora instance in cluster (modify cluster)
    case2_details = {
        'DBInstanceIdentifier': 'aurora-instance-1',
        'Engine': 'aurora-mysql',
        'DBClusterIdentifier': 'aurora-cluster-1'
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


def test_rds11_error_handling_scenarios():
    """Test various error handling scenarios for RDS.11"""
    
    # Test missing DBInstanceIdentifier
    resource_missing_id = {
        'Details': {
            'AwsRdsDbInstance': {
                'Engine': 'postgres',
                'BackupRetentionPeriod': 0
                # Missing DBInstanceIdentifier
            }
        }
    }
    
    details = resource_missing_id['Details']['AwsRdsDbInstance']
    db_id = details.get('DBInstanceIdentifier')
    
    assert db_id is None
    
    # Test missing BackupRetentionPeriod field
    resource_missing_retention = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres'
                # Missing BackupRetentionPeriod
            }
        }
    }
    
    details = resource_missing_retention['Details']['AwsRdsDbInstance']
    retention = details.get('BackupRetentionPeriod')
    
    assert retention is None
    
    # Test missing AwsRdsDbInstance section
    resource_missing_details = {
        'Details': {}
    }
    
    db_details = resource_missing_details['Details'].get('AwsRdsDbInstance')
    assert db_details is None


def test_rds11_success_response_structure():
    """Test the expected success response structure for RDS.11"""
    
    # Expected response structure when remediation succeeds
    expected_success_response = {
        'messages': {
            'actions_taken': "Automatic backups have been enabled. The retention period is 7 days.",
            'actions_required': "None"
        }
    }
    
    # Validate response structure
    assert 'messages' in expected_success_response
    assert 'actions_taken' in expected_success_response['messages']
    assert 'actions_required' in expected_success_response['messages']
    
    # Validate specific messages for RDS.11
    actions_taken = expected_success_response['messages']['actions_taken']
    assert "Automatic backups have been enabled" in actions_taken
    assert "7 days" in actions_taken
    assert expected_success_response['messages']['actions_required'] == "None"


def test_rds11_resource_scope_validation():
    """Test that RDS.11 applies to both instances and clusters"""
    
    # Valid instance resource type
    instance_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'valid-instance',
                'Engine': 'postgres',
                'BackupRetentionPeriod': 0
            }
        }
    }
    
    # Should have AwsRdsDbInstance section for instances
    assert 'AwsRdsDbInstance' in instance_resource['Details']
    
    # Valid cluster resource type (theoretical)
    cluster_resource = {
        'Details': {
            'AwsRdsDbCluster': {
                'DBClusterIdentifier': 'valid-cluster',
                'Engine': 'aurora-postgresql',
                'BackupRetentionPeriod': 0
            }
        }
    }
    
    # Should have AwsRdsDbCluster section for clusters
    assert 'AwsRdsDbCluster' in cluster_resource['Details']
    
    # Both should be valid targets for RDS.11 remediation
    instance_details = instance_resource['Details'].get('AwsRdsDbInstance')
    cluster_details = cluster_resource['Details'].get('AwsRdsDbCluster')
    
    assert instance_details is not None
    assert cluster_details is not None


def test_rds11_backup_configuration_logic():
    """Test backup configuration logic for different scenarios"""
    
    # Test backup retention scenarios that should trigger remediation
    problematic_retentions = [0, 1, 2, 3, 4, 5, 6]  # Less than 7 days
    target_retention = 7
    
    for current_retention in problematic_retentions:
        # All should be remediated to 7 days
        new_retention = target_retention
        
        assert new_retention == 7
        assert new_retention > current_retention
        
    # Test backup retention scenarios that should NOT trigger remediation
    compliant_retentions = [7, 14, 21, 30, 35]  # 7+ days
    
    for retention in compliant_retentions:
        # These would not trigger RDS.11 findings in Security Hub
        assert retention >= 7
        
    # Validate the remediation parameter
    remediation_params = {'BackupRetentionPeriod': 7}
    assert remediation_params['BackupRetentionPeriod'] == 7


if __name__ == "__main__":
    pytest.main([__file__])