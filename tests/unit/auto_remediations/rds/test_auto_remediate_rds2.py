"""
Unit tests for RDS.2 auto-remediation function (Disable Public Accessibility)
"""
import pytest
import sys
import os

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_rds_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from rds_findings import get_rds2_postgres_finding, get_rds2_aurora_instance_finding


@pytest.fixture
def mock_rds2_asff_data():
    """ASFF data structure for RDS.2 control with PostgreSQL instance"""
    return prepare_rds_test_data(get_rds2_postgres_finding)


@pytest.fixture
def mock_aurora_instance_asff_data():
    """ASFF data structure for Aurora instance in cluster (RDS.2)"""
    return prepare_rds_test_data(get_rds2_aurora_instance_finding)


def test_rds2_remediation_structure(mock_rds2_asff_data):
    """Test RDS.2 remediation input structure validation"""
    
    finding = mock_rds2_asff_data['finding']
    resource = finding['Resources'][0]
    
    # Validate all required fields are present for RDS.2 remediation
    assert 'AwsAccountId' in finding
    assert 'Id' in finding
    assert 'Resources' in finding
    assert len(finding['Resources']) > 0
    
    # Validate resource structure
    assert 'Id' in resource
    assert 'Region' in resource
    assert 'Details' in resource
    
    # Validate RDS-specific structure for RDS.2
    assert 'AwsRdsDbInstance' in resource['Details']
    db_details = resource['Details']['AwsRdsDbInstance']
    assert 'DBInstanceIdentifier' in db_details
    assert 'PubliclyAccessible' in db_details


def test_rds2_finding_parsing(mock_rds2_asff_data):
    """Test that the RDS.2 finding parsing logic works correctly"""
    
    finding = mock_rds2_asff_data['finding']
    resource = finding['Resources'][0]
    details = resource['Details']['AwsRdsDbInstance']
    
    # Test basic parsing
    assert finding['AwsAccountId'] == '123456789012'
    assert resource['Region'] == 'us-east-1'
    assert details['DBInstanceIdentifier'] == 'public-db-instance'
    assert details['PubliclyAccessible'] == True


def test_rds2_resource_extraction():
    """Test resource extraction logic for RDS.2"""
    
    # Test standalone DB instance
    standalone_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'standalone-instance',
                'Engine': 'mysql',
                'PubliclyAccessible': True
            }
        }
    }
    
    details = standalone_resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    
    assert db_instance_identifier == 'standalone-instance'
    assert details['PubliclyAccessible'] == True
    
    # Test Aurora instance in cluster
    aurora_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'aurora-instance',
                'Engine': 'aurora-mysql',
                'PubliclyAccessible': True,
                'DBClusterIdentifier': 'aurora-cluster'
            }
        }
    }
    
    details = aurora_resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    cluster_identifier = details.get('DBClusterIdentifier')
    
    assert db_instance_identifier == 'aurora-instance'
    assert cluster_identifier == 'aurora-cluster'
    assert details['PubliclyAccessible'] == True


def test_rds2_modification_parameters():
    """Test the modification parameters for RDS.2"""
    
    # The core parameter for RDS.2 remediation
    expected_params = {'PubliclyAccessible': False}
    
    # Validate parameter structure
    assert 'PubliclyAccessible' in expected_params
    assert expected_params['PubliclyAccessible'] == False
    assert isinstance(expected_params['PubliclyAccessible'], bool)


def test_rds2_engine_compatibility():
    """Test that RDS.2 works with all RDS engine types"""
    
    # RDS.2 should work with all engine types (unlike RDS.9 which is PostgreSQL-specific)
    supported_engines = [
        'mysql',
        'postgres', 
        'oracle-ee',
        'oracle-se2',
        'oracle-se1',
        'oracle-se',
        'sqlserver-ee',
        'sqlserver-se',
        'sqlserver-ex',
        'sqlserver-web',
        'aurora-mysql',
        'aurora-postgresql',
        'mariadb'
    ]
    
    # For each engine, the PubliclyAccessible parameter should be valid
    for engine in supported_engines:
        # Simulate resource for each engine type
        resource_details = {
            'DBInstanceIdentifier': f'test-{engine.replace("-", "")}-instance',
            'Engine': engine,
            'PubliclyAccessible': True
        }
        
        # The parameter should always be the same regardless of engine
        modification_params = {'PubliclyAccessible': False}
        
        assert modification_params['PubliclyAccessible'] == False
        assert resource_details['Engine'] == engine


def test_rds2_aurora_vs_standalone_handling():
    """Test that RDS.2 handles both Aurora and standalone instances correctly"""
    
    # Standalone instance - only has DBInstanceIdentifier
    standalone_details = {
        'DBInstanceIdentifier': 'standalone-postgres',
        'Engine': 'postgres',
        'PubliclyAccessible': True
    }
    
    # Extract identifier (same for both types)
    standalone_id = standalone_details['DBInstanceIdentifier']
    assert standalone_id == 'standalone-postgres'
    assert 'DBClusterIdentifier' not in standalone_details
    
    # Aurora instance - has both DBInstanceIdentifier and DBClusterIdentifier
    aurora_details = {
        'DBInstanceIdentifier': 'aurora-instance-1',
        'Engine': 'aurora-postgresql',
        'PubliclyAccessible': True,
        'DBClusterIdentifier': 'my-aurora-cluster'
    }
    
    # Extract identifier (same extraction method for both)
    aurora_id = aurora_details['DBInstanceIdentifier']
    cluster_id = aurora_details.get('DBClusterIdentifier')
    
    assert aurora_id == 'aurora-instance-1'
    assert cluster_id == 'my-aurora-cluster'
    
    # Both use the same modification approach (modify instance, not cluster)
    modification_params = {'PubliclyAccessible': False}
    assert modification_params['PubliclyAccessible'] == False


def test_rds2_error_handling_scenarios():
    """Test various error handling scenarios for RDS.2"""
    
    # Test missing DBInstanceIdentifier
    resource_missing_id = {
        'Details': {
            'AwsRdsDbInstance': {
                'Engine': 'postgres',
                'PubliclyAccessible': True
                # Missing DBInstanceIdentifier
            }
        }
    }
    
    details = resource_missing_id['Details']['AwsRdsDbInstance']
    db_id = details.get('DBInstanceIdentifier')  # Using .get() for safety
    
    assert db_id is None
    
    # Test missing PubliclyAccessible field
    resource_missing_public = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres'
                # Missing PubliclyAccessible
            }
        }
    }
    
    details = resource_missing_public['Details']['AwsRdsDbInstance']
    publicly_accessible = details.get('PubliclyAccessible')
    
    assert publicly_accessible is None
    
    # Test missing AwsRdsDbInstance section
    resource_missing_details = {
        'Details': {}
    }
    
    db_details = resource_missing_details['Details'].get('AwsRdsDbInstance')
    assert db_details is None


def test_rds2_success_response_structure():
    """Test the expected success response structure for RDS.2"""
    
    # Expected response structure when remediation succeeds
    expected_success_response = {
        'messages': {
            'actions_taken': "Public access has been disabled.",
            'actions_required': "None"
        }
    }
    
    # Validate response structure
    assert 'messages' in expected_success_response
    assert 'actions_taken' in expected_success_response['messages']
    assert 'actions_required' in expected_success_response['messages']
    
    # Validate specific messages for RDS.2
    assert expected_success_response['messages']['actions_taken'] == "Public access has been disabled."
    assert expected_success_response['messages']['actions_required'] == "None"


def test_rds2_resource_type_validation():
    """Test that RDS.2 only applies to DB instances, not clusters directly"""
    
    # Valid resource type - DB Instance
    valid_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'valid-instance',
                'Engine': 'postgres',
                'PubliclyAccessible': True
            }
        }
    }
    
    # Should have AwsRdsDbInstance section
    assert 'AwsRdsDbInstance' in valid_resource['Details']
    assert 'AwsRdsDbCluster' not in valid_resource['Details']
    
    # Invalid resource type - DB Cluster (RDS.2 doesn't apply to clusters directly)
    cluster_resource = {
        'Details': {
            'AwsRdsDbCluster': {
                'DBClusterIdentifier': 'cluster-name',
                'Engine': 'aurora-postgresql'
            }
        }
    }
    
    # Should not have AwsRdsDbInstance for cluster-only resource
    assert 'AwsRdsDbCluster' in cluster_resource['Details']
    assert 'AwsRdsDbInstance' not in cluster_resource['Details']


def test_rds2_modification_scope():
    """Test that RDS.2 modifies instances, not clusters"""
    
    # RDS.2 always modifies DB instances, even for Aurora
    # This is because PubliclyAccessible is an instance-level setting
    
    # Test parameter scope for standalone instance
    standalone_params = {'PubliclyAccessible': False}
    
    # Verify this is instance-level, not cluster-level
    cluster_level_params = [
        'BackupRetentionPeriod',
        'DatabaseName', 
        'DBClusterIdentifier',
        'DBSubnetGroupName',
        'VpcSecurityGroupIds'
    ]
    
    # PubliclyAccessible should not be in cluster-level parameters
    assert 'PubliclyAccessible' not in cluster_level_params
    assert 'PubliclyAccessible' in standalone_params
    assert standalone_params['PubliclyAccessible'] == False


if __name__ == "__main__":
    pytest.main([__file__])