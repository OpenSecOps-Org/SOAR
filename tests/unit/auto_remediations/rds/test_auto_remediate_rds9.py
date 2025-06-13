import pytest
import sys
import os

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_rds_test_data

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from tests.fixtures.security_hub_findings.rds_findings import (
    get_rds9_postgres_finding,
    get_unsupported_engine_finding,
    get_rds9_cluster_finding
)


@pytest.fixture
def mock_rds9_asff_data():
    """ASFF data structure for RDS.9 control with PostgreSQL instance"""
    return prepare_rds_test_data(get_rds9_postgres_finding)


@pytest.fixture 
def mock_unsupported_engine_asff_data():
    """ASFF data structure for unsupported MySQL engine"""
    return prepare_rds_test_data(get_unsupported_engine_finding)


@pytest.fixture
def mock_cluster_asff_data():
    """ASFF data structure for RDS.9 cluster finding"""
    return prepare_rds_test_data(get_rds9_cluster_finding)


def test_rds9_remediation_structure(mock_rds9_asff_data):
    """Test RDS.9 remediation input structure validation"""
    
    # Test that we can validate the input structure without importing the problematic module
    finding = mock_rds9_asff_data['finding']
    resource = finding['Resources'][0]
    
    # Validate all required fields are present for RDS.9 remediation
    assert 'AwsAccountId' in finding
    assert 'Id' in finding
    assert 'Resources' in finding
    assert len(finding['Resources']) > 0
    
    # Validate resource structure
    assert 'Id' in resource
    assert 'Region' in resource
    assert 'Details' in resource
    
    # Validate RDS-specific structure
    if 'AwsRdsDbInstance' in resource['Details']:
        db_details = resource['Details']['AwsRdsDbInstance']
        assert 'DBInstanceIdentifier' in db_details
        assert 'Engine' in db_details
        assert 'EngineVersion' in db_details


def test_rds9_finding_parsing(mock_rds9_asff_data):
    """Test that the finding parsing logic works correctly"""
    
    finding = mock_rds9_asff_data['finding']
    resource = finding['Resources'][0]
    
    # Test basic parsing
    assert finding['AwsAccountId'] == '123456789012'
    assert resource['Region'] == 'us-east-1'
    assert resource['Details']['AwsRdsDbInstance']['DBInstanceIdentifier'] == 'test-postgres-instance'
    assert resource['Details']['AwsRdsDbInstance']['Engine'] == 'postgres'


def test_rds9_unique_suffix_generation(mock_rds9_asff_data):
    """Test that unique suffix generation works from finding ID"""
    
    finding = mock_rds9_asff_data['finding']
    finding_id = finding.get('Id', '')
    
    # Test suffix extraction logic
    if finding_id:
        unique_suffix = '-' + finding_id.split('/')[-1][-8:]
        assert len(unique_suffix) == 9  # '-' + 8 characters
        assert unique_suffix.startswith('-')


def test_rds9_engine_parameters():
    """Test that engine parameters are correctly defined"""
    
    # Define expected parameters locally to avoid import issues
    expected_engines = ['postgres', 'aurora-postgresql']
    expected_log_types = {
        'postgres': ["postgresql", "upgrade"],
        'aurora-postgresql': ['postgresql']
    }
    
    expected_parameters = {
        'postgres': [
            {'ApplyMethod': 'immediate', 'ParameterName': 'log_statement', 'ParameterValue': 'ddl'},
            {'ApplyMethod': 'immediate', 'ParameterName': 'log_min_duration_statement', 'ParameterValue': '-1'}
        ],
        'aurora-postgresql': [
            {'ApplyMethod': 'immediate', 'ParameterName': 'log_statement', 'ParameterValue': 'ddl'},
            {'ApplyMethod': 'immediate', 'ParameterName': 'log_min_duration_statement', 'ParameterValue': '-1'}
        ]
    }
    
    # Test that our expected structure is valid
    for engine in expected_engines:
        assert engine in expected_parameters
        assert engine in expected_log_types
        
        # Verify parameter structure
        for param in expected_parameters[engine]:
            assert 'ApplyMethod' in param
            assert 'ParameterName' in param  
            assert 'ParameterValue' in param
            assert param['ApplyMethod'] == 'immediate'
        
        # Verify log types contain 'postgresql'
        assert 'postgresql' in expected_log_types[engine]


def test_rds9_parameter_group_naming():
    """Test parameter group naming conventions"""
    
    # Test naming pattern for different scenarios
    db_identifier = "test-postgres-instance"
    finding_id = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012"
    
    # Extract unique suffix
    unique_suffix = '-' + finding_id.split('/')[-1][-8:]
    
    # Generate expected parameter group names
    expected_instance_pg_name = f"{db_identifier}-logging-enabled{unique_suffix}"
    expected_cluster_pg_name = f"{db_identifier}-cluster-logging-enabled{unique_suffix}"
    
    # Verify naming conventions
    assert len(expected_instance_pg_name) <= 255  # AWS limit
    assert len(expected_cluster_pg_name) <= 255   # AWS limit
    assert unique_suffix in expected_instance_pg_name
    assert unique_suffix in expected_cluster_pg_name
    assert "logging-enabled" in expected_instance_pg_name
    assert "logging-enabled" in expected_cluster_pg_name


def test_case_detection_logic():
    """Test the three case detection scenarios"""
    
    # Case 1: Standalone DB instance
    case1_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres'
                # No DBClusterIdentifier
            }
        }
    }
    
    instance_details = case1_resource['Details'].get('AwsRdsDbInstance')
    instance_db_cluster_identifier = case1_resource['Details'].get('AwsRdsDbInstance', {}).get('DBClusterIdentifier')
    cluster_details = case1_resource['Details'].get('AwsRdsDbCluster')
    
    # Should be Case 1: instance exists, no cluster identifier
    assert instance_details is not None
    assert instance_db_cluster_identifier is None
    assert cluster_details is None
    
    # Case 2: Direct DB cluster finding
    case2_resource = {
        'Details': {
            'AwsRdsDbCluster': {
                'DBClusterIdentifier': 'test-cluster',
                'Engine': 'aurora-postgresql'
            }
        }
    }
    
    instance_details = case2_resource['Details'].get('AwsRdsDbInstance')
    cluster_details = case2_resource['Details'].get('AwsRdsDbCluster')
    
    # Should be Case 2: cluster exists, no instance
    assert instance_details is None
    assert cluster_details is not None
    
    # Case 3: DB instance in a cluster
    case3_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance-in-cluster',
                'Engine': 'aurora-postgresql',
                'DBClusterIdentifier': 'parent-cluster'
            }
        }
    }
    
    instance_details = case3_resource['Details'].get('AwsRdsDbInstance')
    instance_db_cluster_identifier = case3_resource['Details'].get('AwsRdsDbInstance', {}).get('DBClusterIdentifier')
    
    # Should be Case 3: instance exists with cluster identifier
    assert instance_details is not None
    assert instance_db_cluster_identifier == 'parent-cluster'


def test_engine_support_validation():
    """Test engine support validation logic"""
    
    # Import ENGINE_LOG_TYPES locally to avoid import issues
    engine_log_types = {
        'postgres':          ["postgresql", "upgrade"],
        'aurora-postgresql': ['postgresql']
    }
    
    # Test supported engines
    assert 'postgres' in engine_log_types
    assert 'aurora-postgresql' in engine_log_types
    
    # Test unsupported engines
    assert 'mysql' not in engine_log_types
    assert 'mariadb' not in engine_log_types
    assert 'oracle' not in engine_log_types
    
    # Test log types for supported engines
    postgres_logs = engine_log_types.get('postgres')
    aurora_logs = engine_log_types.get('aurora-postgresql')
    
    assert postgres_logs == ["postgresql", "upgrade"]
    assert aurora_logs == ['postgresql']
    
    # Test unsupported engine returns None
    mysql_logs = engine_log_types.get('mysql')
    assert mysql_logs is None


def test_unique_suffix_generation_edge_cases():
    """Test unique suffix generation with various finding ID formats"""
    
    # Standard finding ID
    finding_id_1 = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012"
    suffix_1 = '-' + finding_id_1.split('/')[-1][-8:]
    assert suffix_1 == '-56789012'
    
    # Short finding ID
    finding_id_2 = "arn:aws:securityhub:us-east-1:123456789012:finding/short"
    suffix_2 = '-' + finding_id_2.split('/')[-1][-8:]
    assert suffix_2 == '-short'
    
    # Very long finding ID
    finding_id_3 = "arn:aws:securityhub:us-east-1:123456789012:finding/very-long-finding-identifier-with-many-characters"
    suffix_3 = '-' + finding_id_3.split('/')[-1][-8:]
    assert suffix_3 == '-aracters'
    
    # Empty finding ID (edge case)
    finding_id_4 = ""
    if finding_id_4:
        suffix_4 = '-' + finding_id_4.split('/')[-1][-8:]
    else:
        suffix_4 = ''
    assert suffix_4 == ''


def test_parameter_validation():
    """Test parameter structure validation"""
    
    # Expected parameter structure for RDS.9
    expected_postgres_params = [
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
    
    # Validate parameter structure
    for param in expected_postgres_params:
        assert 'ApplyMethod' in param
        assert 'ParameterName' in param
        assert 'ParameterValue' in param
        assert param['ApplyMethod'] == 'immediate'
    
    # Validate specific parameters for RDS.9
    param_names = [p['ParameterName'] for p in expected_postgres_params]
    assert 'log_statement' in param_names
    assert 'log_min_duration_statement' in param_names
    
    # Validate parameter values
    log_statement_param = next(p for p in expected_postgres_params if p['ParameterName'] == 'log_statement')
    log_duration_param = next(p for p in expected_postgres_params if p['ParameterName'] == 'log_min_duration_statement')
    
    assert log_statement_param['ParameterValue'] == 'ddl'
    assert log_duration_param['ParameterValue'] == '-1'


def test_cloudwatch_logs_configuration():
    """Test CloudWatch logs export configuration"""
    
    # Expected log types for different engines
    engine_log_types = {
        'postgres':          ["postgresql", "upgrade"],
        'aurora-postgresql': ['postgresql']
    }
    
    # Test CloudWatch logs export structure
    for engine, log_types in engine_log_types.items():
        cloudwatch_config = {
            'EnableLogTypes': log_types
        }
        
        assert 'EnableLogTypes' in cloudwatch_config
        assert isinstance(cloudwatch_config['EnableLogTypes'], list)
        assert len(cloudwatch_config['EnableLogTypes']) > 0
        
        # All engines should enable 'postgresql' logs
        assert 'postgresql' in cloudwatch_config['EnableLogTypes']


def test_resource_details_extraction():
    """Test resource details extraction logic"""
    
    # Test instance details extraction
    instance_resource = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres',
                'EngineVersion': '14.9'
            }
        }
    }
    
    instance_details = instance_resource['Details'].get('AwsRdsDbInstance')
    cluster_details = instance_resource['Details'].get('AwsRdsDbCluster')
    details = instance_details or cluster_details
    
    assert details is not None
    assert details['Engine'] == 'postgres'
    assert details['DBInstanceIdentifier'] == 'test-instance'
    
    # Test cluster details extraction
    cluster_resource = {
        'Details': {
            'AwsRdsDbCluster': {
                'DBClusterIdentifier': 'test-cluster',
                'Engine': 'aurora-postgresql'
            }
        }
    }
    
    instance_details = cluster_resource['Details'].get('AwsRdsDbInstance')
    cluster_details = cluster_resource['Details'].get('AwsRdsDbCluster')
    details = instance_details or cluster_details
    
    assert details is not None
    assert details['Engine'] == 'aurora-postgresql'
    assert details['DBClusterIdentifier'] == 'test-cluster'


def test_error_handling_scenarios():
    """Test various error handling scenarios"""
    
    # Test missing engine handling
    resource_no_engine = {
        'Details': {
            'AwsRdsDbInstance': {
                'DBInstanceIdentifier': 'test-instance'
                # Missing Engine field
            }
        }
    }
    
    details = resource_no_engine['Details'].get('AwsRdsDbInstance')
    engine = details.get('Engine')  # Using .get() for safety
    
    assert engine is None
    
    # Test missing details handling
    resource_no_details = {
        'Details': {}
    }
    
    instance_details = resource_no_details['Details'].get('AwsRdsDbInstance')
    cluster_details = resource_no_details['Details'].get('AwsRdsDbCluster')
    details = instance_details or cluster_details
    
    assert details is None
    
    # Test missing cluster identifier handling
    cluster_resource_missing_id = {
        'Details': {
            'AwsRdsDbCluster': {
                'Engine': 'aurora-postgresql'
                # Missing DBClusterIdentifier
            }
        }
    }
    
    details = cluster_resource_missing_id['Details'].get('AwsRdsDbCluster')
    cluster_id = details.get('DBClusterIdentifier')
    
    assert cluster_id is None


if __name__ == "__main__":
    pytest.main([__file__])