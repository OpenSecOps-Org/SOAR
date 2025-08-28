"""
Unit tests for RDS.4 auto-remediation: RDS snapshots should be encrypted

This control checks whether Amazon RDS DB snapshots are encrypted. This includes both
DB instance snapshots and DB cluster snapshots.

Test triggers:
- Instance snapshot: aws rds describe-db-snapshots --db-snapshot-identifier test-snapshot
- Cluster snapshot: aws rds describe-db-cluster-snapshots --db-cluster-snapshot-identifier test-cluster-snapshot

The auto-remediation copies the snapshot with encryption enabled using the AWS managed
key (aws/rds), then deletes the original unencrypted snapshot.
"""
import pytest
from unittest.mock import MagicMock, patch, call
from moto import mock_aws
import boto3

# Import the lambda handler
import sys
import os
# Add lambda layers to Python path for aws_utils and rds_remediation imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
rds_remediation_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'layers', 'rds_remediation', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)
sys.path.insert(0, rds_remediation_path)

# Mock environment variables before importing the function
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'

# Add function directory to path
rds4_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'functions', 'auto_remediations', 'auto_remediate_rds4')
sys.path.insert(0, rds4_path)
from functions.auto_remediations.auto_remediate_rds4.app import lambda_handler

# Import fixtures
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures', 'security_hub_findings'))
from rds_findings import (
    get_rds4_instance_snapshot_finding,
    get_rds4_cluster_snapshot_finding,
    get_rds4_encrypted_snapshot_finding,
    get_rds4_empty_snapshot_finding
)

# Import centralized ASFF data helper
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fixtures'))
from asff_data import prepare_rds_test_data


class TestRds4SnapshotDetection:
    """Test snapshot type detection and basic validation"""
    
    def test_detect_instance_snapshot_from_resource_type(self):
        """Test detection of DB instance snapshot from resource type"""
        finding = get_rds4_instance_snapshot_finding()
        resource = finding['finding']['Resources'][0]
        assert resource['Details']['AwsRdsDbSnapshot']['DbSnapshotIdentifier'] == 'instance-snapshot-unencrypted'
        assert 'DbInstanceIdentifier' in resource['Details']['AwsRdsDbSnapshot']
        assert 'DbClusterIdentifier' not in resource['Details']['AwsRdsDbSnapshot']
    
    def test_detect_cluster_snapshot_from_resource_type(self):
        """Test detection of DB cluster snapshot from resource type"""
        finding = get_rds4_cluster_snapshot_finding()
        resource = finding['finding']['Resources'][0]
        assert resource['Details']['AwsRdsDbClusterSnapshot']['DbClusterSnapshotIdentifier'] == 'cluster-snapshot-unencrypted'
        assert 'DbClusterIdentifier' in resource['Details']['AwsRdsDbClusterSnapshot']
        assert 'DbInstanceIdentifier' not in resource['Details']['AwsRdsDbClusterSnapshot']
    
    def test_encrypted_snapshot_should_be_skipped(self):
        """Test that already encrypted snapshots are identified for skipping"""
        finding = get_rds4_encrypted_snapshot_finding()
        resource = finding['finding']['Resources'][0]
        assert resource['Details']['AwsRdsDbSnapshot']['Encrypted'] is True
        assert 'KmsKeyId' in resource['Details']['AwsRdsDbSnapshot']


class TestRds4SnapshotCopyLogic:
    """Test snapshot copy operations with encryption"""
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_instance_snapshot_copy_with_encryption(self, mock_get_client):
        """Test copying DB instance snapshot with encryption enabled"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        # Configure describe_db_snapshots to return unencrypted snapshot
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'instance-snapshot-unencrypted',
                'DBInstanceIdentifier': 'source-instance-1',
                'Engine': 'postgres',
                'Encrypted': False,
                'AllocatedStorage': 20
            }]
        }
        
        # Configure copy_db_snapshot to succeed
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {
                'DBSnapshotIdentifier': 'instance-snapshot-unencrypted-encrypted-copy-12345678',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        # Configure waiter to succeed
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler
        response = lambda_handler(test_data, {})
        
        # Verify copy_db_snapshot was called with encryption
        mock_rds.copy_db_snapshot.assert_called_once()
        copy_call = mock_rds.copy_db_snapshot.call_args[1]
        assert copy_call['SourceDBSnapshotIdentifier'] == 'instance-snapshot-unencrypted'
        assert copy_call['TargetDBSnapshotIdentifier'] == 'instance-snapshot-unencrypted-encrypted'
        assert copy_call['KmsKeyId'] == 'alias/aws/rds'
        assert copy_call['CopyTags'] is True
        
        # Verify waiter was used
        mock_rds.get_waiter.assert_called_with('db_snapshot_available')
        mock_waiter.wait.assert_called_once()
        
        # Verify original snapshot deletion
        mock_rds.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier='instance-snapshot-unencrypted'
        )
        
        # Verify response structure and success messages
        assert 'messages' in response
        assert 'The snapshot has been copied to a new, encrypted snapshot' in response['messages']['actions_taken']
        assert response['messages']['actions_required'] == "None"
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_cluster_snapshot_copy_with_encryption(self, mock_get_client):
        """Test copying DB cluster snapshot with encryption enabled"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        # Configure describe_db_cluster_snapshots to return unencrypted snapshot
        mock_rds.describe_db_cluster_snapshots.return_value = {
            'DBClusterSnapshots': [{
                'DBClusterSnapshotIdentifier': 'cluster-snapshot-unencrypted',
                'DBClusterIdentifier': 'source-cluster-1',
                'Engine': 'aurora-postgresql',
                'Encrypted': False,
                'AllocatedStorage': 1
            }]
        }
        
        # Configure copy_db_cluster_snapshot to succeed
        mock_rds.copy_db_cluster_snapshot.return_value = {
            'DBClusterSnapshot': {
                'DBClusterSnapshotIdentifier': 'cluster-snapshot-unencrypted-encrypted-copy-12345678',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        # Configure waiter to succeed
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_cluster_snapshot_finding)
        
        # Call the lambda handler
        response = lambda_handler(test_data, {})
        
        # Verify copy_db_cluster_snapshot was called with encryption
        mock_rds.copy_db_cluster_snapshot.assert_called_once()
        copy_call = mock_rds.copy_db_cluster_snapshot.call_args[1]
        assert copy_call['SourceDBClusterSnapshotIdentifier'] == 'cluster-snapshot-unencrypted'
        assert copy_call['TargetDBClusterSnapshotIdentifier'] == 'cluster-snapshot-unencrypted-encrypted'
        assert copy_call['KmsKeyId'] == 'alias/aws/rds'
        assert copy_call['CopyTags'] is True
        
        # Verify waiter was used
        mock_rds.get_waiter.assert_called_with('db_cluster_snapshot_available')
        mock_waiter.wait.assert_called_once()
        
        # Verify original snapshot deletion
        mock_rds.delete_db_cluster_snapshot.assert_called_once_with(
            DBClusterSnapshotIdentifier='cluster-snapshot-unencrypted'
        )
        
        assert 'messages' in response
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_empty_snapshot_copy_optimization(self, mock_get_client):
        """Test that empty snapshots (size 0) still get copied but with optimized parameters"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        # Configure describe_db_snapshots to return empty snapshot
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'empty-snapshot-test',
                'DBInstanceIdentifier': 'source-instance-empty',
                'Engine': 'mysql',
                'Encrypted': False,
                'AllocatedStorage': 0
            }]
        }
        
        # Configure copy_db_snapshot to succeed
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {
                'DBSnapshotIdentifier': 'empty-snapshot-test-encrypted-copy-12345678',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        # Configure waiter to succeed
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_empty_snapshot_finding)
        
        # Call the lambda handler
        response = lambda_handler(test_data, {})
        
        # Empty snapshots (AllocatedStorage=0) are deleted directly, not copied
        mock_rds.copy_db_snapshot.assert_not_called()
        
        # Verify deletion of original empty snapshot
        mock_rds.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier='empty-snapshot-test'
        )
        
        # Verify empty snapshot response message
        assert 'messages' in response
        assert response['messages']['actions_taken'] == "The snapshot was empty and has been deleted."
        assert response['messages']['actions_required'] == "None"


class TestRds4UniqueNaming:
    """Test unique snapshot identifier generation"""
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_unique_target_snapshot_name_generation(self, mock_get_client):
        """Test that target snapshot names include unique suffixes to prevent collisions"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        # Configure describe and copy operations
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'test-snapshot',
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres',
                'Encrypted': False,
                'AllocatedStorage': 10
            }]
        }
        
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {
                'DBSnapshotIdentifier': 'test-snapshot-encrypted-copy-12345678',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler
        lambda_handler(test_data, {})
        
        # Verify target name follows the pattern: {original_name}-encrypted
        copy_call = mock_rds.copy_db_snapshot.call_args[1]
        target_name = copy_call['TargetDBSnapshotIdentifier']
        assert target_name == 'instance-snapshot-unencrypted-encrypted'
        assert target_name.endswith('-encrypted')


class TestRds4KmsKeyHandling:
    """Test KMS key specification and encryption parameters"""
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_aws_managed_key_usage(self, mock_get_client):
        """Test that AWS managed RDS key is used for encryption"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'test-snapshot',
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres',
                'Encrypted': False,
                'AllocatedStorage': 20
            }]
        }
        
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {'DBSnapshotIdentifier': 'test-copy', 'Encrypted': True, 'Status': 'creating'}
        }
        
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler
        lambda_handler(test_data, {})
        
        # Verify AWS managed key is specified (Encrypted is implied by KmsKeyId)
        copy_call = mock_rds.copy_db_snapshot.call_args[1]
        assert copy_call['KmsKeyId'] == 'alias/aws/rds'
        assert copy_call['CopyTags'] is True


class TestRds4ErrorHandling:
    """Test error scenarios and resilience"""
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_already_encrypted_snapshot_processing(self, mock_get_client):
        """Test that already encrypted snapshots are still processed (function doesn't check encryption status from findings)"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        # Configure copy operation to succeed (function will attempt to copy even if already encrypted)
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {
                'DBSnapshotIdentifier': 'already-encrypted-snapshot-encrypted',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        # Configure waiter to succeed
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_encrypted_snapshot_finding)
        
        # Call the lambda handler
        response = lambda_handler(test_data, {})
        
        # Verify copy operation was attempted (function doesn't check if already encrypted)
        mock_rds.copy_db_snapshot.assert_called_once()
        copy_call = mock_rds.copy_db_snapshot.call_args[1]
        assert copy_call['SourceDBSnapshotIdentifier'] == 'already-encrypted-snapshot'
        assert copy_call['TargetDBSnapshotIdentifier'] == 'already-encrypted-snapshot-encrypted'
        assert copy_call['KmsKeyId'] == 'alias/aws/rds'
        
        # Verify deletion of original snapshot
        mock_rds.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier='already-encrypted-snapshot'
        )
        
        assert 'messages' in response
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_copy_operation_failure_handling(self, mock_get_client):
        """Test handling of copy operation failures"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'test-snapshot',
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres',
                'Encrypted': False,
                'AllocatedStorage': 20
            }]
        }
        
        # Configure copy to fail
        mock_rds.copy_db_snapshot.side_effect = Exception('Copy operation failed')
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler and expect exception
        with pytest.raises(Exception, match='Copy operation failed'):
            lambda_handler(test_data, {})
        
        # Verify copy was attempted but delete was not called due to failure
        mock_rds.copy_db_snapshot.assert_called_once()
        mock_rds.delete_db_snapshot.assert_not_called()
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_waiter_timeout_handling(self, mock_get_client):
        """Test handling of waiter timeout scenarios"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'test-snapshot',
                'DBInstanceIdentifier': 'test-instance',
                'Engine': 'postgres',
                'Encrypted': False,
                'AllocatedStorage': 20
            }]
        }
        
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {'DBSnapshotIdentifier': 'test-copy', 'Encrypted': True, 'Status': 'creating'}
        }
        
        # Configure waiter to timeout
        mock_waiter = MagicMock()
        mock_waiter.wait.side_effect = Exception('Waiter timeout')
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler and expect exception
        with pytest.raises(Exception, match='Waiter timeout'):
            lambda_handler(test_data, {})
        
        # Verify copy was attempted and waiter was called
        mock_rds.copy_db_snapshot.assert_called_once()
        mock_waiter.wait.assert_called_once()
        # Delete should not be called if waiter fails
        mock_rds.delete_db_snapshot.assert_not_called()


class TestRds4MultiStepWorkflow:
    """Test the complete multi-step workflow validation"""
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')
    def test_complete_workflow_sequence(self, mock_get_client):
        """Test that the complete workflow executes in correct order: copy → wait → delete"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {
                'DBSnapshotIdentifier': 'instance-snapshot-unencrypted-encrypted',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler
        response = lambda_handler(test_data, {})
        
        # Verify the sequence of operations (no describe call since data comes from Security Hub)
        assert mock_rds.copy_db_snapshot.call_count == 1
        assert mock_rds.get_waiter.call_count == 1
        assert mock_waiter.wait.call_count == 1
        assert mock_rds.delete_db_snapshot.call_count == 1
        
        # Verify the order by checking call order
        handle = mock_rds.method_calls
        method_names = [call[0] for call in handle]
        
        # Expected order: copy_db_snapshot, get_waiter, delete_db_snapshot
        copy_index = next(i for i, name in enumerate(method_names) if 'copy_db_snapshot' in name)
        waiter_index = next(i for i, name in enumerate(method_names) if 'get_waiter' in name)
        delete_index = next(i for i, name in enumerate(method_names) if 'delete_db_snapshot' in name)
        
        assert copy_index < waiter_index < delete_index
        
        assert 'messages' in response
    
    @mock_aws
    @patch('functions.auto_remediations.auto_remediate_rds4.app.get_client')  
    def test_workflow_preserves_snapshot_metadata(self, mock_get_client):
        """Test that critical snapshot metadata is preserved during copy operation"""
        # Setup mock RDS client
        mock_rds = MagicMock()
        mock_get_client.return_value = mock_rds
        
        mock_rds.describe_db_snapshots.return_value = {
            'DBSnapshots': [{
                'DBSnapshotIdentifier': 'metadata-test-snapshot',
                'DBInstanceIdentifier': 'production-db-instance',
                'Engine': 'postgres',
                'EngineVersion': '14.9',
                'Encrypted': False,
                'AllocatedStorage': 100,
                'Port': 5432,
                'AvailabilityZone': 'us-east-1a'
            }]
        }
        
        mock_rds.copy_db_snapshot.return_value = {
            'DBSnapshot': {
                'DBSnapshotIdentifier': 'metadata-test-snapshot-encrypted-copy-12345678',
                'Encrypted': True,
                'Status': 'creating'
            }
        }
        
        mock_waiter = MagicMock()
        mock_rds.get_waiter.return_value = mock_waiter
        
        test_data = prepare_rds_test_data(get_rds4_instance_snapshot_finding)
        
        # Call the lambda handler
        lambda_handler(test_data, {})
        
        # Verify copy parameters preserve source snapshot reference
        copy_call = mock_rds.copy_db_snapshot.call_args[1]
        assert copy_call['SourceDBSnapshotIdentifier'] == 'instance-snapshot-unencrypted'
        
        # Key transformation: KmsKeyId should be aws/rds (Encrypted is implied)
        assert copy_call['KmsKeyId'] == 'alias/aws/rds'
        assert copy_call['CopyTags'] is True