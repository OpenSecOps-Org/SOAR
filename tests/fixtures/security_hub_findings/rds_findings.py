"""
Sample Security Hub findings for RDS testing
"""

def get_rds9_postgres_finding():
    """Mock Security Hub finding for RDS.9 control with PostgreSQL instance"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:test-postgres-instance',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'test-postgres-instance',
                        'Engine': 'postgres',
                        'EngineVersion': '14.9'
                    }
                }
            }]
        }
    }

def get_rds9_aurora_postgres_finding():
    """Mock Security Hub finding for RDS.9 control with Aurora PostgreSQL instance"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/aurora-postgres-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:test-aurora-postgres-instance',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'test-aurora-postgres-instance',
                        'Engine': 'aurora-postgresql',
                        'EngineVersion': '14.9'
                    }
                }
            }]
        }
    }

def get_unsupported_engine_finding():
    """Mock Security Hub finding for unsupported MySQL engine"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/mysql-test-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:test-mysql-instance',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'test-mysql-instance',
                        'Engine': 'mysql',
                        'EngineVersion': '8.0'
                    }
                }
            }]
        }
    }

def get_rds2_postgres_finding():
    """Mock Security Hub finding for RDS.2 control with publicly accessible PostgreSQL instance"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds2-finding-id',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:public-db-instance',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'public-db-instance',
                        'Engine': 'postgres',
                        'PubliclyAccessible': True
                    }
                }
            }]
        }
    }

def get_rds2_aurora_instance_finding():
    """Mock Security Hub finding for Aurora instance in cluster (RDS.2)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/aurora-rds2-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:aurora-instance-1',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'aurora-instance-1',
                        'Engine': 'aurora-postgresql',
                        'PubliclyAccessible': True,
                        'DBClusterIdentifier': 'aurora-cluster-1'
                    }
                }
            }]
        }
    }

def get_rds9_cluster_finding():
    """Mock Security Hub finding for RDS cluster (for RDS.9 testing)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/cluster-finding-id',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:cluster:test-cluster',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbCluster': {
                        'DBClusterIdentifier': 'test-cluster',
                        'Engine': 'aurora-postgresql',
                        'EngineVersion': '14.9',
                        'DbClusterParameterGroups': [{
                            'DbClusterParameterGroupName': 'default.aurora-postgresql14'
                        }]
                    }
                }
            }]
        }
    }

def get_rds11_instance_finding():
    """Mock Security Hub finding for RDS.11 control with standalone instance (backup disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds11-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:instance-no-backup',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'instance-no-backup',
                        'Engine': 'postgres',
                        'BackupRetentionPeriod': 0
                    }
                }
            }]
        }
    }

def get_rds11_cluster_finding():
    """Mock Security Hub finding for RDS.11 control with Aurora cluster (backup disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds11-cluster-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:cluster:cluster-no-backup',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbCluster': {
                        'DBClusterIdentifier': 'cluster-no-backup',
                        'Engine': 'aurora-postgresql',
                        'BackupRetentionPeriod': 0
                    }
                }
            }]
        }
    }

def get_rds11_aurora_instance_finding():
    """Mock Security Hub finding for RDS.11 control with Aurora instance in cluster (backup disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds11-aurora-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:aurora-instance-no-backup',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'aurora-instance-no-backup',
                        'Engine': 'aurora-mysql',
                        'DBClusterIdentifier': 'parent-cluster-no-backup',
                        'BackupRetentionPeriod': 0
                    }
                }
            }]
        }
    }

def get_rds13_instance_finding():
    """Mock Security Hub finding for RDS.13 control with standalone instance (auto upgrades disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds13-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:instance-no-auto-upgrade',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'instance-no-auto-upgrade',
                        'Engine': 'mysql',
                        'AutoMinorVersionUpgrade': False
                    }
                }
            }]
        }
    }

def get_rds13_cluster_finding():
    """Mock Security Hub finding for RDS.13 control with Aurora cluster (auto upgrades disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds13-cluster-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:cluster:cluster-no-auto-upgrade',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbCluster': {
                        'DBClusterIdentifier': 'cluster-no-auto-upgrade',
                        'Engine': 'aurora-mysql',
                        'AutoMinorVersionUpgrade': False
                    }
                }
            }]
        }
    }

def get_rds13_aurora_instance_finding():
    """Mock Security Hub finding for RDS.13 control with Aurora instance in cluster (auto upgrades disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds13-aurora-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:aurora-instance-no-auto-upgrade',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'aurora-instance-no-auto-upgrade',
                        'Engine': 'aurora-postgresql',
                        'DBClusterIdentifier': 'parent-cluster-no-auto-upgrade',
                        'AutoMinorVersionUpgrade': False
                    }
                }
            }]
        }
    }

def get_rds17_instance_finding():
    """Mock Security Hub finding for RDS.17 control with standalone instance (tag copying disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds17-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:instance-no-tag-copy',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'instance-no-tag-copy',
                        'Engine': 'postgres',
                        'CopyTagsToSnapshot': False
                    }
                }
            }]
        }
    }

def get_rds17_cluster_finding():
    """Mock Security Hub finding for RDS.17 control with Aurora cluster (tag copying disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds17-cluster-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:cluster:cluster-no-tag-copy',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbCluster': {
                        'DBClusterIdentifier': 'cluster-no-tag-copy',
                        'Engine': 'aurora-mysql',
                        'CopyTagsToSnapshot': False
                    }
                }
            }]
        }
    }

def get_rds17_aurora_instance_finding():
    """Mock Security Hub finding for RDS.17 control with Aurora instance in cluster (tag copying disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds17-aurora-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:aurora-instance-no-tag-copy',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'aurora-instance-no-tag-copy',
                        'Engine': 'aurora-postgresql',
                        'DBClusterIdentifier': 'parent-cluster-no-tag-copy',
                        'CopyTagsToSnapshot': False
                    }
                }
            }]
        }
    }

def get_rds6_instance_finding():
    """Mock Security Hub finding for RDS.6 control with standalone instance (enhanced monitoring disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds6-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:instance-no-monitoring',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'instance-no-monitoring',
                        'Engine': 'mysql',
                        'MonitoringInterval': 0
                    }
                }
            }]
        }
    }

def get_rds6_cluster_finding():
    """Mock Security Hub finding for RDS.6 control with Aurora cluster (enhanced monitoring disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds6-cluster-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:cluster:cluster-no-monitoring',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbCluster': {
                        'DBClusterIdentifier': 'cluster-no-monitoring',
                        'Engine': 'aurora-mysql',
                        'MonitoringInterval': 0
                    }
                }
            }]
        }
    }

def get_rds6_aurora_instance_finding():
    """Mock Security Hub finding for RDS.6 control with Aurora instance in cluster (enhanced monitoring disabled)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds6-aurora-instance-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:db:aurora-instance-no-monitoring',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbInstance': {
                        'DBInstanceIdentifier': 'aurora-instance-no-monitoring',
                        'Engine': 'aurora-postgresql',
                        'DBClusterIdentifier': 'parent-cluster-no-monitoring',
                        'MonitoringInterval': 0
                    }
                }
            }]
        }
    }

def get_rds4_instance_snapshot_finding():
    """Mock Security Hub finding for RDS.4 control with unencrypted DB instance snapshot"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds4-instance-snapshot-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:snapshot:rds:instance-snapshot-unencrypted',
                'Type': 'AwsRdsDbSnapshot',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbSnapshot': {
                        'DbSnapshotIdentifier': 'instance-snapshot-unencrypted',
                        'DbInstanceIdentifier': 'source-instance-1',
                        'Engine': 'postgres',
                        'EngineVersion': '14.9',
                        'Encrypted': False,
                        'AllocatedStorage': 20,
                        'SnapshotType': 'manual'
                    }
                }
            }]
        }
    }

def get_rds4_cluster_snapshot_finding():
    """Mock Security Hub finding for RDS.4 control with unencrypted DB cluster snapshot"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds4-cluster-snapshot-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:cluster-snapshot:cluster-snapshot-unencrypted',
                'Type': 'AwsRdsDbClusterSnapshot',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbClusterSnapshot': {
                        'DbClusterSnapshotIdentifier': 'cluster-snapshot-unencrypted',
                        'DbClusterIdentifier': 'source-cluster-1',
                        'Engine': 'aurora-postgresql',
                        'EngineVersion': '14.9',
                        'Encrypted': False,
                        'AllocatedStorage': 1,
                        'SnapshotType': 'manual'
                    }
                }
            }]
        }
    }

def get_rds4_encrypted_snapshot_finding():
    """Mock Security Hub finding for RDS.4 control with already encrypted snapshot (should be skipped)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds4-encrypted-snapshot-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:snapshot:rds:already-encrypted-snapshot',
                'Type': 'AwsRdsDbSnapshot',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbSnapshot': {
                        'DbSnapshotIdentifier': 'already-encrypted-snapshot',
                        'DbInstanceIdentifier': 'source-instance-2',
                        'Engine': 'postgres',
                        'EngineVersion': '14.9',
                        'Encrypted': True,
                        'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                        'AllocatedStorage': 50,
                        'SnapshotType': 'manual'
                    }
                }
            }]
        }
    }

def get_rds4_empty_snapshot_finding():
    """Mock Security Hub finding for RDS.4 control with empty snapshot (size 0)"""
    return {
        'finding': {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/rds4-empty-snapshot-finding',
            'AwsAccountId': '123456789012',
            'Resources': [{
                'Id': 'arn:aws:rds:us-east-1:123456789012:snapshot:rds:empty-snapshot-test',
                'Type': 'AwsRdsDbSnapshot',
                'Region': 'us-east-1',
                'Details': {
                    'AwsRdsDbSnapshot': {
                        'DbSnapshotIdentifier': 'empty-snapshot-test',
                        'DbInstanceIdentifier': 'source-instance-empty',
                        'Engine': 'mysql',
                        'EngineVersion': '8.0.35',
                        'Encrypted': False,
                        'AllocatedStorage': 0,
                        'SnapshotType': 'manual'
                    }
                }
            }]
        }
    }