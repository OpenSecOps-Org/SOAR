"""
Tests for setup_overview_section Lambda function.

Critical tests to validate pandas 2.2.2 fix:
1. Pandas imports correctly (no ModuleNotFoundError)
2. CSV conversion works (pandas DataFrame.to_csv())
"""

from decimal import Decimal


class TestPandasDependency:
    """Test that pandas dependency works correctly."""

    def test_pandas_imports_successfully(self):
        """Test that pandas 2.2.2 imports without errors."""
        import pandas as pd
        import numpy as np
        import humanize

        # Verify versions are pinned correctly
        assert pd.__version__.startswith('2.2')
        assert np.__version__.startswith('1.26')

    def test_pandas_dataframe_to_csv_conversion(self):
        """Test that pandas DataFrame to CSV conversion works (core functionality)."""
        import pandas as pd

        # Test with simple data
        df = pd.DataFrame({
            'SecurityControlId': ['EC2.1', 'S3.1', 'RDS.1'],
            'Title': ['EBS snapshots', 'S3 public access', 'RDS snapshots'],
            'Description': ['Check EBS', 'Check S3', 'Check RDS'],
            'Frequency': [5, 3, 2]
        })

        # Convert to CSV (this is what setup_overview_section does)
        csv_output = df.to_csv(index=False)

        # Verify CSV output
        assert isinstance(csv_output, str)
        assert 'SecurityControlId' in csv_output
        assert 'EC2.1' in csv_output
        assert 'S3.1' in csv_output
        assert 'RDS.1' in csv_output

    def test_pandas_handles_decimal_objects(self):
        """Test that pandas can handle Decimal objects (used in DynamoDB data)."""
        import pandas as pd

        # DynamoDB returns Decimal objects
        data = {
            'penalty_score': [Decimal('50.0'), Decimal('25.5'), Decimal('10.0')],
            'account': ['Production', 'Staging', 'Dev']
        }

        df = pd.DataFrame(data)
        csv_output = df.to_csv(index=False)

        # Should convert successfully
        assert isinstance(csv_output, str)
        assert 'penalty_score' in csv_output
        assert 'Production' in csv_output

    def test_humanize_time_deltas(self):
        """Test that humanize library works for time delta formatting."""
        import humanize

        # Test precisedelta (used in setup_overview_section)
        result = humanize.precisedelta(604800, minimum_unit='hours')  # 1 week in seconds

        assert isinstance(result, str)
        assert 'day' in result.lower() or 'week' in result.lower()

    def test_numpy_basic_operations(self):
        """Test that numpy works for basic array operations."""
        import numpy as np

        arr = np.array([1, 2, 3, 4, 5])
        mean = np.mean(arr)

        assert mean == 3.0
        assert arr.sum() == 15
