"""
Tests for setup_overview_section's dict_list_to_csv helper.

Replaces the previous pandas/numpy library-smoke tests now that pandas has been
removed. The helper must be byte-equivalent to the prior
`pd.DataFrame(records).to_csv(index=False)` call for the scalar-typed records
this module produces (str, int, bool, Decimal); the assertions below are the
parity cases the migration was validated against.
"""

from decimal import Decimal

from functions.reports.setup_overview_section.app import dict_list_to_csv


class TestDictListToCsv:
    """Behavioural tests for the pandas-replacement helper."""

    def test_empty_list_matches_pandas_empty_dataframe(self):
        """Empty input returns '\\n' (pandas DataFrame([]).to_csv(index=False) behaviour)."""
        assert dict_list_to_csv([]) == "\n"

    def test_single_row_simple_types(self):
        result = dict_list_to_csv([{"a": "1", "b": "2"}])
        assert result == "a,b\n1,2\n"

    def test_multi_row_security_control_shape(self):
        """The shape produced by get_security_control_data_redux."""
        records = [
            {"SecurityControlId": "EC2.1", "Title": "EBS snapshots", "Description": "Check EBS"},
            {"SecurityControlId": "S3.1", "Title": "S3 public access", "Description": "Check S3"},
        ]
        result = dict_list_to_csv(records)
        expected = (
            "SecurityControlId,Title,Description\n"
            "EC2.1,EBS snapshots,Check EBS\n"
            "S3.1,S3 public access,Check S3\n"
        )
        assert result == expected

    def test_decimal_values_from_dynamodb(self):
        """DynamoDB returns Decimal; helper must serialise them via str()."""
        records = [
            {"penalty_score": Decimal("50.0"), "account": "Production"},
            {"penalty_score": Decimal("25.5"), "account": "Staging"},
        ]
        result = dict_list_to_csv(records)
        assert result == "penalty_score,account\n50.0,Production\n25.5,Staging\n"

    def test_integer_values(self):
        """Frequency counts and similar ints serialise without trailing zeros."""
        records = [{"id": "X", "count": 5}, {"id": "Y", "count": 0}]
        result = dict_list_to_csv(records)
        assert result == "id,count\nX,5\nY,0\n"

    def test_value_with_comma_is_quoted(self):
        """Embedded delimiter triggers minimal quoting (matches pandas)."""
        records = [{"msg": "has,comma"}]
        result = dict_list_to_csv(records)
        assert result == 'msg\n"has,comma"\n'

    def test_value_with_double_quote_is_escaped(self):
        """Embedded quote becomes doubled and the cell is quoted (CSV standard)."""
        records = [{"msg": 'has"quote'}]
        result = dict_list_to_csv(records)
        assert result == 'msg\n"has""quote"\n'

    def test_value_with_newline_is_quoted(self):
        """Embedded newline triggers quoting; line stays a logical CSV cell."""
        records = [{"msg": "has\nnewline"}]
        result = dict_list_to_csv(records)
        assert result == 'msg\n"has\nnewline"\n'

    def test_none_value_renders_as_empty(self):
        """None becomes empty cell (csv module's default; matches pandas NaN handling)."""
        records = [{"a": "x", "b": None}, {"a": "y", "b": "z"}]
        result = dict_list_to_csv(records)
        assert result == "a,b\nx,\ny,z\n"

    def test_lineterminator_is_lf_only(self):
        """Output uses LF, not CRLF — pandas default on Linux/macOS, what Lambda runtime expects."""
        result = dict_list_to_csv([{"a": "1"}])
        assert "\r" not in result
