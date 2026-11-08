"""The incidents table can be queried by alarm and time.

CloudWatch context enrichment looks up earlier incidents of the same alarm. Remember Incident
Opened records GeneratorId (the alarm name, for alarm findings) and opened_at (ISO 8601), so
the table needs an index on exactly those two attributes.
"""
from pathlib import Path

import yaml

TEMPLATE = Path(__file__).resolve().parents[2] / 'template.yaml'


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that accepts CloudFormation tags (!Ref, !GetAtt, !Sub, ...) without resolving them."""


CfnLoader.add_multi_constructor('!', lambda loader, suffix, node: None)


def incidents_table():
    return yaml.load(TEMPLATE.read_text(), Loader=CfnLoader)['Resources']['Incidents']['Properties']


def test_incidents_table_has_a_generator_id_opened_at_index():
    indexes = {i['IndexName']: i for i in incidents_table()['GlobalSecondaryIndexes']}
    index = indexes['GeneratorId-opened_at-index']
    assert index['KeySchema'] == [{'AttributeName': 'GeneratorId', 'KeyType': 'HASH'},
                                  {'AttributeName': 'opened_at', 'KeyType': 'RANGE'}]
    assert index['Projection'] == {'ProjectionType': 'ALL'}


def test_index_attributes_are_defined_as_strings():
    definitions = {d['AttributeName']: d['AttributeType'] for d in incidents_table()['AttributeDefinitions']}
    assert definitions['GeneratorId'] == 'S'
    assert definitions['opened_at'] == 'S'


def test_existing_index_is_kept():
    """get_overdue_tickets and the reports use dummy-opened_at-index"""
    indexes = {i['IndexName'] for i in incidents_table()['GlobalSecondaryIndexes']}
    assert 'dummy-opened_at-index' in indexes
