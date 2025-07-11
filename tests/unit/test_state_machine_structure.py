"""
State machine structure tests to prevent regressions.

These tests validate the ASFF processor state machine structure and will fail
immediately if any structural changes are made without updating the tests.
"""

import yaml
import pytest
from pathlib import Path


def load_asff_state_machine():
    """Load the ASFF processor state machine definition."""
    state_machine_path = Path(__file__).parent.parent.parent / 'statemachines' / 'asff_processor.asl.yaml'
    with open(state_machine_path, 'r') as f:
        return yaml.safe_load(f)


# All previous individual tests removed - comprehensive validation now handled by test_complete_state_machine_connectivity()


def test_complete_state_machine_connectivity():
    """Test complete state machine connectivity - all nodes and their outgoing connections."""
    state_machine = load_asff_state_machine()
    
    # Complete node connectivity table
    # Format: 'NodeName': {'type': 'Task'|'Choice'|'Pass'|'Succeed'|'Fail', 'next': 'NodeName'|[choices]|None}
    expected_connectivity = {
        'Setup, Get Ticket and Decide': {
            'type': 'Task',
            'next': 'Branch on Decision'
        },
        'Branch on Decision': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.ASFF_decision', 'StringEquals': 'do_nothing', 'Next': 'Do Nothing'},
                {'Variable': '$.ASFF_decision', 'StringEquals': 'suppress_finding', 'Next': 'Suppress Finding'},
                {'Variable': '$.ASFF_decision', 'StringEquals': 'close_ticket', 'Next': 'Get Account Data for Closing'},
                {'Variable': '$.ASFF_decision', 'StringEquals': 'failed_control', 'Next': 'Failed Control'},
                {'Variable': '$.ASFF_decision', 'StringEquals': 'incident', 'Next': 'Get Account Data For Incident'}
            ],
            'default': 'Nonexistent Decision'
        },
        'Failed Control': {
            'type': 'Pass',
            'next': 'Get Account Data For Control'
        },
        'Get Account Data For Control': {
            'type': 'Task',
            'next': 'New Account?'
        },
        'New Account?': {
            'type': 'Choice',
            'choices': [
                {'And': [
                    {'Variable': '$.account.AccountNew', 'IsPresent': True},
                    {'Variable': '$.account.AccountNew', 'StringEquals': 'Yes'}
                ], 'Next': 'Suppress Finding'}
            ],
            'default': 'Get Control Enabled Status In Account'
        },
        'Get Control Enabled Status In Account': {
            'type': 'Task',
            'next': 'Is the Control Enabled In This Account?'
        },
        'Is the Control Enabled In This Account?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.db.enabled_controls.Item', 'IsPresent': False, 'Next': 'Suppress Finding'}
            ],
            'default': 'Get Enabled Controls Local Suppressions Table Entry'
        },
        'Get Enabled Controls Local Suppressions Table Entry': {
            'type': 'Task',
            'next': 'Check whether to suppress control locally'
        },
        'Check whether to suppress control locally': {
            'type': 'Task',
            'next': 'Check local control suppression result'
        },
        'Check local control suppression result': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.suppress_locally', 'BooleanEquals': True, 'Next': 'Suppress Finding'}
            ],
            'default': 'Compute Penalty Score'
        },
        'Compute Penalty Score': {
            'type': 'Task',
            'next': 'Get Remediatable SecHub Controls Table Entry'
        },
        'Get Remediatable SecHub Controls Table Entry': {
            'type': 'Task',
            'next': 'Is the autoremediation enabled?'
        },
        'Is the autoremediation enabled?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.db.remediatable-sec-hub-controls.Item', 'IsPresent': False, 'Next': 'Ticket the Team'}
            ],
            'default': 'Get Enabled Controls Local AutoRem Suppressions Table Entry'
        },
        'Get Enabled Controls Local AutoRem Suppressions Table Entry': {
            'type': 'Task',
            'next': 'Check whether to suppress control auto-remediation locally'
        },
        'Check whether to suppress control auto-remediation locally': {
            'type': 'Task',
            'next': 'Check local control auto-remediation suppression result'
        },
        'Check local control auto-remediation suppression result': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.suppress_locally', 'BooleanEquals': False, 'Next': 'Defer All AutoRemediations?'}
            ],
            'default': 'Ticket the Team'
        },
        'Defer All AutoRemediations?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.DeferAutoRemediations', 'StringEquals': 'Yes', 'Next': 'Do Nothing'}
            ],
            'default': 'Attempt AutoRemediation'
        },
        'Attempt AutoRemediation': {
            'type': 'Task',
            'next': 'Reconsider later?'
        },
        'Reconsider later?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.actions.reconsider_later', 'BooleanEquals': True, 'Next': 'Do Nothing'}
            ],
            'default': 'Suppress finding?'
        },
        'Suppress finding?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.actions.suppress_finding', 'BooleanEquals': True, 'Next': 'Suppress Finding'}
            ],
            'default': 'Autoremediation successful?'
        },
        'Autoremediation successful?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.actions.autoremediation_not_done', 'BooleanEquals': True, 'Next': 'Ticket the Team'}
            ],
            'default': 'Format Remediation Message'
        },
        'Ticket the Team': {
            'type': 'Pass',
            'next': 'Defer Team fixes?'
        },
        'Defer Team fixes?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.DeferTeamFixes', 'StringEquals': 'Yes', 'Next': 'Do Nothing'}
            ],
            'default': 'Format Ticketing Message'
        },
        'Format Ticketing Message': {
            'type': 'Task',
            'next': 'Open TEAMFIX Ticket'
        },
        'Open TEAMFIX Ticket': {
            'type': 'Task',
            'next': 'Remember Ticket Opened'
        },
        'Remember Ticket Opened': {
            'type': 'Task',
            'next': 'AddAiInstructionsForOpenedTickets'
        },
        'AddAiInstructionsForOpenedTickets': {
            'type': 'Task',
            'next': 'AddAiDataForOpenedTickets'
        },
        'AddAiDataForOpenedTickets': {
            'type': 'Task',
            'next': 'Send Ticketing Email'
        },
        'Send Ticketing Email': {
            'type': 'Task',
            'next': 'Set to NOTIFIED + Ticket data'
        },
        'Set to NOTIFIED + Ticket data': {
            'type': 'Task',
            'next': None  # End: True
        },
        'Format Remediation Message': {
            'type': 'Task',
            'next': 'Open AUTOFIXED Ticket'
        },
        'Open AUTOFIXED Ticket': {
            'type': 'Task',
            'next': 'Remember AutoRemediation Done'
        },
        'Remember AutoRemediation Done': {
            'type': 'Task',
            'next': 'AddAiInstructionsForAutoremediations'
        },
        'AddAiInstructionsForAutoremediations': {
            'type': 'Task',
            'next': 'AddAiDataForAutoremediation'
        },
        'AddAiDataForAutoremediation': {
            'type': 'Task',
            'next': 'Send Remediation Email'
        },
        'Send Remediation Email': {
            'type': 'Task',
            'next': 'Set to RESOLVED'
        },
        'Set to RESOLVED': {
            'type': 'Task',
            'next': None  # End: True
        },
        'Get Account Data For Incident': {
            'type': 'Task',
            'next': 'AWS Health Reclassifier'
        },
        'AWS Health Reclassifier': {
            'type': 'Task',
            'next': 'Should Reconsider Later After Health?'
        },
        'Should Reconsider Later After Health?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.actions.reconsider_later', 'BooleanEquals': True, 'Next': 'Do Nothing'}
            ],
            'default': 'Account Reassignment Preprocessor'
        },
        'Account Reassignment Preprocessor': {
            'type': 'Task',
            'next': 'Should Suppress Finding After Account Reassignment?'
        },
        'Should Suppress Finding After Account Reassignment?': {
            'type': 'Choice',
            'choices': [
                {'Variable': '$.actions.suppress_finding', 'BooleanEquals': True, 'Next': 'Suppress Finding'}
            ],
            'default': 'Handle Incident'
        },
        'Handle Incident': {
            'type': 'Task',
            'next': None  # End: True
        },
        'Get Account Data for Closing': {
            'type': 'Task',
            'next': 'Format Ticket Closed Message'
        },
        'Format Ticket Closed Message': {
            'type': 'Task',
            'next': 'Close Ticket'
        },
        'Close Ticket': {
            'type': 'Task',
            'next': 'Remember Ticket Closed'
        },
        'Remember Ticket Closed': {
            'type': 'Task',
            'next': 'AddAiInstructionsForClosedTickets'
        },
        'AddAiInstructionsForClosedTickets': {
            'type': 'Task',
            'next': 'AddAiDataForClosedTickets'
        },
        'AddAiDataForClosedTickets': {
            'type': 'Task',
            'next': 'Send Ticket Closed Email'
        },
        'Send Ticket Closed Email': {
            'type': 'Task',
            'next': 'Remove ticket data'
        },
        'Remove ticket data': {
            'type': 'Task',
            'next': None  # End: True
        },
        'Do Nothing': {
            'type': 'Succeed',
            'next': None  # Succeed node
        },
        'Suppress Finding': {
            'type': 'Task',
            'next': None  # End: True
        },
        'Nonexistent Decision': {
            'type': 'Fail',
            'next': None  # Fail node
        }
    }
    
    # Check that all expected nodes exist and no extra nodes
    actual_nodes = set(state_machine['States'].keys())
    expected_nodes = set(expected_connectivity.keys())
    
    missing_nodes = expected_nodes - actual_nodes
    extra_nodes = actual_nodes - expected_nodes
    
    assert not missing_nodes, f"Missing nodes from state machine: {missing_nodes}"
    assert not extra_nodes, f"Extra nodes found in state machine: {extra_nodes}"
    
    # Check each node's connectivity
    for node_name, expected_config in expected_connectivity.items():
        actual_node = state_machine['States'][node_name]
        
        # Check node type
        assert actual_node['Type'] == expected_config['type'], f"Node '{node_name}' has wrong type: expected {expected_config['type']}, got {actual_node['Type']}"
        
        # Check connectivity based on node type
        if expected_config['type'] == 'Choice':
            # Choice nodes have choices and default
            assert 'Choices' in actual_node, f"Choice node '{node_name}' missing Choices"
            assert 'Default' in actual_node, f"Choice node '{node_name}' missing Default"
            
            # Check choices
            expected_choices = expected_config['choices']
            actual_choices = actual_node['Choices']
            assert len(actual_choices) == len(expected_choices), f"Choice node '{node_name}' has wrong number of choices: expected {len(expected_choices)}, got {len(actual_choices)}"
            
            for i, expected_choice in enumerate(expected_choices):
                actual_choice = actual_choices[i]
                for key, value in expected_choice.items():
                    assert actual_choice.get(key) == value, f"Choice node '{node_name}' choice {i} has wrong {key}: expected {value}, got {actual_choice.get(key)}"
            
            # Check default
            assert actual_node['Default'] == expected_config['default'], f"Choice node '{node_name}' has wrong default: expected {expected_config['default']}, got {actual_node['Default']}"
            
        elif expected_config['next'] is not None:
            # Regular nodes with Next
            assert 'Next' in actual_node, f"Node '{node_name}' missing Next"
            assert actual_node['Next'] == expected_config['next'], f"Node '{node_name}' has wrong Next: expected {expected_config['next']}, got {actual_node['Next']}"
            
        else:
            # Terminal nodes (End: True, Succeed, Fail)
            if expected_config['type'] in ['Task', 'Pass']:
                assert actual_node.get('End') == True, f"Terminal node '{node_name}' missing End: True"
            # Succeed and Fail nodes don't have Next or End