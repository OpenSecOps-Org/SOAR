"""
CloudWatch Context Enrichment Function - Specification Tests

This test suite serves as both comprehensive tests AND executable specification
for the CloudWatch context enrichment functionality in SOAR.

=== FUNCTIONAL SPECIFICATION ===

The CloudWatch Context Enrichment Function transforms basic CloudWatch alarm 
findings into enriched incident intelligence by:

1. DETECTION: Identifying CloudWatch alarm findings that need enrichment
2. SERVICE CONTEXT: Extracting service information (Step Functions, Lambda) 
3. ENRICHMENT: Adding execution context, logs, and failure details
4. PATTERN ANALYSIS: Providing historical incident patterns and trends
5. ERROR HANDLING: Graceful degradation when enrichment fails

=== SERVICE DETECTION STRATEGY ===

Primary: Resource-based detection (robust, works with any service names)
- Checks Resources array for AwsStatesStateMachine or AwsLambdaFunction types
- Extracts actual ARNs and service names from resource data

Fallback: Description parsing (backward compatibility)  
- Parses Description field when resource types not supported
- Maintains compatibility with current CloudWatch alarm findings

=== ENRICHMENT CAPABILITIES ===

Step Functions:
- Failed execution details and history
- CloudWatch Logs correlation
- State machine context

Lambda Functions:
- Error logs and invocation context  
- Function-specific failure details

All Services:
- Historical pattern analysis
- Incident frequency and trends
- Automated recommendations

=== TEST ORGANIZATION ===

Tests are organized as a specification, documenting expected behavior:
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import botocore.exceptions

# Add lambda layers to Python path for aws_utils imports
aws_utils_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'functions', 'layers', 'aws_utils', 'python', 'lib', 'python3.12', 'site-packages')
sys.path.insert(0, aws_utils_path)

# Mock environment variables
os.environ['INCIDENTS_TABLE_NAME'] = 'test-incidents-table'
os.environ['INCIDENT_EXPIRATION_DAYS'] = '365'
os.environ['CROSS_ACCOUNT_ROLE'] = 'arn:aws:iam::123456789012:role/TestRole'
os.environ['CLOUDWATCH_ALARM_TYPE'] = 'soar-cloudwatch-alarms'  # Must match SOAR-all-alarms-to-sec-hub
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

from tests.fixtures.asff_data import create_asff_test_data
from tests.fixtures.security_hub_findings.cloudwatch_alarm_findings import (
    get_stepfunctions_alarm_finding_standard,
    get_lambda_alarm_finding_standard,
    get_generic_alarm_finding,
    get_non_cloudwatch_finding,
    get_mock_stepfunctions_execution_details,
    get_mock_stepfunctions_execution_history,
    get_mock_cloudwatch_logs_entries
)


class TestSpecification_1_BasicFunctionality:
    """
    SPECIFICATION 1: Basic Function Contract
    
    The enrichment function MUST:
    - Accept standard SOAR scratchpad events
    - Return enhanced scratchpad data
    - Be callable without errors
    """
    
    def test_lambda_handler_exists(self):
        """Test that lambda_handler function exists and is callable"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        # Verify function exists and is callable
        assert callable(lambda_handler)
        
        # Test with minimal valid input - should not crash
        test_event = {"finding": {}, "account": {}, "actions": {}, "messages": {}, "db": {}}
        result = lambda_handler(test_event, None)
        
        # Should return the event (no-op for now)
        assert result is not None


class TestSpecification_2_CloudWatchAlarmDetection:
    """
    SPECIFICATION 2: CloudWatch Alarm Finding Detection
    
    The function MUST accurately identify CloudWatch alarm findings:
    - Detect Security Hub findings from CloudWatch alarms
    - Ignore non-CloudWatch findings
    - Use finding Types field for detection
    """
    
    def test_is_cloudwatch_alarm_finding_positive(self):
        """Test detection of valid CloudWatch alarm finding"""
        from functions.findings.enrich_cloudwatch_context.app import is_cloudwatch_alarm_finding
        
        cloudwatch_alarm_finding = get_stepfunctions_alarm_finding_standard()
        result = is_cloudwatch_alarm_finding(cloudwatch_alarm_finding)
        
        assert result is True
    
    def test_is_cloudwatch_alarm_finding_negative(self):
        """Test rejection of non-CloudWatch findings"""
        from functions.findings.enrich_cloudwatch_context.app import is_cloudwatch_alarm_finding
        
        non_cloudwatch_finding = get_non_cloudwatch_finding()
        result = is_cloudwatch_alarm_finding(non_cloudwatch_finding)
        
        assert result is False

    def test_cloudwatch_alarm_type_exact_matching(self):
        """Test exact matching against configured CloudWatch alarm type"""
        from functions.findings.enrich_cloudwatch_context.app import is_cloudwatch_alarm_finding
        
        # Test with exact match (should return True)
        exact_match_finding = {
            'Types': ['Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms']
        }
        assert is_cloudwatch_alarm_finding(exact_match_finding) is True
        
        # Test with different alarm type (should return False)
        different_type_finding = {
            'Types': ['Software and Configuration Checks/CloudWatch Alarms/different-alarm-type']
        }
        assert is_cloudwatch_alarm_finding(different_type_finding) is False
        
        # Test with old loose matching pattern (should return False)
        old_pattern_finding = {
            'Types': ['Some Other Type/CloudWatch Alarms/something']
        }
        assert is_cloudwatch_alarm_finding(old_pattern_finding) is False
        
        # Test environment variable override
        with patch.dict(os.environ, {'CLOUDWATCH_ALARM_TYPE': 'custom-alarm-type'}):
            custom_finding = {
                'Types': ['Software and Configuration Checks/CloudWatch Alarms/custom-alarm-type']
            }
            assert is_cloudwatch_alarm_finding(custom_finding) is True


class TestSpecification_3_ServiceContextExtraction:
    """
    SPECIFICATION 3: Service Context Extraction Strategy
    
    The function MUST extract service context using a dual approach:
    
    PRIMARY: Resource-based detection (preferred, robust)
    - Extract from Resources array: AwsStatesStateMachine, AwsLambdaFunction
    - Works with ANY service names (including arbitrary names like "BLAHONGA")
    - Provides actual ARNs for enrichment
    
    FALLBACK: Description parsing (backward compatibility)
    - Parse Description field when resource types not supported
    - Maintains compatibility with existing findings
    
    PRIORITY: Resource-based detection ALWAYS takes precedence over description parsing
    """
    
    def test_stepfunctions_detection_with_arbitrary_names(self):
        """REQUIREMENT: Must work with ANY state machine names, not just naming patterns"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        # Test with arbitrary state machine names - no naming pattern required!
        test_cases = [
            {
                'state_machine_name': 'BLAHONGA',  # Completely arbitrary name
                'region': 'us-east-1',
                'account': '123456789012'
            },
            {
                'state_machine_name': 'MyCompanyWorkflow',
                'region': 'eu-west-1', 
                'account': '999888777666'
            },
            {
                'state_machine_name': 'SomeRandomStateMachine123',
                'region': 'ap-southeast-2',
                'account': '111222333444'
            }
        ]
        
        for test_case in test_cases:
            # Create finding with resource data (not relying on alarm title)
            finding = {
                'Title': 'Could be any alarm name here - we ignore it!',
                'AwsAccountId': test_case['account'],
                'Region': test_case['region'],
                'Resources': [
                    {
                        'Type': 'AwsStatesStateMachine',
                        'Id': f"arn:aws:states:{test_case['region']}:{test_case['account']}:stateMachine:{test_case['state_machine_name']}",
                        'Region': test_case['region']
                    }
                ]
            }
            
            result = extract_service_context(finding)
            
            assert result['service_type'] == 'stepfunctions'
            assert result['state_machine_name'] == test_case['state_machine_name']
            assert result['state_machine_arn'] == finding['Resources'][0]['Id']
            assert result['enrichment_enabled'] is True
    
    def test_lambda_detection_with_arbitrary_names(self):
        """REQUIREMENT: Must work with ANY Lambda function names, not just naming patterns"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        # Test with arbitrary Lambda function names - no naming pattern required!
        test_cases = [
            {
                'function_name': 'MyArbitraryFunction',  # Completely arbitrary name
                'region': 'us-east-1',
                'account': '123456789012'
            },
            {
                'function_name': 'SomeCompanyProcessor',
                'region': 'eu-west-1', 
                'account': '999888777666'
            },
            {
                'function_name': 'WeirdFunctionName123XYZ',
                'region': 'ap-southeast-2',
                'account': '111222333444'
            }
        ]
        
        for test_case in test_cases:
            # Create finding with resource data (not relying on alarm title)
            finding = {
                'Title': 'Any alarm name works - we use resource data!',
                'AwsAccountId': test_case['account'],
                'Region': test_case['region'],
                'Resources': [
                    {
                        'Type': 'AwsLambdaFunction',
                        'Id': f"arn:aws:lambda:{test_case['region']}:{test_case['account']}:function:{test_case['function_name']}",
                        'Region': test_case['region']
                    }
                ]
            }
            
            result = extract_service_context(finding)
            
            assert result['service_type'] == 'lambda'
            assert result['function_name'] == test_case['function_name']
            assert result['function_arn'] == finding['Resources'][0]['Id']
            assert result['enrichment_enabled'] is True
    
    def test_extract_stepfunctions_context_fixture(self):
        """Test Step Functions service context extraction with test fixture"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        stepfunctions_alarm_finding = get_stepfunctions_alarm_finding_standard()
        result = extract_service_context(stepfunctions_alarm_finding)
        
        assert result['service_type'] == 'stepfunctions'
        assert 'state_machine_name' in result
        assert result['enrichment_enabled'] is True
    
    def test_extract_lambda_context_fixture(self):
        """Test Lambda function service context extraction with test fixture"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        lambda_alarm_finding = get_lambda_alarm_finding_standard()
        result = extract_service_context(lambda_alarm_finding)
        
        assert result['service_type'] == 'lambda'
        assert 'function_name' in result
        assert result['enrichment_enabled'] is True
    
    def test_extract_generic_context(self):
        """Test generic service context for unknown alarm types"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        generic_finding = get_generic_alarm_finding()
        result = extract_service_context(generic_finding)
        
        # Generic alarm with unsupported resource type - no enrichment enabled
        assert result['service_type'] == 'generic'
        assert result['enrichment_enabled'] is False
        assert result['detection_method'] == 'none'
    
    def test_resource_data_edge_cases(self):
        """Test edge cases for resource-based service detection"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        # Test finding with no resources
        finding_no_resources = {'Title': 'Some alarm', 'Resources': []}
        result = extract_service_context(finding_no_resources)
        assert result['service_type'] == 'generic'
        assert result['enrichment_enabled'] is False
        assert 'error' in result
        
        # Test finding with empty resources list
        finding_empty_resources = {'Title': 'Some alarm'}  # No Resources key at all
        result = extract_service_context(finding_empty_resources)
        assert result['service_type'] == 'generic'
        assert result['enrichment_enabled'] is False
        
        # Test finding with malformed resource ARN
        finding_malformed_arn = {
            'Title': 'Some alarm',
            'Resources': [
                {
                    'Type': 'AwsStatesStateMachine',
                    'Id': 'malformed-arn-without-proper-structure',
                    'Region': 'us-east-1'
                }
            ]
        }
        result = extract_service_context(finding_malformed_arn)
        assert result['service_type'] == 'stepfunctions'
        assert result['state_machine_name'] == 'UnknownStateMachine'  # Fallback name
        
        # Test Lambda with versioned ARN
        finding_versioned_lambda = {
            'Title': 'Some alarm',
            'Resources': [
                {
                    'Type': 'AwsLambdaFunction',
                    'Id': 'arn:aws:lambda:us-east-1:123456789012:function:MyFunction:1',
                    'Region': 'us-east-1'
                }
            ]
        }
        result = extract_service_context(finding_versioned_lambda)
        assert result['service_type'] == 'lambda'
        assert result['function_name'] == 'MyFunction'  # Version stripped
    
    def test_resource_detection_takes_priority(self):
        """REQUIREMENT: Resource-based detection MUST take priority over description parsing"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        # Finding with BOTH resource data AND description
        # Resource-based detection should take priority
        finding_with_both = {
            'AwsAccountId': '123456789012',
            'Region': 'us-east-1',
            'Description': 'The WrongNameFromDescription state machine failed.',  # Wrong info in description
            'Resources': [
                {
                    'Type': 'AwsAccountId',
                    'Id': '123456789012',
                    'Region': 'us-east-1'
                },
                {
                    'Type': 'AwsStatesStateMachine',
                    'Id': 'arn:aws:states:us-east-1:123456789012:stateMachine:CorrectNameFromResource',
                    'Region': 'us-east-1'
                }
            ]
        }
        
        result = extract_service_context(finding_with_both)
        
        # Should use resource data, NOT description parsing
        assert result['service_type'] == 'stepfunctions'
        assert result['state_machine_name'] == 'CorrectNameFromResource'  # From resource, not description
        assert result['detection_method'] == 'resource_arn'
        assert result['enrichment_enabled'] is True

    def test_backward_compatibility_with_old_cloudwatch_findings(self):
        """REQUIREMENT: Must handle old CloudWatch findings with only account resources"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        # Old-style CloudWatch finding with only AwsAccountId resource (no monitored resource)
        old_style_stepfunctions_finding = {
            'AwsAccountId': '123456789012',
            'Region': 'us-east-1',
            'Description': 'The SOARASFFProcessor state machine failed.',  # Info only in description
            'Resources': [
                {
                    'Type': 'AwsAccountId',
                    'Id': '123456789012',
                    'Region': 'us-east-1'
                }
                # No AwsStatesStateMachine resource - old format
            ]
        }
        
        result = extract_service_context(old_style_stepfunctions_finding)
        
        # No longer supports description parsing - requires proper ASFF resource types
        assert result['service_type'] == 'generic'
        assert result['detection_method'] == 'none'
        assert result['enrichment_enabled'] is False
        
        # Old-style Lambda finding
        old_style_lambda_finding = {
            'AwsAccountId': '555666777888',
            'Region': 'eu-west-1',
            'Description': 'The ProcessFindings function failed.',
            'Resources': [
                {
                    'Type': 'AwsAccountId',
                    'Id': '555666777888',
                    'Region': 'eu-west-1'
                }
                # No AwsLambdaFunction resource - old format
            ]
        }
        
        result = extract_service_context(old_style_lambda_finding)
        
        # No longer supports description parsing - requires proper ASFF resource types
        assert result['service_type'] == 'generic'
        assert result['detection_method'] == 'none'
        assert result['enrichment_enabled'] is False

    def test_malformed_enhanced_resource_data(self):
        """REQUIREMENT: Must handle malformed enhanced resource data gracefully"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        # Enhanced finding with malformed state machine resource
        malformed_cases = [
            # Case 1: AwsStatesStateMachine resource with empty ID
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The BackupStateMachine state machine failed.',
                'Resources': [
                    {
                        'Type': 'AwsAccountId',
                        'Id': '123456789012',
                        'Region': 'us-east-1'
                    },
                    {
                        'Type': 'AwsStatesStateMachine',
                        'Id': '',  # Empty ARN
                        'Region': 'us-east-1'
                    }
                ]
            },
            # Case 2: AwsLambdaFunction resource with None ID
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The BackupFunction function failed.',
                'Resources': [
                    {
                        'Type': 'AwsAccountId',
                        'Id': '123456789012',
                        'Region': 'us-east-1'
                    },
                    {
                        'Type': 'AwsLambdaFunction',
                        'Id': None,  # None ARN
                        'Region': 'us-east-1'
                    }
                ]
            },
            # Case 3: Resource with missing 'Id' field entirely
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The BackupStateMachine state machine failed.',
                'Resources': [
                    {
                        'Type': 'AwsAccountId',
                        'Id': '123456789012',
                        'Region': 'us-east-1'
                    },
                    {
                        'Type': 'AwsStatesStateMachine',
                        # No 'Id' field at all
                        'Region': 'us-east-1'
                    }
                ]
            }
        ]
        
        for i, malformed_finding in enumerate(malformed_cases):
            result = extract_service_context(malformed_finding)
            
            # Malformed resource data results in no enrichment (no description parsing fallback)
            assert result['service_type'] == 'generic', f"Case {i+1} failed"
            assert result['detection_method'] == 'none', f"Case {i+1} failed"
            assert result['enrichment_enabled'] is False, f"Case {i+1} failed"

    def test_completely_corrupted_resource_array(self):
        """REQUIREMENT: Must handle completely corrupted or unexpected resource structures"""
        from functions.findings.enrich_cloudwatch_context.app import extract_service_context
        
        corrupted_cases = [
            # Case 1: Resources is not a list
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The TestStateMachine state machine failed.',
                'Resources': "not-a-list"  # String instead of list
            },
            # Case 2: Resource items are not dictionaries
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The TestStateMachine state machine failed.',
                'Resources': ["string-item", 12345, None]  # Non-dict items
            },
            # Case 3: Resource dictionary missing Type field
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The TestStateMachine state machine failed.',
                'Resources': [
                    {
                        'Id': 'arn:aws:states:us-east-1:123456789012:stateMachine:TestStateMachine',
                        'Region': 'us-east-1'
                        # No 'Type' field
                    }
                ]
            },
            # Case 4: Mixed valid and invalid resources
            {
                'AwsAccountId': '123456789012',
                'Region': 'us-east-1',
                'Description': 'The TestStateMachine state machine failed.',
                'Resources': [
                    {
                        'Type': 'AwsAccountId',
                        'Id': '123456789012',
                        'Region': 'us-east-1'
                    },
                    "invalid-resource",  # Invalid item
                    {
                        'Type': 'AwsStatesStateMachine',
                        'Id': 'arn:aws:states:us-east-1:123456789012:stateMachine:TestStateMachine',
                        'Region': 'us-east-1'
                    }
                ]
            }
        ]
        
        for i, corrupted_finding in enumerate(corrupted_cases):
            # Should not crash and handle gracefully
            result = extract_service_context(corrupted_finding)
            
            # Cases 1-3: Corrupted resources result in no enrichment (no description parsing fallback)
            # Case 4: Mixed valid/invalid should find the valid AwsStatesStateMachine resource
            if i < 3:
                assert result['service_type'] == 'generic', f"Case {i+1} failed"
                assert result['detection_method'] == 'none', f"Case {i+1} failed"
                assert result['enrichment_enabled'] is False, f"Case {i+1} failed"
            else:
                # Case 4: Should find valid AwsStatesStateMachine resource despite invalid items
                assert result['service_type'] == 'stepfunctions', f"Case {i+1} failed"
                assert result['state_machine_name'] == 'TestStateMachine', f"Case {i+1} failed"
                assert result['detection_method'] == 'resource_arn', f"Case {i+1} failed"
                assert result['enrichment_enabled'] is True, f"Case {i+1} failed"


class TestSpecification_4_MainWorkflowIntegration:
    """
    SPECIFICATION 4: Main Workflow Integration
    
    The lambda_handler MUST:
    - Process CloudWatch alarm findings and enrich them
    - Pass through non-CloudWatch findings unchanged  
    - Return enhanced scratchpad with enriched_context
    """
    
    def test_cloudwatch_alarm_enrichment_workflow(self):
        """Test that CloudWatch alarm findings get enriched"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        finding_data = get_stepfunctions_alarm_finding_standard()
        cloudwatch_scratchpad_data = create_asff_test_data(finding_data)
        result = lambda_handler(cloudwatch_scratchpad_data, None)
        
        # Should return enhanced scratchpad with enriched context
        assert result is not None
        assert 'finding' in result
        assert 'enriched_context' in result
        assert result['enriched_context']['service_type'] == 'stepfunctions'
    
    def test_non_cloudwatch_finding_passthrough(self):
        """Test that non-CloudWatch findings pass through unchanged"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        finding_data = get_non_cloudwatch_finding()
        non_cloudwatch_scratchpad_data = create_asff_test_data(finding_data)
        result = lambda_handler(non_cloudwatch_scratchpad_data, None)
        
        # Should return original scratchpad unchanged
        assert result == non_cloudwatch_scratchpad_data
        assert 'enriched_context' not in result


class TestSpecification_5_ErrorHandlingAndGracefulDegradation:
    """
    SPECIFICATION 5: Error Handling and Graceful Degradation
    
    The function MUST handle errors gracefully:
    - Continue processing when enrichment fails
    - Handle malformed or missing data
    - Never crash the entire incident processing pipeline
    - Provide meaningful error information
    """
    
    def test_malformed_finding_graceful_handling(self):
        """Test that malformed findings are handled gracefully"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        # Malformed scratchpad with missing finding
        malformed_event = {
            'account': {},
            'actions': {},
            'messages': {},
            'db': {}
            # No 'finding' key
        }
        
        result = lambda_handler(malformed_event, None)
        
        # Should return original event unchanged
        assert result == malformed_event
        assert 'enriched_context' not in result
    
    def test_finding_missing_required_fields(self):
        """Test finding with missing required fields"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        # Finding missing Types field
        incomplete_finding_data = {
            'Id': 'test-incomplete-finding',
            'Title': 'INFRA-SOAR-ASFF-Processor-SM-Failure-HIGH',
            'Description': 'Step Function execution failed',
            'AwsAccountId': '123456789012'
            # No 'Types' field
        }
        event = create_asff_test_data(incomplete_finding_data)
        
        result = lambda_handler(event, None)
        
        # Should handle gracefully - not detected as CloudWatch alarm
        assert result == event
        assert 'enriched_context' not in result
    
    def test_generic_service_no_enrichment(self):
        """Test that generic services get no enrichment"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        # Generic alarm that doesn't match Step Functions or Lambda patterns
        generic_finding_data = get_generic_alarm_finding()
        event = create_asff_test_data(generic_finding_data)
        
        result = lambda_handler(event, None)
        
        # Should pass through unchanged due to enrichment_enabled = False
        assert result == event
        assert 'enriched_context' not in result


class TestStepFunctionsEnrichmentWithAWSMocking:
    """Test Step Functions enrichment with real AWS API mocking"""
    
    @pytest.fixture
    def aws_credentials(self):
        """Mocked AWS Credentials for moto."""
        os.environ["AWS_ACCESS_KEY_ID"] = "testing"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
        os.environ["AWS_SECURITY_TOKEN"] = "testing"
        os.environ["AWS_SESSION_TOKEN"] = "testing"
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    
    def test_stepfunctions_execution_enrichment_success(self, aws_credentials):
        """Test successful Step Functions execution enrichment with AWS API mocking"""
        
        # Create SOAR scratchpad with Step Functions alarm
        stepfunctions_alarm_finding = get_stepfunctions_alarm_finding_standard()
        scratchpad_data = create_asff_test_data(stepfunctions_alarm_finding)
        
        # Get mock data from fixtures
        mock_stepfunctions_execution_details = get_mock_stepfunctions_execution_details()
        mock_stepfunctions_execution_history = get_mock_stepfunctions_execution_history()
        mock_cloudwatch_logs_entries = get_mock_cloudwatch_logs_entries()
        
        with patch('functions.findings.enrich_cloudwatch_context.app.get_client') as mock_get_client:
            # Setup mock Step Functions client 
            mock_stepfunctions = MagicMock()
            mock_cloudwatch_logs = MagicMock()
            
            # Configure get_client to return appropriate clients
            def client_side_effect(service_name, account_id, region=None):
                if service_name == 'stepfunctions':
                    return mock_stepfunctions
                elif service_name == 'logs':
                    return mock_cloudwatch_logs
                else:
                    return MagicMock()
            
            mock_get_client.side_effect = client_side_effect
            
            # Setup mock responses - use timestamp that matches test data (2024-01-01T12:00:00.000Z)
            test_execution_time = datetime.fromisoformat('2024-01-01T11:59:45.000Z'.replace('Z', '+00:00'))
            mock_stepfunctions.list_executions.return_value = {
                'executions': [
                    {
                        'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:test-execution-123',
                        'stateMachineArn': 'arn:aws:states:us-east-1:123456789012:stateMachine:SOARASFFProcessor',
                        'name': 'test-execution-123',
                        'status': 'FAILED',
                        'startDate': test_execution_time,  # Within 30-second window of alarm
                        'stopDate': test_execution_time
                    }
                ]
            }
            mock_stepfunctions.describe_execution.return_value = mock_stepfunctions_execution_details
            mock_stepfunctions.get_execution_history.return_value = mock_stepfunctions_execution_history
            mock_cloudwatch_logs.filter_log_events.return_value = mock_cloudwatch_logs_entries
            
            # Execute enrichment
            from functions.findings.enrich_cloudwatch_context.app import lambda_handler
            result = lambda_handler(scratchpad_data, None)
            
            # Verify enrichment occurred
            assert 'enriched_context' in result
            enriched = result['enriched_context']
            
            # Verify basic enrichment structure
            assert enriched['service_type'] == 'stepfunctions'
            assert enriched['state_machine_name'] == 'SOARASFFProcessor'
            assert 'enrichment_timestamp' in enriched
            
            # Verify Step Functions specific enrichment
            assert 'failed_executions' in enriched
            assert len(enriched['failed_executions']) > 0
            
            # Verify execution details were captured
            execution = enriched['failed_executions'][0]
            assert 'execution_arn' in execution
            assert 'failure_details' in execution
            assert 'logs_summary' in execution
            
            # Verify API calls were made correctly
            mock_get_client.assert_any_call('stepfunctions', '123456789012', 'us-east-1')
            mock_stepfunctions.describe_execution.assert_called()
            mock_stepfunctions.get_execution_history.assert_called()
    
    def test_stepfunctions_enrichment_api_failure_graceful_degradation(self, aws_credentials):
        """Test graceful degradation when Step Functions API fails"""
        
        stepfunctions_alarm_finding = get_stepfunctions_alarm_finding_standard()
        scratchpad_data = create_asff_test_data(stepfunctions_alarm_finding)
        
        with patch('functions.findings.enrich_cloudwatch_context.app.get_client') as mock_get_client:
            mock_stepfunctions = MagicMock()
            mock_get_client.return_value = mock_stepfunctions
            
            # Simulate API failure
            mock_stepfunctions.describe_execution.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': 'ExecutionDoesNotExist', 'Message': 'Execution does not exist'}},
                'DescribeExecution'
            )
            
            # Execute enrichment
            from functions.findings.enrich_cloudwatch_context.app import lambda_handler
            result = lambda_handler(scratchpad_data, None)
            
            # Should still provide basic enrichment without AWS-specific details
            assert 'enriched_context' in result
            enriched = result['enriched_context']
            assert enriched['service_type'] == 'stepfunctions'
            assert enriched['state_machine_name'] == 'SOARASFFProcessor'
            
            # Failed executions should be empty due to API failure
            assert enriched['failed_executions'] == []


class TestLambdaFunctionEnrichmentWithAWSMocking:
    """Test Lambda function enrichment with AWS API mocking"""
    
    def test_lambda_function_enrichment_structure(self):
        """Test that Lambda function alarms get proper enrichment structure"""
        
        lambda_alarm_finding = get_lambda_alarm_finding_standard()
        scratchpad_data = create_asff_test_data(lambda_alarm_finding)
        
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        result = lambda_handler(scratchpad_data, None)
        
        # Verify enrichment occurred
        assert 'enriched_context' in result
        enriched = result['enriched_context']
        
        # Verify Lambda-specific enrichment structure
        assert enriched['service_type'] == 'lambda'
        assert enriched['function_name'] == 'ProcessFindings'
        assert 'enrichment_timestamp' in enriched


class TestStepFunctionsRealIntegration:
    """Test real Step Functions execution discovery and filtering"""
    
    def test_list_executions_in_evaluation_window(self):
        """Test listing Step Functions executions within alarm evaluation window"""
        from functions.findings.enrich_cloudwatch_context.app import list_executions_in_window
        
        # Setup
        state_machine_arn = "arn:aws:states:us-east-1:123456789012:stateMachine:SOARASFFProcessor"
        evaluation_window = {
            'start_time': '2024-01-01T12:00:00.000Z',
            'end_time': '2024-01-01T12:30:00.000Z'
        }
        
        with patch('functions.findings.enrich_cloudwatch_context.app.get_client') as mock_get_client:
            mock_stepfunctions = MagicMock()
            mock_get_client.return_value = mock_stepfunctions
            
            # Mock list_executions response
            mock_stepfunctions.list_executions.return_value = {
                'executions': [
                    {
                        'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:exec1',
                        'stateMachineArn': state_machine_arn,
                        'name': 'exec1',
                        'status': 'FAILED',
                        'startDate': datetime(2024, 1, 1, 12, 10, 0, tzinfo=timezone.utc),
                        'stopDate': datetime(2024, 1, 1, 12, 15, 0, tzinfo=timezone.utc)
                    },
                    {
                        'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:exec2',
                        'stateMachineArn': state_machine_arn,
                        'name': 'exec2',
                        'status': 'SUCCEEDED',
                        'startDate': datetime(2024, 1, 1, 12, 20, 0, tzinfo=timezone.utc),
                        'stopDate': datetime(2024, 1, 1, 12, 25, 0, tzinfo=timezone.utc)
                    }
                ]
            }
            
            # Execute
            executions = list_executions_in_window(state_machine_arn, evaluation_window, '123456789012', 'us-east-1')
            
            # Verify - only failed executions within window should be returned
            assert len(executions) == 1  # Only exec1 is FAILED
            assert executions[0]['name'] == 'exec1'
            assert executions[0]['status'] == 'FAILED'
            
            # Verify correct API call
            mock_stepfunctions.list_executions.assert_called_once_with(
                stateMachineArn=state_machine_arn,
                statusFilter='FAILED',
                maxResults=100
            )
    
    def test_filter_failed_executions_in_window(self):
        """Test filtering executions to only failed ones within time window"""
        from functions.findings.enrich_cloudwatch_context.app import filter_failed_executions_in_window
        
        # Setup execution list with mixed statuses and times
        executions = [
            {
                'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:failed1',
                'status': 'FAILED',
                'startDate': datetime(2024, 1, 1, 12, 10, 0, tzinfo=timezone.utc),
                'stopDate': datetime(2024, 1, 1, 12, 15, 0, tzinfo=timezone.utc)
            },
            {
                'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:succeeded1',
                'status': 'SUCCEEDED',
                'startDate': datetime(2024, 1, 1, 12, 10, 0, tzinfo=timezone.utc),
                'stopDate': datetime(2024, 1, 1, 12, 15, 0, tzinfo=timezone.utc)
            },
            {
                'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:old_failed',
                'status': 'FAILED',
                'startDate': datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc),  # Outside window
                'stopDate': datetime(2024, 1, 1, 11, 5, 0, tzinfo=timezone.utc)
            }
        ]
        
        evaluation_window = {
            'start_time': '2024-01-01T12:00:00.000Z',
            'end_time': '2024-01-01T12:30:00.000Z'
        }
        
        # Execute
        failed_executions = filter_failed_executions_in_window(executions, evaluation_window)
        
        # Verify - only failed execution within window
        assert len(failed_executions) == 1
        assert failed_executions[0]['executionArn'].endswith(':failed1')
        assert failed_executions[0]['status'] == 'FAILED'


class TestLocalDynamoDBAccess:
    """Test that DynamoDB access uses local client, not cross-account roles"""
    
    @patch('functions.findings.enrich_cloudwatch_context.app.dynamodb_client')
    def test_local_dynamodb_client_used_not_cross_account(self, mock_dynamodb_client):
        """Test that local DynamoDB client is used instead of cross-account role assumption"""
        from functions.findings.enrich_cloudwatch_context.app import query_dynamodb_incidents
        
        # Mock successful DynamoDB response
        mock_dynamodb_client.query.return_value = {
            'Items': [
                {
                    'incident_id': {'S': 'test-incident'},
                    'alarm_type': {'S': 'test-alarm'},
                    'timestamp': {'N': '1704110400'},
                    'resolution_time_minutes': {'N': '10'},
                    'auto_resolved': {'BOOL': True}
                }
            ]
        }
        
        # Execute function
        result = query_dynamodb_incidents('test-alarm', 30)
        
        # Verify local DynamoDB client was used
        mock_dynamodb_client.query.assert_called_once()
        
        # Verify no get_client calls (which would indicate cross-account access)
        with patch('functions.findings.enrich_cloudwatch_context.app.get_client') as mock_get_client:
            query_dynamodb_incidents('test-alarm', 30)
            mock_get_client.assert_not_called()
        
        # Verify result structure
        assert len(result) == 1
        assert result[0]['incident_id'] == 'test-incident'
    
    @patch('functions.findings.enrich_cloudwatch_context.app.dynamodb_client')
    def test_dynamodb_query_uses_environment_table_name(self, mock_dynamodb_client):
        """Test that DynamoDB queries use the environment variable for table name"""
        from functions.findings.enrich_cloudwatch_context.app import query_dynamodb_incidents
        
        mock_dynamodb_client.query.return_value = {'Items': []}
        
        with patch.dict('os.environ', {'INCIDENTS_TABLE_NAME': 'custom-incidents-table'}):
            query_dynamodb_incidents('test-alarm', 30)
            
            # Verify the correct table name was used
            call_args = mock_dynamodb_client.query.call_args
            assert call_args[1]['TableName'] == 'custom-incidents-table'


class TestDynamoDBPatternAnalysis:
    """Test DynamoDB historical incident pattern analysis"""
    
    @patch('functions.findings.enrich_cloudwatch_context.app.dynamodb_client')
    def test_query_dynamodb_incidents_by_alarm_type(self, mock_dynamodb_client):
        """Test querying DynamoDB incidents table for similar alarm patterns"""
        from functions.findings.enrich_cloudwatch_context.app import query_dynamodb_incidents
        
        # Setup
        alarm_type = "INFRA-SOAR-ASFF-Processor-SM-Failure"
        retention_days = 30
        
        # Mock DynamoDB query response using module-level client
        mock_dynamodb_client.query.return_value = {
            'Items': [
                {
                    'incident_id': {'S': 'incident-001'},
                    'alarm_type': {'S': 'INFRA-SOAR-ASFF-Processor-SM-Failure'},
                    'timestamp': {'N': '1704110400'},  # 2024-01-01T12:00:00Z
                    'severity': {'S': 'HIGH'},
                    'resolution_time_minutes': {'N': '15'},
                    'auto_resolved': {'BOOL': True}
                },
                {
                    'incident_id': {'S': 'incident-002'},
                    'alarm_type': {'S': 'INFRA-SOAR-ASFF-Processor-SM-Failure'},
                    'timestamp': {'N': '1704114000'},  # 2024-01-01T13:00:00Z
                    'severity': {'S': 'HIGH'},
                    'resolution_time_minutes': {'N': '8'},
                    'auto_resolved': {'BOOL': True}
                }
            ]
        }
        
        # Execute
        incidents = query_dynamodb_incidents(alarm_type, retention_days)
        
        # Verify
        assert len(incidents) == 2
        assert incidents[0]['incident_id'] == 'incident-001'
        assert incidents[1]['incident_id'] == 'incident-002'
        
        # Verify DynamoDB query call
        mock_dynamodb_client.query.assert_called_once()
        call_args = mock_dynamodb_client.query.call_args
        assert 'TableName' in call_args.kwargs
        assert 'IndexName' in call_args.kwargs  # Should use GSI for alarm_type queries
        assert call_args.kwargs['IndexName'] == 'alarm-type-timestamp-index'
    
    def test_classify_incident_pattern_frequent_occurrences(self):
        """Test incident pattern classification for frequent recurring issues"""
        from functions.findings.enrich_cloudwatch_context.app import classify_incident_pattern
        
        # Setup - frequent recurring incidents (7+ for frequent classification)
        incidents = [
            {'incident_id': 'incident-001', 'timestamp': 1704110400, 'resolution_time_minutes': 15, 'auto_resolved': True},
            {'incident_id': 'incident-002', 'timestamp': 1704114000, 'resolution_time_minutes': 8, 'auto_resolved': True},
            {'incident_id': 'incident-003', 'timestamp': 1704117600, 'resolution_time_minutes': 12, 'auto_resolved': True},
            {'incident_id': 'incident-004', 'timestamp': 1704121200, 'resolution_time_minutes': 10, 'auto_resolved': True},
            {'incident_id': 'incident-005', 'timestamp': 1704124800, 'resolution_time_minutes': 14, 'auto_resolved': True},
            {'incident_id': 'incident-006', 'timestamp': 1704128400, 'resolution_time_minutes': 9, 'auto_resolved': True},
            {'incident_id': 'incident-007', 'timestamp': 1704132000, 'resolution_time_minutes': 11, 'auto_resolved': True}
        ]
        
        # Execute
        pattern = classify_incident_pattern(incidents)
        
        # Verify
        assert pattern['pattern_type'] == 'frequent_recurring'
        assert pattern['frequency_score'] == 7  # High frequency
        assert pattern['auto_resolution_rate'] == 1.0  # 100% auto-resolved
        assert pattern['avg_resolution_time_minutes'] == 11.29  # Average of all resolution times
        assert pattern['trend'] == 'stable'  # Consistent resolution times
        assert pattern['recommendation'] == 'monitor_for_root_cause'
    
    def test_classify_incident_pattern_isolated_occurrence(self):
        """Test incident pattern classification for isolated/rare issues"""
        from functions.findings.enrich_cloudwatch_context.app import classify_incident_pattern
        
        # Setup - single isolated incident
        incidents = [
            {
                'incident_id': 'incident-001',
                'timestamp': 1704110400,
                'resolution_time_minutes': 45,
                'auto_resolved': False
            }
        ]
        
        # Execute
        pattern = classify_incident_pattern(incidents)
        
        # Verify
        assert pattern['pattern_type'] == 'isolated_occurrence'
        assert pattern['frequency_score'] == 1  # Low frequency
        assert pattern['auto_resolution_rate'] == 0.0  # 0% auto-resolved
        assert pattern['avg_resolution_time_minutes'] == 45
        assert pattern['trend'] == 'unknown'  # Not enough data for trend
        assert pattern['recommendation'] == 'investigate_thoroughly'
    
    def test_analyze_incident_patterns_integration(self):
        """Test full incident pattern analysis integration"""
        from functions.findings.enrich_cloudwatch_context.app import analyze_incident_patterns
        
        # Setup
        finding = {
            'Id': 'test-finding-id',
            'Title': 'INFRA-SOAR-ASFF-Processor-SM-Failure-HIGH',
            'AwsAccountId': '123456789012',
            'Region': 'us-east-1'
        }
        
        with patch('functions.findings.enrich_cloudwatch_context.app.query_dynamodb_incidents') as mock_query:
            with patch('functions.findings.enrich_cloudwatch_context.app.classify_incident_pattern') as mock_classify:
                # Mock responses
                mock_query.return_value = [
                    {'incident_id': 'incident-001', 'timestamp': 1704110400},
                    {'incident_id': 'incident-002', 'timestamp': 1704114000}
                ]
                mock_classify.return_value = {
                    'pattern_type': 'frequent_recurring',
                    'frequency_score': 8,
                    'recommendation': 'monitor_for_root_cause'
                }
                
                # Execute
                analysis = analyze_incident_patterns(finding)
                
                # Verify
                assert 'historical_incidents' in analysis
                assert 'pattern_classification' in analysis
                assert analysis['pattern_classification']['pattern_type'] == 'frequent_recurring'
                assert len(analysis['historical_incidents']) == 2
                
                # Verify function calls
                mock_query.assert_called_once_with('INFRA-SOAR-ASFF-Processor-SM-Failure', 365)  # Default retention (uses INCIDENT_EXPIRATION_DAYS)
                mock_classify.assert_called_once()


class TestCompleteIntegration:
    """Test complete end-to-end enrichment integration"""
    
    @patch('functions.findings.enrich_cloudwatch_context.app.dynamodb_client')
    def test_full_enrichment_with_pattern_analysis(self, mock_dynamodb_client):
        """Test complete enrichment with both AWS execution data and pattern analysis"""
        from functions.findings.enrich_cloudwatch_context.app import lambda_handler
        
        # Setup
        stepfunctions_alarm_finding = get_stepfunctions_alarm_finding_standard()
        scratchpad_data = create_asff_test_data(stepfunctions_alarm_finding)
        
        with patch('functions.findings.enrich_cloudwatch_context.app.get_client') as mock_get_client:
            # Mock AWS clients
            mock_stepfunctions = MagicMock()
            
            def client_side_effect(service_name, account_id, region=None):
                if service_name == 'stepfunctions':
                    return mock_stepfunctions
                else:
                    return MagicMock()
            
            mock_get_client.side_effect = client_side_effect
            
            # Mock Step Functions responses
            mock_stepfunctions.list_executions.return_value = {
                'executions': [
                    {
                        'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:test-exec',
                        'status': 'FAILED',
                        'startDate': datetime.now(timezone.utc),
                        'stopDate': datetime.now(timezone.utc)
                    }
                ]
            }
            mock_stepfunctions.describe_execution.return_value = {
                'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:SOARASFFProcessor:test-exec',
                'status': 'FAILED'
            }
            mock_stepfunctions.get_execution_history.return_value = {'events': []}
            
            # Mock DynamoDB pattern analysis response using module-level client
            mock_dynamodb_client.query.return_value = {
                'Items': [
                    {
                        'incident_id': {'S': 'incident-001'},
                        'alarm_type': {'S': 'INFRA-SOAR-ASFF-Processor-SM-Failure'},
                        'timestamp': {'N': '1704110400'},
                        'resolution_time_minutes': {'N': '15'},
                        'auto_resolved': {'BOOL': True}
                    },
                    {
                        'incident_id': {'S': 'incident-002'},
                        'alarm_type': {'S': 'INFRA-SOAR-ASFF-Processor-SM-Failure'},
                        'timestamp': {'N': '1704114000'},
                        'resolution_time_minutes': {'N': '12'},
                        'auto_resolved': {'BOOL': True}
                    }
                ]
            }
            
            # Execute
            result = lambda_handler(scratchpad_data, None)
            
            # Verify complete enrichment
            assert 'enriched_context' in result
            enriched = result['enriched_context']
            
            # Verify service-specific enrichment
            assert enriched['service_type'] == 'stepfunctions'
            assert enriched['state_machine_name'] == 'SOARASFFProcessor'
            assert 'failed_executions' in enriched
            
            # Verify pattern analysis integration
            assert 'pattern_analysis' in enriched
            pattern_analysis = enriched['pattern_analysis']
            assert 'historical_incidents' in pattern_analysis
            assert 'pattern_classification' in pattern_analysis
            assert len(pattern_analysis['historical_incidents']) == 2
            assert pattern_analysis['pattern_classification']['pattern_type'] == 'infrequent_recurring'  # 2 incidents
            
            # Verify AWS API calls were made
            mock_stepfunctions.list_executions.assert_called()
            mock_dynamodb_client.query.assert_called()


class TestTimestampHandling:
    """Test timestamp extraction and window calculation functionality"""
    
    def test_get_incident_timestamp_prefers_first_observed_at(self):
        """Test that FirstObservedAt is preferred when available"""
        from functions.findings.enrich_cloudwatch_context.app import get_incident_timestamp
        
        finding = {
            'CreatedAt': '2024-01-01T12:05:00.000Z',
            'FirstObservedAt': '2024-01-01T12:00:00.000Z', 
            'LastObservedAt': '2024-01-01T12:01:00.000Z'
        }
        
        timestamp = get_incident_timestamp(finding)
        assert timestamp == '2024-01-01T12:00:00.000Z'  # Should use FirstObservedAt
    
    def test_get_incident_timestamp_fallback_to_last_observed_at(self):
        """Test fallback to LastObservedAt when FirstObservedAt missing"""
        from functions.findings.enrich_cloudwatch_context.app import get_incident_timestamp
        
        finding = {
            'CreatedAt': '2024-01-01T12:05:00.000Z',
            'LastObservedAt': '2024-01-01T12:01:00.000Z'
            # No FirstObservedAt
        }
        
        timestamp = get_incident_timestamp(finding)
        assert timestamp == '2024-01-01T12:01:00.000Z'  # Should use LastObservedAt
    
    def test_get_incident_timestamp_fallback_to_created_at(self):
        """Test final fallback to CreatedAt when observation times missing"""
        from functions.findings.enrich_cloudwatch_context.app import get_incident_timestamp
        
        finding = {
            'CreatedAt': '2024-01-01T12:05:00.000Z'
            # No FirstObservedAt or LastObservedAt
        }
        
        timestamp = get_incident_timestamp(finding)
        assert timestamp == '2024-01-01T12:05:00.000Z'  # Should use CreatedAt
    
    def test_get_incident_timestamp_handles_empty_finding(self):
        """Test graceful handling of finding with no timestamps"""
        from functions.findings.enrich_cloudwatch_context.app import get_incident_timestamp
        
        finding = {}  # No timestamp fields
        
        timestamp = get_incident_timestamp(finding)
        assert timestamp == ''  # Should return empty string


class TestConfigurationManagement:
    """Test that configuration is properly managed via environment variables"""
    
    def test_environment_variable_configuration(self):
        """Test that function respects environment variable configuration"""
        from functions.findings.enrich_cloudwatch_context.app import calculate_incident_time_window
        
        # Test with ASFF timestamp
        incident_time = '2024-01-01T12:00:00.000Z'
        window = calculate_incident_time_window(incident_time)
        
        # Should use incident time directly with small lookback window
        assert 'start_time' in window
        assert 'end_time' in window
        # End time should be the normalized version of the incident time
        expected_end_time = datetime.fromisoformat(incident_time.replace('Z', '+00:00')).isoformat()
        assert window['end_time'] == expected_end_time
    
    def test_region_extraction_from_finding(self):
        """Test that region is properly extracted from finding, not hardcoded"""
        from functions.findings.enrich_cloudwatch_context.app import enrich_stepfunctions_context
        
        # Test finding with specific region
        finding = {
            'AwsAccountId': '123456789012',
            'Region': 'eu-west-1',  # Different from default
            'Title': 'INFRA-SOAR-ASFF-Processor-SM-Failure-HIGH'
        }
        service_context = {
            'service_type': 'stepfunctions',
            'state_machine_name': 'SOARASFFProcessor',
            'enrichment_enabled': True
        }
        
        with patch('functions.findings.enrich_cloudwatch_context.app.get_client') as mock_get_client:
            mock_client = MagicMock()
            mock_get_client.return_value = mock_client
            
            # Mock API failure to avoid execution logic
            mock_client.describe_execution.side_effect = Exception("Test exception")
            
            # Call enrichment function
            enrich_stepfunctions_context(finding, service_context)
            
            # Verify get_client was called with the correct region from finding
            mock_get_client.assert_called_with('stepfunctions', '123456789012', 'eu-west-1')
    
    def test_error_when_region_missing(self):
        """Test that missing region raises ValueError"""
        from functions.findings.enrich_cloudwatch_context.app import enrich_stepfunctions_context
        
        # Test finding without region
        finding = {
            'AwsAccountId': '123456789012',
            'Id': 'test-finding-no-region',
            # No Region field
            'Title': 'INFRA-SOAR-ASFF-Processor-SM-Failure-HIGH'
        }
        service_context = {
            'service_type': 'stepfunctions',
            'state_machine_name': 'SOARASFFProcessor',
            'enrichment_enabled': True
        }
        
        # Should raise ValueError when region is missing
        with pytest.raises(ValueError) as exc_info:
            enrich_stepfunctions_context(finding, service_context)
        
        assert "Region not found in finding" in str(exc_info.value)
        assert "test-finding-no-region" in str(exc_info.value)
    
