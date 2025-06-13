import os
import pytest
from importlib import import_module


@pytest.fixture
def mock_env_variables(monkeypatch):
    # Mock environment variables with default values
    monkeypatch.setenv('DEV_ENVS', "DEV, DEVELOPMENT, DEVINT, DI")
    monkeypatch.setenv('STAGING_ENVS', "STAGING, STG, PREPROD, PP, TEST, QA, UAT, SIT, SYSTEMTEST, INTEGRATION")
    monkeypatch.setenv('PROD_ENVS', "PROD, PRD, PRODUCTION, LIVE")


@pytest.fixture
def mock_env_variables_custom(monkeypatch):
    # Mock environment variables with custom values
    monkeypatch.setenv('DEV_ENVS', "CUSTOM_DEV, CUSTOM_DEVELOPMENT")
    monkeypatch.setenv('STAGING_ENVS', "CUSTOM_STAGING, CUSTOM_PREPROD")
    monkeypatch.setenv('PROD_ENVS', "CUSTOM_PROD, CUSTOM_PRODUCTION")


@pytest.fixture
def mock_env_variables_empty(monkeypatch):
    # Mock environment variables with empty strings
    monkeypatch.setenv('DEV_ENVS', "")
    monkeypatch.setenv('STAGING_ENVS', "")
    monkeypatch.setenv('PROD_ENVS', "")


@pytest.fixture
def mock_input_data_dev():
    # Mock input data for a development environment
    return {
        'finding': {
            'Severity': {'Normalized': 30}
        },
        'account': {
            'Environment': 'dev'
        }
    }

@pytest.fixture
def mock_input_data_staging():
    # Mock input data for a staging environment
    return {
        'finding': {
            'Severity': {'Normalized': 50}
        },
        'account': {
            'Environment': 'staging'
        }
    }

@pytest.fixture
def mock_input_data_prod():
    # Mock input data for a production environment
    return {
        'finding': {
            'Severity': {'Normalized': 80}
        },
        'account': {
            'Environment': 'prod'
        }
    }

@pytest.fixture
def mock_input_data_unknown():
    # Mock input data for an unknown environment
    return {
        'finding': {
            'Severity': {'Normalized': 40}
        },
        'account': {
            'Environment': 'unknown'
        }
    }

@pytest.fixture
def mock_input_data_custom_dev():
    return {
        'finding': {
            'Severity': {'Normalized': 30}
        },
        'account': {
            'Environment': 'custom_dev'
        }
    }

@pytest.fixture
def mock_input_data_custom_staging():
    return {
        'finding': {
            'Severity': {'Normalized': 50}
        },
        'account': {
            'Environment': 'custom_staging'
        }
    }

@pytest.fixture
def mock_input_data_custom_prod():
    return {
        'finding': {
            'Severity': {'Normalized': 80}
        },
        'account': {
            'Environment': 'custom_prod'
        }
    }

@pytest.fixture
def mock_input_data_edge_severity():
    return {
        'finding': {
            'Severity': {'Normalized': 0}
        },
        'account': {
            'Environment': 'dev'
        }
    }

@pytest.fixture
def mock_input_data_max_severity():
    return {
        'finding': {
            'Severity': {'Normalized': 100}
        },
        'account': {
            'Environment': 'prod'
        }
    }


def test_lambda_handler_dev(mock_env_variables, mock_input_data_dev):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_dev, None)
    assert float(result) == pytest.approx(((30 + 60.0) / 100.0) ** 2.0 * 1.0)


def test_lambda_handler_staging(mock_env_variables, mock_input_data_staging):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_staging, None)
    assert float(result) == pytest.approx(((50 + 60.0) / 100.0) ** 2.0 * 2.0)


def test_lambda_handler_prod(mock_env_variables, mock_input_data_prod):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_prod, None)
    assert float(result) == pytest.approx(((80 + 60.0) / 100.0) ** 2.0 * 10.0)


def test_lambda_handler_unknown(mock_env_variables, mock_input_data_unknown):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_unknown, None)
    assert float(result) == pytest.approx(((40 + 60.0) / 100.0) ** 2.0 * 1.0)


def test_lambda_handler_custom_dev(mock_env_variables_custom, mock_input_data_custom_dev):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_custom_dev, None)
    assert float(result) == pytest.approx(((30 + 60.0) / 100.0) ** 2.0 * 1.0)


def test_lambda_handler_custom_staging(mock_env_variables_custom, mock_input_data_custom_staging):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_custom_staging, None)
    assert float(result) == pytest.approx(((50 + 60.0) / 100.0) ** 2.0 * 2.0)


def test_lambda_handler_custom_prod(mock_env_variables_custom, mock_input_data_custom_prod):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_custom_prod, None)
    assert float(result) == pytest.approx(((80 + 60.0) / 100.0) ** 2.0 * 10.0)


def test_lambda_handler_edge_severity(mock_env_variables, mock_input_data_edge_severity):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_edge_severity, None)
    assert float(result) == pytest.approx(((0 + 60.0) / 100.0) ** 2.0 * 1.0)


def test_lambda_handler_max_severity(mock_env_variables, mock_input_data_max_severity):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_max_severity, None)
    assert float(result) == pytest.approx(((100 + 60.0) / 100.0) ** 2.0 * 10.0)


def test_lambda_handler_empty_env_vars(mock_env_variables_empty, mock_input_data_dev):
    module = import_module('functions.findings.compute_penalty_score.app')
    lambda_handler = module.lambda_handler
    result = lambda_handler(mock_input_data_dev, None)
    assert float(result) == pytest.approx(((30 + 60.0) / 100.0) ** 2.0 * 1.0)


if __name__ == "__main__":
    pytest.main()
    