import pytest
import sys
import os
from pathlib import Path

# Add the root directory of the project to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def pytest_configure():
    """Load environment variables from .env.test before running tests."""
    try:
        from dotenv import load_dotenv
        env_file = Path(__file__).parent.parent / '.env.test'
        if env_file.exists():
            load_dotenv(env_file)
            print(f"✅ Loaded environment from {env_file}")
        else:
            print(f"⚠️  Environment file not found: {env_file}")
            print("   Run: cp .env.test.example .env.test")
    except ImportError:
        print("⚠️  python-dotenv not installed.")
        print("   Install with: pip install python-dotenv")
        print("   Or manually load environment: source .env.test")


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

