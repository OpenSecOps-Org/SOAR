# SOAR Development Guide

## Commands
- Build: `sam build --parallel --cached`
- Deploy: `./deploy` (add `--dry-run` for test run)
- Test: `pytest tests/`
- Single test: `pytest tests/path/to/test_file.py::test_function_name`
- Publish: `./publish [version]` (version optional, will read from CHANGELOG.md)
- Setup project: `./setup [repo-name]`

## Code Style
- **Imports**: Standard library first, then third-party, then local modules
- **Formatting**: 4-space indentation, snake_case for variables/functions
- **Types**: Type hints encouraged where they improve clarity
- **Error Handling**: Use try/except with specific exceptions
- **Logging**: Use print statements for AWS Lambda (visible in CloudWatch)
- **Naming**: Descriptive names that communicate intent
- **AWS Integration**: Follow least privilege principle for IAM roles
- **String Comparison**: Always use `==` not `is` for string comparisons
- **Environment Variables**: Use default values for environment variables

## Project Structure
- AWS Serverless Application Model (SAM) project with Lambda functions organized by domain
- Python 3.12 runtime for all Lambda functions
- State machines in statemachines/ folder (ASL YAML format)
- Function-specific requirements.txt in each Lambda function directory
- AI prompts stored in ai-prompts/ folder

## Testing
- Tests use pytest with moto for AWS mocking
- Fixtures defined in tests/conftest.py and individual test files
- Test naming: test_*_function_name.py in tests/ directory
- Mock environment variables in tests using monkeypatch