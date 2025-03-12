import pytest
import os

@pytest.fixture(autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for tests."""
    os.environ["CDK_DEFAULT_ACCOUNT"] = "123456789012"
    os.environ["CDK_DEFAULT_REGION"] = "us-east-1"
    # Use mock values that clearly indicate these are for testing
    os.environ["AWS_ACCESS_KEY_ID"] = "TESTING_FAKE_ACCESS_KEY_ID"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "TESTING_FAKE_SECRET_ACCESS_KEY"
    # Alternatively, could use:
    # from unittest.mock import patch
    # with patch.dict('os.environ', {
    #     'AWS_ACCESS_KEY_ID': 'TESTING_FAKE_ACCESS_KEY_ID',
    #     'AWS_SECRET_ACCESS_KEY': 'TESTING_FAKE_SECRET_ACCESS_KEY'
    # }):
    os.environ["AWS_SECURITY_TOKEN"] = "TESTING_FAKE_SECURITY_TOKEN"
    os.environ["AWS_SESSION_TOKEN"] = "TESTING_FAKE_SESSION_TOKEN"