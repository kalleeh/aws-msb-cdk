import pytest
import boto3
import os


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as requiring live AWS credentials")


@pytest.fixture(scope="session")
def aws_region():
    return os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(scope="session")
def boto_session(aws_region):
    return boto3.Session(region_name=aws_region)


def is_integration_enabled():
    """
    Integration tests only run when explicitly opted in via MSB_INTEGRATION_TESTS=1.
    This prevents false failures when credentials exist but lack the required
    permissions (e.g. on a CI server or a Lightsail instance with a limited role).

    To run: MSB_INTEGRATION_TESTS=1 AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/ -v
    """
    return os.environ.get("MSB_INTEGRATION_TESTS", "").strip() == "1"


requires_aws = pytest.mark.skipif(
    not is_integration_enabled(),
    reason="Set MSB_INTEGRATION_TESTS=1 to run integration tests against a live AWS account"
)
