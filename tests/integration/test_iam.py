"""
Integration tests for IAM controls.

Verifies that IAM is configured according to MSB requirements:
- Password policy meets MSB requirements (min length 16, complexity, reuse prevention)
- IAM Access Analyzer exists with type ACCOUNT
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]

MSB_PASSWORD_MIN_LENGTH = 16
MSB_PASSWORD_REUSE_PREVENTION = 24


def test_iam_password_policy_minimum_length(boto_session):
    client = boto_session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        pytest.fail("No IAM account password policy is set — MSB requires a password policy")

    min_length = policy.get("MinimumPasswordLength", 0)
    assert min_length >= MSB_PASSWORD_MIN_LENGTH, (
        f"IAM password policy minimum length is {min_length}, "
        f"expected at least {MSB_PASSWORD_MIN_LENGTH}"
    )


def test_iam_password_policy_requires_uppercase(boto_session):
    client = boto_session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        pytest.fail("No IAM account password policy is set — MSB requires a password policy")

    assert policy.get("RequireUppercaseCharacters") is True, (
        "IAM password policy does not require uppercase characters"
    )


def test_iam_password_policy_requires_lowercase(boto_session):
    client = boto_session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        pytest.fail("No IAM account password policy is set — MSB requires a password policy")

    assert policy.get("RequireLowercaseCharacters") is True, (
        "IAM password policy does not require lowercase characters"
    )


def test_iam_password_policy_requires_numbers(boto_session):
    client = boto_session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        pytest.fail("No IAM account password policy is set — MSB requires a password policy")

    assert policy.get("RequireNumbers") is True, (
        "IAM password policy does not require numbers"
    )


def test_iam_password_policy_requires_symbols(boto_session):
    client = boto_session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        pytest.fail("No IAM account password policy is set — MSB requires a password policy")

    assert policy.get("RequireSymbols") is True, (
        "IAM password policy does not require symbols"
    )


def test_iam_password_policy_reuse_prevention(boto_session):
    client = boto_session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        pytest.fail("No IAM account password policy is set — MSB requires a password policy")

    reuse_prevention = policy.get("PasswordReusePrevention", 0)
    assert reuse_prevention >= MSB_PASSWORD_REUSE_PREVENTION, (
        f"IAM password reuse prevention is set to {reuse_prevention}, "
        f"expected at least {MSB_PASSWORD_REUSE_PREVENTION}"
    )


def test_iam_access_analyzer_exists(boto_session):
    client = boto_session.client("accessanalyzer")
    paginator = client.get_paginator("list_analyzers")
    analyzers = []
    for page in paginator.paginate():
        analyzers.extend(page.get("analyzers", []))

    account_analyzers = [a for a in analyzers if a.get("type") == "ACCOUNT"]
    assert account_analyzers, (
        "No IAM Access Analyzer of type ACCOUNT found — "
        "MSB requires an Access Analyzer to be deployed for the account"
    )


def test_iam_access_analyzer_is_active(boto_session):
    client = boto_session.client("accessanalyzer")
    paginator = client.get_paginator("list_analyzers")
    analyzers = []
    for page in paginator.paginate():
        analyzers.extend(page.get("analyzers", []))

    account_analyzers = [a for a in analyzers if a.get("type") == "ACCOUNT"]
    assert account_analyzers, (
        "No IAM Access Analyzer of type ACCOUNT found"
    )

    analyzer = account_analyzers[0]
    status = analyzer.get("status")
    assert status == "ACTIVE", (
        f"IAM Access Analyzer '{analyzer.get('name')}' status is '{status}', expected 'ACTIVE'"
    )
