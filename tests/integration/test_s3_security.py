"""
Integration tests for S3 account-level security controls.

Verifies that S3 account-level Block Public Access is fully enabled:
- BlockPublicAcls is True
- IgnorePublicAcls is True
- BlockPublicPolicy is True
- RestrictPublicBuckets is True
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]


def test_s3_block_public_acls_enabled(boto_session):
    client = boto_session.client("s3control")
    account_id = boto_session.client("sts").get_caller_identity()["Account"]
    response = client.get_public_access_block(AccountId=account_id)
    config = response.get("PublicAccessBlockConfiguration", {})

    assert config.get("BlockPublicAcls") is True, (
        "S3 account-level BlockPublicAcls is not enabled — "
        "account-level S3 Block Public Access is not fully configured"
    )


def test_s3_ignore_public_acls_enabled(boto_session):
    client = boto_session.client("s3control")
    account_id = boto_session.client("sts").get_caller_identity()["Account"]
    response = client.get_public_access_block(AccountId=account_id)
    config = response.get("PublicAccessBlockConfiguration", {})

    assert config.get("IgnorePublicAcls") is True, (
        "S3 account-level IgnorePublicAcls is not enabled — "
        "account-level S3 Block Public Access is not fully configured"
    )


def test_s3_block_public_policy_enabled(boto_session):
    client = boto_session.client("s3control")
    account_id = boto_session.client("sts").get_caller_identity()["Account"]
    response = client.get_public_access_block(AccountId=account_id)
    config = response.get("PublicAccessBlockConfiguration", {})

    assert config.get("BlockPublicPolicy") is True, (
        "S3 account-level BlockPublicPolicy is not enabled — "
        "account-level S3 Block Public Access is not fully configured"
    )


def test_s3_restrict_public_buckets_enabled(boto_session):
    client = boto_session.client("s3control")
    account_id = boto_session.client("sts").get_caller_identity()["Account"]
    response = client.get_public_access_block(AccountId=account_id)
    config = response.get("PublicAccessBlockConfiguration", {})

    assert config.get("RestrictPublicBuckets") is True, (
        "S3 account-level RestrictPublicBuckets is not enabled — "
        "account-level S3 Block Public Access is not fully configured"
    )


def test_s3_all_public_access_block_settings_enabled(boto_session):
    """Single consolidated test verifying all four S3 Block Public Access settings."""
    client = boto_session.client("s3control")
    account_id = boto_session.client("sts").get_caller_identity()["Account"]
    response = client.get_public_access_block(AccountId=account_id)
    config = response.get("PublicAccessBlockConfiguration", {})

    settings = {
        "BlockPublicAcls": config.get("BlockPublicAcls"),
        "IgnorePublicAcls": config.get("IgnorePublicAcls"),
        "BlockPublicPolicy": config.get("BlockPublicPolicy"),
        "RestrictPublicBuckets": config.get("RestrictPublicBuckets"),
    }

    disabled_settings = [k for k, v in settings.items() if v is not True]
    assert not disabled_settings, (
        f"The following S3 account-level Block Public Access settings are not enabled: "
        f"{disabled_settings}. Full config: {settings}"
    )
