"""
Integration tests for KMS keys.

Verifies that KMS keys are configured according to MSB requirements:
- MSB KMS keys exist (aliases: msb/master-key, msb/cloudtrail-key, msb/s3-key, msb/ebs-key)
- All MSB keys have rotation enabled
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]

MSB_KEY_ALIASES = [
    "alias/msb/master-key",
    "alias/msb/cloudtrail-key",
    "alias/msb/s3-key",
    "alias/msb/ebs-key",
]


def _get_all_aliases(client):
    """Return a dict mapping alias name -> key id for all customer aliases."""
    aliases = {}
    paginator = client.get_paginator("list_aliases")
    for page in paginator.paginate():
        for alias in page.get("Aliases", []):
            name = alias.get("AliasName", "")
            target = alias.get("TargetKeyId")
            if name.startswith("alias/msb") and target:
                aliases[name] = target
    return aliases


def test_kms_msb_master_key_exists(boto_session):
    client = boto_session.client("kms")
    aliases = _get_all_aliases(client)
    alias = "alias/msb/master-key"
    assert alias in aliases, (
        f"KMS key alias '{alias}' not found — MSB master key has not been deployed"
    )


def test_kms_msb_cloudtrail_key_exists(boto_session):
    client = boto_session.client("kms")
    aliases = _get_all_aliases(client)
    alias = "alias/msb/cloudtrail-key"
    assert alias in aliases, (
        f"KMS key alias '{alias}' not found — MSB CloudTrail key has not been deployed"
    )


def test_kms_msb_s3_key_exists(boto_session):
    client = boto_session.client("kms")
    aliases = _get_all_aliases(client)
    alias = "alias/msb/s3-key"
    assert alias in aliases, (
        f"KMS key alias '{alias}' not found — MSB S3 key has not been deployed"
    )


def test_kms_msb_ebs_key_exists(boto_session):
    client = boto_session.client("kms")
    aliases = _get_all_aliases(client)
    alias = "alias/msb/ebs-key"
    assert alias in aliases, (
        f"KMS key alias '{alias}' not found — MSB EBS key has not been deployed"
    )


def test_kms_msb_keys_have_rotation_enabled(boto_session):
    client = boto_session.client("kms")
    aliases = _get_all_aliases(client)

    missing_aliases = [a for a in MSB_KEY_ALIASES if a not in aliases]
    if missing_aliases:
        pytest.skip(
            f"Skipping rotation check — the following MSB key aliases were not found: {missing_aliases}"
        )

    keys_without_rotation = []
    for alias_name, key_id in aliases.items():
        if alias_name not in MSB_KEY_ALIASES:
            continue
        try:
            rotation = client.get_key_rotation_status(KeyId=key_id)
            if not rotation.get("KeyRotationEnabled"):
                keys_without_rotation.append(alias_name)
        except client.exceptions.NotFoundException:
            keys_without_rotation.append(f"{alias_name} (key not found)")

    assert not keys_without_rotation, (
        f"The following MSB KMS keys do not have automatic key rotation enabled: "
        f"{keys_without_rotation}"
    )
