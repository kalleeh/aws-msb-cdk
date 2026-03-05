"""
Integration tests for Security Hub.

Verifies that Security Hub is enabled and configured according to MSB requirements:
- Hub is enabled
- AWS Foundational Security Best Practices (FSBP) standard is enabled and active
- CIS AWS Foundations Benchmark v3.0.0 standard is enabled and active
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]

# Standard ARN fragments used to identify each standard
FSBP_ARN_FRAGMENT = "aws-foundational-security-best-practices"
CIS_V3_ARN_FRAGMENT = "cis-aws-foundations-benchmark/v/3.0.0"


def _get_enabled_standards(client):
    """Return a list of all enabled standard subscription dicts."""
    subscriptions = []
    paginator = client.get_paginator("get_enabled_standards")
    for page in paginator.paginate():
        subscriptions.extend(page.get("StandardsSubscriptions", []))
    return subscriptions


def test_security_hub_is_enabled(boto_session):
    client = boto_session.client("securityhub")
    try:
        hub = client.describe_hub()
        assert hub.get("HubArn"), "Security Hub HubArn is missing — Security Hub may not be enabled"
    except client.exceptions.InvalidAccessException as exc:
        pytest.fail(f"Security Hub is not enabled in this account/region: {exc}")


def test_security_hub_fsbp_standard_enabled(boto_session):
    client = boto_session.client("securityhub")
    subscriptions = _get_enabled_standards(client)

    fsbp_subs = [
        s for s in subscriptions
        if FSBP_ARN_FRAGMENT in s.get("StandardsArn", "")
    ]
    assert fsbp_subs, (
        f"AWS Foundational Security Best Practices standard is not enabled in Security Hub "
        f"(looked for ARN fragment '{FSBP_ARN_FRAGMENT}')"
    )

    status = fsbp_subs[0].get("StandardsStatus")
    assert status == "READY", (
        f"FSBP standard subscription status is '{status}', expected 'READY'"
    )


def test_security_hub_cis_v3_standard_enabled(boto_session):
    client = boto_session.client("securityhub")
    subscriptions = _get_enabled_standards(client)

    cis_subs = [
        s for s in subscriptions
        if CIS_V3_ARN_FRAGMENT in s.get("StandardsArn", "")
    ]
    assert cis_subs, (
        f"CIS AWS Foundations Benchmark v3.0.0 standard is not enabled in Security Hub "
        f"(looked for ARN fragment '{CIS_V3_ARN_FRAGMENT}')"
    )

    status = cis_subs[0].get("StandardsStatus")
    assert status == "READY", (
        f"CIS v3.0.0 standard subscription status is '{status}', expected 'READY'"
    )
