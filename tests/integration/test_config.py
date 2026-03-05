"""
Integration tests for AWS Config.

Verifies that AWS Config is enabled and configured according to MSB requirements:
- Configuration recorder exists and is recording
- Delivery channel exists
- At least one Config rule is present
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]


def test_config_recorder_exists(boto_session):
    client = boto_session.client("config")
    recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
    assert recorders, "No AWS Config configuration recorder found — AWS Config is not configured"


def test_config_recorder_is_recording(boto_session):
    client = boto_session.client("config")
    recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
    assert recorders, "No AWS Config configuration recorder found — AWS Config is not configured"

    recorder_name = recorders[0]["name"]
    statuses = client.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    ).get("ConfigurationRecordersStatus", [])

    assert statuses, f"No status found for configuration recorder '{recorder_name}'"
    status = statuses[0]
    assert status.get("recording") is True, (
        f"AWS Config recorder '{recorder_name}' is not currently recording "
        f"(recording={status.get('recording')})"
    )


def test_config_delivery_channel_exists(boto_session):
    client = boto_session.client("config")
    channels = client.describe_delivery_channels().get("DeliveryChannels", [])
    assert channels, (
        "No AWS Config delivery channel found — Config cannot deliver snapshots or history"
    )


def test_config_at_least_one_rule_exists(boto_session):
    client = boto_session.client("config")
    paginator = client.get_paginator("describe_config_rules")
    rules = []
    for page in paginator.paginate():
        rules.extend(page.get("ConfigRules", []))

    assert rules, (
        "No AWS Config rules found — expected at least one Config rule to be deployed"
    )
