"""
Integration tests for CloudTrail.

Verifies that CloudTrail is configured according to MSB requirements:
- At least one trail exists
- The MSB trail (name contains 'msb') is logging
- Log file validation is enabled
- Multi-region is enabled
- CloudWatch Logs integration is configured
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]

MSB_TRAIL_NAME_FRAGMENT = "msb"


def _get_all_trails(client):
    """Return a list of all trail dicts from describe_trails."""
    response = client.describe_trails(includeShadowTrails=False)
    return response.get("trailList", [])


def _find_msb_trail(trails):
    """Return the first trail whose name contains the MSB fragment (case-insensitive)."""
    for trail in trails:
        if MSB_TRAIL_NAME_FRAGMENT.lower() in trail.get("Name", "").lower():
            return trail
    return None


def test_cloudtrail_at_least_one_trail_exists(boto_session):
    client = boto_session.client("cloudtrail")
    trails = _get_all_trails(client)
    assert trails, "No CloudTrail trails found — CloudTrail is not configured"


def test_cloudtrail_msb_trail_exists(boto_session):
    client = boto_session.client("cloudtrail")
    trails = _get_all_trails(client)
    msb_trail = _find_msb_trail(trails)
    assert msb_trail is not None, (
        f"No CloudTrail trail with name containing '{MSB_TRAIL_NAME_FRAGMENT}' was found. "
        f"Trails present: {[t.get('Name') for t in trails]}"
    )


def test_cloudtrail_msb_trail_is_logging(boto_session):
    client = boto_session.client("cloudtrail")
    trails = _get_all_trails(client)
    msb_trail = _find_msb_trail(trails)
    assert msb_trail is not None, (
        f"No CloudTrail trail with name containing '{MSB_TRAIL_NAME_FRAGMENT}' was found"
    )

    trail_name = msb_trail["Name"]
    status = client.get_trail_status(Name=trail_name)
    assert status.get("IsLogging") is True, (
        f"CloudTrail MSB trail '{trail_name}' is not currently logging"
    )


def test_cloudtrail_msb_trail_log_file_validation_enabled(boto_session):
    client = boto_session.client("cloudtrail")
    trails = _get_all_trails(client)
    msb_trail = _find_msb_trail(trails)
    assert msb_trail is not None, (
        f"No CloudTrail trail with name containing '{MSB_TRAIL_NAME_FRAGMENT}' was found"
    )

    enabled = msb_trail.get("LogFileValidationEnabled")
    assert enabled is True, (
        f"CloudTrail MSB trail '{msb_trail['Name']}' does not have log file validation enabled"
    )


def test_cloudtrail_msb_trail_is_multi_region(boto_session):
    client = boto_session.client("cloudtrail")
    trails = _get_all_trails(client)
    msb_trail = _find_msb_trail(trails)
    assert msb_trail is not None, (
        f"No CloudTrail trail with name containing '{MSB_TRAIL_NAME_FRAGMENT}' was found"
    )

    is_multi = msb_trail.get("IsMultiRegionTrail")
    assert is_multi is True, (
        f"CloudTrail MSB trail '{msb_trail['Name']}' is not a multi-region trail"
    )


def test_cloudtrail_msb_trail_cloudwatch_logs_configured(boto_session):
    client = boto_session.client("cloudtrail")
    trails = _get_all_trails(client)
    msb_trail = _find_msb_trail(trails)
    assert msb_trail is not None, (
        f"No CloudTrail trail with name containing '{MSB_TRAIL_NAME_FRAGMENT}' was found"
    )

    log_group_arn = msb_trail.get("CloudWatchLogsLogGroupArn")
    assert log_group_arn, (
        f"CloudTrail MSB trail '{msb_trail['Name']}' does not have CloudWatch Logs integration configured "
        f"(CloudWatchLogsLogGroupArn is missing)"
    )
