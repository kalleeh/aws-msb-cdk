"""
Integration tests for GuardDuty.

Verifies that GuardDuty is enabled and configured according to MSB requirements:
- Detector exists and is ENABLED
- Finding publishing frequency is FIFTEEN_MINUTES
- Key protection features are enabled (S3_DATA_EVENTS, EBS_MALWARE_PROTECTION)
"""
import pytest
from tests.integration.conftest import requires_aws

pytestmark = [pytest.mark.integration, requires_aws]


def test_guardduty_detector_exists(boto_session):
    client = boto_session.client("guardduty")
    detectors = client.list_detectors()["DetectorIds"]
    assert detectors, "No GuardDuty detectors found — GuardDuty is not enabled"


def test_guardduty_detector_is_enabled(boto_session):
    client = boto_session.client("guardduty")
    detectors = client.list_detectors()["DetectorIds"]
    assert detectors, "No GuardDuty detectors found — GuardDuty is not enabled"

    detector = client.get_detector(DetectorId=detectors[0])
    assert detector["Status"] == "ENABLED", (
        f"GuardDuty detector status is {detector['Status']}, expected ENABLED"
    )


def test_guardduty_finding_publishing_frequency(boto_session):
    client = boto_session.client("guardduty")
    detectors = client.list_detectors()["DetectorIds"]
    assert detectors, "No GuardDuty detectors found — GuardDuty is not enabled"

    detector = client.get_detector(DetectorId=detectors[0])
    freq = detector.get("FindingPublishingFrequency")
    assert freq == "FIFTEEN_MINUTES", (
        f"GuardDuty finding publishing frequency is '{freq}', expected 'FIFTEEN_MINUTES'"
    )


def test_guardduty_s3_protection_enabled(boto_session):
    client = boto_session.client("guardduty")
    detectors = client.list_detectors()["DetectorIds"]
    assert detectors, "No GuardDuty detectors found — GuardDuty is not enabled"

    detector_id = detectors[0]
    detector = client.get_detector(DetectorId=detector_id)

    data_sources = detector.get("DataSources", {})
    s3_logs = data_sources.get("S3Logs", {})
    s3_status = s3_logs.get("Status")
    assert s3_status == "ENABLED", (
        f"GuardDuty S3_DATA_EVENTS protection status is '{s3_status}', expected 'ENABLED'"
    )


def test_guardduty_ebs_malware_protection_enabled(boto_session):
    client = boto_session.client("guardduty")
    detectors = client.list_detectors()["DetectorIds"]
    assert detectors, "No GuardDuty detectors found — GuardDuty is not enabled"

    detector_id = detectors[0]
    detector = client.get_detector(DetectorId=detector_id)

    features = detector.get("Features", [])
    ebs_feature = next(
        (f for f in features if f.get("Name") == "EBS_MALWARE_PROTECTION"),
        None
    )
    assert ebs_feature is not None, (
        "EBS_MALWARE_PROTECTION feature not found in GuardDuty detector features"
    )
    assert ebs_feature.get("Status") == "ENABLED", (
        f"GuardDuty EBS_MALWARE_PROTECTION status is '{ebs_feature.get('Status')}', expected 'ENABLED'"
    )
