# Compliance Testing Framework

This document describes the testing framework used to validate compliance controls in the AWS MSB CDK implementation.

## Overview

The compliance testing framework validates that the CDK implementation correctly enforces each security control. It operates at two levels:

1. **Unit tests (CDK synthesis)**: Verify that CloudFormation templates are generated with the correct resources and properties. These run fast, require no AWS credentials, and form the primary regression barrier.
2. **Integration tests (post-deployment)**: Verify that live AWS services are actually configured as required after a real deployment. These require credentials and an already-deployed MSB environment.

Together the two layers cover:

- **Resource creation**: Required resources are synthesised and deployed
- **Resource configuration**: Resources have the correct properties
- **Resource relationships**: Resources are properly connected (encryption keys, log destinations, SNS topics)
- **Policy validation**: IAM policies have correct permissions
- **Runtime state**: Services are active and operating (GuardDuty enabled, Config recording, etc.)

---

## Unit Tests (CDK Synthesis)

### What they validate

Unit tests use the `aws-cdk-lib/assertions` `Template` class to assert on the synthesised CloudFormation template. They run entirely in-process — no AWS credentials or network access required.

The suite currently contains **76 tests** across the following files:

| File | What it covers |
|------|----------------|
| `tests/test_compliance.py` | Core compliance controls (IAM password policy, CloudTrail, KMS rotation, IAM.16 governance) and Control Tower managed mode |
| `tests/test_logging_stack.py` | CloudTrail trail, S3 log bucket, KMS encryption, CIS 3.x metric filters and CloudWatch alarms |
| `tests/test_app.py` | Full-stack synthesis smoke tests for all stacks |
| `tests/test_network_security_stack.py` | VPC default-SG remediation, flow logs, security group rules |
| `tests/test_vpc_stack.py` | VPC creation, subnet layout, VPC endpoints |
| `tests/test_vpc_endpoints.py` | Interface and gateway endpoint presence |
| `tests/test_sns_encryption.py` | SNS topic KMS encryption |
| `tests/test_notifications_regional_stack.py` | Regional notifications topic |
| `tests/test_waf_stack.py` | WAFv2 WebACL and managed rule groups |
| `tests/test_multi_region.py` | Multi-region deployment patterns |
| `tests/test_imports.py` | Package import sanity checks |

### Control Tower managed mode

`tests/test_compliance.py` contains a dedicated `TestControlTowerManagedMode` class that verifies correct behaviour when `control_tower_managed=True`:

- GuardDuty detector is **not** created (Control Tower manages it)
- Security Hub Hub resource is **not** created
- Macie session is **not** created
- AWS Config recorder is **not** created
- AWS Config delivery channel is **not** created
- CloudTrail trail is **not** created (CT provides the Organisation Trail)
- CloudWatch alarms **are still created** (MSB's unique-value contribution on top of CT)

A regression test confirms that the same resources **are** created in the default (non-CT) deployment.

### CDK Nag

All stacks are checked with `cdk_nag.AwsSolutionsChecks` during synthesis (applied in `app.py`). The project maintains **0 CDK Nag errors and 0 warnings** in both standalone mode and CT mode:

```bash
# Standalone
cdk synth --context notification_email=you@example.com

# Control Tower mode
cdk synth --context notification_email=you@example.com --context control_tower_managed=true
```

### Example unit test

```python
def test_cloudtrail_enabled_and_configured(self):
    app = cdk.App()
    stack = LoggingStack(app, "TestLoggingStack")
    template = Template.from_stack(stack)

    template.has_resource_properties("AWS::CloudTrail::Trail", {
        "IsLogging": True,
        "IsMultiRegionTrail": True,
        "EnableLogFileValidation": True,
        "IncludeGlobalServiceEvents": True
    })
```

### Running unit tests

```bash
# Run all unit tests (excludes integration tests)
pytest tests/ --ignore=tests/integration -v

# Run a specific test file
pytest tests/test_compliance.py -v

# Run with coverage
pytest tests/ --ignore=tests/integration --cov=aws_msb_cdk
```

---

## Integration Tests (Post-Deployment)

Integration tests call live AWS APIs to confirm that deployed resources are in the expected state. They are skipped by default and only run when explicitly opted in.

### Covered services

| Test file | Controls validated |
|-----------|-------------------|
| `tests/integration/test_guardduty.py` | Detector exists, status=ENABLED, finding frequency=FIFTEEN_MINUTES, S3 protection, EBS malware protection |
| `tests/integration/test_security_hub.py` | Hub enabled, FSBP standard READY, CIS v3.0.0 standard READY |
| `tests/integration/test_cloudtrail.py` | Trail exists, is logging, log file validation enabled, multi-region enabled, CloudWatch Logs integration |
| `tests/integration/test_config.py` | Recorder exists, recorder is recording, delivery channel exists, at least one Config rule present |
| `tests/integration/test_iam.py` | Password policy (min length 16, uppercase, lowercase, numbers, symbols, reuse prevention 24), Access Analyzer ACTIVE |
| `tests/integration/test_kms.py` | All 4 MSB key aliases present (master-key, cloudtrail-key, s3-key, ebs-key), rotation enabled on all |
| `tests/integration/test_s3_security.py` | All 4 account-level S3 Block Public Access settings enabled |

### Running integration tests

Integration tests require live AWS credentials with read permissions to the deployed account and region:

```bash
MSB_INTEGRATION_TESTS=1 AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/ -v
```

The `MSB_INTEGRATION_TESTS=1` environment variable is required. Omitting it causes all integration tests to be skipped automatically, preventing false failures on CI runners or environments with limited IAM permissions.

---

## Test Organization

Tests are organised by compliance control category:

1. **IAM Controls**: Password policy, Access Analyzer, IAM.16 policy governance
2. **Logging Controls**: CloudTrail, CloudWatch metric filters and alarms, S3 log bucket
3. **Data Protection Controls**: KMS key rotation, S3 encryption, SNS encryption
4. **Network Security Controls**: VPC, security groups, flow logs, VPC endpoints
5. **Monitoring Controls**: CloudWatch alarms (CIS 4.1-4.16), GuardDuty, Security Hub
6. **Config Controls**: Configuration recorder, delivery channel, Config rules

---

## Recent Improvements

### 76 unit tests (was 43)

The test suite has grown significantly. Additions include:

- CIS 3.x CloudWatch metric filter and alarm tests (all 13 filters and alarms explicitly verified)
- Control Tower managed mode tests (`TestControlTowerManagedMode` — 8 tests)
- WAF stack tests
- Multi-region deployment tests
- VPC endpoint tests
- SNS encryption tests

### Integration test suite

A new `tests/integration/` directory provides post-deployment validation for the controls that previously required manual verification. See the [Untested Controls](untested_controls.md) document for the updated list of what remains untested.

### IAM.16 Testing

IAM.16 (IAM policies attached only to groups or roles) is tested by verifying that the monitoring Lambda, its EventBridge schedule rule, and its policy-attachment event rule are all synthesised correctly. The Lambda also has a CloudWatch Errors alarm so silent failures are caught.

### CloudTrail Log File Validation (CIS 3.3)

The `EnableLogFileValidation` property is explicitly asserted in unit tests and verified at runtime via the integration test suite.

---

## Future Enhancements

1. **Expanded integration coverage**: Add post-deployment checks for VPC flow logs and CloudWatch alarm notification delivery
2. **Policy analysis**: Enhance assertions for complex IAM policy documents
3. **Compliance reporting**: Generate machine-readable compliance reports from pytest output
