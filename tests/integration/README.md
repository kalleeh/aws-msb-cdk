# MSB Integration Tests

These tests validate that the AWS Minimum Security Baseline (MSB) security controls are
actually active in a deployed AWS environment. They use `boto3` to make read-only API
calls against live AWS services — no CDK synthesis or deployment is required at test time.

## Prerequisites

- The MSB CDK stacks have been deployed to your AWS account
- Valid AWS credentials are configured (environment variables, AWS profile, or instance role)
- `AWS_DEFAULT_REGION` is set to the region where the stacks are deployed

## How to Run

```bash
# Run all integration tests against us-east-1
AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/ -v

# Run a specific test file
AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/test_guardduty.py -v

# Run with a named AWS profile
AWS_DEFAULT_REGION=us-east-1 AWS_PROFILE=my-profile pytest tests/integration/ -v
```

If `AWS_DEFAULT_REGION` is not set or valid credentials cannot be obtained, all tests
will be **skipped automatically** rather than failing.

## Test Coverage

| File | Controls Validated |
|------|--------------------|
| `test_guardduty.py` | GuardDuty detector enabled, finding frequency (15 min), S3 data events protection, EBS malware protection |
| `test_security_hub.py` | Security Hub enabled, FSBP standard active, CIS AWS Foundations v3.0.0 active |
| `test_cloudtrail.py` | Trail exists, MSB trail is logging, log file validation, multi-region, CloudWatch Logs integration |
| `test_config.py` | Configuration recorder exists and is recording, delivery channel exists, at least one Config rule present |
| `test_iam.py` | Password policy (min length 16, complexity requirements, reuse prevention 24), Access Analyzer type ACCOUNT active |
| `test_kms.py` | MSB KMS key aliases exist (master-key, cloudtrail-key, s3-key, ebs-key), automatic rotation enabled |
| `test_s3_security.py` | Account-level S3 Block Public Access — all four settings enabled |

## Notes

- All tests are **read-only** — they make no changes to your AWS environment.
- Tests use the `pytest.mark.integration` marker and the `requires_aws` skip condition.
- To run only integration tests from the root test suite: `pytest -m integration`
- To exclude integration tests from the unit test run: `pytest --ignore=tests/integration`
