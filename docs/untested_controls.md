# Untested Controls and Residual Risk

This document explains why certain controls in the compliance matrix are not covered by automated tests, categorizing them by reason for exclusion.

Controls that were previously listed here but are now covered by the automated test suite have been removed from the tables below. See [Compliance Testing](compliance_testing.md) for details on what is tested.

## Controls Now Covered by Automated Tests

The following controls were previously untested. They are now validated by either unit tests (CDK synthesis) or post-deployment integration tests:

| Control ID | Description | Test Type | Test Location |
|------------|-------------|-----------|---------------|
| GuardDuty.1 | GuardDuty detector enabled | Integration | `tests/integration/test_guardduty.py` |
| SecurityHub.1 | Security Hub enabled with FSBP and CIS v3.0.0 standards | Integration | `tests/integration/test_security_hub.py` |
| CloudTrail.1/CIS 3.1-3.3 | Trail logging with multi-region and log file validation | Integration | `tests/integration/test_cloudtrail.py` |
| Config.1 | Config recorder running and delivery channel present | Integration | `tests/integration/test_config.py` |
| IAM.9/CIS 1.8-1.12 | IAM password policy — all parameters | Integration | `tests/integration/test_iam.py` |
| KMS.4/CIS 3.7 | KMS automatic key rotation on all 4 MSB keys | Integration | `tests/integration/test_kms.py` |
| S3.1 | S3 account-level Block Public Access — all 4 settings | Integration | `tests/integration/test_s3_security.py` |
| CIS 4.1-4.16 | CloudWatch metric filters and alarms | Unit | `tests/test_logging_stack.py`, `tests/test_compliance.py` |

---

## 1. Runtime-Dependent Controls

These controls can only be fully verified at runtime after deployment, and automated integration tests do not yet cover them:

| Control ID | Description | Framework Reference | Reason |
|------------|-------------|---------------------|--------|
| IAM.8 | IAM Access Analyzer findings | FSBP, CIS 1.20, IR.6 | Finding generation and alerting requires runtime events; the Analyzer's existence and ACTIVE status are tested, but actual finding detection requires real IAM configuration drift |

## 2. Documented Residual Risk Controls

These controls are explicitly documented as residual risk in the compliance matrix:

| Control ID | Description | Framework Reference | Reference Document |
|------------|-------------|---------------------|-------------------|
| IAM.4 | Hardware MFA for root account | FSBP | [Residual Risk](residual_risk.md#hardware-mfa) |
| CIS 1.13 | MFA for root user | CIS 3.0.0 | [Residual Risk](residual_risk.md#root-mfa) |
| CIS 1.4 | No root access key | CIS 3.0.0 | [Residual Risk](residual_risk.md#root-access-key) |
| SSB.IAM.8 | Privileged access management | AWS SSB | [Residual Risk](residual_risk.md#privileged-access) |
| SSB.DAT.9 | Data classification | AWS SSB | [Residual Risk](residual_risk.md#data-classification) |
| SSB.DAT.10 | DLP controls | AWS SSB | [Residual Risk](residual_risk.md#dlp-controls) |
| SSB.IR.7 | Incident response playbooks | AWS SSB | [Residual Risk](residual_risk.md#incident-response) |
| SSB.IR.9 | Incident response exercises | AWS SSB | [Residual Risk](residual_risk.md#incident-response) |
| SSB.NET.10 | WAF for web applications | AWS SSB | [Residual Risk](residual_risk.md#waf) |

## 3. Implementation Gaps

These controls are partially implemented but have gaps that prevent complete testing:

| Control ID | Description | Framework Reference | Gap Description |
|------------|-------------|---------------------|----------------|
| SSB.LOG.10 | Centralized log management | AWS SSB | Logs are centralized but full log analysis is not implemented |
| SSB.IR.8 | Automated remediation | AWS SSB | Limited automated remediation is implemented |
| SSB.NET.9 | Network segmentation | AWS SSB | Basic network segmentation is implemented but may not meet all requirements |

## 4. Out of Scope Controls

These controls are outside the scope of what the MSB implements:

| Control ID | Description | Framework Reference | Scope Limitation |
|------------|-------------|---------------------|------------------|
| CIS 5.5 | VPC peering routing tables | CIS 3.0.0 | MSB creates secure VPCs but does not manage peering connections |

## 5. Manual Verification Required

These controls require manual verification procedures:

| Control ID | Description | Framework Reference | Verification Method |
|------------|-------------|---------------------|---------------------|
| CIS 1.18 | Security contact information | CIS 3.0.0 | Manual account verification |
| IAM.7 | Eliminate use of root user | FSBP, CIS 1.7 | Manual operational verification |
| IAM.3 | Access key rotation | FSBP, CIS 1.14 | Manual verification of rotation process |
| Config.3 | Compliance reporting | FSBP, COM.3 | Manual verification of reports |

## Improving Test Coverage

To further improve test coverage for the remaining controls:

1. **Expand integration tests**: Add post-deployment checks for VPC flow log delivery and CloudWatch alarm notification routing
2. **Runtime event simulation**: For IAM.8, simulate IAM configuration drift in a test account and verify Access Analyzer findings are generated and alerted
3. **Manual Verification Procedures**: Document step-by-step manual procedures for controls that cannot be automatically tested
4. **Acceptance of Residual Risk**: For controls that are explicitly excluded, document the acceptance of residual risk

See [Compliance Testing](compliance_testing.md) for more information on the testing framework and approach.
