# Untested Controls and Residual Risk

This document explains why certain controls in the compliance matrix are not covered by automated tests, categorizing them by reason for exclusion.

## 1. Runtime-Dependent Controls

These controls can only be verified at runtime after deployment, not during CDK synthesis testing:

| Control ID | Description | Framework Reference | Reason |
|------------|-------------|---------------------|--------|
| SecurityHub.1 | Security Hub enabled | FSBP, CIS 3.10, LOG.8 | While we test resource creation, integration functionality requires runtime verification |
| IAM.8 | IAM Access Analyzer findings | FSBP, CIS 1.20, IR.6 | Finding generation and alerting requires runtime verification |
| CIS 4.1-4.16 | Various monitoring controls | CIS 3.0.0 | Requires runtime verification of event patterns and alerting |

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
| IAM.8 | IAM Access Analyzer alerts | FSBP, IR.6 | Access Analyzer is enabled but alerts are not fully implemented |
| IAM.16 | IAM policies attached only to groups or roles | FSBP | Implementation exists but needs to be integrated into the main stack |

## 4. Out of Scope Controls

These controls are outside the scope of what the MSB implements:

| Control ID | Description | Framework Reference | Scope Limitation |
|------------|-------------|---------------------|------------------|
| CIS 5.5 | VPC peering routing tables | CIS 3.0.0 | MSB creates secure VPCs but doesn't manage peering connections |

## 5. Manual Verification Required

These controls require manual verification procedures:

| Control ID | Description | Framework Reference | Verification Method |
|------------|-------------|---------------------|---------------------|
| CIS 1.18 | Security contact information | CIS 3.0.0 | Manual account verification |
| IAM.7 | Eliminate use of root user | FSBP, CIS 1.7 | Manual operational verification |
| IAM.3 | Access key rotation | FSBP, CIS 1.14 | Manual verification of rotation process |
| Config.3 | Compliance reporting | FSBP, COM.3 | Manual verification of reports |

## Improving Test Coverage

To improve test coverage for these controls:

1. **Runtime Testing**: Implement integration tests that deploy resources and verify runtime behavior
2. **Custom Assertions**: Develop specialized assertions for complex controls
3. **Manual Verification Procedures**: Document manual verification procedures for controls that cannot be automatically tested
4. **Acceptance of Residual Risk**: For controls that are explicitly excluded, document the acceptance of residual risk

See [Compliance Testing](compliance_testing.md) for more information on the testing framework and approach.