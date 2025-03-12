# Compliance Testing Framework

This document explains the compliance testing framework used in the AWS MSB CDK project to verify alignment with security standards and frameworks.

## Overview

The compliance testing framework provides a structured approach to verify that the implemented security controls align with industry standards and AWS security frameworks. It maps tests to specific controls and provides evidence of compliance.

## Supported Compliance Frameworks

The testing framework supports the following compliance frameworks:

1. **AWS Foundational Security Best Practices (FSBP)** - AWS security best practices for foundational security
2. **CIS AWS Foundations Benchmark v3.0.0** - Center for Internet Security benchmarks for AWS
3. **AWS Startup Security Baseline (SSB)** - AWS security baseline for startups

## Test Structure

Each compliance test is structured to:

1. Verify a specific security control implementation
2. Document which compliance frameworks and controls it validates
3. Provide evidence of compliance through assertions

Example test:

```python
def test_iam_password_policy_compliance(self):
    """
    Test IAM password policy meets CIS AWS 3.0.0 requirements
    - FSBP: IAM.9
    - CIS AWS 3.0.0: 1.8, 1.9, 1.10, 1.11
    - AWS SSB: IAM.1
    """
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = IAMStack(app, "TestIAMStack")
    template = Template.from_stack(stack)
    
    # THEN
    template.has_resource_properties("AWS::IAM::AccountPasswordPolicy", {
        "MinimumPasswordLength": 14,  # CIS 1.8 requires minimum length of 14
        "RequireUppercaseCharacters": True,  # CIS 1.11
        "RequireLowercaseCharacters": True,  # CIS 1.12
        "RequireSymbols": True,  # CIS 1.13
        "RequireNumbers": True,  # CIS 1.14
        "MaxPasswordAge": 90,  # CIS 1.10 requires 90 days or less
        "PasswordReusePrevention": 24,  # CIS 1.9 requires 24 or greater
        "AllowUsersToChangePassword": True  # Best practice
    })
```

## Compliance Report Generation

The framework includes a report generator that:

1. Parses test files to extract compliance annotations
2. Maps tests to controls in the compliance matrix
3. Calculates coverage metrics
4. Generates reports in multiple formats (HTML, Markdown, CSV)

### Running the Compliance Tests and Reports

To run the compliance tests and generate reports:

```bash
./tests/run_compliance_tests.sh
```

This script:
1. Runs all compliance-specific tests
2. Generates HTML, Markdown, and CSV compliance reports
3. Shows coverage metrics for security controls

### Report Formats

The framework generates reports in three formats:

1. **HTML Report** - Interactive report with detailed coverage information
2. **Markdown Report** - Documentation-friendly report for inclusion in project docs
3. **CSV Report** - Data-friendly format for further analysis or import into spreadsheets

### Report Content

Each report includes:

1. **Overall Coverage Metrics** - Percentage of controls covered by tests
2. **Covered Controls** - List of controls with test coverage, grouped by category
3. **Uncovered Controls** - List of controls without test coverage
4. **Test Details** - List of tests with their compliance mappings

## Extending the Framework

To add new compliance tests:

1. Create a test function in `tests/test_compliance.py`
2. Add compliance annotations in the docstring using the format:
   ```
   - FSBP: [control-id]
   - CIS AWS 3.0.0: [control-id]
   - AWS SSB: [control-id]
   ```
3. Implement assertions that verify the control implementation

## Compliance Matrix

The compliance matrix in `docs/compliance_matrix.md` serves as the source of truth for mapping MSB controls to compliance frameworks. The testing framework uses this matrix to calculate coverage metrics.

## Benefits

This compliance testing framework provides several benefits:

1. **Evidence of Compliance** - Provides evidence that security controls are implemented correctly
2. **Coverage Metrics** - Shows how well the implementation covers compliance requirements
3. **Documentation** - Generates documentation that can be used for audits
4. **Traceability** - Maps tests to specific compliance controls

## Future Enhancements

Planned enhancements to the compliance testing framework:

1. **Integration with CI/CD** - Automatically run compliance tests in CI/CD pipelines
2. **Compliance Dashboards** - Generate interactive dashboards for compliance monitoring
3. **Additional Frameworks** - Support for additional compliance frameworks (NIST, PCI DSS, etc.)
4. **Automated Remediation** - Suggest remediation steps for uncovered controls