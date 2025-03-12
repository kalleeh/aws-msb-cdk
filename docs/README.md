# AWS MSB CDK Documentation

This directory contains documentation for the AWS Minimum Security Baseline (MSB) CDK implementation. Below is a guide to the documentation files and their purposes.

## Core Documentation Files

| File | Purpose |
|------|---------|
| [compliance_matrix.json](compliance_matrix.json) | **Source of truth** - JSON data mapping all security controls to compliance frameworks |
| [compliance_report.html](compliance_report.html) | **Interactive dashboard** - Visual report showing test coverage and implementation details |
| [untested_controls.md](untested_controls.md) | Explains why certain controls are not covered by automated tests |

## Implementation Documentation

| File | Purpose |
|------|---------|
| [control_implementation_details.md](control_implementation_details.md) | Technical details on how each security control is implemented in CDK |
| [security_control_types.md](security_control_types.md) | Categorizes controls by type (preventative, detective, etc.) |
| [development_guide.md](development_guide.md) | Guide for developers working on the project |

## Compliance Documentation

| File | Purpose |
|------|---------|
| [compliance_testing.md](compliance_testing.md) | Explains the testing framework and methodology |
| [residual_risk.md](residual_risk.md) | Assessment of security controls not fully implemented |
| [programmatic_controls.md](programmatic_controls.md) | Additional controls that can be added to address residual risk |

## Legacy/Reference Files

| File | Purpose |
|------|---------|
| [compliance_matrix.md](compliance_matrix.md) | Human-readable version of the compliance matrix (generated from JSON) |
| [compliance_report.md](compliance_report.md) | Text-based summary of compliance test results |

## Using the Documentation

1. Start with the **compliance_report.html** for a visual overview of the security controls and test coverage
2. Refer to **control_implementation_details.md** to understand how specific controls are implemented
3. Check **untested_controls.md** and **residual_risk.md** to understand security gaps
4. Use **development_guide.md** when contributing to the project

## File Relationships

```
compliance_matrix.json  ──────┐
       │                      │
       ▼                      ▼
compliance_matrix.md    generate_html_report.py
                              │
                              ▼
test_compliance.py  ────► compliance_report.html
       │                      │
       ▼                      ▼
untested_controls.md    compliance_report.md
```

- **compliance_matrix.json** is the source of truth for all controls
- **generate_html_report.py** creates the HTML dashboard from test results and the matrix
- **test_compliance.py** contains the actual compliance tests
- Documentation files explain different aspects of the implementation and testing