# Compliance Testing Framework

This document describes the testing framework used to validate compliance controls in the AWS MSB CDK implementation.

## Overview

The compliance testing framework uses AWS CDK's built-in testing capabilities to verify that resources are created with the correct properties and configurations to meet compliance requirements. The framework focuses on validating the following aspects:

1. **Resource Creation**: Verifying that required resources are created
2. **Resource Configuration**: Verifying that resources have the correct properties
3. **Resource Relationships**: Verifying that resources are properly connected
4. **Policy Validation**: Verifying that IAM policies have the correct permissions

## Testing Approach

### Synthesis Testing

Most compliance controls are tested using CDK's synthesis testing capabilities. This approach validates that the CDK code generates CloudFormation templates with the correct resources and properties. The `aws-cdk-lib/assertions` module provides the `Template` class, which allows us to make assertions about the synthesized CloudFormation template.

Example:

```python
def test_cloudtrail_enabled_and_configured(self):
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = LoggingStack(app, "TestLoggingStack")
    template = Template.from_stack(stack)
    
    # THEN
    # Verify CloudTrail is enabled with proper configuration
    template.has_resource_properties("AWS::CloudTrail::Trail", {
        "IsLogging": True,
        "IsMultiRegionTrail": True,
        "EnableLogFileValidation": True,
        "IncludeGlobalServiceEvents": True
    })
```

### Runtime Testing

Some controls require runtime verification after deployment. These controls are documented in the [Untested Controls](untested_controls.md) document. For these controls, we recommend implementing integration tests that deploy resources and verify runtime behavior.

## Test Organization

Tests are organized by compliance control category:

1. **IAM Controls**: Tests for IAM-related controls
2. **Logging Controls**: Tests for CloudTrail, CloudWatch, and other logging controls
3. **Data Protection Controls**: Tests for encryption and data protection controls
4. **Network Security Controls**: Tests for VPC, security groups, and other network controls
5. **Monitoring Controls**: Tests for monitoring and alerting controls

## Custom Assertions

For complex controls, we've developed custom assertions to simplify testing:

1. **Policy Assertions**: Validate IAM policy statements
2. **Encryption Assertions**: Validate encryption configurations
3. **Logging Assertions**: Validate logging configurations

## Running Tests

To run the compliance tests:

```bash
pytest tests/test_compliance.py -v
```

## Improving Test Coverage

To improve test coverage for untested controls:

1. **Runtime Testing**: Implement integration tests that deploy resources and verify runtime behavior
2. **Custom Assertions**: Develop specialized assertions for complex controls
3. **Manual Verification Procedures**: Document manual verification procedures for controls that cannot be automatically tested

## Recent Improvements

### IAM.16 Testing

We've added testing for IAM.16 (IAM policies attached only to groups or roles) by implementing a Lambda function that monitors and reports on IAM policies attached directly to users. The test verifies that:

1. The Lambda function is created with the correct configuration
2. EventBridge rules are set up to trigger the Lambda on a schedule and on policy attachment events
3. The Lambda has the necessary permissions to check IAM policies and send notifications

### CloudTrail Log File Validation (CIS 3.3)

We've improved testing for CloudTrail log file validation by explicitly verifying that the `EnableLogFileValidation` property is set to `True` in the CloudTrail configuration.

## Future Enhancements

1. **Integration Testing**: Implement integration tests for runtime-dependent controls
2. **Policy Analysis**: Enhance policy analysis capabilities to validate complex IAM policies
3. **Compliance Reporting**: Generate compliance reports based on test results