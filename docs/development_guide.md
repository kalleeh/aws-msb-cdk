# Development Guide for AWS MSB CDK Implementation

This guide provides detailed information for developers working on the AWS Minimum Security Baseline (MSB) CDK implementation.

## Project Structure

The project follows standard AWS CDK Python project structure:

```
aws-msb-cdk/
├── aws_msb_cdk/                # Main package directory
│   ├── __init__.py             # Package initialization
│   ├── global_stacks/          # Global stacks (IAM, S3, Logging, KMS)
│   ├── regional_stacks/        # Regional stacks (Network, Security, etc.)
│   └── constructs/             # Reusable CDK constructs
├── tests/                      # Test directory
│   ├── integration/            # Post-deployment integration tests
│   └── *.py                    # Unit tests (CDK synthesis)
├── app.py                      # CDK application entry point
├── cdk.json                    # CDK context configuration and defaults
├── setup.sh                    # Guided first-time deployment script
├── requirements.txt            # Python dependencies
└── requirements-dev.txt        # Development dependencies
```

## Development Environment

### Technical Requirements

- **Python**: Version 3.9 or higher
- **AWS CDK**: Version 2.x (this project is not compatible with CDK v1)
- **Node.js**: Version 14.x or higher (required for CDK)
- **npm**: Version 7.x or higher
- **AWS CLI**: Version 2.x

### Environment Setup

1. **Python Virtual Environment**

   Always use a virtual environment for development:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install Dependencies**

   ```bash
   # Install runtime dependencies
   pip install -r requirements.txt

   # Install development dependencies
   pip install -r requirements-dev.txt
   ```

3. **IDE Configuration**

   If using VS Code, the following settings are recommended:

   ```json
   {
     "python.linting.enabled": true,
     "python.linting.pylintEnabled": true,
     "python.formatting.provider": "black",
     "editor.formatOnSave": true,
     "python.testing.pytestEnabled": true
   }
   ```

---

## CDK Context Variables

Context variables configure the deployment. They can be set in `cdk.json` (as project defaults) or passed on the command line with `--context key=value`.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `notification_email` | string | *(required)* | Email address for security alerts and SNS subscription confirmations |
| `security_contact_phone` | string | `""` | Phone number for the AWS account security contact (e.g. `+1-555-123-4567`) |
| `global_region` | string | `us-east-1` | Primary AWS region where global stacks are deployed |
| `target_regions` | list | `["us-east-1", "us-west-2"]` | All regions to receive regional stacks |
| `enable_object_lock` | boolean | `false` | Enable WORM S3 Object Lock on the centralised log bucket (recommended for regulated industries) |
| `enable_waf` | boolean | `false` | Deploy a WAFv2 WebACL with managed rule groups in each target region |
| `control_tower_managed` | boolean | `false` | Signal that this account is managed by AWS Control Tower (see below) |
| `cloudtrail_log_group_name` | string | *(auto-detected)* | Override the CloudWatch Logs log group name that CloudTrail writes to. Used in CT mode to attach metric filters to an existing CT-managed trail's log group. |

### The `control_tower_managed` flag

When set to `true`, MSB skips creating resources that AWS Control Tower already manages at the organisation level:

- GuardDuty detector
- Security Hub Hub and standard subscriptions
- Macie session
- AWS Config configuration recorder and delivery channel
- CloudTrail trail

MSB's unique-value resources are still created in CT mode:

- CloudWatch metric filters and alarms (CIS 4.1-4.16)
- IAM password policy
- KMS keys
- VPC and network security controls
- IAM Access Analyzer
- Remediation Lambdas (default SG, S3 public access, IAM policy checker)

Enable CT mode:

```bash
cdk deploy --all \
  --context notification_email=you@example.com \
  --context control_tower_managed=true
```

In CT mode, pass `cloudtrail_log_group_name` if the CT organisation trail uses a non-default log group name so the CIS metric filters are attached to the correct log group:

```bash
cdk deploy --all \
  --context notification_email=you@example.com \
  --context control_tower_managed=true \
  --context cloudtrail_log_group_name=aws-controltower/CloudTrailLogs
```

---

## First-Time Deployment

For new deployments, use the `setup.sh` guided script instead of running CDK commands manually. It handles prerequisites, dependency installation, CDK bootstrap, and stack deployment in the correct order:

```bash
./setup.sh
```

The script:

1. Checks prerequisites (AWS CLI, Node.js 14+, Python 3.9+)
2. Creates a Python virtual environment and installs dependencies
3. Installs the CDK CLI globally via npm if not already present
4. Prompts for required configuration (`notification_email`, `security_contact_phone`) and optional configuration (`global_region`, additional regions, `enable_waf`, `enable_object_lock`)
5. Displays a deployment summary and asks for confirmation
6. Bootstraps the AWS account for CDK in each target region
7. Deploys global stacks first (`MSB-KMS-Global`, `MSB-Logging-Global`, `MSB-S3-Security`, `MSB-IAM-Global`), then all remaining stacks

Run `./setup.sh --help` for full usage information.

---

## CDK v2 Import Guidelines

When working with this project, ensure you follow the AWS CDK v2 import patterns:

### Correct Import Patterns for CDK v2

```python
# Import Construct from the constructs module
from constructs import Construct

# Import core types from aws_cdk
from aws_cdk import App, Stack, CfnOutput, Duration, RemovalPolicy

# Import AWS Construct Library modules from namespaces under aws_cdk
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_kms as kms
```

### Incorrect Import Patterns (CDK v1 style)

Do not use these patterns:

```python
# Do not import from aws_cdk_lib (incorrect)
from aws_cdk_lib import App, Stack

# Do not import from individual modules (incorrect)
from aws_cdk.aws_s3 import Bucket
from aws_cdk.core import Duration
```

---

## Coding Standards

### Python Imports

Follow this import order:

```python
# Standard library imports
import os
import json

# Third-party imports
import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
    aws_s3 as s3,
    aws_kms as kms,
)
from constructs import Construct

# Local application imports
from aws_msb_cdk.constructs.secure_bucket import SecureBucket
```

### CDK Best Practices

1. **Use L2 Constructs** when available instead of L1 (CFN) resources
2. **Implement Proper Removal Policies** for production resources
3. **Use Environment-Specific Configuration** via CDK context
4. **Apply Tags** to all resources for better management
5. **Use CDK Aspects** for cross-cutting concerns

---

## Testing

### Test Structure

```
tests/
├── integration/               # Post-deployment tests (require live AWS)
│   ├── conftest.py            # boto3 session fixtures and requires_aws marker
│   ├── test_guardduty.py
│   ├── test_security_hub.py
│   ├── test_cloudtrail.py
│   ├── test_config.py
│   ├── test_iam.py
│   ├── test_kms.py
│   └── test_s3_security.py
├── test_compliance.py         # Core compliance controls + CT mode tests
├── test_logging_stack.py      # CloudTrail, CIS metric filters/alarms
├── test_app.py                # Full-stack synthesis smoke tests
├── test_network_security_stack.py
├── test_vpc_stack.py
├── test_vpc_endpoints.py
├── test_sns_encryption.py
├── test_notifications_regional_stack.py
├── test_waf_stack.py
└── test_multi_region.py
```

### Running Unit Tests

Unit tests use CDK synthesis and require no AWS credentials:

```bash
# Run all unit tests
pytest tests/ --ignore=tests/integration -v

# Run a specific test file
pytest tests/test_compliance.py -v

# Run with coverage report
pytest tests/ --ignore=tests/integration --cov=aws_msb_cdk
```

### Running Integration Tests

Integration tests call live AWS APIs and require credentials with read permissions to the deployed account. They only run when explicitly opted in:

```bash
MSB_INTEGRATION_TESTS=1 AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/ -v
```

Setting `MSB_INTEGRATION_TESTS=1` is required. Without it, all integration tests are automatically skipped so CI pipelines do not fail on environments that lack credentials or sufficient permissions.

### CDK Nag

All stacks must pass `AwsSolutionsChecks` with **0 errors and 0 warnings**. The check is applied in `app.py` and runs during every `cdk synth` and unit test synthesis.

If you add a new resource that triggers a CDK Nag finding and the suppression is genuinely justified, add a `NagSuppressions` call with a clear reason string. Follow the project's existing suppression pattern:

**Always use `self.stack_name` in `by_path` calls — never hardcode a stack name.**

```python
from cdk_nag import NagSuppressions

# Correct — uses self.stack_name so the path is stable across test and
# deployment stack names
NagSuppressions.add_resource_suppressions_by_path(
    self,
    f"/{self.stack_name}/MyRole/DefaultPolicy/Resource",
    [{"id": "AwsSolutions-IAM5", "reason": "Wildcard required because the IAM API does not support resource-level restrictions for this action."}]
)
```

Hardcoding the stack name in a `by_path` call causes the suppression to silently not apply during unit tests (where the stack is instantiated with a different logical ID), leaving nag failures in the test run.

### Lambda Error Alarms

Every remediation Lambda in the project must have a CloudWatch Errors alarm that notifies the MSB SNS topic. This pattern ensures silent Lambda failures are caught before they create a compliance gap.

```python
import aws_cdk.aws_cloudwatch as cloudwatch

error_alarm = cloudwatch.Alarm(self, "MyLambdaErrors",
    metric=my_lambda.metric_errors(period=Duration.minutes(5)),
    threshold=1,
    evaluation_periods=1,
    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
    alarm_name=f"msb-my-lambda-errors-{self.region}",
    alarm_description="Lambda has errors — the automated control may no longer be enforced.",
    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
)
error_alarm.add_alarm_action(
    cloudwatch_actions.SnsAction(self.notifications_topic)
)
```

This pattern is implemented for all three existing remediation Lambdas: the default security group remediator (`NetworkSecurityStack`), the S3 public access checker (`S3SecurityStack`), and the IAM policy checker (`IAMStack`).

---

## Deployment Workflow

1. **Local Development**
   - Make changes to stack definitions
   - Run unit tests to verify changes:
     ```bash
     pytest tests/ --ignore=tests/integration -v
     ```
   - Synthesize to verify CloudFormation template generation and CDK Nag:
     ```bash
     cdk synth --context notification_email=you@example.com
     ```

2. **Review Changes**
   ```bash
   cdk diff --context notification_email=you@example.com
   ```

3. **Deployment**
   - For first-time deployments, use `setup.sh`
   - For subsequent deployments, use `cdk deploy --all` with the appropriate context flags

4. **Post-Deployment Verification**
   ```bash
   MSB_INTEGRATION_TESTS=1 AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/ -v
   ```

---

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure your virtual environment is activated
   - Verify all dependencies are installed: `pip install -r requirements.txt -r requirements-dev.txt`

2. **CDK Synthesis Errors**
   - Check for circular dependencies between stacks
   - Verify all required context values are provided (`notification_email` is required)

3. **CDK Nag Failures**
   - A nag finding in a new resource means a suppression or a fix is needed before merging
   - If suppressing, use `self.stack_name` in the path — not a hardcoded string

4. **Deployment Failures**
   - Check CloudFormation events in the AWS Console
   - Verify IAM permissions for the deploying user/role

### Debugging Tips

1. Enable CDK debug logging:
   ```bash
   export CDK_DEBUG=true
   cdk synth --context notification_email=you@example.com
   ```

2. Synthesize a specific stack to reduce output:
   ```bash
   cdk synth MSB-Logging-Global --context notification_email=you@example.com
   ```

---

## Contributing

1. Create a feature branch from main
2. Make your changes
3. Run unit tests and ensure they all pass: `pytest tests/ --ignore=tests/integration`
4. Verify `cdk synth` completes with 0 CDK Nag findings
5. If your change adds a new control, add a corresponding unit test
6. If your change adds a remediation Lambda, add a CloudWatch Errors alarm
7. Submit a pull request with a clear description of changes

This project strictly uses CDK v2 and Python. All code should be compatible with these versions and follow the established project structure and import patterns.
