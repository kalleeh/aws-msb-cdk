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
├── app.py                      # CDK application entry point
├── cdk.json                    # CDK context configuration
├── requirements.txt            # Python dependencies
└── requirements-dev.txt        # Development dependencies
```

## Development Environment

### Technical Requirements

- **Python**: Version 3.8 or higher (3.9+ recommended)
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
# ❌ Don't import from aws_cdk_lib (incorrect)
from aws_cdk_lib import App, Stack

# ❌ Don't import from individual modules (incorrect)
from aws_cdk.aws_s3 import Bucket
from aws_cdk.core import Duration
```

### Example of Correct Usage

```python
from constructs import Construct
from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_iam as iam,
    RemovalPolicy,
    Duration,
)

class MyStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create an S3 bucket
        bucket = s3.Bucket(
            self, "MyBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
        )
        
        # Create an IAM role
        role = iam.Role(
            self, "MyRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        
        # Grant the role access to the bucket
        bucket.grant_read(role)
```

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

Example:

```python
# Good practice
bucket = s3.Bucket(
    self, "LoggingBucket",
    encryption=s3.BucketEncryption.S3_MANAGED,
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
    removal_policy=cdk.RemovalPolicy.RETAIN,
)

# Apply tags to all resources in the stack
cdk.Tags.of(self).add("Project", "MSB")
```

## Testing

### Test Structure

Tests are organized to mirror the package structure:

```
tests/
├── unit/                      # Unit tests
│   ├── global_stacks/         # Tests for global stacks
│   └── regional_stacks/       # Tests for regional stacks
└── integration/               # Integration tests
```

### Writing Tests

Use pytest fixtures for common setup:

```python
import pytest
import aws_cdk as cdk
from aws_cdk.assertions import Template

@pytest.fixture
def app():
    return cdk.App()

@pytest.fixture
def stack(app):
    return MyStack(app, "MyTestStack")

@pytest.fixture
def template(stack):
    return Template.from_stack(stack)

def test_s3_bucket_created(template):
    template.has_resource("AWS::S3::Bucket", {
        "Properties": {
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }
    })
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/global_stacks/test_iam_stack.py

# Run with coverage report
pytest --cov=aws_msb_cdk
```

## Deployment Workflow

1. **Local Development**
   - Make changes to stack definitions
   - Run tests to verify changes
   - Synthesize CDK app to verify CloudFormation template generation:
     ```bash
     cdk synth
     ```

2. **Review Changes**
   - Use CDK diff to review changes before deployment:
     ```bash
     cdk diff
     ```

3. **Deployment**
   - Deploy changes following the deployment instructions in the README

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure your virtual environment is activated
   - Verify all dependencies are installed

2. **CDK Synthesis Errors**
   - Check for circular dependencies between stacks
   - Verify all required context values are provided

3. **Deployment Failures**
   - Check CloudFormation events in the AWS Console
   - Verify IAM permissions for the deploying user/role

### Debugging Tips

1. Use CDK context parameters for debugging:
   ```bash
   cdk synth --context debug=true
   ```

2. Enable AWS CDK debug logging:
   ```bash
   export CDK_DEBUG=true
   ```

## Contributing

1. Create a feature branch from main
2. Make your changes
3. Run tests and ensure they pass
4. Submit a pull request with a clear description of changes

Remember that this project strictly uses CDK v2 and Python. All code should be compatible with these versions and follow the established project structure and import patterns.