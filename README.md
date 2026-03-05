# AWS Minimum Security Baseline (MSB) CDK

This project implements AWS security best practices using the AWS Cloud Development Kit (CDK). It provides a comprehensive set of security controls aligned with industry standards including AWS Foundational Security Best Practices (FSBP), CIS AWS Foundations Benchmark v3.0.0, and AWS Startup Security Baseline (SSB).

## Features

- **Comprehensive Security Controls**: Implements 45+ security controls across multiple AWS services
- **Compliance Mapping**: Maps controls to industry standards (FSBP, CIS AWS 3.0.0, AWS SSB)
- **Automated Testing**: Includes automated compliance tests to validate control implementation
- **Detailed Documentation**: Provides comprehensive documentation on control implementation and testing
- **Multi-Region Support**: Deploys security controls across multiple AWS regions

## Architecture

The project is organized into specialized stacks:

- **IAM Stack**: Identity and access management controls
- **S3 Security Stack**: S3 bucket security controls
- **Logging Stack**: Centralized logging configuration
- **Security Monitoring Stack**: GuardDuty, Security Hub, and IAM Access Analyzer
- **Network Security Stack**: VPC security controls
- **KMS Stack**: Key management and encryption controls
- **Compliance Stack**: Aggregates all security controls

## Optional Features

### WAFv2 Web Application Firewall

The WAF stack is optional because WAF rules are application-specific and incur additional cost. When enabled, it deploys a REGIONAL WAFv2 WebACL with five AWS managed rule groups:

- **AWSManagedRulesCommonRuleSet** — OWASP Top 10 core protections
- **AWSManagedRulesKnownBadInputsRuleSet** — known bad inputs (Log4j, SSRF, etc.)
- **AWSManagedRulesAmazonIpReputationList** — known malicious IPs
- **AWSManagedRulesAnonymousIpList** — Tor, VPN, and proxy blocking
- **AWSManagedRulesSQLiRuleSet** — SQL injection protection
- **Rate limiting rule** — blocks IPs that exceed 2000 requests per 5 minutes

To deploy the WAF stack alongside the other regional stacks:

```
cdk deploy MSB-WAF-us-east-1 --context notification_email=your@email.com --context enable_waf=true
```

After deployment, associate the exported `MSB-WAF-WebACLArn-{region}` CloudFormation output with your resources:

```bash
# Associate with an Application Load Balancer
aws wafv2 associate-web-acl \
  --web-acl-arn <WebACLArn> \
  --resource-arn <alb-arn> \
  --region <region>
```

For CloudFront distributions, set the `web_acl_id` property on the distribution (note: CloudFront requires a CLOUDFRONT-scoped WebACL in us-east-1). For API Gateway, associate via the stage settings in the console or CLI.

## Getting Started

### Prerequisites

- AWS CDK v2
- Python 3.9+
- AWS CLI configured with appropriate permissions

### Installation

1. Clone the repository
2. Create and activate a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development and testing
   ```

### Deployment

1. Bootstrap your AWS environment (if not already done):
   ```
   cdk bootstrap
   ```

2. Deploy the stacks:
   ```
   cdk deploy --all
   ```

## Compliance Testing

Run the compliance tests to validate the implementation:

```
./tests/run_compliance_tests.sh
```

This will:
1. Run all compliance tests
2. Generate an HTML compliance report
3. Open the report in your browser

## Documentation

- [Compliance Matrix](docs/compliance_matrix.md): Maps controls to industry standards
- [Control Implementation Details](docs/control_implementation_details.md): Details on how controls are implemented
- [Untested Controls](docs/untested_controls.md): Explanation of controls not covered by automated tests
- [Development Guide](docs/development_guide.md): Guide for developers contributing to the project

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

See [SECURITY.md](SECURITY.md) for details on reporting security issues.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.