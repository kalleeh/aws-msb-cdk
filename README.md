# AWS Minimum Security Baseline (MSB) CDK

A production-ready AWS security baseline for single-account pilots — before you need a full Landing Zone. Deploy in minutes, get ~95% green in Security Hub, and have a documented path to Control Tower when you're ready to grow.

**Target audience:** Founders and engineering teams going to production on AWS for the first time. Not a security team. Not AWS experts.

---

## What it does

Deploys a complete security baseline across your AWS account:

- **Threat detection** — GuardDuty with all protection plans, Security Hub with FSBP v1.0.0 + CIS AWS v3.0.0, Inspector v2, Macie
- **Audit trail** — Multi-region CloudTrail with KMS encryption, log validation, and S3 + Lambda data events
- **Compliance monitoring** — AWS Config with 30+ managed rules covering FSBP and CIS controls
- **Real-time alerting** — 13 CloudWatch metric filters/alarms (fires within 5 minutes) + SNS email notifications per region
- **Automated remediation** — Lambdas that automatically secure default security groups, enforce S3 public access blocks, and detect direct IAM policy attachments
- **Encryption** — KMS CMKs for CloudTrail, S3, RDS, EBS; EBS encryption by default
- **Network security** — VPC with private/isolated subnets, 13 VPC endpoints, bastion and application security groups
- **IAM controls** — Password policy (CIS 1.8–1.11), Access Analyzer, support role (CIS 1.17), security contact (CIS 1.18)

Expected Security Hub score after deployment: **~95% green**. The remaining findings are hardware MFA for root (requires a physical device — cannot be automated by any tool).

---

## Quick start

```bash
./setup.sh
```

The setup script checks prerequisites, creates a Python venv, prompts for your configuration, shows a cost estimate, and deploys everything. No CDK knowledge required.

**Prerequisites:** AWS CLI configured (`aws configure`), Node.js, Python 3.9+

---

## Manual deployment

If you prefer to deploy manually:

```bash
# Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Bootstrap CDK (first time only)
cdk bootstrap

# Deploy
cdk deploy --all \
  --context notification_email=your@company.com \
  --context security_contact_phone=+1-555-123-4567
```

After deployment, **check your email and confirm the SNS subscription** — without this, no alerts will be delivered.

---

## Configuration

All configuration is passed as CDK context variables. Set defaults in `cdk.json` or pass on the command line with `--context key=value`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `notification_email` | Yes | — | Email address for all security alerts |
| `security_contact_phone` | No | — | Phone for CIS 1.18 security contact. If omitted, security contact is not set. |
| `global_region` | No | `us-east-1` | Region for global stacks (IAM, KMS, Logging, S3) |
| `target_regions` | No | `["us-east-1", "us-west-2"]` | Regions for regional stacks |
| `enable_waf` | No | `false` | Deploy optional WAFv2 stack |
| `enable_object_lock` | No | `false` | Enable WORM Object Lock on the logs bucket |
| `control_tower_managed` | No | `false` | Skip resources CT already manages (see below) |
| `cloudtrail_log_group_name` | No | `aws-controltower/CloudTrailLogs` | CT trail log group name (CT mode only) |

---

## Stack architecture

```
Global (deployed once in global_region):
  MSB-KMS-Global              KMS CMKs for all services
  MSB-Logging-Global          CloudTrail, Config role, SNS topic, CloudWatch alarms
  MSB-S3-Security             Account-level S3 public access block + enforcement Lambda
  MSB-IAM-Global              Password policy, Access Analyzer, IAM policy checker Lambda

Regional (deployed in each target_region):
  MSB-Notifications-Regional  SNS topic + email subscription per region
  MSB-Network-Security        Default SG remediation Lambda, VPC flow logs destination
  MSB-Logging-Regional        Config recorder + delivery channel
  MSB-Security-Regional       GuardDuty, Security Hub, Inspector, Macie, findings bucket
  MSB-Security-Monitoring     EventBridge rules → SNS for all security findings
  MSB-VPC-Regional            VPC, subnets, NAT gateway, VPC endpoints
  MSB-Compliance              30+ Config managed rules (FSBP + CIS)

Optional:
  MSB-WAF-{region}            WAFv2 WebACL (enable with --context enable_waf=true)
```

---

## Optional features

### WAFv2 Web Application Firewall

```bash
cdk deploy MSB-WAF-us-east-1 \
  --context notification_email=your@company.com \
  --context enable_waf=true
```

Deploys a REGIONAL WebACL with 5 AWS managed rule groups (CommonRuleSet, KnownBadInputs, AmazonIpReputationList, AnonymousIpList, SQLiRuleSet) and a rate limiting rule (2000 req/5 min per IP). After deployment, associate the exported `MSB-WAF-WebACLArn-{region}` with your ALB, API Gateway, or AppSync.

### Object Lock (WORM logs)

For regulated industries that require immutable audit logs:

```bash
cdk deploy MSB-Logging-Global --context enable_object_lock=true ...
```

Off by default because Object Lock cannot be disabled after bucket creation — keep it off during pilot/iteration phases.

---

## Control Tower compatibility

If you are deploying MSB into accounts already managed by AWS Control Tower, add `--context control_tower_managed=true`. This skips the five resources that hard-conflict with Control Tower's Organisation-level management (GuardDuty detector, Security Hub hub, Config recorder/channel, CloudTrail trail, Inspector, Macie) while still deploying everything CT does not provide:

- 13 CloudWatch metric filters and alarms (CT does not provide these)
- IAM policy checker, default SG remediation, S3 public access enforcement Lambdas
- Config rules (ComplianceStack)
- KMS keys, VPC, SNS regional topics, EventBridge routing

```bash
cdk deploy --all \
  --context notification_email=your@company.com \
  --context control_tower_managed=true \
  --context cloudtrail_log_group_name=aws-controltower/CloudTrailLogs
```

See [docs/landing-zone-migration.md](docs/landing-zone-migration.md) for the full enrollment process including which MSB stacks to destroy before CT enrollment.

---

## Testing

**Unit tests** (CDK synthesis validation, 68 tests):

```bash
source .venv/bin/activate
python -m pytest tests/ --ignore=tests/integration -v
```

**Integration tests** (post-deployment validation against a live AWS account):

```bash
MSB_INTEGRATION_TESTS=1 AWS_DEFAULT_REGION=us-east-1 pytest tests/integration/ -v
```

Integration tests cover: GuardDuty enabled, Security Hub standards active, CloudTrail logging, Config recording, IAM password policy, KMS key rotation, S3 public access block. They skip automatically if `MSB_INTEGRATION_TESTS=1` is not set.

---

## Cost estimate

| Scenario | Estimated monthly cost |
|---|---|
| Security baseline only (no VPC stack) | ~$40–90/month |
| With VPC stack (NAT + endpoints) | ~$165–215/month |
| With large S3 datasets (Macie) | Add $5–50+/month |

See [docs/cost.md](docs/cost.md) for a per-service breakdown. The biggest surprises: VPC interface endpoints (~$190/month across 13 endpoints × 2 AZs) and Macie (scales with data volume).

---

## Documentation

| Document | Description |
|---|---|
| [docs/cost.md](docs/cost.md) | Per-service cost breakdown for a typical pilot |
| [docs/alert-response.md](docs/alert-response.md) | Runbook for every alert the MSB generates |
| [docs/residual_risk.md](docs/residual_risk.md) | Formal risk register for auditors (SOC 2, ISO 27001) |
| [docs/landing-zone-migration.md](docs/landing-zone-migration.md) | When and how to migrate to Control Tower |
| [docs/compliance_matrix.md](docs/compliance_matrix.md) | Full FSBP / CIS / SSB control mapping |
| [docs/control_implementation_details.md](docs/control_implementation_details.md) | How each control is implemented |

---

## After deployment checklist

- [ ] Confirm the SNS subscription email (check inbox, click Confirm)
- [ ] Enable MFA on the root account ([AWS console](https://console.aws.amazon.com/iam/home#/security_credentials))
- [ ] Review [docs/alert-response.md](docs/alert-response.md) so your team knows what to do when alerts fire
- [ ] Sign off [docs/residual_risk.md](docs/residual_risk.md) for your compliance records
- [ ] If using WAF, associate the WebACL ARN with your load balancers or API gateways

---

## License

MIT — see LICENSE file.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
