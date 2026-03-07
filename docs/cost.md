# MSB Cost Guide

A practical cost reference for founders and small teams running MSB in a single production AWS account. Not a generic AWS pricing page — these numbers reflect what MSB actually deploys.

---

## Monthly cost estimate for a typical pilot

Assumptions: 2–5 engineers, light workloads, two regions (us-east-1 + us-west-2, the default `target_regions` in `cdk.json`), no large S3 datasets.

### GuardDuty

GuardDuty charges based on the volume of data it analyses: CloudTrail management events, S3 data events, VPC Flow Logs, and DNS query logs. MSB enables GuardDuty with all protection plan features: S3 data events, EKS audit logs, EBS malware protection, RDS login events, Lambda network logs, EKS runtime monitoring, and EC2/Fargate runtime monitoring.

For a small account with light activity (few EC2 instances, moderate API call volume, no EKS):

- **Estimated: $15–30/month per region**
- A 30-day free trial is available on first activation
- Costs rise quickly once you add EC2 instances, Lambda invocations, or EKS clusters — each adds a separate billable dimension

### Security Hub

Security Hub charges $0.001 per security check per month. MSB enables two standards:
- AWS Foundational Security Best Practices (FSBP) v1.0.0
- CIS AWS Foundations Benchmark v3.0.0

Each standard runs roughly 180–220 checks. For a small account with ~30 resources:

- **Estimated: $10–20/month per region**
- A 30-day free trial is available on first activation
- Checks scale with the number of resources in the account, not the number of findings

### AWS Config

Config charges $0.003 per configuration item recorded and $0.001 per rule evaluation. MSB deploys approximately 30 managed Config rules via `ComplianceStack`, covering encryption, IAM, S3, CloudTrail, networking, Lambda, and SSM. The recorder is set to `all_supported=True`, so every supported resource type is tracked.

- **Estimated: $5–15/month per region**
- Lower end if your resource count is stable (few changes = few configuration items)
- Upper end if you are actively deploying and tearing down resources (CI/CD pipelines, frequent deploys)
- Config snapshots are delivered every 6 hours to the central S3 logs bucket

### Amazon Inspector

Inspector v2 is enabled for EC2, ECR, and Lambda. Pricing is per resource scanned:

- Lambda: ~$0.01/function/month (first scan) + $0.01/function/month ongoing
- EC2: ~$0.006/instance/month (SSM-managed instances) + vulnerability database fees
- ECR: charged per unique container image layer scanned

**If you have no EC2 instances or ECR images during the pilot, Inspector cost is minimal — mainly Lambda scanning.**

- **Estimated: $2–10/month** for a pilot with a few Lambda functions and no EC2
- Add ~$0.006 per EC2 instance per month once you start launching instances

### Amazon Macie

Macie charges $1.00/bucket/month for automated discovery evaluation and $1.00/GB for data classification. MSB enables Macie with `FIFTEEN_MINUTES` publishing frequency.

- **Estimated: $5–15/month** for a pilot with a handful of buckets and minimal data
- **This can be significant if you have large S3 datasets.** A single bucket with 100 GB of data classified by Macie = $100+ in that month alone
- Macie's automated discovery evaluates every bucket in the account, so the per-bucket charge applies regardless of whether you trigger manual classification jobs

If you have large S3 buckets during the pilot phase, consider this the most important cost item to monitor.

### KMS — Customer Managed Keys

MSB's `KMSStack` creates five CMKs:
1. `msb/master-key` — general encryption
2. `msb/cloudtrail-key` — CloudTrail log encryption
3. `msb/s3-key` — S3 encryption
4. `msb/rds-key` — RDS encryption
5. `msb/ebs-key` — EBS default encryption key

Each KMS CMK costs $1.00/month. API call charges are $0.03 per 10,000 requests.

- **Fixed cost: $5/month** (5 keys × $1)
- API calls add $1–3/month at typical pilot volumes
- The `NotificationsRegionalStack` creates one additional KMS key per non-global region (for SNS encryption), so two regions = 6 KMS keys total

### CloudTrail

MSB deploys a single multi-region trail (`msb-cloudtrail`) that covers all regions and global service events. The first management events trail per region is free.

MSB also enables advanced event selectors for **all S3 data events** and **all Lambda data events** (required for CIS 3.10 and 3.11). These are billable:

- S3 data events: $0.10 per 100,000 events
- Lambda data events: $0.10 per 100,000 events

- **Management events: $0/month** (free tier covers the first trail)
- **Data events: $1–10/month** at pilot scale, depending on S3 and Lambda activity
- S3 data events can become expensive if you have high-throughput buckets (uploads, downloads, presigned URLs) — each object-level API call is a billable event

### SNS and CloudWatch

MSB creates one SNS topic per deployed region (in the global region, it is created by `LoggingStack`; in additional regions, by `NotificationsRegionalStack`). CloudWatch metric filters and alarms cover all 13 CIS v3.0.0 alarm controls (3.1–3.14 and 4.4, 4.15, 4.16).

- SNS: effectively free at pilot scale (email delivery, no volume)
- CloudWatch alarms: ~$0.10/alarm/month × 13 alarms = ~$1.30/month per region
- CloudWatch Logs ingestion for CloudTrail log group: $0.50/GB ingested

- **Estimated: $3–8/month** across both regions

### NAT Gateway (VPC stack)

`VpcStack` deploys one NAT gateway (`nat_gateways=1`) in a VPC with 2 Availability Zones. NAT gateway pricing:

- Hourly charge: $0.045/hour = **~$33/month**
- Data processing: $0.045/GB transferred through the NAT gateway

The data processing charge depends entirely on how much traffic your private subnets send to the internet. For a pilot with light egress, the hourly charge dominates.

- **Estimated: $33–50/month** (hourly rate plus light data transfer)
- This is often the biggest surprise for teams new to VPC costs

### VPC Interface Endpoints (VPC stack)

`VpcStack` creates 13 interface endpoints (in addition to 2 free gateway endpoints for S3 and DynamoDB):

`ssm`, `ssmmessages`, `ec2messages`, `kms`, `logs`, `monitoring`, `sqs`, `sns`, `secretsmanager`, `ecr.api`, `ecr.dkr`, `ecs`, `lambda`

Interface endpoint pricing: $0.01/hour per endpoint per Availability Zone. With 2 AZs:

- 13 endpoints × 2 AZs × $0.01/hour × 730 hours = **~$190/month**
- Data processing through interface endpoints: $0.01/GB

The VPC endpoints exist to keep AWS API traffic inside the VPC (no NAT gateway charges for AWS service calls, improved security posture). Whether the security benefit justifies the cost depends on your workload.

- **Estimated: ~$190/month** for all 13 endpoints across 2 AZs
- Endpoints you are not using still incur the hourly charge

---

## Summary table

| Scenario | Estimated monthly cost |
|---|---|
| Security baseline only (no VPC stack deployed) | ~$45–100/month |
| With VPC stack (NAT + all 13 interface endpoints) | ~$270–320/month |
| With VPC stack, reduced to essential endpoints only | ~$140–190/month |
| Add large S3 datasets (Macie classification) | Add $5–100+/month |

These estimates assume two regions (the default `target_regions` configuration). A single-region deployment roughly halves the per-region costs.

---

## Cost optimisation tips for pilots

**The VPC stack is optional and expensive.** Do not deploy `MSB-VPC-Regional-*` until you have workloads that actually need it. The security baseline stacks (GuardDuty, Security Hub, Config, CloudTrail, KMS) do not depend on the VPC stack.

**Not all 13 interface endpoints may be relevant to your workload.** If you are not running ECS, you do not need the `ecs` endpoint. If you have no Lambda functions inside the VPC, the `lambda` endpoint adds no value. Each endpoint costs ~$15/month across 2 AZs.

**Macie automated discovery evaluates all buckets.** If you have large datasets (backups, data lakes, logs) in S3 during the pilot, the classification charge adds up fast. Consider disabling automated discovery for large archival buckets during the pilot phase and re-enabling it before you go live.

**GuardDuty protection plans scale with resource types.** If you have no EKS clusters, the EKS audit log and runtime monitoring features are enabled but cost nothing (nothing to analyse). Once you add EKS, costs increase.

**Free trials.** GuardDuty and Security Hub each offer a 30-day free trial on first activation per account per region. The trial covers all features. Use this window to validate findings and tune before the billing starts.

**CloudTrail S3 data events.** The `all S3 data events` selector (required for CIS 3.10) charges $0.10 per 100,000 events. If you have a high-traffic S3 bucket (e.g., a web app serving assets or a data pipeline), this can grow unexpectedly. Monitor it in Cost Explorer with the CloudTrail service filter in the first few weeks.

---

## How costs scale

As your workloads grow, GuardDuty and Config costs increase proportionally with event volume and resource count. These costs are not waste — they represent the operational cost of maintaining a production-grade security posture.

For context: these security baseline costs typically represent 5–10% of a production AWS bill. A team spending $2,000/month on compute and data services should expect $100–200/month on the MSB security baseline.

When you move to AWS Landing Zone or Control Tower, these costs are incurred per account. A standard three-account setup (management, dev, prod) roughly triples the security baseline costs, offset by the benefits of account isolation.
