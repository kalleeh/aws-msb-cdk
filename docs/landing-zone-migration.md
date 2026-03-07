# Graduating from MSB to AWS Landing Zone

MSB is designed for single-account production pilots. It gives you a solid security baseline quickly, without the operational overhead of a multi-account structure. This guide covers when that trade-off stops making sense, what the migration looks like, and what you keep from MSB on the other side.

Target audience: CTOs and senior engineers making the call on whether to migrate.

---

## When to migrate

These are concrete triggers, not vague guidance. If two or more apply, it is time to move.

**You need more than one AWS account.** The most common trigger. Dev/staging/prod separation in a single account relies on IAM boundaries that are easy to misconfigure. Once you need true isolation — separate blast radius, separate billing, separate IAM namespaces — you need multiple accounts, which means you need an Organisation.

**You have more than ~10 engineers who need AWS access.** Managing IAM users at scale becomes an operational burden. Onboarding, offboarding, access reviews, and MFA enforcement all get harder. IAM Identity Center (SSO) with permission sets, which Control Tower sets up for you, handles this cleanly.

**Enterprise customers require multi-account isolation in their security questionnaires.** This is increasingly common in security reviews and vendor assessments. If a customer asks "do you have production/non-production account separation?", and the answer is no, some deals do not close.

**You need SCPs to enforce controls you cannot trust individual teams to follow.** Service Control Policies attach to the Organisation and cannot be overridden by account-level IAM. If you need to guarantee "no public S3 buckets anywhere" or "only approved regions" regardless of what any individual engineer does, you need an Organisation with SCPs.

**You are pursuing ISO 27001 or SOC 2 Type II.** Auditors increasingly expect multi-account architectures for these certifications. Single-account setups are not automatic disqualifiers, but you will need to explain and justify the compensating controls. Multi-account makes the audit easier.

**You are spending more than ~$5,000/month on AWS.** Below this threshold, the operational overhead of Landing Zone (setting up account vending, maintaining pipelines, managing OU structures) costs more in engineering time than it saves. Above it, the cost visibility, SCP guardrails, and operational discipline start paying off.

---

## What carries over and what needs cleanup

These MSB components interact with Control Tower during enrollment. Understanding what happens to each one avoids surprises.

**GuardDuty.** Control Tower makes the Audit account the GuardDuty Organisation admin. Your existing MSB detector becomes a member detector managed from the Audit account. The `CfnDetector` CloudFormation resource is removed in step 4 (pre-enrollment cleanup); Control Tower recreates the detector under its own management. Existing findings history stays intact. MSB's protection plan configuration (S3, EBS malware, runtime monitoring, RDS login events, Lambda network logs) should be set as the Organisation default from the Audit account after enrollment.

**Security Hub.** Same pattern as GuardDuty. The Audit account becomes the Security Hub administrator. Your existing hub becomes a member. Removed in pre-enrollment cleanup; Control Tower recreates it. MSB's automation rules (suppressing Account.1, root MFA hardware controls) can be promoted to Organisation-wide automation rules from the Audit account.

**CloudTrail.** Control Tower creates an Organisation Trail covering all member accounts. MSB's per-account `msb-cloudtrail` trail is removed in pre-enrollment cleanup. Your existing CloudTrail logs in `msb-logs-{account}-{region}` stay in S3 for historical reference. The `LoggingStack` CloudWatch metric filters and alarms remain active, now attaching to Control Tower's trail log group via the `cloudtrail_log_group_name` context variable.

**AWS Config.** Control Tower deploys a Config recorder and delivery channel into each enrolled account. MSB's versions are removed in pre-enrollment cleanup. After enrollment, MSB's `ComplianceStack` (~30 Config rules) is redeployed with `control_tower_managed=true` and sits on top of the CT-managed recorder — the rules work independently of who created the recorder.

**KMS keys.** The five CMKs created by `KMSStack` (master, CloudTrail, S3, RDS, EBS) are not touched by Control Tower and require no migration. Cross-account access can be granted via key policy if other accounts need to read encrypted data.

**SNS alerting.** The per-region SNS topics are not touched by Control Tower and continue working. In a multi-account setup, you can additionally route critical Security Hub findings through a central Security account SNS topic for aggregated visibility, while keeping per-account topics for account-specific operational alerts.

**Inspector and Macie.** Control Tower can enable these at the Organisation level from the Audit account. MSB's versions are removed in pre-enrollment cleanup; Control Tower manages them after enrollment. MSB's EventBridge rules routing findings to SNS remain active in CT mode.

---

## What needs to be rebuilt

These components do not have a direct lift-and-shift path. They need to be replaced or re-architected.

**IAM users.** MSB's `IAMStack` creates IAM users and enforces MFA via IAM policies and a Lambda checker. In Landing Zone, these are replaced by IAM Identity Center (SSO) with permission sets mapped to your identity provider (Google Workspace, Okta, Azure AD, or the built-in Identity Center directory). IAM users in individual accounts are deprecated. This is the most disruptive change operationally — engineers need to update their AWS CLI configuration to use SSO profiles.

**Single-account VPC.** MSB's `VpcStack` creates a standalone VPC (`10.0.0.0/16`) per region with a NAT gateway and VPC interface endpoints. In a multi-account Landing Zone, networking moves to a shared Network account using either a Transit Gateway hub-and-spoke pattern or AWS Network Firewall with centralised egress. The MSB VPC gets decommissioned in favour of VPC attachments to the central Transit Gateway. Workloads in dev and prod accounts connect to the shared network account rather than each having their own VPCs with duplicate NAT gateways and endpoints.

**Per-account Config rules.** MSB's `ComplianceStack` deploys ~30 managed Config rules directly into each account. In an Organisation, these are replaced by Organisation Config conformance packs deployed from the management or delegated admin account. Individual account Config recorders remain active, but the rules are managed centrally.

**MSB CDK stacks.** The MSB stacks need to be deployed into each new account as it is created, always with `--context control_tower_managed=true` in a CT-managed Organisation. Automate this with a GitHub Actions workflow using OIDC federation, or CodePipeline with cross-account roles — running `cdk deploy` manually into each account does not scale. For account vending, Control Tower's Customizations for Control Tower (CfCT) solution or Account Factory Customization (AFC) can trigger the MSB pipeline automatically when a new account is created; CfCT is the more established option for CDK-based customisations. For small organisations (under ~20 accounts), a GitHub Actions workflow triggered manually or by an account creation event is simpler and sufficient.

---

## Migration path (step by step)

This is a sequential process. Do not skip steps.

**1. Create a new AWS account to serve as the Management account.**
Do not convert your existing MSB account into the management account. AWS explicitly recommends against running workloads in the management account — it is a billing root and SCP anchor, not a place for production infrastructure. Create a fresh AWS account. This account will own the Organisation, Control Tower, and billing. Your existing MSB account will become a member account (your production workload account).

**2. Enable AWS Organizations from the new management account and invite the existing MSB account.**
From the new management account, create an Organisation with all features enabled (not just consolidated billing). Send a join invitation to your existing MSB account. Accept it from the MSB account. The existing account is now a member of the Organisation with all its resources intact.

**3. Enable Control Tower from the management account.**
Control Tower sets up Landing Zone, creates a Log Archive account and an Audit account, and deploys baseline SCPs. During setup it will detect existing GuardDuty and Security Hub configurations in member accounts and prompt you to adopt them at the Organisation level. Follow the Control Tower console — it handles most of the Organisation-level enablement automatically.

**4. Enroll the existing MSB account in Control Tower.**
This is where MSB's pre-existing security resources require careful handling. Control Tower's enrollment process deploys a StackSet into the account that creates a Config recorder, delivery channel, GuardDuty detector, and Security Hub hub. If MSB's versions of these already exist, the enrollment StackSet will fail.

Before enrolling the existing account, remove the conflicting MSB stacks:

```bash
# Run from your existing MSB account with appropriate credentials

# Remove the stacks that will hard-conflict with Control Tower's enrollment
cdk destroy MSB-Security-Regional-us-east-1   # GuardDuty, Security Hub, Inspector, Macie
cdk destroy MSB-Logging-Regional-us-east-1    # Config recorder + delivery channel
cdk destroy MSB-Logging-Global                # CloudTrail trail
```

> **What you are NOT destroying:** KMS keys, SNS topics, CloudWatch alarms and metric filters, Lambda remediators, VPC, Config rules, IAM stack. These have no conflict with Control Tower and will remain active throughout.

After the conflicting stacks are removed, enroll the account through the Control Tower console (Account Factory → Enroll account). Control Tower will recreate the removed resources under its own management.

**5. Redeploy MSB with `control_tower_managed=true`.**
Once enrollment completes, redeploy MSB into the account. The `control_tower_managed=true` flag tells MSB to skip the resources Control Tower now owns and only deploy its unique-value components:

```bash
cdk deploy --all \
  --context notification_email=your@company.com \
  --context control_tower_managed=true
```

This restores the CloudWatch alarms, Lambda remediators, Config rules, KMS keys, SNS regional topics, and VPC — everything that Control Tower does not automatically provide. If your Control Tower Organisation Trail uses a different CloudWatch Logs group name than the default (`aws-controltower/CloudTrailLogs`), pass it explicitly:

```bash
  --context cloudtrail_log_group_name=/your/ct/trail/log-group
```

**6. Deploy MSB into each new account as you create them.**
When you create dev, staging, or additional prod accounts through Control Tower Account Factory, deploy MSB immediately after provisioning using the `control_tower_managed=true` flag. New accounts get CT's baseline (GuardDuty, Security Hub, Config) from the Organisation, plus MSB's unique-value layer on top (CloudWatch alarms, Lambda remediators, Config rules, SNS alerting, KMS keys).

For more than a handful of accounts, automate this with a GitHub Actions workflow or CodePipeline triggered by account creation. Running `cdk deploy` manually into each account does not scale.

**7. Replace IAM users with Identity Center permission sets.**
Set up IAM Identity Center in the management account. Connect it to your identity provider or use the built-in directory. Create permission sets that mirror the access patterns your team currently has (read-only, developer, admin). Migrate engineers one at a time by creating their Identity Center assignment, confirming SSO access works, then removing their IAM user. MSB's IAM policy checker Lambda (`IAMStack`) can remain active during the transition as a safety net.

**8. Set up SCPs for baseline guardrails.**
Control Tower deploys a set of mandatory and strongly recommended SCPs. Add your own for controls MSB cannot enforce at the account level: denying specific high-risk regions, preventing CloudTrail from being disabled, requiring MFA for sensitive API calls. SCPs enforce these guarantees regardless of account-level IAM configuration.

**9. Decommission the single-account VPC in favour of shared networking.**
Once workloads have migrated to the multi-account structure and Transit Gateway (or equivalent) is in place, remove the MSB VPC stack from the original account. Migrating workloads off the standalone VPC is the most time-consuming part of the overall migration — plan for weeks, not days.

---

## What MSB gives you that Landing Zone does not automatically provide

Control Tower gives you account structure, baseline SCPs, and Organisation-level security service enablement. It does not replace everything MSB deploys. Keep these MSB components active in every account:

**CloudWatch metric filters and alarms (CIS 3.1–3.14, 4.4, 4.15, 4.16).** MSB's `LoggingStack` deploys 13 CloudWatch metric filters and alarms that alert on specific CloudTrail events: unauthorized API calls, console sign-ins without MFA, CloudTrail config changes, KMS key deletion, S3 bucket policy changes, Config recorder changes, network gateway changes, route table changes, VPC changes, IAM policy changes, security group changes, and NACL changes. These are per-account alarms routed to per-account SNS topics. Control Tower and Security Hub do not replace these — Security Hub findings are slower (minutes to hours), whereas these alarms fire within 5 minutes of the event. Keep them in every account.

**The IAM policy checker Lambda (`IAMStack`).** MSB deploys a Lambda function that checks IAM policies for overly permissive statements and alerts via SNS. This is a useful fast-feedback mechanism in every account, particularly during the period when developers are still getting used to least-privilege IAM patterns. Organisation SCPs set the ceiling, but the Lambda checker provides account-level visibility into policy drift below that ceiling.

**The default security group remediation Lambda.** MSB deploys a Lambda that detects and remediates default security groups that have been inadvertently opened. This is valuable in every account regardless of Organisation structure — default SG exposure is a common misconfiguration that SCPs alone do not catch.

**Regional SNS topics with email subscriptions.** Even with Security Hub aggregation providing a cross-account findings view in the Security account, per-account SNS topics with direct email subscriptions remain valuable. They give account owners immediate notification of security events in their own account without requiring them to log into the Security account. Keep the `NotificationsRegionalStack` pattern in every account.

---

## Further reading

- [AWS Control Tower documentation](https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html)
- [Enabling GuardDuty for an AWS Organization](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html)
- [Security Hub administrator and member accounts](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-accounts.html)
- [AWS Organizations best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices.html)
- [IAM Identity Center setup guide](https://docs.aws.amazon.com/singlesignon/latest/userguide/getting-started.html)
