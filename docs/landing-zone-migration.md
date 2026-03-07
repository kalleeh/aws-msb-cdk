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

## What carries over automatically

These MSB components migrate to a Landing Zone architecture without being rebuilt — they just get promoted to Organisation-level equivalents.

**GuardDuty.** Enable GuardDuty as an Organisation delegated admin from the management or Security account. Existing detector configurations and findings history in the original account stay intact. New accounts added to the Organisation automatically get GuardDuty enabled with the same protection plan settings. MSB's protection plan configuration (S3, EBS malware, runtime monitoring, RDS login events, Lambda network logs) carries over as the Organisation default.

**Security Hub.** Same pattern. Designate a Security Hub administrator account, and findings from all member accounts aggregate into a single view. The FSBP v1.0.0 and CIS v3.0.0 standards MSB enables become the Organisation standard. MSB's automation rules (suppressing Account.1, root MFA hardware controls) can be promoted to Organisation-wide automation rules.

**CloudTrail.** Replace the per-account trail (`msb-cloudtrail`) with an Organisation Trail created from the management account. One Organisation Trail covers all current and future accounts automatically — no need to deploy the `LoggingStack` trail into each new account. The central S3 logs bucket (`msb-logs-{account}-{region}`) becomes the Organisation-wide log archive; redirect the Organisation Trail to a dedicated log archive account bucket.

**AWS Config.** Replace per-account Config recorders with an Organisation Config aggregator. Config rules can be promoted to Organisation conformance packs, which deploy automatically to all member accounts. MSB's ~30 managed rules (`ComplianceStack`) become the baseline conformance pack.

**KMS keys.** The five CMKs created by `KMSStack` (master, CloudTrail, S3, RDS, EBS) stay in the originating account. Cross-account access can be granted via key policy if other accounts need to read encrypted data (e.g., cross-account RDS snapshots, S3 replication). There is no automatic migration needed.

**SNS alerting.** The per-region SNS topics created by `LoggingStack` and `NotificationsRegionalStack` continue working in the original account. In a multi-account setup, you typically add Security Hub finding aggregation and route critical findings through a central Security account SNS topic, while keeping the per-account topics for account-specific operational alerts.

---

## What needs to be rebuilt

These components do not have a direct lift-and-shift path. They need to be replaced or re-architected.

**IAM users.** MSB's `IAMStack` creates IAM users and enforces MFA via IAM policies and a Lambda checker. In Landing Zone, these are replaced by IAM Identity Center (SSO) with permission sets mapped to your identity provider (Google Workspace, Okta, Azure AD, or the built-in Identity Center directory). IAM users in individual accounts are deprecated. This is the most disruptive change operationally — engineers need to update their AWS CLI configuration to use SSO profiles.

**Single-account VPC.** MSB's `VpcStack` creates a standalone VPC (`10.0.0.0/16`) per region with a NAT gateway and VPC interface endpoints. In a multi-account Landing Zone, networking moves to a shared Network account using either a Transit Gateway hub-and-spoke pattern or AWS Network Firewall with centralised egress. The MSB VPC gets decommissioned in favour of VPC attachments to the central Transit Gateway. Workloads in dev and prod accounts connect to the shared network account rather than each having their own VPCs with duplicate NAT gateways and endpoints.

**Per-account Config rules.** MSB's `ComplianceStack` deploys ~30 managed Config rules directly into each account. In an Organisation, these are replaced by Organisation Config conformance packs deployed from the management or delegated admin account. Individual account Config recorders remain active, but the rules are managed centrally.

**MSB CDK stacks.** The MSB stacks themselves need to be deployed into each new account as it is created. This should be automated via a pipeline — CodePipeline with CloudFormation StackSets, or GitHub Actions with OIDC federation. You should not be running `cdk deploy` manually into each account. Account vending (creating new accounts with baseline controls pre-applied) is a core Control Tower feature; MSB becomes the customisation layer applied on top of Control Tower's baseline via Control Tower Account Factory Customization (AFC) or a post-creation hook.

---

## Migration path (step by step)

This is a sequential process. Do not skip steps.

**1. Create an AWS Organisation and enable all features.**
From your existing AWS account (which becomes the management account), go to AWS Organizations and create an Organisation. Enable all features, not just consolidated billing. This unlocks SCPs, trusted access for services, and delegated admin accounts.

**2. Create a dedicated Security/Audit account.**
Do not use the management account for security tooling. Create a Security account (also called an Audit account) as a member of the Organisation. This account will become the GuardDuty administrator, Security Hub administrator, and the destination for your central CloudTrail log archive. The original MSB account (your existing production account) can remain as-is while you set up the structure around it.

**3. Enable Control Tower.**
Enable Control Tower from the management account. Control Tower will set up Landing Zone, create a Log Archive account, enroll your existing accounts where possible, and deploy baseline SCPs. It will detect existing GuardDuty and Security Hub configurations and prompt you to adopt them. Follow the Control Tower console through this process — it handles most of the Organisation-level enablement automatically.

**4. Deploy MSB into each new account as you create them.**
When you create dev and prod accounts through Control Tower Account Factory, deploy MSB via your pipeline immediately after provisioning. New accounts get the full security baseline (GuardDuty detector, Security Hub standards, Config recorder, CloudWatch alarms, KMS keys) automatically. The Organisation-level GuardDuty and Security Hub will pick up these accounts as members automatically once enrolled.

**5. Replace IAM users with Identity Center permission sets.**
Set up IAM Identity Center in the management account. Connect it to your identity provider or use the built-in directory. Create permission sets that mirror the access patterns your team currently has (read-only, developer, admin). Migrate engineers one at a time by creating their Identity Center assignment, confirming SSO access works, then removing their IAM user. MSB's IAM policy checker Lambda (`IAMStack`) can remain active during the transition as a safety net.

**6. Set up SCPs for baseline guardrails.**
Control Tower deploys a set of mandatory and strongly recommended SCPs. Add your own for any controls MSB cannot enforce at the account level: denying specific high-risk regions, preventing CloudTrail from being disabled, requiring MFA for sensitive API calls. SCPs in the Organisation enforce these guarantees regardless of account-level IAM configuration.

**7. Decommission the single-account VPC in favour of shared networking.**
Once workloads have migrated to the multi-account structure and Transit Gateway (or equivalent) is in place, remove the MSB VPC stack from the original account. Migrating workloads off the standalone VPC is the most time-consuming part of the overall Landing Zone migration — plan for it to take weeks, not days.

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
