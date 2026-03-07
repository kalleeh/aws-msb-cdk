# MSB Alert Response Runbook

**Audience:** Engineers receiving MSB security alerts who are not security specialists.
**Purpose:** Tell you exactly what to do when an alert arrives. No guessing.

---

## Before anything else: the First 30 Minutes protocol

When a Critical or High alert arrives and you do not yet know what it is, do these steps in order — even before reading the specific section for that alert type.

**1. Open CloudTrail → Event history**
Go to the AWS Console, search for "CloudTrail", click "Event history". Filter by time (last 1 hour). Look for anything that looks wrong: unusual API calls, calls from unfamiliar IP addresses, actions by the root user or an IAM user you don't recognize.

**2. Identify the IAM principal**
Every CloudTrail event includes a `userIdentity` field. Find the user, role, or service that made the call. Ask: do I recognize this principal? Did a human do this or was it automated?

**3. Check the source IP**
Every CloudTrail event includes `sourceIPAddress`. If it is a known AWS service (e.g., `ec2.amazonaws.com`) that is normal. If it is an external IP, look it up at https://ipinfo.io. If the IP is in a country where you have no users or operations, treat it as likely malicious.

**4. Check if the activity is still ongoing**
Filter CloudTrail to the last 15 minutes. Is the same principal still making calls? If yes, act immediately — do not wait to fully understand the situation before containing the threat.

**5. Contain before investigating**
If you suspect a compromised credential: go to IAM, find the user or role, and attach a deny-all inline policy or delete the access key. You can investigate afterward. The cost of containment is zero. The cost of not containing a live breach is not.

---

## 1. Root Account Activity

**Source:** EventBridge rules `msb-root-activity-monitoring` and `msb-root-api-activity-monitoring`

The root account is the master account with unlimited permissions — it can delete everything, remove billing protections, and bypass all IAM restrictions. After initial setup, it should never be used for day-to-day operations.

### 1.1 Root console sign-in alert

**What triggered it:** Someone signed into the AWS Console using the root email address and password (not an IAM user — the actual account owner credentials).

**Severity: Critical**

**First check:**
- Did you or a colleague intentionally log in as root in the last few minutes? (If yes: go to #false-positive below.)
- Is there an active incident (e.g., locked out of all IAM accounts) that required root access?

**If it's a real issue:**
1. Go to IAM → Credential report → verify if root access keys exist. If they do: delete them immediately under "Security credentials" for the root user.
2. Go to CloudTrail and find the root sign-in event. Check the source IP. If unrecognized, your root credentials may be compromised.
3. Change the root account password immediately: log into root, go to "Security credentials", change password.
4. If you cannot log in as root (attacker changed the password), initiate AWS account recovery via https://aws.amazon.com/support. Have your account ID, the email address, and a phone number registered to the account ready.
5. Review all IAM users for newly created accounts or modified permissions within the last 24 hours.
6. Review billing and check for resource creation in unexpected regions.

**If it's a false positive:**
Someone on your team logged in as root for a legitimate reason (e.g., rotating the root MFA device, recovering from a lockout). Confirm with that person, document the reason, and dismiss. Consider whether the task could have been done with an IAM user instead.

---

### 1.2 Root API activity alert

**What triggered it:** API calls were made to AWS using root credentials — this means someone used root access keys or a root session to call AWS APIs programmatically (not just the console).

**Severity: Critical**

**First check:**
- Does your root account have access keys configured? (It should not. Go to IAM → Root security credentials and check.)
- What API calls were made? Check CloudTrail. Look at `eventName` in the events.

**If it's a real issue:**
1. Go to IAM → Security credentials for root → delete any access keys immediately.
2. Review the CloudTrail events for what was done with root access. Look specifically for: CreateUser, AttachUserPolicy, PutBucketPolicy, CreateBucket, RunInstances.
3. If any resources were created: inventory them and delete what you did not authorize.
4. Rotate root password.
5. Verify MFA is still configured on the root account (it cannot be removed without root MFA — if MFA is gone, treat as full account compromise).

**If it's a false positive:**
Root API calls can be triggered by legitimate activities if someone used root credentials to run a script or CLI command. If a team member confirms this, verify exactly what they ran in CloudTrail and document it.

---

## 2. CloudWatch Alarms

**Source:** LoggingStack — CloudWatch metric filters on the CloudTrail log group, alarm names prefixed `MSB-`

These alarms watch CloudTrail in near-real-time (5-minute windows). They fire when the listed events appear in your account's API log.

A note on false positives: many of these alarms fire during normal infrastructure changes. If your team is actively deploying, doing CDK deploys, or running Terraform, expect these to fire. The key question is always: **did I authorize this activity?**

---

### 2.1 Unauthorized API calls (`MSB-UnauthorizedAPICalls`)

**What triggered it:** One or more API calls returned `AccessDenied` or `UnauthorizedOperation` errors. This means something (a user, a script, or an attacker) tried to call an AWS API and was denied by IAM policy.

**Severity: Medium**

**First check:**
- Check CloudTrail for recent `AccessDenied` events. What API was called? What principal called it?
- Is a Lambda function, application, or deployment pipeline running that might be hitting permissions issues?

**If it's a real issue:**
Multiple denials from an unrecognized principal — especially enumeration-style calls (DescribeInstances, ListBuckets, GetCallerIdentity in rapid succession) — indicate reconnaissance. An attacker with a stolen credential is probing what it can access.
1. Identify the principal in CloudTrail.
2. If it is an IAM user with an access key: revoke the key immediately.
3. If it is an assumed role: find which EC2 instance, Lambda, or service assumed it and investigate that resource.
4. Check GuardDuty — it may already have a finding for this activity.

**If it's a false positive:**
An application or Lambda has insufficient permissions and is generating errors. Check your application logs alongside CloudTrail to correlate. Fix the IAM policy for the application, which will also stop the alert.

---

### 2.2 Console sign-in without MFA (`MSB-ConsoleSignInWithoutMFA`)

**What triggered it:** An IAM user successfully logged into the AWS Console without using MFA. The filter matches only successful logins, not failures.

**Severity: High**

**First check:**
- Which IAM user logged in without MFA? Check CloudTrail for `ConsoleLogin` events.
- Is this a service account, a new hire, or someone whose MFA device was recently replaced?

**If it's a real issue:**
Console access without MFA means the account is secured only by password. If that password was leaked, an attacker has full console access with no second factor to stop them.
1. Go to IAM → find the user → force a password reset by disabling the console password.
2. Enable MFA on the account before re-enabling console access.
3. Audit what the user did during that session via CloudTrail (filter by username).

**If it's a false positive:**
A team member's MFA device broke or they recently got a new phone and haven't reconfigured the authenticator app. Help them set up MFA immediately, then re-enable their console access.

---

### 2.3 IAM policy changes (`MSB-IAMPolicyChanges`)

**What triggered it:** A change was made to IAM: a policy was created, deleted, or modified; a policy was attached or detached from a user, group, or role.

**Severity: High**

**First check:**
- Check CloudTrail for the specific event. What changed? Who made the change?
- Is this part of a known deployment (CDK deploy, Terraform run, manual IAM work)?

**If it's a real issue:**
Unexpected IAM policy changes — especially attaching `AdministratorAccess` to a user or role, or creating new users — are a strong indicator of privilege escalation. An attacker with limited access will attempt to grant themselves broader access.
1. Review the specific change in CloudTrail.
2. If an unexpected user or role was granted elevated permissions: remove those permissions immediately.
3. If a new IAM user was created that you do not recognize: disable the user and delete any access keys, then investigate.
4. Rotate credentials for any users the unexpected principal had access to modify.

**If it's a false positive:**
Your team made a legitimate IAM change. Verify with the person who made it, confirm it matches intent, and move on.

---

### 2.4 CloudTrail configuration changes (`MSB-CloudTrailConfigChanges`)

**What triggered it:** The CloudTrail trail was created, updated, deleted, or logging was started/stopped.

**Severity: Critical**

**First check:**
- Go to CloudTrail → Trails. Is the `msb-cloudtrail` trail still active and logging?
- Did anyone on your team make intentional changes to CloudTrail?

**If it's a real issue:**
Disabling CloudTrail is one of the first things an attacker does after gaining access — it erases the audit trail of their activity going forward. If `StopLogging` or `DeleteTrail` appears in CloudTrail:
1. Re-enable the trail immediately if it was stopped.
2. Assume that any activity between when logging stopped and when it was re-enabled is unlogged and unknown. You will not have a complete picture of what happened during that window.
3. Cross-reference GuardDuty findings and VPC flow logs to partially reconstruct activity during the gap.
4. Investigate who stopped logging and treat them as compromised.

**If it's a false positive:**
CDK or Terraform deployments that touch the logging stack will trigger this alarm. Confirm with your deployment log.

---

### 2.5 S3 bucket policy changes (`MSB-S3BucketPolicyChanges`)

**What triggered it:** A bucket ACL or policy was modified, or lifecycle/replication/CORS configuration was changed on an S3 bucket.

**Severity: High**

**First check:**
- Which bucket was affected? Check CloudTrail for the `PutBucketPolicy` or `PutBucketAcl` event and look at the `requestParameters` field.
- Was a bucket made public?

**If it's a real issue:**
Bucket policy changes that grant public access (`"Principal": "*"`) or grant access to unrecognized AWS accounts are serious. Sensitive data may now be publicly readable.
1. Go to S3 → the affected bucket → Permissions tab → review the bucket policy.
2. If the policy grants unintended access, revert it by pasting in the previous policy or removing the offending statement.
3. Enable S3 server access logging on the bucket temporarily to see if data was accessed during the exposure window.
4. Check CloudTrail for `GetObject` events on that bucket.

**If it's a false positive:**
Your deployment pipeline or a team member made a routine policy update. Confirm and verify the resulting policy is what was intended.

---

### 2.6 Security group changes (`MSB-SecurityGroupChanges`)

**What triggered it:** An inbound or outbound rule was added or removed from a security group, or a security group was created or deleted.

**Severity: Medium**

**First check:**
- What security group was modified and what was the change? Look at CloudTrail `AuthorizeSecurityGroupIngress` or similar events.
- Was port 22 (SSH), 3389 (RDP), or 0.0.0.0/0 (all traffic) opened?

**If it's a real issue:**
An attacker who has gained access may open inbound ports to create persistent access (backdoor). Opening 0.0.0.0/0 on any port is a red flag.
1. Go to EC2 → Security Groups → find the affected group.
2. Review the current rules. Remove any rules you did not authorize.
3. Check if any EC2 instances associated with this security group were accessed from the newly opened IP range or port (check VPC flow logs).

**If it's a false positive:**
Normal infrastructure work triggers this constantly. Confirm with whoever made the change.

---

### 2.7 Network ACL changes (`MSB-NACLChanges`)

**What triggered it:** A Network Access Control List (a VPC-level firewall) rule was created, modified, or deleted.

**Severity: Medium**

**First check:**
- Which NACL was changed? What rule was added or removed?
- NACLs are less commonly changed than security groups — unexpected NACL changes are more suspicious.

**If it's a real issue:**
An attacker may modify NACLs to either allow traffic in (creating access) or block traffic out (disruption, hiding exfiltration). A rule that denies all outbound traffic could be a ransomware-style disruption.
1. Go to VPC → Network ACLs. Find the affected NACL.
2. Review the rule set. Compare against your known baseline.
3. Revert any unauthorized rules.

**If it's a false positive:**
CDK/Terraform network stack deployments, or a network engineer making manual changes. Confirm.

---

### 2.8 VPC changes (`MSB-VPCChanges`)

**What triggered it:** A VPC was created, deleted, or modified — including VPC peering connections being created or accepted.

**Severity: Medium**

**First check:**
- What VPC event occurred? New VPC creation is relatively common. VPC peering acceptance is more unusual.
- Was a VPC peering connection accepted that you did not initiate?

**If it's a real issue:**
An accepted VPC peering connection from an unrecognized account could allow an external party to route traffic into your network.
1. Go to VPC → Peering Connections. Review all connections.
2. Delete any connections you did not create.
3. Review route tables to see if routes to the peer were already added.

**If it's a false positive:**
Your team is building out VPC infrastructure. Confirm the specific event was authorized.

---

### 2.9 KMS key changes/deletion (`MSB-KMSKeyChanges`)

**What triggered it:** A KMS customer-managed key was disabled or scheduled for deletion.

**Severity: Critical**

**First check:**
- Which key was disabled or scheduled for deletion? Check CloudTrail for `DisableKey` or `ScheduleKeyDeletion`.
- Is any data (S3, RDS, EBS, Secrets Manager) encrypted with this key? If deleted, that data becomes permanently unreadable.

**If it's a real issue:**
Deleting KMS keys is irreversible after the deletion window (7-30 days). This could be ransomware-style data destruction.
1. Go to KMS → Customer-managed keys. Find the key.
2. If scheduled for deletion: click "Cancel key deletion" immediately.
3. If already disabled: re-enable it.
4. Identify what resources use this key. If those resources are critical, treat this as a high-severity incident.
5. Investigate who made the change.

**If it's a false positive:**
A cleanup operation or CDK stack destroy. Confirm that the key is not protecting any live data before allowing deletion.

---

### 2.10 Route table changes (`MSB-RouteTableChanges`)

**What triggered it:** A route was added, changed, or removed in a VPC route table, or a route table was created, deleted, or disassociated from a subnet.

**Severity: Medium**

**First check:**
- What route was changed? Adding a route to an internet gateway or new VPN endpoint is more suspicious than routine CDK updates.
- Does the change route traffic somewhere unexpected (e.g., to an unrecognized gateway)?

**If it's a real issue:**
An attacker could add a route to redirect traffic to a gateway they control (traffic interception). They could also remove routes to cause outages.
1. Go to VPC → Route Tables. Review the current state against your expected network design.
2. Revert any unauthorized routes.
3. Check VPC flow logs to see if any traffic was affected.

**If it's a false positive:**
CDK/Terraform networking stack deployments. Confirm.

---

### 2.11 Network gateway changes (`MSB-NetworkGatewayChanges`)

**What triggered it:** An internet gateway or customer gateway was created, deleted, or attached/detached to a VPC.

**Severity: High**

**First check:**
- What gateway was affected? Detaching the internet gateway from your production VPC would cause an outage. Attaching one to an internal-only VPC would create unexpected internet exposure.
- Is this change consistent with your network architecture?

**If it's a real issue:**
Unauthorized internet gateway attachment to a private VPC can expose workloads that were designed to have no internet access.
1. Go to VPC → Internet Gateways. Verify the attachment state.
2. If incorrectly attached: detach it.
3. Review route tables — an internet gateway with no routes pointing to it is harmless. Routes pointing to it are the actual exposure.

**If it's a false positive:**
Network infrastructure changes in CDK/Terraform. Confirm.

---

### 2.12 Config service changes (`MSB-AWSConfigChanges`)

**What triggered it:** AWS Config was stopped, its delivery channel was deleted or modified, or its configuration recorder was modified.

**Severity: Critical**

**First check:**
- Is AWS Config still recording? Go to Config → Settings and check.
- Did anyone intentionally modify Config as part of a deployment?

**If it's a real issue:**
Stopping Config is similar to stopping CloudTrail — it eliminates the configuration change audit trail. An attacker does this to hide changes to resources.
1. Go to Config → Settings → restart the configuration recorder if it was stopped.
2. Investigate who stopped it and when, and what configuration changes occurred during the gap.
3. Review the specific Config rules that are now non-compliant due to missed evaluations.

**If it's a false positive:**
CDK deployments that touch the Config stack. Confirm.

---

### 2.13 Failed console sign-in attempts (`MSB-ConsoleAuthFailures`)

**What triggered it:** Three or more failed console login attempts occurred within 5 minutes.

**Severity: Medium**

**First check:**
- Which IAM username was the target? Check CloudTrail for `ConsoleLogin` events with `errorMessage: "Failed authentication"`.
- Is the username a real user on your team or a guessed username (e.g., `admin`, `administrator`, `root`)?

**If it's a real issue:**
Three failures in 5 minutes from an unrecognized IP targeting a real username indicates a credential stuffing or brute force attack. If the account eventually succeeded (check for a successful `ConsoleLogin` after the failures), treat this as a breach.
1. If the username is real: temporarily disable console access for that user until you've confirmed the situation.
2. Force a password reset.
3. Verify MFA is enabled — if it is, failed logins are less dangerous (MFA would block completion even with the correct password).
4. If failures are coming from a specific IP: consider adding a WAF or IP-based restriction if your users always access from known IPs.

**If it's a false positive:**
A team member forgot their password and tried multiple times, or a misconfigured automated tool is attempting to authenticate. Confirm with the team.

---

## 3. GuardDuty Findings

**Source:** EventBridge rule `msb-guardduty-findings` — fires for every GuardDuty finding

GuardDuty findings arrive as JSON in the email. The key fields are:
- `detail.type` — the finding category (e.g., `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`)
- `detail.severity` — a number from 0-10 (7+ is High/Critical, 4-7 is Medium, below 4 is Low/Informational)
- `detail.description` — plain English description of what happened
- `detail.resource` — what AWS resource was involved
- `detail.service.action` — what action was detected

Go to the GuardDuty console and click the finding for full context and recommended remediation steps. GuardDuty's built-in remediation guidance is good — use it.

---

### 3.1 UnauthorizedAccess findings

**Examples:** `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`, `UnauthorizedAccess:IAMUser/MaliciousIPCaller`

**What triggered it:** An IAM credential was used from an unusual location (country or IP range not seen before for this account) or from a known-malicious IP address (GuardDuty maintains threat intelligence feeds).

**Severity: High to Critical**

**First check:**
- Does the location match anywhere your team operates? Check the `geoLocation` field in the finding.
- Is there a VPN or proxy involved? Some team members using VPNs appear to come from unexpected locations.

**If it's a real issue:**
1. Go to IAM → find the user or role in the finding.
2. If it is an IAM user with an access key: delete the access key immediately.
3. If it is an assumed role on an EC2 instance: stop the instance and investigate.
4. Review CloudTrail for all activity by this principal in the last 24 hours.
5. Look for: data exfiltration (GetObject on S3), new resource creation (RunInstances), IAM changes (CreateUser, AttachPolicy).

**If it's a false positive:**
Team member using a VPN or traveling abroad. Confirm their location, then archive the finding in GuardDuty with a note.

---

### 3.2 Recon findings

**Examples:** `Recon:EC2/PortProbeUnprotectedPort`, `Recon:IAMUser/NetworkPermissions`

**What triggered it:** Something is scanning your infrastructure. Port scanning on EC2 instances is external probing of open ports. IAM-based recon means an IAM credential is being used to enumerate what resources are accessible.

**Severity: Medium**

**First check:**
- Is this EC2 port scan against an instance that is supposed to be internet-facing? External port scans on publicly accessible services are normal internet background noise.
- If it is IAM-based recon: is the principal a known service or a suspicious actor?

**If it's a real issue (IAM recon):**
Enumeration by a compromised credential is a precursor to actual exploitation. Follow the same steps as 3.1 — revoke the credential and review CloudTrail history.

**If it's a false positive (EC2 port scan):**
Port scanning of internet-facing IPs is routine background internet activity. If the instance has no open ports it should not have, no action needed. Archive in GuardDuty.

---

### 3.3 CryptoCurrency findings

**Examples:** `CryptoCurrency:EC2/BitcoinTool.B`, `CryptoCurrency:Lambda/BitcoinTool.B`

**What triggered it:** An EC2 instance or Lambda function is communicating with cryptocurrency mining pool infrastructure. This almost always means the resource has been compromised and is being used to mine cryptocurrency for someone else.

**Severity: High**

**First check:**
- Which resource is involved? Is it an EC2 instance or a Lambda function?
- When was it created? Is it a resource your team deployed?

**If it's a real issue:**
This is a confirmed compromise. The resource is running attacker-controlled code.
1. If EC2: immediately stop the instance (not terminate — you may want to preserve evidence). Take a snapshot if you need the data. Do not restart it.
2. If Lambda: throttle the function (set reserved concurrency to 0 in Lambda settings). Then investigate how the code was deployed — was the Lambda code modified?
3. Check your deployment pipeline for signs of code injection.
4. Check IAM: what role does the resource run as? Audit all activity by that role in the last 72 hours.
5. Rotate any secrets or credentials that may have been accessible from the compromised resource (environment variables, Secrets Manager — check if GetSecretValue was called from that instance/function).

**If it's a false positive:**
Extremely unlikely for crypto mining findings. GuardDuty is highly confident on these. Treat as real until proven otherwise.

---

### 3.4 Trojan / Malware findings

**Examples:** `Trojan:EC2/BlackholeTraffic`, `Malware:EC2/MaliciousFile` (from EBS scanning)

**What triggered it:** GuardDuty's EBS malware protection scanned the file system of an EC2 instance and found a malicious file, or an instance is communicating with known malware command-and-control infrastructure.

**Severity: Critical**

**First check:**
- What instance is affected?
- Is this instance internet-facing or internal?
- What services run on this instance?

**If it's a real issue:**
1. Isolate the instance: modify its security group to deny all inbound and outbound traffic (replace current rules with a deny-all security group).
2. Do not terminate yet — you need to preserve evidence and understand the blast radius.
3. Check what IAM permissions the instance role has, and whether any API calls were made from the instance to S3, Secrets Manager, or other sensitive services in the last 24 hours.
4. Assess whether any data on the instance is sensitive and whether it may have been exfiltrated.
5. Rebuild the instance from a known-good AMI. Do not attempt to "clean" a compromised instance — rebuild it.
6. Investigate how the malware got there: was it a vulnerable application, a malicious package, or a deployment pipeline issue?

**If it's a false positive:**
GuardDuty EBS scanning occasionally flags legitimate security tools (penetration testing tools, vulnerability scanners). Check what files are flagged in the finding detail before taking action.

---

### 3.5 Policy:S3/BucketPublicAccessGranted

**What triggered it:** GuardDuty detected that an S3 bucket's access controls were changed to make the bucket publicly accessible (accessible by anyone on the internet without authentication).

**Severity: High**

**First check:**
- Which bucket? What does it contain?
- Was this intentional (e.g., a public static website)?

**If it's a real issue:**
1. Go to S3 → the bucket → Permissions → review the bucket policy and ACL.
2. If the bucket contains sensitive data: remove the public access immediately. Go to S3 Permissions tab → edit Block Public Access settings → enable all four settings.
3. Enable S3 server access logging and check for any GetObject requests that came in during the exposure window.
4. Determine who modified the policy and whether it was intentional.

**If it's a false positive:**
You intentionally host a public static website or public assets from this bucket. In that case, ensure the bucket contains only the files that should be public. Verify the bucket policy does not grant `s3:*` (all actions) — it should only grant `s3:GetObject`.

---

## 4. Security Hub Findings

**Source:** EventBridge rule `msb-security-hub-findings` — fires for all Security Hub findings as they are imported

Security Hub continuously evaluates your account against two standards:
- **FSBP** (AWS Foundational Security Best Practices) — AWS-specific controls
- **CIS v3.0.0** (CIS AWS Foundations Benchmark) — industry benchmark controls

### Understanding the email

Security Hub alerts can be high volume — it will send alerts for every finding it imports. Severity levels are:
- **CRITICAL** (score 90-100): Act immediately. These represent serious misconfigurations with high exploitability.
- **HIGH** (70-89): Address within 24-48 hours.
- **MEDIUM** (40-69): Schedule for the next sprint.
- **LOW/INFORMATIONAL** (0-39): Fix when convenient.

### Triaging in the console

Rather than responding to each individual email, use the Security Hub console as your source of truth:

1. Go to Security Hub → Findings.
2. Filter by `Workflow status = NEW` and `Severity = CRITICAL` first.
3. Work through Critical findings. For each: click the finding title for the full description including AWS remediation guidance.
4. Mark findings as `RESOLVED` after fixing, or `SUPPRESSED` if they are intentional accepted risks.
5. Repeat for HIGH findings.

### FSBP vs CIS — what the difference means

Both standards overlap heavily. FSBP (e.g., `EC2.6`, `S3.1`, `IAM.4`) uses AWS-native IDs and tends to be more specific to AWS services. CIS (e.g., `CIS 2.1.2`, `CIS 3.5`) maps to the CIS Benchmark publication and is often referenced in compliance audits.

If you see the same resource flagged by both FSBP and CIS, fixing it once resolves both findings.

### Findings to always act on immediately

- Any finding containing "public access" for an S3 bucket
- Any finding containing "security group" that allows 0.0.0.0/0 on port 22 or 3389
- `IAM.1` — IAM policies with `*:*` (full admin access) attached directly to users
- `EC2.2` — default VPC security group is not restricted (the MSB handles this automatically, but if it fires, investigate)
- `CloudTrail.1` or `CloudTrail.2` — CloudTrail disabled or not encrypting logs
- `KMS.4` — KMS key rotation disabled

### Findings that are expected / suppressed by MSB

The MSB automatically suppresses two Security Hub findings that require manual account-level actions:
- `Account.1` (security contact not set) — set this manually in AWS Billing and Cost Management → Account Settings
- `IAM.4`, `IAM.6`, `IAM.9` (hardware MFA for root) — requires a physical hardware MFA device

---

## 5. IAM Policy Checker

**Source:** IAMStack Lambda `msb-iam-policy-checker` — runs daily and on `AttachUserPolicy` / `PutUserPolicy` events

### Alert: "IAM users with policies attached directly"

**What triggered it:** One or more IAM users have managed or inline policies attached directly to them, rather than being a member of an IAM group that has the policy.

**Severity: Low**

**What it means:** Best practice is to assign permissions to groups, not individual users. When permissions are on individual users, it is harder to audit who has what access, and easier to accidentally grant too much access to one person.

**How to fix it:**

1. Go to IAM → Users → click the flagged user → Permissions tab.
2. Note what policies are directly attached (both inline and managed).
3. Find or create an IAM group with an equivalent policy.
4. Add the user to that group.
5. Remove the directly-attached policies from the user.

Example: if a user has `AmazonS3ReadOnlyAccess` attached directly, create a group called `s3-read-only`, attach the policy to the group, add the user to the group, and remove the policy from the user.

**If you cannot immediately fix it:**
This is Low severity. It does not indicate active compromise. Schedule it for your next sprint and document the exception.

---

## 6. Default Security Group Secured

**Source:** NetworkSecurityStack Lambda `msb-secure-default-sg` — runs daily and on security group change events

### Alert: "Default Security Groups Secured"

**What triggered it:** The MSB Lambda found one or more VPC default security groups that had inbound or outbound rules configured, and automatically removed those rules.

**Severity: Low (notification, not an incident)**

**What this is:** Every VPC comes with a "default" security group. If you launch an EC2 instance or RDS database without specifying a security group, it gets the default one. The problem: if the default security group has permissive rules (e.g., allows all traffic), then any resource accidentally launched without a security group specified becomes exposed.

The MSB Lambda removes all rules from the default security group so it denies all traffic by default.

**What to check:**

1. Look at the email — which VPCs and security group IDs were affected?
2. Ask: are any resources currently associated with those default security groups? Go to EC2 → Security Groups → find the default SG for each VPC → check the "Associated resources" tab.
3. If resources are attached to the now-empty default SG: they may have lost network connectivity. Move those resources to a properly configured security group.

**If those rules were intentional:**
You should create a named security group with those rules and assign it explicitly to your resources. Do not use the default SG for actual workloads — its purpose is to be empty.

---

## 7. S3 Public Access Block Enforced

**Source:** S3SecurityStack Lambda `msb-s3-public-access-checker` — runs daily and on `CreateBucket` events

### Alert: "S3 Bucket Public Access Block Enforcement"

**What triggered it:** The MSB Lambda found one or more S3 buckets where the public access block settings were not fully enabled, and automatically enabled them.

**Severity: Low to High** (depends on what was in the bucket)

**What this means:** The MSB enforces four S3 public access block settings on every bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. If any of those were off for a bucket, the Lambda turned them on.

**What to check:**

1. Look at the `enforced_buckets` list in the email. These buckets had their public access blocks enabled by the Lambda.
2. For each bucket: go to S3 → the bucket → Properties. What does it contain? Is it sensitive?
3. Was the bucket publicly accessible before the Lambda ran? Check S3 server access logs or CloudTrail for recent GetObject calls from unauthenticated (public) sources.
4. Why was the block off? Was it a new bucket that was incorrectly configured, or an intentional public bucket?

**If you need a legitimately public bucket (e.g., static website hosting):**

The account-level public access block is already set to block all by default. You will need to:
1. Use CloudFront to serve public content from a private S3 bucket — this is the recommended pattern and avoids needing the bucket itself to be public.
2. If you absolutely need a public bucket: this requires modifying the MSB configuration to exclude that bucket from enforcement. Discuss with your security owner before doing this. You should not disable account-level public access blocks.

**Failed buckets:**
If the `failed_buckets` list is non-empty: the Lambda could not enforce the block on those buckets. This requires manual action. Go to each bucket and enable public access block manually.

---

## 8. Inspector Findings

**Source:** SecurityRegionalStack EventBridge rule `msb-inspector-findings` — fires for all Inspector v2 findings

Inspector scans your EC2 instances (OS packages), ECR container images, and Lambda function packages for known CVEs (software vulnerabilities).

### Alert: Critical or High CVE finding

**What triggered it:** Inspector found a package on an EC2 instance, in a container image, or in a Lambda layer that has a known CVE (software vulnerability) with a High or Critical score.

**Severity: High to Critical** (based on Inspector's severity score)

**What the alert includes:**
- The resource affected (instance ID, image URI, or Lambda function name)
- The package name and version
- The CVE identifier (e.g., CVE-2024-XXXX)
- The fixed version (if available)

**First check:**
- Is the resource internet-facing? A CVE in a library on an instance that is not internet-accessible is much less urgent than one on a public-facing instance.
- Is there a fix available? Check the `fixedVersion` field in the finding.

**If there is a fix available:**
1. For EC2: SSH into the instance and run the package manager update (`apt upgrade <package-name>` or `yum update <package-name>`). Or redeploy the instance from an updated AMI.
2. For Lambda: update the dependency in your `requirements.txt` or `package.json`, rebuild the deployment package, and redeploy the function.
3. For ECR/containers: update the base image or the affected package in your Dockerfile, rebuild the image, and push it to ECR. Redeploy any running containers from the updated image.
4. After patching: the finding will be re-evaluated by Inspector automatically. It will move to CLOSED once the vulnerable version is no longer detected.

**If there is no fix available:**
Note the CVE, monitor it for a fix, and consider compensating controls (e.g., restrict network access to the affected resource, add WAF rules if the CVE is web-exploitable).

**Volume note:** Inspector will generate findings for every vulnerability it finds. On a new account with existing instances, you may get a large number of findings at initial activation. Prioritize by severity and by whether the resource is internet-facing.

---

## 9. Macie Findings

**Source:** SecurityRegionalStack EventBridge rule `msb-macie-findings` — fires for all Macie findings

Macie scans S3 buckets for sensitive data: credentials, PII (names, email addresses, phone numbers, government IDs), financial data, and other categories defined by AWS managed identifiers.

### Alert: Sensitive data discovered in S3

**What triggered it:** Macie found files in an S3 bucket that appear to contain sensitive data.

**Severity tiers:**
- **CRITICAL/HIGH**: Credentials (API keys, passwords, private keys) found in S3. Act within hours.
- **MEDIUM**: PII such as names with associated email addresses, social security numbers, credit card numbers. Act within 24-48 hours.
- **LOW**: Less specific PII (email addresses alone, phone numbers). Review and assess.

**First check for credential findings (Critical):**
- What file contains the credentials? Go to the Macie console → Findings → click the finding for the specific file path.
- Are those credentials active? If you find an AWS access key in a file: go to IAM and check if that key exists and is still active.

**If credentials are found in S3:**
1. If they are active credentials: rotate/revoke them immediately. This is the most urgent action.
2. Determine how long the credentials have been in S3. Check S3 access logs for any GetObject requests on that file from unexpected principals.
3. Remove the credentials from the S3 file. Committed secrets should also be removed from git history if they came from version control.
4. Check CloudTrail for activity by those credentials during the exposure window.

**If PII is found in S3:**
1. Determine if the data should be in S3. Is it a data lake, a backup, or something that ended up there accidentally?
2. If it should not be there: move or delete it.
3. If it should be there but needs better protection: ensure the bucket has encryption enabled, access logging enabled, and appropriate bucket policies restricting access to specific IAM principals.
4. If this is a regulated category (e.g., financial data subject to PCI DSS, health data subject to HIPAA): escalate immediately — this may trigger a compliance obligation.

**Volume note:** Macie will generate findings for every object it analyzes. Run Macie's classification jobs selectively (targeted at buckets likely to contain sensitive data) rather than scanning all buckets at once if volume becomes overwhelming.

---

## Appendix: Quick-reference severity guide

| Alert | Severity | Typical response time |
|---|---|---|
| Root account sign-in | Critical | Immediate |
| Root API activity | Critical | Immediate |
| CloudTrail stopped | Critical | Immediate |
| AWS Config stopped | Critical | Immediate |
| KMS key deletion | Critical | Immediate |
| Malware on EC2 | Critical | Immediate |
| Crypto mining detected | High | Within 1 hour |
| Console login without MFA | High | Within 4 hours |
| IAM policy changes (unexpected) | High | Within 4 hours |
| UnauthorizedAccess GuardDuty | High | Within 4 hours |
| S3 bucket made public | High | Within 4 hours |
| Credentials found in S3 (Macie) | High | Within 4 hours |
| Security group changes (unexpected) | Medium | Within 24 hours |
| Failed console logins | Medium | Within 24 hours |
| Unauthorized API calls | Medium | Within 24 hours |
| Security Hub HIGH findings | High | Within 48 hours |
| Security Hub MEDIUM findings | Medium | Next sprint |
| IAM direct policy attachment | Low | Next sprint |
| Default SG secured (notification) | Low | Next sprint |
| S3 public access block enforced | Low | Review and confirm |
| Inspector findings (no internet exposure) | Medium | Next sprint |
