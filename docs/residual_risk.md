# Residual Risk Assessment

This document outlines the security controls from AWS Foundational Security Best Practices (FSBP), CIS AWS Foundations Benchmark v3.0.0, and AWS Startup Security Baseline (SSB) that are not fully implemented in the AWS MSB CDK project, representing residual risk.

## Risk Assessment Matrix

| Risk Level | Impact | Description |
|------------|--------|-------------|
| **High** | Critical | Controls that, if not implemented, could lead to significant security incidents with major business impact |
| **Medium** | Significant | Controls that provide important security benefits but may have operational challenges or dependencies |
| **Low** | Moderate | Controls that enhance security posture but have limited impact if not implemented |

## Residual Risk Controls

### IAM Controls

| Control ID | Standard | Description | Risk Level | Reason for Exclusion |
|------------|----------|-------------|------------|----------------------|
| IAM.4 | FSBP | Hardware MFA for root account | Medium | Requires physical hardware; MSB focuses on programmatic controls |
| CIS 1.13 | CIS 3.0.0 | Ensure MFA is enabled for the "root" user | Medium | Requires manual setup; MSB monitors but can't enforce |
| CIS 1.4 | CIS 3.0.0 | Ensure no 'root' user access key exists | Medium | Requires operational procedure; MSB monitors but can't enforce removal |
| CIS 1.18 | CIS 3.0.0 | Ensure security contact information is registered | Low | Requires manual account configuration |
| SSB.IAM.8 | AWS SSB | Implement privileged access management | High | Requires additional tooling and processes beyond MSB |

### Data Protection Controls

| Control ID | Standard | Description | Risk Level | Reason for Exclusion |
|------------|----------|-------------|------------|----------------------|
| SSB.DAT.9 | AWS SSB | Implement data classification | Medium | Requires application-level controls and processes |
| SSB.DAT.10 | AWS SSB | Implement DLP controls | High | Requires additional tooling beyond infrastructure |

### Logging and Monitoring Controls

| Control ID | Standard | Description | Risk Level | Reason for Exclusion |
|------------|----------|-------------|------------|----------------------|
| CIS 3.3 | CIS 3.0.0 | Ensure CloudTrail log file validation is enabled | Low | Implemented but can't prevent future trails without validation |
| CIS 3.7 | CIS 3.0.0 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | Low | Implemented but can't prevent future trails without encryption |
| CIS 4.1-4.16 | CIS 3.0.0 | Various monitoring and alerting controls | Medium | MSB implements core monitoring but not all specific CIS monitoring recommendations |
| SSB.LOG.10 | AWS SSB | Implement centralized log management | Medium | MSB centralizes logs but doesn't implement full log analysis |

### Incident Response Controls

| Control ID | Standard | Description | Risk Level | Reason for Exclusion |
|------------|----------|-------------|------------|----------------------|
| SSB.IR.7 | AWS SSB | Develop incident response playbooks | High | Requires operational procedures beyond infrastructure |
| SSB.IR.8 | AWS SSB | Implement automated remediation | Medium | MSB provides alerts but limited automated remediation |
| SSB.IR.9 | AWS SSB | Conduct regular incident response exercises | Medium | Requires operational procedures beyond infrastructure |

### Network Security Controls

| Control ID | Standard | Description | Risk Level | Reason for Exclusion |
|------------|----------|-------------|------------|----------------------|
| CIS 5.5 | CIS 3.0.0 | Ensure routing tables for VPC peering are "least access" | Medium | MSB creates secure VPCs but doesn't manage peering connections |
| SSB.NET.9 | AWS SSB | Implement network segmentation | Low | MSB creates basic network segmentation but may not meet all requirements |
| SSB.NET.10 | AWS SSB | Implement WAF for web applications | High | Requires application-specific configuration |

## Risk Mitigation Recommendations

To address the residual risk from controls not fully implemented in the MSB:

### High Risk Controls

1. **Privileged Access Management (SSB.IAM.8)**
   - Implement AWS IAM Identity Center (formerly AWS SSO)
   - Consider third-party PAM solutions for advanced use cases
   - Implement just-in-time access for privileged operations
   - Code sample:
     ```python
     # Example of how to integrate with IAM Identity Center
     from aws_cdk import aws_sso as sso
     
     permission_set = sso.CfnPermissionSet(self, "AdminPermissionSet",
         instance_arn="arn:aws:sso:::instance/ssoins-xxxxxxxxx",
         name="AdminPermissionSet",
         session_duration="PT2H",
         managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"]
     )
     ```

2. **Data Loss Prevention (SSB.DAT.10)**
   - Implement Amazon Macie for sensitive data discovery
   - Configure S3 Object Lambda for content inspection
   - Consider third-party DLP solutions for comprehensive coverage
   - Code sample:
     ```python
     # Example of enabling Macie
     from aws_cdk import aws_macie as macie
     
     macie_session = macie.CfnSession(self, "MacieSession")
     ```

3. **Web Application Firewall (SSB.NET.10)**
   - Implement AWS WAF for web applications
   - Configure AWS WAF security automations
   - Create custom rules for application-specific threats
   - Code sample:
     ```python
     # Example of adding WAF to resources
     from aws_cdk import aws_wafv2 as wafv2
     
     web_acl = wafv2.CfnWebACL(self, "WebACL",
         default_action={"allow": {}},
         scope="REGIONAL",
         visibility_config={
             "cloudWatchMetricsEnabled": True,
             "metricName": "WebACLMetric",
             "sampledRequestsEnabled": True
         },
         rules=[
             {
                 "name": "AWS-AWSManagedRulesCommonRuleSet",
                 "priority": 0,
                 "statement": {
                     "managedRuleGroupStatement": {
                         "vendorName": "AWS",
                         "name": "AWSManagedRulesCommonRuleSet"
                     }
                 },
                 "overrideAction": {"none": {}},
                 "visibilityConfig": {
                     "cloudWatchMetricsEnabled": True,
                     "metricName": "AWS-AWSManagedRulesCommonRuleSet",
                     "sampledRequestsEnabled": True
                 }
             }
         ]
     )
     ```

4. **Incident Response Playbooks (SSB.IR.7)**
   - Develop documentation and playbooks for common security incidents
   - Integrate with AWS Systems Manager Incident Manager
   - Conduct regular tabletop exercises
   - Code sample:
     ```python
     # Example of setting up Systems Manager Incident Manager
     from aws_cdk import aws_ssm_incidents as incidents
     
     response_plan = incidents.CfnResponsePlan(self, "SecurityIncidentResponsePlan",
         name="security-incident-response",
         incident_template={
             "title": "Security Incident",
             "impact": 3
         },
         engagements=["arn:aws:ssm-contacts:region:account-id:contact/contact-name"]
     )
     ```

### Medium Risk Controls

1. **Root Account Security (IAM.4, CIS 1.13, CIS 1.4)**
   - Implement hardware MFA for the root account (manual process)
   - Regularly audit root account credentials
   - Establish operational procedures for root account management
   - Consider implementing break-glass procedures for root access

2. **Centralized Log Management (SSB.LOG.10)**
   - Enhance the logging stack to include log analysis capabilities
   - Consider integrating with Amazon OpenSearch Service
   - Code sample:
     ```python
     # Example of adding OpenSearch for log analysis
     from aws_cdk import aws_opensearchservice as opensearch
     
     log_analysis_domain = opensearch.Domain(self, "LogAnalysisDomain",
         version=opensearch.EngineVersion.OPENSEARCH_1_3,
         capacity={
             "master_nodes": 3,
             "data_nodes": 2
         },
         ebs={
             "volume_size": 100
         },
         encryption_at_rest={
             "enabled": True
         },
         node_to_node_encryption=True,
         enforce_https=True
     )
     ```

3. **Data Classification (SSB.DAT.9)**
   - Implement tagging strategies for data classification
   - Consider using Amazon Macie for automated data classification
   - Develop data handling procedures based on classification levels

### Low Risk Controls

1. **Security Contact Information (CIS 1.18)**
   - Manually register security contact information in the AWS account
   - Establish a process to keep contact information up to date

2. **Network Segmentation (SSB.NET.9)**
   - Enhance VPC design with additional security groups and NACLs
   - Implement Transit Gateway for advanced network segmentation
   - Code sample:
     ```python
     # Example of enhanced network segmentation
     app_tier_sg = ec2.SecurityGroup(self, "AppTierSG",
         vpc=vpc,
         description="Security group for application tier",
         allow_all_outbound=False
     )
     
     data_tier_sg = ec2.SecurityGroup(self, "DataTierSG",
         vpc=vpc,
         description="Security group for data tier",
         allow_all_outbound=False
     )
     
     # Allow only specific traffic between tiers
     app_tier_sg.add_ingress_rule(
         ec2.Peer.security_group_id(web_tier_sg.security_group_id),
         ec2.Port.tcp(8080),
         "Allow traffic from web tier"
     )
     ```

## Implementation Roadmap

To address the residual risk, consider the following implementation roadmap:

1. **Phase 1: High-Risk Controls** (1-2 months)
   - Implement Web Application Firewall (SSB.NET.10)
   - Set up privileged access management (SSB.IAM.8)
   - Develop incident response playbooks (SSB.IR.7)

2. **Phase 2: Medium-Risk Controls** (2-3 months)
   - Enhance root account security (IAM.4, CIS 1.13, CIS 1.4)
   - Set up centralized log management (SSB.LOG.10)
   - Implement data classification (SSB.DAT.9)

3. **Phase 3: Low-Risk Controls** (3-4 months)
   - Register security contact information (CIS 1.18)
   - Improve network segmentation (SSB.NET.9)

## Conclusion

While the AWS MSB CDK implementation provides a strong security foundation, addressing these residual risks will further enhance the security posture of your AWS environment. The implementation roadmap provides a structured approach to addressing these risks based on their priority.

Many of these residual risks require manual processes, operational procedures, or additional AWS services that go beyond the scope of infrastructure as code. Organizations should consider these risks as part of their overall security program and implement appropriate controls based on their specific requirements and risk tolerance.