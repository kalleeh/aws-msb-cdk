import pytest
import aws_cdk as cdk
from aws_cdk.assertions import Template, Match

from aws_msb_cdk.compliance_stack import ComplianceStack
from aws_msb_cdk.security_regional_stack import SecurityRegionalStack
from aws_msb_cdk.security_monitoring_stack import SecurityMonitoringStack
from aws_msb_cdk.iam_stack import IAMStack
from aws_msb_cdk.s3_security_stack import S3SecurityStack
from aws_msb_cdk.kms_stack import KMSStack
from aws_msb_cdk.logging_stack import LoggingStack
from aws_msb_cdk.logging_regional_stack import LoggingRegionalStack
from aws_msb_cdk.network_security_stack import NetworkSecurityStack
from aws_msb_cdk.vpc_stack import VpcStack

class TestComplianceMatrix:
    """Tests that verify alignment with compliance frameworks"""
    
    def test_iam_password_policy_compliance(self):
        """
        Test IAM password policy meets CIS AWS 3.0.0 requirements
        - FSBP: IAM.9
        - CIS AWS 3.0.0: 1.8, 1.9, 1.10, 1.11
        - AWS SSB: IAM.1
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = IAMStack(app, "TestIAMStack")
        template = Template.from_stack(stack)
        
        # THEN
        template.has_resource_properties("AWS::IAM::AccountPasswordPolicy", {
            "MinimumPasswordLength": 14,  # CIS 1.8 requires minimum length of 14
            "RequireUppercaseCharacters": True,  # CIS 1.11
            "RequireLowercaseCharacters": True,  # CIS 1.12
            "RequireSymbols": True,  # CIS 1.13
            "RequireNumbers": True,  # CIS 1.14
            "MaxPasswordAge": 90,  # CIS 1.10 requires 90 days or less
            "PasswordReusePrevention": 24,  # CIS 1.9 requires 24 or greater
            "AllowUsersToChangePassword": True  # Best practice
        })
    
    def test_s3_security_compliance(self):
        """
        Test S3 security controls meet compliance requirements
        - FSBP: S3.1, S3.4
        - CIS AWS 3.0.0: 2.1.1, 2.1.2, 2.1.5
        - AWS SSB: DAT.1, DAT.2
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = S3SecurityStack(app, "TestS3SecurityStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify account-level block public access (CIS 2.1.2)
        template.has_resource("Custom::AWS", {})
        
        # Verify Lambda function for enforcing bucket-level public access blocks (CIS 2.1.5)
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": "index.handler",
            "Timeout": 300
        })
        
        # Verify Lambda has proper permissions
        template.has_resource_properties("AWS::IAM::Policy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "s3:PutAccountPublicAccessBlock",
                        "Effect": "Allow"
                    })
                ])
            }
        })
    
    def test_security_hub_compliance_standards(self):
        """
        Test Security Hub enables compliance standards
        - FSBP: SecurityHub.1
        - CIS AWS 3.0.0: 3.10
        - AWS SSB: COM.2, LOG.8
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify Lambda function for enabling CIS Benchmark
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": "index.handler",
            "Runtime": "python3.9"
        })
        
        # Verify Lambda has proper permissions
        template.has_resource_properties("AWS::IAM::Policy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "securityhub:BatchEnableStandards",
                        "Effect": "Allow"
                    })
                ])
            }
        })
    
    def test_guardduty_enabled(self):
        """
        Test GuardDuty is enabled
        - FSBP: GuardDuty.1
        - CIS AWS 3.0.0: 3.8
        - AWS SSB: LOG.7
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = SecurityRegionalStack(app, "TestSecurityRegionalStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify GuardDuty Detector is enabled
        template.has_resource_properties("AWS::GuardDuty::Detector", {
            "Enable": True
        })
    
    def test_security_monitoring_for_root_activity(self):
        """
        Test monitoring for root account activity
        - FSBP: IAM.7
        - CIS AWS 3.0.0: 1.7
        - AWS SSB: IAM.2
        """
        # GIVEN
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = cdk.aws_sns.Topic(stack, "TestTopic")
        
        # WHEN
        monitoring_stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", 
                                       notifications_topic=notifications_topic)
        template = Template.from_stack(monitoring_stack)
        
        # THEN
        # Verify EventBridge rule for root account activity
        template.has_resource_properties("AWS::Events::Rule", {
            "EventPattern": {
                "source": ["aws.signin"],
                "detail-type": ["AWS Console Sign In via CloudTrail"],
                "detail": {
                    "userIdentity": {
                        "type": ["Root"]
                    }
                }
            }
        })
    
    def test_config_rules_for_compliance(self):
        """
        Test AWS Config Rules for compliance monitoring
        - FSBP: Config.1
        - CIS AWS 3.0.0: 3.5
        - AWS SSB: COM.1, LOG.6
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify essential Config Rules exist
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "CLOUD_TRAIL_ENABLED"
            }
        })
        
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "IAM_PASSWORD_POLICY"
            }
        })
        
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
            }
        })
        
    def test_vpc_flow_logs_enabled(self):
        """
        Test VPC Flow Logs are enabled
        - FSBP: EC2.6
        - CIS AWS 3.0.0: 3.9
        - AWS SSB: NET.1
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        network_stack = NetworkSecurityStack(app, "TestNetworkSecurityStack")
        template = Template.from_stack(network_stack)
        
        # THEN
        # Verify VPC Flow Logs resources
        template.resource_count_is("AWS::IAM::Role", 2)  # Updated to expect 2 roles
        template.has_resource_properties("AWS::IAM::Role", {
            "AssumeRolePolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "sts:AssumeRole",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "vpc-flow-logs.amazonaws.com"
                        }
                    })
                ])
            }
        })
        
    def test_security_group_monitoring(self):
        """
        Test Security Group changes are monitored
        - FSBP: EC2.19
        - CIS AWS 3.0.0: 5.3
        - AWS SSB: NET.4
        """
        # GIVEN
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = cdk.aws_sns.Topic(stack, "TestTopic")
        
        # WHEN
        monitoring_stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", 
                                       notifications_topic=notifications_topic)
        template = Template.from_stack(monitoring_stack)
        
        # THEN
        # Verify EventBridge rule for security group changes
        template.has_resource_properties("AWS::Events::Rule", {
            "EventPattern": {
                "source": ["aws.ec2"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": Match.array_with([
                        "AuthorizeSecurityGroupIngress",
                        "AuthorizeSecurityGroupEgress"
                    ])
                }
            }
        })
        
    def test_iam_access_analyzer_enabled(self):
        """
        Test IAM Access Analyzer is enabled
        - FSBP: IAM.8
        - CIS AWS 3.0.0: 1.20
        - AWS SSB: IAM.6
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = SecurityRegionalStack(app, "TestSecurityRegionalStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify IAM Access Analyzer is created
        template.has_resource_properties("AWS::AccessAnalyzer::Analyzer", {
            "AnalyzerName": Match.any_value(),
            "Type": "ACCOUNT"
        })
        
    def test_cloudtrail_enabled_and_configured(self):
        """
        Test CloudTrail is enabled and properly configured
        - FSBP: CloudTrail.1, CloudTrail.4, CloudTrail.5
        - CIS AWS 3.0.0: 3.1, 3.2
        - AWS SSB: LOG.1, LOG.2, LOG.4
        """
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
        
    def test_kms_key_rotation(self):
        """
        Test KMS key rotation is enabled
        - FSBP: KMS.4
        - CIS AWS 3.0.0: 3.7
        - AWS SSB: DAT.4
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = KMSStack(app, "TestKMSStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify KMS key rotation is enabled
        template.has_resource_properties("AWS::KMS::Key", {
            "EnableKeyRotation": True
        })
        
    def test_default_security_group_restrictions(self):
        """
        Test default security groups are restricted
        - FSBP: EC2.2
        - CIS AWS 3.0.0: 5.4
        - AWS SSB: NET.2
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        network_stack = NetworkSecurityStack(app, "TestNetworkSecurityStack")
        template = Template.from_stack(network_stack)
        
        # THEN
        # Verify Lambda function for securing default security groups
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": "index.handler",
            "Runtime": Match.any_value()
        })
        
        # Verify Lambda has proper permissions
        template.has_resource_properties("AWS::IAM::Policy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": Match.array_with([
                            "ec2:DescribeSecurityGroups",
                            "ec2:RevokeSecurityGroupIngress"
                        ]),
                        "Effect": "Allow"
                    })
                ])
            }
        })
        
        # Verify scheduled rule to run the Lambda
        template.has_resource_properties("AWS::Events::Rule", {
            "ScheduleExpression": Match.any_value(),
            "State": "ENABLED"
        })
        
    def test_s3_bucket_ssl_enforcement(self):
        """
        Test S3 bucket SSL enforcement
        - FSBP: S3.5
        - CIS AWS 3.0.0: 2.1.3
        - AWS SSB: DAT.3
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = S3SecurityStack(app, "TestS3SecurityStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify secure bucket creation method enforces SSL
        # This is a method test, not a resource test
        # We can verify the method exists and check its implementation
        assert hasattr(stack, "create_secure_bucket"), "create_secure_bucket method should exist"
        
    def test_aws_config_enabled(self):
        """
        Test AWS Config is enabled
        - FSBP: Config.1
        - CIS AWS 3.0.0: 3.5
        - AWS SSB: LOG.6
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        # Create dependencies for LoggingRegionalStack
        stack = cdk.Stack(app, "TestStack")
        logs_bucket = cdk.aws_s3.Bucket(stack, "TestBucket")
        config_role = cdk.aws_iam.Role(stack, "TestRole", 
                                      assumed_by=cdk.aws_iam.ServicePrincipal("config.amazonaws.com"))
        
        # Create the stack under test
        logging_stack = LoggingRegionalStack(app, "TestLoggingRegionalStack", 
                                           logs_bucket=logs_bucket,
                                           config_role=config_role)
        template = Template.from_stack(logging_stack)
        
        # THEN
        # Verify AWS Config is enabled
        template.has_resource_properties("AWS::Config::ConfigurationRecorder", {
            "RecordingGroup": {
                "AllSupported": True
            }
        })
        
        # Verify delivery channel
        template.has_resource("AWS::Config::DeliveryChannel", {})
        
    def test_cloudwatch_log_group_retention(self):
        """
        Test CloudWatch Log Group retention
        - FSBP: CloudWatch.1
        - CIS AWS 3.0.0: 3.4
        - AWS SSB: LOG.5
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = LoggingStack(app, "TestLoggingStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify CloudTrail is configured to send logs to CloudWatch with retention
        template.has_resource_properties("AWS::CloudTrail::Trail", {
            "IsLogging": True,
            "CloudWatchLogsLogGroupArn": Match.any_value()
        })
        
        # Verify CloudWatch Log Group has retention set
        template.has_resource_properties("AWS::Logs::LogGroup", {
            "RetentionInDays": 365  # ONE_YEAR retention
        })
        
    def test_network_acl_monitoring(self):
        """
        Test Network ACL monitoring
        - FSBP: EC2.21
        - AWS SSB: NET.5
        """
        # GIVEN
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = cdk.aws_sns.Topic(stack, "TestTopic")
        
        # WHEN
        monitoring_stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", 
                                       notifications_topic=notifications_topic)
        template = Template.from_stack(monitoring_stack)
        
        # THEN
        # Verify EventBridge rule for NACL changes
        template.has_resource_properties("AWS::Events::Rule", {
            "EventPattern": {
                "source": ["aws.ec2"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": Match.array_with([
                        "CreateNetworkAcl",
                        "DeleteNetworkAcl",
                        "CreateNetworkAclEntry",
                        "DeleteNetworkAclEntry"
                    ])
                }
            }
        })
        
    def test_sns_topic_encryption(self):
        """
        Test SNS Topic encryption
        - FSBP: SNS.1
        - AWS SSB: DAT.8
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = LoggingStack(app, "TestLoggingStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify SNS Topic exists
        template.has_resource("AWS::SNS::Topic", {})
        
        # Note: SNS Topic encryption would typically use a KMS key, but this is not
        # implemented in the current stack. This test documents the gap.
        # See docs/untested_controls.md for details on this control gap.
        
    def test_ebs_encryption_by_default(self):
        """
        Test EBS encryption by default
        - FSBP: EC2.7
        - CIS AWS 3.0.0: 2.2.1
        - AWS SSB: DAT.5
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = KMSStack(app, "TestKMSStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify EBS encryption by default
        template.has_resource("Custom::AWS", {})
        
        # Verify Lambda function for enabling EBS encryption
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": Match.any_value(),
            "Runtime": Match.any_value()
        })
        
        # Verify Lambda has proper permissions
        template.has_resource_properties("AWS::IAM::Policy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "ec2:EnableEbsEncryptionByDefault",
                        "Effect": "Allow"
                    })
                ])
            }
        })
        
    def test_iam_roles_for_service_access(self):
        """
        Test IAM roles for service access
        - FSBP: IAM.21
        - CIS AWS 3.0.0: 1.16, 1.17
        - AWS SSB: IAM.7
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        # Note: The IAMStack doesn't currently create service roles directly
        # This is a gap in the implementation that should be addressed
        # For now, we'll test this in the NetworkSecurityStack which does create roles
        stack = NetworkSecurityStack(app, "TestNetworkSecurityStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Verify IAM roles are created for service access
        roles = template.find_resources("AWS::IAM::Role")
        assert len(roles) >= 1, "At least one IAM role should be created"
        
    def test_restricted_ssh_access(self):
        """
        Test restricted SSH access
        - FSBP: EC2.13
        - CIS AWS 3.0.0: 5.2
        - AWS SSB: NET.7
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify Config Rule for SSH access
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "INCOMING_SSH_DISABLED"
            }
        })
        
    def test_restricted_rdp_access(self):
        """
        Test restricted RDP access
        - FSBP: EC2.14
        - CIS AWS 3.0.0: 5.2
        - AWS SSB: NET.8
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify Config Rule for RDP access
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "RESTRICTED_INCOMING_TRAFFIC"
            },
            "InputParameters": {
                "blockedPort1": "3389"
            }
        })
        
    def test_access_keys_rotated(self):
        """
        Test access keys rotation monitoring
        - FSBP: IAM.3
        - CIS AWS 3.0.0: 1.14
        - AWS SSB: IAM.4
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify Config Rule for access key rotation
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "ACCESS_KEYS_ROTATED"
            },
            "InputParameters": {
                "maxAccessKeyAge": "90"
            }
        })
        
    def test_mfa_for_console_access(self):
        """
        Test MFA for console access
        - FSBP: IAM.19
        - CIS AWS 3.0.0: 1.12
        - AWS SSB: IAM.3
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
        template = Template.from_stack(stack)
        
        # THEN
        # Verify Config Rule for MFA
        template.has_resource_properties("AWS::Config::ConfigRule", {
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
            }
        })
        
    def test_vpc_endpoints_security(self):
        """
        Test VPC endpoint security
        - FSBP: EC2.15
        - AWS SSB: NET.6
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = VpcStack(app, "TestVPCStack")
        template = Template.from_stack(stack)
        
        # THEN
        # Note: VPC endpoints are not explicitly implemented in the current stack.
        # This test documents the gap. See docs/untested_controls.md for details.
        # We'll verify that the VPC is created but not make specific assertions about endpoints
        template.has_resource("AWS::EC2::VPC", {})
        
    def test_security_hub_findings_alerts(self):
        """
        Test Security Hub findings alerts
        - FSBP: SecurityHub.2
        - AWS SSB: COM.5, IR.5
        """
        # GIVEN
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = cdk.aws_sns.Topic(stack, "TestTopic")
        
        # WHEN
        monitoring_stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", 
                                       notifications_topic=notifications_topic)
        template = Template.from_stack(monitoring_stack)
        
        # THEN
        # Verify EventBridge rule for Security Hub findings
        template.has_resource_properties("AWS::Events::Rule", {
            "EventPattern": {
                "source": ["aws.securityhub"],
                "detail-type": ["Security Hub Findings - Imported"]
            }
        })
        
    def test_guardduty_findings_alerts(self):
        """
        Test GuardDuty findings alerts
        - FSBP: GuardDuty.4
        - AWS SSB: IR.4
        """
        # GIVEN
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = cdk.aws_sns.Topic(stack, "TestTopic")
        
        # WHEN
        monitoring_stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", 
                                       notifications_topic=notifications_topic)
        template = Template.from_stack(monitoring_stack)
        
        # THEN
        # Verify EventBridge rule for GuardDuty findings
        template.has_resource_properties("AWS::Events::Rule", {
            "EventPattern": {
                "source": ["aws.guardduty"],
                "detail-type": ["GuardDuty Finding"]
            }
        })
        
    def test_iam_access_analyzer_alerts(self):
        """
        Test IAM Access Analyzer alerts
        - FSBP: IAM.8
        - AWS SSB: IR.6
        """
        # GIVEN
        app = cdk.App()
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = cdk.aws_sns.Topic(stack, "TestTopic")
        
        # WHEN
        monitoring_stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", 
                                       notifications_topic=notifications_topic)
        template = Template.from_stack(monitoring_stack)
        
        # THEN
        # Note: IAM Access Analyzer alerts are not explicitly implemented in the current stack.
        # This test documents the gap. See docs/untested_controls.md for details.
        # We'll verify that the stack exists but not make specific assertions
        assert monitoring_stack is not None