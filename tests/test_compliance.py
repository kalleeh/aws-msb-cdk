import aws_cdk as cdk
from aws_cdk.assertions import Template, Match
import aws_cdk.aws_sns as sns

from aws_msb_cdk.iam_stack import IAMStack
from aws_msb_cdk.logging_stack import LoggingStack
from aws_msb_cdk.kms_stack import KMSStack

class TestCompliance:
    def test_iam_password_policy(self):
        """
        Test IAM password policy meets NIST SP 800-63B and CIS v3.0.0 benchmarks
        - CIS AWS 3.0.0: 1.8, 1.9, 1.11, 1.12, 1.13, 1.14
        - NOTE: MaxPasswordAge intentionally omitted per NIST SP 800-63B recommendation
          against periodic password expiration. CIS v3.0.0 dropped this requirement.
        """
        # GIVEN
        app = cdk.App()

        # WHEN
        stack = IAMStack(app, "TestIAMStack")
        template = Template.from_stack(stack)

        # THEN
        # Verify password policy is created with proper settings
        template.has_resource_properties("AWS::IAM::AccountPasswordPolicy", {
            "MinimumPasswordLength": 16,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "PasswordReusePrevention": 24,
            "HardExpiry": False,
            "AllowUsersToChangePassword": True
        })
        
    def test_iam_access_analyzer(self):
        """
        Test IAM Access Analyzer is enabled
        - FSBP: IAM.8
        - CIS AWS 3.0.0: 1.20
        - AWS SSB: IR.6
        """
        # GIVEN
        app = cdk.App()
        
        # WHEN
        stack = IAMStack(app, "TestIAMStack")
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
        - CIS AWS 3.0.0: 3.1, 3.2, 3.3
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
            "EnableLogFileValidation": True,  # This validates CIS 3.3 - CloudTrail log file validation
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
        
    def test_iam_policy_governance(self):
        """
        Test IAM policy governance monitoring
        - FSBP: IAM.16
        """
        # GIVEN
        app = cdk.App()
        
        # Create a mock SNS topic for notifications
        stack = cdk.Stack(app, "TestStack")
        notifications_topic = sns.Topic(stack, "TestTopic")
        
        # WHEN
        iam_stack = IAMStack(app, "TestIAMStack", notifications_topic=notifications_topic)
        template = Template.from_stack(iam_stack)
        
        # THEN
        # Verify Lambda function for IAM policy checking is created
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": "index.handler",
            "Runtime": "python3.13",
            "Timeout": 60
        })
        
        # Verify EventBridge rule for daily checks
        template.has_resource_properties("AWS::Events::Rule", {
            "ScheduleExpression": "rate(1 day)",
            "State": "ENABLED"
        })
        
        # Verify EventBridge rule for policy attachment events
        template.has_resource_properties("AWS::Events::Rule", {
            "EventPattern": {
                "source": ["aws.iam"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": Match.array_with(["AttachUserPolicy", "PutUserPolicy"])
                }
            }
        })