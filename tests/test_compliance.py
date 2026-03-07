import aws_cdk as cdk
from aws_cdk.assertions import Template, Match
import aws_cdk.aws_sns as sns
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_iam as iam

from aws_msb_cdk.iam_stack import IAMStack
from aws_msb_cdk.logging_stack import LoggingStack
from aws_msb_cdk.kms_stack import KMSStack
from aws_msb_cdk.security_regional_stack import SecurityRegionalStack
from aws_msb_cdk.logging_regional_stack import LoggingRegionalStack

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


class TestControlTowerManagedMode:
    """
    Verify that control_tower_managed=True suppresses resources that conflict
    with Control Tower's own management (GuardDuty, Security Hub, Macie,
    Config recorder/channel, CloudTrail trail) while preserving unique-value
    resources such as CloudWatch alarms.
    """

    # ------------------------------------------------------------------ #
    # SecurityRegionalStack tests
    # ------------------------------------------------------------------ #

    def test_guardduty_not_created_when_ct_managed(self):
        """GuardDuty detector must be absent when CT manages the account."""
        # GIVEN
        app = cdk.App()

        # WHEN
        stack = SecurityRegionalStack(app, "TestCTSecurityRegional",
                                      notifications_topic=None,
                                      control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — zero GuardDuty detectors
        template.resource_count_is("AWS::GuardDuty::Detector", 0)

    def test_security_hub_not_created_when_ct_managed(self):
        """Security Hub Hub resource must be absent when CT manages the account."""
        # GIVEN
        app = cdk.App()

        # WHEN
        stack = SecurityRegionalStack(app, "TestCTSecurityRegional",
                                      notifications_topic=None,
                                      control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — zero Security Hub Hubs
        template.resource_count_is("AWS::SecurityHub::Hub", 0)

    def test_macie_not_created_when_ct_managed(self):
        """Macie session must be absent when CT manages the account."""
        # GIVEN
        app = cdk.App()

        # WHEN
        stack = SecurityRegionalStack(app, "TestCTSecurityRegional",
                                      notifications_topic=None,
                                      control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — zero Macie sessions
        template.resource_count_is("AWS::Macie::Session", 0)

    # ------------------------------------------------------------------ #
    # LoggingRegionalStack tests
    # ------------------------------------------------------------------ #

    def test_config_recorder_not_created_when_ct_managed(self):
        """Config recorder must be absent — CT creates its own recorder."""
        # GIVEN
        app = cdk.App()
        stack_scope = cdk.Stack(app, "MockScope")
        mock_bucket = s3.Bucket(stack_scope, "MockBucket")
        mock_role = iam.Role(stack_scope, "MockRole",
                             assumed_by=iam.ServicePrincipal("config.amazonaws.com"))

        # WHEN
        stack = LoggingRegionalStack(app, "TestCTLoggingRegional",
                                     logs_bucket=mock_bucket,
                                     config_role=mock_role,
                                     control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — zero Config recorders
        template.resource_count_is("AWS::Config::ConfigurationRecorder", 0)

    def test_config_delivery_channel_not_created_when_ct_managed(self):
        """Config delivery channel must be absent — CT creates its own."""
        # GIVEN
        app = cdk.App()
        stack_scope = cdk.Stack(app, "MockScope2")
        mock_bucket = s3.Bucket(stack_scope, "MockBucket")
        mock_role = iam.Role(stack_scope, "MockRole",
                             assumed_by=iam.ServicePrincipal("config.amazonaws.com"))

        # WHEN
        stack = LoggingRegionalStack(app, "TestCTLoggingRegional2",
                                     logs_bucket=mock_bucket,
                                     config_role=mock_role,
                                     control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — zero Config delivery channels
        template.resource_count_is("AWS::Config::DeliveryChannel", 0)

    # ------------------------------------------------------------------ #
    # LoggingStack tests
    # ------------------------------------------------------------------ #

    def test_cloudwatch_alarms_still_created_when_ct_managed(self):
        """
        CloudWatch alarms are the unique value MSB provides on top of CT.
        They must still be created even when CT manages the trail.
        """
        # GIVEN
        app = cdk.App()

        # WHEN — kms_stack=None means no external KMS; CT mode skips trail creation
        stack = LoggingStack(app, "TestCTLogging",
                             kms_stack=None,
                             control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — at least 13 CIS v3.0.0 alarms are still present
        alarms = template.find_resources("AWS::CloudWatch::Alarm")
        assert len(alarms) >= 13, (
            f"Expected at least 13 CloudWatch alarms in CT-managed mode, got {len(alarms)}"
        )

    def test_cloudtrail_not_created_when_ct_managed(self):
        """CloudTrail trail must be absent — CT provides the Organisation Trail."""
        # GIVEN
        app = cdk.App()

        # WHEN
        stack = LoggingStack(app, "TestCTLoggingTrail",
                             kms_stack=None,
                             control_tower_managed=True)
        template = Template.from_stack(stack)

        # THEN — zero CloudTrail trails in this stack
        template.resource_count_is("AWS::CloudTrail::Trail", 0)

    # ------------------------------------------------------------------ #
    # Regression: default mode still creates the GuardDuty detector
    # ------------------------------------------------------------------ #

    def test_guardduty_created_when_not_ct_managed(self):
        """Default (non-CT) mode must still enable the GuardDuty detector."""
        # GIVEN
        app = cdk.App()

        # WHEN — default control_tower_managed=False
        stack = SecurityRegionalStack(app, "TestDefaultSecurityRegional",
                                      notifications_topic=None,
                                      control_tower_managed=False)
        template = Template.from_stack(stack)

        # THEN — exactly one GuardDuty detector is created
        template.resource_count_is("AWS::GuardDuty::Detector", 1)