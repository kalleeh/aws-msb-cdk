from aws_cdk import (
    Stack,
    aws_guardduty as guardduty,
    aws_securityhub as securityhub,
    aws_iam as iam,
    aws_s3 as s3,
    aws_macie as macie,
    aws_events as events,
    aws_events_targets as targets,
    Duration,
    RemovalPolicy,
    custom_resources as cr,
)
from constructs import Construct


class SecurityRegionalStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic, notification_email=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ------------------------------------------------------------------ #
        # S3 bucket for GuardDuty findings export
        # ------------------------------------------------------------------ #
        findings_bucket = s3.Bucket(self, "GuardDutyFindingsBucket",
            bucket_name=f"msb-guardduty-findings-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="FindingsRetention",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(30)
                        )
                    ],
                    expiration=Duration.days(365)
                )
            ]
        )

        # ------------------------------------------------------------------ #
        # GuardDuty Detector - all protection plan features enabled
        # ------------------------------------------------------------------ #
        detector = guardduty.CfnDetector(self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES",
            features=[
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="S3_DATA_EVENTS",
                    status="ENABLED"
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="EKS_AUDIT_LOGS",
                    status="ENABLED"
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="EBS_MALWARE_PROTECTION",
                    status="ENABLED",
                    additional_configuration=[
                        guardduty.CfnDetector.CFNFeatureAdditionalConfigurationProperty(
                            name="EC2_AGENT_MANAGEMENT",
                            status="ENABLED"
                        )
                    ]
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="RDS_LOGIN_EVENTS",
                    status="ENABLED"
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="LAMBDA_NETWORK_LOGS",
                    status="ENABLED"
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="EKS_RUNTIME_MONITORING",
                    status="ENABLED",
                    additional_configuration=[
                        guardduty.CfnDetector.CFNFeatureAdditionalConfigurationProperty(
                            name="EKS_ADDON_MANAGEMENT",
                            status="ENABLED"
                        )
                    ]
                ),
                guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                    name="RUNTIME_MONITORING",
                    status="ENABLED",
                    additional_configuration=[
                        guardduty.CfnDetector.CFNFeatureAdditionalConfigurationProperty(
                            name="EC2_AGENT_MANAGEMENT",
                            status="ENABLED"
                        ),
                        guardduty.CfnDetector.CFNFeatureAdditionalConfigurationProperty(
                            name="EKS_ADDON_MANAGEMENT",
                            status="ENABLED"
                        ),
                        guardduty.CfnDetector.CFNFeatureAdditionalConfigurationProperty(
                            name="FARGATE_AGENT_MANAGEMENT",
                            status="ENABLED"
                        ),
                    ]
                ),
            ]
        )

        # ------------------------------------------------------------------ #
        # Security Hub - enable hub then activate FSBP v1.0.0 + CIS v3.0.0
        # CfnStandard is a native L1 construct — no custom resource needed
        # ------------------------------------------------------------------ #
        security_hub = securityhub.CfnHub(self, "SecurityHub")

        fsbp_standard = securityhub.CfnStandard(self, "FBSPStandard",
            standards_arn=f"arn:aws:securityhub:{self.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
        )
        fsbp_standard.node.add_dependency(security_hub)

        cis_standard = securityhub.CfnStandard(self, "CISv3Standard",
            standards_arn=f"arn:aws:securityhub:{self.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
        )
        cis_standard.node.add_dependency(security_hub)

        # ------------------------------------------------------------------ #
        # Amazon Inspector v2 - enable for EC2, ECR, and Lambda
        # ------------------------------------------------------------------ #
        inspector = cr.AwsCustomResource(self, "EnableInspectorV2",
            on_create=cr.AwsSdkCall(
                service="Inspector2",
                action="enable",
                parameters={
                    "resourceTypes": ["EC2", "ECR", "LAMBDA"]
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    f"InspectorV2Enable-{self.region}"
                )
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=[
                        "inspector2:Enable",
                        "inspector2:List*",
                        "iam:CreateServiceLinkedRole",
                    ],
                    resources=["*"]
                )
            ])
        )

        # ------------------------------------------------------------------ #
        # Amazon Macie - enable session
        # ------------------------------------------------------------------ #
        macie_session = macie.CfnSession(self, "MacieSession",
            finding_publishing_frequency="FIFTEEN_MINUTES",
            status="ENABLED"
        )

        # ------------------------------------------------------------------ #
        # EventBridge rules to route security findings to SNS notifications
        # ------------------------------------------------------------------ #
        if notifications_topic:
            # Inspector v2 findings → SNS
            events.Rule(self, "InspectorFindingsRule",
                rule_name=f"msb-inspector-findings-{self.region}",
                description="Routes Inspector v2 findings to SNS notifications",
                event_pattern=events.EventPattern(
                    source=["aws.inspector2"],
                    detail_type=["Inspector2 Finding"]
                ),
                targets=[targets.SnsTopic(notifications_topic)]
            )

            # Macie findings → SNS
            events.Rule(self, "MacieFindingsRule",
                rule_name=f"msb-macie-findings-{self.region}",
                description="Routes Macie findings to SNS notifications",
                event_pattern=events.EventPattern(
                    source=["aws.macie2"],
                    detail_type=["Macie Finding"]
                ),
                targets=[targets.SnsTopic(notifications_topic)]
            )

        # ------------------------------------------------------------------ #
        # Security Hub Automation Rules - suppress manual-action controls
        # ------------------------------------------------------------------ #

        # Rule 1: Suppress FSBP Account.1 (security contact - manual console action)
        securityhub.CfnAutomationRule(self, "SuppressAccountContactRule",
            rule_name="MSB-Suppress-ManualControls-AccountContact",
            description="Suppress FSBP Account.1 findings that require manual console action to set a security contact",
            rule_order=1,
            is_terminal=False,
            actions=[
                securityhub.CfnAutomationRule.AutomationRulesActionProperty(
                    type="FINDING_FIELDS_UPDATE",
                    finding_fields_update=securityhub.CfnAutomationRule.AutomationRulesFindingFieldsUpdateProperty(
                        workflow=securityhub.CfnAutomationRule.WorkflowUpdateProperty(
                            status="SUPPRESSED"
                        )
                    )
                )
            ],
            criteria=securityhub.CfnAutomationRule.AutomationRulesFindingFiltersProperty(
                generator_id=[
                    securityhub.CfnAutomationRule.StringFilterProperty(
                        comparison="CONTAINS",
                        value="account-security-contact"
                    )
                ],
                workflow_status=[
                    securityhub.CfnAutomationRule.StringFilterProperty(
                        comparison="EQUALS",
                        value="NEW"
                    )
                ],
                compliance_status=[
                    securityhub.CfnAutomationRule.StringFilterProperty(
                        comparison="EQUALS",
                        value="FAILED"
                    )
                ]
            )
        )

        # Rule 2: Suppress IAM root MFA controls (FSBP IAM.4, IAM.6, IAM.9 - hardware MFA)
        securityhub.CfnAutomationRule(self, "SuppressRootMFARule",
            rule_name="MSB-Suppress-ManualControls-RootMFA",
            description="Suppress FSBP IAM.4/IAM.6/IAM.9 findings that require physical hardware MFA for root",
            rule_order=2,
            is_terminal=False,
            actions=[
                securityhub.CfnAutomationRule.AutomationRulesActionProperty(
                    type="FINDING_FIELDS_UPDATE",
                    finding_fields_update=securityhub.CfnAutomationRule.AutomationRulesFindingFieldsUpdateProperty(
                        workflow=securityhub.CfnAutomationRule.WorkflowUpdateProperty(
                            status="SUPPRESSED"
                        )
                    )
                )
            ],
            criteria=securityhub.CfnAutomationRule.AutomationRulesFindingFiltersProperty(
                generator_id=[
                    securityhub.CfnAutomationRule.StringFilterProperty(
                        comparison="CONTAINS",
                        value="iam-root-hardware-mfa"
                    ),
                    securityhub.CfnAutomationRule.StringFilterProperty(
                        comparison="CONTAINS",
                        value="iam-root-mfa"
                    )
                ],
                workflow_status=[
                    securityhub.CfnAutomationRule.StringFilterProperty(
                        comparison="EQUALS",
                        value="NEW"
                    )
                ]
            )
        )

        # ------------------------------------------------------------------ #
        # Exports
        # ------------------------------------------------------------------ #
        self.detector = detector
        self.security_hub = security_hub
        self.findings_bucket = findings_bucket
        self.inspector = inspector
        self.macie_session = macie_session
