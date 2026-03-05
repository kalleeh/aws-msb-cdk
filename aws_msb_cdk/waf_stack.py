from aws_cdk import (
    Stack,
    aws_wafv2 as wafv2,
    aws_sns as sns,
    CfnOutput,
)
from constructs import Construct
from cdk_nag import NagSuppressions


class WafStack(Stack):
    """
    Optional WAFv2 Web ACL with AWS Managed Rule Groups.
    Deploy with: cdk deploy MSB-WAF-{region} --context enable_waf=true

    After deployment, associate the WebACL ARN with your resources:
    - ALB: aws elbv2 associate-web-acl --web-acl-arn <arn> --resource-arn <alb-arn>
    - CloudFront: set web_acl_id on the distribution
    - API Gateway: associate via stage settings
    """

    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Accept a topic ARN string for cross-deployment use (regional-only deploys)
        if isinstance(notifications_topic, str):
            notifications_topic = sns.Topic.from_topic_arn(self, "NotificationsTopic", notifications_topic)

        self.notifications_topic = notifications_topic

        # Build the list of AWS Managed Rule Groups
        managed_rule_groups = [
            wafv2.CfnWebACL.RuleProperty(
                name="AWSManagedRulesCommonRuleSet",
                priority=10,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        vendor_name="AWS",
                        name="AWSManagedRulesCommonRuleSet",
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="AWSManagedRulesCommonRuleSet",
                ),
            ),
            wafv2.CfnWebACL.RuleProperty(
                name="AWSManagedRulesKnownBadInputsRuleSet",
                priority=20,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        vendor_name="AWS",
                        name="AWSManagedRulesKnownBadInputsRuleSet",
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="AWSManagedRulesKnownBadInputsRuleSet",
                ),
            ),
            wafv2.CfnWebACL.RuleProperty(
                name="AWSManagedRulesAmazonIpReputationList",
                priority=30,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        vendor_name="AWS",
                        name="AWSManagedRulesAmazonIpReputationList",
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="AWSManagedRulesAmazonIpReputationList",
                ),
            ),
            wafv2.CfnWebACL.RuleProperty(
                name="AWSManagedRulesAnonymousIpList",
                priority=40,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        vendor_name="AWS",
                        name="AWSManagedRulesAnonymousIpList",
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="AWSManagedRulesAnonymousIpList",
                ),
            ),
            wafv2.CfnWebACL.RuleProperty(
                name="AWSManagedRulesSQLiRuleSet",
                priority=50,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        vendor_name="AWS",
                        name="AWSManagedRulesSQLiRuleSet",
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="AWSManagedRulesSQLiRuleSet",
                ),
            ),
            # Rate limiting rule: 2000 requests per 5 minutes (300 seconds) per IP
            wafv2.CfnWebACL.RuleProperty(
                name="RateLimitPerIP",
                priority=60,
                action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                        limit=2000,
                        aggregate_key_type="IP",
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="RateLimitPerIP",
                ),
            ),
        ]

        # Create the WAFv2 WebACL with REGIONAL scope (for ALB / API Gateway)
        web_acl = wafv2.CfnWebACL(
            self,
            "WebACL",
            name=f"msb-web-acl-{self.region}",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            rules=managed_rule_groups,
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name=f"msb-web-acl-{self.region}",
            ),
        )

        # Export the WebACL ARN so users can associate it with their resources
        CfnOutput(
            self,
            "WebACLArn",
            value=web_acl.attr_arn,
            description=(
                "MSB WAFv2 WebACL ARN — associate with ALB, CloudFront, or API Gateway. "
                "ALB: aws elbv2 associate-web-acl --web-acl-arn <arn> --resource-arn <alb-arn>"
            ),
            export_name=f"MSB-WAF-WebACLArn-{self.region}",
        )

        # CDK Nag suppressions
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-WAF1",
                    "reason": (
                        "AWS Shield Advanced is not required for this baseline deployment. "
                        "Users may opt in to Shield Advanced separately for DDoS protection on production workloads."
                    ),
                },
                {
                    "id": "AwsSolutions-WAF2",
                    "reason": (
                        "AWS X-Ray tracing is not applicable to WAFv2 WebACLs. "
                        "This finding does not apply to this resource type."
                    ),
                },
                {
                    "id": "AwsSolutions-WAF4",
                    "reason": (
                        "All five AWS managed rule groups (CommonRuleSet, KnownBadInputs, "
                        "AmazonIpReputationList, AnonymousIpList, SQLiRuleSet) are included. "
                        "The rate-limiting rule uses BLOCK action. Managed rules use none{} "
                        "override (inherit the rule group's default actions) which is the "
                        "recommended configuration."
                    ),
                },
            ],
        )
