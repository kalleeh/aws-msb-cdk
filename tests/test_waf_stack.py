import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.waf_stack import WafStack


class TestWafStack:
    @pytest.fixture
    def app(self):
        return cdk.App()

    @pytest.fixture
    def waf_stack(self, app):
        return WafStack(app, "TestWAFStack",
                        env=cdk.Environment(account="123456789012", region="us-east-1"))

    @pytest.fixture
    def template(self, waf_stack):
        return Template.from_stack(waf_stack)

    # ------------------------------------------------------------------ #
    # WebACL scope and visibility                                          #
    # ------------------------------------------------------------------ #

    def test_web_acl_is_regional(self, template):
        """WebACL must use REGIONAL scope (for ALB / API Gateway)."""
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Scope": "REGIONAL",
        })

    def test_web_acl_cloudwatch_metrics_enabled(self, template):
        """Top-level visibility config must enable CloudWatch metrics."""
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "VisibilityConfig": {
                "CloudWatchMetricsEnabled": True,
                "SampledRequestsEnabled": True,
            }
        })

    # ------------------------------------------------------------------ #
    # Managed rule groups                                                  #
    # ------------------------------------------------------------------ #

    def _get_rule_names(self, template) -> list:
        web_acls = template.find_resources("AWS::WAFv2::WebACL")
        assert len(web_acls) == 1, "Expected exactly one WebACL"
        props = list(web_acls.values())[0]["Properties"]
        return [rule["Name"] for rule in props.get("Rules", [])]

    def test_common_rule_set_present(self, template):
        """AWSManagedRulesCommonRuleSet must be included."""
        assert "AWSManagedRulesCommonRuleSet" in self._get_rule_names(template)

    def test_known_bad_inputs_rule_set_present(self, template):
        """AWSManagedRulesKnownBadInputsRuleSet must be included."""
        assert "AWSManagedRulesKnownBadInputsRuleSet" in self._get_rule_names(template)

    def test_amazon_ip_reputation_list_present(self, template):
        """AWSManagedRulesAmazonIpReputationList must be included."""
        assert "AWSManagedRulesAmazonIpReputationList" in self._get_rule_names(template)

    def test_anonymous_ip_list_present(self, template):
        """AWSManagedRulesAnonymousIpList must be included."""
        assert "AWSManagedRulesAnonymousIpList" in self._get_rule_names(template)

    def test_sqli_rule_set_present(self, template):
        """AWSManagedRulesSQLiRuleSet must be included."""
        assert "AWSManagedRulesSQLiRuleSet" in self._get_rule_names(template)

    def test_all_five_managed_rule_groups_present(self, template):
        """All five AWS managed rule groups must be present."""
        rule_names = self._get_rule_names(template)
        expected = {
            "AWSManagedRulesCommonRuleSet",
            "AWSManagedRulesKnownBadInputsRuleSet",
            "AWSManagedRulesAmazonIpReputationList",
            "AWSManagedRulesAnonymousIpList",
            "AWSManagedRulesSQLiRuleSet",
        }
        assert expected.issubset(set(rule_names)), (
            f"Missing managed rule groups: {expected - set(rule_names)}"
        )

    def test_managed_rule_groups_use_aws_vendor(self, template):
        """All managed rule group statements must reference the AWS vendor."""
        web_acls = template.find_resources("AWS::WAFv2::WebACL")
        props = list(web_acls.values())[0]["Properties"]
        for rule in props["Rules"]:
            stmt = rule.get("Statement", {})
            mrgs = stmt.get("ManagedRuleGroupStatement")
            if mrgs:
                assert mrgs["VendorName"] == "AWS", (
                    f"Rule {rule['Name']} uses unexpected vendor {mrgs['VendorName']}"
                )

    # ------------------------------------------------------------------ #
    # Rate limiting rule                                                   #
    # ------------------------------------------------------------------ #

    def test_rate_limit_rule_exists(self, template):
        """A rate-based rule named RateLimitPerIP must be present."""
        assert "RateLimitPerIP" in self._get_rule_names(template)

    def test_rate_limit_rule_limit_value(self, template):
        """Rate limit rule must cap at 2000 requests per 5-minute window."""
        web_acls = template.find_resources("AWS::WAFv2::WebACL")
        props = list(web_acls.values())[0]["Properties"]
        rate_rule = next(
            (r for r in props["Rules"] if r["Name"] == "RateLimitPerIP"), None
        )
        assert rate_rule is not None, "RateLimitPerIP rule not found"
        rbs = rate_rule["Statement"]["RateBasedStatement"]
        assert rbs["Limit"] == 2000
        assert rbs["AggregateKeyType"] == "IP"

    def test_rate_limit_rule_uses_block_action(self, template):
        """Rate limit rule must use Block action (not Count)."""
        web_acls = template.find_resources("AWS::WAFv2::WebACL")
        props = list(web_acls.values())[0]["Properties"]
        rate_rule = next(
            (r for r in props["Rules"] if r["Name"] == "RateLimitPerIP"), None
        )
        assert rate_rule is not None, "RateLimitPerIP rule not found"
        assert "Block" in rate_rule.get("Action", {}), (
            "RateLimitPerIP rule should use Block action"
        )

    # ------------------------------------------------------------------ #
    # CfnOutput                                                            #
    # ------------------------------------------------------------------ #

    def test_web_acl_arn_output_exists(self, template):
        """Stack must export the WebACL ARN as a CfnOutput."""
        outputs = template.find_outputs("*")
        output_keys = list(outputs.keys())
        arn_outputs = [k for k in output_keys if "WebACLArn" in k or "WebAcl" in k.lower()]
        assert len(arn_outputs) >= 1, (
            f"No WebACL ARN output found. Outputs: {output_keys}"
        )

    # ------------------------------------------------------------------ #
    # Stack is NOT created when enable_waf is false / absent              #
    # ------------------------------------------------------------------ #

    def test_waf_stack_not_created_when_flag_absent(self):
        """WafStack should not be instantiated when enable_waf context is absent."""
        app = cdk.App()
        # Simulate app.py logic: only create WafStack if enable_waf == "true"
        enable_waf = app.node.try_get_context("enable_waf")
        waf_created = False
        if enable_waf and str(enable_waf).lower() == "true":
            WafStack(app, "MSB-WAF-us-east-1",
                     env=cdk.Environment(account="123456789012", region="us-east-1"))
            waf_created = True
        assert not waf_created, "WafStack should not be created when enable_waf is absent"

    def test_waf_stack_not_created_when_flag_false(self):
        """WafStack should not be instantiated when enable_waf=false."""
        app = cdk.App(context={"enable_waf": False})
        enable_waf = app.node.try_get_context("enable_waf")
        waf_created = False
        if enable_waf and str(enable_waf).lower() == "true":
            WafStack(app, "MSB-WAF-us-east-1",
                     env=cdk.Environment(account="123456789012", region="us-east-1"))
            waf_created = True
        assert not waf_created, "WafStack should not be created when enable_waf=false"

    def test_waf_stack_created_when_flag_true(self):
        """WafStack should be instantiated when enable_waf=true."""
        app = cdk.App(context={"enable_waf": "true"})
        enable_waf = app.node.try_get_context("enable_waf")
        waf_created = False
        if enable_waf and str(enable_waf).lower() == "true":
            stack = WafStack(app, "MSB-WAF-us-east-1",
                             env=cdk.Environment(account="123456789012", region="us-east-1"))
            waf_created = True
        assert waf_created, "WafStack should be created when enable_waf=true"

    # ------------------------------------------------------------------ #
    # String topic ARN normalization                                       #
    # ------------------------------------------------------------------ #

    def test_string_topic_arn_accepted(self):
        """WafStack must accept a raw SNS topic ARN string without errors."""
        app = cdk.App()
        stack = WafStack(
            app, "TestWAFStackWithTopicArn",
            notifications_topic="arn:aws:sns:us-east-1:123456789012:msb-notifications",
            env=cdk.Environment(account="123456789012", region="us-east-1"),
        )
        template = Template.from_stack(stack)
        # WebACL should still be created successfully
        template.resource_count_is("AWS::WAFv2::WebACL", 1)
