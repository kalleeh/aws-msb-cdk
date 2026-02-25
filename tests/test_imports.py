import pytest
import aws_cdk as cdk
from aws_cdk.assertions import Template, Match

def test_regional_only_deployment_context_handling():
    """Test that CDK app context is set and readable for regional-only deployment"""
    app = cdk.App(context={
        "target": "regional",
        "global_region": "us-east-1",
        "target_regions": ["us-east-1"],
        "notification_email": "test@example.com"
    })

    assert app.node.try_get_context("target") == "regional"
    assert app.node.try_get_context("global_region") == "us-east-1"
    assert app.node.try_get_context("notification_email") == "test@example.com"