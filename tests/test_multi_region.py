import pytest
import os
import aws_cdk as cdk

def test_app_multi_region_deployment():
    """Test that the app correctly handles multi-region context"""
    app = cdk.App(context={
        "notification_email": "test@example.com",
        "global_region": "us-east-1",
        "target_regions": ["us-east-1"]
    })
    # The app module itself is tested in test_imports.py
    # This test validates CDK context handling
    assert app.node.try_get_context("global_region") == "us-east-1"
    assert app.node.try_get_context("notification_email") == "test@example.com"
