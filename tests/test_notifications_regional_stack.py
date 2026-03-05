import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.notifications_regional_stack import NotificationsRegionalStack


@pytest.fixture
def app():
    return cdk.App()


@pytest.fixture
def stack(app):
    return NotificationsRegionalStack(
        app, "TestNotificationsRegionalStack",
        notification_email="test@example.com",
    )


@pytest.fixture
def template(stack):
    return Template.from_stack(stack)


def test_sns_topic_created(template):
    """A single SNS topic is created."""
    template.resource_count_is("AWS::SNS::Topic", 1)


def test_sns_topic_display_name(template):
    """Topic display name is set correctly."""
    template.has_resource_properties("AWS::SNS::Topic", {
        "DisplayName": "MSB Security Notifications",
    })


def test_sns_topic_encrypted_with_kms(template):
    """Topic has a KmsMasterKeyId — encryption is enabled."""
    template.has_resource_properties("AWS::SNS::Topic", {
        "KmsMasterKeyId": Match.any_value(),
    })


def test_kms_key_created_with_rotation(template):
    """A KMS key with rotation enabled is created for the topic."""
    template.resource_count_is("AWS::KMS::Key", 1)
    template.has_resource_properties("AWS::KMS::Key", {
        "EnableKeyRotation": True,
    })


def test_kms_key_alias_created(template):
    """A KMS alias is created for the SNS encryption key."""
    template.resource_count_is("AWS::KMS::Alias", 1)
    # AliasName contains an Fn::Join / Ref token when no env is bound,
    # so we only verify a KMS alias resource exists.
    aliases = template.find_resources("AWS::KMS::Alias")
    assert len(aliases) == 1


def test_email_subscription_added(template):
    """An email subscription is added for the provided address."""
    template.resource_count_is("AWS::SNS::Subscription", 1)
    template.has_resource_properties("AWS::SNS::Subscription", {
        "Protocol": "email",
        "Endpoint": "test@example.com",
    })


def test_notifications_topic_attribute_exported(stack):
    """The stack exposes a notifications_topic attribute."""
    assert hasattr(stack, "notifications_topic")
    assert stack.notifications_topic is not None


def test_independent_stacks_per_region(app):
    """Two regional notification stacks are fully independent (no shared resources)."""
    stack_east = NotificationsRegionalStack(
        app, "TestNotificationsRegionalStackEast",
        notification_email="test@example.com",
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )
    stack_west = NotificationsRegionalStack(
        app, "TestNotificationsRegionalStackWest",
        notification_email="test@example.com",
        env=cdk.Environment(account="123456789012", region="us-west-2"),
    )

    template_east = Template.from_stack(stack_east)
    template_west = Template.from_stack(stack_west)

    # Both stacks define exactly one topic and one KMS key each
    template_east.resource_count_is("AWS::SNS::Topic", 1)
    template_west.resource_count_is("AWS::SNS::Topic", 1)
    template_east.resource_count_is("AWS::KMS::Key", 1)
    template_west.resource_count_is("AWS::KMS::Key", 1)

    # KMS alias names embed the region and therefore differ between stacks
    aliases_east = template_east.find_resources("AWS::KMS::Alias")
    aliases_west = template_west.find_resources("AWS::KMS::Alias")
    alias_name_east = list(aliases_east.values())[0]["Properties"]["AliasName"]
    alias_name_west = list(aliases_west.values())[0]["Properties"]["AliasName"]
    assert alias_name_east != alias_name_west
    assert "us-east-1" in alias_name_east
    assert "us-west-2" in alias_name_west
