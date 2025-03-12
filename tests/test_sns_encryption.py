import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.notifications_stack import NotificationsStack

@pytest.fixture
def notifications_stack():
    app = cdk.App()
    notifications_stack = NotificationsStack(app, "TestNotificationsStack", notification_email="test@example.com")
    return notifications_stack

def test_sns_topic_created(notifications_stack):
    template = Template.from_stack(notifications_stack)
    
    # Verify SNS topic is created
    template.resource_count_is("AWS::SNS::Topic", 1)
    
    # Verify topic name
    template.has_resource_properties("AWS::SNS::Topic", {
        "TopicName": Match.string_like_regexp("msb-notifications-"),
        "DisplayName": "MSB Security Notifications"
    })

def test_kms_key_created(notifications_stack):
    template = Template.from_stack(notifications_stack)
    
    # Verify KMS key is created
    template.resource_count_is("AWS::KMS::Key", 1)
    
    # Verify key properties
    template.has_resource_properties("AWS::KMS::Key", {
        "Description": "KMS key for SNS topic encryption",
        "EnableKeyRotation": True
    })
    
    # Verify key alias
    template.has_resource_properties("AWS::KMS::Alias", {
        "AliasName": Match.string_like_regexp("alias/msb-sns-encryption-")
    })

def test_sns_topic_encrypted(notifications_stack):
    template = Template.from_stack(notifications_stack)
    
    # Verify SNS topic is encrypted with KMS
    template.has_resource_properties("AWS::SNS::Topic", {
        "KmsMasterKeyId": Match.any_value()
    })
    
    # Get the KMS key ID reference
    kms_keys = template.find_resources("AWS::KMS::Key")
    assert len(kms_keys) == 1
    kms_key_id = list(kms_keys.keys())[0]
    
    # Verify SNS topic references the KMS key
    sns_topics = template.find_resources("AWS::SNS::Topic")
    assert len(sns_topics) == 1
    sns_topic = list(sns_topics.values())[0]
    
    # Check that the KMS key reference is in the SNS topic properties
    assert "KmsMasterKeyId" in sns_topic["Properties"]
    
def test_email_subscription_added(notifications_stack):
    template = Template.from_stack(notifications_stack)
    
    # Verify email subscription is created
    template.resource_count_is("AWS::SNS::Subscription", 1)
    
    # Verify subscription properties
    template.has_resource_properties("AWS::SNS::Subscription", {
        "Protocol": "email",
        "Endpoint": "test@example.com"
    })