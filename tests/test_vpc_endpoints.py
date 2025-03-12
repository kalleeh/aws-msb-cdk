import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.vpc_stack import VpcStack
from aws_msb_cdk.vpc_endpoints_stack import VpcEndpointsStack

@pytest.fixture
def vpc_stack():
    app = cdk.App()
    vpc_stack = VpcStack(app, "TestVpcStack")
    return vpc_stack

@pytest.fixture
def vpc_endpoints_stack(vpc_stack):
    app = cdk.App()
    vpc_endpoints_stack = VpcEndpointsStack(app, "TestVpcEndpointsStack", vpc=vpc_stack.vpc)
    return vpc_endpoints_stack

def test_vpc_endpoints_security_group_created(vpc_endpoints_stack):
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Verify security group is created
    template.resource_count_is("AWS::EC2::SecurityGroup", 1)
    
    # Verify security group has ingress rule for HTTPS
    template.has_resource_properties("AWS::EC2::SecurityGroupIngress", {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443
    })

def test_gateway_endpoints_created(vpc_endpoints_stack):
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Verify S3 gateway endpoint is created
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.string_like_regexp("s3"),
        "VpcEndpointType": "Gateway"
    })
    
    # Verify DynamoDB gateway endpoint is created
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.string_like_regexp("dynamodb"),
        "VpcEndpointType": "Gateway"
    })

def test_interface_endpoints_created(vpc_endpoints_stack):
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Count the number of interface endpoints (should be at least 13)
    interface_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "VpcEndpointType": "Interface"
        }
    })
    
    assert len(interface_endpoints) >= 13
    
    # Verify some key interface endpoints
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.string_like_regexp("ssm"),
        "VpcEndpointType": "Interface",
        "PrivateDnsEnabled": True
    })
    
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.string_like_regexp("kms"),
        "VpcEndpointType": "Interface",
        "PrivateDnsEnabled": True
    })

def test_endpoint_policies(vpc_endpoints_stack):
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Verify S3 endpoint has a policy
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.string_like_regexp("s3"),
        "PolicyDocument": Match.object_like({
            "Statement": Match.array_with([
                Match.object_like({
                    "Action": Match.array_with([
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket"
                    ])
                })
            ])
        })
    })
    
    # Verify DynamoDB endpoint has a policy
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.string_like_regexp("dynamodb"),
        "PolicyDocument": Match.object_like({
            "Statement": Match.array_with([
                Match.object_like({
                    "Action": Match.array_with([
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:Query",
                        "dynamodb:Scan"
                    ])
                })
            ])
        })
    })