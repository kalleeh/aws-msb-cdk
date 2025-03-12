import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.vpc_stack import VpcStack

@pytest.fixture
def vpc_stack():
    app = cdk.App()
    vpc_stack = VpcStack(app, "TestVpcStack")
    return vpc_stack

def test_vpc_created(vpc_stack):
    template = Template.from_stack(vpc_stack)
    
    # Verify VPC is created
    template.resource_count_is("AWS::EC2::VPC", 1)
    
    # Verify VPC properties
    template.has_resource_properties("AWS::EC2::VPC", {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsHostnames": True,
        "EnableDnsSupport": True,
        "Tags": Match.array_with([
            {
                "Key": "Name",
                "Value": Match.string_like_regexp("msb-vpc-")
            }
        ])
    })

def test_security_groups_created(vpc_stack):
    template = Template.from_stack(vpc_stack)
    
    # Verify security groups are created
    template.resource_count_is("AWS::EC2::SecurityGroup", 3)  # Bastion, App, and VPC Endpoint SGs
    
    # Verify bastion security group
    template.has_resource_properties("AWS::EC2::SecurityGroup", {
        "GroupDescription": "Security group for bastion hosts",
        "GroupName": "msb-bastion-sg"
    })
    
    # Verify application security group
    template.has_resource_properties("AWS::EC2::SecurityGroup", {
        "GroupDescription": "Security group for application servers",
        "GroupName": "msb-application-sg"
    })
    
    # Verify VPC endpoint security group
    template.has_resource_properties("AWS::EC2::SecurityGroup", {
        "GroupDescription": "Security group for VPC endpoints"
    })

def test_vpc_endpoints_created(vpc_stack):
    template = Template.from_stack(vpc_stack)
    
    # Verify gateway endpoints are created
    s3_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "ServiceName": Match.string_like_regexp("s3"),
            "VpcEndpointType": "Gateway"
        }
    })
    assert len(s3_endpoints) == 1
    
    dynamodb_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "ServiceName": Match.string_like_regexp("dynamodb"),
            "VpcEndpointType": "Gateway"
        }
    })
    assert len(dynamodb_endpoints) == 1
    
    # Verify interface endpoints are created
    interface_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "VpcEndpointType": "Interface"
        }
    })
    assert len(interface_endpoints) >= 13  # At least 13 interface endpoints

def test_endpoint_policies(vpc_stack):
    template = Template.from_stack(vpc_stack)
    
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