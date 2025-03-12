import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.vpc_stack import VpcStack
from aws_msb_cdk.vpc_endpoints_stack import VpcEndpointsStack

def test_vpc_endpoints_security_group_created():
    # Create a single app for both stacks to avoid cross-app reference issues
    app = cdk.App()
    vpc_stack = VpcStack(app, "TestVpcStack")
    vpc_endpoints_stack = VpcEndpointsStack(app, "TestVpcEndpointsStack", vpc=vpc_stack.vpc)
    
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Verify security group is created
    template.resource_count_is("AWS::EC2::SecurityGroup", 1)
    
    # Security group rules are embedded in the security group resource in CDK
    template.has_resource_properties("AWS::EC2::SecurityGroup", {
        "SecurityGroupIngress": Match.array_with([
            Match.object_like({
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443
            })
        ])
    })

def test_gateway_endpoints_created():
    # Create a single app for both stacks to avoid cross-app reference issues
    app = cdk.App()
    vpc_stack = VpcStack(app, "TestVpcStack")
    vpc_endpoints_stack = VpcEndpointsStack(app, "TestVpcEndpointsStack", vpc=vpc_stack.vpc)
    
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Verify S3 gateway endpoint is created - use Match.any_value() for ServiceName
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "ServiceName": Match.any_value(),
        "VpcEndpointType": "Gateway"
    })
    
    # Count gateway endpoints (should be 2 - S3 and DynamoDB)
    gateway_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "VpcEndpointType": "Gateway"
        }
    })
    
    assert len(gateway_endpoints) == 2

def test_interface_endpoints_created():
    # Create a single app for both stacks to avoid cross-app reference issues
    app = cdk.App()
    vpc_stack = VpcStack(app, "TestVpcStack")
    vpc_endpoints_stack = VpcEndpointsStack(app, "TestVpcEndpointsStack", vpc=vpc_stack.vpc)
    
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Count the number of interface endpoints (should be at least 13)
    interface_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "VpcEndpointType": "Interface"
        }
    })
    
    assert len(interface_endpoints) >= 13
    
    # Verify interface endpoints have PrivateDnsEnabled set to true
    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "VpcEndpointType": "Interface",
        "PrivateDnsEnabled": True
    })

def test_endpoint_policies():
    # Create a single app for both stacks to avoid cross-app reference issues
    app = cdk.App()
    vpc_stack = VpcStack(app, "TestVpcStack")
    vpc_endpoints_stack = VpcEndpointsStack(app, "TestVpcEndpointsStack", vpc=vpc_stack.vpc)
    
    template = Template.from_stack(vpc_endpoints_stack)
    
    # Verify endpoints have policies
    gateway_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {
            "VpcEndpointType": "Gateway"
        }
    })
    
    # Check that all gateway endpoints have a policy document
    for endpoint_id, endpoint in gateway_endpoints.items():
        assert "PolicyDocument" in endpoint["Properties"]