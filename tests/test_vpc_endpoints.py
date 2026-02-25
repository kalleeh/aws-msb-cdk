import aws_cdk as cdk
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.vpc_stack import VpcStack


def test_vpc_endpoints_security_group_created():
    """VpcStack creates a security group for VPC endpoints"""
    app = cdk.App()
    stack = VpcStack(app, "TestVpcStack")
    template = Template.from_stack(stack)

    # Endpoint SG allows HTTPS from within VPC
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
    """VpcStack creates S3 and DynamoDB gateway endpoints (free)"""
    app = cdk.App()
    stack = VpcStack(app, "TestVpcStack")
    template = Template.from_stack(stack)

    gateway_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {"VpcEndpointType": "Gateway"}
    })
    assert len(gateway_endpoints) == 2


def test_interface_endpoints_created():
    """VpcStack creates interface endpoints for AWS services"""
    app = cdk.App()
    stack = VpcStack(app, "TestVpcStack")
    template = Template.from_stack(stack)

    interface_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {"VpcEndpointType": "Interface"}
    })
    assert len(interface_endpoints) >= 5

    template.has_resource_properties("AWS::EC2::VPCEndpoint", {
        "VpcEndpointType": "Interface",
        "PrivateDnsEnabled": True
    })


def test_endpoint_policies():
    """Gateway endpoints have resource policies"""
    app = cdk.App()
    stack = VpcStack(app, "TestVpcStack")
    template = Template.from_stack(stack)

    gateway_endpoints = template.find_resources("AWS::EC2::VPCEndpoint", {
        "Properties": {"VpcEndpointType": "Gateway"}
    })

    for endpoint_id, endpoint in gateway_endpoints.items():
        assert "PolicyDocument" in endpoint["Properties"]
