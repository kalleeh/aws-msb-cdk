import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.vpc_stack import VpcStack

class TestVpcStack:
    @pytest.fixture
    def app(self):
        return cdk.App()
    
    @pytest.fixture
    def vpc_stack(self, app):
        class MockVpcStack(VpcStack):
            def create_vpc_endpoints(self, vpc):
                # Override to avoid subnet issues in testing
                pass
        
        return MockVpcStack(app, "TestVpcStack")
    
    def test_vpc_created(self, vpc_stack):
        template = Template.from_stack(vpc_stack)
        
        # Verify VPC is created
        template.resource_count_is("AWS::EC2::VPC", 1)
        
        # Verify VPC properties
        template.has_resource_properties("AWS::EC2::VPC", {
            "CidrBlock": "10.0.0.0/16",
            "EnableDnsHostnames": True,
            "EnableDnsSupport": True
        })
    
    def test_security_groups_created(self, vpc_stack):
        template = Template.from_stack(vpc_stack)
        
        # Verify security groups are created
        template.resource_count_is("AWS::EC2::SecurityGroup", 2)  # Bastion and App SGs
        
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