import setuptools

with open("README.md") as fp:
    long_description = fp.read()

setuptools.setup(
    name="aws-msb-cdk",
    version="1.0.0",
    description="AWS Minimum Security Baseline CDK Implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="AWS MSB Team",
    package_dir={"": "aws_msb_cdk"},
    packages=setuptools.find_packages(where="aws_msb_cdk"),
    install_requires=[
        "aws-cdk-lib>=2.100.0",
        "constructs>=10.3.0",
        "boto3>=1.34.0",
    ],
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
)