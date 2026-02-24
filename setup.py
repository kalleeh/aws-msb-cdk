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
    extras_require={
        "dev": [
            "pytest==6.2.5",
            "pytest-cov==4.1.0",
            "pytest-mock==3.10.0",
            "pytest-xdist==3.3.1",
            "pytest-env==0.8.2",
            "pytest-timeout==2.1.0",
            "pytest-randomly==3.13.0",
            "pytest-typeguard==1.5.0",
            "flake8==6.1.0",
            "pylint==2.17.5",
            "autopep8==2.0.4",
            "black==23.9.1",
            "isort==5.12.0",
            "coverage==7.3.2",
            "moto==4.2.5",
            "boto3-stubs[essential]==1.28.57",
            "mypy==1.5.1",
            "types-setuptools==68.2.0.0",
            "types-boto3==1.0.2",
        ],
    },
    python_requires=">=3.13",
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