#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Setting up development environment for AWS MSB CDK project...${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Check if virtual environment exists, create if not
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source .venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install development dependencies
echo -e "${YELLOW}Installing development dependencies...${NC}"
pip install -e ".[dev]"

# Install pre-commit hooks if pre-commit is available
if command -v pre-commit &> /dev/null; then
    echo -e "${YELLOW}Setting up pre-commit hooks...${NC}"
    pre-commit install
fi

# Create .env.test file if it doesn't exist
if [ ! -f ".env.test" ]; then
    echo -e "${YELLOW}Creating .env.test file...${NC}"
    cat > .env.test << EOL
# Test environment variables - do not use real credentials
AWS_ACCESS_KEY_ID=TESTING_FAKE_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=TESTING_FAKE_SECRET_ACCESS_KEY
CDK_DEFAULT_ACCOUNT=123456789012
CDK_DEFAULT_REGION=us-east-1
AWS_REGION=us-east-1
PYTHONPATH=${PWD}
PYTEST_ADDOPTS="-v"
# Set to 1 to enable test coverage reporting
ENABLE_COVERAGE=1
# Disable AWS credential checks for testing
AWS_SDK_LOAD_CONFIG=0
EOL
fi

# Run a simple test to verify setup
echo -e "${YELLOW}Running a test to verify setup...${NC}"
python -m pytest tests/test_imports.py -v

echo -e "${GREEN}Development environment setup complete!${NC}"
echo -e "${GREEN}To activate the virtual environment, run: source .venv/bin/activate${NC}"
echo -e "${GREEN}To run tests in VSCode, use the Test Explorer or run: python -m pytest${NC}"