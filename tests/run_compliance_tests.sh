#!/bin/bash

# Run Compliance Tests and Generate Report
# This script runs the compliance tests and generates a comprehensive report

# Set colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AWS MSB Compliance Test Suite ===${NC}"
echo "Running tests and generating compliance report..."

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
    echo "Virtual environment activated"
fi

# Run the tests
echo -e "\n${YELLOW}Running compliance tests...${NC}"
python -m pytest tests/test_compliance.py -v

# Check if tests passed
if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}All compliance tests passed!${NC}"
else
    echo -e "\n${RED}Some compliance tests failed. Please review the output above.${NC}"
    echo "Continuing with report generation..."
fi

# Generate HTML report
echo -e "\n${YELLOW}Generating HTML compliance report...${NC}"
python generate_html_report.py

echo -e "\n${GREEN}Compliance testing and reporting complete!${NC}"
echo "Reports generated:"
echo "  - HTML: docs/compliance_report.html"
echo -e "\nOpen the HTML report in your browser for a detailed view of compliance coverage."