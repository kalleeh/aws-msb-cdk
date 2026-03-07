#!/usr/bin/env bash
# setup.sh — Guided first-time deployment for AWS Minimum Security Baseline (MSB)
#
# Usage: ./setup.sh [--help]
#
# This script walks you through deploying MSB to your AWS account.
# It checks prerequisites, collects configuration, and runs the CDK deployment.

set -e

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat <<'EOF'
AWS Minimum Security Baseline (MSB) — Setup Script

USAGE
    ./setup.sh [--help]

WHAT THIS SCRIPT DOES
    1. Verifies prerequisites (AWS CLI, Node.js, Python 3.9+)
    2. Creates a Python virtual environment and installs dependencies
    3. Installs the AWS CDK CLI if it is not already present
    4. Prompts you for the configuration values required to deploy MSB
    5. Shows a deployment summary and asks for confirmation
    6. Bootstraps your AWS account for CDK (if not already bootstrapped)
    7. Deploys all MSB stacks in the correct order

CONFIGURATION COLLECTED
    notification_email      — Where security alerts and SNS confirmations are sent
    security_contact_phone  — Phone number for the security contact in IAM
    global_region           — The primary AWS region (default: us-east-1)
    target_regions          — Additional regions to deploy into (optional)
    enable_waf              — Deploy a WAFv2 WebACL for internet-facing resources
    enable_object_lock      — Enable WORM object lock on the centralised log bucket
                              (recommended for regulated industries)

ESTIMATED COST
    $30–75 / month for a single-region deployment.
    See docs/cost.md for a line-item breakdown.

REQUIREMENTS
    - AWS CLI installed and configured (run `aws configure` first)
    - Node.js 14+ (required by the CDK CLI)
    - Python 3.9+

EOF
    exit 0
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# ANSI colours — used only when stdout is a terminal
if [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[0;32m"
    YELLOW="\033[0;33m"
    RED="\033[0;31m"
    CYAN="\033[0;36m"
    RESET="\033[0m"
else
    BOLD="" GREEN="" YELLOW="" RED="" CYAN="" RESET=""
fi

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}$1${RESET}"
    echo "───────────────────────────────────────"
}

print_ok()   { echo -e "  ${GREEN}[ok]${RESET}  $1"; }
print_warn() { echo -e "  ${YELLOW}[warn]${RESET} $1"; }
print_err()  { echo -e "  ${RED}[err]${RESET}  $1" >&2; }
print_info() { echo -e "  ${CYAN}-->${RESET}   $1"; }

# Prompt for a required (non-empty) value.
# prompt_required VAR_NAME "prompt text"
prompt_required() {
    local var_name="$1"
    local prompt_text="$2"
    local value=""
    while [ -z "$value" ]; do
        printf "  %s " "$prompt_text"
        read -r value
        if [ -z "$value" ]; then
            print_warn "This field is required — please enter a value."
        fi
    done
    eval "${var_name}=\"\$value\""
}

# Prompt with a default value.
# prompt_default VAR_NAME "prompt text" "default"
prompt_default() {
    local var_name="$1"
    local prompt_text="$2"
    local default="$3"
    printf "  %s " "$prompt_text"
    read -r value
    if [ -z "$value" ]; then
        value="$default"
    fi
    eval "${var_name}=\"\$value\""
}

# Prompt for a yes/no question; default is 'no'.
# prompt_yn VAR_NAME "prompt text"   → sets VAR_NAME to "true" or "false"
prompt_yn() {
    local var_name="$1"
    local prompt_text="$2"
    printf "  %s " "$prompt_text"
    read -r yn
    case "$yn" in
        [Yy]|[Yy][Ee][Ss]) eval "${var_name}=true"  ;;
        *)                   eval "${var_name}=false" ;;
    esac
}

# ---------------------------------------------------------------------------
# Resolve the script's own directory so all relative paths stay correct
# regardless of where the user runs the script from.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Step 1 — Prerequisites
# ---------------------------------------------------------------------------
print_header "Step 1 of 6: Checking prerequisites"

# AWS CLI
if ! command -v aws > /dev/null 2>&1; then
    print_err "AWS CLI is not installed."
    echo ""
    echo "  Install it from: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    echo "  Then run: aws configure"
    exit 1
fi
print_ok "AWS CLI found ($(aws --version 2>&1 | head -1))"

# AWS credentials / identity
CALLER_IDENTITY=$(aws sts get-caller-identity 2>&1) || {
    print_err "AWS credentials are not configured or are invalid."
    echo ""
    echo "  Run 'aws configure' to set up your credentials."
    echo "  If you are using a named profile, set: export AWS_PROFILE=<profile>"
    exit 1
}

AWS_ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
AWS_REGION="${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || echo "")}"
if [ -z "$AWS_REGION" ]; then
    AWS_REGION="us-east-1"
    print_warn "No default region found in AWS config; will use us-east-1 as the global region."
fi

print_ok "AWS account:  ${AWS_ACCOUNT_ID}"
print_ok "AWS region:   ${AWS_REGION} (currently configured)"

# Node.js
if ! command -v node > /dev/null 2>&1; then
    print_err "Node.js is not installed (required by the AWS CDK CLI)."
    echo ""
    echo "  Install it from: https://nodejs.org/  (LTS version recommended)"
    exit 1
fi
NODE_VERSION=$(node --version)
print_ok "Node.js found (${NODE_VERSION})"

# Python 3.9+
if ! command -v python3 > /dev/null 2>&1; then
    print_err "python3 is not installed."
    echo ""
    echo "  Install Python 3.9 or later from: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]; }; then
    print_err "Python 3.9+ is required (found ${PYTHON_VERSION})."
    echo ""
    echo "  Install a newer version from: https://www.python.org/downloads/"
    exit 1
fi
print_ok "Python found (${PYTHON_VERSION})"

# ---------------------------------------------------------------------------
# Step 2 — Python virtual environment
# ---------------------------------------------------------------------------
print_header "Step 2 of 6: Python virtual environment"

VENV_DIR="${SCRIPT_DIR}/.venv"

if [ ! -d "$VENV_DIR" ]; then
    print_info "Creating virtual environment at .venv ..."
    python3 -m venv "$VENV_DIR"
    print_ok "Virtual environment created."
else
    print_ok "Virtual environment already exists (.venv)"
fi

# Activate the venv for the remainder of this script
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

print_info "Installing Python dependencies ..."
pip install --quiet --upgrade pip
pip install --quiet -r "${SCRIPT_DIR}/requirements.txt"
print_ok "Python dependencies installed."

# ---------------------------------------------------------------------------
# Step 3 — CDK CLI
# ---------------------------------------------------------------------------
print_header "Step 3 of 6: AWS CDK CLI"

if ! command -v cdk > /dev/null 2>&1; then
    print_info "CDK CLI not found — installing globally via npm ..."
    npm install -g aws-cdk
    print_ok "CDK installed ($(cdk --version))"
else
    print_ok "CDK CLI already installed ($(cdk --version))"
fi

# ---------------------------------------------------------------------------
# Step 4 — Required configuration
# ---------------------------------------------------------------------------
print_header "Step 4 of 6: Required configuration"

echo "  Please answer the following questions."
echo "  Fields marked with * are required."
echo ""

prompt_required NOTIFICATION_EMAIL   "* Email address for security alerts:"
prompt_required SECURITY_PHONE       "* Phone number for security contact (e.g. +1-555-123-4567):"
prompt_default  GLOBAL_REGION        "  Primary AWS region (press Enter for ${AWS_REGION}):" "$AWS_REGION"

# ---------------------------------------------------------------------------
# Step 5 — Optional configuration
# ---------------------------------------------------------------------------
print_header "Step 5 of 6: Optional configuration"

echo "  Press Enter to accept the defaults shown in brackets."
echo ""

printf "  Deploy to additional regions? (leave blank for primary region only): "
read -r EXTRA_REGIONS_INPUT

if [ -n "$EXTRA_REGIONS_INPUT" ]; then
    # Build a JSON array from space- or comma-separated input
    # Convert commas to spaces, then build array
    REGIONS_NORMALIZED=$(echo "$EXTRA_REGIONS_INPUT" | tr ',' ' ')
    TARGET_REGIONS_JSON="[\"${GLOBAL_REGION}\""
    for r in $REGIONS_NORMALIZED; do
        r_trimmed=$(echo "$r" | tr -d ' ')
        if [ -n "$r_trimmed" ] && [ "$r_trimmed" != "$GLOBAL_REGION" ]; then
            TARGET_REGIONS_JSON="${TARGET_REGIONS_JSON}, \"${r_trimmed}\""
        fi
    done
    TARGET_REGIONS_JSON="${TARGET_REGIONS_JSON}]"

    # Human-readable list for the summary
    TARGET_REGIONS_DISPLAY=$(echo "$TARGET_REGIONS_JSON" | tr -d '[]"' | tr ',' ' ' | tr -s ' ')
else
    TARGET_REGIONS_JSON="[\"${GLOBAL_REGION}\"]"
    TARGET_REGIONS_DISPLAY="$GLOBAL_REGION (primary only)"
fi

prompt_yn ENABLE_WAF         "  Enable WAF Web ACL for internet-facing applications? (y/N):"
prompt_yn ENABLE_OBJECT_LOCK "  Enable WORM object lock on logs? Recommended for regulated industries (y/N):"

# ---------------------------------------------------------------------------
# Step 6 — Deployment summary and confirmation
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "${BOLD} MSB Deployment Summary${RESET}"
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
printf " %-18s %s\n" "AWS Account:"     "$AWS_ACCOUNT_ID"
printf " %-18s %s\n" "Primary region:"  "$GLOBAL_REGION"
printf " %-18s %s\n" "All regions:"     "$TARGET_REGIONS_DISPLAY"
printf " %-18s %s\n" "Alert email:"     "$NOTIFICATION_EMAIL"
printf " %-18s %s\n" "Security phone:"  "$SECURITY_PHONE"
printf " %-18s %s\n" "WAF enabled:"     "$ENABLE_WAF"
printf " %-18s %s\n" "Object lock:"     "$ENABLE_OBJECT_LOCK"
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo ""
echo "  This will deploy security monitoring, alerting, and baseline"
echo "  controls. Estimated cost: \$30-75/month (see docs/cost.md)."
echo ""

printf "  Proceed with deployment? (y/N): "
read -r CONFIRM
case "$CONFIRM" in
    [Yy]|[Yy][Ee][Ss]) ;;
    *)
        echo ""
        echo "  Deployment cancelled. No changes were made."
        exit 0
        ;;
esac

# ---------------------------------------------------------------------------
# Build the --context flags used in every cdk command
# ---------------------------------------------------------------------------
CTX_FLAGS=""
CTX_FLAGS="${CTX_FLAGS} --context notification_email=${NOTIFICATION_EMAIL}"
CTX_FLAGS="${CTX_FLAGS} --context security_contact_phone=${SECURITY_PHONE}"
CTX_FLAGS="${CTX_FLAGS} --context global_region=${GLOBAL_REGION}"
CTX_FLAGS="${CTX_FLAGS} --context target_regions=${TARGET_REGIONS_JSON}"
CTX_FLAGS="${CTX_FLAGS} --context enable_waf=${ENABLE_WAF}"
CTX_FLAGS="${CTX_FLAGS} --context enable_object_lock=${ENABLE_OBJECT_LOCK}"

# ---------------------------------------------------------------------------
# CDK Bootstrap
# ---------------------------------------------------------------------------
print_header "Bootstrapping AWS environment"

print_info "Running: cdk bootstrap (account ${AWS_ACCOUNT_ID} / region ${GLOBAL_REGION})"
(
    cd "$SCRIPT_DIR"
    # Bootstrap global region
    # shellcheck disable=SC2086
    cdk bootstrap "aws://${AWS_ACCOUNT_ID}/${GLOBAL_REGION}" $CTX_FLAGS
)

# Bootstrap any additional regions
for r in $(echo "$TARGET_REGIONS_JSON" | tr -d '[]"' | tr ',' '\n' | tr -d ' '); do
    if [ "$r" != "$GLOBAL_REGION" ]; then
        print_info "Bootstrapping additional region: ${r}"
        (
            cd "$SCRIPT_DIR"
            # shellcheck disable=SC2086
            cdk bootstrap "aws://${AWS_ACCOUNT_ID}/${r}" $CTX_FLAGS
        )
    fi
done

print_ok "Bootstrap complete."

# ---------------------------------------------------------------------------
# Deploy — global stacks first, then all stacks
# ---------------------------------------------------------------------------
print_header "Deploying MSB stacks"

cd "$SCRIPT_DIR"

print_info "Deploying global stacks ..."
# shellcheck disable=SC2086
cdk deploy MSB-KMS-Global MSB-Logging-Global MSB-S3-Security MSB-IAM-Global \
    --require-approval never \
    $CTX_FLAGS

print_ok "Global stacks deployed."

print_info "Deploying all remaining stacks ..."
# shellcheck disable=SC2086
cdk deploy --all \
    --require-approval never \
    $CTX_FLAGS

print_ok "All stacks deployed successfully."

# ---------------------------------------------------------------------------
# Post-deploy instructions
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "${BOLD} Deployment Complete — Next Steps${RESET}"
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}1. Confirm your SNS email subscription${RESET}"
echo "     Check your inbox at: ${NOTIFICATION_EMAIL}"
echo "     You will have received a message from AWS Notifications."
echo "     Click the 'Confirm subscription' link to start receiving alerts."
echo ""
echo -e "  ${BOLD}2. Enable MFA on the AWS root account${RESET}"
echo "     This is the single most important thing you can do to secure"
echo "     your account. Do it now — it takes less than 5 minutes."
echo "     https://console.aws.amazon.com/iam/home#/security_credentials"
echo ""

if [ "$ENABLE_WAF" = "true" ]; then
    echo -e "  ${BOLD}3. Associate the WAF WebACL with your resources${RESET}"
    echo "     Your WebACL ARN is exported as a CloudFormation output."
    echo "     Retrieve it with:"
    echo ""
    for r in $(echo "$TARGET_REGIONS_JSON" | tr -d '[]"' | tr ',' '\n' | tr -d ' '); do
        echo "       aws cloudformation describe-stacks \\"
        echo "         --stack-name MSB-WAF-${r} \\"
        echo "         --region ${r} \\"
        echo "         --query 'Stacks[0].Outputs[?OutputKey==\`WebACLArn\`].OutputValue' \\"
        echo "         --output text"
        echo ""
    done
    echo "     Then associate with an Application Load Balancer:"
    echo ""
    echo "       aws wafv2 associate-web-acl \\"
    echo "         --web-acl-arn <WebACLArn> \\"
    echo "         --resource-arn <your-alb-arn> \\"
    echo "         --region <region>"
    echo ""
    echo "     For API Gateway or CloudFront, see README.md for details."
    echo ""
fi

echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo ""
