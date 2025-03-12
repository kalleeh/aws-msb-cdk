#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default values
NOTIFICATION_EMAIL=""
GLOBAL_REGION="us-east-1"
TARGET_REGIONS=""
TARGET=""
PROFILE=""
BOOTSTRAP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --email)
      NOTIFICATION_EMAIL="$2"
      shift 2
      ;;
    --global-region)
      GLOBAL_REGION="$2"
      shift 2
      ;;
    --regions)
      TARGET_REGIONS="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --bootstrap)
      BOOTSTRAP=true
      shift
      ;;
    --help)
      echo "Usage: ./deploy.sh [options]"
      echo ""
      echo "Options:"
      echo "  --email EMAIL          Notification email address (required)"
      echo "  --global-region REGION Global region for IAM, S3, etc. (default: us-east-1)"
      echo "  --regions REGIONS      Comma-separated list of target regions (default: global-region)"
      echo "  --target TARGET        Deploy only 'global' or 'regional' resources (default: both)"
      echo "  --profile PROFILE      AWS CLI profile to use"
      echo "  --bootstrap            Bootstrap CDK in the target regions"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if notification email is provided
if [ -z "$NOTIFICATION_EMAIL" ]; then
  echo -e "${RED}Error: Notification email is required. Use --email to specify it.${NC}"
  exit 1
fi

# If no target regions specified, use global region
if [ -z "$TARGET_REGIONS" ]; then
  TARGET_REGIONS="$GLOBAL_REGION"
fi

# Convert comma-separated regions to array
IFS=',' read -ra REGION_ARRAY <<< "$TARGET_REGIONS"

# Prepare profile option if provided
PROFILE_OPT=""
if [ -n "$PROFILE" ]; then
  PROFILE_OPT="--profile $PROFILE"
  export AWS_PROFILE="$PROFILE"
fi

# Check AWS credentials
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws $PROFILE_OPT sts get-caller-identity > /dev/null 2>&1; then
  echo -e "${RED}Error: Unable to validate AWS credentials. Please check your AWS configuration.${NC}"
  exit 1
fi

# Get account ID
ACCOUNT_ID=$(aws $PROFILE_OPT sts get-caller-identity --query "Account" --output text)
echo -e "${GREEN}Using AWS Account: $ACCOUNT_ID${NC}"

# Bootstrap CDK if requested
if [ "$BOOTSTRAP" = true ]; then
  echo -e "${YELLOW}Bootstrapping CDK in the global region: $GLOBAL_REGION${NC}"
  npx cdk bootstrap $PROFILE_OPT aws://$ACCOUNT_ID/$GLOBAL_REGION
  
  # Bootstrap other regions if different from global
  for REGION in "${REGION_ARRAY[@]}"; do
    if [ "$REGION" != "$GLOBAL_REGION" ]; then
      echo -e "${YELLOW}Bootstrapping CDK in region: $REGION${NC}"
      npx cdk bootstrap $PROFILE_OPT aws://$ACCOUNT_ID/$REGION
    fi
  done
fi

# Prepare target option
TARGET_OPT=""
if [ -n "$TARGET" ]; then
  TARGET_OPT="--context target=$TARGET"
fi

# Prepare regions context
REGIONS_CONTEXT="--context global_region=$GLOBAL_REGION --context target_regions=$TARGET_REGIONS"

# Deploy the stacks
echo -e "${YELLOW}Deploying AWS MSB CDK stacks...${NC}"
npx cdk deploy $PROFILE_OPT --all \
  --context notification_email=$NOTIFICATION_EMAIL \
  $REGIONS_CONTEXT \
  $TARGET_OPT \
  --require-approval never

echo -e "${GREEN}Deployment completed successfully!${NC}"