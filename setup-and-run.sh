#!/bin/bash

###############################################################################
# Azure Cloud Shell Setup Script for AWS S3 to Azure Blob Copy Tool
###############################################################################
#
# This script automates the setup and execution of the AWS S3 to Azure Blob
# copy tool in Azure Cloud Shell. It performs the following steps:
# 1. Clones the repository (if not already cloned)
# 2. Sets up a Python virtual environment
# 3. Installs required Python dependencies
# 4. Runs the copyawstoazure.py script with provided parameters
#
# Usage:
#   bash setup-and-run.sh [OPTIONS]
#
# OPTIONS are passed directly to copyawstoazure.py. Common options include:
#   --account-name <name>     Azure Storage account name
#   --account-url <url>       Azure Storage account blob URL
#   --region <region>         AWS region hint for discovery
#   --access-key <key>        AWS access key ID
#   --secret-key <key>        AWS secret access key
#   --session-token <token>   AWS session token
#   --no-overwrite            Do not overwrite existing blobs
#   --max-concurrency <n>     Parallelism for uploads (default: 4)
#
# Example:
#   bash setup-and-run.sh --account-name mystorageacct --region us-east-1
#
# Environment Variables:
#   You can also set these environment variables instead of passing CLI args:
#   - AZURE_STORAGE_ACCOUNT_NAME
#   - AZURE_STORAGE_ACCOUNT_URL
#   - AWS_REGION
#   - AWS_ACCESS_KEY_ID
#   - AWS_SECRET_ACCESS_KEY
#   - AWS_SESSION_TOKEN
#
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/ahmedsza/awss3toazureblobcopy.git"
REPO_DIR="awss3toazureblobcopy"
VENV_DIR="venv"
PYTHON_CMD="python3"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AWS S3 to Azure Blob Copy Tool Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if Python 3 is available
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed or not in PATH${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Python 3 found: $($PYTHON_CMD --version)"
echo ""

# Step 1: Clone or update repository
echo -e "${YELLOW}Step 1: Cloning repository...${NC}"
if [ -d "$REPO_DIR" ]; then
    echo "Repository directory already exists. Pulling latest changes..."
    cd "$REPO_DIR"
    git pull || echo "Could not pull latest changes, using existing code"
    cd ..
else
    echo "Cloning repository from $REPO_URL..."
    git clone "$REPO_URL"
fi
echo -e "${GREEN}✓${NC} Repository ready"
echo ""

# Change to repository directory
cd "$REPO_DIR"

# Step 2: Set up virtual environment
echo -e "${YELLOW}Step 2: Setting up virtual environment...${NC}"
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists. Reusing it..."
else
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
fi
echo -e "${GREEN}✓${NC} Virtual environment ready"
echo ""

# Activate virtual environment
echo -e "${YELLOW}Step 3: Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"
echo -e "${GREEN}✓${NC} Virtual environment activated"
echo ""

# Step 4: Install dependencies
echo -e "${YELLOW}Step 4: Installing dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    echo "Installing packages from requirements.txt..."
    pip install --upgrade pip
    pip install -r requirements.txt
    echo -e "${GREEN}✓${NC} Dependencies installed"
else
    echo -e "${RED}Error: requirements.txt not found${NC}"
    exit 1
fi
echo ""

# Step 5: Verify Azure login
echo -e "${YELLOW}Step 5: Verifying Azure authentication...${NC}"
echo "Checking Azure CLI login status..."
if az account show 2>/dev/null 1>&2; then
    ACCOUNT_NAME=$(az account show --query "name" -o tsv 2>/dev/null)
    echo -e "${GREEN}✓${NC} Logged in to Azure as: $ACCOUNT_NAME"
else
    echo -e "${YELLOW}Warning: Not logged in to Azure CLI${NC}"
    echo "Run 'az login' before executing this script if you need Azure authentication"
fi
echo ""

# Step 6: Run the script
echo -e "${YELLOW}Step 6: Running copyawstoazure.py...${NC}"
echo "Command: python copyawstoazure.py $@"
echo ""
echo -e "${GREEN}========================================${NC}"
echo ""

# Run the main script with all passed arguments
python copyawstoazure.py "$@"

# Capture exit code
EXIT_CODE=$?

echo ""
echo -e "${GREEN}========================================${NC}"
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Script completed successfully!${NC}"
else
    echo -e "${RED}✗ Script completed with errors (exit code: $EXIT_CODE)${NC}"
fi
echo -e "${GREEN}========================================${NC}"

# Deactivate virtual environment
deactivate

exit $EXIT_CODE
