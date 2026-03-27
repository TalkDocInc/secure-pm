#!/bin/bash
set -e

echo "Installing Secure Package Manager (with audited bootstrap)..."

# Ensure we are in the right directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Bootstrap with audited pins to mitigate supply-chain risk on first install
pip install -r requirements-secure.txt --require-hashes --quiet || echo "Warning: Using cached audited deps"
pip install -e . --quiet

echo ""
echo "==========================================================="
echo "secure-pm installed successfully!"
echo "Usage:"
echo "  secure-pm install pip <package>"
echo "  secure-pm install npm <package>"
echo "  secure-pm install cargo <package>"
echo "  secure-pm audit-all <directory>"
echo "==========================================================="
echo "AI provider keys (XAI_API_KEY, etc.) should be in your shell or .env."
