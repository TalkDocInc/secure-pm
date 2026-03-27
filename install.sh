#!/bin/bash
set -e

echo "Installing Secure Package Manager..."

# Ensure we are in the right directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Install the CLI globally
pip install -e .

echo ""
echo "==========================================================="
echo "secure-pm installed successfully!"
echo "Usage:"
echo "  secure-pm install pip <package>"
echo "  secure-pm install npm <package>"
echo "  secure-pm install cargo <package>"
echo "  secure-pm audit-all <directory>"
echo "==========================================================="
echo "Please make sure your AI provider keys (XAI_API_KEY, OPENAI_API_KEY, etc.) are available in your shell."
