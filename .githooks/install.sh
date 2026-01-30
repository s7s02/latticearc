#!/bin/bash
# Install git hooks for LatticeArc development
#
# Usage: ./.githooks/install.sh

set -e

echo "Installing git hooks..."
git config core.hooksPath .githooks
echo "Git hooks installed. Pre-commit formatting is now enabled."
