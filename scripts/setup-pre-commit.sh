#!/bin/bash
# Setup pre-commit hooks
# Usage: ./scripts/setup-pre-commit.sh

set -e

echo "Installing pre-commit..."
pip install pre-commit

echo "Installing pre-commit hooks..."
pre-commit install

echo "Running pre-commit on all files (first time)..."
pre-commit run --all-files || true

echo "Pre-commit hooks installed successfully!"
echo "Hooks will now run automatically on 'git commit'"
