#!/usr/bin/env zsh

# OpenSecOps Foundation Component Git Repository Setup
#
# This script configures the dual-repository workflow used by OpenSecOps Foundation components,
# setting up proper git remotes for both development and publication workflows.
#
# What it configures:
# - 'origin' remote: Points to development repository (e.g., PeterBengtson/Component-DEV)
# - 'OpenSecOps' remote: Points to published repository (OpenSecOps-Org/Component)
#
# The dual-repository pattern enables:
# - Messy development commits in personal repositories
# - Clean release-only history in public OpenSecOps repositories  
# - Professional presentation without losing development history
#
# This setup is required before using the ./publish script to create clean releases.
#
# Usage:
#   ./setup [component-name]    # Component name for published repository
#
# Run this script once when setting up a new Foundation component to enable the 
# publishing workflow that maintains clean public repository history.

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "There are uncommitted changes. Please commit or stash them before running this script."
    exit 1
fi

# Check for repository name argument
if [ -z "$1" ]; then
    echo "Please provide the repository name (e.g., SOAR-releases)."
    exit 1
fi

REPO_NAME=$1

# Add OpenSecOps organization repository as a remote (if it doesn't already exist)
if ! git remote | grep -q 'OpenSecOps'; then
    git remote add OpenSecOps "https://github.com/OpenSecOps-Org/$REPO_NAME.git"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add 'OpenSecOps' remote."
        exit 1
    fi
else
    echo "'OpenSecOps' remote already exists"
fi

# Switch back to the main branch before finishing
git checkout main
if [ $? -ne 0 ]; then
    echo "Error: Failed to switch back to 'main' branch."
    exit 1
fi
