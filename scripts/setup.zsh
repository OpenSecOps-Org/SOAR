#!/usr/bin/env zsh

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

# Add CloudSecOps organization repository as a remote (if it doesn't already exist)
if ! git remote | grep -q 'cloudsecops'; then
    git remote add cloudsecops "https://github.com/CloudSecOps-Org/$REPO_NAME.git"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add 'cloudsecops' remote."
        exit 1
    fi
else
    echo "'cloudsecops' remote already exists"
fi

# Switch back to the main branch before finishing
git checkout main
if [ $? -ne 0 ]; then
    echo "Error: Failed to switch back to 'main' branch."
    exit 1
fi
