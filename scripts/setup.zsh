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

# Add Delegat's company repository as a remote (if it doesn't already exist)
if ! git remote | grep -q 'delegat'; then
    git remote add delegat "https://github.com/Delegat-AB/$REPO_NAME.git"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add 'delegat' remote."
        exit 1
    fi
else
    echo "'delegat' remote already exists"
fi

# Switch back to the main branch before finishing
git checkout main
if [ $? -ne 0 ]; then
    echo "Error: Failed to switch back to 'main' branch."
    exit 1
fi
