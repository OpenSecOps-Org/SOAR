#!/usr/bin/env zsh

# OpenSecOps Foundation Component Publishing Workflow
#
# This script implements the sophisticated dual-repository publishing system used across
# OpenSecOps Foundation components to maintain clean public repositories while preserving
# full development history.
#
# What it does:
# - Collapses all messy development commits into a single clean release commit
# - Creates/updates a 'releases' branch with just the final state of files  
# - Tags the release with the version number from CHANGELOG.md or command line
# - Pushes to both development and published repositories with appropriate history
#
# Repository Pattern:
# - Development repo (origin): Full messy commit history for active development
# - Published repo (OpenSecOps): Clean release-only history for professional presentation
#
# This ensures the public OpenSecOps repositories have clean, meaningful commit histories
# while developers retain full working history in their development repositories.
#
# Usage:
#   ./publish [version]    # Version from CHANGELOG.md if not specified
#
# The dual-repository workflow ensures professional public repositories while preserving 
# complete development history for maintainers.

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "There are uncommitted changes. Please commit or stash them before running this script."
    exit 1
fi

# Check for version argument. If not provided, read from CHANGELOG.md
if [ -z "$1" ]; then
    if [ -f "$PWD/CHANGELOG.md" ]; then
        TAG_VERSION=$(awk '/^## v/{print $2; exit}' "$PWD/CHANGELOG.md")
    fi

    if [ -z "$TAG_VERSION" ]; then
        echo "Please provide a version tag (e.g., v1.0.0) or add it to the CHANGELOG.md in the format '## v1.0.0'"
        exit 1
    fi
else
    TAG_VERSION=$1
fi

# Check if the tag already exists
if git rev-parse $TAG_VERSION > /dev/null 2>&1; then
    echo "Tag '$TAG_VERSION' already exists. Exiting without creating a new tag."
    exit 0
fi

# Get the repository name - try OpenSecOps remote first, then origin if OpenSecOps doesn't exist
if git remote | grep -q 'OpenSecOps'; then
    REMOTE_URL=$(git remote get-url OpenSecOps)
else
    REMOTE_URL=$(git remote get-url origin)
fi
REPO_NAME=$(basename -s .git "$REMOTE_URL")

cleanup() {
    git checkout main
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to switch back to 'main' branch."
    fi
}

# Register cleanup function to run on script exit
trap cleanup EXIT

# Ensure on main branch & pull the latest changes
git checkout main
if [ $? -ne 0 ]; then
    echo "Error: Failed to switch to 'main' branch."
    exit 1
fi

git pull origin main
if [ $? -ne 0 ]; then
    echo "Error: Failed to pull latest changes from 'main'."
    exit 1
fi

# Get the tree object for the current HEAD of main
MAIN_TREE=$(git rev-parse HEAD^{tree})

# Check if the 'releases' branch exists
if ! git rev-parse --verify releases > /dev/null 2>&1; then
    # Create a fresh 'releases' branch from 'main'
    git checkout -b releases main
else
    # Checkout the 'releases' branch
    git checkout releases
fi

# Create a new commit on the 'releases' branch with the tree from 'main'
RELEASE_COMMIT=$(git commit-tree -m "Release $TAG_VERSION" $MAIN_TREE -p releases)

# Move the 'releases' branch to the new commit
git reset --hard $RELEASE_COMMIT

# Tag the release
git tag $TAG_VERSION

# Push the release branch and tags to the origin repo
git push origin releases --tags
if [ $? -ne 0 ]; then
    echo "Error: Pushing to origin failed."
    exit 1
fi

# Push the releases branch to the OpenSecOps repo's main branch
if git remote | grep -q 'OpenSecOps'; then
    git push OpenSecOps releases:main --tags
    if [ $? -ne 0 ]; then
        echo "Error: Pushing to OpenSecOps failed."
        exit 1
    fi
fi
