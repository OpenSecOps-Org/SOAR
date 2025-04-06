#!/usr/bin/env zsh

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

# Get the repository name - try delegat remote first, then origin if delegat doesn't exist
if git remote | grep -q 'delegat'; then
    REMOTE_URL=$(git remote get-url delegat)
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

# Push the releases branch to the delegat repo's main branch if it exists
if git remote | grep -q 'delegat'; then
    git push delegat releases:main --tags
    if [ $? -ne 0 ]; then
        echo "Error: Pushing to delegat failed."
        exit 1
    fi
fi

# Push the releases branch to the cloudsecops repo's main branch
if git remote | grep -q 'cloudsecops'; then
    git push cloudsecops releases:main --tags
    if [ $? -ne 0 ]; then
        echo "Error: Pushing to cloudsecops failed."
        exit 1
    fi
fi
