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

# Get the repository name from the 'delegat' remote URL
DELEGAT_REMOTE_URL=$(git remote get-url delegat)
REPO_NAME=$(basename -s .git "$DELEGAT_REMOTE_URL")

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

# Check if the 'releases' branch exists
if ! git rev-parse --verify releases > /dev/null 2>&1; then
    # Clean up the working directory before creating a new branch
    git clean -fd
    # For a fresh releases branch, squash all the existing commits into one
    git checkout --orphan releases
    git add -A
    git commit -m "Initial release $TAG_VERSION"
    git tag $TAG_VERSION
else
    # Check if `main` and `releases` are equal
    if git diff main releases --quiet; then
        # Check if delegat branch is empty or doesn't exist
        if ! git ls-remote --heads delegat main | grep main > /dev/null; then
            git checkout --orphan releases
            git add -A
            git commit -m "Initial release $TAG_VERSION"
            git tag $TAG_VERSION
        else
            echo "'main' and 'releases' are equal. No changes to publish."
            exit 0
        fi
    else
        git checkout releases
        git merge main --squash --allow-unrelated-histories -X theirs
        if [ $? -ne 0 ]; then
            echo "Error: Squash merge failed."
            exit 1
        fi

        # Commit the squashed changes
        git commit -m "Release $TAG_VERSION"
        if [ $? -ne 0 ]; then
            echo "Error: Commit of squashed changes failed."
            exit 1
        fi

        # Tag the release
        if ! git rev-parse $TAG_VERSION > /dev/null 2>&1; then
            git tag $TAG_VERSION
            if [ $? -ne 0 ]; then
                echo "Error: Tagging failed."
                exit 1
            fi
        else
            echo "Tag '$TAG_VERSION' already exists. Proceeding without creating a new tag."
        fi
    fi
fi

# Push the release branch and tags to the dev repo
git push origin releases --tags
if [ $? -ne 0 ]; then
    echo "Error: Pushing to origin failed."
    exit 1
fi

# Push the releases branch to the delegat repo's main branch
git push delegat releases:main --tags
if [ $? -ne 0 ]; then
    echo "Error: Pushing to delegat failed."
    exit 1
fi
