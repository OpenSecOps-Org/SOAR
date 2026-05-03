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
#   ./publish [--dry-run] [version]
#
# --dry-run: run the supply-chain release gate (drift, CVE, hash
# integrity, SECURITY.md staleness), report what would be tagged and
# pushed, and exit without modifying any local or remote state. A
# clean --dry-run means publish is safe to run.
#
# Version: read from CHANGELOG.md if not specified.
#
# The dual-repository workflow ensures professional public repositories while preserving
# complete development history for maintainers.

# --- Argument parsing -----------------------------------------------------
DRY_RUN=false
TAG_VERSION=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*) echo "unknown flag: $arg" >&2; exit 2 ;;
        *)  TAG_VERSION="$arg" ;;
    esac
done

# Check for uncommitted changes (skipped in dry-run — we want to be
# able to verify the gate even with WIP changes around).
if [[ "$DRY_RUN" != true ]]; then
    if ! git diff-index --quiet HEAD --; then
        echo "There are uncommitted changes. Please commit or stash them before running this script."
        exit 1
    fi
fi

# Resolve version from CHANGELOG.md if not provided.
if [ -z "$TAG_VERSION" ]; then
    if [ -f "$PWD/CHANGELOG.md" ]; then
        TAG_VERSION=$(awk '/^## v/{print $2; exit}' "$PWD/CHANGELOG.md")
    fi

    if [ -z "$TAG_VERSION" ]; then
        echo "Please provide a version tag (e.g., v1.0.0) or add it to the CHANGELOG.md in the format '## v1.0.0'"
        exit 1
    fi
fi

# --- Phase framing + wallclock helpers ------------------------------------
# Top-level [N/M] counters give the maintainer visibility into a run that
# now takes minutes (full hash-integrity download per dep + per-function
# CycloneDX SBOM generation). Timer per phase records wallclock elapsed
# so regressions in any one phase are noticed.
PHASE_TOTAL=4
phase_start=0
phase_banner() {
    # phase_banner <N> <description>
    phase_start=$SECONDS
    echo
    printf '═══ [%d/%d] %s ═══\n' "$1" "$PHASE_TOTAL" "$2"
}
phase_done() {
    # phase_done — emit elapsed line for the most recent phase_banner
    local elapsed=$((SECONDS - phase_start))
    local m=$((elapsed / 60))
    local s=$((elapsed % 60))
    if (( m > 0 )); then
        printf '    (elapsed: %dm %ds)\n' "$m" "$s"
    else
        printf '    (elapsed: %ds)\n' "$s"
    fi
}
TOTAL_START=$SECONDS

# --- Conversion-state detection -------------------------------------------
# `.security-config.toml` at repo root is the canonical "this repo has
# formally adopted the supply-chain framework" marker. Refresh
# distributes the template to every repo, but the config file is
# per-repo opt-in. Unconverted repos run the "oldtime" publish:
# tag + push only, no supply-chain gate, no SBOM, no GitHub Release
# object.
if [[ -f .security-config.toml ]]; then
    REPO_IS_CONVERTED=true
else
    REPO_IS_CONVERTED=false
fi

# --- Component identity ---------------------------------------------------
# Derive the component name from the OpenSecOps remote URL — this is the
# customer-facing repository name (e.g. "SOAR", "Foundation-..."), used
# for SBOM filename, GitHub Release URL, and Full-Changelog compare link.
# Falls back to origin's basename when the OpenSecOps remote is not yet
# configured (a `./setup` run is the normal way to add it).
if git remote 2>/dev/null | grep -q '^OpenSecOps$'; then
    COMPONENT_NAME=$(basename -s .git "$(git remote get-url OpenSecOps)")
    HAS_OPENSECOPS_REMOTE=true
else
    COMPONENT_NAME=$(basename -s .git "$(git remote get-url origin)")
    HAS_OPENSECOPS_REMOTE=false
fi

# --- Defaults shared by both modes ----------------------------------------
SBOM_TMP_DIR=""
SBOM_PATH=""
EVIDENCE_PATH=""
GH_AVAILABLE=false
GH_AUTHED=false

if [[ "$REPO_IS_CONVERTED" == true ]]; then
    # ----- Converted-repo path: full Phase 6 flow -------------------------

    # --- Supply-chain release gate
    # Refuse to publish on drift, CVE, hash mismatch, or stale SECURITY.md.
    # Both checks are read-only; no file modifications.
    phase_banner 1 "supply-chain release gate (drift / CVE / hash / OSV / provenance / SECURITY.md)"

    if [[ -x scripts/_check-requirements.sh ]]; then
        if ! scripts/_check-requirements.sh; then
            echo
            echo "Supply-chain gate FAILED: drift, CVE, or hash mismatch detected above."
            echo "  → fix the issues, recompile (./compile-requirements), recommit, and retry."
            exit 1
        fi
    else
        echo "Note: scripts/_check-requirements.sh not present — skipping supply-chain checks."
        echo "      Refresh this repo from the Installer to enable the release gate."
    fi

    if [[ -x scripts/_generate-security-md.sh ]]; then
        if ! scripts/_generate-security-md.sh --check .; then
            echo
            echo "SECURITY.md is stale relative to template + .security-config.toml."
            echo "  → run scripts/_generate-security-md.sh, commit the result, and retry."
            exit 1
        fi
    fi
    phase_done

    # --- Aggregate CycloneDX SBOM + per-function evidence tarball ---------
    # Both generated fresh at release time. Always emitted (including
    # dry-run) so generation failures surface at gate time, not after the
    # push. Outputs go to a tmp dir that the EXIT trap cleans up.
    #
    # Two assets, one phase:
    #   - aggregate SBOM (one summary file; what intake reviewers
    #     consume for component-level inventory)
    #   - evidence tarball (the per-function .cdx.json + .provenance.json
    #     witnesses; what a CycloneDX-mature deep review consumes for
    #     per-function audit)
    phase_banner 2 "release artefact emission (SBOM + evidence)"
    SBOM_TMP_DIR=$(mktemp -d -t opensecops-publish-XXXXXX)
    SBOM_PATH="${SBOM_TMP_DIR}/${COMPONENT_NAME}-${TAG_VERSION}-sbom.cdx.json"
    EVIDENCE_PATH="${SBOM_TMP_DIR}/${COMPONENT_NAME}-${TAG_VERSION}-evidence.tar.gz"
    trap 'rm -rf "$SBOM_TMP_DIR"' EXIT

    if [[ -x scripts/_aggregate-sbom.sh ]]; then
        if ! scripts/_aggregate-sbom.sh \
                --component "$COMPONENT_NAME" \
                --version   "$TAG_VERSION" \
                --output    "$SBOM_PATH"; then
            echo
            echo "Aggregate SBOM generation FAILED — see output above."
            echo "  → most likely a missing requirements.txt; run compile-requirements"
            echo "    and recommit, then retry."
            exit 1
        fi
    else
        echo "Note: scripts/_aggregate-sbom.sh not present — skipping SBOM emission."
        echo "      Refresh this repo from the Installer to enable SBOM generation."
        SBOM_PATH=""
    fi

    if [[ -x scripts/_bundle-evidence.sh ]]; then
        if ! scripts/_bundle-evidence.sh \
                --component "$COMPONENT_NAME" \
                --version   "$TAG_VERSION" \
                --output    "$EVIDENCE_PATH"; then
            echo
            echo "Evidence bundle generation FAILED — see output above."
            echo "  → most likely missing requirements.cdx.json or"
            echo "    requirements.provenance.json; run compile-requirements"
            echo "    and recommit, then retry."
            exit 1
        fi
    else
        echo "Note: scripts/_bundle-evidence.sh not present — skipping evidence bundle."
        echo "      Refresh this repo from the Installer to enable evidence bundling."
        EVIDENCE_PATH=""
    fi
    phase_done

    # --- gh auth precheck (warn-only in dry-run, hard-fail in real run) ---
    if command -v gh >/dev/null 2>&1; then
        GH_AVAILABLE=true
        if gh auth status --hostname github.com >/dev/null 2>&1; then
            GH_AUTHED=true
        fi
    fi
else
    # ----- Unconverted-repo path: oldtime publish -------------------------
    echo
    echo "── unconverted repo (no .security-config.toml) — running oldtime publish ──"
    echo "   Supply-chain gate and aggregate SBOM are skipped; no GitHub Release"
    echo "   object will be created. Tag + push to remotes only."
fi

# --- Dry-run preview short-circuit ----------------------------------------
if [[ "$DRY_RUN" == true ]]; then
    echo
    echo "── Dry-run preview ──"
    echo "  Component:  $COMPONENT_NAME"
    if [[ "$REPO_IS_CONVERTED" == true ]]; then
        echo "  Mode:       converted (full Phase 6 flow)"
    else
        echo "  Mode:       unconverted (oldtime publish — tag + push only)"
    fi
    echo "  Would tag:  $TAG_VERSION"
    echo "  Would push: releases branch + tags to 'origin' (development repo)"
    if [[ "$HAS_OPENSECOPS_REMOTE" == true ]]; then
        echo "              releases:main + tags to 'OpenSecOps' (published repo)"
        if [[ "$REPO_IS_CONVERTED" == true ]]; then
            echo "  Would create GitHub Release on OpenSecOps-Org/${COMPONENT_NAME}:"
            echo "              tag:    $TAG_VERSION"
            echo "              body:   CHANGELOG slice for $TAG_VERSION + Full-Changelog compare link"
            echo "              asset:  ${COMPONENT_NAME}-${TAG_VERSION}-sbom.cdx.json"
            if [[ -n "$EVIDENCE_PATH" ]]; then
                echo "              asset:  ${COMPONENT_NAME}-${TAG_VERSION}-evidence.tar.gz"
            fi
        fi
    fi
    if [[ -n "$SBOM_PATH" ]]; then
        echo "  Generated:  $SBOM_PATH"
        echo "              (size: $(wc -c < "$SBOM_PATH" | tr -d ' ') bytes; cleaned on exit)"
    fi
    if [[ -n "$EVIDENCE_PATH" ]]; then
        echo "  Generated:  $EVIDENCE_PATH"
        echo "              (size: $(wc -c < "$EVIDENCE_PATH" | tr -d ' ') bytes; cleaned on exit)"
    fi
    if [[ "$REPO_IS_CONVERTED" == true && "$HAS_OPENSECOPS_REMOTE" == true ]]; then
        if [[ "$GH_AVAILABLE" != true ]]; then
            echo "  WARNING:    gh CLI not on PATH — required for GitHub Release creation."
            echo "              install: https://cli.github.com/"
        elif [[ "$GH_AUTHED" != true ]]; then
            echo "  WARNING:    gh CLI present but not authenticated — run \`gh auth login\`."
        fi
    fi
    echo
    TOTAL=$((SECONDS - TOTAL_START))
    if (( TOTAL >= 60 )); then
        printf 'Dry-run exit: gate clean, publish would proceed. (total: %dm %ds)\n' \
            $((TOTAL / 60)) $((TOTAL % 60))
    else
        printf 'Dry-run exit: gate clean, publish would proceed. (total: %ds)\n' "$TOTAL"
    fi
    exit 0
fi

# --- Real run: hard-fail on missing gh tooling (only in converted mode) ---
if [[ "$REPO_IS_CONVERTED" == true && "$HAS_OPENSECOPS_REMOTE" == true ]]; then
    if [[ "$GH_AVAILABLE" != true ]]; then
        echo "Error: gh CLI not on PATH — required to create the GitHub Release."
        echo "  → install: https://cli.github.com/"
        exit 1
    fi
    if [[ "$GH_AUTHED" != true ]]; then
        echo "Error: gh CLI not authenticated against github.com."
        echo "  → run: gh auth login --hostname github.com --scopes repo"
        exit 1
    fi
fi

# Check if the tag already exists
if git rev-parse $TAG_VERSION > /dev/null 2>&1; then
    echo "Tag '$TAG_VERSION' already exists. Exiting without creating a new tag."
    exit 0
fi

# REPO_NAME alias kept for backwards-compatibility with any inline use
# below; COMPONENT_NAME (set above, before the dry-run short-circuit) is
# the canonical identifier going forward.
REPO_NAME="$COMPONENT_NAME"

cleanup() {
    [[ -n "$SBOM_TMP_DIR" ]] && rm -rf "$SBOM_TMP_DIR"
    git checkout main
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to switch back to 'main' branch."
    fi
}

# Register cleanup function to run on script exit (replaces the earlier
# tmp-only trap with one that also restores the working branch).
trap cleanup EXIT

if [[ "$REPO_IS_CONVERTED" == true ]]; then
    phase_banner 3 "build releases branch + tag + push to remotes"
else
    # Oldtime publish — single phase, no [N/M] framing.
    phase_start=$SECONDS
    echo
    echo "── tag + push to remotes ──"
fi

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
if [[ "$HAS_OPENSECOPS_REMOTE" == true ]]; then
    git push OpenSecOps releases:main --tags
    if [ $? -ne 0 ]; then
        echo "Error: Pushing to OpenSecOps failed."
        exit 1
    fi
fi
phase_done

# --- GitHub Release on the OpenSecOps remote ------------------------------
# Customers consume releases on OpenSecOps-Org only (the DEV remote
# retains tags but no Release object). Body = CHANGELOG slice for this
# version + auto-appended Full-Changelog compare link when a prior tag
# exists on the OpenSecOps remote.
if [[ "$HAS_OPENSECOPS_REMOTE" == true && -n "$SBOM_PATH" ]]; then
    phase_banner 4 "create GitHub Release + upload SBOM asset"
    OWNER_REPO="OpenSecOps-Org/${COMPONENT_NAME}"
    NOTES_FILE="${SBOM_TMP_DIR}/release-notes.md"

    # Slice the current version's section out of CHANGELOG.md and
    # wrap each long bullet at 72 columns so the rendered release-notes
    # page is readable rather than one giant paragraph per bullet.
    # Continuation lines align with the bullet's content (after `* `).
    # Pattern: from `## $TAG_VERSION` to (but not including) the next
    # `## v` heading or EOF.
    if [[ -f CHANGELOG.md ]]; then
        awk -v ver="$TAG_VERSION" '
            /^## v/ { p = ($2 == ver); next }
            p
        ' CHANGELOG.md \
        | uv run --no-project --quiet --python ">=3.11" python -c "$(cat <<'PYEOF'
# Wrap each bullet at WIDTH columns. The CHANGELOG source uses
# `    * ...` (4-space-indented bullets) for human readability, but
# GitHub-flavored Markdown treats 4+ leading spaces as a code-block
# fence and renders the entire body in a fixed-width font. So we
# dedent every bullet to column 1 (`* ...`) and set continuation
# indent to 2 spaces (aligning with the content after `* `).
import re, sys, textwrap
WIDTH = 80
bullet_re = re.compile(r'^\s*\*\s+(.*)$')
for line in sys.stdin:
    line = line.rstrip('\n')
    if not line.strip():
        print(line)
        continue
    m = bullet_re.match(line)
    if m:
        content = m.group(1)
        print(textwrap.fill(
            content,
            width=WIDTH,
            initial_indent='* ',
            subsequent_indent='  ',
            break_long_words=False,
            break_on_hyphens=False,
        ))
    else:
        # Non-bullet line: preserve original (also dedent leading space
        # so it doesn't accidentally become a code block).
        print(line.lstrip())
PYEOF
)" > "$NOTES_FILE"
    else
        echo "Release ${TAG_VERSION}." > "$NOTES_FILE"
    fi

    # Determine the most-recent prior tag on the OpenSecOps remote (for
    # the Full-Changelog compare link). Empty for the very first ever
    # release of a component, in which case we silently skip the link.
    PREV_TAG=$(gh api "repos/${OWNER_REPO}/tags" --jq '.[] | .name' 2>/dev/null \
                 | grep -v "^${TAG_VERSION}\$" | head -1 || true)
    if [[ -n "$PREV_TAG" ]]; then
        {
            echo
            echo "**Full Changelog**: https://github.com/${OWNER_REPO}/compare/${PREV_TAG}...${TAG_VERSION}"
        } >> "$NOTES_FILE"
    fi

    # Assets: aggregate SBOM (always) + evidence tarball (when present).
    # Evidence is the per-function deep-audit witness set; SBOM is the
    # component-level inventory summary. Both ship as release assets.
    RELEASE_ASSETS=("$SBOM_PATH")
    if [[ -n "$EVIDENCE_PATH" ]]; then
        RELEASE_ASSETS+=("$EVIDENCE_PATH")
    fi

    echo
    echo "── Creating GitHub Release on ${OWNER_REPO} ──"
    if ! gh release create "$TAG_VERSION" \
            --repo "$OWNER_REPO" \
            --title "$TAG_VERSION" \
            --notes-file "$NOTES_FILE" \
            "${RELEASE_ASSETS[@]}"; then
        echo
        echo "Error: gh release create failed."
        echo "  → if the release already exists (republishes are not supported by"
        echo "    OpenSecOps policy), bump the version in CHANGELOG.md and re-run."
        echo "    The git tag has already been pushed; manual cleanup may be"
        echo "    required if the version is dropped before re-publishing."
        exit 1
    fi
    echo "✓ GitHub Release created: https://github.com/${OWNER_REPO}/releases/tag/${TAG_VERSION}"
    phase_done
fi

# --- Final summary --------------------------------------------------------
echo
TOTAL=$((SECONDS - TOTAL_START))
if (( TOTAL >= 60 )); then
    printf '✓ %s %s published. (total: %dm %ds)\n' \
        "$COMPONENT_NAME" "$TAG_VERSION" $((TOTAL / 60)) $((TOTAL % 60))
else
    printf '✓ %s %s published. (total: %ds)\n' \
        "$COMPONENT_NAME" "$TAG_VERSION" "$TOTAL"
fi
