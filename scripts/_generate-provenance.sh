#!/usr/bin/env bash
# _generate-provenance.sh — emit a SLSA Build L1 in-toto provenance
# document for a release.
#
# This is the §4.11 cat. 4 attestation: a signed declaration of which
# build steps ran for this release. Direct answer to "did publish.zsh's
# gate actually fire, or did the maintainer skip it and sign anyway?"
# Phase 11's reproducibility check answers the same question indirectly
# (if the lock is reproducible, the gate's outputs were correct
# regardless of process); this provenance doc answers it directly by
# naming the build steps in a signed attestation.
#
# Format: in-toto Statement v1 with predicate-type SLSA Provenance v1.
#   https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
#   https://slsa.dev/spec/v1.2/provenance
#
# Subjects: every artefact released alongside this provenance document
# (the aggregate SBOM and the evidence tarball). The .bundle signature
# files are not subjects of provenance — they are themselves Sigstore
# signatures over the named subjects, with their own attestation chain
# in Rekor.
#
# Honest level claim: SLSA Build **L1**. The maintainer-laptop release
# model in §6 cannot meet L2 (which explicitly requires a hosted build
# platform that generates and signs the provenance) without adding
# release-path CI, which §8 rules out. The L2-adjacent controls we *do*
# implement — Sigstore signing of every release artefact and the
# `# uv-compiled-at:` reproducibility fence — are documented in
# `SECURITY.md` §9 alongside the L1 claim.
#
# Determinism: provenance documents naturally vary per release
# (different version, commit SHA, timestamps). Determinism within a
# single release is not a goal; the signed claim is.
#
# Usage:
#   _generate-provenance.sh \
#       --component <NAME> --version <VER> \
#       --output <PATH> \
#       <subject1> [<subject2> ...]
#
# Tooling: requires `uv` and `git` on PATH. Stdlib-only Python
# (hashlib, json, os) via `uv run`.

set -euo pipefail

# Resolve symlinks so we find _requirements_lib.sh next to the real script.
_self="${BASH_SOURCE[0]}"
while [[ -L "$_self" ]]; do
    _link="$(readlink "$_self")"
    case "$_link" in
        /*) _self="$_link" ;;
        *)  _self="$(dirname "$_self")/$_link" ;;
    esac
done
SCRIPT_DIR="$(cd "$(dirname "$_self")" && pwd)"
unset _self _link
# shellcheck source=_requirements_lib.sh
source "$SCRIPT_DIR/_requirements_lib.sh"

COMPONENT=""
VERSION=""
OUTPUT=""
SUBJECTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --component) COMPONENT="$2"; shift 2 ;;
        --version)   VERSION="$2";   shift 2 ;;
        --output)    OUTPUT="$2";    shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --) shift; SUBJECTS+=("$@"); break ;;
        -*) req_lib_error "unknown arg: $1"; exit 2 ;;
        *)  SUBJECTS+=("$1"); shift ;;
    esac
done

if [[ -z "$COMPONENT" || -z "$VERSION" || -z "$OUTPUT" ]]; then
    req_lib_error "usage: _generate-provenance.sh --component <NAME> --version <VER> --output <PATH> <subject>..."
    exit 2
fi
if (( ${#SUBJECTS[@]} == 0 )); then
    req_lib_error "no subject artefacts provided"
    exit 2
fi
if ! command -v uv >/dev/null 2>&1; then
    req_lib_error "uv is not on PATH"; exit 2
fi

# Source-tree context: pin the provenance to an exact git commit so a
# customer can clone the repo at that SHA and reproduce the build inputs.
COMMIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
COMMIT_REF="$(git symbolic-ref -q HEAD 2>/dev/null || echo refs/heads/unknown)"
REPO_URL="$(git remote get-url OpenSecOps 2>/dev/null \
            || git remote get-url origin 2>/dev/null \
            || echo unknown)"

# Toolchain context: the versions of every tool that ran in the build
# pipeline. Recorded under runDetails.builder.version so customers can
# match a problematic release to the exact toolchain that produced it.
BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
UV_VERSION="$(uv --version 2>&1 | awk '{print $2}' || echo absent)"
COSIGN_VERSION="$(cosign version 2>&1 | awk '/^GitVersion/{print $2}' || echo absent)"
PYTHON_VERSION="$(uv run --no-project --quiet --python ">=3.11" python -c \
    'import platform; print(platform.python_version())' 2>/dev/null || echo absent)"

req_lib_info "── generating SLSA Build L1 in-toto provenance ──"
req_lib_info "  component: ${COMPONENT} ${VERSION}"
req_lib_info "  subjects:  ${#SUBJECTS[@]}"
req_lib_info "  commit:    ${COMMIT_SHA:0:12}"

mkdir -p "$(dirname "$OUTPUT")"

# Hand off to Python: hash each subject, build the in-toto statement
# JSON, write to OUTPUT. Stdlib only (hashlib, json, os).
uv run --no-project --quiet --python ">=3.11" python - \
    "$OUTPUT" "$COMPONENT" "$VERSION" "$COMMIT_SHA" "$COMMIT_REF" \
    "$REPO_URL" "$BUILD_TIMESTAMP" "$UV_VERSION" "$COSIGN_VERSION" \
    "$PYTHON_VERSION" "${SUBJECTS[@]}" <<'PY'
import hashlib
import json
import os
import sys

(
    output, component, version,
    commit_sha, commit_ref, repo_url,
    build_timestamp, uv_version, cosign_version, python_version,
) = sys.argv[1:11]
subject_paths = sys.argv[11:]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


subjects = [
    {"name": os.path.basename(p), "digest": {"sha256": sha256(p)}}
    for p in subject_paths
]

# SLSA v1 buildType is a free-form URI canonically identifying the build
# platform. We pin a stable URI under the OpenSecOps-Org namespace
# referencing publish.zsh. The URI is canonical, not dereferenceable.
build_type = "https://github.com/OpenSecOps-Org/spec/build/publish-zsh/v1"

statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": subjects,
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": {
                "component": component,
                "version": version,
            },
            "internalParameters": {
                "uv_version": uv_version,
                "cosign_version": cosign_version,
                "python_version": python_version,
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+{repo_url}@{commit_ref}",
                    "digest": {"gitCommit": commit_sha},
                }
            ],
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/OpenSecOps-Org/Installer/blob/main/scripts/publish.zsh",
                "version": {
                    "uv": uv_version,
                    "cosign": cosign_version,
                    "python": python_version,
                },
            },
            "metadata": {
                "invocationId": f"{component}-{version}-{build_timestamp}",
                "startedOn": build_timestamp,
                "finishedOn": build_timestamp,
            },
            "byproducts": [
                {
                    "name": "supply-chain release gate",
                    "uri": "scripts/_check-requirements.sh",
                    "annotations": {
                        "mode": "--reproducible",
                        "checks": [
                            "drift (clean uv cache + --exclude-newer fence)",
                            "CVE (pip-audit --strict)",
                            "hash integrity (pip download --require-hashes)",
                            "malware-feed (OSV.dev MAL-* IDs)",
                            "provenance drift (PyPI metadata, advisory)",
                        ],
                    },
                },
                {
                    "name": "aggregate SBOM",
                    "uri": "scripts/_aggregate-sbom.sh",
                    "annotations": {"format": "CycloneDX 1.6 JSON"},
                },
                {
                    "name": "evidence tarball",
                    "uri": "scripts/_bundle-evidence.sh",
                    "annotations": {"format": "PAX-tar + gzip (deterministic)"},
                },
                {
                    "name": "Sigstore signing",
                    "uri": "cosign sign-blob --yes --bundle",
                    "annotations": {
                        "format": "in-toto bundle (cert + sig + Rekor entry)",
                        "issuer": "https://github.com/login/oauth",
                    },
                },
            ],
        },
    },
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(statement, f, indent=2, sort_keys=True)
    f.write("\n")

print(f"  output:  {output}")
print(f"  size:    {os.path.getsize(output)} bytes")
PY

req_lib_ok "✓ SLSA Build L1 in-toto provenance written to ${OUTPUT}"
