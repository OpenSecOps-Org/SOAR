#!/usr/bin/env bash
# _bundle-evidence.sh — emit a deterministic per-function evidence
# tarball for release.
#
# The aggregate CycloneDX SBOM (`_aggregate-sbom.sh`) is one summary
# file. The strongest *technical substance* in the supply-chain system
# is the per-function `requirements.cdx.json` + `requirements.provenance.json`
# committed in source — those are the witnesses the aggregate summarises.
# Until v3.0.1 they were invisible from the GitHub Releases page; this
# bundle surfaces them as a release asset alongside the aggregate SBOM.
#
# The bundle is generated fresh at release time by `./publish` and is
# what consumers download to do per-component deep audit.
#
# Determinism contract: same inputs + same toolchain produce a
# byte-identical tarball.
#   - File order: `sorted()` ascending by repo-relative path.
#   - tarfile.PAX_FORMAT with TarInfo.mtime/uid/gid zeroed and
#     uname/gname empty; pax_headers cleared (PAX would otherwise
#     shadow the zeroed mtime via an extended header).
#   - gzip.GzipFile(mtime=0) for the outer compression layer.
#   - Arcnames computed against `git rev-parse --show-toplevel`, not
#     `os.path.relpath(...)` against the caller's CWD — so the bundle
#     is identical regardless of the directory `./publish` invokes
#     this script from.
#
# Usage:
#   _bundle-evidence.sh --component <NAME> --version <VER> --output <PATH>
#
# Tooling: `uv` on PATH. Stdlib-only Python (tarfile, gzip, os).

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
ROOT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --component) COMPONENT="$2"; shift 2 ;;
        --version)   VERSION="$2";   shift 2 ;;
        --output)    OUTPUT="$2";    shift 2 ;;
        --root)      ROOT="$2";      shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) req_lib_error "unknown arg: $1"; exit 2 ;;
    esac
done

if [[ -z "$COMPONENT" || -z "$VERSION" || -z "$OUTPUT" ]]; then
    req_lib_error "usage: _bundle-evidence.sh --component <NAME> --version <VER> --output <PATH>"
    exit 2
fi
if ! command -v uv >/dev/null 2>&1; then
    req_lib_error "uv is not on PATH"; exit 2
fi

# Repo root anchors all arcnames so the tarball is byte-identical
# regardless of the directory ./publish invokes this script from.
REPO_ROOT="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
    req_lib_error "cannot determine repo root via git -C ${ROOT} rev-parse --show-toplevel"
    req_lib_error "  → run from inside a git working copy"
    exit 2
fi

# Discover every requirements.in; the evidence files (.cdx.json,
# .provenance.json) live as siblings. Designs that use `-r` includes
# (e.g. shared boto3.in) produce no separate evidence artefacts —
# their deps merge into each consuming function's provenance file —
# so iterating .in files captures the complete witness set.
IN_FILES=()
while IFS= read -r _f; do
    IN_FILES+=("$_f")
done < <(req_lib_discover_in_files "$ROOT" | sort)
unset _f

if [[ ${#IN_FILES[@]} -eq 0 ]]; then
    req_lib_error "no requirements.in files found under ${ROOT}"
    req_lib_error "  → has this repo been converted to the locked-dependency model?"
    exit 1
fi

req_lib_info "── bundling evidence (${COMPONENT} ${VERSION}) ──"
req_lib_info "  found ${#IN_FILES[@]} requirements.in file(s)"

# Collect candidate files: adjacent .cdx.json + .provenance.json for
# each .in. Convert to absolute paths so the Python tail can reliably
# compute repo-relative arcnames.
EVIDENCE_FILES=()
for in_file in "${IN_FILES[@]}"; do
    dir="$(cd "$(dirname "$in_file")" && pwd)"
    for sibling in requirements.cdx.json requirements.provenance.json; do
        abs="${dir}/${sibling}"
        if [[ -f "$abs" ]]; then
            EVIDENCE_FILES+=("$abs")
        fi
    done
done

if [[ ${#EVIDENCE_FILES[@]} -eq 0 ]]; then
    req_lib_error "no .cdx.json or .provenance.json evidence files found alongside any .in"
    req_lib_error "  → run \`compile-requirements.sh\` and recommit before releasing"
    exit 1
fi

req_lib_info "  collected ${#EVIDENCE_FILES[@]} evidence file(s)"

mkdir -p "$(dirname "$OUTPUT")"

# Pass repo root + output + entries via argv. Python tail computes
# arcnames as paths relative to repo root, sorts, and writes a
# deterministic PAX tarball gzipped with mtime=0.
uv run --no-project --quiet --python ">=3.11" python - \
    "$OUTPUT" "$REPO_ROOT" "$COMPONENT" "$VERSION" "${EVIDENCE_FILES[@]}" <<'PY'
import gzip
import os
import sys
import tarfile

output, repo_root, component, version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
files = sys.argv[5:]

# Compute arcnames repo-relative; sort; dedupe (idempotent).
entries = []
seen = set()
for abs_path in files:
    rel = os.path.relpath(abs_path, repo_root)
    if rel in seen:
        continue
    seen.add(rel)
    entries.append((rel, abs_path))
entries.sort()

# Top-level directory inside the tarball — gives a clean extract dir.
top = f"{component}-{version}-evidence"


def _tarinfo(rel_path, abs_path):
    """Build a fully-zeroed TarInfo so the bundle is byte-identical.

    PAX is required for spec-correct large mtime/uid handling, but PAX
    can shadow the zeroed `mtime` field via extended headers — we clear
    `pax_headers` to prevent that.
    """
    info = tarfile.TarInfo(name=f"{top}/{rel_path}")
    info.size = os.path.getsize(abs_path)
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.type = tarfile.REGTYPE
    info.pax_headers = {}
    return info


# Nested context managers — file → gzip(mtime=0) → tar(PAX_FORMAT) — for
# correct cleanup semantics and a byte-identical envelope.
with open(output, "wb") as fh, \
        gzip.GzipFile(filename="", fileobj=fh, mode="wb", mtime=0) as gz, \
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
    for rel, abs_path in entries:
        info = _tarinfo(rel, abs_path)
        with open(abs_path, "rb") as src:
            tf.addfile(info, src)

size = os.path.getsize(output)
print(f"  files:   {len(entries)}")
print(f"  output:  {output}")
print(f"  size:    {size} bytes")
PY

req_lib_ok "✓ evidence tarball written to ${OUTPUT}"
