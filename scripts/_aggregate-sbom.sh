#!/usr/bin/env bash
# _aggregate-sbom.sh — emit one component-level CycloneDX SBOM that is
# the union of every per-Lambda-function SBOM in the current repo.
#
# Per-function SBOMs are derived artefacts (`compile-requirements.sh`
# regenerates them deterministically from `requirements.txt`). The
# aggregate SBOM is generated fresh at release time by `./publish`
# (this script), attached as a release asset, and is what customers
# and intake reviewers actually consume.
#
# This script does NOT touch the working tree. It regenerates each
# per-function SBOM into a temp dir, merges them, writes the aggregate
# to --output, then cleans up the temp dir. Idempotent: same inputs +
# same `uv` version produce a byte-identical aggregate.
#
# Usage:
#   _aggregate-sbom.sh --component <NAME> --version <VER> --output <PATH>
#
# Tooling: `uv` on PATH; `cyclonedx-bom` (provides `cyclonedx-py
# requirements`) reachable via `uvx`. Same prereqs as
# `compile-requirements.sh` — no additional tooling.

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
    req_lib_error "usage: _aggregate-sbom.sh --component <NAME> --version <VER> --output <PATH>"
    exit 2
fi
if ! command -v uv >/dev/null 2>&1; then
    req_lib_error "uv is not on PATH"; exit 2
fi
if ! command -v uvx >/dev/null 2>&1; then
    req_lib_error "uvx is not on PATH"; exit 2
fi

# Collect every requirements.txt that has a sibling requirements.in
# (steady-state post-Phase-4). Legacy bare-.txt files would also be
# picked up if needed by enabling req_lib_discover_legacy_txt_files;
# at v3.0.0 SOAR is fully converted so the .in walker is sufficient.
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

req_lib_info "── aggregating SBOM (${COMPONENT} ${VERSION}) ──"
req_lib_info "  found ${#IN_FILES[@]} requirements.in files"

TMP_DIR="$(mktemp -d -t opensecops-sbom-XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Generate per-function SBOMs into the temp dir (one subdir per function,
# named by sha256(.txt-path) so collisions are impossible).
SBOM_PATHS=()
LOCK_PATHS=()
N_TOTAL=${#IN_FILES[@]}
i=0
for in_file in "${IN_FILES[@]}"; do
    i=$((i + 1))
    txt_file="${in_file%.in}.txt"
    # Strip leading "./" for tidier display.
    display_path="${txt_file#./}"
    printf '  [%d/%d] %s\n' "$i" "$N_TOTAL" "$display_path"
    if [[ ! -f "$txt_file" ]]; then
        req_lib_error "    missing lock: ${txt_file}"
        req_lib_error "    → run compile-requirements.sh and recommit"
        exit 1
    fi
    func_dir="$(dirname "$txt_file")"
    key="$(printf '%s' "$txt_file" | shasum -a 256 | awk '{print $1}')"
    sbom_out="${TMP_DIR}/${key}.cdx.json"
    if ! ( cd "$func_dir" && uvx --from cyclonedx-bom cyclonedx-py requirements \
                                "$(basename "$txt_file")" -o "$sbom_out" >/dev/null 2>&1 ); then
        req_lib_error "    cyclonedx-py FAILED for ${txt_file}"
        exit 1
    fi
    if ! req_lib_normalize_cdx_sbom "$sbom_out" "$txt_file" >/dev/null 2>&1; then
        req_lib_error "    normalize FAILED for ${sbom_out}"
        exit 1
    fi
    SBOM_PATHS+=("$sbom_out")
    LOCK_PATHS+=("$txt_file")
done

# Capture toolchain versions for `metadata.tools` so the SBOM records
# what produced it. Versions are pure-data, do not affect determinism
# unless the toolchain is bumped (which it should reflect anyway).
UV_VERSION="$(uv --version 2>/dev/null | awk '{print $2}' || echo unknown)"
CYCLONEDX_VERSION="$(uvx --from cyclonedx-bom cyclonedx-py --version 2>/dev/null \
    | awk '{print $NF; exit}' || echo unknown)"

# Merge into one aggregate. Determinism contract:
#   - components deduplicated by `purl` (or `bom-ref` when purl absent),
#     keeping first-seen for stable ordering
#   - components sorted by purl ascending
#   - bom-ref set to the purl (stable across regenerations; replaces
#     cyclonedx-py's line-numbered `requirements-L<N>` which churns
#     whenever a transitive shifts position in the lock)
#   - hashes hoisted from externalReferences[].hashes[] to canonical
#     component.hashes[] (CycloneDX consumers expect them there)
#   - serialNumber = UUIDv5 over `opensecops:sbom:<component>:<version>:<sha256(sorted lock contents)>`
#   - metadata.timestamp pinned to fixed epoch (1970-01-01) — same
#     constant the per-function normaliser uses
#   - metadata.tools / metadata.lifecycles: pure data; lifecycle = build
mkdir -p "$(dirname "$OUTPUT")"

uv run --no-project --quiet --python ">=3.11" python - \
    "$OUTPUT" "$COMPONENT" "$VERSION" \
    "$UV_VERSION" "$CYCLONEDX_VERSION" \
    "${LOCK_PATHS[@]}" --sboms-- "${SBOM_PATHS[@]}" <<'PY'
import hashlib, json, sys, uuid

argv = sys.argv[1:]
output, component, version = argv[0], argv[1], argv[2]
uv_version, cyclonedx_version = argv[3], argv[4]
sep = argv.index("--sboms--")
locks = argv[5:sep]
sboms = argv[sep + 1:]

# Hash of all locks (sorted by path) — feeds the deterministic serialNumber.
h = hashlib.sha256()
for lock in sorted(locks):
    with open(lock, "rb") as f:
        h.update(hashlib.sha256(f.read()).digest())
lock_digest = h.hexdigest()
serial = uuid.uuid5(
    uuid.NAMESPACE_URL,
    f"opensecops:sbom:{component}:{version}:{lock_digest}",
)


def canonicalize(c):
    """Hoist hashes to canonical component.hashes[] and stabilize bom-ref.

    cyclonedx-py's `requirements` mode emits hashes only inside
    `externalReferences[].hashes[]`, uses line-numbered bom-refs
    (`requirements-L7`), and writes a `description` field that is the
    raw line from requirements.txt — package name, version, and every
    hash repeated verbatim. All three are spec-quirks of that mode, not
    what consumers expect. We:
      - copy hashes to `component.hashes[]` (canonical CycloneDX location);
      - replace the bom-ref with the purl when one is present (the purl
        is `pkg:pypi/<name>@<version>` — stable across regenerations);
      - drop the requirements-line `description` (every byte of it is
        already represented elsewhere in the component object — pyyaml's
        is 2KB of pure redundancy).
    `externalReferences` is preserved as-is so any tool that reads from
    there still works.
    """
    purl = c.get("purl")
    if purl:
        c["bom-ref"] = purl
    if not c.get("hashes"):
        seen_hashes = set()
        canonical_hashes = []
        for ref in c.get("externalReferences") or []:
            for h_entry in ref.get("hashes") or []:
                alg = h_entry.get("alg")
                content = h_entry.get("content")
                if not alg or not content:
                    continue
                key = (alg, content)
                if key in seen_hashes:
                    continue
                seen_hashes.add(key)
                canonical_hashes.append({"alg": alg, "content": content})
        canonical_hashes.sort(key=lambda x: (x["alg"], x["content"]))
        if canonical_hashes:
            c["hashes"] = canonical_hashes
    desc = c.get("description")
    if isinstance(desc, str) and desc.startswith("requirements line "):
        del c["description"]
    return c


# Read every per-function SBOM, accumulate components, dedupe by purl
# (fallback to bom-ref).
seen = set()
merged = []
spec_version = None
bom_format = None
for s in sboms:
    with open(s, "r", encoding="utf-8") as f:
        data = json.load(f)
    bom_format = bom_format or data.get("bomFormat", "CycloneDX")
    spec_version = spec_version or data.get("specVersion")
    for c in data.get("components", []) or []:
        key = c.get("purl") or c.get("bom-ref") or json.dumps(c, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        merged.append(canonicalize(c))

merged.sort(key=lambda c: (c.get("purl") or c.get("bom-ref") or "", c.get("name", "")))

aggregate = {
    "bomFormat": bom_format or "CycloneDX",
    "specVersion": spec_version or "1.5",
    "serialNumber": f"urn:uuid:{serial}",
    "version": 1,
    "metadata": {
        "timestamp": "1970-01-01T00:00:00+00:00",
        "lifecycles": [{"phase": "build"}],
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "cyclonedx-py",
                    "version": cyclonedx_version,
                    "purl": f"pkg:pypi/cyclonedx-bom@{cyclonedx_version}",
                    "bom-ref": f"pkg:pypi/cyclonedx-bom@{cyclonedx_version}",
                },
                {
                    "type": "application",
                    "name": "uv",
                    "version": uv_version,
                    "bom-ref": f"opensecops:tool:uv@{uv_version}",
                },
            ],
        },
        "component": {
            "type": "application",
            "name": component,
            "version": version,
            "bom-ref": f"pkg:generic/{component}@{version}",
            "description": (
                f"OpenSecOps {component} component — released artefact. "
                f"See SECURITY.md in the source repository for the supply-chain "
                f"posture, governance model, and verification commands."
            ),
        },
    },
    "components": merged,
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(aggregate, f, indent=2)
    f.write("\n")

print(f"  components: {len(merged)} (deduplicated from {sum(1 for _ in sboms)} per-function SBOMs)")
print(f"  output:     {output}")
PY

req_lib_ok "✓ aggregate SBOM written to ${OUTPUT}"
