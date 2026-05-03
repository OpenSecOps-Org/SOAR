#!/usr/bin/env bash
# _requirements_lib.sh — shared helper sourced by:
#   compile-requirements.sh   (maintainer-side generator)
#   check-requirements.sh     (release-gate verifier)
#   scan-updates.sh           (informational update scanner)
#
# Provides: dynamic discovery of requirements files, the canonical
# exclusion list, output formatting, and severity-threshold handling.
# Convention: no committed inventories, no
# `functions/` assumption — discovery walks from the repo root each run.
#
# This file is distributed byte-identically to every component repo by
# Installer/refresh and must remain self-contained (no external deps
# beyond a POSIX shell + standard `find`).

# --- Guard against double-sourcing ----------------------------------------
if [[ -n "${_REQUIREMENTS_LIB_SOURCED:-}" ]]; then
    return 0
fi
_REQUIREMENTS_LIB_SOURCED=1

# --- Canonical exclusion list ---------------------------------------------
# Directories the discovery walker must never descend into. Kept here so
# all three top-level scripts share one definition.
REQ_LIB_EXCLUDE_DIRS=(
    ".git"
    ".aws-sam"
    ".venv"
    "venv"
    "node_modules"
    "__pycache__"
    ".pytest_cache"
)

# --- Colour codes (no-op when not a TTY) ----------------------------------
if [[ -t 1 ]]; then
    REQ_LIB_RED="\033[91m"
    REQ_LIB_YELLOW="\033[93m"
    REQ_LIB_GREEN="\033[92m"
    REQ_LIB_BOLD="\033[1m"
    REQ_LIB_END="\033[0m"
else
    REQ_LIB_RED=""
    REQ_LIB_YELLOW=""
    REQ_LIB_GREEN=""
    REQ_LIB_BOLD=""
    REQ_LIB_END=""
fi

# --- Discovery -------------------------------------------------------------
# req_lib_build_find_prune_args
#   Echoes the `find` predicate fragment that prunes REQ_LIB_EXCLUDE_DIRS.
#   Intended use: eval inside a `find` invocation.
req_lib_build_find_prune_args() {
    local first=1
    printf '\\( '
    for d in "${REQ_LIB_EXCLUDE_DIRS[@]}"; do
        if (( first )); then
            first=0
        else
            printf -- '-o '
        fi
        printf -- '-name %q ' "$d"
    done
    printf '\\) -prune'
}

# req_lib_discover_in_files <root>
#   Print every `requirements.in` under <root>, one per line, excluding
#   REQ_LIB_EXCLUDE_DIRS. Steady-state discovery (Phase 4+).
req_lib_discover_in_files() {
    local root="${1:-.}"
    local prune
    prune="$(req_lib_build_find_prune_args)"
    eval "find \"$root\" $prune -o -type f -name 'requirements.in' -print"
}

# req_lib_discover_legacy_txt_files <root>
#   Print every `requirements.txt` under <root> that does NOT have a sibling
#   `requirements.in`. Used during the migration window (Phases 3–4) so the
#   walker still sees dependency-bearing dirs that have not been converted
#   yet. Steady state (post-Phase-4): this returns nothing.
req_lib_discover_legacy_txt_files() {
    local root="${1:-.}"
    local prune
    prune="$(req_lib_build_find_prune_args)"
    eval "find \"$root\" $prune -o -type f -name 'requirements.txt' -print" \
        | while IFS= read -r txt; do
            [[ -f "${txt%.txt}.in" ]] || printf '%s\n' "$txt"
        done
}

# req_lib_discover_python_files <root>
#   Print every `*.py` file under <root>, excluding REQ_LIB_EXCLUDE_DIRS.
#   Used by the boto3-import detection in `Installer/refresh` per
#   the boto3 distribution-detection rule: a repo
#   needs `boto3.in` distributed iff any of its Python files imports
#   boto3 or botocore at module / function level (Lambda runtime
#   bundles boto3, so the source is the honest signal — not requirements
#   files, which only see the post-conversion subset).
req_lib_discover_python_files() {
    local root="${1:-.}"
    local prune
    prune="$(req_lib_build_find_prune_args)"
    eval "find \"$root\" $prune -o -type f -name '*.py' -print"
}

# --- Output formatting -----------------------------------------------------
req_lib_info()  { printf '%b\n' "${REQ_LIB_BOLD}${1}${REQ_LIB_END}"; }
req_lib_ok()    { printf '%b\n' "${REQ_LIB_GREEN}${1}${REQ_LIB_END}"; }
req_lib_warn()  { printf '%b\n' "${REQ_LIB_YELLOW}${1}${REQ_LIB_END}"; }
req_lib_error() { printf '%b\n' "${REQ_LIB_RED}${1}${REQ_LIB_END}" >&2; }

# --- Severity-threshold handling ------------------------------------------
# pip-audit emits findings tagged with a severity. The release gate
# (check-requirements.sh) fails on anything at-or-above the threshold;
# scan-updates.sh reports informationally regardless.
REQ_LIB_SEVERITY_ORDER=(NONE LOW MODERATE HIGH CRITICAL)

# req_lib_severity_rank <SEVERITY>
#   Echo a numeric rank (0..4) for the given severity; -1 if unknown.
req_lib_severity_rank() {
    local needle
    needle="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
    local i=0
    for s in "${REQ_LIB_SEVERITY_ORDER[@]}"; do
        if [[ "$s" == "$needle" ]]; then
            printf '%d\n' "$i"
            return 0
        fi
        ((i++))
    done
    printf -- '-1\n'
}

# req_lib_severity_meets_threshold <FOUND> <THRESHOLD>
#   Exit 0 iff FOUND >= THRESHOLD on REQ_LIB_SEVERITY_ORDER.
req_lib_severity_meets_threshold() {
    local found_rank threshold_rank
    found_rank="$(req_lib_severity_rank "$1")"
    threshold_rank="$(req_lib_severity_rank "$2")"
    (( found_rank >= 0 && threshold_rank >= 0 && found_rank >= threshold_rank ))
}

# --- Direct-dep provenance (PyPI metadata baseline) -----------------------
# Phase 5 advisory check: each `.in` gets its own `<base>.provenance.json`
# capturing PyPI-attested fields for the deps declared in that file.
# `compile-requirements.sh` writes/refreshes them; `_check-requirements.sh`
# re-fetches at gate time and warns (does not fail) on drift. The
# committed file is the diff baseline; drift is the signal; accepting a
# diff is a deliberate commit.
#
# Provenance JSON shape (deterministic; sorted keys, indent=2):
#   {
#     "direct_deps": {
#       "<pkg>": {
#         "author": "...",
#         "author_email": "...",
#         "home_page": "...",
#         "maintainer": "...",
#         "maintainer_email": "...",
#         "project_urls": { "<label>": "<url>", ... }
#       },
#       ...
#     }
#   }
#
# Captured fields are intentionally limited to what the PyPI JSON API
# exposes today and what a reviewer can usefully diff. Verified-publisher
# attestations (PEP 740) and Trusted Publishers metadata are not exposed
# via /pypi/<pkg>/json today; if PyPI surfaces them later, additional
# fields can be added without breaking the existing baselines (the diff
# logic ignores keys absent from the committed file).
#
# Both helpers below dedupe PyPI fetches across all .in paths in a single
# invocation so a tree of N functions sharing M direct deps does O(M)
# HTTP calls, not O(N*M).

# Inline Python module shared by writer + checker. Injected via -c so
# stdin stays connected to the caller's pipe (same pattern as the
# malware-feed helper). Both helpers share parsing + fetching logic.
_REQ_LIB_PROVENANCE_PY='
import json, os, re, sys, urllib.error, urllib.request

PROVENANCE_FIELDS = (
    "author",
    "author_email",
    "home_page",
    "maintainer",
    "maintainer_email",
    "project_urls",
)

_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_INCLUDE_RE = re.compile(r"^(?:-r|--requirement)\s+(.+?)\s*$")

def parse_direct_deps(in_path, _seen_files=None):
    """Read a requirements .in file and return the list of direct-dep
    names it consumes — its own declared lines plus the lines pulled in
    transitively from any -r / --requirement includes. Includes are
    treated as textual substitution (the way pip / uv pip compile do):
    an include has no identity of its own; its declared deps merge into
    the consumer dep set. Cycle-safe via _seen_files set. Returns names
    in declaration order, deduped case-insensitively, or None on read
    error."""
    if _seen_files is None:
        _seen_files = set()
    abs_path = os.path.abspath(in_path)
    if abs_path in _seen_files:
        return []
    _seen_files.add(abs_path)

    try:
        with open(in_path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"cannot read {in_path}: {e}", file=sys.stderr)
        return None

    base_dir = os.path.dirname(abs_path)
    deps, seen = [], set()
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m_inc = _INCLUDE_RE.match(line)
        if m_inc:
            ref = m_inc.group(1).strip()
            ref_path = ref if os.path.isabs(ref) else os.path.join(base_dir, ref)
            sub = parse_direct_deps(ref_path, _seen_files)
            if sub is None:
                return None
            for name in sub:
                key = name.lower()
                if key not in seen:
                    seen.add(key)
                    deps.append(name)
            continue
        if line.startswith("-"):
            continue
        m = _NAME_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        deps.append(name)
    return deps

def fetch_pypi(name, cache):
    """Fetch /pypi/<name>/json once per name within this process."""
    key = name.lower()
    if key in cache:
        return cache[key]
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/json", timeout=15,
        ) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        print(f"PyPI metadata fetch failed for {name}: {e}", file=sys.stderr)
        cache[key] = None
        return None
    cache[key] = data
    return data

def provenance_record(pypi_data):
    """Build a deterministic provenance record from a PyPI JSON response."""
    info = (pypi_data or {}).get("info") or {}
    record = {}
    for field in PROVENANCE_FIELDS:
        val = info.get(field)
        if field == "project_urls":
            record[field] = dict(sorted((val or {}).items()))
        else:
            record[field] = val if isinstance(val, str) else ""
    return record

def provenance_path_for(in_path):
    if in_path.endswith(".in"):
        return in_path[:-3] + ".provenance.json"
    return in_path + ".provenance.json"

def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
'

# req_lib_write_provenance_for_in_files
#   Reads .in paths from stdin (one per line). For each path, parses
#   declared direct deps, fetches PyPI metadata (deduped across all
#   paths), writes adjacent <base>.provenance.json. Empty .in files
#   (only -r references) get {"direct_deps": {}}.
#   Exits:
#     0 — every file written
#     2 — IO/network error
req_lib_write_provenance_for_in_files() {
    python3 -c "$_REQ_LIB_PROVENANCE_PY"'
paths = [line.strip() for line in sys.stdin if line.strip()]
if not paths:
    sys.exit(0)
cache = {}
errors = 0
for in_path in paths:
    deps = parse_direct_deps(in_path)
    if deps is None:
        errors += 1
        continue
    payload = {"direct_deps": {}}
    for name in sorted(deps, key=str.lower):
        data = fetch_pypi(name, cache)
        if data is None:
            errors += 1
            continue
        payload["direct_deps"][name] = provenance_record(data)
    try:
        write_json(provenance_path_for(in_path), payload)
    except OSError as e:
        print(f"cannot write provenance for {in_path}: {e}", file=sys.stderr)
        errors += 1
sys.exit(2 if errors else 0)
'
}

# req_lib_check_provenance_drift
#   Reads .in paths from stdin (one per line). For each path, reads the
#   committed <base>.provenance.json (warns if missing), re-fetches PyPI
#   for the dep set the committed file claims, diffs. Drift lines are
#   printed to stdout in the form:
#     <in_path>: <pkg>.<field>[.<subfield>]: <committed> -> <current>
#   PyPI fetches deduped across paths. Advisory: drift => exit 1, but
#   the bash caller treats this as warn-only.
#   Exits:
#     0 — no drift, no missing baselines
#     1 — drift detected, or committed baseline missing for some .in
#     2 — IO/network error
req_lib_check_provenance_drift() {
    python3 -c "$_REQ_LIB_PROVENANCE_PY"'
paths = [line.strip() for line in sys.stdin if line.strip()]
if not paths:
    sys.exit(0)
cache = {}
findings = []
errors = 0
missing = []
for in_path in paths:
    prov_path = provenance_path_for(in_path)
    if not os.path.exists(prov_path):
        missing.append((in_path, prov_path))
        continue
    try:
        with open(prov_path, encoding="utf-8") as f:
            committed = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"cannot read {prov_path}: {e}", file=sys.stderr)
        errors += 1
        continue
    committed_deps = (committed or {}).get("direct_deps") or {}
    for pkg, committed_record in sorted(committed_deps.items(), key=lambda kv: kv[0].lower()):
        data = fetch_pypi(pkg, cache)
        if data is None:
            errors += 1
            continue
        current_record = provenance_record(data)
        for field in PROVENANCE_FIELDS:
            cval = committed_record.get(field, "")
            nval = current_record.get(field, "")
            if isinstance(cval, dict) or isinstance(nval, dict):
                cval = cval if isinstance(cval, dict) else {}
                nval = nval if isinstance(nval, dict) else {}
                for subkey in sorted(set(cval.keys()) | set(nval.keys())):
                    csub = cval.get(subkey, "<missing>")
                    nsub = nval.get(subkey, "<missing>")
                    if csub != nsub:
                        findings.append(f"{in_path}: {pkg}.{field}.{subkey}: {csub!r} -> {nsub!r}")
            else:
                if cval != nval:
                    findings.append(f"{in_path}: {pkg}.{field}: {cval!r} -> {nval!r}")

if errors:
    sys.exit(2)
for line in missing:
    print(f"{line[0]}: NO BASELINE — committed {line[1]} is missing; run compile-requirements.sh")
for finding in findings:
    print(finding)
sys.exit(1 if (findings or missing) else 0)
'
}

# --- Generated-artefact determinism ---------------------------------------
# Per-function `requirements.cdx.json` files are committed under git as
# diffable baselines for direct-dep PyPI provenance. For that
# to work, repeated `compile-requirements.sh` runs must produce byte-
# identical output on unchanged inputs. `cyclonedx-py requirements`
# emits two non-deterministic fields:
#   - metadata.timestamp = wall-clock at generation
#   - serialNumber       = fresh UUID per run
# We rewrite both to derived sentinels so the SBOM becomes a pure
# function of the lock file content.

# --- Malware-feed cross-reference (OSV API) -------------------------------
# Phase 5 hard gate: cross-reference every pinned package+version against
# the OSSF malicious-packages feed via the OSV.dev /querybatch API. The
# OSV.dev service aggregates many vulnerability sources; OSSF malicious-
# packages entries carry the `MAL-NNNN` ID prefix, distinguishing them
# from regular CVEs (`GHSA-…`, `PYSEC-…`) which `pip-audit` already covers.
#
# We deliberately do NOT maintain a local clone of the feed: the OSV API
# is the canonical query surface, returns version-matched results server-
# side, has no local state to manage, and unifies maintainer-side and CI
# (Phase 8) into one code path. The release gate already requires network
# (pip-audit, pip download); one more endpoint doesn't change the profile.
#
# Behaviour: fail-closed. If the API is unreachable, returns an error, or
# returns a malformed response, the helper exits 2 — the gate cannot make
# the safety claim under uncertainty. Maintainer retries with connectivity.

# req_lib_query_osv_malware_feed
#   Reads `pkg==version` lines from stdin (one per line; empty / comment
#   lines ignored). Issues a single OSV /querybatch POST. Filters results
#   for `MAL-*` advisory IDs. Prints one line per finding to stdout in
#   the form: `<pkg>==<version>  matches OSSF malicious-packages feed: MAL-NNNN[, MAL-MMMM]`.
#   Exits:
#     0 — no matches
#     1 — at least one malicious-packages-feed match found (details on stdout)
#     2 — API unreachable / returned error / malformed (message on stderr)
req_lib_query_osv_malware_feed() {
    # Pass program via -c so stdin stays connected to the caller's pipe.
    # (`python3 - <<HEREDOC` would route the heredoc itself to stdin and
    # `sys.stdin` would see the program text, not the piped pkg list.)
    python3 -c "$(cat <<'PYEOF'
import json, sys, urllib.request, urllib.error

pins = []
seen = set()
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#") or "==" not in line:
        continue
    name, _, version = line.partition("==")
    name, version = name.strip(), version.strip()
    key = (name.lower(), version)
    if key in seen:
        continue
    seen.add(key)
    pins.append((name, version))

if not pins:
    sys.exit(0)

payload = json.dumps({
    "queries": [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in pins
    ]
}).encode("utf-8")

req = urllib.request.Request(
    "https://api.osv.dev/v1/querybatch",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
except (urllib.error.URLError, TimeoutError, OSError) as e:
    print(f"OSV API unreachable: {e}", file=sys.stderr)
    sys.exit(2)

try:
    data = json.loads(body)
except json.JSONDecodeError as e:
    print(f"OSV API returned invalid JSON: {e}", file=sys.stderr)
    sys.exit(2)

results = data.get("results")
if not isinstance(results, list) or len(results) != len(pins):
    print(
        f"OSV API returned malformed response: "
        f"expected {len(pins)} results, got {len(results) if isinstance(results, list) else 'non-list'}",
        file=sys.stderr,
    )
    sys.exit(2)

findings = []
for (name, version), result in zip(pins, results):
    vulns = (result or {}).get("vulns") or []
    mal_ids = sorted({v.get("id") for v in vulns if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"].startswith("MAL-")})
    if mal_ids:
        findings.append(f"{name}=={version}  matches OSSF malicious-packages feed: {', '.join(mal_ids)}")

if findings:
    for f in findings:
        print(f)
    sys.exit(1)
sys.exit(0)
PYEOF
)"
}

# req_lib_normalize_cdx_sbom <sbom_path> <lock_path>
#   In-place rewrite <sbom_path>: timestamp -> fixed epoch, serialNumber
#   -> UUIDv5 derived from sha256(<lock_path>). Indent + key order
#   preserved (json.dump with indent=2, no sort) so the diff against
#   the previous-format committed SBOMs is limited to those two fields.
#   Exit 0 on success, non-zero on tooling/IO error.
req_lib_normalize_cdx_sbom() {
    local sbom_path="$1"
    local lock_path="$2"
    python3 - "$sbom_path" "$lock_path" <<'PYEOF'
import hashlib, json, sys, uuid
sbom_path, lock_path = sys.argv[1], sys.argv[2]
with open(lock_path, "rb") as f:
    lock_digest = hashlib.sha256(f.read()).hexdigest()
serial = uuid.uuid5(uuid.NAMESPACE_URL, f"opensecops:sbom:{lock_digest}")
with open(sbom_path, "r", encoding="utf-8") as f:
    sbom = json.load(f)
sbom.setdefault("metadata", {})["timestamp"] = "1970-01-01T00:00:00+00:00"
sbom["serialNumber"] = f"urn:uuid:{serial}"
with open(sbom_path, "w", encoding="utf-8") as f:
    json.dump(sbom, f, indent=2)
    f.write("\n")
PYEOF
}
