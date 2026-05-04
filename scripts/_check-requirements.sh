#!/usr/bin/env bash
# check-requirements.sh — release-gate verifier (read-only).
#
# For every `requirements.in` under <root> (default `.`):
#
#   1. DRIFT CHECK (recompile-and-diff):
#      - Copy the committed `requirements.txt` to a temp file. This seeds
#        `uv pip compile` with the existing pins as resolution preferences,
#        so the result is a stable equilibrium when the `.in` has not
#        changed (newer PyPI uploads inside declared ranges do NOT cause
#        false drift).
#      - Run `uv pip compile --generate-hashes -o "$tmp" requirements.in`
#        from inside the function dir (canonical relative paths so the
#        autogen-header line is reproducible regardless of caller CWD).
#      - Diff $tmp against the committed `requirements.txt`. Any
#        difference fails the gate.
#      - This is what catches both "forgot to recompile after editing
#        .in" and "someone hand-edited a hash in the lock" — the
#        recompile produces the correct hash, the diff exposes the edit.
#
#   2. CVE CHECK:
#      - Run `pip-audit --strict --disable-pip --requirement <txt>` against
#        the committed lock. Any finding fails the gate.
#      - The override path is the `acknowledged_cves` array in
#        `.security-config.toml` at the repo root: each entry's `cve_id`
#        is passed to `pip-audit` via `--ignore-vuln <cve>`. The
#        rendered `SECURITY.md` §12 mirrors the same list with full
#        context (package, date, reason, expected resolution) so the
#        decision is publicly accountable. Acknowledging is a deliberate
#        maintainer action: edit `.security-config.toml`, re-render
#        `SECURITY.md`, commit both.
#
#   3. HASH-INTEGRITY CHECK (catches lock-file tampering / supply-chain
#      corruption that the recompile-and-diff path cannot catch):
#      - Run `pip download --require-hashes --no-deps -r <txt> -d <tmp>`.
#      - pip downloads each artifact from PyPI and verifies its SHA-256
#        matches at least one of the `--hash=sha256:...` entries in the
#        lock. Mismatch fails with the canonical
#        "THESE PACKAGES DO NOT MATCH THE HASHES" error.
#      - This is the same verification `sam build` performs at customer
#        install time — moving it to release-gate time means corruption
#        is caught BEFORE bytes ship to customers, not by their broken
#        deploy. Empirical note: `uv pip compile --generate-hashes`
#        passes seed hashes through verbatim when versions are already
#        pinned, so corrupted hashes do NOT surface via the recompile-
#        and-diff path. Hash integrity must be checked separately.
#
#   4. MALWARE-FEED CROSS-REFERENCE (OSV API; tree-wide):
#      - After the per-function loop, collect every unique pinned
#        package+version across all committed locks and POST a single
#        `/v1/querybatch` request to https://api.osv.dev.
#      - Filter the response for `MAL-*` advisory IDs — those are the
#        OSSF malicious-packages feed entries (other prefixes like
#        `GHSA-` and `PYSEC-` are regular CVEs that pip-audit covers
#        in step 2).
#      - Any match fails the gate with an explicit
#        "remove or replace <pkg>==<ver>" instruction. Hash pins alone
#        do not catch a package that was malicious at compile time, so
#        this is the L3 "scan for malware / deny list" control.
#      - Fail-closed: if the OSV API is unreachable or returns malformed
#        results, the gate fails. The gate cannot make the safety claim
#        under uncertainty.
#      - No local feed clone is maintained: the OSV API is the canonical
#        query surface, returns version-matched results server-side, and
#        unifies maintainer-side and CI (Phase 8) into one code path.
#
#   5. PROVENANCE DRIFT (PyPI metadata; ADVISORY; tree-wide):
#      - For each `.in` file (any name — `requirements.in` AND shared
#        specs like `boto3.in`), read the committed
#        `<base>.provenance.json` baseline and re-fetch PyPI metadata
#        for its declared direct deps.
#      - Compare a stable subset of fields (author, author_email,
#        maintainer, maintainer_email, home_page, project_urls). Drift
#        is the signal a publisher attribution has changed since the
#        baseline was committed.
#      - WARN, do not fail. The maintainer reviews drifts the same way
#        they review lock-file diffs; accepting a drift is a deliberate
#        recompile + recommit. Missing baselines are reported separately
#        (run `compile-requirements.sh` and recommit).
#      - Why advisory and not a hard gate: PyPI's JSON metadata reflects
#        upload-time uploader-supplied values; "verified" project URLs
#        prove URL control at verification time, not a continuing
#        publisher relationship — they are not a trustworthy hard
#        provenance signal. Where PyPI Trusted Publishers / PEP 740
#        attestations are available, those can be promoted to hard gate
#        per-dep in a later phase; the rest stays advisory.
#      - PyPI fetches deduped across all .in paths in a single helper
#        invocation: O(M unique direct deps), not O(N .in files × M).
#
# Read-only: never modifies any committed file.
#
# --public-log mode (used by the Phase 8 daily-scan CI workflow against
# published OpenSecOps repos): sensitive findings are redacted to a
# generic line. Package names, versions, CVE IDs, and malware-feed
# entries do NOT appear in stdout. The exit code stays non-zero so the
# workflow fails closed. Maintainers reproduce details by re-running
# locally without the flag — there is no separate "private channel"
# output. The redaction is enforced in this script (not in workflow
# YAML) so it is testable locally.
#
# Exit codes:
#   0 — every .in/.txt pair clean (no drift, no CVEs, no hash mismatches,
#       no malware-feed matches)
#   1 — any of the four checks failed, or the malware-feed API was
#       unreachable (fail-closed)
#   2 — usage / tooling error
#
# Tooling: requires `uv` and `python3` on PATH. `pip-audit` reaches via
# `uvx`. Malware-feed check uses Python stdlib only (urllib.request).

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

# --- Argument parsing -----------------------------------------------------
PUBLIC_LOG=0
REPRODUCIBLE=0
ROOT="."
while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-log)   PUBLIC_LOG=1; shift ;;
        --reproducible) REPRODUCIBLE=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --) shift; break ;;
        -*) req_lib_error "unknown flag: $1"; exit 2 ;;
        *)  ROOT="$1"; shift ;;
    esac
done

if ! command -v uv >/dev/null 2>&1; then
    req_lib_error "uv is not on PATH"
    exit 2
fi

# --- Acknowledged-and-deferred CVEs --------------------------------------
# Read the repo's .security-config.toml (when present) for any CVE IDs
# the maintainer has explicitly acknowledged. These are passed to
# `pip-audit` via `--ignore-vuln <cve>` so the gate skips them.
# Schema: `acknowledged_cves` is an array of inline tables; each entry
# must carry at least `cve_id`. Other fields (package, date, reason,
# expected_resolution) are consumed by the SECURITY.md renderer for
# the customer-facing §12 table — they are documentation, not gate
# inputs. Missing TOML or empty array means no acknowledgements.
IGNORE_VULN_ARGS=()
ACKED_CVES=()
CONFIG_FILE="${ROOT}/.security-config.toml"
if [[ -f "$CONFIG_FILE" ]]; then
    # uv-shipped Python ≥3.11 (stdlib tomllib; no third-party deps).
    # Output: one CVE ID per line on stdout; nothing on success-empty.
    # Any TOML or schema error → non-zero exit, message on stderr.
    set +e
    acked_raw="$(uv run --no-project --quiet --python ">=3.11" python - "$CONFIG_FILE" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    cfg = tomllib.load(f)
entries = cfg.get("acknowledged_cves", []) or []
if not isinstance(entries, list):
    sys.stderr.write("acknowledged_cves must be an array\n")
    sys.exit(3)
for entry in entries:
    if not isinstance(entry, dict):
        sys.stderr.write(
            "each acknowledged_cves entry must be an inline table with at least cve_id\n"
        )
        sys.exit(3)
    cve = entry.get("cve_id")
    if not cve or not isinstance(cve, str):
        sys.stderr.write("each acknowledged_cves entry needs cve_id (string)\n")
        sys.exit(3)
    print(cve)
PY
)"
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
        req_lib_error "  failed to parse acknowledged_cves from ${CONFIG_FILE}"
        exit 2
    fi
    while IFS= read -r cve; do
        [[ -n "$cve" ]] || continue
        ACKED_CVES+=("$cve")
        IGNORE_VULN_ARGS+=("--ignore-vuln" "$cve")
    done <<< "$acked_raw"
fi

# --- Output gating --------------------------------------------------------
# In --public-log mode, suppress sensitive details (package names, CVE
# IDs, lock contents) and emit a generic redacted line in their place.
emit_sensitive() {
    if [[ $PUBLIC_LOG -eq 1 ]]; then
        printf '      %s\n' "sensitive-finding-detected; rerun locally for details"
    else
        sed 's/^/      /'
    fi
}

# --- Walk -----------------------------------------------------------------
_mode_label="full"
[[ $PUBLIC_LOG   -eq 1 ]] && _mode_label="public-log"
[[ $REPRODUCIBLE -eq 1 ]] && _mode_label="${_mode_label}+reproducible"
req_lib_info "check-requirements: scanning ${ROOT} for requirements.in files (mode: ${_mode_label})"
unset _mode_label

IN_FILES=()
while IFS= read -r _f; do
    IN_FILES+=("$_f")
done < <(req_lib_discover_in_files "$ROOT" | sort)
unset _f

if [[ ${#IN_FILES[@]} -eq 0 ]]; then
    req_lib_warn "no requirements.in files found under ${ROOT}"
    exit 0
fi

req_lib_info "found ${#IN_FILES[@]} requirements.in file(s)"
if (( ${#ACKED_CVES[@]} > 0 )); then
    req_lib_info "honouring ${#ACKED_CVES[@]} acknowledged-and-deferred CVE(s) from .security-config.toml"
    for cve in "${ACKED_CVES[@]}"; do
        printf '  - %s\n' "$cve"
    done
fi

drift_count=0
cve_count=0
hash_count=0
missing_lock=0

for in_file in "${IN_FILES[@]}"; do
    dir="$(dirname "$in_file")"
    txt_file="${in_file%.in}.txt"

    printf '\n'
    req_lib_info "── ${in_file} ──"

    if [[ ! -f "$txt_file" ]]; then
        req_lib_error "  no committed requirements.txt — run compile-requirements.sh and commit"
        missing_lock=$((missing_lock + 1))
        continue
    fi

    # 1. DRIFT — recompile-and-diff. Two modes:
    #
    #   default: seed from committed lock + trust maintainer's uv cache.
    #     Fast; catches "forgot to recompile after editing .in" and
    #     "someone hand-edited a hash in the lock". Used by every
    #     interactive run of this script and by compile-requirements.sh
    #     informationally.
    #
    #   --reproducible: clean uv cache + `--exclude-newer <ts>` fence,
    #     where <ts> is the `# uv-compiled-at:` header committed in the
    #     lock. Stricter; verifies that any second machine producing the
    #     same lock from .in + pinned uv version + clean cache + recorded
    #     timestamp gets bit-identical output. This is the §4.11 cat. 3
    #     gate-derivation reproducibility property; ./publish runs in
    #     this mode at release time.
    tmp="$(mktemp -t check-req.XXXXXX)"
    if [[ $REPRODUCIBLE -eq 1 ]]; then
        ts="$(grep -m1 '^# uv-compiled-at:' "$txt_file" \
                | sed 's/^# uv-compiled-at:[[:space:]]*//')"
        if [[ -z "$ts" ]]; then
            req_lib_error "  no '# uv-compiled-at:' header in $txt_file"
            req_lib_warn  "      → run compile-requirements.sh and recommit to add the reproducibility timestamp"
            drift_count=$((drift_count + 1))
            rm -f "$tmp"
            continue
        fi
        clean_cache="$(mktemp -d -t uv-clean-cache.XXXXXX)"
        if ! ( cd "$dir" && UV_CACHE_DIR="$clean_cache" uv pip compile \
                --generate-hashes --quiet \
                --exclude-newer "$ts" \
                requirements.in -o "$tmp" ) 2>/dev/null; then
            req_lib_error "  recompile FAILED in --reproducible mode (clean cache + --exclude-newer $ts)"
            drift_count=$((drift_count + 1))
            rm -f "$tmp"
            rm -rf "$clean_cache"
            continue
        fi
        rm -rf "$clean_cache"
    else
        cp "$txt_file" "$tmp"
        if ! ( cd "$dir" && uv pip compile --generate-hashes --quiet \
                requirements.in -o "$tmp" ) 2>/dev/null; then
            req_lib_error "  recompile FAILED — toolchain or .in error"
            drift_count=$((drift_count + 1))
            rm -f "$tmp"
            continue
        fi
    fi

    # Diff after stripping (a) uv's 2-line autogen header (its `-o <path>`
    # argv differs between committed and temp paths) and (b) the optional
    # `# uv-compiled-at:` metadata line (an *input* to resolution under
    # --exclude-newer, not evidence of regeneration timing; uv does not
    # emit it, compile-requirements.sh post-processes it in, so a fresh
    # recompile temp file lacks it). Stripping is uniform across both
    # modes and handles legacy locks (no timestamp) as a no-op.
    if diff -q \
            <(tail -n +3 "$tmp"      | grep -v '^# uv-compiled-at:') \
            <(tail -n +3 "$txt_file" | grep -v '^# uv-compiled-at:') \
            >/dev/null 2>&1; then
        if [[ $REPRODUCIBLE -eq 1 ]]; then
            req_lib_ok "  ✓ no drift (reproducible: clean cache + --exclude-newer ${ts})"
        else
            req_lib_ok "  ✓ no drift"
        fi
    else
        req_lib_error "  ! DRIFT detected — committed requirements.txt differs from .in resolution"
        if [[ $PUBLIC_LOG -eq 1 ]]; then
            printf '      %s\n' "sensitive-finding-detected; rerun locally for details"
        else
            # `|| true` so that diff's non-zero exit (the expected case
            # in this branch) does not short-circuit subsequent checks
            # via `set -euo pipefail`. Drift still rejects via
            # drift_count; the trailing `|| true` is for reporting
            # completeness only.
            diff \
                <(tail -n +3 "$txt_file" | grep -v '^# uv-compiled-at:') \
                <(tail -n +3 "$tmp"      | grep -v '^# uv-compiled-at:') \
                | sed 's/^/      /' || true
        fi
        if [[ $REPRODUCIBLE -eq 1 ]]; then
            req_lib_warn  "      → in --reproducible mode this means the lock is not bit-reproducible from .in"
            req_lib_warn  "        + pinned uv version + clean cache + recorded timestamp;"
            req_lib_warn  "        either the toolchain has drifted (uv version) or the lock has been hand-edited"
        else
            req_lib_warn  "      → run \`compile-requirements.sh\` and recommit"
        fi
        drift_count=$((drift_count + 1))
    fi
    rm -f "$tmp"

    # 2. CVE — pip-audit on committed lock.
    # `--ignore-vuln` entries come from .security-config.toml's
    # `acknowledged_cves` array (parsed once, above). Empty when there
    # are no acknowledgements.
    if uvx pip-audit --strict --disable-pip --requirement "$txt_file" \
            ${IGNORE_VULN_ARGS[@]+"${IGNORE_VULN_ARGS[@]}"} \
            >/dev/null 2>&1; then
        req_lib_ok "  ✓ pip-audit clean"
    else
        req_lib_error "  ! CVE finding(s):"
        uvx pip-audit --strict --disable-pip --requirement "$txt_file" \
            ${IGNORE_VULN_ARGS[@]+"${IGNORE_VULN_ARGS[@]}"} \
            2>&1 | emit_sensitive || true
        req_lib_warn  "      → bump offending package + recompile, or add an"
        req_lib_warn  "        acknowledged_cves entry in .security-config.toml + re-render SECURITY.md"
        cve_count=$((cve_count + 1))
    fi

    # 3. HASH INTEGRITY — pip downloads each artifact from PyPI and
    #    verifies its SHA-256 matches the recorded hash. Catches
    #    lock-file tampering / supply-chain corruption at gate time,
    #    before bytes ship to customers.
    hash_tmpdir="$(mktemp -d -t check-req-dl.XXXXXX)"
    if uvx --from pip pip download --require-hashes --no-deps \
            -r "$txt_file" -d "$hash_tmpdir" >/dev/null 2>&1; then
        req_lib_ok "  ✓ hash integrity verified (downloaded + checked)"
    else
        req_lib_error "  ! HASH MISMATCH — committed lock does not match PyPI artifacts"
        if [[ $PUBLIC_LOG -eq 1 ]]; then
            printf '      %s\n' "sensitive-finding-detected; rerun locally for details"
        else
            uvx --from pip pip download --require-hashes --no-deps \
                -r "$txt_file" -d "$hash_tmpdir" 2>&1 \
                | grep -E 'THESE PACKAGES|Expected|Got|from https://' \
                | sed 's/^/      /' || true
        fi
        req_lib_warn  "      → lock has been tampered with, or PyPI artifact has changed; investigate before recompiling"
        hash_count=$((hash_count + 1))
    fi
    rm -rf "$hash_tmpdir"
done

# --- 4. MALWARE-FEED CROSS-REFERENCE (OSV API) ----------------------------
# Tree-wide pass: collect every unique pinned package+version across all
# committed locks, query the OSV.dev /querybatch API once, filter results
# for `MAL-*` advisory IDs (OSSF malicious-packages feed entries). Any
# match fails the release gate. Fail-closed on API error: the gate cannot
# verify malware-feed status under uncertainty.
malware_count=0
api_error=0
if (( ${#IN_FILES[@]} > 0 && missing_lock == 0 )); then
    printf '\n'
    req_lib_info "── malware-feed cross-reference (OSV) ──"

    # Aggregate unique pkg==version lines from every committed lock.
    pin_list="$(
        for in_file in "${IN_FILES[@]}"; do
            txt_file="${in_file%.in}.txt"
            [[ -f "$txt_file" ]] || continue
            grep -E '^[A-Za-z0-9_.-]+==' "$txt_file" | sed 's/[[:space:]].*//'
        done | sort -u
    )"
    pin_count=$(printf '%s' "$pin_list" | grep -c '^.' || true)

    if [[ $pin_count -eq 0 ]]; then
        req_lib_warn "  no pinned packages to check"
    else
        # Helper uses non-zero exit as signal (1=findings, 2=API error).
        # `set -e` would terminate the script on those, so wrap.
        set +e
        malware_findings="$(printf '%s\n' "$pin_list" | req_lib_query_osv_malware_feed)"
        helper_exit=$?
        set -e

        if [[ $helper_exit -eq 0 ]]; then
            req_lib_ok "  ✓ no matches across ${pin_count} unique pinned package(s)"
        elif [[ $helper_exit -eq 1 ]]; then
            req_lib_error "  ! MALICIOUS PACKAGE(S) found in committed locks:"
            if [[ $PUBLIC_LOG -eq 1 ]]; then
                printf '      %s\n' "sensitive-finding-detected; rerun locally for details"
            else
                printf '%s\n' "$malware_findings" | sed 's/^/      /'
            fi
            req_lib_warn  "      → remove or replace these packages; they are in the OSSF malicious-packages feed"
            req_lib_warn  "        (https://github.com/ossf/malicious-packages)"
            malware_count=$(printf '%s' "$malware_findings" | grep -c '^.' || true)
        else
            req_lib_error "  ! malware-feed check FAILED: OSV API unreachable or returned error"
            req_lib_warn  "      → release gate cannot verify malware-feed cross-reference; retry with network access"
            api_error=1
        fi
    fi
fi

# --- 5. PROVENANCE DRIFT (PyPI metadata; ADVISORY) ------------------------
# For each requirements.in, compare the committed
# `requirements.provenance.json` against fresh PyPI metadata for the
# direct deps the function consumes (own lines + `-r`-included lines).
# Drift is reported as a warning; the gate does NOT fail. Missing
# baselines indicate `compile-requirements.sh` has not been run since
# the dep was added.
provenance_drift_count=0
provenance_missing_count=0
printf '\n'
req_lib_info "── provenance drift (PyPI metadata; advisory) ──"

if [[ ${#IN_FILES[@]} -eq 0 ]]; then
    req_lib_warn "  no requirements.in files found"
else
    # Helper uses non-zero exit as signal (1=drift/missing, 2=API error).
    # `set -e` would terminate the script on those, so wrap.
    set +e
    provenance_findings="$(printf '%s\n' "${IN_FILES[@]}" | req_lib_check_provenance_drift)"
    helper_exit=$?
    set -e
    case $helper_exit in
        0)
            req_lib_ok "  ✓ no drift across ${#IN_FILES[@]} requirements.in file(s)"
            ;;
        1)
            # Split the helper output: NO BASELINE lines vs drift lines.
            missing_lines="$(printf '%s\n' "$provenance_findings" | grep ': NO BASELINE' || true)"
            drift_lines="$(printf '%s\n' "$provenance_findings" | grep -v ': NO BASELINE' | grep -v '^$' || true)"
            if [[ -n "$missing_lines" ]]; then
                provenance_missing_count=$(printf '%s' "$missing_lines" | grep -c '^.' || true)
                req_lib_warn "  ! ${provenance_missing_count} .in file(s) have no committed provenance baseline:"
                printf '%s\n' "$missing_lines" | sed 's/^/      /'
                req_lib_warn  "      → run \`compile-requirements.sh\` and recommit"
            fi
            if [[ -n "$drift_lines" ]]; then
                provenance_drift_count=$(printf '%s' "$drift_lines" | grep -c '^.' || true)
                req_lib_warn "  ! ${provenance_drift_count} provenance drift(s) detected (advisory; does NOT fail the gate):"
                if [[ $PUBLIC_LOG -eq 1 ]]; then
                    printf '      %s\n' "advisory-finding-detected; rerun locally for details"
                else
                    printf '%s\n' "$drift_lines" | sed 's/^/      /'
                fi
                req_lib_warn  "      → review the diff and recompile if the change is acceptable;"
                req_lib_warn  "        or investigate publisher hijack if the change is unexpected"
            fi
            ;;
        2)
            req_lib_error "  ! provenance check FAILED: PyPI metadata fetch error"
            req_lib_warn  "      → advisory check could not run; retry with network access (gate continues)"
            ;;
    esac
fi

# --- Summary --------------------------------------------------------------
printf '\n'
req_lib_info "── summary ──"
req_lib_info "  files processed:        ${#IN_FILES[@]}"
[[ $missing_lock             -gt 0 ]] && req_lib_error "  missing locks:          ${missing_lock}"
[[ $drift_count              -gt 0 ]] && req_lib_error "  drift findings:         ${drift_count}"
[[ $cve_count                -gt 0 ]] && req_lib_error "  CVE findings:           ${cve_count}"
[[ $hash_count               -gt 0 ]] && req_lib_error "  hash mismatches:        ${hash_count}"
[[ $malware_count            -gt 0 ]] && req_lib_error "  malware findings:       ${malware_count}"
[[ $api_error                -gt 0 ]] && req_lib_error "  malware-feed API:       unreachable (gate cannot verify)"
[[ $provenance_missing_count -gt 0 ]] && req_lib_warn  "  provenance baselines:   ${provenance_missing_count} missing (advisory)"
[[ $provenance_drift_count   -gt 0 ]] && req_lib_warn  "  provenance drifts:      ${provenance_drift_count} (advisory)"

if (( missing_lock + drift_count + cve_count + hash_count + malware_count + api_error == 0 )); then
    if (( provenance_missing_count + provenance_drift_count > 0 )); then
        req_lib_ok    "  release-gate clean ✓ (provenance advisories above are non-blocking)"
    else
        req_lib_ok    "  release-gate clean ✓"
    fi
    exit 0
fi

req_lib_error "  release-gate FAILED"
exit 1
