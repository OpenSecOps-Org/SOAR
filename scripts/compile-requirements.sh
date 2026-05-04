#!/usr/bin/env bash
# compile-requirements.sh — maintainer-side generator (read-write).
#
# For every `requirements.in` under <root> (default `.`):
#   1. Run `uv pip compile --generate-hashes <in> -o <txt>` to (re)generate
#      the hashed lock file adjacent to the input.
#   2. Run `pip-audit --strict --disable-pip` against the resulting `.txt`
#      to surface CVEs informationally. Findings here do NOT fail the
#      script — they are reported so the maintainer can act. The
#      release-gate enforcement lives in `check-requirements.sh`.
#   3. Generate a CycloneDX SBOM (`requirements.cdx.json`) adjacent to the
#      lock, using `cyclonedx-py requirements`.
#
# `uv pip compile` is invoked with the existing committed `.txt` (when
# present) as the seed via `--output-file`'s "preferences" behaviour: uv
# reads the existing pins as resolution preferences, producing a stable
# equilibrium when the `.in` has not changed and new PyPI uploads have
# appeared inside declared ranges. To re-resolve up to current latest,
# pass `--upgrade`. (See `scan-updates.sh` for the read-only inverse.)
#
# Exit codes:
#   0  — every compile + SBOM step succeeded; pip-audit findings (if any)
#        were reported informationally
#   non-zero — one or more compile or SBOM steps failed
#
# Tooling: requires `uv` on PATH. `pip-audit` and `cyclonedx-py` are
# fetched on demand via `uvx`, so they need not be pre-installed.

set -euo pipefail

# Resolve symlinks so we find _requirements_lib.sh next to the real script,
# not next to the top-level symlink the user invoked.
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

ROOT="${1:-.}"

if ! command -v uv >/dev/null 2>&1; then
    req_lib_error "uv is not on PATH. Install via: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 2
fi

req_lib_info "compile-requirements: scanning ${ROOT} for requirements.in files"

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

failures=0
audit_findings=0

for in_file in "${IN_FILES[@]}"; do
    dir="$(dirname "$in_file")"
    txt_file="${in_file%.in}.txt"
    sbom_file="${dir}/requirements.cdx.json"

    printf '\n'
    req_lib_info "── ${in_file} ──"

    # 1. Compile lock — invoke uv from inside the function directory with
    #    canonical relative paths so the autogen-header command line is
    #    byte-identical regardless of where the maintainer ran the script
    #    from. (uv records the literal argv in the output header comment.)
    if ! ( cd "$dir" && uv pip compile --generate-hashes --quiet \
            requirements.in -o requirements.txt ); then
        req_lib_error "  compile FAILED for ${in_file}"
        failures=$((failures + 1))
        continue
    fi

    # 1a. Insert a reproducibility timestamp as line 3 of the lock.
    #     `_check-requirements.sh --reproducible` reads this back as the
    #     `--exclude-newer` fence: any second machine recompiling later
    #     in time can pin the candidate set to packages uploaded on or
    #     before this moment, eliminating spurious drift caused by newer
    #     PyPI uploads inside declared version ranges. uv does not emit
    #     this header itself; we post-process it in.
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    {
        sed -n '1,2p' "$txt_file"
        printf '# uv-compiled-at: %s\n' "$ts"
        sed -n '3,$p' "$txt_file"
    } > "${txt_file}.uvh.tmp"
    mv "${txt_file}.uvh.tmp" "$txt_file"

    req_lib_ok "  ✓ compiled → ${txt_file}  (uv-compiled-at: ${ts})"

    # 2. pip-audit (informational here; release-gate is check-requirements.sh)
    if uvx pip-audit --strict --disable-pip --requirement "$txt_file" \
            >/dev/null 2>&1; then
        req_lib_ok "  ✓ pip-audit clean"
    else
        req_lib_warn "  ! pip-audit found issues:"
        uvx pip-audit --strict --disable-pip --requirement "$txt_file" \
            2>&1 | sed 's/^/      /' || true
        audit_findings=$((audit_findings + 1))
    fi

    # 3. CycloneDX SBOM (with determinism post-processing — committed under
    #    git as a diffable baseline; raw cyclonedx-py output has volatile
    #    timestamp + serialNumber, normalised by req_lib_normalize_cdx_sbom).
    if uvx --from cyclonedx-bom cyclonedx-py requirements \
            "$txt_file" -o "$sbom_file" >/dev/null 2>&1 \
       && req_lib_normalize_cdx_sbom "$sbom_file" "$txt_file" >/dev/null 2>&1; then
        req_lib_ok "  ✓ SBOM    → ${sbom_file}"
    else
        req_lib_error "  SBOM generation FAILED for ${txt_file}"
        failures=$((failures + 1))
    fi
done

# --- 4. PROVENANCE BASELINES (PyPI metadata) ------------------------------
# Each `requirements.in` produces one `requirements.provenance.json`
# sibling to its lock and SBOM. The provenance covers every direct dep
# the function consumes — its own declared lines plus lines pulled in
# transitively from any `-r`-included files (treated as textual
# substitution: an include has no identity of its own and gets no
# separate artefact). Drift against this baseline is the advisory
# provenance signal `_check-requirements.sh` reports.
#
# PyPI fetches dedupe across all paths in a single helper invocation.
printf '\n'
req_lib_info "── provenance baselines (PyPI metadata) ──"

if [[ ${#IN_FILES[@]} -eq 0 ]]; then
    req_lib_warn "  no requirements.in files found"
else
    if printf '%s\n' "${IN_FILES[@]}" | req_lib_write_provenance_for_in_files; then
        req_lib_ok "  ✓ wrote ${#IN_FILES[@]} provenance file(s)"
    else
        req_lib_error "  provenance write FAILED (PyPI fetch error or IO error)"
        failures=$((failures + 1))
    fi
fi

printf '\n'
req_lib_info "── summary ──"
req_lib_info "  files processed:    ${#IN_FILES[@]}"
if [[ $audit_findings -gt 0 ]]; then
    req_lib_warn  "  pip-audit findings: ${audit_findings} file(s) — informational, address before release-gate"
else
    req_lib_ok    "  pip-audit findings: 0"
fi
if [[ $failures -gt 0 ]]; then
    req_lib_error "  compile/SBOM/provenance failures: ${failures}"
    exit 1
fi
req_lib_ok    "  compile/SBOM/provenance failures: 0"
