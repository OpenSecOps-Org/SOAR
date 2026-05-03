#!/usr/bin/env bash
# scan-updates.sh — informational update scanner (read-only).
#
# Counterpart to check-requirements.sh, with deliberately inverted
# resolver semantics:
#
#   check-requirements.sh — SEEDS the recompile from the committed lock,
#                           so newer PyPI uploads inside declared ranges
#                           do not produce false drift. Goal: stability.
#   scan-updates.sh       — compiles into a FRESH temp file with --upgrade
#                           and no seed, so the resolver considers every
#                           permissible version. The diff against the
#                           committed lock IS the upgrade report.
#                           Goal: discovery of what's available.
#
# For every `requirements.in` under <root> (default `.`):
#
#   1. AVAILABLE-UPGRADE SCAN:
#      - Run `uv pip compile --upgrade --generate-hashes -o "$tmp"
#        requirements.in` (fresh empty temp; --upgrade forces the resolver
#        to consider all permissible versions).
#      - Diff $tmp against the committed `requirements.txt` (autogen
#        header stripped). Reported informationally — does NOT fail.
#      - $tmp deleted.
#
#   2. CVE SCAN:
#      - Run `pip-audit --strict --disable-pip --requirement <txt>` against
#        the committed lock. Reported informationally — does NOT fail by
#        default. In --public-log mode, fails the script (matching
#        check-requirements.sh).
#
# Read-only: never modifies any committed file.
#
# Exit codes:
#   default mode:       0 always (informational; both checks just report)
#   --public-log mode:  0 if no CVEs; 1 if any CVE found (workflow fails
#                       closed on sensitive findings, with package /
#                       version / CVE-ID redacted from stdout)
#   2: usage / tooling error
#
# This script is NOT wired into `./publish`. The release gate is
# check-requirements.sh. scan-updates.sh is a notice board, not a wall.
#
# Tooling: requires `uv` on PATH. `pip-audit` reaches via `uvx`.

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
ROOT="."
while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-log) PUBLIC_LOG=1; shift ;;
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

emit_sensitive() {
    if [[ $PUBLIC_LOG -eq 1 ]]; then
        printf '      %s\n' "sensitive-finding-detected; rerun locally for details"
    else
        sed 's/^/      /'
    fi
}

req_lib_info "scan-updates: scanning ${ROOT} for requirements.in files (mode: $([[ $PUBLIC_LOG -eq 1 ]] && echo public-log || echo full))"

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

upgrade_count=0
cve_count=0
files_with_upgrades=0
files_with_cves=0

for in_file in "${IN_FILES[@]}"; do
    dir="$(dirname "$in_file")"
    txt_file="${in_file%.in}.txt"

    printf '\n'
    req_lib_info "── ${in_file} ──"

    if [[ ! -f "$txt_file" ]]; then
        req_lib_warn "  no committed requirements.txt — skipping"
        continue
    fi

    # 1. AVAILABLE-UPGRADE SCAN — fresh temp, --upgrade, no seed.
    tmp="$(mktemp -t scan-updates.XXXXXX)"
    if ! ( cd "$dir" && uv pip compile --upgrade --generate-hashes --quiet \
            requirements.in -o "$tmp" ) 2>/dev/null; then
        req_lib_error "  upgrade-scan recompile FAILED — toolchain or .in error"
        rm -f "$tmp"
        continue
    fi

    # Compare package==version lines only, not hashes (a hash diff alone
    # means PyPI re-published metadata for the same version — not an
    # upgrade). Matching `^<name>==<version>` lines from each file.
    upgrades_for_file="$(
        diff \
            <(sed -nE 's/^([a-zA-Z0-9_.-]+==[^ [:space:]\\]+).*$/\1/p' "$txt_file" | sort) \
            <(sed -nE 's/^([a-zA-Z0-9_.-]+==[^ [:space:]\\]+).*$/\1/p' "$tmp"      | sort) \
        || true
    )"

    if [[ -z "$upgrades_for_file" ]]; then
        req_lib_ok "  ✓ all dependencies at latest permissible version"
    else
        # Render as a simple "name: cur → new" report
        # `< name==X` lines = currently committed; `> name==Y` lines = available
        committed_lines="$(printf '%s\n' "$upgrades_for_file" | grep -E '^< ' | sed 's/^< //')"
        available_lines="$(printf '%s\n' "$upgrades_for_file" | grep -E '^> ' | sed 's/^> //')"

        # Build a "name -> cur" map and "name -> new" map.
        req_lib_warn "  ! upgrades available:"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            name="${line%%==*}"
            cur="${line#*==}"
            new="$(printf '%s\n' "$available_lines" | grep -E "^${name}==" | head -1 | sed "s/^${name}==//")"
            if [[ -n "$new" && "$cur" != "$new" ]]; then
                printf '      %s: %s → %s\n' "$name" "$cur" "$new"
                upgrade_count=$((upgrade_count + 1))
            elif [[ -z "$new" ]]; then
                printf '      %s: %s → (removed from resolution)\n' "$name" "$cur"
                upgrade_count=$((upgrade_count + 1))
            fi
        done <<< "$committed_lines"

        # Catch newly-introduced packages (in $tmp, not in committed)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            name="${line%%==*}"
            new="${line#*==}"
            if ! printf '%s\n' "$committed_lines" | grep -qE "^${name}=="; then
                printf '      %s: (new transitive) → %s\n' "$name" "$new"
                upgrade_count=$((upgrade_count + 1))
            fi
        done <<< "$available_lines"

        files_with_upgrades=$((files_with_upgrades + 1))
    fi
    rm -f "$tmp"

    # 2. CVE SCAN — informational by default; fails in --public-log mode.
    if uvx pip-audit --strict --disable-pip --requirement "$txt_file" \
            >/dev/null 2>&1; then
        req_lib_ok "  ✓ pip-audit clean"
    else
        if [[ $PUBLIC_LOG -eq 1 ]]; then
            req_lib_error "  ! CVE finding(s):"
        else
            req_lib_warn  "  ! CVE finding(s) (informational):"
        fi
        uvx pip-audit --strict --disable-pip --requirement "$txt_file" \
            2>&1 | emit_sensitive || true
        cve_count=$((cve_count + 1))
        files_with_cves=$((files_with_cves + 1))
    fi
done

# --- Summary --------------------------------------------------------------
printf '\n'
req_lib_info "── summary ──"
req_lib_info "  files processed:        ${#IN_FILES[@]}"
if [[ $upgrade_count -gt 0 ]]; then
    req_lib_warn  "  upgrades available:     ${upgrade_count} package change(s) across ${files_with_upgrades} file(s)"
else
    req_lib_ok    "  upgrades available:     0"
fi
if [[ $cve_count -gt 0 ]]; then
    if [[ $PUBLIC_LOG -eq 1 ]]; then
        req_lib_error "  CVE findings:           ${cve_count} file(s) — workflow fails closed"
    else
        req_lib_warn  "  CVE findings:           ${cve_count} file(s) (informational; release-gate enforcement is in check-requirements.sh)"
    fi
else
    req_lib_ok    "  CVE findings:           0"
fi

# Exit-code semantics: default mode is informational (always 0).
# --public-log mode fails closed on CVEs so the daily-scan workflow
# surfaces them via job-failure rather than silently in logs.
if [[ $PUBLIC_LOG -eq 1 && $cve_count -gt 0 ]]; then
    exit 1
fi
exit 0
