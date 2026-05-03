#!/usr/bin/env bash
# generate-security-md.sh — render <repo>/SECURITY.md from
# <repo>/SECURITY.md.template + <repo>/.security-config.toml.
#
# Per the OpenSecOps supply-chain config schema:
#   - SECURITY.md.template — canonical, refresh-distributed byte-identical
#     to every component repo. Source of truth for everything universal
#     across components (policy text, governance, framework claims).
#   - .security-config.toml — per-component values, hand-authored, lives
#     in the component repo, NOT touched by refresh, NOT touched by this
#     generator (read-only).
#   - SECURITY.md — generated artefact, committed. Customer-facing.
#
# Schema (post-Phase-6 simplification, 2026-05-03):
#   converted          (bool, required)        — has this repo been converted
#                                                 to the locked-dependency model?
#   converted_in       (str,  required if converted=true)
#                                               — the release tag at which the
#                                                 conversion shipped (e.g. "v3.0.0").
#   acknowledged_cves  (array, optional)       — defaults to empty; renders as
#                                                 "_None at this time._" in §12.
#   component_name     (str, optional)         — auto-derived from
#                                                 `git remote get-url OpenSecOps`
#                                                 when absent.
#
# Placeholder set:
#   {{COMPONENT_NAME}}      — from TOML or auto-derived from git remote.
#   {{SUPPLY_CHAIN_STATUS}} — rendered from `converted` + `converted_in`.
#   {{SBOM_LOCATION}}       — derived URL pattern using {{COMPONENT_NAME}}.
#   {{ACKNOWLEDGED_CVES}}   — markdown table or "_None at this time._".
#
# Idempotency contract: running the script twice with unchanged inputs
# must produce no working-tree changes. Validated by comparing the
# rendered output to the existing `SECURITY.md` (when present).
#
# Usage:
#   generate-security-md.sh                  # operates on `.`
#   generate-security-md.sh <repo>           # operates on a specific dir
#   generate-security-md.sh --check          # exits non-zero if rendered
#                                            #   output differs from the
#                                            #   committed SECURITY.md
#                                            #   (use in release-gate /
#                                            #   CI to enforce idempotency)
#
# Tooling: uv-shipped Python ≥3.11 (uses stdlib `tomllib`). No third-
# party dependencies.

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

CHECK_ONLY=0
ROOT="."
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --) shift; break ;;
        -*) req_lib_error "unknown flag: $1"; exit 2 ;;
        *)  ROOT="$1"; shift ;;
    esac
done

TEMPLATE="${ROOT}/SECURITY.md.template"
CONFIG="${ROOT}/.security-config.toml"
OUTPUT="${ROOT}/SECURITY.md"

if [[ ! -f "$TEMPLATE" ]]; then
    req_lib_error "no template at ${TEMPLATE}"
    req_lib_error "  → run \`./refresh\` from the Installer to distribute it"
    exit 2
fi
if [[ ! -f "$CONFIG" ]]; then
    req_lib_error "no config at ${CONFIG}"
    req_lib_error "  → author it; see the OpenSecOps supply-chain config schema for the schema"
    exit 2
fi
if ! command -v uv >/dev/null 2>&1; then
    req_lib_error "uv is not on PATH"
    exit 2
fi

# Auto-derive component name from `git remote get-url OpenSecOps` when
# the TOML does not declare one. The OpenSecOps remote is the public
# release repo (per the OpenSecOps dual-repository convention), so
# the URL's basename is authoritative for the customer-facing component
# name. Empty if the remote is missing or git is unavailable; the Python
# stage falls back to the TOML value or fails with a clear error.
AUTO_COMPONENT_NAME=""
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    AUTO_COMPONENT_NAME="$(git -C "$ROOT" remote get-url OpenSecOps 2>/dev/null | sed -E 's#^.*/##; s#\.git$##' || true)"
fi
export AUTO_COMPONENT_NAME

# Render via uv-shipped Python (stdlib tomllib; no third-party deps).
rendered="$(
    uv run --no-project --quiet --python ">=3.11" python - "$TEMPLATE" "$CONFIG" <<'PY'
import os, re, sys, tomllib

template_path, config_path = sys.argv[1], sys.argv[2]

with open(config_path, "rb") as f:
    config = tomllib.load(f)

# --- Schema validation -----------------------------------------------------

converted = config.get("converted")
if converted is None:
    sys.stderr.write(
        "ERROR: .security-config.toml missing required key `converted` (bool)\n"
        "→ set `converted = true` (or `false`); see the OpenSecOps supply-chain config schema\n"
    )
    sys.exit(3)
if not isinstance(converted, bool):
    sys.stderr.write("ERROR: `converted` must be a boolean (true/false)\n")
    sys.exit(3)

converted_in = config.get("converted_in")
if converted and not converted_in:
    sys.stderr.write(
        "ERROR: `converted = true` requires `converted_in` (e.g. `converted_in = \"v3.0.0\"`)\n"
    )
    sys.exit(3)

component_name = config.get("component_name") or os.environ.get("AUTO_COMPONENT_NAME") or ""
if not component_name:
    sys.stderr.write(
        "ERROR: cannot determine component_name\n"
        "→ either set `component_name` in .security-config.toml, or ensure the repo\n"
        "  has an `OpenSecOps` git remote (the basename of the URL is used)\n"
    )
    sys.exit(3)

acknowledged_cves = config.get("acknowledged_cves", []) or []
if not isinstance(acknowledged_cves, list):
    sys.stderr.write("ERROR: `acknowledged_cves` must be an array (possibly empty)\n")
    sys.exit(3)

# --- Derived values --------------------------------------------------------

if converted:
    supply_chain_status = (
        f"This component was converted to the locked-dependency model in **{converted_in}**. "
        f"The supply-chain posture below applies to {converted_in} and every release after it. "
        f"Earlier releases predate the conversion and do not carry these guarantees; per §1, the "
        f"remediation for any exposure on an earlier release is to upgrade to the current release."
    )
else:
    supply_chain_status = (
        "This component has **not yet been converted** to the locked-dependency model. The posture "
        "below describes the target end-state for this component once conversion lands; it is not yet "
        "in effect. The conversion timing for unconverted components is tracked in "
        "the project's roadmap."
    )

# Customers receive releases on the OpenSecOps-Org public remote (the DEV
# remote is internal). Asset name pattern is `<component>-<version>-sbom.cdx.json`.
sbom_location = (
    f"```\n"
    f"https://github.com/OpenSecOps-Org/{component_name}/releases/download/<VERSION>/"
    f"{component_name}-<VERSION>-sbom.cdx.json\n"
    f"```\n\n"
    f"Replace `<VERSION>` with the release tag (e.g. `{converted_in}`). The asset is attached "
    f"to every release on the public OpenSecOps-Org remote."
)

if not acknowledged_cves:
    acknowledged_cves_rendered = "_None at this time._"
else:
    # Each entry is expected to be an inline table with keys: cve_id, package,
    # date_acknowledged, reason, expected_resolution. Missing keys render as "—".
    cols = ["cve_id", "package", "date_acknowledged", "reason", "expected_resolution"]
    headers = ["CVE ID", "Package", "Acknowledged", "Reason", "Expected resolution"]
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for entry in acknowledged_cves:
        if not isinstance(entry, dict):
            sys.stderr.write(
                "ERROR: each `acknowledged_cves` entry must be a TOML table with keys "
                "cve_id, package, date_acknowledged, reason, expected_resolution\n"
            )
            sys.exit(3)
        lines.append("| " + " | ".join(str(entry.get(c, "—")) for c in cols) + " |")
    acknowledged_cves_rendered = "\n".join(lines)

# --- Substitution ----------------------------------------------------------

lookup = {
    "COMPONENT_NAME":      component_name,
    "SUPPLY_CHAIN_STATUS": supply_chain_status,
    "SBOM_LOCATION":       sbom_location,
    "ACKNOWLEDGED_CVES":   acknowledged_cves_rendered,
}

with open(template_path, "r", encoding="utf-8") as f:
    template = f.read()

placeholder_re = re.compile(r"\{\{([A-Z0-9_]+)\}\}")

missing = []

def repl(match):
    key = match.group(1)
    if key not in lookup:
        missing.append(key)
        return match.group(0)
    return str(lookup[key])

rendered = placeholder_re.sub(repl, template)

if missing:
    sys.stderr.write(
        "ERROR: unresolved placeholders in template: "
        + ", ".join(sorted(set(missing))) + "\n"
        + "→ either remove from template, add to the lookup in _generate-security-md.sh,\n"
        + "  or extend .security-config.toml schema (see the OpenSecOps supply-chain config schema)\n"
    )
    sys.exit(3)

# Strip the top-of-file HTML comment block (template-author guidance,
# not customer-facing) — it spans from the opening `<!--` on line 1
# through the matching `-->`. Customers reading SECURITY.md should not
# see template plumbing.
rendered = re.sub(r"\A<!--.*?-->\n*", "", rendered, count=1, flags=re.DOTALL)

# Ensure trailing newline so re-running on the same inputs produces no
# diff (most editors append one when humans save the file).
if not rendered.endswith("\n"):
    rendered += "\n"

sys.stdout.write(rendered)
PY
)"
rc=$?
if [[ $rc -ne 0 ]]; then
    exit $rc
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
    if [[ ! -f "$OUTPUT" ]]; then
        req_lib_error "no committed ${OUTPUT} — run without --check to generate it"
        exit 1
    fi
    if diff -q <(printf '%s' "$rendered") "$OUTPUT" >/dev/null 2>&1; then
        req_lib_ok "✓ ${OUTPUT} is up-to-date with template + config"
        exit 0
    else
        req_lib_error "${OUTPUT} is OUT OF DATE — re-run without --check and commit"
        diff <(printf '%s' "$rendered") "$OUTPUT" | sed 's/^/      /' | head -40
        exit 1
    fi
fi

# Idempotency: only write if content changed.
if [[ -f "$OUTPUT" ]] && diff -q <(printf '%s' "$rendered") "$OUTPUT" >/dev/null 2>&1; then
    req_lib_ok "✓ ${OUTPUT} unchanged"
else
    printf '%s' "$rendered" > "$OUTPUT"
    req_lib_ok "✓ wrote ${OUTPUT} ($(wc -l < "$OUTPUT" | tr -d ' ') lines)"
fi
