#!/usr/bin/env bash
# _acquire-oidc-token.sh — single-shot OIDC device-flow against
# Sigstore's oauth2 proxy (oauth2.sigstore.dev).
#
# Outputs the resulting id_token to stdout; the user-facing
# prompt (verification URL + code) goes to stderr so callers can
# capture the token cleanly with `tok=$(_acquire-oidc-token.sh)`.
#
# Use case: publish.zsh's Phase 3 signs three artefacts in a row.
# Without this script, each `cosign sign-blob` triggers its own
# device-flow prompt — three OAuth round-trips per release. Setting
# `SIGSTORE_ID_TOKEN` to the token returned here lets cosign skip
# its own OIDC dance, so a single device-flow approval covers all
# signatures in the same release.
#
# Endpoints are discovered via OIDC well-known config rather than
# hard-coded so a future Sigstore endpoint change doesn't break us
# silently.
#
# Tooling: requires `uv` on PATH. Stdlib-only Python (urllib, json, time).

set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is not on PATH" >&2
    exit 2
fi

uv run --no-project --quiet --python ">=3.11" python - <<'PY'
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = "https://oauth2.sigstore.dev/auth"
CLIENT_ID = "sigstore"
SCOPE = "openid email"


def http_post_form(url, data):
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(data).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    return urllib.request.urlopen(req)


def main():
    # Discover endpoints via OIDC well-known config — robust against
    # future Sigstore endpoint reshuffles.
    well_known = json.loads(
        urllib.request.urlopen(
            f"{ISSUER}/.well-known/openid-configuration"
        ).read()
    )
    device_auth_endpoint = well_known["device_authorization_endpoint"]
    token_endpoint = well_known["token_endpoint"]

    # PKCE (S256) — Sigstore's oauth2 proxy requires this on the
    # device-authorization flow. RFC 7636: code_verifier is a
    # high-entropy random string; code_challenge is base64url-no-pad
    # of sha256(code_verifier).
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )

    # Step 1: request a device code (with PKCE challenge).
    resp = json.loads(
        http_post_form(
            device_auth_endpoint,
            {
                "client_id": CLIENT_ID,
                "scope": SCOPE,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        ).read()
    )

    # Step 2: prompt the user (stderr — keeps stdout clean for the
    # token capture by the caller).
    sys.stderr.write("\n")
    sys.stderr.write(
        f"  Sign in at: {resp['verification_uri_complete']}\n"
    )
    sys.stderr.write(
        f"    (or visit {resp['verification_uri']} and enter {resp['user_code']})\n"
    )
    sys.stderr.write(
        f"  Code valid for {resp.get('expires_in', 600)} seconds\n"
    )
    sys.stderr.flush()

    # Step 3: poll the token endpoint until the user approves
    # (or the device code expires).
    interval = int(resp.get("interval", 5))
    deadline = time.time() + int(resp.get("expires_in", 600))

    while time.time() < deadline:
        time.sleep(interval)
        try:
            token_resp = json.loads(
                http_post_form(
                    token_endpoint,
                    {
                        "client_id": CLIENT_ID,
                        "device_code": resp["device_code"],
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "code_verifier": code_verifier,
                    },
                ).read()
            )
        except urllib.error.HTTPError as exc:
            err = {}
            try:
                err = json.loads(exc.read())
            except Exception:
                pass
            error = err.get("error", "")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            sys.stderr.write(
                f"  Error from token endpoint: {error or exc.code} — {err}\n"
            )
            sys.exit(1)

        id_token = token_resp.get("id_token")
        if not id_token:
            sys.stderr.write(
                f"  Token response had no id_token: {token_resp}\n"
            )
            sys.exit(1)

        # Step 4: emit the token to stdout (caller captures into
        # SIGSTORE_ID_TOKEN).
        sys.stdout.write(id_token)
        sys.stderr.write("  Token received.\n")
        return

    sys.stderr.write("  Device code expired without authorisation.\n")
    sys.exit(1)


main()
PY
