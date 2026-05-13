"""
Release verification — Sigstore signature check for OpenSecOps components.

Distributed by Installer/refresh to every converted component so that
both init.py (Installer-side, eager check at clone/pull time) and deploy.py
(component-side, just-in-time check before sam build / cfn deploy) share
the same trust-anchor + verifier logic.

A single point of truth for:
  - the OIDC identity that must have signed every released artefact;
  - the org under which signed releases are published;
  - the STRICT_VERIFICATION knob (flipped to True after Phase 10 closes);
  - the verifier function itself.

To rotate the trust anchor, update both EXPECTED_SIGNER_IDENTITY and
EXPECTED_SIGNER_ISSUER in this file and ship an Installer release.
Refresh will redistribute the change to every component.
"""

import json
import os
import subprocess
import tempfile
import urllib.request
import urllib.error


# --- Trust anchor ---------------------------------------------------------

EXPECTED_SIGNER_IDENTITY = "peter@peterbengtson.com"
EXPECTED_SIGNER_ISSUER = "https://github.com/login/oauth"
PUBLIC_ORG = "OpenSecOps-Org"

# Phase 10 closed on 2026-05-13: every repo in apps/foundation/repos.toml
# and apps/soar/repos.toml ships signed releases. Strict mode is now the
# steady-state: a release without signed bundles is a downgrade signal,
# not a "not yet signed" state.
STRICT_VERIFICATION = True


# --- Colours (no-op when not a TTY; matches deploy.py's palette) ----------

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
LIGHT_BLUE = "\033[94m"
BOLD = "\033[1m"
END = "\033[0m"


def _printc(colour, msg):
    print(f"{colour}{msg}{END}", flush=True)


# --- Verifier -------------------------------------------------------------

def verify_release(repo_name, repo_dir=".", unsafe_untagged=False):
    """
    Verify that the source tree at `repo_dir` corresponds to a Sigstore-signed
    GitHub Release of `repo_name` (under PUBLIC_ORG on GitHub) published by
    EXPECTED_SIGNER_IDENTITY via EXPECTED_SIGNER_ISSUER.

    Returns True on success or acceptable skip; False on hard failure.
    All status is printed; the caller decides what to do with False.
    """
    # 1. Resolve HEAD (of repo_dir) to a release tag.
    res = subprocess.run(
        ['git', '-C', repo_dir, 'describe', '--tags', '--exact-match', 'HEAD'],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        commit = subprocess.run(
            ['git', '-C', repo_dir, 'rev-parse', '--short', 'HEAD'],
            capture_output=True, text=True,
        ).stdout.strip()
        user = os.environ.get('USER', '?')
        if unsafe_untagged:
            _printc(RED + BOLD,
                f"OVERRIDE: deploying {repo_name} at untagged commit {commit} by {user}")
            return True
        _printc(RED, f"{repo_name}: HEAD ({commit}) is not on a release tag.")
        _printc(RED, "  Pass --unsafe-untagged to proceed anyway.")
        return False
    tag = res.stdout.strip()

    # 1a. Note whether the local checkout claims to be converted.
    #     `.security-config.toml` at the repo root is the canonical
    #     "this repo has formally adopted the supply-chain framework"
    #     marker. A converted repo MUST have signed release bundles;
    #     missing bundles for a converted repo is a downgrade signal,
    #     not a "not yet signed" state.
    repo_is_converted = os.path.exists(os.path.join(repo_dir, '.security-config.toml'))

    # 2. Look up the GitHub Release for that tag.
    api_url = f"https://api.github.com/repos/{PUBLIC_ORG}/{repo_name}/releases/tags/{tag}"
    try:
        with urllib.request.urlopen(api_url) as resp:
            release = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            if repo_is_converted:
                _printc(RED,
                    f"{repo_name} {tag}: this repo has `.security-config.toml` "
                    f"(declares itself converted) but no GitHub Release exists "
                    f"for the tag. This is a downgrade signal — refusing to "
                    f"proceed.")
                return False
            _printc(YELLOW,
                f"{repo_name} {tag}: verification is skipped for now as the repo "
                f"has not yet been signed. This is a work in progress; we will "
                f"complete it in a day or two, no more.")
            if STRICT_VERIFICATION:
                _printc(RED, "  STRICT_VERIFICATION is on — refusing to proceed.")
                return False
            return True
        raise

    # 3. Find the .bundle assets.
    bundles = [a for a in release['assets'] if a['name'].endswith('.bundle')]
    if not bundles:
        if repo_is_converted:
            _printc(RED,
                f"{repo_name} {tag}: release exists but has no signed bundles, "
                f"and this repo has `.security-config.toml` (declares itself "
                f"converted). Possible downgrade attack (bundles stripped from "
                f"the release after signing) — refusing to proceed.")
            return False
        _printc(YELLOW,
            f"{repo_name} {tag}: verification is skipped for now as the repo "
            f"has not yet been signed. This is a work in progress; we will "
            f"complete it in a day or two, no more.")
        if STRICT_VERIFICATION:
            _printc(RED, "  STRICT_VERIFICATION is on — refusing to proceed.")
            return False
        return True

    # 4. Verify every bundle against its artefact.
    _printc(LIGHT_BLUE,
        f"Verifying release artefacts for {repo_name} {tag} "
        f"({len(bundles)} signed asset(s); signer must be "
        f"{EXPECTED_SIGNER_IDENTITY} via {EXPECTED_SIGNER_ISSUER})...")

    try:
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
        from sigstore.models import Bundle
    except ImportError:
        _printc(RED, "  ✗ sigstore Python package not installed.")
        _printc(RED, "    Run ./init from the Installer to install it.")
        return False

    verifier = Verifier.production()
    policy = Identity(
        identity=EXPECTED_SIGNER_IDENTITY,
        issuer=EXPECTED_SIGNER_ISSUER,
    )
    assets_by_name = {a['name']: a for a in release['assets']}

    with tempfile.TemporaryDirectory() as td:
        for bundle_asset in bundles:
            bundle_name = bundle_asset['name']
            artifact_name = bundle_name[: -len('.bundle')]
            if artifact_name not in assets_by_name:
                _printc(RED,
                    f"  ✗ bundle {bundle_name} has no matching artefact on the release")
                return False
            artifact_asset = assets_by_name[artifact_name]

            artifact_path = os.path.join(td, artifact_name)
            bundle_path = os.path.join(td, bundle_name)
            urllib.request.urlretrieve(artifact_asset['browser_download_url'], artifact_path)
            urllib.request.urlretrieve(bundle_asset['browser_download_url'], bundle_path)

            with open(bundle_path, 'rb') as f:
                bundle = Bundle.from_json(f.read())
            with open(artifact_path, 'rb') as f:
                artifact_bytes = f.read()

            try:
                verifier.verify_artifact(input_=artifact_bytes, bundle=bundle, policy=policy)
                _printc(GREEN, f"  ✓ verified {artifact_name}")
            except Exception as e:
                _printc(RED, f"  ✗ verification FAILED for {artifact_name}: {e}")
                return False

    _printc(GREEN + BOLD,
        f"{repo_name} {tag}: all release artefacts verified against {EXPECTED_SIGNER_IDENTITY}")
    return True
