#!/usr/bin/env python3
"""Issue a fresh least-privilege PAT after identity-lifecycle browser tests.

The V1 administrator-continuity acceptance deliberately disables and then
re-enables the release owner. Disabling an identity revokes every PAT from the
earlier security epoch, so later private-MCP checks must use a newly issued
credential. The one-time token is written to a fixed private file and is never
printed.
"""

from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any
from urllib.parse import urlparse
from urllib.request import HTTPCookieProcessor, HTTPSHandler, ProxyHandler, build_opener

from acceptance_network import RejectRedirectHandler, isolated_loopback_resolution
from prepare_release_runtime_acceptance import (
    AcceptanceSetupError,
    _api_data,
    _csrf,
    _normalise_base_url,
    _required_environment,
    _tls_context,
    _write_private_json,
)

ALLOWED_OUTPUT_NAMES = frozenset({
    "pat-read-refreshed.json",
    "pat-read-unified.json",
})


def _safe_inputs(
    repository_root: Path,
    credential_directory: Path,
    manifest_path: Path,
    output_path: Path,
) -> tuple[Path, Path, Path]:
    repository = repository_root.expanduser().resolve(strict=True)
    credentials_requested = credential_directory.expanduser().absolute()
    if credentials_requested.is_symlink():
        raise AcceptanceSetupError("credential directory must be a real directory")
    credentials = credentials_requested.resolve(strict=True)
    metadata = credentials.stat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AcceptanceSetupError("credential directory must have mode 0700")
    if metadata.st_uid != os.geteuid():
        raise AcceptanceSetupError("credential directory must be owned by the current user")
    if credentials == repository or repository in credentials.parents:
        raise AcceptanceSetupError("credential directory must stay outside the repository")

    manifest_requested = manifest_path.expanduser().absolute()
    output_requested = output_path.expanduser().absolute()
    if manifest_requested.parent != credentials_requested or output_requested.parent != credentials_requested:
        raise AcceptanceSetupError("manifest and refreshed token must be direct credential-directory children")
    if manifest_requested.is_symlink() or not manifest_requested.is_file():
        raise AcceptanceSetupError("release manifest must be a private regular file")
    manifest = manifest_requested.resolve(strict=True)
    manifest_metadata = manifest.stat()
    if (
        manifest.parent != credentials
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
        or manifest_metadata.st_uid != os.geteuid()
        or manifest_metadata.st_nlink != 1
    ):
        raise AcceptanceSetupError("release manifest must be an owned mode-0600 single-link file")
    if output_requested.exists() or output_requested.is_symlink():
        raise AcceptanceSetupError("refreshed token output must not already exist")
    if output_requested.name not in ALLOWED_OUTPUT_NAMES:
        raise AcceptanceSetupError("refreshed token output name is not an allowed fixed name")
    return credentials, manifest, output_requested


def _cookie_header(cookies: CookieJar) -> str:
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in cookies)


@isolated_loopback_resolution()
def refresh(args: argparse.Namespace) -> dict[str, str]:
    _, manifest_path, output_path = _safe_inputs(
        Path(args.repository_root),
        Path(args.credential_directory),
        Path(args.manifest),
        Path(args.output),
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_owner = str(manifest.get("ownerId", ""))
    if manifest.get("schemaVersion") != 1 or not expected_owner.isdigit():
        raise AcceptanceSetupError("release manifest does not identify the numeric owner")

    private_base_url = _normalise_base_url(
        "WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL", allow_http=True
    )
    public_base_url = _normalise_base_url(
        "WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL", allow_http=False
    )
    private_host = (urlparse(private_base_url).hostname or "").lower()
    if urlparse(private_base_url).scheme == "http" and not (
        private_host in {"localhost", "::1"} or private_host.startswith("127.")
    ):
        raise AcceptanceSetupError("an HTTP private acceptance ingress must be loopback-only")

    username = _required_environment("WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME")
    password = _required_environment("WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD")
    cookies = CookieJar()
    opener = build_opener(
        ProxyHandler({}),
        RejectRedirectHandler(),
        HTTPCookieProcessor(cookies),
        HTTPSHandler(context=_tls_context(public_base_url)),
    )
    csrf_header, csrf_token = _csrf(opener, public_base_url)
    caller = _api_data(
        opener,
        "POST",
        f"{public_base_url}/api/auth/login",
        {"username": username, "password": password},
        {csrf_header: csrf_token},
    )
    if not isinstance(caller, dict) or str(caller.get("subjectId", "")) != expected_owner:
        raise AcceptanceSetupError("refreshed PAT login did not resolve the release owner")
    cookie_header = _cookie_header(cookies)
    if "WEB_STARTER_SESSION=" not in cookie_header:
        raise AcceptanceSetupError("refreshed PAT login did not establish a production session")

    issued = _api_data(
        opener,
        "POST",
        f"{private_base_url}/api/security/personal-tokens",
        {
            "name": f"release-read-refreshed-{secrets.token_hex(6)}",
            "scopes": ["system:info", "project:list", "audit:list"],
            "allowedIpCidrs": [],
            "expiresAt": None,
        },
        {csrf_header: csrf_token, "Cookie": cookie_header},
    )
    if (
        not isinstance(issued, dict)
        or not str(issued.get("id", "")).isdigit()
        or not isinstance(issued.get("token"), str)
        or not issued["token"].startswith("wst_pat_")
    ):
        raise AcceptanceSetupError("refreshed PAT endpoint returned an invalid one-time credential")

    summaries = _api_data(
        opener,
        "GET",
        f"{private_base_url}/api/security/personal-tokens",
        headers={"Cookie": cookie_header},
    )
    if not isinstance(summaries, list) or any(
        not isinstance(summary, dict) or "token" in summary for summary in summaries
    ):
        raise AcceptanceSetupError("personal-token listing exposed an invalid or readable secret field")

    _write_private_json(output_path, {"token": issued["token"]})
    output_metadata = output_path.stat()
    if (
        stat.S_IMODE(output_metadata.st_mode) != 0o600
        or output_metadata.st_uid != os.geteuid()
        or output_metadata.st_nlink != 1
    ):
        raise AcceptanceSetupError("refreshed PAT output is not an owned mode-0600 single-link file")
    return {"ownerId": expected_owner, "credentialId": str(issued["id"])}


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--credential-directory", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        result = refresh(parse_arguments(sys.argv[1:] if argv is None else argv))
    except (AcceptanceSetupError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL release-runtime-read-token-refresh: {error}", file=sys.stderr)
        return 1
    print(
        "PASS release-runtime-read-token-refresh: "
        f"owner={result['ownerId']} credential={result['credentialId']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
