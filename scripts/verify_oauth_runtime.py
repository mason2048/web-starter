#!/usr/bin/env python3
"""Verify OAuth and MCP ingress boundaries against a disposable runtime stack."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import ssl
import sys
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from acceptance_network import (
    RejectRedirectHandler,
    is_isolated_acceptance_host,
    isolated_loopback_resolution,
    reject_tls_key_logging,
)


class OAuthRuntimeError(RuntimeError):
    """Raised for a failed protocol or ingress assertion."""


def _load_private_json(path: Path, label: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise OAuthRuntimeError(f"{label} must be a real regular file")
    if os.name == "posix" and resolved.stat().st_mode & 0o077:
        raise OAuthRuntimeError(f"{label} must be private (chmod 600)")
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OAuthRuntimeError(f"{label} is not valid JSON") from error
    if not isinstance(document, dict):
        raise OAuthRuntimeError(f"{label} must contain a JSON object")
    return document


def _context(public_url: str) -> ssl.SSLContext:
    try:
        reject_tls_key_logging()
    except ValueError as error:
        raise OAuthRuntimeError(str(error)) from error
    if os.environ.get("WEB_STARTER_ACCEPTANCE_INSECURE_TLS", "false").lower() != "true":
        return ssl.create_default_context()
    host = (urlparse(public_url).hostname or "").lower()
    try:
        isolated = is_isolated_acceptance_host(host)
    except ValueError as error:
        raise OAuthRuntimeError(str(error)) from error
    if not isolated:
        raise OAuthRuntimeError("insecure TLS is allowed only for loopback acceptance hosts")
    return ssl._create_unverified_context()  # noqa: SLF001 - self-signed acceptance certificate only


def _request(opener: Any, method: str, url: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    request = Request(url, data=body, headers=headers or {}, method=method)
    try:
        with opener.open(request, timeout=20) as response:
            return response.status, response.read(), dict(response.headers.items())
    except HTTPError as error:
        payload = error.read()
        return error.code, payload, dict(error.headers.items())


def _json(status: int, payload: bytes, label: str) -> dict[str, Any]:
    if status < 200 or status >= 300:
        raise OAuthRuntimeError(f"{label} returned HTTP {status}")
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as error:
        raise OAuthRuntimeError(f"{label} did not return JSON") from error
    if not isinstance(document, dict):
        raise OAuthRuntimeError(f"{label} did not return a JSON object")
    return document


def _bearer(document: dict[str, Any], label: str) -> str:
    token = document.get("token") or document.get("access_token")
    if not isinstance(token, str) or len(token) < 20:
        raise OAuthRuntimeError(f"{label} does not contain a bearer token")
    return token


def _pat_response_path(token_files: dict[str, Any]) -> Path:
    override = os.environ.get(
        "WEB_STARTER_OAUTH_ACCEPTANCE_PAT_RESPONSE_FILE", ""
    ).strip()
    configured = override or token_files.get("patRead", "")
    return Path(str(configured))


def _jwt_segment(token: str, index: int, label: str) -> dict[str, Any]:
    segments = token.split(".")
    if len(segments) != 3:
        raise OAuthRuntimeError("OAuth access token is not a compact JWT")
    try:
        encoded = segments[index] + "=" * (-len(segments[index]) % 4)
        header = json.loads(base64.urlsafe_b64decode(encoded))
    except (ValueError, json.JSONDecodeError) as error:
        raise OAuthRuntimeError(f"OAuth access token has invalid {label}") from error
    if not isinstance(header, dict):
        raise OAuthRuntimeError(f"OAuth access token {label} is not an object")
    return header


def _jwt_header(token: str) -> dict[str, Any]:
    return _jwt_segment(token, 0, "protected header")


def _jwt_claims(token: str) -> dict[str, Any]:
    return _jwt_segment(token, 1, "claims")


def _header(headers: dict[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _mcp_initialize(opener: Any, base_url: str, bearer: str,
                    trace_id: str, extra_headers: dict[str, str] | None = None
                    ) -> tuple[int, bytes, dict[str, str]]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "X-Trace-Id": trace_id,
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    headers.update(extra_headers or {})
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "release-oauth-runtime", "version": "1.0.0"},
        },
    }, separators=(",", ":")).encode()
    return _request(opener, "POST", f"{base_url}/mcp", payload, headers)


@isolated_loopback_resolution()
def verify(manifest_path: Path, report_path: Path) -> dict[str, Any]:
    manifest = _load_private_json(manifest_path, "runtime manifest")
    if manifest.get("schemaVersion") != 1:
        raise OAuthRuntimeError("runtime manifest uses an unsupported schema")
    private_url = str(manifest.get("privateMcpBaseUrl", "")).rstrip("/")
    public_url = str(manifest.get("publicBaseUrl", "")).rstrip("/")
    if urlparse(private_url).scheme not in {"http", "https"} or urlparse(public_url).scheme != "https":
        raise OAuthRuntimeError("runtime manifest contains invalid ingress URLs")
    token_files = manifest.get("tokenFiles")
    if not isinstance(token_files, dict):
        raise OAuthRuntimeError("runtime manifest is missing token-file references")
    signing_keys = manifest.get("oauthSigningKeys")
    if not isinstance(signing_keys, dict):
        raise OAuthRuntimeError("runtime manifest is missing OAuth signing-key references")
    active_kid = signing_keys.get("activeKid")
    retiring_kid = signing_keys.get("retiringKid")
    if not isinstance(active_kid, str) or not isinstance(retiring_kid, str) or active_kid == retiring_kid:
        raise OAuthRuntimeError("runtime manifest contains invalid OAuth signing-key references")
    client = _load_private_json(Path(str(token_files.get("oauthClient", ""))), "OAuth client file")
    pat = _bearer(
        _load_private_json(_pat_response_path(token_files), "PAT file"),
        "PAT file",
    )
    client_id = client.get("client_id")
    client_secret = client.get("client_secret")
    if not isinstance(client_id, str) or not isinstance(client_secret, str):
        raise OAuthRuntimeError("OAuth client file is missing client credentials")

    opener = build_opener(
        ProxyHandler({}),
        RejectRedirectHandler(),
        HTTPSHandler(context=_context(public_url)),
    )
    metadata_status, metadata_body, _ = _request(
        opener, "GET", f"{public_url}/.well-known/oauth-authorization-server",
        headers={"Accept": "application/json"},
    )
    metadata = _json(metadata_status, metadata_body, "authorization-server metadata")
    if metadata.get("issuer") != public_url:
        raise OAuthRuntimeError("authorization-server metadata issuer does not match the public ingress")
    if metadata.get("token_endpoint") != f"{public_url}/oauth2/token":
        raise OAuthRuntimeError("authorization-server metadata token endpoint is incorrect")
    if metadata.get("code_challenge_methods_supported") != ["S256"]:
        raise OAuthRuntimeError("authorization server does not advertise PKCE S256 exclusively")
    if "registration_endpoint" in metadata:
        raise OAuthRuntimeError("authorization-server metadata unexpectedly advertises dynamic registration")
    registration_payload = json.dumps({
        "client_name": "forbidden-dynamic-client",
        "redirect_uris": ["https://attacker.example.invalid/callback"],
    }, separators=(",", ":")).encode()
    for registration_path in ("/connect/register", "/oauth2/register"):
        registration_status, _, _ = _request(
            opener,
            "POST",
            public_url + registration_path,
            registration_payload,
            {"Accept": "application/json", "Content-Type": "application/json"},
        )
        if registration_status != 404:
            raise OAuthRuntimeError(
                f"dynamic client registration path {registration_path} returned HTTP {registration_status}"
            )
    jwks_uri = metadata.get("jwks_uri")
    if jwks_uri != f"{public_url}/oauth2/jwks":
        raise OAuthRuntimeError("authorization-server metadata JWKS URI is incorrect")
    jwks_status, jwks_body, _ = _request(
        opener, "GET", jwks_uri, headers={"Accept": "application/json"}
    )
    jwks = _json(jwks_status, jwks_body, "authorization-server JWKS")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not all(isinstance(key, dict) for key in keys):
        raise OAuthRuntimeError("authorization-server JWKS does not contain a key array")
    if {key.get("kid") for key in keys} != {active_kid, retiring_kid}:
        raise OAuthRuntimeError("authorization-server JWKS does not expose the expected active/retiring kids")
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    if any(key.get("kty") != "RSA" or private_fields.intersection(key) for key in keys):
        raise OAuthRuntimeError("authorization-server JWKS exposed an invalid or private key")

    protected_status, protected_body, _ = _request(
        opener, "GET", f"{public_url}/.well-known/oauth-protected-resource/mcp",
        headers={"Accept": "application/json"},
    )
    protected = _json(protected_status, protected_body, "protected-resource metadata")
    if (
        protected.get("resource") != f"{public_url}/mcp"
        or protected.get("authorization_servers") != [public_url]
        or protected.get("bearer_methods_supported") != ["header"]
    ):
        raise OAuthRuntimeError("protected-resource metadata does not bind the public MCP URL")

    encoded = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    token_body = urlencode({
        "grant_type": "client_credentials",
        "scope": "system:info project:list audit:list",
    }).encode()
    token_status, token_payload, _ = _request(
        opener,
        "POST",
        f"{public_url}/oauth2/token",
        token_body,
        {
            "Accept": "application/json",
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    token_response = _json(token_status, token_payload, "client-credentials token endpoint")
    oauth_bearer = _bearer(token_response, "client-credentials response")
    if _jwt_header(oauth_bearer).get("kid") != active_kid:
        raise OAuthRuntimeError("new OAuth access token was not signed with the active kid")
    claims = _jwt_claims(oauth_bearer)
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if claims.get("iss") != public_url or audiences != [f"{public_url}/mcp"]:
        raise OAuthRuntimeError("OAuth access token issuer or audience differs from metadata")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    expires_in = token_response.get("expires_in")
    if (
        isinstance(issued_at, bool) or not isinstance(issued_at, int)
        or isinstance(expires_at, bool) or not isinstance(expires_at, int)
        or isinstance(expires_in, bool) or not isinstance(expires_in, int)
        or not 0 < expires_in <= 3600
        or expires_at - issued_at != expires_in
    ):
        raise OAuthRuntimeError("Client Credentials token is not a consistent short-lived credential")

    oauth_status, oauth_payload, _ = _mcp_initialize(
        opener, public_url, oauth_bearer, "release-oauth-public-initialize"
    )
    if oauth_status != 200 or b"2025-11-25" not in oauth_payload:
        raise OAuthRuntimeError("OAuth access token did not initialize MCP through the public ingress")
    private_status, private_payload, _ = _mcp_initialize(
        opener, private_url, pat, "release-pat-private-initialize"
    )
    if private_status != 200 or b"2025-11-25" not in private_payload:
        raise OAuthRuntimeError("PAT did not initialize MCP through the private ingress")
    public_pat_status, _, _ = _mcp_initialize(
        opener, public_url, pat, "release-pat-public-rejected"
    )
    if public_pat_status != 401:
        raise OAuthRuntimeError(f"public ingress accepted a PAT (HTTP {public_pat_status})")
    invalid_origin_status, _, _ = _mcp_initialize(
        opener,
        public_url,
        oauth_bearer,
        "release-invalid-origin-rejected",
        {"Origin": "https://invalid-origin.example.invalid"},
    )
    if invalid_origin_status != 403:
        raise OAuthRuntimeError(f"public ingress did not reject an invalid Origin (HTTP {invalid_origin_status})")

    unauthenticated_status, unauthenticated_body, unauthenticated_headers = _mcp_initialize(
        opener, public_url, "", "release-www-authenticate"
    )
    expected_challenge = (
        f'Bearer resource_metadata="{public_url}/.well-known/oauth-protected-resource/mcp"'
    )
    if (
        unauthenticated_status != 401
        or _header(unauthenticated_headers, "WWW-Authenticate") != expected_challenge
        or json.loads(unauthenticated_body).get("error") != "unauthorized"
    ):
        raise OAuthRuntimeError("MCP authentication challenge differs from protected-resource metadata")

    public_api_status, _, _ = _request(
        opener,
        "GET",
        f"{public_url}/api/projects",
        headers={"Accept": "application/json", "Authorization": f"Bearer {oauth_bearer}"},
    )
    if public_api_status != 404:
        raise OAuthRuntimeError(f"public ingress exposed a private management API (HTTP {public_api_status})")
    for operations_path in (
            "/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness",
            "/actuator/info", "/actuator/metrics", "/actuator/prometheus",
            "/health", "/info", "/metrics", "/prometheus"):
        operations_status, _, _ = _request(
            opener, "GET", f"{public_url}{operations_path}",
            headers={"Accept": "application/json"},
        )
        if operations_status != 404:
            raise OAuthRuntimeError(
                f"public ingress exposed an operations endpoint at {operations_path} "
                f"(HTTP {operations_status})"
            )

    report = {
        "schemaVersion": 1,
        "status": "PASS",
        "checks": {
            "metadata": "PASS",
            "multiKeyJwks": "PASS",
            "activeSigningKid": "PASS",
            "oauthMetadataConsistency": "PASS",
            "dynamicClientRegistrationDisabled": "PASS",
            "wwwAuthenticate": "PASS",
            "clientCredentials": "PASS",
            "clientCredentialsShortLived": "PASS",
            "oauthPublicMcp": "PASS",
            "patPrivateMcp": "PASS",
            "patPublicRejected": "PASS",
            "invalidOriginRejected": "PASS",
            "publicManagementApiHidden": "PASS",
            "publicOperationsEndpointsHidden": "PASS",
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(os.environ.get("WEB_STARTER_OAUTH_ACCEPTANCE_MANIFEST", "")),
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/oauth-runtime.json"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        verify(args.manifest, args.output)
    except (OAuthRuntimeError, OSError, ValueError) as error:
        print(f"FAIL oauth-runtime: {error}", file=sys.stderr)
        return 1
    print("PASS oauth-runtime: metadata, client credentials, ingress token boundary and MCP initialization")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
