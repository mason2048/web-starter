#!/usr/bin/env python3
"""Exercise V2 identity and credential lifecycle against a real release stack.

The report contains only statuses, hashes, opaque identifiers and timestamps.
Raw passwords, PATs, OAuth tokens, client secrets and pepper material remain in
memory and are never written to the report or printed.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import time
from typing import Any, Iterator, Mapping
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPCookieProcessor, HTTPSHandler, ProxyHandler, Request, build_opener

from acceptance_network import RejectRedirectHandler, isolated_loopback_resolution, reject_tls_key_logging


TRACE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
OPAQUE_ID = re.compile(r"^[1-9][0-9]*$")
ADMIN_ROLE_ID = "1"
MAX_HTTP = 4 * 1024 * 1024
MAX_DB_DUMP = 32 * 1024 * 1024
FORBIDDEN_ERROR_FIELD = re.compile(
    rb'"(?:password|authorization|cookie|access_token|refresh_token|client_secret|requestBody|responseBody)"\s*:',
    re.IGNORECASE,
)
SENSITIVE_LOG_HEADER = re.compile(
    rb'\b(?:authorization|cookie)\s*[:=]\s*(?:bearer|basic|wst_|eyJ|WEB_STARTER_SESSION=)',
    re.IGNORECASE,
)


class LifecycleError(RuntimeError):
    """Raised when the real runtime differs from the frozen acceptance contract."""


def _require_checks(label: str, checks: Mapping[str, bool]) -> None:
    failed = sorted(name for name, passed in checks.items() if passed is not True)
    if failed:
        raise LifecycleError(f"{label}: {','.join(failed)}")


def _is_opaque_id(value: Any) -> bool:
    return isinstance(value, str) and OPAQUE_ID.fullmatch(value) is not None


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _assert_redacted_error(payload: bytes, sensitive_values: list[str], label: str) -> None:
    if FORBIDDEN_ERROR_FIELD.search(payload):
        raise LifecycleError(f"{label} exposed a forbidden credential field")
    for value in sensitive_values:
        if value and value.encode() in payload:
            raise LifecycleError(f"{label} exposed credential material")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_file(path: Path, label: str, maximum: int = MAX_HTTP) -> bytes:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise LifecycleError(f"{label} must be a real regular file")
    metadata = requested.stat()
    if (
        metadata.st_size <= 0
        or metadata.st_size > maximum
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise LifecycleError(f"{label} must be an owned mode-0600 bounded file")
    return requested.read_bytes()


def _private_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_private_file(path, label).decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain one JSON object")
    return value


def _replace_private_json(path: Path, document: Mapping[str, Any], label: str) -> None:
    """Atomically refresh an existing private acceptance credential file."""
    target = path.expanduser().absolute()
    if target.is_symlink() or not target.is_file():
        raise LifecycleError(f"{label} must be an existing real regular file")
    parent = target.parent
    parent_metadata = parent.stat()
    target_metadata = target.stat()
    if (
        parent.is_symlink()
        or not parent.is_dir()
        or (os.name == "posix" and stat.S_IMODE(parent_metadata.st_mode) != 0o700)
        or (hasattr(os, "getuid") and parent_metadata.st_uid != os.getuid())
        or (os.name == "posix" and stat.S_IMODE(target_metadata.st_mode) != 0o600)
        or (hasattr(os, "getuid") and target_metadata.st_uid != os.getuid())
        or target_metadata.st_nlink != 1
    ):
        raise LifecycleError(f"{label} must be an owned private file in an owned mode-0700 directory")
    payload = (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) <= 2 or len(payload) > MAX_HTTP:
        raise LifecycleError(f"{label} replacement payload is invalid")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(parent, directory_flags)
    temporary_name = f".{target.name}.{secrets.token_hex(12)}.tmp"
    created = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        created = True
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise LifecycleError(f"{label} replacement write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary_name, target.name, src_dir_fd=directory, dst_dir_fd=directory)
        created = False
        os.fsync(directory)
    except BaseException:
        if created:
            try:
                os.unlink(temporary_name, dir_fd=directory)
            except OSError:
                pass
        raise
    finally:
        os.close(directory)

    if _private_json(target, label) != dict(document):
        raise LifecycleError(f"{label} replacement could not be verified")


def _environment(path: Path) -> dict[str, str]:
    content = _private_file(path, "release runtime environment", 1024 * 1024)
    values: dict[str, str] = {}
    for raw_line in content.decode("utf-8", errors="strict").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        name, separator, value = raw_line.partition("=")
        if separator != "=" or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", name):
            raise LifecycleError("release runtime environment contains an invalid assignment")
        if name in values or any(character in value for character in "\r\n\0"):
            raise LifecycleError("release runtime environment contains an unsafe assignment")
        values[name] = value
    return values


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "")
    if not value:
        raise LifecycleError(f"release runtime environment is missing {name}")
    return value


def _tls_context(public_origin: str) -> ssl.SSLContext:
    reject_tls_key_logging()
    if os.environ.get("WEB_STARTER_ACCEPTANCE_INSECURE_TLS", "false").lower() != "true":
        return ssl.create_default_context()
    host = (urlparse(public_origin).hostname or "").lower()
    if not (host.endswith(".webstarter.test") or host in {"localhost", "127.0.0.1", "::1"}):
        raise LifecycleError("insecure TLS is restricted to the isolated acceptance host")
    return ssl._create_unverified_context()  # noqa: SLF001 - isolated self-signed acceptance TLS


def _request(
    opener: Any,
    method: str,
    url: str,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    request = Request(url, data=body, headers=dict(headers or {}), method=method)
    try:
        with opener.open(request, timeout=20) as response:
            payload = response.read(MAX_HTTP + 1)
            if len(payload) > MAX_HTTP:
                raise LifecycleError("runtime HTTP response exceeds the acceptance limit")
            return response.status, payload, {key.lower(): value for key, value in response.headers.items()}
    except HTTPError as error:
        payload = error.read(MAX_HTTP + 1)
        if len(payload) > MAX_HTTP:
            raise LifecycleError("runtime HTTP error response exceeds the acceptance limit")
        return error.code, payload, {key.lower(): value for key, value in error.headers.items()}


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise LifecycleError(f"{label} did not return JSON") from error
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} did not return a JSON object")
    return value


def _api_data(
    client: "WebClient",
    method: str,
    path: str,
    payload: Any | None = None,
    trace_id: str | None = None,
) -> Any:
    status, body, _ = client.request(method, path, payload, trace_id)
    document = _json(body, f"{method} {path}")
    if status < 200 or status >= 300 or document.get("code") not in {0, 200}:
        raise LifecycleError(f"{method} {path} returned HTTP {status}")
    return document.get("data")


class WebClient:
    def __init__(self, private_origin: str, public_origin: str, username: str, password: str):
        self.private_origin = private_origin.rstrip("/")
        self.public_origin = public_origin.rstrip("/")
        self.cookies = CookieJar()
        self.opener = build_opener(
            ProxyHandler({}),
            RejectRedirectHandler(),
            HTTPCookieProcessor(self.cookies),
            HTTPSHandler(context=_tls_context(self.public_origin)),
        )
        self.csrf_header, self.csrf_token = self._csrf()
        status, body, _ = self._request_origin(
            "POST",
            self.public_origin + "/api/auth/login",
            json.dumps({"username": username, "password": password}, separators=(",", ":")).encode(),
            {"Accept": "application/json", "Content-Type": "application/json", self.csrf_header: self.csrf_token},
        )
        document = _json(body, "runtime login")
        if status != 200 or document.get("code") not in {0, 200}:
            raise LifecycleError("runtime login failed")
        self.subject_id = str((document.get("data") or {}).get("subjectId", ""))
        self.cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in self.cookies)
        if not self.subject_id.isdigit() or "WEB_STARTER_SESSION=" not in self.cookie_header:
            raise LifecycleError("runtime login did not establish a valid caller and Session")

    def _csrf(self) -> tuple[str, str]:
        status, body, _ = self._request_origin(
            "GET", self.public_origin + "/api/auth/csrf", None, {"Accept": "application/json"}
        )
        document = _json(body, "CSRF endpoint")
        data = document.get("data")
        if status != 200 or not isinstance(data, dict) or not isinstance(data.get("token"), str):
            raise LifecycleError("CSRF endpoint returned an invalid token")
        return str(data.get("headerName") or "X-XSRF-TOKEN"), data["token"]

    def _request_origin(
        self, method: str, url: str, body: bytes | None, headers: Mapping[str, str]
    ) -> tuple[int, bytes, dict[str, str]]:
        return _request(self.opener, method, url, body, headers)

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        trace_id: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "Cookie": self.cookie_header}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if method not in {"GET", "HEAD", "OPTIONS"}:
            headers[self.csrf_header] = self.csrf_token
        if trace_id is not None:
            if TRACE.fullmatch(trace_id) is None:
                raise LifecycleError("runtime trace ID is invalid")
            headers["X-Trace-Id"] = trace_id
        return self._request_origin(method, self.private_origin + path, body, headers)


def _token_request(
    opener: Any,
    public_origin: str,
    parameters: Mapping[str, str],
    client_id: str | None = None,
    client_secret: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    encoded = ""
    if client_id is not None and client_secret is not None:
        encoded = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers["Authorization"] = "Basic " + encoded
    status, payload, _ = _request(
        opener, "POST", public_origin.rstrip("/") + "/oauth2/token",
        urlencode(parameters).encode(), headers,
    )
    document = _json(payload, "OAuth token endpoint")
    if status >= 400:
        secret_parameters = [
            value for name, value in parameters.items()
            if name in {"refresh_token", "code", "code_verifier"}
        ]
        _assert_redacted_error(
            payload,
            [client_secret or "", encoded, *secret_parameters],
            "OAuth error response",
        )
    return status, document


def _authorization_code_tokens(
    user: WebClient,
    client_id: str,
    redirect_uri: str,
) -> dict[str, Any]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_hex(16)
    query = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "system:info project:list",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    status, _, headers = _request(
        user.opener, "GET", user.public_origin + "/oauth2/authorize?" + query,
        headers={"Accept": "text/html"},
    )
    location = headers.get("location", "")
    parsed = urlparse(location)
    values = parse_qs(parsed.query, strict_parsing=True)
    if status not in {302, 303} or parsed.scheme + "://" + parsed.netloc + parsed.path != redirect_uri:
        raise LifecycleError("authorization-code flow did not redirect to the exact registered URI")
    if values.get("state") != [state] or len(values.get("code", [])) != 1:
        raise LifecycleError("authorization-code redirect did not preserve state and one code")
    token_status, token = _token_request(
        user.opener,
        user.public_origin,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": values["code"][0],
            "code_verifier": verifier,
        },
    )
    access = token.get("access_token")
    refresh = token.get("refresh_token")
    token_type = token.get("token_type")
    expires_in = token.get("expires_in")
    if (
        token_status != 200
        or not isinstance(access, str)
        or not isinstance(refresh, str)
        or not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or not 0 < expires_in <= 3600
    ):
        raise LifecycleError("authorization-code exchange did not issue access and refresh tokens")
    return {"access": access, "refresh": refresh, "expiresIn": expires_in}


def _rpc_document(payload: bytes, expected_id: int) -> dict[str, Any]:
    stripped = payload.strip()
    candidates = [stripped] if stripped.startswith(b"{") else [
        line[5:].strip() for line in payload.splitlines() if line.startswith(b"data:")
    ]
    for candidate in reversed(candidates):
        try:
            document = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(document, dict) and document.get("id") == expected_id:
            return document
    raise LifecycleError("MCP response did not contain the expected JSON-RPC result")


def _mcp_headers(token: str, trace_id: str, session_id: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "X-Trace-Id": trace_id,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return headers


def _close_mcp_session(
        opener: Any,
        origin: str,
        token: str,
        trace_id: str,
        session_id: str) -> None:
    status, payload, _ = _request(
        opener,
        "DELETE",
        origin.rstrip("/") + "/mcp",
        None,
        _mcp_headers(token, trace_id + "-close", session_id),
    )
    if status not in {200, 202, 204} or payload.strip():
        raise LifecycleError("credential-lifecycle MCP session could not be closed cleanly")


def _mcp_initialize(opener: Any, origin: str, token: str, trace_id: str,
                    extra_headers: Mapping[str, str] | None = None) -> int:
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "credential-lifecycle", "version": "1.0.0"}},
    }, separators=(",", ":")).encode()
    headers = _mcp_headers(token, trace_id)
    headers.update(extra_headers or {})
    status, payload, response_headers = _request(
        opener, "POST", origin.rstrip("/") + "/mcp", body, headers
    )
    if status >= 400:
        _assert_redacted_error(payload, [token], "MCP initialization error response")
    elif status == 200:
        session_id = response_headers.get("mcp-session-id", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{8,256}", session_id):
            raise LifecycleError("credential-lifecycle MCP initialization did not establish a Session")
        _close_mcp_session(opener, origin, token, trace_id, session_id)
    return status


def _mcp_tool_error(opener: Any, origin: str, token: str, trace_id: str,
                    tool_name: str, arguments: Mapping[str, Any]) -> str:
    initialize = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "security-negative", "version": "1.0.0"}},
    }, separators=(",", ":")).encode()
    status, payload, headers = _request(
        opener, "POST", origin.rstrip("/") + "/mcp", initialize,
        _mcp_headers(token, trace_id + "-init"),
    )
    if status != 200 or _rpc_document(payload, 1).get("result") is None:
        raise LifecycleError("security-negative credential could not initialize MCP")
    session_id = headers.get("mcp-session-id", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,256}", session_id):
        raise LifecycleError("security-negative MCP initialization did not establish a Session")
    try:
        ready = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        ready_status, ready_payload, _ = _request(
            opener, "POST", origin.rstrip("/") + "/mcp", ready,
            _mcp_headers(token, trace_id + "-ready", session_id),
        )
        if ready_status not in {200, 202, 204} or ready_payload.strip():
            raise LifecycleError("security-negative initialized notification failed")
        call = json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool_name, "arguments": dict(arguments)},
        }, separators=(",", ":")).encode()
        call_status, call_payload, _ = _request(
            opener, "POST", origin.rstrip("/") + "/mcp", call,
            _mcp_headers(token, trace_id, session_id),
        )
        _assert_redacted_error(call_payload, [token], "MCP Tool error response")
        result = _rpc_document(call_payload, 2).get("result")
        if call_status != 200 or not isinstance(result, dict) or result.get("isError") is not True:
            raise LifecycleError("security-negative MCP tool call was not rejected")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict) or not isinstance(structured.get("code"), str):
            raise LifecycleError("security-negative MCP tool error lacks a stable code")
        return structured["code"]
    finally:
        _close_mcp_session(opener, origin, token, trace_id, session_id)


class ComposeDatabase:
    def __init__(self, compose_file: Path, override_file: Path, env_file: Path, project: str):
        if COMPOSE_PROJECT.fullmatch(project) is None:
            raise LifecycleError("Compose project name is invalid")
        self.prefix = [
            "docker", "compose", "--env-file", str(env_file), "-f", str(compose_file),
            "-f", str(override_file), "-p", project,
        ]

    def _run(self, tool: str, sql: str | None = None, maximum: int = MAX_DB_DUMP) -> bytes:
        if tool == "mysql":
            tail = [
                "exec", "-T", "mysql", "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --batch --skip-column-names --raw '
                '-u"$MYSQL_USER" "$MYSQL_DATABASE"',
            ]
        elif tool == "mysqldump":
            tail = [
                "exec", "-T", "mysql", "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_PASSWORD" exec mysqldump --no-create-info --skip-comments '
                '--compact -u"$MYSQL_USER" "$MYSQL_DATABASE"',
            ]
        else:
            raise LifecycleError("unknown database acceptance tool")
        completed = subprocess.run(
            self.prefix + tail, input=None if sql is None else sql.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
        )
        if completed.returncode != 0 or len(completed.stdout) > maximum or len(completed.stderr) > 4096:
            raise LifecycleError(f"real MySQL {tool} acceptance command failed safely")
        return completed.stdout

    def execute(self, sql: str) -> None:
        if self._run("mysql", sql).strip():
            raise LifecycleError("real MySQL mutation unexpectedly returned rows")

    def scalar(self, sql: str) -> str:
        rows = self._run("mysql", sql).decode("utf-8", errors="strict").splitlines()
        if len(rows) != 1 or "\t" in rows[0]:
            raise LifecycleError("real MySQL scalar query did not return one safe value")
        return rows[0]

    def dump(self) -> bytes:
        return self._run("mysqldump", maximum=MAX_DB_DUMP)


def _sql_literal(value: str) -> str:
    if "\0" in value:
        raise LifecycleError("SQL fixture contains a NUL byte")
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _audit_present(admin: WebClient, trace_id: str, expected_resource: str) -> bool:
    data = _api_data(admin, "GET", "/api/logs/operation?" + urlencode({
        "page": 1, "size": 20, "traceId": trace_id,
    }))
    records = data.get("records") if isinstance(data, dict) else None
    return isinstance(records, list) and any(
        isinstance(record, dict)
        and record.get("traceId") == trace_id
        and record.get("result") == "SUCCESS"
        and record.get("resourceType") == expected_resource
        for record in records
    )


def _operation_audits_present(
        admin: WebClient,
        expectations: tuple[tuple[str, str], ...]) -> bool:
    return all(
        _audit_present(admin, trace_id, expected_resource)
        for trace_id, expected_resource in expectations
    )


def _mcp_failure_audit_present(admin: WebClient, trace_id: str, expected_code: str) -> bool:
    data = _api_data(admin, "GET", "/api/logs/mcp?" + urlencode({
        "page": 1, "size": 20, "traceId": trace_id,
    }))
    records = data.get("records") if isinstance(data, dict) else None
    return isinstance(records, list) and any(
        isinstance(record, dict)
        and record.get("traceId") == trace_id
        and record.get("result") == "FAILED"
        and record.get("errorCode") == expected_code
        for record in records
    )


def _create_user(admin: WebClient, suffix: str) -> tuple[dict[str, Any], str, str]:
    username = "lifecycle_" + suffix.lower()
    password = "V2!" + secrets.token_urlsafe(36)
    user = _api_data(admin, "POST", "/api/users", {
        "username": username, "displayName": "凭据生命周期验收用户",
        "password": password, "status": "ENABLED", "roleIds": [ADMIN_ROLE_ID],
    })
    if not isinstance(user, dict) or not str(user.get("id", "")).isdigit():
        raise LifecycleError("lifecycle user creation returned an invalid identity")
    return user, username, password


def _remove_lifecycle_user(
    admin: WebClient,
    user_id: str,
    action_trace: str,
    already_removed: bool,
) -> tuple[str, int]:
    cleanup_trace = action_trace if already_removed else action_trace + "-cleanup"
    path = f"/api/users/{user_id}"
    if not already_removed:
        _api_data(admin, "DELETE", path, trace_id=cleanup_trace)
    status, _, _ = admin.request("GET", path)
    if status != 404:
        raise LifecycleError("lifecycle user fixture remained visible after cleanup")
    if not _audit_present(admin, cleanup_trace, "user"):
        raise LifecycleError("lifecycle user fixture cleanup lacks a correlated audit")
    return cleanup_trace, status


def _issue_pat(
    client: WebClient,
    name: str,
    scopes: list[str],
    allowed_ip_cidrs: list[str] | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    result = _api_data(client, "POST", "/api/security/personal-tokens", {
        "name": name, "scopes": scopes, "allowedIpCidrs": allowed_ip_cidrs or [],
        "expiresAt": expires_at,
    })
    if not isinstance(result, dict) or not isinstance(result.get("token"), str):
        raise LifecycleError("PAT issuance did not return one-time plaintext")
    return result


def _lifecycle_case(
    admin: WebClient,
    opener: Any,
    private_mcp_origin: str,
    public_origin: str,
    public_client_id: str,
    redirect_uri: str,
    action: str,
    sequence: int,
) -> tuple[dict[str, Any], list[str]]:
    suffix = f"{action[:3]}{sequence}{secrets.token_hex(3)}"
    user_record, username, password = _create_user(admin, suffix)
    user = WebClient(admin.private_origin, public_origin, username, password)
    pat = _issue_pat(user, "cascade-" + suffix.lower(), ["system:info", "project:list"])
    oauth = _authorization_code_tokens(user, public_client_id, redirect_uri)
    trace = f"release-lifecycle-{action}-{sequence}"
    pat_before_status = _mcp_initialize(
        opener, private_mcp_origin, pat["token"], trace + "-pat-before"
    )
    oauth_before_status = _mcp_initialize(
        opener, public_origin, oauth["access"], trace + "-oauth-before"
    )
    if pat_before_status != 200:
        raise LifecycleError("lifecycle PAT did not work before invalidation")
    if oauth_before_status != 200:
        raise LifecycleError("lifecycle OAuth access token did not work before invalidation")

    if action == "password-reset":
        _api_data(admin, "PUT", f"/api/users/{user_record['id']}/password",
                  {"password": "R2!" + secrets.token_urlsafe(36)}, trace)
        resource = "user"
    elif action == "subject-disable":
        _api_data(admin, "PUT", f"/api/users/{user_record['id']}", {
            "displayName": user_record["displayName"], "email": None, "mobile": None,
            "status": "DISABLED", "version": user_record["version"],
            "roleIds": [ADMIN_ROLE_ID],
        }, trace)
        resource = "user"
    elif action == "subject-remove":
        _api_data(admin, "DELETE", f"/api/users/{user_record['id']}", trace_id=trace)
        resource = "user"
    elif action == "security-logout":
        _api_data(user, "POST", "/api/security/me/security-logout", trace_id=trace)
        resource = "me"
    else:
        raise LifecycleError("unknown lifecycle action")

    session_status, _, _ = user.request("GET", "/api/auth/me")
    access_status = _mcp_initialize(opener, public_origin, oauth["access"], trace + "-oauth-after")
    pat_status = _mcp_initialize(opener, private_mcp_origin, pat["token"], trace + "-pat-after")
    refresh_status, refresh_document = _token_request(opener, public_origin, {
        "grant_type": "refresh_token", "client_id": public_client_id,
        "refresh_token": oauth["refresh"],
    })
    refresh_error = refresh_document.get("error")
    if (
        session_status != 401
        or access_status != 401
        or pat_status != 401
        or refresh_status not in {400, 401}
        or refresh_error != "invalid_grant"
    ):
        raise LifecycleError(f"{action} did not invalidate every bound credential on the next request")
    if not _audit_present(admin, trace, resource):
        raise LifecycleError(f"{action} did not produce a correlated operation audit")
    cleanup_trace, cleanup_status = _remove_lifecycle_user(
        admin,
        str(user_record["id"]),
        trace,
        action == "subject-remove",
    )
    return ({
        "action": action,
        "traceId": trace,
        "oauthGrantType": "authorization_code",
        "pkceMethod": "S256",
        "oauthAccessExpiresInSeconds": oauth["expiresIn"],
        "oauthBeforeHttpStatus": oauth_before_status,
        "sessionNextHttpStatus": session_status,
        "oauthAccessNextHttpStatus": access_status,
        "oauthRefreshNextHttpStatus": refresh_status,
        "oauthRefreshError": refresh_error,
        "patNextHttpStatus": pat_status,
        "operationAuditObserved": True,
        "fixtureCleanupTraceId": cleanup_trace,
        "fixtureReadAfterCleanupHttpStatus": cleanup_status,
        "fixtureCleanupAuditObserved": True,
    }, [
        password,
        user.csrf_token,
        *(cookie.value for cookie in user.cookies),
        pat["token"],
        oauth["access"],
        oauth["refresh"],
    ])


def _compose_logs(prefix: list[str]) -> bytes:
    completed = subprocess.run(
        prefix + ["logs", "--no-color", "app", "nginx", "mcp-public-nginx"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > MAX_DB_DUMP or len(completed.stderr) > 4096:
        raise LifecycleError("runtime logs could not be scanned safely")
    return completed.stdout


@isolated_loopback_resolution()
def rehearse(args: argparse.Namespace) -> dict[str, Any]:
    repository = args.repository_root.resolve(strict=True)
    manifest = _private_json(args.manifest, "release runtime manifest")
    runtime_identity = _private_json(args.runtime_identity, "runtime identity")
    oauth_report = _private_json(args.oauth_runtime_report, "OAuth runtime report")
    environment = _environment(args.env_file)
    private_origin = str(manifest.get("privateBaseUrl", "")).rstrip("/")
    private_mcp_origin = str(manifest.get("privateMcpBaseUrl", "")).rstrip("/")
    public_origin = str(manifest.get("publicBaseUrl", "")).rstrip("/")
    public_client_id = str(manifest.get("publicClientId", ""))
    redirect_uri = str(manifest.get("redirectUri", ""))
    if (
        manifest.get("schemaVersion") != 1
        or urlparse(private_origin).scheme not in {"http", "https"}
        or urlparse(private_mcp_origin).scheme not in {"http", "https"}
        or urlparse(public_origin).scheme != "https"
        or not public_client_id
        or not redirect_uri
    ):
        raise LifecycleError("release runtime manifest is incompatible")
    if runtime_identity.get("status") != "PASS" or oauth_report.get("status") != "PASS":
        raise LifecycleError("runtime identity and OAuth boundary evidence must already be PASS")
    oauth_checks = oauth_report.get("checks")
    if not isinstance(oauth_checks, dict) or any(
        oauth_checks.get(name) != "PASS"
        for name in (
            "oauthMetadataConsistency", "dynamicClientRegistrationDisabled",
            "wwwAuthenticate", "clientCredentials",
            "clientCredentialsShortLived", "oauthPublicMcp", "patPrivateMcp",
            "patPublicRejected", "invalidOriginRejected",
        )
    ):
        raise LifecycleError("OAuth boundary evidence lacks the required negative checks")

    admin_username = os.environ.get("WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME", "")
    admin_password = os.environ.get("WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD", "")
    if not admin_username or not admin_password:
        raise LifecycleError("release administrator credentials are unavailable in the private runner")
    admin = WebClient(private_origin, public_origin, admin_username, admin_password)
    opener = build_opener(ProxyHandler({}), RejectRedirectHandler(), HTTPSHandler(context=_tls_context(public_origin)))
    database = ComposeDatabase(args.compose_file, args.compose_override, args.env_file, args.compose_project)
    compose_prefix = database.prefix
    sensitive_values = [
        admin_password,
        admin.csrf_token,
        *(cookie.value for cookie in admin.cookies),
    ]

    lifecycle: list[dict[str, Any]] = []
    for sequence, action in enumerate(
        ("password-reset", "subject-disable", "subject-remove", "security-logout"), start=1
    ):
        observation, values = _lifecycle_case(
            admin, opener, private_mcp_origin, public_origin, public_client_id,
            redirect_uri, action, sequence,
        )
        lifecycle.append(observation)
        sensitive_values.extend(values)

    active_pepper = _required(environment, "WEB_STARTER_CREDENTIAL_PEPPER")
    active_version = _required(environment, "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION")
    retiring_pepper = _required(environment, "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING")
    retiring_version = _required(environment, "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION")
    if (
        VERSION.fullmatch(active_version) is None
        or VERSION.fullmatch(retiring_version) is None
        or active_version == retiring_version
        or active_pepper == retiring_pepper
    ):
        raise LifecycleError("credential Pepper key ring is not a real two-version rotation")
    raw_old_pat = "wst_pat_" + secrets.token_urlsafe(32)
    old_hash = hmac.new(retiring_pepper.encode(), raw_old_pat.encode(), hashlib.sha256).hexdigest()
    active_hash = hmac.new(active_pepper.encode(), raw_old_pat.encode(), hashlib.sha256).hexdigest()
    fixture_id = 8_000_000_000_000_000_000 + secrets.randbelow(100_000_000)
    database.execute(
        "INSERT INTO sec_access_credential "
        "(id,credential_type,subject_id,subject_security_epoch,name,token_hash,pepper_version,"
        "token_hint,scopes,ip_cidrs,expires_at,revoked_at,revoked_reason,last_used_at,created_by,created_at) "
        f"SELECT {fixture_id},'PERSONAL_ACCESS_TOKEN',id,security_epoch,'pepper-migration-fixture',"
        f"{_sql_literal(old_hash)},{_sql_literal(retiring_version)},'wst_pat_migr','system:info',NULL,NULL,"
        f"NULL,NULL,NULL,id,CURRENT_TIMESTAMP(6) FROM sys_user WHERE id={int(admin.subject_id)};"
    )
    before_version = database.scalar(
        f"SELECT pepper_version FROM sec_access_credential WHERE id={fixture_id};"
    )
    pepper_trace = "release-pepper-migration"
    pepper_status = _mcp_initialize(opener, private_mcp_origin, raw_old_pat, pepper_trace)
    after_row = database.scalar(
        "SELECT CONCAT(pepper_version,':',token_hash,':',IF(last_used_at IS NULL,'0','1')) "
        f"FROM sec_access_credential WHERE id={fixture_id};"
    )
    after_version, after_hash, last_used = after_row.split(":")
    if (
        before_version != retiring_version
        or pepper_status != 200
        or after_version != active_version
        or not hmac.compare_digest(after_hash, active_hash)
        or last_used != "1"
    ):
        raise LifecycleError("old Pepper credential did not migrate atomically after successful authentication")
    sensitive_values.extend([raw_old_pat, active_pepper, retiring_pepper])

    token_files = manifest.get("tokenFiles")
    if not isinstance(token_files, dict):
        raise LifecycleError("runtime manifest is missing OAuth client material")
    client_path = Path(str(token_files.get("oauthClient", "")))
    client_file = _private_json(client_path, "OAuth client fixture")
    if set(client_file) != {"client_id", "client_secret"}:
        raise LifecycleError("OAuth client fixture contains unexpected fields")
    client_id = client_file.get("client_id")
    old_secret = client_file.get("client_secret")
    if not isinstance(client_id, str) or not isinstance(old_secret, str):
        raise LifecycleError("OAuth client fixture is incomplete")
    clients = _api_data(admin, "GET", "/api/security/oauth-clients")
    client = next((item for item in clients if isinstance(item, dict) and item.get("clientId") == client_id), None)
    if not isinstance(client, dict) or not isinstance(client.get("id"), str):
        raise LifecycleError("OAuth client record could not be resolved through the management API")
    oauth_service_account_id = client.get("serviceAccountId")
    service_accounts = _api_data(admin, "GET", "/api/security/service-accounts")
    oauth_service_account = next(
        (
            item for item in service_accounts
            if isinstance(item, dict) and item.get("id") == oauth_service_account_id
        ),
        None,
    )
    original_role_ids = (
        oauth_service_account.get("roleIds")
        if isinstance(oauth_service_account, dict) else None
    )
    if (
        not _is_opaque_id(oauth_service_account_id)
        or not isinstance(oauth_service_account, dict)
        or not isinstance(original_role_ids, list)
        or not original_role_ids
        or any(not _is_opaque_id(role_id) for role_id in original_role_ids)
    ):
        raise LifecycleError("OAuth client service account or role binding is invalid")
    rotate_trace = "release-client-secret-rotate"
    rotated = _api_data(
        admin, "POST", f"/api/security/oauth-clients/{client['id']}/rotate-secret",
        {"overlapSeconds": 2}, rotate_trace,
    )
    new_secret = rotated.get("clientSecret") if isinstance(rotated, dict) else None
    rotated_client = rotated.get("client") if isinstance(rotated, dict) else None
    if not isinstance(new_secret, str) or not isinstance(rotated_client, dict):
        raise LifecycleError("OAuth Client Secret rotation did not return one-time material")
    token_parameters = {"grant_type": "client_credentials", "scope": "system:info project:list audit:list"}
    old_during, old_during_body = _token_request(opener, public_origin, token_parameters, client_id, old_secret)
    new_during, new_during_body = _token_request(opener, public_origin, token_parameters, client_id, new_secret)
    if old_during != 200 or new_during != 200:
        raise LifecycleError("OAuth Client Secret overlap window did not accept both versions")
    sensitive_values.extend([
        old_secret, new_secret,
        base64.b64encode(f"{client_id}:{old_secret}".encode()).decode(),
        base64.b64encode(f"{client_id}:{new_secret}".encode()).decode(),
        str(old_during_body.get("access_token", "")), str(new_during_body.get("access_token", "")),
    ])
    time.sleep(3)
    old_after, old_after_body = _token_request(opener, public_origin, token_parameters, client_id, old_secret)
    new_after, new_after_body = _token_request(opener, public_origin, token_parameters, client_id, new_secret)
    if old_after not in {400, 401} or old_after_body.get("error") != "invalid_client" or new_after != 200:
        raise LifecycleError("OAuth Client Secret overlap did not end with old-secret rejection")
    existing_oauth_access = new_after_body.get("access_token")
    if not isinstance(existing_oauth_access, str):
        raise LifecycleError("OAuth Client Credentials response is missing its access token")
    sensitive_values.append(existing_oauth_access)
    if not _audit_present(admin, rotate_trace, "oauth-client"):
        raise LifecycleError("OAuth Client Secret rotation lacks a correlated audit record")

    revoke_roles_trace = "release-client-credentials-role-revoke"
    _api_data(
        admin,
        "PUT",
        f"/api/security/service-accounts/{oauth_service_account_id}",
        {
            "displayName": oauth_service_account["displayName"],
            "description": oauth_service_account.get("description"),
            "enabled": True,
            "roleIds": [],
        },
        revoke_roles_trace,
    )
    revoked_oauth_status = _mcp_initialize(
        opener, public_origin, existing_oauth_access,
        "release-client-credentials-role-revoked",
    )
    if revoked_oauth_status != 401 or not _audit_present(
        admin, revoke_roles_trace, "service-account"
    ):
        raise LifecycleError("role revocation did not immediately reject the existing OAuth token")

    restore_roles_trace = "release-client-credentials-role-restore"
    _api_data(
        admin,
        "PUT",
        f"/api/security/service-accounts/{oauth_service_account_id}",
        {
            "displayName": oauth_service_account["displayName"],
            "description": oauth_service_account.get("description"),
            "enabled": True,
            "roleIds": original_role_ids,
        },
        restore_roles_trace,
    )
    final_oauth_status, final_oauth_body = _token_request(
        opener, public_origin, token_parameters, client_id, new_secret
    )
    final_oauth_access = final_oauth_body.get("access_token")
    restored_oauth_status = _mcp_initialize(
        opener, public_origin, str(final_oauth_access),
        "release-client-credentials-role-restored",
    ) if isinstance(final_oauth_access, str) else 0
    if (
        final_oauth_status != 200
        or not isinstance(final_oauth_access, str)
        or restored_oauth_status != 200
        or not _audit_present(admin, restore_roles_trace, "service-account")
    ):
        raise LifecycleError("restored service account did not issue a usable OAuth token")
    sensitive_values.append(final_oauth_access)
    # The release verifier intentionally runs again after the destructive
    # lifecycle rehearsal. Refresh only its external mode-0600 fixture after
    # proving that the old secret is terminally rejected; production storage,
    # reports and logs still never receive plaintext material.
    _replace_private_json(
        client_path,
        {"client_id": client_id, "client_secret": new_secret},
        "OAuth client fixture",
    )
    _replace_private_json(
        Path(str(token_files.get("oauthToken", ""))),
        final_oauth_body,
        "OAuth token fixture",
    )

    scope_denied_pat = _issue_pat(admin, "scope-denied-negative", ["project:list"])
    scope_denied_code = _mcp_tool_error(
        opener, private_mcp_origin, scope_denied_pat["token"], "release-scope-denied",
        "project.create", {"name": "Denied", "code": "DENIED_SCOPE", "ownerId": admin.subject_id,
                           "status": "PLANNING", "description": "must not be created"},
    )
    expiring_at = datetime.now(timezone.utc) + timedelta(seconds=10)
    expiring_pat = _issue_pat(
        admin,
        "expiring-runtime-negative",
        ["system:info"],
        expires_at=expiring_at.isoformat().replace("+00:00", "Z"),
    )
    expiring_before_status = _mcp_initialize(
        opener, private_mcp_origin, expiring_pat["token"], "release-pat-expiring-before"
    )
    wait_seconds = max(0.0, (expiring_at - datetime.now(timezone.utc)).total_seconds() + 0.5)
    if wait_seconds > 15:
        raise LifecycleError("PAT expiry rehearsal calculated an unsafe wait")
    time.sleep(wait_seconds)
    expired_pat_status = _mcp_initialize(
        opener, private_mcp_origin, expiring_pat["token"], "release-pat-expired-after"
    )
    restricted_pat = _issue_pat(
        admin,
        "ip-restricted-runtime-negative",
        ["system:info"],
        allowed_ip_cidrs=["203.0.113.7/32"],
    )
    restricted_pat_status = _mcp_initialize(
        opener, private_mcp_origin, restricted_pat["token"], "release-pat-ip-restricted"
    )
    account_create_trace = "release-service-account-create"
    account = _api_data(admin, "POST", "/api/security/service-accounts", {
        "code": "rbac_negative_" + secrets.token_hex(4), "displayName": "RBAC negative",
        "description": "Disposable security acceptance subject",
        "roleIds": [ADMIN_ROLE_ID],
    }, account_create_trace)
    if (
        not isinstance(account, dict)
        or not _is_opaque_id(account.get("id"))
        or account.get("enabled") is not True
        or account.get("roleIds") != [ADMIN_ROLE_ID]
    ):
        raise LifecycleError("service account was not created enabled with its assigned role")
    account_token_issue_trace = "release-service-account-token-issue"
    account_token = _api_data(admin, "POST", f"/api/security/service-accounts/{account['id']}/tokens", {
        "name": "rbac-negative-token", "scopes": ["project:create"],
        "allowedIpCidrs": [], "expiresAt": None,
    }, account_token_issue_trace)
    private_service_token_status = _mcp_initialize(
        opener, private_mcp_origin, account_token["token"], "release-service-token-private"
    )
    public_service_token_status = _mcp_initialize(
        opener, public_origin, account_token["token"], "release-service-token-public"
    )
    role_remove_trace = "release-service-account-role-remove"
    _api_data(admin, "PUT", f"/api/security/service-accounts/{account['id']}", {
        "displayName": account["displayName"], "description": account.get("description"),
        "enabled": True, "roleIds": [],
    }, role_remove_trace)
    rbac_denied_code = _mcp_tool_error(
        opener, private_mcp_origin, account_token["token"], "release-rbac-denied",
        "project.create", {"name": "Denied", "code": "DENIED_RBAC", "ownerId": admin.subject_id,
                           "status": "PLANNING", "description": "must not be created"},
    )
    role_restore_trace = "release-service-account-role-restore"
    _api_data(admin, "PUT", f"/api/security/service-accounts/{account['id']}", {
        "displayName": account["displayName"], "description": account.get("description"),
        "enabled": True, "roleIds": [ADMIN_ROLE_ID],
    }, role_restore_trace)
    role_restored_status = _mcp_initialize(
        opener, private_mcp_origin, account_token["token"],
        "release-service-account-role-restored",
    )

    peer_issue_trace = "release-service-account-peer-token-issue"
    account_peer_token = _api_data(
        admin,
        "POST",
        f"/api/security/service-accounts/{account['id']}/tokens",
        {
            "name": "service-account-peer-token", "scopes": ["system:info"],
            "allowedIpCidrs": [], "expiresAt": None,
        },
        peer_issue_trace,
    )
    peer_before_revoke_status = _mcp_initialize(
        opener, private_mcp_origin, account_peer_token["token"],
        "release-service-account-peer-before-revoke",
    )

    token_revoke_trace = "release-service-account-token-revoke"
    _api_data(
        admin,
        "DELETE",
        f"/api/security/service-accounts/{account['id']}/tokens/{account_token['id']}",
        trace_id=token_revoke_trace,
    )
    revoked_service_token_status = _mcp_initialize(
        opener, private_mcp_origin, account_token["token"],
        "release-service-account-token-revoked",
    )
    peer_after_revoke_status = _mcp_initialize(
        opener, private_mcp_origin, account_peer_token["token"],
        "release-service-account-peer-after-revoke",
    )

    account_disable_trace = "release-service-account-disable"
    _api_data(admin, "PUT", f"/api/security/service-accounts/{account['id']}", {
        "displayName": account["displayName"], "description": account.get("description"),
        "enabled": False, "roleIds": [ADMIN_ROLE_ID],
    }, account_disable_trace)
    disabled_token_statuses = [
        _mcp_initialize(
            opener, private_mcp_origin, token, f"release-service-account-disabled-{index}"
        )
        for index, token in enumerate(
            (account_token["token"], account_peer_token["token"]), start=1
        )
    ]
    token_rows = _api_data(
        admin, "GET", f"/api/security/service-accounts/{account['id']}/tokens"
    )
    expected_token_ids = {str(account_token["id"]), str(account_peer_token["id"])}
    revoked_token_ids = {
        str(row.get("id")) for row in token_rows
        if isinstance(row, dict) and row.get("revokedAt") is not None
    } if isinstance(token_rows, list) else set()
    all_existing_rows_revoked = expected_token_ids.issubset(revoked_token_ids)

    account_reenable_trace = "release-service-account-reenable"
    _api_data(admin, "PUT", f"/api/security/service-accounts/{account['id']}", {
        "displayName": account["displayName"], "description": account.get("description"),
        "enabled": True, "roleIds": [ADMIN_ROLE_ID],
    }, account_reenable_trace)
    reenabled_old_token_statuses = [
        _mcp_initialize(
            opener, private_mcp_origin, token, f"release-service-account-reenabled-old-{index}"
        )
        for index, token in enumerate(
            (account_token["token"], account_peer_token["token"]), start=1
        )
    ]
    replacement_issue_trace = "release-service-account-replacement-token-issue"
    replacement_token = _api_data(
        admin,
        "POST",
        f"/api/security/service-accounts/{account['id']}/tokens",
        {
            "name": "service-account-replacement-token", "scopes": ["system:info"],
            "allowedIpCidrs": [], "expiresAt": None,
        },
        replacement_issue_trace,
    )
    replacement_token_status = _mcp_initialize(
        opener, private_mcp_origin, replacement_token["token"],
        "release-service-account-replacement-active",
    )
    service_account_audits = _operation_audits_present(admin, (
        (account_create_trace, "service-account"),
        (account_token_issue_trace, "token"),
        (role_remove_trace, "service-account"),
        (role_restore_trace, "service-account"),
        (peer_issue_trace, "token"),
        (token_revoke_trace, "token"),
        (account_disable_trace, "service-account"),
        (account_reenable_trace, "service-account"),
        (replacement_issue_trace, "token"),
    ))
    revoked = _issue_pat(admin, "revoked-negative", ["system:info"])
    _api_data(admin, "DELETE", f"/api/security/personal-tokens/{revoked['id']}")
    revoked_status = _mcp_initialize(opener, private_mcp_origin, revoked["token"], "release-revoked-negative")
    boundary_private = _mcp_initialize(
        opener, private_mcp_origin, scope_denied_pat["token"], "release-boundary-private"
    )
    boundary_public = _mcp_initialize(
        opener, public_origin, scope_denied_pat["token"], "release-boundary-public"
    )
    personal_tokens = _api_data(admin, "GET", "/api/security/personal-tokens")
    if not isinstance(personal_tokens, list):
        raise LifecycleError("personal token list did not return an array")
    token_rows_by_id = {
        str(row.get("id")): row for row in personal_tokens if isinstance(row, dict)
    }
    scope_pat_row = token_rows_by_id.get(str(scope_denied_pat["id"]))
    expiring_pat_row = token_rows_by_id.get(str(expiring_pat["id"]))
    restricted_pat_row = token_rows_by_id.get(str(restricted_pat["id"]))
    revoked_pat_row = token_rows_by_id.get(str(revoked["id"]))
    plaintext_absent_from_list = all(
        {"token", "rawToken", "plaintext"}.isdisjoint(row)
        for row in personal_tokens if isinstance(row, dict)
    )
    scope_database_row = database.scalar(
        "SELECT CONCAT(token_hash,':',token_hint,':',IF(last_used_at IS NULL,'0','1'),':',"
        "credential_type,':',subject_id) FROM sec_access_credential "
        f"WHERE id={int(scope_denied_pat['id'])};"
    )
    scope_hash, scope_hint, scope_last_used, scope_type, scope_subject = scope_database_row.split(":")
    database_hash_only = (
        re.fullmatch(r"[0-9a-f]{64}", scope_hash) is not None
        and scope_hash != scope_denied_pat["token"]
        and scope_hint == scope_denied_pat.get("tokenHint")
        and scope_type == "PERSONAL_ACCESS_TOKEN"
        and scope_subject == str(admin.subject_id)
    )
    personal_token_observations_valid = (
        isinstance(scope_pat_row, dict)
        and scope_pat_row.get("lastUsedAt") is not None
        and scope_last_used == "1"
        and isinstance(expiring_pat_row, dict)
        and expiring_pat_row.get("expiresAt") is not None
        and isinstance(restricted_pat_row, dict)
        and restricted_pat_row.get("allowedIpCidrs") == ["203.0.113.7/32"]
        and isinstance(revoked_pat_row, dict)
        and revoked_pat_row.get("revokedAt") is not None
    )
    invalid_host = _mcp_initialize(
        opener, private_mcp_origin, scope_denied_pat["token"], "release-invalid-host",
        {"Host": "invalid-host.example.invalid"},
    )
    scope_denied_audit = _mcp_failure_audit_present(admin, "release-scope-denied", "FORBIDDEN")
    rbac_denied_audit = _mcp_failure_audit_present(admin, "release-rbac-denied", "FORBIDDEN")
    _require_checks("V1 security-negative contract regressed", {
        "rbac-allowed-scope-denied": scope_denied_code == "FORBIDDEN",
        "scope-allowed-rbac-denied": rbac_denied_code == "FORBIDDEN",
        "revoked-credential-rejected": revoked_status == 401,
        "expiring-pat-works-before-expiry": expiring_before_status == 200,
        "expired-pat-rejected": expired_pat_status == 401,
        "ip-restricted-pat-rejected": restricted_pat_status == 401,
        "personal-token-list-never-redisplays-plaintext": plaintext_absent_from_list,
        "personal-token-database-hash-and-owner-bound": database_hash_only,
        "personal-token-lifecycle-fields-observed": personal_token_observations_valid,
        "private-pat-accepted": boundary_private == 200,
        "public-pat-rejected": boundary_public == 401,
        "private-service-token-accepted": private_service_token_status == 200,
        "public-service-token-rejected": public_service_token_status == 401,
        "invalid-host-rejected": 400 <= invalid_host < 500,
        "scope-denied-audit-observed": scope_denied_audit,
        "rbac-denied-audit-observed": rbac_denied_audit,
        "service-account-role-restored": role_restored_status == 200,
        "service-account-peer-before-revoke": peer_before_revoke_status == 200,
        "revoked-service-token-rejected": revoked_service_token_status == 401,
        "peer-survives-single-token-revocation": peer_after_revoke_status == 200,
        "disabled-account-rejects-all-existing-tokens": disabled_token_statuses == [401, 401],
        "disabled-account-revokes-all-token-rows": all_existing_rows_revoked,
        "reenable-does-not-resurrect-old-tokens": reenabled_old_token_statuses == [401, 401],
        "reenabled-account-issues-usable-token": replacement_token_status == 200,
        "service-account-operation-audits-observed": service_account_audits,
    })
    sensitive_values.extend([
        scope_denied_pat["token"], expiring_pat["token"], restricted_pat["token"],
        account_token["token"], account_peer_token["token"],
        replacement_token["token"], revoked["token"],
    ])

    database_dump = database.dump()
    logs = _compose_logs(compose_prefix)
    for value in sensitive_values:
        if value and (value.encode() in database_dump or value.encode() in logs):
            raise LifecycleError("plaintext credential material appeared in database or runtime logs")
    if SENSITIVE_LOG_HEADER.search(logs):
        raise LifecycleError("runtime logs exposed a Cookie or Authorization header")

    source_paths = [
        "scripts/rehearse_credential_lifecycle.py",
        "scripts/validate_credential_lifecycle_evidence.py",
        "scripts/verify_oauth_runtime.py",
        "security/v2-credential-lifecycle-runtime-summary.schema.json",
        "deploy/nginx/external-mcp.conf",
        "web-starter-system/src/main/java/dev/webstarter/system/service/UserService.java",
        "web-starter-system/src/main/java/dev/webstarter/system/service/impl/UserServiceImpl.java",
        "web-starter-security/src/main/java/dev/webstarter/security/web/AccountSecurityController.java",
        "web-starter-security/src/main/java/dev/webstarter/security/session/IdentitySecurityLifecycleAdapter.java",
        "web-starter-security/src/main/java/dev/webstarter/security/token/CredentialPepperKeyRing.java",
        "web-starter-security/src/main/java/dev/webstarter/security/token/AccessCredentialService.java",
        "web-starter-security/src/main/java/dev/webstarter/security/oauth/OAuthClientManagementService.java",
        "web-starter-security/src/main/java/dev/webstarter/security/oauth/OAuthClientSecretPasswordEncoder.java",
        "web-starter-admin/src/main/resources/db/migration/V7__add_credential_rotation.sql",
        "web-starter-web/src/views/security/AccountSecurityView.vue",
    ]
    source_hashes = {path: _file_sha256(repository / path) for path in source_paths}
    release_tag = os.environ.get("WEB_STARTER_RELEASE_TAG", "")
    release_version = os.environ.get("WEB_STARTER_RELEASE_VERSION", "")
    git_commit = os.environ.get("GITHUB_SHA", "")
    if not release_tag or release_tag != "v" + release_version or not re.fullmatch(r"[0-9a-f]{40}", git_commit):
        raise LifecycleError("formal release identity is missing or inconsistent")
    report = {
        "schemaVersion": 1,
        "acceptanceIds": ["V2-AC-24", "V2-AC-27", "V2-AC-28", "V2-AC-36"],
        "status": "PASS",
        "observedAt": _now(),
        "candidate": {
            "releaseTag": release_tag, "releaseVersion": release_version, "gitCommit": git_commit,
            "appImageReference": runtime_identity["images"]["app"]["reference"],
            "nginxImageReference": runtime_identity["images"]["nginx"]["reference"],
        },
        "runtime": {
            "composeProject": args.compose_project,
            "privateOrigin": private_origin,
            "privateMcpOrigin": private_mcp_origin,
            "publicOrigin": public_origin,
            "runtimeIdentitySha256": _file_sha256(args.runtime_identity),
            "oauthRuntimeReportSha256": _file_sha256(args.oauth_runtime_report),
        },
        "cascadeInvalidation": {"cases": lifecycle},
        "pepperRotation": {
            "beforeVersion": before_version, "afterVersion": after_version,
            "authenticationHttpStatus": pepper_status, "activeHashMatched": True,
            "lastUsedRecorded": True, "databasePlaintextAbsent": True, "runtimeLogPlaintextAbsent": True,
        },
        "clientSecretRotation": {
            "overlapSeconds": 2, "oldDuringHttpStatus": old_during,
            "newDuringHttpStatus": new_during, "oldAfterHttpStatus": old_after,
            "oldAfterError": old_after_body.get("error"), "newAfterHttpStatus": new_after,
            "preRegisteredClientObserved": True, "operationAuditObserved": True,
        },
        "clientCredentialsLifecycle": {
            "shortLivedTokenObserved": True,
            "roleRevocationHttpStatus": revoked_oauth_status,
            "roleRestorationHttpStatus": restored_oauth_status,
            "revocationAuditObserved": True,
            "restorationAuditObserved": True,
        },
        "serviceAccountLifecycle": {
            "createdEnabledWithRole": True,
            "roleRemovalErrorCode": rbac_denied_code,
            "roleRestorationHttpStatus": role_restored_status,
            "explicitRevocationHttpStatus": revoked_service_token_status,
            "peerAfterSingleRevocationHttpStatus": peer_after_revoke_status,
            "disabledTokenHttpStatuses": disabled_token_statuses,
            "allExistingTokenRowsRevoked": all_existing_rows_revoked,
            "reenabledOldTokenHttpStatuses": reenabled_old_token_statuses,
            "replacementTokenHttpStatus": replacement_token_status,
            "operationAuditsObserved": service_account_audits,
        },
        "personalTokenLifecycle": {
            "boundUserObserved": database_hash_only,
            "oneTimePlaintextObserved": plaintext_absent_from_list,
            "databaseHashAndHintObserved": database_hash_only,
            "scopeDeniedCode": scope_denied_code,
            "beforeExpiryHttpStatus": expiring_before_status,
            "afterExpiryHttpStatus": expired_pat_status,
            "revokedHttpStatus": revoked_status,
            "ipRestrictedHttpStatus": restricted_pat_status,
            "lastUsedRecorded": personal_token_observations_valid,
            "lifecycleFieldsObserved": personal_token_observations_valid,
        },
        "securityRegression": {
            "rbacAllowedScopeDeniedCode": scope_denied_code,
            "scopeAllowedRbacDeniedCode": rbac_denied_code,
            "disabledSubjectRejected": True,
            "revokedCredentialHttpStatus": revoked_status,
            "privatePatHttpStatus": boundary_private,
            "publicPatHttpStatus": boundary_public,
            "privateServiceTokenHttpStatus": private_service_token_status,
            "publicServiceTokenHttpStatus": public_service_token_status,
            "invalidHostHttpStatus": invalid_host,
            "invalidOriginRejected": True,
            "scopeDeniedAuditObserved": scope_denied_audit,
            "rbacDeniedAuditObserved": rbac_denied_audit,
            "correlatedAuditsObserved": True,
        },
        "secretHandling": {
            "rawCredentialsPersisted": False, "databaseDumpScanned": True,
            "runtimeLogsScanned": True, "errorResponsesScanned": True,
            "runtimeSensitiveHeadersAbsent": True,
            "sensitiveValueCount": len([v for v in sensitive_values if v]),
        },
        "sources": source_hashes,
    }
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():
        raise LifecycleError("credential lifecycle output must be a new file in an existing real directory")
    if os.name == "posix" and stat.S_IMODE(output.parent.stat().st_mode) != 0o700:
        raise LifecycleError("credential lifecycle output directory must have mode 0700")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    return report


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--runtime-identity", required=True, type=Path)
    parser.add_argument("--oauth-runtime-report", required=True, type=Path)
    parser.add_argument("--compose-file", required=True, type=Path)
    parser.add_argument("--compose-override", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        report = rehearse(parse_arguments(sys.argv[1:] if argv is None else argv))
    except (LifecycleError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL credential-lifecycle: {error}", file=sys.stderr)
        return 1
    print(
        "PASS credential-lifecycle: "
        + ",".join(report["acceptanceIds"])
        + " passed against the real candidate stack"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
