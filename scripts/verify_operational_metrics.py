#!/usr/bin/env python3
"""Verify authenticated, low-cardinality operational metrics at runtime.

The dedicated password is read only from the process environment, used to
construct an in-memory HTTP Basic header, and never written to evidence or
printed. Output contains metric names, bounded tag metadata, and numeric values
only.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import subprocess
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from acceptance_network import RejectRedirectHandler, reject_tls_key_logging


class OperationalMetricsError(RuntimeError):
    """Raised when operational metrics cannot be proven safely."""


CUSTOM_METRICS: dict[str, set[str]] = {
    "webstarter.audit.operations": {"boundary", "result"},
    "webstarter.audit.persist.failures": {"type"},
    "webstarter.login.attempts": {"result"},
    "webstarter.mcp.calls": {"tool", "result"},
    "webstarter.mcp.call.duration": {"tool", "result"},
    "webstarter.mcp.rate_limited": {"risk"},
    "webstarter.mcp.sessions": {"event"},
    "webstarter.protocol.requests": {"endpoint", "method", "outcome"},
    "webstarter.rate_limited": {"endpoint"},
}
SNAPSHOT_METRICS = tuple(CUSTOM_METRICS) + ("hikaricp.connections.usage",)
ALLOWED_TAG_VALUES: dict[str, dict[str, set[str]]] = {
    "webstarter.audit.operations": {
        "boundary": {"project", "security", "system", "extension"},
        "result": {"SUCCESS", "FAILED", "OTHER"},
    },
    "webstarter.audit.persist.failures": {"type": {"login", "operation", "mcp"}},
    "webstarter.login.attempts": {"result": {"SUCCESS", "FAILED", "OTHER"}},
    "webstarter.mcp.calls": {
        "tool": {
            "system.info", "project.list", "project.get", "project.create",
            "project.update", "project.remove", "audit.list", "unknown",
        },
        "result": {"SUCCESS", "FAILED", "OTHER"},
    },
    "webstarter.mcp.call.duration": {
        "tool": {
            "system.info", "project.list", "project.get", "project.create",
            "project.update", "project.remove", "audit.list", "unknown",
        },
        "result": {"SUCCESS", "FAILED", "OTHER"},
    },
    "webstarter.mcp.rate_limited": {
        "risk": {"read", "write", "destructive", "protocol"},
    },
    "webstarter.mcp.sessions": {
        "event": {
            "created", "deleted", "cleanup_failed", "limit_rejected",
            "owner_mismatch", "expired", "not_found",
        },
    },
    "webstarter.protocol.requests": {
        "endpoint": {"login", "oauth_token", "mcp"},
        "method": {"GET", "POST", "DELETE", "OTHER"},
        "outcome": {"SUCCESS", "RATE_LIMITED", "CLIENT_ERROR", "SERVER_ERROR", "OTHER"},
    },
    "webstarter.rate_limited": {"endpoint": {"login", "oauth_token", "mcp"}},
}
PROTOCOL_ENDPOINTS = ("login", "oauth_token", "mcp")
FORBIDDEN_TAG_FRAGMENTS = (
    "actor", "clientid", "client_id", "credential", "ip", "principal",
    "sessionid", "subject", "token", "trace", "user",
)
SECRET_VALUE = re.compile(
    r"(?i)(?:\b(?:wst_)?(?:pat|sat|svc)_[A-Za-z0-9._~-]{8,}|bearer\s+|"
    r"BEGIN (?:RSA )?PRIVATE KEY)"
)
TRACE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
MAX_COMPOSE_LOG_BYTES = 32 * 1024 * 1024


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or any(character in value for character in "\r\n\0"):
        raise OperationalMetricsError(f"{name} is required and must be a single line")
    return value


def _base_url(value: str) -> str:
    parsed = urlparse(value.rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OperationalMetricsError("management base URL must be an HTTP(S) origin")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} \
            or parsed.query or parsed.fragment:
        raise OperationalMetricsError("management base URL must not contain credentials or a path")
    host = parsed.hostname.lower()
    if host not in {"localhost", "::1"} and not host.startswith("127."):
        raise OperationalMetricsError("runtime verification accepts only a loopback management origin")
    return value.rstrip("/")


def _opener(base_url: str):
    handlers: list[Any] = [ProxyHandler({}), RejectRedirectHandler()]
    if base_url.startswith("https://"):
        try:
            reject_tls_key_logging()
        except ValueError as error:
            raise OperationalMetricsError(str(error)) from error
        context = ssl.create_default_context()
        handlers.append(HTTPSHandler(context=context))
    return build_opener(*handlers)


def _basic(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return "Basic " + encoded


def _request(
    opener: Any,
    url: str,
    authorization: str | None = None,
    read_json: bool = False,
    accept: str = "application/json",
) -> tuple[int, Any | None]:
    headers = {"Accept": accept}
    if authorization is not None:
        headers["Authorization"] = authorization
    request = Request(url, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read()
            document = json.loads(raw) if read_json and raw else None
            return response.status, document
    except HTTPError as error:
        error.read()
        return error.code, None
    except (URLError, TimeoutError) as error:
        raise OperationalMetricsError("management endpoint is unreachable") from error


def _metric(
    opener: Any,
    base_url: str,
    authorization: str,
    name: str,
    tags: tuple[tuple[str, str], ...] = (),
) -> dict[str, Any]:
    query = urlencode([("tag", f"{key}:{value}") for key, value in tags])
    url = f"{base_url}/actuator/metrics/{quote(name, safe='')}"
    if query:
        url += "?" + query
    status, document = _request(opener, url, authorization, read_json=True)
    if status == 404:
        return {"present": False, "measurements": {}, "tags": {}}
    if status != 200 or not isinstance(document, dict):
        raise OperationalMetricsError(f"metric {name} returned HTTP {status}")
    measurements: dict[str, float] = {}
    for item in document.get("measurements", []):
        if isinstance(item, dict) and isinstance(item.get("statistic"), str):
            measurements[item["statistic"]] = float(item.get("value", 0))
    available: dict[str, list[str]] = {}
    for item in document.get("availableTags", []):
        if not isinstance(item, dict) or not isinstance(item.get("tag"), str):
            raise OperationalMetricsError(f"metric {name} returned malformed tag metadata")
        values = item.get("values", [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise OperationalMetricsError(f"metric {name} returned malformed tag values")
        available[item["tag"]] = sorted(values)
    return {"present": True, "measurements": measurements, "tags": available}


def _validate_custom_tags(metrics: dict[str, dict[str, Any]], password: str) -> None:
    for name, allowed_keys in CUSTOM_METRICS.items():
        metric = metrics[name]
        if not metric["present"]:
            raise OperationalMetricsError(f"metric {name} is not pre-registered")
        actual_keys = set(metric["tags"])
        if actual_keys != allowed_keys:
            raise OperationalMetricsError(f"metric {name} does not expose its exact bounded tag keys")
        for key, values in metric["tags"].items():
            compact_key = key.lower().replace("-", "").replace(".", "")
            if any(fragment in compact_key for fragment in FORBIDDEN_TAG_FRAGMENTS):
                raise OperationalMetricsError(f"metric {name} exposes a forbidden identity tag")
            for value in values:
                if len(value) > 128 or SECRET_VALUE.search(value) or value == password:
                    raise OperationalMetricsError(f"metric {name} exposes unsafe tag material")
            expected_values = ALLOWED_TAG_VALUES[name][key]
            if set(values) != expected_values:
                raise OperationalMetricsError(f"metric {name} exposes an incomplete or drifting tag domain")


def _count(snapshot: dict[str, Any], metric: str) -> float:
    return float(snapshot["metrics"][metric]["measurements"].get("COUNT", 0.0))


def capture(base_url: str, username: str, password: str) -> dict[str, Any]:
    opener = _opener(base_url)
    authorization = _basic(username, password)
    wrong = _basic(username, secrets.token_urlsafe(32))
    statuses = {
        "healthAnonymous": _request(opener, base_url + "/actuator/health")[0],
        "infoAnonymous": _request(opener, base_url + "/actuator/info")[0],
        "metricsAnonymous": _request(opener, base_url + "/actuator/metrics")[0],
        "metricsWrongCredential": _request(
            opener, base_url + "/actuator/metrics", wrong
        )[0],
        "infoOperationalCredential": _request(
            opener, base_url + "/actuator/info", authorization
        )[0],
        "metricsOperationalCredential": _request(
            opener, base_url + "/actuator/metrics", authorization
        )[0],
        "prometheusOperationalCredential": _request(
            opener,
            base_url + "/actuator/prometheus",
            authorization,
            accept="text/plain",
        )[0],
    }
    expected = {
        "healthAnonymous": 200,
        "infoAnonymous": 401,
        "metricsAnonymous": 401,
        "metricsWrongCredential": 401,
        "infoOperationalCredential": 200,
        "metricsOperationalCredential": 200,
        "prometheusOperationalCredential": 200,
    }
    if statuses != expected:
        raise OperationalMetricsError(
            "operational endpoint authorization matrix failed: "
            + json.dumps(statuses, sort_keys=True)
        )
    metrics = {name: _metric(opener, base_url, authorization, name) for name in SNAPSHOT_METRICS}
    _validate_custom_tags(metrics, password)
    if not metrics["hikaricp.connections.usage"]["present"]:
        raise OperationalMetricsError("Hikari connection-pool usage metric is absent")
    protocol_endpoints = {
        endpoint: _metric(
            opener, base_url, authorization, "webstarter.protocol.requests",
            (("endpoint", endpoint),),
        )
        for endpoint in PROTOCOL_ENDPOINTS
    }
    if any(not metric["present"] for metric in protocol_endpoints.values()):
        raise OperationalMetricsError("one or more protocol endpoint metric series are absent")
    return {
        "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "authorization": statuses,
        "metrics": metrics,
        "protocolEndpoints": protocol_endpoints,
    }


def evaluate(
    before: dict[str, Any],
    after: dict[str, Any],
    require_rate_limited: bool,
    require_audit_failure: bool,
) -> dict[str, bool]:
    checks = {
        "authorizationMatrix": all(
            after["authorization"].get(key) == value
            for key, value in {
                "healthAnonymous": 200,
                "infoAnonymous": 401,
                "metricsAnonymous": 401,
                "metricsWrongCredential": 401,
                "infoOperationalCredential": 200,
                "metricsOperationalCredential": 200,
                "prometheusOperationalCredential": 200,
            }.items()
        ),
        "operationAuditCounterIncreased":
            _count(after, "webstarter.audit.operations")
            > _count(before, "webstarter.audit.operations"),
        "loginAttemptCounterIncreased":
            _count(after, "webstarter.login.attempts")
            > _count(before, "webstarter.login.attempts"),
        "mcpCallCounterIncreased":
            _count(after, "webstarter.mcp.calls")
            > _count(before, "webstarter.mcp.calls"),
        "mcpCallDurationCounterIncreased":
            _count(after, "webstarter.mcp.call.duration")
            > _count(before, "webstarter.mcp.call.duration"),
        "mcpSessionCounterIncreased":
            _count(after, "webstarter.mcp.sessions")
            > _count(before, "webstarter.mcp.sessions"),
        "hikariUsageCounterIncreased":
            _count(after, "hikaricp.connections.usage")
            > _count(before, "hikaricp.connections.usage"),
    }
    for endpoint in PROTOCOL_ENDPOINTS:
        checks[endpoint + "ProtocolCounterIncreased"] = (
            float(after["protocolEndpoints"][endpoint]["measurements"].get("COUNT", 0.0))
            > float(before["protocolEndpoints"][endpoint]["measurements"].get("COUNT", 0.0))
        )
    if require_rate_limited:
        checks["rateLimitedCounterIncreased"] = (
            _count(after, "webstarter.rate_limited")
            > _count(before, "webstarter.rate_limited")
        )
    if require_audit_failure:
        checks["auditPersistFailureCounterIncreased"] = (
            _count(after, "webstarter.audit.persist.failures")
            > _count(before, "webstarter.audit.persist.failures")
        )
    return checks


def _structured_log_sample(
    compose_file: Path,
    compose_override: Path,
    env_file: Path,
    compose_project: str,
    run_command: Any = subprocess.run,
) -> dict[str, Any]:
    if COMPOSE_PROJECT.fullmatch(compose_project) is None:
        raise OperationalMetricsError("Compose project name is invalid")
    paths = (compose_file, compose_override, env_file)
    resolved: list[Path] = []
    for path in paths:
        requested = path.expanduser().absolute()
        if requested.is_symlink() or not requested.is_file():
            raise OperationalMetricsError("structured-log Compose input must be a real file")
        resolved.append(requested.resolve(strict=True))
    try:
        completed = run_command(
            [
                "docker", "compose", "--project-name", compose_project,
                "--env-file", str(resolved[2]),
                "-f", str(resolved[0]), "-f", str(resolved[1]),
                "logs", "--no-color", "app",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperationalMetricsError("structured application logs could not be read") from error
    stdout = completed.stdout.encode() if isinstance(completed.stdout, str) else completed.stdout
    stderr = completed.stderr.encode() if isinstance(completed.stderr, str) else completed.stderr
    if (
        completed.returncode != 0 or not isinstance(stdout, bytes) or not isinstance(stderr, bytes)
        or len(stdout) <= 0 or len(stdout) > MAX_COMPOSE_LOG_BYTES or len(stderr) > 8192
    ):
        raise OperationalMetricsError("structured application logs are unavailable or unbounded")
    candidates: list[tuple[int, dict[str, Any], bytes]] = []
    for raw_line in stdout.splitlines():
        payload = raw_line.partition(b"|")[2].strip() if b"|" in raw_line else raw_line.strip()
        if not payload.startswith(b"{") or len(payload) > 64 * 1024:
            continue
        try:
            document = json.loads(payload.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict) or document.get("message") != "protocol_request":
            continue
        trace_id = document.get("traceId")
        endpoint = document.get("endpoint")
        method = document.get("method")
        outcome = document.get("outcome")
        log = document.get("log")
        level = log.get("level") if isinstance(log, dict) else None
        timestamp = document.get("@timestamp")
        if (
            not isinstance(trace_id, str) or TRACE_ID.fullmatch(trace_id) is None
            or endpoint not in PROTOCOL_ENDPOINTS
            or method not in {"GET", "POST", "DELETE", "OTHER"}
            or outcome not in {"SUCCESS", "RATE_LIMITED", "CLIENT_ERROR", "SERVER_ERROR", "OTHER"}
            or level != "INFO" or not isinstance(timestamp, str) or len(timestamp) > 64
        ):
            continue
        priority = 0 if endpoint == "mcp" else 1
        candidates.append((priority, document, payload))
    if not candidates:
        raise OperationalMetricsError("no bounded ECS protocol log retained its Trace ID")
    _, selected, payload = sorted(candidates, key=lambda item: item[0])[0]
    return {
        "format": "ecs",
        "timestamp": selected["@timestamp"],
        "level": selected["log"]["level"],
        "message": selected["message"],
        "traceId": selected["traceId"],
        "endpoint": selected["endpoint"],
        "method": selected["method"],
        "outcome": selected["outcome"],
        "sourceLineSha256": hashlib.sha256(payload).hexdigest(),
    }


def _write_private(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    finally:
        os.close(descriptor)
    temporary.replace(path)
    path.chmod(0o600)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--management-base-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--require-rate-limited", action="store_true")
    parser.add_argument("--require-audit-failure", action="store_true")
    parser.add_argument("--require-structured-log", action="store_true")
    parser.add_argument("--compose-file", type=Path)
    parser.add_argument("--compose-override", type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--compose-project")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        base_url = _base_url(args.management_base_url)
        username = _required_environment("WEB_STARTER_ACCEPTANCE_MANAGEMENT_USERNAME")
        password = _required_environment("WEB_STARTER_ACCEPTANCE_MANAGEMENT_PASSWORD")
        snapshot = capture(base_url, username, password)
        if args.baseline is None:
            document = {"schemaVersion": 1, "status": "SNAPSHOT", **snapshot}
        else:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            checks = evaluate(
                baseline,
                snapshot,
                args.require_rate_limited,
                args.require_audit_failure,
            )
            document = {
                "schemaVersion": 1,
                "status": "PASS" if all(checks.values()) else "FAIL",
                **snapshot,
                "baselineObservedAt": baseline.get("observedAt"),
                "checks": checks,
            }
            if args.require_structured_log:
                if any(value is None for value in (
                    args.compose_file, args.compose_override, args.env_file, args.compose_project,
                )):
                    raise OperationalMetricsError(
                        "structured-log verification requires exact Compose inputs"
                    )
                document["structuredLog"] = _structured_log_sample(
                    args.compose_file, args.compose_override, args.env_file,
                    args.compose_project,
                )
        _write_private(args.output, document)
    except (OperationalMetricsError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL operational-metrics: {error}", file=sys.stderr)
        return 1
    if document["status"] == "FAIL":
        print("FAIL operational-metrics: one or more runtime metric deltas did not increase")
        return 1
    print(f"PASS operational-metrics: {document['status'].lower()} captured without secrets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
