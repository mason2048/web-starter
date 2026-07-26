#!/usr/bin/env python3
"""Independently validate V2-AC-37 runtime observability evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence


SUMMARY_NAME = "v2-observability-runtime-summary.json"
SCHEMA_PATH = "security/v2-observability-runtime-summary.schema.json"
SOURCE_PATHS = (
    "scripts/verify_operational_metrics.py",
    "scripts/validate_observability_evidence.py",
    SCHEMA_PATH,
    "web-starter-admin/src/main/java/dev/webstarter/admin/config/OperationalMetricsConfiguration.java",
    "web-starter-admin/src/main/java/dev/webstarter/admin/web/ProtocolMetricsFilter.java",
    "web-starter-admin/src/main/java/dev/webstarter/admin/web/TraceIdFilter.java",
    "web-starter-admin/src/main/resources/application.yml",
    "web-starter-system/src/main/java/dev/webstarter/system/service/impl/AuditLogRecorderImpl.java",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/web/McpGovernanceFilter.java",
)
CUSTOM_TAGS: dict[str, dict[str, set[str]]] = {
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
METRICS = {*CUSTOM_TAGS, "hikaricp.connections.usage"}
PROTOCOL_ENDPOINTS = ("login", "oauth_token", "mcp")
AUTHORIZATION = {
    "healthAnonymous": 200,
    "infoAnonymous": 401,
    "metricsAnonymous": 401,
    "metricsWrongCredential": 401,
    "infoOperationalCredential": 200,
    "metricsOperationalCredential": 200,
    "prometheusOperationalCredential": 200,
}
EXPECTED_CHECKS = {
    "authorizationMatrix",
    "operationAuditCounterIncreased",
    "loginAttemptCounterIncreased",
    "mcpCallCounterIncreased",
    "mcpCallDurationCounterIncreased",
    "mcpSessionCounterIncreased",
    "hikariUsageCounterIncreased",
    "loginProtocolCounterIncreased",
    "oauth_tokenProtocolCounterIncreased",
    "mcpProtocolCounterIncreased",
    "rateLimitedCounterIncreased",
}
TRACE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ISO8601_TIMESTAMP = re.compile(
    r"^(?P<second>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<timezone>Z|[+-][0-9]{2}:[0-9]{2})$"
)
OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
IMAGE_REFERENCE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
SENSITIVE = re.compile(
    rb"(?i)(?:wst_(?:pat|svc)_[A-Za-z0-9._~-]{8,}|bearer\s+|"
    rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    rb"BEGIN (?:RSA )?PRIVATE KEY)"
)


class ObservabilityEvidenceError(ValueError):
    """Evidence is unsafe, stale or semantically incomplete."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ObservabilityEvidenceError(f"JSON repeats field {key}")
        result[key] = value
    return result


def _load_private(path: Path, label: str, maximum: int = 4 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise ObservabilityEvidenceError(f"{label} must be a real regular file")
    metadata = requested.stat()
    if (
        metadata.st_size <= 0 or metadata.st_size > maximum
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise ObservabilityEvidenceError(f"{label} must be an owned mode-0600 bounded file")
    payload = requested.read_bytes()
    if SENSITIVE.search(payload):
        raise ObservabilityEvidenceError(f"{label} contains credential-shaped material")
    try:
        document = json.loads(payload.decode("utf-8", errors="strict"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ObservabilityEvidenceError(f"{label} must be unique-key UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ObservabilityEvidenceError(f"{label} must contain one object")
    return document, payload


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ObservabilityEvidenceError(f"{label} has unexpected or missing fields")


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ObservabilityEvidenceError(f"{label} is not an ISO-8601 timestamp")
    matched = ISO8601_TIMESTAMP.fullmatch(value)
    if matched is None:
        raise ObservabilityEvidenceError(f"{label} is not an ISO-8601 timestamp")
    fraction = matched.group("fraction")
    normalised_fraction = "" if fraction is None else "." + fraction[:6].ljust(6, "0")
    zone = "+00:00" if matched.group("timezone") == "Z" else matched.group("timezone")
    try:
        # Python datetime stores microseconds, while Spring Boot's ECS formatter emits up to
        # nanoseconds. Parse the validated instant at microsecond precision without rejecting
        # otherwise valid ISO-8601 evidence.
        parsed = datetime.fromisoformat(matched.group("second") + normalised_fraction + zone)
    except ValueError as error:
        raise ObservabilityEvidenceError(f"{label} is not an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ObservabilityEvidenceError(f"{label} lacks a timezone")
    parsed = parsed.astimezone(timezone.utc)
    if parsed > datetime.now(timezone.utc):
        raise ObservabilityEvidenceError(f"{label} is in the future")
    return parsed


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ObservabilityEvidenceError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ObservabilityEvidenceError(f"{label} is negative or non-finite")
    return result


def _metric(value: Any, name: str, expected_tags: Mapping[str, set[str]] | None) -> float:
    if not isinstance(value, dict):
        raise ObservabilityEvidenceError(f"metric {name} must be an object")
    _exact(value, {"present", "measurements", "tags"}, f"metric {name}")
    if value.get("present") is not True:
        raise ObservabilityEvidenceError(f"metric {name} is absent")
    measurements = value.get("measurements")
    tags = value.get("tags")
    if not isinstance(measurements, dict) or "COUNT" not in measurements:
        raise ObservabilityEvidenceError(f"metric {name} lacks COUNT")
    for statistic, measurement in measurements.items():
        if not isinstance(statistic, str) or not statistic or len(statistic) > 64:
            raise ObservabilityEvidenceError(f"metric {name} has an invalid statistic")
        _number(measurement, f"metric {name} {statistic}")
    if not isinstance(tags, dict):
        raise ObservabilityEvidenceError(f"metric {name} tag document is invalid")
    if expected_tags is not None:
        if set(tags) != set(expected_tags):
            raise ObservabilityEvidenceError(f"metric {name} tag keys are not exact")
        for key, expected in expected_tags.items():
            values = tags.get(key)
            if not isinstance(values, list) or set(values) != expected \
                    or len(values) != len(expected) or any(not isinstance(item, str) for item in values):
                raise ObservabilityEvidenceError(f"metric {name} tag domain drifted")
    return _number(measurements["COUNT"], f"metric {name} COUNT")


def _snapshot(document: Mapping[str, Any], label: str, runtime: bool) -> dict[str, Any]:
    fields = {"schemaVersion", "status", "observedAt", "authorization", "metrics", "protocolEndpoints"}
    if runtime:
        fields |= {"baselineObservedAt", "checks", "structuredLog"}
    _exact(document, fields, label)
    expected_status = "PASS" if runtime else "SNAPSHOT"
    if document.get("schemaVersion") != 1 or document.get("status") != expected_status:
        raise ObservabilityEvidenceError(f"{label} status contract differs")
    observed = _timestamp(document.get("observedAt"), label + " observedAt")
    if document.get("authorization") != AUTHORIZATION:
        raise ObservabilityEvidenceError(f"{label} authorization matrix differs")
    metrics = document.get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != METRICS:
        raise ObservabilityEvidenceError(f"{label} metric inventory differs")
    counts = {
        name: _metric(metrics[name], name, CUSTOM_TAGS.get(name))
        for name in sorted(METRICS)
    }
    endpoints = document.get("protocolEndpoints")
    if not isinstance(endpoints, dict) or set(endpoints) != set(PROTOCOL_ENDPOINTS):
        raise ObservabilityEvidenceError(f"{label} protocol endpoint inventory differs")
    endpoint_counts = {
        endpoint: _metric(endpoints[endpoint], f"protocol endpoint {endpoint}", None)
        for endpoint in PROTOCOL_ENDPOINTS
    }
    return {"observed": observed, "counts": counts, "endpointCounts": endpoint_counts}


def validate_reports(baseline: Mapping[str, Any], runtime: Mapping[str, Any]) -> dict[str, str]:
    before = _snapshot(baseline, "operational metrics baseline", False)
    after = _snapshot(runtime, "operational metrics runtime", True)
    if after["observed"] < before["observed"] \
            or runtime.get("baselineObservedAt") != baseline.get("observedAt"):
        raise ObservabilityEvidenceError("operational metric observation order differs")
    checks = {
        "authorizationMatrix": True,
        "operationAuditCounterIncreased": after["counts"]["webstarter.audit.operations"] > before["counts"]["webstarter.audit.operations"],
        "loginAttemptCounterIncreased": after["counts"]["webstarter.login.attempts"] > before["counts"]["webstarter.login.attempts"],
        "mcpCallCounterIncreased": after["counts"]["webstarter.mcp.calls"] > before["counts"]["webstarter.mcp.calls"],
        "mcpCallDurationCounterIncreased": after["counts"]["webstarter.mcp.call.duration"] > before["counts"]["webstarter.mcp.call.duration"],
        "mcpSessionCounterIncreased": after["counts"]["webstarter.mcp.sessions"] > before["counts"]["webstarter.mcp.sessions"],
        "hikariUsageCounterIncreased": after["counts"]["hikaricp.connections.usage"] > before["counts"]["hikaricp.connections.usage"],
        "rateLimitedCounterIncreased": after["counts"]["webstarter.rate_limited"] > before["counts"]["webstarter.rate_limited"],
    }
    for endpoint in PROTOCOL_ENDPOINTS:
        checks[endpoint + "ProtocolCounterIncreased"] = (
            after["endpointCounts"][endpoint] > before["endpointCounts"][endpoint]
        )
    if set(checks) != EXPECTED_CHECKS or any(value is not True for value in checks.values()) \
            or runtime.get("checks") != checks:
        raise ObservabilityEvidenceError("operational metric deltas are not exact PASS")
    structured = runtime.get("structuredLog")
    if not isinstance(structured, dict):
        raise ObservabilityEvidenceError("structured log evidence is absent")
    _exact(structured, {
        "format", "timestamp", "level", "message", "traceId", "endpoint",
        "method", "outcome", "sourceLineSha256",
    }, "structured log evidence")
    if (
        structured.get("format") != "ecs" or structured.get("level") != "INFO"
        or structured.get("message") != "protocol_request"
        or not isinstance(structured.get("traceId"), str)
        or TRACE.fullmatch(structured["traceId"]) is None
        or structured.get("endpoint") not in PROTOCOL_ENDPOINTS
        or structured.get("method") not in {"GET", "POST", "DELETE", "OTHER"}
        or structured.get("outcome") not in {"SUCCESS", "RATE_LIMITED", "CLIENT_ERROR", "SERVER_ERROR", "OTHER"}
        or not isinstance(structured.get("sourceLineSha256"), str)
        or SHA256.fullmatch(structured["sourceLineSha256"]) is None
    ):
        raise ObservabilityEvidenceError("structured ECS log sample is incomplete")
    _timestamp(structured.get("timestamp"), "structured log timestamp")
    return {name: "PASS" for name in sorted(EXPECTED_CHECKS | {"structuredTraceLog"})}


def _git_run(root: Path, arguments: Sequence[str], maximum: int) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C", "LANG": "C"})
    completed = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *arguments], cwd=root,
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > maximum \
            or len(completed.stderr) > 64 * 1024:
        raise ObservabilityEvidenceError("candidate Git inspection failed safely")
    return completed.stdout


def _git(root: Path, arguments: Sequence[str]) -> str:
    return _git_run(root, arguments, 16 * 1024 * 1024).decode(
        "utf-8", errors="strict"
    ).strip()


def _candidate(root: Path, commit: str, version: str, tag: str) -> dict[str, Any]:
    candidate = root.resolve(strict=True)
    if OBJECT_ID.fullmatch(commit) is None or VERSION.fullmatch(version) is None \
            or tag != "v" + version or "SNAPSHOT" in version.upper():
        raise ObservabilityEvidenceError("candidate release identity is invalid")
    if _git(candidate, ["status", "--porcelain=v1", "--untracked-files=all"]):
        raise ObservabilityEvidenceError("observability candidate must be clean")
    if _git(candidate, ["rev-parse", "HEAD"]) != commit \
            or _git(candidate, ["cat-file", "-t", f"refs/tags/{tag}"]) != "tag" \
            or _git(candidate, ["rev-list", "-n", "1", tag]) != commit:
        raise ObservabilityEvidenceError("candidate commit or annotated tag differs")
    tree = _git(candidate, ["rev-parse", "HEAD^{tree}"])
    tag_object = _git(candidate, ["rev-parse", f"refs/tags/{tag}"])
    hashes: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        path = candidate / relative
        payload = path.read_bytes()
        committed = _git_run(candidate, ["show", f"HEAD:{relative}"], 8 * 1024 * 1024)
        if committed != payload:
            raise ObservabilityEvidenceError(f"candidate source binding differs: {relative}")
        hashes[relative] = hashlib.sha256(payload).hexdigest()
    return {"gitCommit": commit, "gitTree": tree, "tagObject": tag_object,
            "releaseVersion": version, "releaseTag": tag, "sourceSha256": hashes}


def validate(
    baseline_path: Path,
    runtime_path: Path,
    candidate_root: Path,
    runtime_identity_path: Path,
    compose_project: str,
    release_tag: str,
    output: Path | None,
) -> dict[str, Any]:
    baseline, baseline_payload = _load_private(baseline_path, "operational metrics baseline")
    runtime, runtime_payload = _load_private(runtime_path, "operational metrics runtime")
    identity, identity_payload = _load_private(runtime_identity_path, "runtime identity", 1024 * 1024)
    if PROJECT.fullmatch(compose_project) is None:
        raise ObservabilityEvidenceError("observability Compose project is invalid")
    release = identity.get("release") if isinstance(identity, dict) else None
    images = identity.get("images") if isinstance(identity, dict) else None
    if identity.get("schemaVersion") != 2 or identity.get("status") != "PASS" \
            or not isinstance(release, dict) or not isinstance(images, dict):
        raise ObservabilityEvidenceError("runtime identity prerequisite is not PASS")
    commit = release.get("gitCommit")
    version = release.get("version")
    if not isinstance(commit, str) or not isinstance(version, str):
        raise ObservabilityEvidenceError("runtime release identity is incomplete")
    binding = _candidate(candidate_root, commit, version, release_tag)
    image_binding: dict[str, dict[str, str]] = {}
    for service in ("app", "nginx"):
        image = images.get(service)
        if not isinstance(image, dict) or not isinstance(image.get("reference"), str) \
                or IMAGE_REFERENCE.fullmatch(image["reference"]) is None \
                or not isinstance(image.get("imageId"), str) \
                or IMAGE_ID.fullmatch(image["imageId"]) is None:
            raise ObservabilityEvidenceError("runtime App/Nginx identity is incomplete")
        image_binding[service] = {"reference": image["reference"], "imageId": image["imageId"]}
    checks = validate_reports(baseline, runtime)
    summary = {
        "schemaVersion": 1,
        "acceptanceIds": ["V2-AC-37"],
        "status": "PASS",
        "candidate": {key: binding[key] for key in (
            "gitCommit", "gitTree", "tagObject", "releaseVersion", "releaseTag"
        )},
        "runtime": {
            "composeProject": compose_project,
            "images": image_binding,
            "runtimeIdentitySha256": hashlib.sha256(identity_payload).hexdigest(),
        },
        "checks": checks,
        "evidence": {
            "baselineSha256": hashlib.sha256(baseline_payload).hexdigest(),
            "runtimeSha256": hashlib.sha256(runtime_payload).hexdigest(),
            "sourceSha256": dict(sorted(binding["sourceSha256"].items())),
        },
    }
    if output is not None:
        target = output.expanduser().absolute()
        if target.name != SUMMARY_NAME or target.exists() or target.is_symlink() \
                or target.parent.is_symlink() or not target.parent.is_dir() \
                or (os.name == "posix" and stat.S_IMODE(target.parent.stat().st_mode) != 0o700):
            raise ObservabilityEvidenceError("observability summary output is unsafe")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_summary_bytes(summary))
    return summary


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    return (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--runtime-identity", required=True, type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate(
            args.baseline, args.runtime, args.candidate_root, args.runtime_identity,
            args.compose_project, args.release_tag, args.output,
        )
    except (ObservabilityEvidenceError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL observability-evidence: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": summary["status"], "acceptanceIds": summary["acceptanceIds"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
