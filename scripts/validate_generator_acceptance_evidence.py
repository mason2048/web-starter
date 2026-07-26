#!/usr/bin/env python3
"""Independently validate candidate-bound V2-AC-08 through V2-AC-15 evidence.

The validator does not import the producer.  It snapshots the private raw
bundle, verifies the clean annotated release candidate and every committed
generator/producer/validator/schema blob, independently derives the runtime
relationships, and replays the offline generator in a disposable clone.  The
replay never starts Docker or executes generated application code.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable, Mapping, Sequence
import xml.etree.ElementTree as ET


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_FILE = "generator-acceptance.json"
CHECKSUM_FILE = EVIDENCE_FILE + ".sha256"
SUMMARY_FILE = "v2-generator-acceptance-summary.json"
PRODUCER_PATH = "scripts/rehearse_generator_acceptance.py"
VALIDATOR_PATH = "scripts/validate_generator_acceptance_evidence.py"
SCHEMA_PATH = "security/v2-generator-acceptance.schema.json"
SOURCE_PATHS = (
    "pom.xml",
    "web-starter-web/package.json",
    "bin/web-starter",
    "scripts/generated_module_plan.py",
    "scripts/repository_policy.py",
    "scripts/run_release_runtime_acceptance.sh",
    "web-starter-web/e2e/release-runtime.spec.ts",
    PRODUCER_PATH,
    VALIDATOR_PATH,
    SCHEMA_PATH,
    "web-starter-tooling/pom.xml",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/ChangePlan.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/Checks.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/CliOptions.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/Digests.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/GitTargetGuard.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/ToolingException.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/WorkspaceTransaction.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/cli/WebStarterCli.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/DeveloperCommands.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/ProcessExecutor.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/module/ModuleDeclarationReader.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/module/ModuleGenerator.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/module/ModuleSpec.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/module/ModuleTemplates.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/module/WorkspaceIdentity.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/project/ProjectInitializer.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/project/ProjectSpec.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/project/TrackedTemplate.java",
)
ACCEPTANCE_IDS = tuple(f"V2-AC-{number:02d}" for number in range(8, 16))
EXPECTED_ARTIFACTS = frozenset({
    "runtime-production-compose-policy.json",
    "runtime-version-identity.json",
    "operational-metrics-baseline.json",
    "oauth-runtime.json",
    "operational-metrics-runtime.json",
    "unified-verify-summary.json",
    "release-runtime-acceptance.json",
    "runtime-compose-ps.json",
})
GENERATED_ARTIFACT = "generated-module-runtime.json"
VERIFY_LAYERS = frozenset({
    "backend", "browser", "container", "frontend", "mcp", "oauth", "policy",
})
RUNTIME_CHECKS = frozenset({
    "authenticatedOperationalMetrics",
    "emptyVolumesAndMigrations",
    "privateBrowserProjectCrud",
    "privateBrowserAccountSecurity",
    "privateBrowserCredentialLifecycle",
    "oauthPkce",
    "oauthClientCredentials",
    "oauthMultiKeyJwksActiveSigning",
    "publicOperationsEndpointsHidden",
    "patPrivatePublicBoundary",
    "officialMcpSdkPublicOAuth",
    "officialMcpSdkPrivatePat",
    "officialMcpSdkCrudAudit",
    "runtimeVersionIdentity",
    "mysqlReadinessAndLiveness",
    "redisReadinessAndLiveness",
    "auditTraceSearchAndCorrelation",
    "unifiedSevenLayerVerify",
})
MCP_CRUD_TRACE_PREFIX = "release-sdk"
OAUTH_CHECKS = frozenset({
    "metadata", "multiKeyJwks", "activeSigningKid", "oauthMetadataConsistency",
    "dynamicClientRegistrationDisabled", "wwwAuthenticate", "clientCredentials",
    "clientCredentialsShortLived", "oauthPublicMcp", "patPrivateMcp",
    "patPublicRejected", "invalidOriginRejected", "publicManagementApiHidden",
    "publicOperationsEndpointsHidden",
})
METRIC_CHECKS = frozenset({
    "authorizationMatrix", "hikariUsageCounterIncreased",
    "loginAttemptCounterIncreased", "loginProtocolCounterIncreased",
    "mcpCallCounterIncreased", "mcpCallDurationCounterIncreased",
    "mcpProtocolCounterIncreased", "mcpSessionCounterIncreased",
    "oauth_tokenProtocolCounterIncreased", "operationAuditCounterIncreased",
    "rateLimitedCounterIncreased",
})
PROTOCOL_ENDPOINTS = frozenset({"login", "oauth_token", "mcp"})
PROTOCOL_METHODS = ("DELETE", "GET", "OTHER", "POST")
PROTOCOL_OUTCOMES = (
    "CLIENT_ERROR", "OTHER", "RATE_LIMITED", "SERVER_ERROR", "SUCCESS",
)
ECS_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
TRACE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
AUTHORIZATION_MATRIX = {
    "healthAnonymous": 200,
    "infoAnonymous": 401,
    "metricsAnonymous": 401,
    "metricsWrongCredential": 401,
    "infoOperationalCredential": 200,
    "metricsOperationalCredential": 200,
    "prometheusOperationalCredential": 200,
}
COMPOSE_SERVICES = frozenset({"mysql", "redis", "app", "nginx", "mcp-public-nginx"})

SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
PROJECT_NAME = re.compile(r"^[a-z][a-z0-9-]{2,49}$")
MODULE_NAME = re.compile(r"^[a-z][a-z0-9]{1,30}$")
SOURCE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        r"[\"']?(?:password|access_token|refresh_token|client_secret|code_verifier|cookie)"
        r"[\"']?\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"\bwst_(?:pat|svc)_[0-9A-Za-z._~-]{8,}", re.IGNORECASE),
)

TOP_FIELDS = frozenset({
    "schemaVersion", "acceptanceIds", "status", "observedAt", "candidate", "tooling",
    "derivedProject", "generatedModule", "stages", "cleanup", "evidencePolicy",
})
CANDIDATE_FIELDS = frozenset({
    "commit", "tree", "tag", "tagObject", "mavenVersion", "frontendVersion",
    "cleanWorktree", "sourceBlobs",
})
SOURCE_BLOB_FIELDS = frozenset({"gitBlob", "sha256"})
TOOLING_FIELDS = frozenset({"producerPath", "validatorPath", "schemaPath", "sourceCount"})
PROJECT_FIELDS = frozenset({
    "name", "productName", "groupId", "database", "environmentPrefix",
    "forbiddenTermsSha256",
})
MODULE_FIELDS = frozenset({
    "name", "label", "migrationVersion", "permissionIdBase", "menuId", "withMcp",
})
STAGE_FIELDS = frozenset({
    "name", "version", "commit", "tree", "buildContextSha256", "composeProject",
    "expectedModules", "expectedMcpModules", "images", "artifacts", "status",
})
IMAGE_FIELDS = frozenset({"reference", "imageId"})
CLEANUP_FIELDS = frozenset({
    "composeProjectsRemoved", "registryContainerRemoved", "generatedImageReferencesRemoved",
    "temporaryProjectTreeRemoved", "status",
})
POLICY_FIELDS = frozenset({
    "outsideRepository", "directoryMode", "fileMode", "onlyExpectedFiles",
    "rawSecretsPersisted",
})


class GeneratorEvidenceError(ValueError):
    """Raw generator evidence is unsafe, forged, stale, or semantically incomplete."""


@dataclass(frozen=True)
class FileSnapshot:
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int
    sha256: str
    payload: bytes


@dataclass(frozen=True)
class BundleSnapshot:
    root_device: int
    root_inode: int
    root_modified_ns: int
    files: dict[str, FileSnapshot]


@dataclass(frozen=True)
class ReplayResult:
    project_tree: str
    module_tree: str
    generated_plan: dict[str, Any]
    check_names: tuple[str, ...]


def _exact(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    required = set(expected)
    if actual != required:
        raise GeneratorEvidenceError(
            f"{label} fields are not exact (missing={','.join(sorted(required - actual))}; "
            f"unknown={','.join(sorted(actual - required))})"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GeneratorEvidenceError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GeneratorEvidenceError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise GeneratorEvidenceError(f"{label} must be a string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise GeneratorEvidenceError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GeneratorEvidenceError(f"{label} must be an integer >= {minimum}")
    return value


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = _string(value, label)
    if pattern.fullmatch(text) is None:
        raise GeneratorEvidenceError(f"{label} has an invalid format")
    return text


def _timestamp(value: Any, label: str) -> str:
    text = _string(value, label)
    if len(text) > 64:
        raise GeneratorEvidenceError(f"{label} is too long")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exception:
        raise GeneratorEvidenceError(f"{label} is not an RFC 3339 timestamp") from exception
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GeneratorEvidenceError(f"{label} must include a timezone")
    return text


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GeneratorEvidenceError(f"JSON object repeats field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise GeneratorEvidenceError(f"JSON contains non-finite number: {value}")


def _load_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    if any(pattern.search(payload.decode("utf-8", errors="ignore")) for pattern in SECRET_PATTERNS):
        raise GeneratorEvidenceError(f"{label} contains secret-shaped material")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise GeneratorEvidenceError(f"{label} is not strict UTF-8 JSON") from exception
    return _object(value, label)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _snapshot_file(path: Path, label: str) -> FileSnapshot:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise GeneratorEvidenceError(f"{label} must be a regular non-symlink file")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise GeneratorEvidenceError(f"{label} mode must be exactly 0600")
        if before.st_size > 2 * 1024 * 1024:
            raise GeneratorEvidenceError(f"{label} exceeds the 2 MiB limit")
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exception:
        raise GeneratorEvidenceError(f"{label} cannot be read") from exception
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(payload) != before.st_size:
        raise GeneratorEvidenceError(f"{label} changed while it was read")
    return FileSnapshot(
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        stat.S_IMODE(before.st_mode), _sha256_bytes(payload), payload,
    )


def _snapshot_bundle(bundle: Path, repository: Path) -> BundleSnapshot:
    raw = bundle.expanduser().absolute()
    if raw.is_symlink() or not raw.is_dir():
        raise GeneratorEvidenceError("evidence bundle must be a non-symlink directory")
    root = raw.resolve(strict=True)
    if _inside(root, repository):
        raise GeneratorEvidenceError("evidence bundle must remain outside the repository")
    root_stat = root.lstat()
    if stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise GeneratorEvidenceError("evidence bundle mode must be exactly 0700")
    if {path.name for path in root.iterdir()} != {EVIDENCE_FILE, CHECKSUM_FILE, "stages"}:
        raise GeneratorEvidenceError("evidence bundle root file set is not exact")
    stages = root / "stages"
    if stages.is_symlink() or not stages.is_dir() or stat.S_IMODE(stages.stat().st_mode) != 0o700:
        raise GeneratorEvidenceError("evidence stages directory must be a real 0700 directory")
    if {path.name for path in stages.iterdir()} != {"project", "module"}:
        raise GeneratorEvidenceError("evidence stage directory set is not exact")
    files: dict[str, FileSnapshot] = {
        EVIDENCE_FILE: _snapshot_file(root / EVIDENCE_FILE, EVIDENCE_FILE),
        CHECKSUM_FILE: _snapshot_file(root / CHECKSUM_FILE, CHECKSUM_FILE),
    }
    for stage_name in ("project", "module"):
        stage = stages / stage_name
        if stage.is_symlink() or not stage.is_dir() or stat.S_IMODE(stage.stat().st_mode) != 0o700:
            raise GeneratorEvidenceError(f"{stage_name} stage must be a real 0700 directory")
        expected = set(EXPECTED_ARTIFACTS)
        if stage_name == "module":
            expected.add(GENERATED_ARTIFACT)
        actual = {path.name for path in stage.iterdir()}
        if actual != expected:
            raise GeneratorEvidenceError(f"{stage_name} stage file set is not exact")
        for name in sorted(expected):
            relative = f"stages/{stage_name}/{name}"
            files[relative] = _snapshot_file(stage / name, relative)
    return BundleSnapshot(
        root_stat.st_dev, root_stat.st_ino, root_stat.st_mtime_ns, files
    )


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    expect_success: bool = True,
    timeout: int = 900,
    label: str,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command), cwd=cwd, env=None if environment is None else dict(environment),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        raise GeneratorEvidenceError(f"{label} did not complete") from exception
    if expect_success != (completed.returncode == 0):
        raise GeneratorEvidenceError(
            f"{label} returned unexpected exit {completed.returncode}"
        )
    return completed


def _git(repository: Path, *arguments: str, label: str) -> str:
    return _run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
         "-c", "core.hooksPath=/dev/null", "-C", str(repository), *arguments],
        environment=_git_environment(), timeout=120, label=label,
    ).stdout.strip()


def _git_blob_bytes(repository: Path, blob: str, label: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
             "-c", "core.hooksPath=/dev/null", "-C", str(repository),
             "cat-file", "blob", blob],
            env=_git_environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        raise GeneratorEvidenceError(f"{label} did not complete") from exception
    if completed.returncode != 0:
        raise GeneratorEvidenceError(f"{label} failed")
    return completed.stdout


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key in {
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_TEMPLATE_DIR", "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def _root_versions(repository: Path) -> tuple[str, str]:
    try:
        root = ET.parse(repository / "pom.xml").getroot()
    except (OSError, ET.ParseError) as exception:
        raise GeneratorEvidenceError("candidate root POM is invalid") from exception
    namespace = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
    maven = (root.findtext(namespace + "version") or "").strip()
    frontend = _load_json_bytes(
        (repository / "web-starter-web/package.json").read_bytes(), "frontend manifest"
    ).get("version")
    if not isinstance(frontend, str):
        raise GeneratorEvidenceError("frontend version is missing")
    for value, label in ((maven, "Maven"), (frontend, "frontend")):
        if VERSION.fullmatch(value) is None or "snapshot" in value.lower():
            raise GeneratorEvidenceError(f"candidate {label} version must be non-SNAPSHOT")
    if maven != frontend:
        raise GeneratorEvidenceError("candidate Maven and frontend versions differ")
    return maven, frontend


def _verify_candidate(candidate_value: Any, repository: Path) -> dict[str, Any]:
    candidate = _object(candidate_value, "candidate")
    _exact(candidate, CANDIDATE_FIELDS, "candidate")
    commit = _pattern(candidate["commit"], GIT_OBJECT, "candidate.commit")
    tree = _pattern(candidate["tree"], GIT_OBJECT, "candidate.tree")
    tag_object = _pattern(candidate["tagObject"], GIT_OBJECT, "candidate.tagObject")
    if candidate["cleanWorktree"] is not True:
        raise GeneratorEvidenceError("candidate.cleanWorktree must be true")
    status = _git(
        repository, "status", "--porcelain=v1", "--untracked-files=all",
        label="candidate clean-worktree check",
    )
    actual_commit = _git(repository, "rev-parse", "HEAD^{commit}", label="candidate HEAD")
    actual_tree = _git(repository, "rev-parse", "HEAD^{tree}", label="candidate tree")
    if status or actual_commit != commit or actual_tree != tree:
        raise GeneratorEvidenceError("candidate is dirty or differs from evidence")
    maven, frontend = _root_versions(repository)
    if candidate["mavenVersion"] != maven or candidate["frontendVersion"] != frontend:
        raise GeneratorEvidenceError("candidate version binding differs from committed manifests")
    expected_tag = "v" + maven
    if candidate["tag"] != expected_tag:
        raise GeneratorEvidenceError("candidate tag must equal v plus the release version")
    actual_tag_object = _git(
        repository, "rev-parse", f"refs/tags/{expected_tag}", label="release tag object"
    )
    tag_type = _git(repository, "cat-file", "-t", actual_tag_object, label="release tag type")
    tagged_commit = _git(
        repository, "rev-parse", f"refs/tags/{expected_tag}^{{commit}}",
        label="release tag commit",
    )
    tagged_tree = _git(
        repository, "rev-parse", f"refs/tags/{expected_tag}^{{tree}}", label="release tag tree"
    )
    if (
        actual_tag_object != tag_object or tag_type != "tag"
        or tagged_commit != commit or tagged_tree != tree
    ):
        raise GeneratorEvidenceError("candidate is not bound to the exact annotated release tag")

    sources = _object(candidate["sourceBlobs"], "candidate.sourceBlobs")
    _exact(sources, SOURCE_PATHS, "candidate.sourceBlobs")
    for relative in SOURCE_PATHS:
        if SOURCE_PATH.fullmatch(relative) is None:
            raise GeneratorEvidenceError("frozen source path is unsafe")
        binding = _object(sources[relative], f"source binding {relative}")
        _exact(binding, SOURCE_BLOB_FIELDS, f"source binding {relative}")
        blob = _pattern(binding["gitBlob"], GIT_OBJECT, f"source blob {relative}")
        digest = _pattern(binding["sha256"], SHA256, f"source SHA-256 {relative}")
        actual_blob = _git(
            repository, "rev-parse", f"{commit}:{relative}", label=f"source blob {relative}"
        )
        if actual_blob != blob or _git(
            repository, "cat-file", "-t", blob, label=f"source blob type {relative}"
        ) != "blob":
            raise GeneratorEvidenceError(f"source blob differs from candidate: {relative}")
        committed = _git_blob_bytes(repository, blob, f"source blob bytes {relative}")
        current = repository / relative
        if current.is_symlink() or not current.is_file():
            raise GeneratorEvidenceError(f"candidate source path is unsafe: {relative}")
        current_bytes = current.read_bytes()
        if _sha256_bytes(committed) != digest or current_bytes != committed:
            raise GeneratorEvidenceError(f"source bytes differ from candidate: {relative}")
    executing_validator_input = Path(__file__)
    executing_validator = executing_validator_input.resolve(strict=True)
    if (
        executing_validator_input.is_symlink()
        or _sha256_bytes(executing_validator.read_bytes())
        != sources[VALIDATOR_PATH]["sha256"]
    ):
        raise GeneratorEvidenceError(
            "executing generator validator differs from the committed candidate"
        )
    return candidate


def _validate_tooling(document: Mapping[str, Any], candidate: Mapping[str, Any]) -> None:
    tooling = _object(document["tooling"], "tooling")
    _exact(tooling, TOOLING_FIELDS, "tooling")
    if tooling != {
        "producerPath": PRODUCER_PATH,
        "validatorPath": VALIDATOR_PATH,
        "schemaPath": SCHEMA_PATH,
        "sourceCount": len(SOURCE_PATHS),
    }:
        raise GeneratorEvidenceError("tooling identity differs from the frozen validator contract")
    sources = _object(candidate["sourceBlobs"], "candidate.sourceBlobs")
    for relative in (PRODUCER_PATH, VALIDATOR_PATH, SCHEMA_PATH):
        if relative not in sources:
            raise GeneratorEvidenceError("producer, validator, and schema must be source-bound")


def _validate_metric(
    document: dict[str, Any],
    baseline: dict[str, Any] | None,
    project_name: str,
) -> None:
    common = {
        "schemaVersion", "status", "observedAt", "authorization", "metrics",
        "protocolEndpoints",
    }
    expected = common if baseline is None else common | {
        "baselineObservedAt", "checks", "structuredLog",
    }
    _exact(document, expected, "operational metrics artifact")
    if document["schemaVersion"] != 1:
        raise GeneratorEvidenceError("operational metrics schema is unsupported")
    expected_status = "SNAPSHOT" if baseline is None else "PASS"
    if document["status"] != expected_status:
        raise GeneratorEvidenceError("operational metrics status is inconsistent")
    _timestamp(document["observedAt"], "operational metrics observedAt")
    if document["authorization"] != AUTHORIZATION_MATRIX:
        raise GeneratorEvidenceError("operational metrics authorization matrix is incomplete")
    compact_name = project_name.replace("-", "")
    expected_metrics = {
        f"{compact_name}.audit.operations",
        f"{compact_name}.audit.persist.failures",
        f"{compact_name}.login.attempts",
        f"{compact_name}.mcp.calls",
        f"{compact_name}.mcp.call.duration",
        f"{compact_name}.mcp.rate_limited",
        f"{compact_name}.mcp.sessions",
        f"{compact_name}.protocol.requests",
        f"{compact_name}.rate_limited",
        "hikaricp.connections.usage",
    }
    metrics = _object(document["metrics"], "operational metrics")
    if set(metrics) != expected_metrics:
        raise GeneratorEvidenceError("operational metrics set is incomplete")
    for name, metric_value in metrics.items():
        if not isinstance(name, str) or len(name) > 128:
            raise GeneratorEvidenceError("operational metric name is unsafe")
        metric = _object(metric_value, f"metric {name}")
        _exact(metric, {"present", "measurements", "tags"}, f"metric {name}")
        _boolean(metric["present"], f"metric {name} present")
        measurements = _object(metric["measurements"], f"metric {name} measurements")
        for measurement in measurements.values():
            if isinstance(measurement, bool) or not isinstance(measurement, (int, float)) \
                    or not math.isfinite(float(measurement)):
                raise GeneratorEvidenceError("metric contains a non-finite measurement")
        _object(metric["tags"], f"metric {name} tags")

    protocol_endpoints = _object(
        document["protocolEndpoints"], "operational protocol endpoint metrics"
    )
    if set(protocol_endpoints) != set(PROTOCOL_ENDPOINTS):
        raise GeneratorEvidenceError(
            "operational protocol endpoint metric set is incomplete"
        )
    for endpoint in PROTOCOL_ENDPOINTS:
        metric = _object(
            protocol_endpoints[endpoint],
            f"operational protocol endpoint metric {endpoint}",
        )
        _exact(
            metric,
            {"present", "measurements", "tags"},
            f"operational protocol endpoint metric {endpoint}",
        )
        measurements = _object(
            metric["measurements"],
            f"operational protocol endpoint metric {endpoint} measurements",
        )
        tags = _object(
            metric["tags"],
            f"operational protocol endpoint metric {endpoint} tags",
        )
        count = measurements.get("COUNT")
        if (
            metric["present"] is not True
            or set(measurements) != {"COUNT"}
            or isinstance(count, bool)
            or not isinstance(count, (int, float))
            or not math.isfinite(float(count))
            or tags != {
                "method": list(PROTOCOL_METHODS),
                "outcome": list(PROTOCOL_OUTCOMES),
            }
        ):
            raise GeneratorEvidenceError(
                f"operational protocol endpoint metric {endpoint} is not exact"
            )
    if baseline is not None:
        if document["baselineObservedAt"] != baseline["observedAt"]:
            raise GeneratorEvidenceError("metrics runtime does not bind its baseline")
        checks = _object(document["checks"], "metrics checks")
        if set(checks) != set(METRIC_CHECKS) or any(value is not True for value in checks.values()):
            raise GeneratorEvidenceError("metrics runtime checks are incomplete")
        structured_log = _object(
            document["structuredLog"], "operational structured log proof"
        )
        _exact(
            structured_log,
            {
                "format", "timestamp", "level", "message", "traceId", "endpoint",
                "method", "outcome", "sourceLineSha256",
            },
            "operational structured log proof",
        )
        if (
            structured_log["format"] != "ecs"
            or not isinstance(structured_log["timestamp"], str)
            or ECS_TIMESTAMP.fullmatch(structured_log["timestamp"]) is None
            or structured_log["level"] != "INFO"
            or structured_log["message"] != "protocol_request"
            or not isinstance(structured_log["traceId"], str)
            or TRACE_ID.fullmatch(structured_log["traceId"]) is None
            or structured_log["endpoint"] not in PROTOCOL_ENDPOINTS
            or structured_log["method"] not in PROTOCOL_METHODS
            or structured_log["outcome"] not in PROTOCOL_OUTCOMES
            or not isinstance(structured_log["sourceLineSha256"], str)
            or SHA256.fullmatch(structured_log["sourceLineSha256"]) is None
        ):
            raise GeneratorEvidenceError(
                "operational structured log proof is not exact"
            )


def _stage_json(snapshot: BundleSnapshot, stage: str, name: str) -> dict[str, Any]:
    return _load_json_bytes(snapshot.files[f"stages/{stage}/{name}"].payload, f"{stage}/{name}")


def _validate_stage(
    stage_value: Any,
    *,
    stage_name: str,
    snapshot: BundleSnapshot,
    project: Mapping[str, Any],
    module: Mapping[str, Any],
    version: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    stage = _object(stage_value, f"{stage_name} stage")
    _exact(stage, STAGE_FIELDS, f"{stage_name} stage")
    if stage["name"] != stage_name or stage["status"] != "PASS" or stage["version"] != version:
        raise GeneratorEvidenceError(f"{stage_name} stage identity/status is invalid")
    commit = _pattern(stage["commit"], GIT_OBJECT, f"{stage_name} stage commit")
    _pattern(stage["tree"], GIT_OBJECT, f"{stage_name} stage tree")
    _pattern(stage["buildContextSha256"], SHA256, f"{stage_name} build context")
    expected_module = "-" if stage_name == "project" else module["name"]
    if stage["expectedModules"] != expected_module or stage["expectedMcpModules"] != expected_module:
        raise GeneratorEvidenceError(f"{stage_name} stage module expectation is invalid")
    if not re.fullmatch(rf"wsgen-[a-z0-9]{{12}}-{stage_name}", stage["composeProject"]):
        raise GeneratorEvidenceError(f"{stage_name} Compose project is not isolated")
    images = _object(stage["images"], f"{stage_name} images")
    _exact(images, {"app", "nginx"}, f"{stage_name} images")
    for role in ("app", "nginx"):
        image = _object(images[role], f"{stage_name} {role} image")
        _exact(image, IMAGE_FIELDS, f"{stage_name} {role} image")
        _pattern(image["reference"], DIGEST_REFERENCE, f"{stage_name} {role} reference")
        _pattern(image["imageId"], IMAGE_ID, f"{stage_name} {role} image ID")
    if images["app"] == images["nginx"]:
        raise GeneratorEvidenceError(f"{stage_name} App and Nginx images are aliased")

    expected_artifacts = set(EXPECTED_ARTIFACTS)
    if stage_name == "module":
        expected_artifacts.add(GENERATED_ARTIFACT)
    artifacts = _object(stage["artifacts"], f"{stage_name} artifacts")
    _exact(artifacts, expected_artifacts, f"{stage_name} artifacts")
    for name in expected_artifacts:
        declared = _pattern(artifacts[name], SHA256, f"{stage_name} artifact {name}")
        actual = snapshot.files[f"stages/{stage_name}/{name}"].sha256
        if declared != actual:
            raise GeneratorEvidenceError(f"{stage_name} artifact hash differs: {name}")

    unified = _stage_json(snapshot, stage_name, "unified-verify-summary.json")
    expected_layers = {name: "PASS" for name in sorted(VERIFY_LAYERS)}
    if unified != {"schemaVersion": 1, "status": "PASS", "layers": expected_layers}:
        raise GeneratorEvidenceError(f"{stage_name} seven-layer evidence is incomplete")

    identity = _stage_json(snapshot, stage_name, "runtime-version-identity.json")
    _exact(identity, {"schemaVersion", "status", "observedAt", "release", "java", "actuator", "images"},
           f"{stage_name} runtime identity")
    if identity["schemaVersion"] != 2 or identity["status"] != "PASS":
        raise GeneratorEvidenceError(f"{stage_name} runtime identity is not complete")
    _timestamp(identity["observedAt"], f"{stage_name} runtime observedAt")
    if identity["release"] != {"version": version, "gitCommit": commit}:
        raise GeneratorEvidenceError(f"{stage_name} runtime release identity differs")
    java = _object(identity["java"], f"{stage_name} Java identity")
    if java.get("specificationVersion") != "21" or not isinstance(java.get("runtimeVersion"), str) \
            or re.match(r"^21(?:[.+-]|$)", java["runtimeVersion"]) is None:
        raise GeneratorEvidenceError(f"{stage_name} did not run Java 21")
    if identity["actuator"] != {
        "applicationVersion": version,
        "buildVersion": version,
        "buildArtifact": project["name"] + "-admin",
        "buildGroup": project["groupId"],
    }:
        raise GeneratorEvidenceError(f"{stage_name} Actuator identity differs")
    runtime_images = _object(identity["images"], f"{stage_name} runtime images")
    _exact(runtime_images, {"app", "nginx", "mysql", "redis"}, f"{stage_name} runtime images")
    for role in ("app", "nginx"):
        expected = {
            "reference": images[role]["reference"],
            "imageId": images[role]["imageId"],
            "ociVersion": version,
            "ociRevision": commit,
        }
        if runtime_images[role] != expected:
            raise GeneratorEvidenceError(f"{stage_name} {role} runtime image differs")
    for role in ("mysql", "redis"):
        dependency = _object(runtime_images[role], f"{stage_name} {role} runtime image")
        _exact(dependency, {"reference", "imageId", "ociVersion", "ociRevision"},
               f"{stage_name} {role} runtime image")
        _pattern(dependency["reference"], DIGEST_REFERENCE, f"{stage_name} {role} reference")
        _pattern(dependency["imageId"], IMAGE_ID, f"{stage_name} {role} image ID")
        if dependency["ociVersion"] is not None or dependency["ociRevision"] is not None:
            raise GeneratorEvidenceError(f"{stage_name} invents OCI labels for {role}")
    ids = [runtime_images[name]["imageId"] for name in ("app", "nginx", "mysql", "redis")]
    refs = [runtime_images[name]["reference"] for name in ("app", "nginx", "mysql", "redis")]
    if len(ids) != len(set(ids)) or len(refs) != len(set(refs)):
        raise GeneratorEvidenceError(f"{stage_name} runtime images are aliased")

    release = _stage_json(snapshot, stage_name, "release-runtime-acceptance.json")
    _exact(release, {"schemaVersion", "status", "observedAt", "release", "images", "identity", "checks", "unifiedVerify"},
           f"{stage_name} release runtime")
    _timestamp(release["observedAt"], f"{stage_name} release observedAt")
    if release["schemaVersion"] != 1 or release["status"] != "PASS" \
            or release["release"] != {"tag": "v" + version, "version": version, "gitCommit": commit} \
            or release["images"] != {role: images[role]["reference"] for role in ("app", "nginx")}:
        raise GeneratorEvidenceError(f"{stage_name} release runtime identity is inconsistent")
    if release["identity"] != {
        "javaSpecificationVersion": "21",
        "applicationVersion": version,
        "buildVersion": version,
        "composeProject": stage["composeProject"],
        "mcpCrudTracePrefix": MCP_CRUD_TRACE_PREFIX,
        "appImage": images["app"]["reference"],
        "nginxImage": images["nginx"]["reference"],
        "appOciVersion": version,
        "appOciRevision": commit,
        "nginxOciVersion": version,
        "nginxOciRevision": commit,
    }:
        raise GeneratorEvidenceError(f"{stage_name} release runtime identity fields differ")
    checks = _object(release["checks"], f"{stage_name} runtime checks")
    if set(checks) != set(RUNTIME_CHECKS) or any(value != "PASS" for value in checks.values()):
        raise GeneratorEvidenceError(f"{stage_name} runtime behavioral check set is incomplete")
    if release["unifiedVerify"] != {
        "path": "unified-verify-summary.json",
        "sha256": snapshot.files[f"stages/{stage_name}/unified-verify-summary.json"].sha256,
        "status": "PASS",
        "layers": expected_layers,
    }:
        raise GeneratorEvidenceError(f"{stage_name} runtime does not bind unified evidence")

    policy = _stage_json(snapshot, stage_name, "runtime-production-compose-policy.json")
    _exact(policy, {"schemaVersion", "status", "composeSha256", "errors"}, f"{stage_name} Compose policy")
    if policy["schemaVersion"] != 1 or policy["status"] != "PASS" or policy["errors"] != []:
        raise GeneratorEvidenceError(f"{stage_name} production Compose policy is not exact PASS")
    _pattern(policy["composeSha256"], SHA256, f"{stage_name} Compose SHA-256")

    oauth = _stage_json(snapshot, stage_name, "oauth-runtime.json")
    _exact(oauth, {"schemaVersion", "status", "checks"}, f"{stage_name} OAuth")
    oauth_checks = _object(oauth["checks"], f"{stage_name} OAuth checks")
    if oauth["schemaVersion"] != 1 or oauth["status"] != "PASS" \
            or set(oauth_checks) != set(OAUTH_CHECKS) \
            or any(value != "PASS" for value in oauth_checks.values()):
        raise GeneratorEvidenceError(f"{stage_name} OAuth evidence is incomplete")

    baseline = _stage_json(snapshot, stage_name, "operational-metrics-baseline.json")
    runtime = _stage_json(snapshot, stage_name, "operational-metrics-runtime.json")
    _validate_metric(baseline, None, project["name"])
    _validate_metric(runtime, baseline, project["name"])

    compose = _stage_json(snapshot, stage_name, "runtime-compose-ps.json")
    _exact(compose, {"schemaVersion", "services"}, f"{stage_name} Compose status")
    services = _array(compose["services"], f"{stage_name} Compose services")
    observed: set[str] = set()
    for service_value in services:
        service = _object(service_value, f"{stage_name} Compose service")
        _exact(service, {"service", "state", "health"}, f"{stage_name} Compose service")
        if service["service"] in observed or service["service"] not in COMPOSE_SERVICES \
                or service["state"] != "running" or service["health"] != "healthy":
            raise GeneratorEvidenceError(f"{stage_name} Compose service is not uniquely healthy")
        observed.add(service["service"])
    if compose["schemaVersion"] != 1 or observed != set(COMPOSE_SERVICES):
        raise GeneratorEvidenceError(f"{stage_name} Compose service set is incomplete")

    generated: dict[str, Any] | None = None
    if stage_name == "module":
        generated_document = _stage_json(snapshot, stage_name, GENERATED_ARTIFACT)
        _exact(generated_document, {"schemaVersion", "status", "modules"}, "generated module runtime")
        modules = _array(generated_document["modules"], "generated module runtime modules")
        if generated_document["schemaVersion"] != 1 or generated_document["status"] != "PASS" or len(modules) != 1:
            raise GeneratorEvidenceError("generated module runtime is not exactly one module")
        generated = _object(modules[0], "generated module runtime item")
        _exact(generated, {
            "module", "artifactId", "migrationSha256", "planSha256", "browserTestSha256",
            "browserStatus", "mcpRuntimeTestSha256", "mcpStatus",
        }, "generated module runtime item")
        if generated["module"] != module["name"] \
                or generated["artifactId"] != project["name"] + "-" + module["name"] \
                or generated["browserStatus"] != "PASS" or generated["mcpStatus"] != "PASS":
            raise GeneratorEvidenceError("generated module runtime identity/status is inconsistent")
        for name in ("migrationSha256", "planSha256", "browserTestSha256", "mcpRuntimeTestSha256"):
            _pattern(generated[name], SHA256, f"generated module {name}")
    return stage, generated


def _tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    ignored = {".git", "target", "node_modules", "dist", "playwright-report", "test-results"}
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(name for name in directories if name not in ignored)
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                raise GeneratorEvidenceError("semantic replay tree contains a symbolic link")
            relative = path.relative_to(root).as_posix()
            digest.update(b"D\0" + relative.encode() + b"\0")
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise GeneratorEvidenceError("semantic replay tree contains an unsafe file")
            relative = path.relative_to(root).as_posix()
            digest.update(b"F\0" + relative.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def _initialize_git(project: Path, environment: Mapping[str, str]) -> str:
    _run(["git", "init", "--quiet"], cwd=project, environment=environment, label="replay Git init")
    _run(["git", "-c", "core.hooksPath=/dev/null", "add", "--all"], cwd=project,
         environment=environment, label="replay Git add")
    tree = _run(["git", "write-tree"], cwd=project, environment=environment,
                label="replay project tree").stdout.strip()
    _run([
        "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
        "-c", "user.name=Web Starter Evidence", "-c", "user.email=evidence@example.invalid",
        "commit", "--quiet", "-m", "Replay generated project",
    ], cwd=project, environment=environment, label="replay project commit")
    return _pattern(tree, GIT_OBJECT, "replay project tree")


def _project_arguments(template: Path, output: Path, project: Mapping[str, Any]) -> list[str]:
    return [
        str(template / "bin/web-starter"), "project", "init",
        "--source", str(template), "--name", project["name"],
        "--product-name", project["productName"], "--group-id", project["groupId"],
        "--package-prefix", project["groupId"], "--database", project["database"],
        "--env-prefix", project["environmentPrefix"], "--output", str(output),
    ]


def _module_declaration(path: Path, module: Mapping[str, Any]) -> None:
    document = {
        "schemaVersion": 1,
        "name": module["name"],
        "label": module["label"],
        "migrationVersion": module["migrationVersion"],
        "permissionIdBase": int(module["permissionIdBase"]),
        "menuId": int(module["menuId"]),
    }
    path.write_text(json.dumps(document, ensure_ascii=False) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _module_command(wrapper: Path, action: str, workspace: Path, declaration: Path, with_mcp: bool = False) -> list[str]:
    result = [
        str(wrapper), "module", action, "--workspace", str(workspace),
        "--declaration", str(declaration),
    ]
    if with_mcp:
        result.append("--with-mcp")
    return result


def _replay_generator(
    repository: Path,
    candidate: Mapping[str, Any],
    project: Mapping[str, Any],
    module: Mapping[str, Any],
    forbidden_terms: Path,
) -> ReplayResult:
    environment = _git_environment()
    checks: list[str] = []
    with tempfile.TemporaryDirectory(prefix="web-starter-generator-validator-") as temporary:
        work = Path(temporary).resolve()
        os.chmod(work, 0o700)
        template = work / "template"
        _run([
            "git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--no-local",
            "--no-checkout", str(repository), str(template),
        ], environment=environment, label="candidate replay clone")
        _run([
            "git", "-c", "core.hooksPath=/dev/null", "checkout", "--quiet", "--detach",
            candidate["commit"],
        ], cwd=template, environment=environment, label="candidate replay checkout")
        _run([
            "./mvnw", "--batch-mode", "--no-transfer-progress", "-pl", "web-starter-tooling",
            "-am", "package", "-DskipTests",
        ], cwd=template, environment=environment, timeout=1800, label="candidate tooling replay build")

        dry_output = work / "dry-project"
        _run([*_project_arguments(template, dry_output, project), "--dry-run"], cwd=template,
             environment=environment, label="project dry-run replay")
        if dry_output.exists() or dry_output.is_symlink():
            raise GeneratorEvidenceError("project dry-run wrote its output")
        checks.append("projectDryRunZeroWrite")

        occupied = work / "occupied-project"
        occupied.mkdir()
        (occupied / "sentinel.txt").write_text("unchanged\n", encoding="utf-8")
        before = _tree_fingerprint(occupied)
        _run(_project_arguments(template, occupied, project), cwd=template, environment=environment,
             expect_success=False, label="occupied project boundary replay")
        if _tree_fingerprint(occupied) != before:
            raise GeneratorEvidenceError("occupied project failure wrote output")
        checks.append("projectOccupiedTargetZeroWrite")

        inside_output = template / "forbidden-derived-output"
        before = _tree_fingerprint(template)
        _run(_project_arguments(template, inside_output, project), cwd=template, environment=environment,
             expect_success=False, label="inside-template output boundary replay")
        if inside_output.exists() or _tree_fingerprint(template) != before:
            raise GeneratorEvidenceError("inside-template project failure wrote output")
        checks.append("projectInsideTemplateZeroWrite")

        invalid_output = work / "invalid-project"
        invalid = _project_arguments(template, invalid_output, project)
        invalid[invalid.index("--name") + 1] = "Invalid/Project"
        _run(invalid, cwd=template, environment=environment, expect_success=False,
             label="invalid project name replay")
        if invalid_output.exists() or invalid_output.is_symlink():
            raise GeneratorEvidenceError("invalid project identity wrote output")
        checks.append("projectInvalidIdentityZeroWrite")

        generated = work / project["name"]
        _run(_project_arguments(template, generated, project), cwd=template,
             environment=environment, label="parameterized project generation replay")
        if (generated / ".git").exists() or not (
            generated / f"{project['name']}-admin/src/main/java"
            / Path(project["groupId"].replace(".", "/"))
        ).is_dir():
            raise GeneratorEvidenceError("parameterized project output identity is incomplete")
        for command, label in (
            ([sys.executable, "-B", "scripts/repository_policy.py", "secrets", "--root", str(generated)],
             "replayed generated project secret scan"),
            ([sys.executable, "-B", "scripts/repository_policy.py", "forbidden", "--root", str(generated),
              "--forbidden-terms-file", str(forbidden_terms)],
             "replayed generated project forbidden-term scan"),
        ):
            _run(command, cwd=generated, environment=environment, label=label)
        checks.append("parameterizedProjectIdentityAndPolicy")
        project_tree = _initialize_git(generated, environment)

        declaration = work / "module.json"
        _module_declaration(declaration, module)
        wrapper = generated / f"bin/{project['name']}"
        baseline = _tree_fingerprint(generated)
        for action in ("validate", "dry-run"):
            _run(_module_command(wrapper, action, generated, declaration), cwd=generated,
                 environment=environment, label=f"module {action} replay")
            if _tree_fingerprint(generated) != baseline:
                raise GeneratorEvidenceError(f"module {action} wrote files")
        checks.extend(("moduleValidateZeroWrite", "moduleDryRunZeroWrite"))

        common_inline = [
            str(wrapper), "module", "validate", "--workspace", str(generated),
            "--name", module["name"], "--label", module["label"],
            "--migration-version", module["migrationVersion"],
            "--permission-id-base", module["permissionIdBase"], "--menu-id", module["menuId"],
        ]
        negative_cases: list[tuple[str, list[str]]] = []
        def changed(flag: str, value: str) -> list[str]:
            command = list(common_inline)
            if flag in command:
                command[command.index(flag) + 1] = value
            else:
                command.extend((flag, value))
            return command
        negative_cases.extend((
            ("moduleInvalidNameZeroWrite", changed("--name", "class")),
            ("moduleInvalidTableZeroWrite", changed("--table", "Bad-Table")),
            ("moduleMigrationConflictZeroWrite", changed("--migration-version", "1")),
            ("modulePermissionIdConflictZeroWrite", changed("--permission-id-base", "1000")),
            ("moduleMenuIdConflictZeroWrite", changed("--menu-id", "2002")),
            ("moduleTableConflictZeroWrite", changed("--table", "sys_user")),
            ("moduleRouteConflictZeroWrite", changed("--route", "/projects")),
            ("modulePermissionCodeConflictZeroWrite", changed("--name", "audit")),
        ))
        for name, command in negative_cases:
            _run(command, cwd=generated, environment=environment, expect_success=False,
                 label=name)
            if _tree_fingerprint(generated) != baseline:
                raise GeneratorEvidenceError(f"{name} changed the workspace")
            checks.append(name)

        expression = work / "expression-module.json"
        expression.write_text(json.dumps({
            "schemaVersion": 1, "name": "expr", "label": "${notExecutable}",
            "migrationVersion": module["migrationVersion"],
            "permissionIdBase": int(module["permissionIdBase"]) + 100,
            "menuId": int(module["menuId"]) + 100,
        }) + "\n", encoding="utf-8")
        expression.chmod(0o600)
        _run(_module_command(wrapper, "validate", generated, expression), cwd=generated,
             environment=environment, expect_success=False, label="expression declaration replay")
        if _tree_fingerprint(generated) != baseline:
            raise GeneratorEvidenceError("expression declaration rejection changed the workspace")
        checks.append("moduleExpressionRejectedZeroWrite")

        default_project = work / "default-module-project"
        mcp_project = work / "mcp-module-project"
        shutil.copytree(generated, default_project, symlinks=True)
        shutil.copytree(generated, mcp_project, symlinks=True)
        default_wrapper = default_project / f"bin/{project['name']}"
        mcp_wrapper = mcp_project / f"bin/{project['name']}"
        _run(_module_command(default_wrapper, "generate", default_project, declaration),
             cwd=default_project, environment=environment, label="default module generation replay")
        module_root = default_project / f"{project['name']}-{module['name']}"
        class_name = module["name"][0].upper() + module["name"][1:]
        java_root = module_root / "src/main/java" / Path(project["groupId"].replace(".", "/")) / module["name"]
        required_suffixes = (
            f"domain/{class_name}.java", f"dto/{class_name}CreateRequest.java",
            f"dto/{class_name}UpdateRequest.java", f"dto/{class_name}Response.java",
            f"persistence/mapper/{class_name}Mapper.java", f"service/{class_name}Service.java",
            f"service/impl/{class_name}ServiceImpl.java", f"web/{class_name}Controller.java",
            f"audit/{class_name}OperationAuditRouteContributor.java",
        )
        if any(not (java_root / suffix).is_file() for suffix in required_suffixes):
            raise GeneratorEvidenceError("default generated module is missing backend layers")
        test_java_root = module_root / "src/test/java" \
            / Path(project["groupId"].replace(".", "/")) / module["name"]
        required_tests = (
            f"service/impl/{class_name}ServiceImplTest.java",
            f"web/{class_name}ControllerTest.java",
            f"audit/{class_name}OperationAuditRouteContributorTest.java",
        )
        frontend_root = default_project / f"{project['name']}-web"
        required_frontend = (
            f"src/features/{module['name']}/types.ts",
            f"src/features/{module['name']}/api.ts",
            f"src/features/{module['name']}/api.spec.ts",
            f"src/features/{module['name']}/{class_name}View.vue",
            f"e2e/generated/{module['name']}-runtime.spec.ts",
        )
        migration = default_project / f"{project['name']}-admin/src/main/resources/db/migration" \
            / f"V{module['migrationVersion']}__create_{module['name']}_module.sql"
        if any(not (test_java_root / suffix).is_file() for suffix in required_tests) \
                or any(not (frontend_root / suffix).is_file() for suffix in required_frontend) \
                or not migration.is_file():
            raise GeneratorEvidenceError(
                "declaration generation is missing tests, Flyway, or frontend layers"
            )
        root_pom = (default_project / "pom.xml").read_text(encoding="utf-8")
        admin_pom = (default_project / f"{project['name']}-admin/pom.xml").read_text(encoding="utf-8")
        navigation = (frontend_root / "src/navigation/manifest.ts").read_text(encoding="utf-8")
        menu = (frontend_root / "src/constants/menu.ts").read_text(encoding="utf-8")
        if (
            f"<module>{project['name']}-{module['name']}</module>" not in root_pom
            or f"<artifactId>{project['name']}-{module['name']}</artifactId>" not in admin_pom
            or f"permission: '{module['name']}:list'" not in navigation
            or module["menuId"] not in menu
        ):
            raise GeneratorEvidenceError(
                "declaration generation did not register Maven, Admin, permission, and menu boundaries"
            )
        if (java_root / "mcp").exists() or any(module_root.rglob("*Mcp*")):
            raise GeneratorEvidenceError("default module generation unexpectedly includes MCP")
        checks.append("defaultModuleWebRestOnly")

        _run(_module_command(mcp_wrapper, "generate", mcp_project, declaration, with_mcp=True),
             cwd=mcp_project, environment=environment, label="explicit MCP module generation replay")
        mcp_java_root = mcp_project / f"{project['name']}-{module['name']}" / "src/main/java" \
            / Path(project["groupId"].replace(".", "/")) / module["name"]
        contributor_path = mcp_java_root / f"mcp/{class_name}McpToolContributor.java"
        if not contributor_path.is_file():
            raise GeneratorEvidenceError("explicit --with-mcp did not generate a compiled contributor")
        contributor_source = contributor_path.read_text(encoding="utf-8")
        for token in (
            "implements McpToolContributor", "McpToolRisk.READ", "McpToolRisk.WRITE",
            "McpToolRisk.DESTRUCTIVE", "McpToolSupport.IDEMPOTENCY_KEY",
            "support.idempotent", f"{class_name}Permissions.LIST",
            f"{class_name}Permissions.CREATE", f"{class_name}Permissions.UPDATE",
            f"{class_name}Permissions.REMOVE", "McpToolSupport.objectSchema",
        ):
            if token not in contributor_source:
                raise GeneratorEvidenceError(
                    "explicit MCP contributor lacks fixed schema, permission, risk, or idempotency semantics"
                )
        _run(["git", "add", "--all"], cwd=mcp_project, environment=environment,
             label="replay MCP module Git add")
        module_tree = _run(["git", "write-tree"], cwd=mcp_project, environment=environment,
                           label="replay MCP module tree").stdout.strip()
        _pattern(module_tree, GIT_OBJECT, "replay MCP module tree")
        plan_output = work / "generated-plan.json"
        _run([sys.executable, "-B", "scripts/generated_module_plan.py", "--repository-root",
              str(mcp_project), "--output", str(plan_output)], cwd=mcp_project,
             environment=environment, label="generated module plan replay")
        plan_document = _load_json_bytes(plan_output.read_bytes(), "replayed generated module plan")
        modules = _array(plan_document.get("modules"), "replayed generated module plans")
        if plan_document.get("schemaVersion") != 1 or len(modules) != 1:
            raise GeneratorEvidenceError("replayed generated module plan is incomplete")
        generated_plan = _object(modules[0], "replayed generated module plan")
        browser_source = (mcp_project / generated_plan["browserTest"]).read_text(encoding="utf-8")
        for token in (
            "createResponse.status()).toBe(200)", "conflictResponse.status()).toBe(409)",
            "deleteResponse.status()).toBe(200)", "expect(forbidden).toBe(403)",
            "'/api/logs/operation'", "traceId",
        ):
            if token not in browser_source:
                raise GeneratorEvidenceError("generated browser test does not close the CRUD/audit loop")
        mcp_source = (mcp_project / generated_plan["mcpRuntimeTestSource"]).read_text(encoding="utf-8")
        for token in (
            "HttpClientStreamableHttpTransport", f'\"{module["name"]}.create\"',
            f'\"{module["name"]}.update\"', f'\"{module["name"]}.remove\"',
            "idempotencyKey",
        ):
            if token not in mcp_source:
                raise GeneratorEvidenceError("generated MCP runtime test is not the fixed official SDK CRUD proof")
        checks.extend(("declarationModuleFullStackShape", "explicitMcpFixedSdkShape"))
        return ReplayResult(project_tree, module_tree, generated_plan, tuple(sorted(checks)))


def _validate_generator_isolation(repository: Path, candidate: Mapping[str, Any]) -> None:
    commit = candidate["commit"]
    names = _git(repository, "ls-tree", "-r", "--name-only", commit, label="candidate tree paths").splitlines()
    generator_paths = [
        path for path in names
        if path.startswith("web-starter-tooling/src/main/java/dev/webstarter/tooling/project/")
        or path.startswith("web-starter-tooling/src/main/java/dev/webstarter/tooling/module/")
    ]
    if not generator_paths:
        raise GeneratorEvidenceError("candidate has no committed generator sources")
    forbidden_source_tokens = (
        "java.net.http", "java.net.URL", "java.net.URI", "Runtime.getRuntime",
        "ScriptEngine", "javax.script", "groovy.lang",
        "freemarker", "velocity", "mustache", "handlebars",
    )
    for relative in generator_paths:
        source = _run(["git", "-C", str(repository), "show", f"{commit}:{relative}"],
                      timeout=120, label=f"generator isolation source {relative}").stdout
        if any(token in source for token in forbidden_source_tokens):
            raise GeneratorEvidenceError(f"generator source has remote/executable-template capability: {relative}")
        if "ProcessBuilder" in source:
            if relative != (
                "web-starter-tooling/src/main/java/dev/webstarter/tooling/project/"
                "TrackedTemplate.java"
            ) or source.count("new ProcessBuilder(command)") != 1 \
                    or 'command.add("git")' not in source \
                    or "command.addAll(List.of(arguments))" not in source:
                raise GeneratorEvidenceError(
                    f"generator source can execute a non-fixed local Git process: {relative}"
                )
    runtime_java = [
        path for path in names
        if path.endswith(".java") and "/src/main/java/" in path
        and not path.startswith("web-starter-tooling/")
    ]
    for relative in runtime_java:
        source = _run(["git", "-C", str(repository), "show", f"{commit}:{relative}"],
                      timeout=120, label=f"runtime isolation source {relative}").stdout
        if "dev.webstarter.tooling" in source:
            raise GeneratorEvidenceError("runtime application imports offline tooling")
    admin_pom = _run(["git", "-C", str(repository), "show", f"{commit}:web-starter-admin/pom.xml"],
                     timeout=120, label="Admin POM isolation").stdout
    if "<artifactId>web-starter-tooling</artifactId>" in admin_pom:
        raise GeneratorEvidenceError("runtime Admin module packages offline tooling")
    schema = _load_json_bytes((repository / SCHEMA_PATH).read_bytes(), "generator evidence schema")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" \
            or schema.get("additionalProperties") is not False:
        raise GeneratorEvidenceError("generator evidence schema is not fail-closed")

    runner = _run(
        ["git", "-C", str(repository), "show", f"{commit}:scripts/run_release_runtime_acceptance.sh"],
        timeout=120, label="runtime proof producer source",
    ).stdout
    runner_requirements = (
        "pnpm exec playwright test",
        "validate_release_runtime_test_reports_proof.py",
        "WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_DIR",
        'len(matched) != 1',
        'len(tests) != 1',
        'len(results) != 1',
        'results[0].get("status") != "passed"',
        '"tests": 1, "failures": 0, "errors": 0, "skipped": 0',
        'cmp -s "${generated_module_plan}" "${generated_module_plan_after}"',
        '"${repository_root}/bin/web-starter" verify',
        'compose[@]}" up -d --wait',
    )
    if any(token not in runner for token in runner_requirements) \
            or any(f'"{name}"' not in runner for name in RUNTIME_CHECKS):
        raise GeneratorEvidenceError(
            "runtime proof producer no longer enforces the frozen browser/MCP/full-gate semantics"
        )
    release_browser = _run(
        ["git", "-C", str(repository), "show", f"{commit}:web-starter-web/e2e/release-runtime.spec.ts"],
        timeout=120, label="release browser proof source",
    ).stdout
    browser_requirements = (
        "private Web UI performs Project CRUD",
        "await login(page, runtime.privateBaseUrl)",
        "项目创建成功",
        "request.method() === 'PUT'",
        "项目已删除",
        "cell', { name: 'REMOVE' }",
        "logs/operation?module=project",
        "traceId",
    )
    if any(token not in release_browser for token in browser_requirements):
        raise GeneratorEvidenceError(
            "release browser proof source no longer proves real login, CRUD, audit, and trace"
        )
    verify_source = _run(
        ["git", "-C", str(repository), "show", f"{commit}:web-starter-tooling/src/main/java/"
         "dev/webstarter/tooling/dev/DeveloperCommands.java"],
        timeout=120, label="unified verify source",
    ).stdout
    verify_requirements = (
        '"maven-verify"', '"--no-transfer-progress", "verify"',
        '"lint", List.of("pnpm", "lint")',
        '"typecheck", List.of("pnpm", "typecheck")',
        '"unit-test", List.of("pnpm", "test")',
        '"production-build", List.of("pnpm", "build")',
        '"playwright-e2e", List.of("pnpm", "test:e2e")',
    )
    if any(token not in verify_source for token in verify_requirements):
        raise GeneratorEvidenceError("unified verify no longer executes the frozen backend/frontend/browser gates")


def _validate_inputs(document: Mapping[str, Any], repository: Path, forbidden_terms: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    project = _object(document["derivedProject"], "derivedProject")
    _exact(project, PROJECT_FIELDS, "derivedProject")
    _pattern(project["name"], PROJECT_NAME, "derivedProject.name")
    if project["name"] == "web-starter" or project["productName"] == "启程 Web Starter" \
            or project["groupId"] == "dev.webstarter" or project["database"] == "web_starter" \
            or project["environmentPrefix"] == "WEB_STARTER_":
        raise GeneratorEvidenceError("derived project is not parameterized away from the template")
    if not isinstance(project["productName"], str) or not project["productName"].strip():
        raise GeneratorEvidenceError("derived project product name is empty")
    if re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", project["groupId"]) is None \
            or re.fullmatch(r"[a-z][a-z0-9_]{1,62}", project["database"]) is None \
            or re.fullmatch(r"[A-Z][A-Z0-9_]{1,62}_", project["environmentPrefix"]) is None:
        raise GeneratorEvidenceError("derived project parameters are invalid")
    expected_terms_hash = _pattern(project["forbiddenTermsSha256"], SHA256, "forbidden terms SHA-256")
    raw_terms = forbidden_terms.expanduser().absolute()
    if raw_terms.is_symlink() or not raw_terms.is_file():
        raise GeneratorEvidenceError("forbidden terms must be a regular non-symlink file")
    terms = raw_terms.resolve(strict=True)
    if _inside(terms, repository) or terms.stat().st_size > 64 * 1024 or terms.stat().st_size == 0:
        raise GeneratorEvidenceError("forbidden terms file must be non-empty, bounded, and outside repository")
    if _sha256_bytes(terms.read_bytes()) != expected_terms_hash:
        raise GeneratorEvidenceError("forbidden terms file differs from producer input")

    module = _object(document["generatedModule"], "generatedModule")
    _exact(module, MODULE_FIELDS, "generatedModule")
    _pattern(module["name"], MODULE_NAME, "generatedModule.name")
    if not isinstance(module["label"], str) or not module["label"].strip() or module["withMcp"] is not True:
        raise GeneratorEvidenceError("generated module identity or explicit MCP flag is invalid")
    for field in ("migrationVersion", "permissionIdBase", "menuId"):
        if not isinstance(module[field], str) or re.fullmatch(r"[1-9][0-9]{0,17}", module[field]) is None:
            raise GeneratorEvidenceError(f"generatedModule.{field} is invalid")
    return project, module


def _write_summary(directory: Path, repository: Path, summary: Mapping[str, Any]) -> Path:
    target_input = directory.expanduser().absolute()
    if target_input.is_symlink() or not target_input.is_dir():
        raise GeneratorEvidenceError("summary output must be an existing non-symlink directory")
    target = target_input.resolve(strict=True)
    if _inside(target, repository) or stat.S_IMODE(target.stat().st_mode) != 0o700:
        raise GeneratorEvidenceError("summary output must be an external mode-0700 directory")
    if any(target.iterdir()):
        raise GeneratorEvidenceError("summary output directory must be empty")
    payload = (json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if any(pattern.search(payload.decode("utf-8")) for pattern in SECRET_PATTERNS):
        raise GeneratorEvidenceError("canonical summary contains secret-shaped material")
    destination = target / SUMMARY_FILE
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(destination.stat().st_mode) != 0o600 or {path.name for path in target.iterdir()} != {SUMMARY_FILE}:
        raise GeneratorEvidenceError("canonical summary publication is not private and exact")
    return destination


def validate_bundle(
    bundle: Path,
    *,
    repository_root: Path,
    forbidden_terms: Path,
    require_pass: bool = False,
    summary_output: Path | None = None,
    _replay: Callable[[Path, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Path], ReplayResult] = _replay_generator,
) -> dict[str, Any]:
    repository_input = repository_root.expanduser().absolute()
    if repository_input.is_symlink() or not repository_input.is_dir():
        raise GeneratorEvidenceError("repository root must be a non-symlink directory")
    repository = repository_input.resolve(strict=True)
    if summary_output is not None and not require_pass:
        raise GeneratorEvidenceError("summary output requires --require-pass")
    before = _snapshot_bundle(bundle, repository)
    checksum_text = before.files[CHECKSUM_FILE].payload.decode("ascii", errors="strict")
    expected_checksum = f"{before.files[EVIDENCE_FILE].sha256}  {EVIDENCE_FILE}\n"
    if checksum_text != expected_checksum:
        raise GeneratorEvidenceError("generator evidence checksum is not exact")
    document = _load_json_bytes(before.files[EVIDENCE_FILE].payload, "generator acceptance evidence")
    _exact(document, TOP_FIELDS, "generator acceptance evidence")
    if document["schemaVersion"] != 2 or document["acceptanceIds"] != list(ACCEPTANCE_IDS):
        raise GeneratorEvidenceError("generator evidence schema or acceptance IDs are incomplete")
    _timestamp(document["observedAt"], "generator evidence observedAt")
    candidate = _verify_candidate(document["candidate"], repository)
    _validate_tooling(document, candidate)
    project, module = _validate_inputs(document, repository, forbidden_terms)
    stages = _array(document["stages"], "stages")
    if len(stages) != 2:
        raise GeneratorEvidenceError("generator evidence must contain exactly two stages")
    project_stage, no_generated = _validate_stage(
        stages[0], stage_name="project", snapshot=before, project=project, module=module,
        version=candidate["mavenVersion"],
    )
    if no_generated is not None:
        raise GeneratorEvidenceError("project-only stage unexpectedly has generated module evidence")
    module_stage, generated = _validate_stage(
        stages[1], stage_name="module", snapshot=before, project=project, module=module,
        version=candidate["mavenVersion"],
    )
    if generated is None:
        raise GeneratorEvidenceError("module stage lacks generated module evidence")
    if project_stage["commit"] == module_stage["commit"] \
            or project_stage["tree"] == module_stage["tree"] \
            or project_stage["composeProject"] == module_stage["composeProject"]:
        raise GeneratorEvidenceError("project and module stages are not distinct")
    project_runtime_identity = _stage_json(before, "project", "runtime-version-identity.json")
    module_runtime_identity = _stage_json(before, "module", "runtime-version-identity.json")
    for dependency in ("mysql", "redis"):
        if project_runtime_identity["images"][dependency] != module_runtime_identity["images"][dependency]:
            raise GeneratorEvidenceError("runtime stages did not use the same immutable dependencies")

    cleanup = _object(document["cleanup"], "cleanup")
    _exact(cleanup, CLEANUP_FIELDS, "cleanup")
    expected_projects = sorted((project_stage["composeProject"], module_stage["composeProject"]))
    expected_images = sorted(
        stage["images"][role]["reference"] for stage in (project_stage, module_stage)
        for role in ("app", "nginx")
    )
    run_ids = {project_stage["composeProject"].split("-")[1], module_stage["composeProject"].split("-")[1]}
    if len(run_ids) != 1:
        raise GeneratorEvidenceError("generator stages do not share one isolated run ID")
    run_id = next(iter(run_ids))
    if cleanup != {
        "composeProjectsRemoved": expected_projects,
        "registryContainerRemoved": f"web-starter-generator-registry-{run_id}",
        "generatedImageReferencesRemoved": expected_images,
        "temporaryProjectTreeRemoved": True,
        "status": "PASS",
    }:
        raise GeneratorEvidenceError("cleanup evidence is not derived from both stages")
    if document["evidencePolicy"] != {
        "outsideRepository": True, "directoryMode": "0700", "fileMode": "0600",
        "onlyExpectedFiles": True, "rawSecretsPersisted": False,
    }:
        raise GeneratorEvidenceError("generator evidence persistence policy is not fail-closed")

    _validate_generator_isolation(repository, candidate)
    replay = _replay(repository, candidate, project, module, forbidden_terms.resolve(strict=True))
    if replay.project_tree != project_stage["tree"] or replay.module_tree != module_stage["tree"]:
        raise GeneratorEvidenceError("independently replayed generated trees differ from runtime stages")
    plan = replay.generated_plan
    expected_plan_values = {
        "module": module["name"],
        "artifactId": project["name"] + "-" + module["name"],
        "withMcp": True,
        "migrationSha256": generated["migrationSha256"],
        "planSha256": generated["planSha256"],
        "browserTestSha256": generated["browserTestSha256"],
        "mcpRuntimeTestSha256": generated["mcpRuntimeTestSha256"],
    }
    for name, expected in expected_plan_values.items():
        if plan.get(name) != expected:
            raise GeneratorEvidenceError(f"runtime generated module differs from replayed semantics: {name}")
    if len(replay.check_names) < 18 or len(replay.check_names) != len(set(replay.check_names)):
        raise GeneratorEvidenceError("semantic replay did not cover the frozen generator boundary matrix")

    independently_passing = (
        document["status"] == "PASS"
        and all(stage["status"] == "PASS" for stage in (project_stage, module_stage))
        and cleanup["status"] == "PASS"
    )
    if not independently_passing:
        raise GeneratorEvidenceError("top-level PASS is not independently derived")
    after = _snapshot_bundle(bundle, repository)
    if before != after:
        raise GeneratorEvidenceError("generator evidence bundle changed during validation")
    final_candidate = _verify_candidate(document["candidate"], repository)
    if final_candidate != candidate:
        raise GeneratorEvidenceError("candidate changed during generator evidence validation")
    if require_pass and not independently_passing:
        raise GeneratorEvidenceError("all AC08-15 evidence must independently PASS")

    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "PASS",
        "acceptanceIds": list(ACCEPTANCE_IDS),
        "candidate": {
            "commit": candidate["commit"], "tree": candidate["tree"],
            "tag": candidate["tag"], "version": candidate["mavenVersion"],
        },
        "derivedProject": {
            "name": project["name"], "groupId": project["groupId"],
            "database": project["database"], "environmentPrefix": project["environmentPrefix"],
        },
        "generatedModule": {
            "name": module["name"], "withMcp": True,
            "projectTree": replay.project_tree, "moduleTree": replay.module_tree,
        },
        "coverage": {acceptance_id: "PASS" for acceptance_id in ACCEPTANCE_IDS},
        "semanticReplay": {"checkCount": len(replay.check_names), "checks": list(replay.check_names)},
        "evidence": {
            "file": EVIDENCE_FILE,
            "sha256": before.files[EVIDENCE_FILE].sha256,
            "sourceCount": len(SOURCE_PATHS),
            "runtimeStageCount": 2,
        },
    }
    if summary_output is not None:
        _write_summary(summary_output, repository, summary)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evidence-directory", required=True, type=Path)
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    result.add_argument("--forbidden-terms", required=True, type=Path)
    result.add_argument("--require-pass", action="store_true")
    result.add_argument(
        "--summary-output", type=Path,
        help=f"existing empty external 0700 directory for {SUMMARY_FILE}; requires --require-pass",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_bundle(
            args.evidence_directory,
            repository_root=args.repository_root,
            forbidden_terms=args.forbidden_terms,
            require_pass=args.require_pass,
            summary_output=args.summary_output,
        )
    except (GeneratorEvidenceError, OSError, UnicodeError, ValueError) as exception:
        print(f"FAIL validate-generator-acceptance-evidence: {exception}", file=sys.stderr)
        return 1
    print(
        "PASS validate-generator-acceptance-evidence: "
        f"acceptances={len(summary['acceptanceIds'])} candidate={summary['candidate']['commit']} "
        f"semanticChecks={summary['semanticReplay']['checkCount']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
