#!/usr/bin/env python3
"""Independently validate formal V2-AC-41 Redis-loss evidence.

The validator uses only the Python standard library.  It does not call Docker,
Redis, MySQL, or the network.  PASS is recomputed from exact report semantics,
the sibling checksum, caller-supplied expected runtime images, and the current
clean Git candidate's committed objects and source bytes.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

TOOL_PATH = "scripts/rehearse_redis_loss.py"
COMMON_PATH = "scripts/recovery_common.py"
VALIDATOR_PATH = "scripts/validate_redis_loss_evidence.py"
SCHEMA_PATH = "security/v2-ac41-redis-loss.schema.json"
MAVEN_PATH = "pom.xml"
FRONTEND_PATH = "web-starter-web/package.json"
FIXED_SOURCE_FILES = (
    TOOL_PATH,
    COMMON_PATH,
    VALIDATOR_PATH,
    SCHEMA_PATH,
    MAVEN_PATH,
    FRONTEND_PATH,
)

SERVICES = ("app", "nginx", "mysql", "redis")
OCI_SERVICES = ("app", "nginx")
FINGERPRINTS = ("business", "rbac", "credential_hashes")
AUDIT_TABLES = ("sys_login_log", "sys_operation_log", "sys_mcp_call_log")

TOP_FIELDS = frozenset({
    "schemaVersion", "acceptanceId", "mode", "status", "executedAtUtc",
    "candidate", "compose", "runtime", "isolation", "redis", "webSession",
    "mysqlFacts", "audit", "safety",
})
CANDIDATE_FIELDS = frozenset({
    "gitCommit", "gitTree", "cleanWorktree", "mavenVersion",
    "frontendVersion", "sourceSha256",
})
COMPOSE_FIELDS = frozenset({"project", "files", "baseUrl", "mysqlDatabase"})
RUNTIME_FIELDS = frozenset({"services", "java"})
SERVICE_FIELDS = frozenset({
    "containerId", "project", "composeReference", "containerReference",
    "expectedReference", "imageId", "expectedImageId", "ociVersion",
    "ociRevision",
})
JAVA_FIELDS = frozenset({"specificationVersion", "runtimeVersion"})
ISOLATION_FIELDS = frozenset({
    "volumes", "volumeDeletionPerformed", "containerDeletionPerformed",
    "projectDeletionPerformed",
})
VOLUME_FIELDS = frozenset({
    "name", "destination", "projectLabel", "composeVolumeLabel", "driver",
    "external",
})
REDIS_FIELDS = frozenset({
    "database", "keysBefore", "command", "result", "keysImmediatelyAfterFlush",
})
SESSION_FIELDS = frozenset({
    "authenticatedBeforeLoss", "beforeLossMeStatus", "oldSessionStatusAfterLoss",
    "reloginSucceeded", "reloginMeStatus", "reloginAttempts",
})
MYSQL_FACT_FIELDS = frozenset({"fingerprintsBefore", "fingerprintsAfter"})
AUDIT_FIELDS = frozenset({"rowsBefore", "rowsAfter"})
SAFETY_FIELDS = frozenset({
    "redisScope", "flushAllExecuted", "volumeDeletionPerformed",
    "containerDeletionPerformed", "projectDeletionPerformed",
})

SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
PROJECT = re.compile(r"^web-starter-ac41-[a-z0-9][a-z0-9-]{0,39}$")
DATABASE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
SOURCE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        r"[\"']?(?:password|access_token|refresh_token|client_secret|code_verifier|cookie)"
        r"[\"']?\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:pat|svc)_[0-9A-Za-z_-]{16,}\b", re.IGNORECASE),
)


class RedisLossEvidenceError(ValueError):
    """The evidence is unsafe, malformed, stale, or does not prove V2-AC-41."""


def _exact(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    required = set(expected)
    if actual != required:
        missing = ",".join(sorted(required - actual))
        unknown = ",".join(sorted(actual - required))
        raise RedisLossEvidenceError(
            f"{label} fields are not exact (missing={missing}; unknown={unknown})"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RedisLossEvidenceError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RedisLossEvidenceError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise RedisLossEvidenceError(f"{label} must be a string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise RedisLossEvidenceError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RedisLossEvidenceError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise RedisLossEvidenceError(f"{label} must be an integer <= {maximum}")
    return value


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = _string(value, label)
    if pattern.fullmatch(text) is None:
        raise RedisLossEvidenceError(f"{label} has an invalid format")
    return text


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RedisLossEvidenceError(f"JSON object repeats field: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise RedisLossEvidenceError(f"JSON contains a non-finite number: {value}")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RedisLossEvidenceError(f"{label} must be a regular non-symlink file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise RedisLossEvidenceError(f"{label} exceeds the 2 MiB limit")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RedisLossEvidenceError(f"{label} is not valid UTF-8 JSON") from exception
    return _object(value, label)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_file_policy(document_path: Path, repository_root: Path) -> tuple[Path, str]:
    expanded = document_path.expanduser().absolute()
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exception:
        raise RedisLossEvidenceError("formal evidence file does not exist") from exception
    repository = repository_root.expanduser().absolute().resolve()
    if _inside(resolved, repository) or _inside(repository, resolved.parent):
        raise RedisLossEvidenceError(
            "formal evidence must be outside and must not contain the repository"
        )
    if expanded.parent.is_symlink() or not expanded.parent.is_dir():
        raise RedisLossEvidenceError("formal evidence directory must be a real directory")
    if stat.S_IMODE(expanded.parent.stat().st_mode) != 0o700:
        raise RedisLossEvidenceError("formal evidence directory must have mode 0700")
    if expanded.is_symlink() or not expanded.is_file():
        raise RedisLossEvidenceError("formal evidence file must be a regular non-symlink file")
    if stat.S_IMODE(expanded.stat().st_mode) != 0o600:
        raise RedisLossEvidenceError("formal evidence file must have mode 0600")

    checksum = Path(str(expanded) + ".sha256")
    if checksum.is_symlink() or not checksum.is_file():
        raise RedisLossEvidenceError("formal evidence sibling checksum is missing or symbolic")
    if checksum.parent.resolve() != expanded.parent.resolve():
        raise RedisLossEvidenceError("formal evidence checksum must be a sibling")
    if stat.S_IMODE(checksum.stat().st_mode) != 0o600:
        raise RedisLossEvidenceError("formal evidence checksum must have mode 0600")
    try:
        content = checksum.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exception:
        raise RedisLossEvidenceError("formal evidence checksum is unreadable") from exception
    digest = _sha256_file(expanded)
    expected = f"{digest}  {expanded.name}\n"
    if content != expected:
        raise RedisLossEvidenceError("formal evidence sibling checksum does not match report bytes")
    try:
        entries = {entry.name for entry in expanded.parent.iterdir()}
    except OSError as exception:
        raise RedisLossEvidenceError("formal evidence directory is unreadable") from exception
    if entries != {expanded.name, checksum.name}:
        raise RedisLossEvidenceError(
            "formal evidence directory must contain only the report and sibling checksum"
        )
    return expanded, digest


def _git(repository: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        completed = subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(repository), *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
    except OSError as exception:
        raise RedisLossEvidenceError("Git is required for formal evidence validation") from exception
    if completed.returncode != 0:
        raise RedisLossEvidenceError(f"Git candidate query failed: {arguments[0]}")
    return completed.stdout


def _repository(path: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise RedisLossEvidenceError("repository root must be a real directory")
    repository = expanded.resolve()
    try:
        top = Path(_git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    except UnicodeDecodeError as exception:
        raise RedisLossEvidenceError("Git repository root is not UTF-8") from exception
    if top != repository:
        raise RedisLossEvidenceError("repository root must be the exact Git worktree root")
    return repository


def _git_id(repository: Path, expression: str, label: str) -> str:
    try:
        value = _git(repository, "rev-parse", "--verify", expression).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise RedisLossEvidenceError(f"{label} is not ASCII") from exception
    if GIT_OBJECT.fullmatch(value) is None:
        raise RedisLossEvidenceError(f"{label} is not a full Git object ID")
    return value


def _require_clean(repository: Path) -> None:
    records = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if not records or any(not record.startswith(b"H ") for record in records):
        raise RedisLossEvidenceError(
            "Git index has skip-worktree, assume-unchanged, or non-normal entries"
        )
    if _git(
        repository,
        "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise RedisLossEvidenceError("formal evidence candidate is not clean")


def _safe_source_path(relative: str) -> Path:
    if SOURCE_PATH.fullmatch(relative) is None:
        raise RedisLossEvidenceError(f"candidate source path is unsafe: {relative}")
    path = Path(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RedisLossEvidenceError(f"candidate source path is unsafe: {relative}")
    return path


def _committed_blob(repository: Path, commit: str, relative: str) -> bytes:
    source = _safe_source_path(relative)
    workspace = repository.joinpath(*source.parts)
    try:
        metadata = workspace.lstat()
        resolved = workspace.resolve(strict=True)
    except OSError as exception:
        raise RedisLossEvidenceError(f"candidate source is missing: {relative}") from exception
    if not stat.S_ISREG(metadata.st_mode) or workspace.is_symlink() or not _inside(resolved, repository):
        raise RedisLossEvidenceError(f"candidate source is not a regular repository file: {relative}")
    entry = _git(repository, "ls-tree", "-z", commit, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1:
        raise RedisLossEvidenceError(f"candidate commit lacks exact source: {relative}")
    header, separator, encoded_path = records[0].partition(b"\t")
    fields = header.split()
    if (
        not separator
        or encoded_path.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise RedisLossEvidenceError(f"candidate source is not a regular blob: {relative}")
    committed = _git(repository, "show", f"{commit}:{relative}")
    if workspace.read_bytes() != committed:
        raise RedisLossEvidenceError(f"candidate workspace bytes differ from commit: {relative}")
    return committed


def _versions(repository: Path) -> tuple[str, str]:
    try:
        root = ET.fromstring((repository / MAVEN_PATH).read_bytes())
    except (OSError, ET.ParseError) as exception:
        raise RedisLossEvidenceError("root Maven POM is unreadable") from exception
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    maven_node = root.find("m:version", namespace)
    if maven_node is None or maven_node.text is None:
        raise RedisLossEvidenceError("root Maven project version is missing")
    maven = maven_node.text.strip()
    frontend = _load_json(repository / FRONTEND_PATH, "frontend package").get("version")
    if (
        not isinstance(frontend, str)
        or VERSION.fullmatch(maven) is None
        or VERSION.fullmatch(frontend) is None
        or "SNAPSHOT" in maven.upper()
        or "SNAPSHOT" in frontend.upper()
        or maven != frontend
    ):
        raise RedisLossEvidenceError(
            "formal evidence requires equal non-SNAPSHOT Maven and frontend versions"
        )
    return maven, frontend


def _validate_candidate(
    value: Any,
    compose_files: Sequence[str],
    repository_root: Path,
) -> tuple[dict[str, Any], Path]:
    candidate = _object(value, "candidate")
    _exact(candidate, CANDIDATE_FIELDS, "candidate")
    repository = _repository(repository_root)
    head = _git_id(repository, "HEAD^{commit}", "candidate HEAD")
    tree = _git_id(repository, "HEAD^{tree}", "candidate tree")
    if candidate["gitCommit"] != head or candidate["gitTree"] != tree:
        raise RedisLossEvidenceError("candidate commit/tree does not match current Git HEAD")
    if _boolean(candidate["cleanWorktree"], "candidate.cleanWorktree") is not True:
        raise RedisLossEvidenceError("candidate.cleanWorktree must be true")
    _require_clean(repository)
    maven, frontend = _versions(repository)
    if candidate["mavenVersion"] != maven or candidate["frontendVersion"] != frontend:
        raise RedisLossEvidenceError("candidate versions do not match current source")

    expected_paths = set(FIXED_SOURCE_FILES) | set(compose_files)
    source_hashes = _object(candidate["sourceSha256"], "candidate.sourceSha256")
    _exact(source_hashes, expected_paths, "candidate.sourceSha256")
    for relative in sorted(expected_paths):
        declared = _pattern(
            source_hashes[relative], SHA256, f"candidate.sourceSha256[{relative}]"
        )
        actual = hashlib.sha256(_committed_blob(repository, head, relative)).hexdigest()
        if declared != actual:
            raise RedisLossEvidenceError(
                f"candidate source hash does not match commit bytes: {relative}"
            )
    if _git_id(repository, "HEAD^{commit}", "candidate HEAD") != head \
            or _git_id(repository, "HEAD^{tree}", "candidate tree") != tree:
        raise RedisLossEvidenceError("candidate identity changed during validation")
    _require_clean(repository)
    return candidate, repository


def _timestamp(value: Any) -> None:
    text = _string(value, "executedAtUtc")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exception:
        raise RedisLossEvidenceError("executedAtUtc must be RFC 3339") from exception
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RedisLossEvidenceError("executedAtUtc must include a timezone")


def _compose(value: Any) -> dict[str, Any]:
    compose = _object(value, "compose")
    _exact(compose, COMPOSE_FIELDS, "compose")
    project = _pattern(compose["project"], PROJECT, "compose.project")
    files = _array(compose["files"], "compose.files")
    if not files or len(files) != len(set(files)):
        raise RedisLossEvidenceError("compose.files must be non-empty and unique")
    for index, relative in enumerate(files):
        text = _string(relative, f"compose.files[{index}]")
        _safe_source_path(text)
        if not text.endswith((".yaml", ".yml")):
            raise RedisLossEvidenceError("compose files must be YAML files")
    base_url = _string(compose["baseUrl"], "compose.baseUrl")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or re.fullmatch(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+test",
            parsed.hostname,
        ) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RedisLossEvidenceError(
            "compose.baseUrl must be a reserved HTTPS acceptance origin"
        )
    try:
        port = parsed.port
    except ValueError as exception:
        raise RedisLossEvidenceError("compose.baseUrl has an invalid port") from exception
    if port is None or port < 1024 or port > 65535:
        raise RedisLossEvidenceError("compose.baseUrl must use an explicit unprivileged port")
    _pattern(compose["mysqlDatabase"], DATABASE, "compose.mysqlDatabase")
    assert project
    return compose


def _runtime(
    value: Any,
    candidate: Mapping[str, Any],
    project: str,
    expected_images: Mapping[str, Mapping[str, str]],
) -> None:
    runtime = _object(value, "runtime")
    _exact(runtime, RUNTIME_FIELDS, "runtime")
    services = _object(runtime["services"], "runtime.services")
    _exact(services, SERVICES, "runtime.services")
    _exact(expected_images, SERVICES, "expected images")
    container_ids: set[str] = set()
    for service in SERVICES:
        evidence = _object(services[service], f"runtime.services.{service}")
        _exact(evidence, SERVICE_FIELDS, f"runtime.services.{service}")
        expected = _object(expected_images[service], f"expected images.{service}")
        _exact(expected, {"reference", "imageId"}, f"expected images.{service}")
        reference = _pattern(
            expected["reference"], DIGEST_REFERENCE, f"expected images.{service}.reference"
        )
        image_id = _pattern(
            expected["imageId"], IMAGE_ID, f"expected images.{service}.imageId"
        )
        container_id = _pattern(
            evidence["containerId"], CONTAINER_ID, f"runtime.services.{service}.containerId"
        )
        if container_id in container_ids:
            raise RedisLossEvidenceError("runtime service container IDs must be unique")
        container_ids.add(container_id)
        for field in ("composeReference", "containerReference", "expectedReference"):
            if _pattern(evidence[field], DIGEST_REFERENCE, f"runtime.services.{service}.{field}") != reference:
                raise RedisLossEvidenceError(f"runtime {service} reference is not cross-bound")
        for field in ("imageId", "expectedImageId"):
            if _pattern(evidence[field], IMAGE_ID, f"runtime.services.{service}.{field}") != image_id:
                raise RedisLossEvidenceError(f"runtime {service} image ID is not cross-bound")
        if evidence["project"] != project:
            raise RedisLossEvidenceError(f"runtime {service} project is not cross-bound")
        if service in OCI_SERVICES:
            if (
                evidence["ociVersion"] != candidate["mavenVersion"]
                or evidence["ociRevision"] != candidate["gitCommit"]
            ):
                raise RedisLossEvidenceError(f"runtime {service} OCI identity is mismatched")
        elif evidence["ociVersion"] is not None or evidence["ociRevision"] is not None:
            raise RedisLossEvidenceError(f"runtime {service} must not invent OCI identity")

    java = _object(runtime["java"], "runtime.java")
    _exact(java, JAVA_FIELDS, "runtime.java")
    if java["specificationVersion"] != "21":
        raise RedisLossEvidenceError("runtime Java specification version must equal 21")
    runtime_version = _string(java["runtimeVersion"], "runtime.java.runtimeVersion")
    if (
        re.match(r"^21(?:[.+_-]|$)", runtime_version) is None
        or len(runtime_version) > 128
        or any(c in runtime_version for c in "\r\n\0")
    ):
        raise RedisLossEvidenceError("runtime Java version must be a valid Java 21 version")


def _isolation(value: Any, project: str) -> None:
    isolation = _object(value, "isolation")
    _exact(isolation, ISOLATION_FIELDS, "isolation")
    volumes = _object(isolation["volumes"], "isolation.volumes")
    _exact(volumes, {"mysql", "redis"}, "isolation.volumes")
    destinations = {"mysql": "/var/lib/mysql", "redis": "/data"}
    volume_names: set[str] = set()
    for service, destination in destinations.items():
        volume = _object(volumes[service], f"isolation.volumes.{service}")
        _exact(volume, VOLUME_FIELDS, f"isolation.volumes.{service}")
        name = _string(volume["name"], f"isolation.volumes.{service}.name")
        logical = _string(
            volume["composeVolumeLabel"],
            f"isolation.volumes.{service}.composeVolumeLabel",
        )
        driver = _string(volume["driver"], f"isolation.volumes.{service}.driver")
        if (
            not name
            or volume["destination"] != destination
            or volume["projectLabel"] != project
            or not logical
            or not driver
            or _boolean(volume["external"], f"isolation.volumes.{service}.external")
        ):
            raise RedisLossEvidenceError(f"{service} volume is not isolated and project-owned")
        if name in volume_names:
            raise RedisLossEvidenceError("MySQL and Redis must not share the same named volume")
        volume_names.add(name)
    for field in (
        "volumeDeletionPerformed", "containerDeletionPerformed", "projectDeletionPerformed"
    ):
        if _boolean(isolation[field], f"isolation.{field}"):
            raise RedisLossEvidenceError("formal rehearsal must not delete project resources")


def _fingerprints(value: Any, label: str) -> dict[str, Any]:
    fingerprints = _object(value, label)
    _exact(fingerprints, FINGERPRINTS, label)
    for name in FINGERPRINTS:
        _pattern(fingerprints[name], SHA256, f"{label}.{name}")
    return fingerprints


def _audits(value: Any, label: str) -> dict[str, Any]:
    rows = _object(value, label)
    _exact(rows, AUDIT_TABLES, label)
    for table in AUDIT_TABLES:
        _integer(rows[table], f"{label}.{table}")
    return rows


def validate_document(
    document: Any,
    *,
    repository_root: Path,
    expected_images: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    root = _object(document, "evidence")
    _exact(root, TOP_FIELDS, "evidence")
    if (
        root["schemaVersion"] != 1
        or isinstance(root["schemaVersion"], bool)
        or root["acceptanceId"] != "V2-AC-41"
        or root["mode"] != "formal"
        or root["status"] != "PASS"
    ):
        raise RedisLossEvidenceError("evidence is not a formal V2-AC-41 PASS document")
    _timestamp(root["executedAtUtc"])
    compose = _compose(root["compose"])
    candidate, _repository_path = _validate_candidate(
        root["candidate"], compose["files"], repository_root
    )
    project = compose["project"]
    _runtime(root["runtime"], candidate, project, expected_images)
    _isolation(root["isolation"], project)

    redis = _object(root["redis"], "redis")
    _exact(redis, REDIS_FIELDS, "redis")
    _integer(redis["database"], "redis.database", maximum=15)
    _integer(redis["keysBefore"], "redis.keysBefore", minimum=1)
    if (
        redis["command"] != "FLUSHDB"
        or redis["result"] != "OK"
        or redis["keysImmediatelyAfterFlush"] != 0
        or isinstance(redis["keysImmediatelyAfterFlush"], bool)
    ):
        raise RedisLossEvidenceError("Redis DB/FLUSHDB evidence is invalid")

    session = _object(root["webSession"], "webSession")
    _exact(session, SESSION_FIELDS, "webSession")
    expected_session = {
        "authenticatedBeforeLoss": True,
        "beforeLossMeStatus": 200,
        "oldSessionStatusAfterLoss": 401,
        "reloginSucceeded": True,
        "reloginMeStatus": 200,
    }
    if any(session.get(name) != value for name, value in expected_session.items()):
        raise RedisLossEvidenceError("session invalidation/re-login evidence is invalid")
    _integer(
        session["reloginAttempts"],
        "webSession.reloginAttempts",
        minimum=1,
        maximum=5,
    )

    mysql_facts = _object(root["mysqlFacts"], "mysqlFacts")
    _exact(mysql_facts, MYSQL_FACT_FIELDS, "mysqlFacts")
    before_fingerprints = _fingerprints(
        mysql_facts["fingerprintsBefore"], "mysqlFacts.fingerprintsBefore"
    )
    after_fingerprints = _fingerprints(
        mysql_facts["fingerprintsAfter"], "mysqlFacts.fingerprintsAfter"
    )
    if before_fingerprints != after_fingerprints:
        raise RedisLossEvidenceError("MySQL domain fingerprints changed after Redis loss")

    audit = _object(root["audit"], "audit")
    _exact(audit, AUDIT_FIELDS, "audit")
    before_audit = _audits(audit["rowsBefore"], "audit.rowsBefore")
    after_audit = _audits(audit["rowsAfter"], "audit.rowsAfter")
    if any(after_audit[name] < before_audit[name] for name in AUDIT_TABLES):
        raise RedisLossEvidenceError("audit rows decreased after Redis loss")
    if after_audit["sys_login_log"] <= before_audit["sys_login_log"]:
        raise RedisLossEvidenceError("re-login did not append a login audit row")

    safety = _object(root["safety"], "safety")
    _exact(safety, SAFETY_FIELDS, "safety")
    if safety != {
        "redisScope": "SELECTED_DATABASE_ONLY",
        "flushAllExecuted": False,
        "volumeDeletionPerformed": False,
        "containerDeletionPerformed": False,
        "projectDeletionPerformed": False,
    }:
        raise RedisLossEvidenceError("resource and Redis command safety evidence is invalid")

    encoded = json.dumps(root, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if any(pattern.search(encoded) for pattern in SECRET_PATTERNS):
        raise RedisLossEvidenceError("formal evidence contains secret-shaped material")
    return {
        "status": "PASS",
        "acceptanceId": "V2-AC-41",
        "gitCommit": candidate["gitCommit"],
        "gitTree": candidate["gitTree"],
        "version": candidate["mavenVersion"],
    }


def validate_document_path(
    document_path: Path,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    expected_images: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    validated_path, initial_digest = _validate_file_policy(document_path, repository_root)
    document = _load_json(validated_path, "formal Redis-loss evidence")
    summary = validate_document(
        document,
        repository_root=repository_root,
        expected_images=expected_images,
    )
    final_path, final_digest = _validate_file_policy(document_path, repository_root)
    if final_path != validated_path or final_digest != initial_digest:
        raise RedisLossEvidenceError("formal evidence changed during validation")
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Independently validate formal V2-AC-41 Redis-loss evidence"
    )
    result.add_argument("--document", required=True, type=Path)
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    for service in SERVICES:
        result.add_argument(f"--expected-{service}-reference", required=True)
        result.add_argument(f"--expected-{service}-image-id", required=True)
    return result


def _expected_images(args: argparse.Namespace) -> dict[str, dict[str, str]]:
    return {
        service: {
            "reference": getattr(args, f"expected_{service}_reference"),
            "imageId": getattr(args, f"expected_{service}_image_id"),
        }
        for service in SERVICES
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_document_path(
            args.document,
            repository_root=args.repository_root,
            expected_images=_expected_images(args),
        )
    except RedisLossEvidenceError as error:
        print(f"FAIL validate-redis-loss-evidence: {error}", file=sys.stderr)
        return 1
    print(
        "PASS validate-redis-loss-evidence: "
        f"acceptance={summary['acceptanceId']} version={summary['version']} "
        f"commit={summary['gitCommit']} tree={summary['gitTree']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
