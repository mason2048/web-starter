#!/usr/bin/env python3
"""Independently validate formal V2-AC-29 production fail-fast evidence.

The verifier never invokes Docker.  It recomputes the sanitized 15-case and
hardened-control semantics, validates the exact isolated command contracts,
and binds a PASS to caller-supplied image identity plus committed Git blobs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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
import xml.etree.ElementTree as ElementTree


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESULT_NAME = "v2-ac29-production-fail-fast.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"

TOOL_PATH = "scripts/rehearse_production_fail_fast.py"
VALIDATOR_PATH = "scripts/validate_production_fail_fast_evidence.py"
SCHEMA_PATH = "security/v2-ac29-production-fail-fast.schema.json"
VALIDATOR_JAVA_PATH = (
    "web-starter-admin/src/main/java/dev/webstarter/admin/config/"
    "ProductionConfigurationValidator.java"
)
INITIALIZER_JAVA_PATH = (
    "web-starter-admin/src/main/java/dev/webstarter/admin/config/"
    "ProductionConfigurationInitializer.java"
)
APPLICATION_JAVA_PATH = (
    "web-starter-admin/src/main/java/dev/webstarter/admin/WebStarterApplication.java"
)
ROOT_POM_PATH = "pom.xml"
ADMIN_POM_PATH = "web-starter-admin/pom.xml"
FRONTEND_MANIFEST_PATH = "web-starter-web/package.json"
APPLICATION_CONFIG_PATH = "web-starter-admin/src/main/resources/application.yml"
DOCKERFILE_PATH = "Dockerfile"
SOURCE_PATHS = (
    TOOL_PATH,
    VALIDATOR_PATH,
    SCHEMA_PATH,
    VALIDATOR_JAVA_PATH,
    INITIALIZER_JAVA_PATH,
    APPLICATION_JAVA_PATH,
    ROOT_POM_PATH,
    ADMIN_POM_PATH,
    FRONTEND_MANIFEST_PATH,
    APPLICATION_CONFIG_PATH,
    DOCKERFILE_PATH,
)

SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_REFERENCE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}@(?P<digest>sha256:[0-9a-f]{64})$"
)
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
SAFE_RUNTIME_VALUE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+() /:-]{0,159}$")
SAFE_JAVA_HOME = re.compile(r"^/[0-9A-Za-z][0-9A-Za-z._+()/ -]{0,158}$")

UNSAFE_PREFIX = "Unsafe production configuration: "
EARLY_MARKER_KEYS = (
    "tomcat", "flyway", "hikari", "jdbcMysql",
    "communicationsLinkFailure", "unableDatabaseConnection",
)
DATABASE_MARKER_KEYS = (
    *EARLY_MARKER_KEYS, "networkUnreachable", "connectionRefused", "mysqlDriver",
)
DATABASE_FAILURE_MARKER_KEYS = (
    "communicationsLinkFailure",
    "unableDatabaseConnection",
    "networkUnreachable",
    "connectionRefused",
)

EXPECTED_CASES = (
    ("http-issuer", ("WEB_STARTER_OAUTH_ISSUER",), "WEB_STARTER_OAUTH_ISSUER must be a non-local absolute HTTPS URI"),
    ("localhost-issuer", ("WEB_STARTER_OAUTH_ISSUER",), "WEB_STARTER_OAUTH_ISSUER must be a non-local absolute HTTPS URI"),
    ("http-audience", ("WEB_STARTER_OAUTH_RESOURCE_AUDIENCE",), "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE must be a non-local absolute HTTPS URI"),
    ("insecure-cookie", ("WEB_STARTER_COOKIE_SECURE",), "WEB_STARTER_COOKIE_SECURE must be true in production"),
    ("development-rsa", ("WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED",), "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED must be false in production"),
    ("empty-secret", ("WEB_STARTER_REDIS_PASSWORD",), "WEB_STARTER_REDIS_PASSWORD must not be empty in production"),
    ("placeholder-secret", ("WEB_STARTER_TOKEN_PEPPER",), "WEB_STARTER_TOKEN_PEPPER contains a weak or placeholder value"),
    ("missing-rsa", ("WEB_STARTER_OAUTH_RSA_PRIVATE_KEY", "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY"), "production requires an injected RSA JWK set or private/public PEM pair"),
    ("broad-host", ("WEB_STARTER_MCP_ALLOWED_HOSTS",), "WEB_STARTER_MCP_ALLOWED_HOSTS must contain exact non-local hosts"),
    ("local-host", ("WEB_STARTER_MCP_ALLOWED_HOSTS",), "WEB_STARTER_MCP_ALLOWED_HOSTS must contain exact non-local hosts"),
    ("broad-origin", ("WEB_STARTER_MCP_ALLOWED_ORIGINS",), "WEB_STARTER_MCP_ALLOWED_ORIGINS must contain exact non-local HTTPS origins"),
    ("http-origin", ("WEB_STARTER_MCP_ALLOWED_ORIGINS",), "WEB_STARTER_MCP_ALLOWED_ORIGINS must contain exact non-local HTTPS origins"),
    ("dangerous-log-level", ("LOGGING_LEVEL_DEV_WEBSTARTER",), "production logging level must not be ALL, TRACE, or DEBUG"),
    ("management-username-reuse", ("WEB_STARTER_MANAGEMENT_USERNAME",), "WEB_STARTER_MANAGEMENT_USERNAME must differ from the Web bootstrap administrator"),
    ("management-password-reuse", ("WEB_STARTER_MANAGEMENT_PASSWORD",), "WEB_STARTER_MANAGEMENT_PASSWORD must not reuse another application secret"),
)

HARDENED_ENVIRONMENT_KEYS = tuple(sorted((
    "WEB_STARTER_RUNTIME_MODE",
    "WEB_STARTER_GIT_COMMIT",
    "WEB_STARTER_OAUTH_ISSUER",
    "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE",
    "WEB_STARTER_COOKIE_SECURE",
    "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED",
    "WEB_STARTER_DB_URL",
    "WEB_STARTER_DB_USERNAME",
    "WEB_STARTER_DB_PASSWORD",
    "WEB_STARTER_DB_CONNECTION_TIMEOUT_MS",
    "WEB_STARTER_DB_VALIDATION_TIMEOUT_MS",
    "WEB_STARTER_REDIS_HOST",
    "WEB_STARTER_REDIS_PASSWORD",
    "WEB_STARTER_TOKEN_PEPPER",
    "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME",
    "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD",
    "WEB_STARTER_MANAGEMENT_USERNAME",
    "WEB_STARTER_MANAGEMENT_PASSWORD",
    "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY",
    "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY",
    "WEB_STARTER_OAUTH_RSA_JWK_SET",
    "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID",
    "WEB_STARTER_MCP_ALLOWED_HOSTS",
    "WEB_STARTER_MCP_ALLOWED_ORIGINS",
    "LOGGING_LEVEL_ROOT",
    "LOGGING_LEVEL_DEV_WEBSTARTER",
)))

TOP_FIELDS = frozenset({
    "schemaVersion", "acceptanceId", "status", "generatedAt", "candidate", "tool",
    "image", "javaRuntime", "execution", "rsa", "dangerousCases", "hardenedControl",
    "evidencePolicy",
})
CANDIDATE_FIELDS = frozenset({
    "head", "tree", "tag", "tagObject", "mavenVersion", "frontendVersion",
    "cleanWorktree", "sourceSha256",
})
TOOL_FIELDS = frozenset({
    "path", "sha256", "validatorPath", "validatorSha256", "schemaPath", "schemaSha256",
})
IMAGE_FIELDS = frozenset({
    "requestedReference", "id", "manifestDigest", "ociVersion", "ociRevision",
    "operatingSystem", "architecture", "javaHome",
})
JAVA_FIELDS = frozenset({
    "status", "imageId", "exitCode", "timedOut", "logBytes", "logSha256",
    "commandSha256", "specificationVersion", "runtimeVersion", "vendor", "checks", "failures",
})
EXECUTION_FIELDS = frozenset({
    "runId", "containerCount", "dockerNetwork", "readOnlyRootFilesystem",
    "publishedPorts", "hostBindMounts", "namedVolumeMounts", "tmpfsMountsPerContainer",
    "pullPolicy", "dockerLogDriver", "immutableImageIdUsed", "exactOwnershipLabels", "cleanup",
})
CLEANUP_FIELDS = frozenset({
    "expectedTargets", "cleanupCalls", "alreadyAbsentAfterAutoRemove", "ownedContainersRemoved",
    "ownershipLabelsVerifiedBeforeRemoval", "unownedRemovalAttempts", "residualContainers",
    "complete",
})
RSA_FIELDS = frozenset({"generatedBits", "persisted"})
CASE_FIELDS = frozenset({
    "case", "changedKeys", "status", "exitCode", "timedOut", "logBytes", "logSha256",
    "commandSha256", "expectedRejectionSha256", "exactRejectionCount", "rejectionOffset",
    "infrastructureMarkersBeforeRejection", "checks", "failures",
})
CONTROL_FIELDS = frozenset({
    "case", "status", "exitCode", "timedOut", "logBytes", "logSha256", "commandSha256",
    "unsafeRejectionCount", "databaseMarkers", "checks", "failures",
})
POLICY_FIELDS = frozenset({
    "outsideRepository", "directoryMode", "fileMode", "onlyReportAndChecksum",
    "rawLogsPersisted", "fixtureMaterialPersisted",
})

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        r"[\"']?(?:password|access_token|refresh_token|client_secret|authorization|cookie)"
        r"[\"']?\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:pat|svc)_[0-9A-Za-z_-]{16,}\b", re.IGNORECASE),
    re.compile(r"https?://[^/\s:@]+:[^@\s/]+@", re.IGNORECASE),
)


class EvidenceValidationError(ValueError):
    """Evidence is malformed, forged, stale, unsafe, or not candidate-bound."""


class EvidenceNotPassingError(EvidenceValidationError):
    """A valid document was explicitly required to PASS but did not."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int
    sha256: str


@dataclass(frozen=True)
class EvidenceSnapshot:
    report: FileIdentity
    checksum: FileIdentity
    report_bytes: bytes
    checksum_bytes: bytes


def _exact(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    required = set(expected)
    if actual != required:
        raise EvidenceValidationError(
            f"{label} fields are not exact (missing={','.join(sorted(required - actual))}; "
            f"unknown={','.join(sorted(actual - required))})"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceValidationError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{label} must be a string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceValidationError(f"{label} must be a boolean")
    return value


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceValidationError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise EvidenceValidationError(f"{label} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise EvidenceValidationError(f"{label} must be <= {maximum}")
    return value


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = _string(value, label)
    if pattern.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} has an invalid format")
    return text


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceValidationError(f"JSON object repeats field: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EvidenceValidationError(f"JSON contains a non-finite number: {value}")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _file_identity(path: Path) -> tuple[FileIdentity, bytes]:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise EvidenceValidationError("Evidence files must be regular non-symlink files")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise EvidenceValidationError("Evidence file mode must be exactly 0600")
        if before.st_size > 2 * 1024 * 1024:
            raise EvidenceValidationError("Evidence file exceeds the 2 MiB safety limit")
        content = path.read_bytes()
        after = path.lstat()
    except OSError as exception:
        raise EvidenceValidationError("Evidence file could not be read safely") from exception
    if (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode
    ) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode
    ) or len(content) != before.st_size:
        raise EvidenceValidationError("Evidence file changed while it was read")
    return FileIdentity(
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        stat.S_IMODE(before.st_mode), _sha256_bytes(content),
    ), content


def _evidence_snapshot(path: Path, repository: Path) -> EvidenceSnapshot:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or expanded.name != RESULT_NAME:
        raise EvidenceValidationError(f"Evidence path must name {RESULT_NAME}")
    try:
        resolved = expanded.resolve(strict=True)
        directory = resolved.parent
        directory_metadata = directory.lstat()
    except OSError as exception:
        raise EvidenceValidationError("Evidence path or directory is missing") from exception
    if directory.is_symlink() or not stat.S_ISDIR(directory_metadata.st_mode):
        raise EvidenceValidationError("Evidence directory must be a real directory")
    if stat.S_IMODE(directory_metadata.st_mode) != 0o700:
        raise EvidenceValidationError("Evidence directory mode must be exactly 0700")
    if directory == repository or _inside(directory, repository):
        raise EvidenceValidationError("Evidence directory must be outside the repository")
    try:
        entries = {item.name: item for item in directory.iterdir()}
    except OSError as exception:
        raise EvidenceValidationError("Evidence directory cannot be enumerated") from exception
    if set(entries) != {RESULT_NAME, CHECKSUM_NAME}:
        raise EvidenceValidationError("Evidence directory must contain only report and checksum")
    report_identity, report_bytes = _file_identity(entries[RESULT_NAME])
    checksum_identity, checksum_bytes = _file_identity(entries[CHECKSUM_NAME])
    expected_checksum = f"{report_identity.sha256}  {RESULT_NAME}\n".encode("ascii")
    if checksum_bytes != expected_checksum:
        raise EvidenceValidationError("Sibling checksum does not exactly match the report")
    return EvidenceSnapshot(report_identity, checksum_identity, report_bytes, checksum_bytes)


def _load_report(content: bytes) -> dict[str, Any]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError("Evidence report must be UTF-8") from exception
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        raise EvidenceValidationError("Evidence report contains secret-shaped material")
    try:
        value = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite,
        )
    except json.JSONDecodeError as exception:
        raise EvidenceValidationError("Evidence report is invalid JSON") from exception
    return _object(value, "report")


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key in {
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    return environment


def _git(repository: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(repository), *arguments,
            ],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exception:
        raise EvidenceValidationError("Git could not be started") from exception
    if completed.returncode != 0:
        raise EvidenceValidationError(f"Git candidate query failed: {arguments[0]}")
    return completed.stdout


def _repository_root(path: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise EvidenceValidationError("Repository root must be a real directory")
    repository = expanded.resolve()
    try:
        top = Path(_git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError("Git repository root is not UTF-8") from exception
    if top != repository:
        raise EvidenceValidationError("Repository root must be the exact Git worktree top level")
    return repository


def _git_id(repository: Path, expression: str, label: str) -> str:
    try:
        value = _git(repository, "rev-parse", "--verify", expression).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError(f"{label} is not ASCII") from exception
    if GIT_OBJECT.fullmatch(value) is None:
        raise EvidenceValidationError(f"{label} is malformed")
    return value


def _require_clean(repository: Path) -> None:
    records = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if not records or any(not record.startswith(b"H ") for record in records):
        raise EvidenceValidationError(
            "Git index has skip-worktree, assume-unchanged, or non-normal entries"
        )
    if _git(
        repository, "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise EvidenceValidationError("Formal AC-29 candidate is not clean")


def _committed_blob(repository: Path, head: str, relative: str) -> bytes:
    source = Path(relative)
    if source.is_absolute() or not source.parts or any(part in {"", ".", ".."} for part in source.parts):
        raise EvidenceValidationError(f"Unsafe candidate source path: {relative}")
    workspace = repository.joinpath(*source.parts)
    try:
        metadata = workspace.lstat()
        resolved = workspace.resolve(strict=True)
    except OSError as exception:
        raise EvidenceValidationError(f"Candidate source is missing: {relative}") from exception
    if not stat.S_ISREG(metadata.st_mode) or workspace.is_symlink() or not _inside(resolved, repository):
        raise EvidenceValidationError(f"Candidate source is unsafe: {relative}")
    records = [
        record for record in _git(repository, "ls-tree", "-z", head, "--", relative).split(b"\0")
        if record
    ]
    if len(records) != 1:
        raise EvidenceValidationError(f"Candidate commit does not contain: {relative}")
    metadata_raw, separator, encoded = records[0].partition(b"\t")
    fields = metadata_raw.split()
    if (
        not separator
        or encoded.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise EvidenceValidationError(f"Candidate source is not a regular Git blob: {relative}")
    committed = _git(repository, "show", f"{head}:{relative}")
    try:
        workspace_bytes = workspace.read_bytes()
    except OSError as exception:
        raise EvidenceValidationError(f"Candidate workspace source cannot be read: {relative}") from exception
    if committed != workspace_bytes:
        raise EvidenceValidationError(f"Candidate workspace source differs from commit: {relative}")
    return committed


def _versions(root_pom: bytes, admin_pom: bytes, frontend: bytes) -> str:
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    try:
        root = ElementTree.fromstring(root_pom)
        admin = ElementTree.fromstring(admin_pom)
        package = json.loads(frontend.decode("utf-8"))
    except (ElementTree.ParseError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceValidationError("Candidate version manifests are invalid") from exception
    root_node = root.find("m:version", namespace)
    admin_node = admin.find("m:parent/m:version", namespace)
    root_version = root_node.text.strip() if root_node is not None and root_node.text else ""
    admin_version = admin_node.text.strip() if admin_node is not None and admin_node.text else ""
    frontend_version = package.get("version") if isinstance(package, dict) else None
    if (
        not isinstance(frontend_version, str)
        or VERSION.fullmatch(root_version) is None
        or "SNAPSHOT" in root_version.upper()
        or root_version != admin_version
        or root_version != frontend_version
    ):
        raise EvidenceValidationError(
            "Maven root/admin and frontend versions must be the same non-SNAPSHOT release"
        )
    return root_version


def _verify_candidate(candidate_value: Any, repository: Path) -> tuple[dict[str, Any], Mapping[str, bytes]]:
    candidate = _object(candidate_value, "candidate")
    _exact(candidate, CANDIDATE_FIELDS, "candidate")
    _require_clean(repository)
    head = _git_id(repository, "HEAD^{commit}", "HEAD commit")
    tree = _git_id(repository, "HEAD^{tree}", "HEAD tree")
    if _pattern(candidate["head"], GIT_OBJECT, "candidate.head") != head:
        raise EvidenceValidationError("Candidate HEAD does not match the current clean checkout")
    if _pattern(candidate["tree"], GIT_OBJECT, "candidate.tree") != tree:
        raise EvidenceValidationError("Candidate tree does not match the current clean checkout")
    if _boolean(candidate["cleanWorktree"], "candidate.cleanWorktree") is not True:
        raise EvidenceValidationError("candidate.cleanWorktree must be true")
    sources_value = _object(candidate["sourceSha256"], "candidate.sourceSha256")
    _exact(sources_value, SOURCE_PATHS, "candidate.sourceSha256")
    blobs = {relative: _committed_blob(repository, head, relative) for relative in SOURCE_PATHS}
    for relative, content in blobs.items():
        if _pattern(sources_value[relative], SHA256, f"sourceSha256[{relative}]") != _sha256_bytes(content):
            raise EvidenceValidationError(f"Candidate source hash is forged: {relative}")
    version = _versions(
        blobs[ROOT_POM_PATH], blobs[ADMIN_POM_PATH], blobs[FRONTEND_MANIFEST_PATH]
    )
    if candidate["mavenVersion"] != version or candidate["frontendVersion"] != version:
        raise EvidenceValidationError("Evidence versions do not match committed manifests")
    tag = f"v{version}"
    if candidate["tag"] != tag:
        raise EvidenceValidationError("Candidate tag does not match the release version")
    tag_ref = f"refs/tags/{tag}"
    try:
        tag_type = _git(repository, "cat-file", "-t", tag_ref).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError("Release tag type is not ASCII") from exception
    if tag_type != "tag":
        raise EvidenceValidationError("Release tag must be annotated")
    tag_object = _git_id(repository, tag_ref, "annotated tag object")
    if candidate["tagObject"] != tag_object:
        raise EvidenceValidationError("Candidate tag object does not match Git")
    if _git_id(repository, f"{tag_ref}^{{commit}}", "tag commit") != head:
        raise EvidenceValidationError("Annotated release tag does not identify HEAD")
    _require_clean(repository)
    if (
        _git_id(repository, "HEAD^{commit}", "final HEAD commit") != head
        or _git_id(repository, "HEAD^{tree}", "final HEAD tree") != tree
        or _git_id(repository, tag_ref, "final annotated tag object") != tag_object
    ):
        raise EvidenceValidationError("Git candidate changed during source validation")
    return candidate, blobs


def _validate_expected_reference(value: str) -> tuple[str, str]:
    if value != value.strip() or "://" in value or ".." in value or value.count("@") != 1:
        raise EvidenceValidationError("Expected App reference is unsafe or mutable")
    match = DIGEST_REFERENCE.fullmatch(value)
    if match is None:
        raise EvidenceValidationError("Expected App reference must use repository@sha256")
    return value, match.group("digest")


def _command(
    name: str,
    run_id: str,
    image_id: str,
    environment_keys: Sequence[str],
    *,
    entrypoint: str | None = None,
    arguments: Sequence[str] = (),
) -> list[str]:
    command = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--name", name,
        "--label", "dev.webstarter.acceptance=ac29",
        "--label", f"dev.webstarter.acceptance.run={run_id}",
        "--log-driver", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "1g", "--cpus", "1.5",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
    ]
    for key in sorted(environment_keys):
        command.extend(("--env", key))
    if entrypoint is not None:
        command.extend(("--entrypoint", entrypoint))
    command.append(image_id)
    command.extend(arguments)
    return command


def _checks(value: Any, expected: Mapping[str, bool], label: str) -> None:
    checks = _object(value, label)
    _exact(checks, expected, label)
    for name, expected_value in expected.items():
        if _boolean(checks[name], f"{label}.{name}") is not expected_value:
            raise EvidenceValidationError(f"{label}.{name} is not independently derived")


def _marker_counts(value: Any, keys: Sequence[str], label: str) -> dict[str, int]:
    markers = _object(value, label)
    _exact(markers, keys, label)
    return {
        key: _integer(markers[key], f"{label}.{key}", minimum=0) for key in keys
    }


def _log_fields(item: Mapping[str, Any], label: str) -> None:
    if _integer(item["logBytes"], f"{label}.logBytes", minimum=1) < 1:
        raise EvidenceValidationError(f"{label}.logBytes must be positive")
    _pattern(item["logSha256"], SHA256, f"{label}.logSha256")
    _pattern(item["commandSha256"], SHA256, f"{label}.commandSha256")


def _validate_java(value: Any, image_id: str, run_id: str) -> bool:
    java = _object(value, "javaRuntime")
    _exact(java, JAVA_FIELDS, "javaRuntime")
    if java["imageId"] != image_id:
        raise EvidenceValidationError("Java probe did not use the expected immutable image ID")
    exit_code = _integer(java["exitCode"], "javaRuntime.exitCode", minimum=0, maximum=255)
    timed_out = _boolean(java["timedOut"], "javaRuntime.timedOut")
    specification = _string(java["specificationVersion"], "javaRuntime.specificationVersion")
    runtime = _string(java["runtimeVersion"], "javaRuntime.runtimeVersion")
    vendor = _string(java["vendor"], "javaRuntime.vendor")
    safe_identity = all(SAFE_RUNTIME_VALUE.fullmatch(item) is not None for item in (specification, runtime, vendor))
    runtime_is_21 = re.match(r"^21(?:[.+_-]|$)", runtime) is not None
    expected_checks = {
        "exitZero": exit_code == 0,
        "completedBeforeTimeout": not timed_out,
        "specificationIs21": specification == "21",
        "runtimeVersionIs21": runtime_is_21,
        "identityValuesSanitized": safe_identity,
    }
    _checks(java["checks"], expected_checks, "javaRuntime.checks")
    failures: list[str] = []
    if exit_code != 0:
        failures.append("nonZeroExit")
    if timed_out:
        failures.append("timedOut")
    if specification != "21":
        failures.append("notJava21")
    if not runtime_is_21:
        failures.append("runtimeVersionNot21")
    if not safe_identity:
        failures.append("runtimeIdentityMissingOrUnsafe")
    if _array(java["failures"], "javaRuntime.failures") != failures:
        raise EvidenceValidationError("Java runtime failures are not independently derived")
    passed = not failures
    if java["status"] != ("PASS" if passed else "FAIL"):
        raise EvidenceValidationError("Java runtime status is not independently derived")
    _log_fields(java, "javaRuntime")
    expected_command = _command(
        f"web-starter-ac29-java-{run_id}", run_id, image_id, (),
        entrypoint="java", arguments=("-XshowSettings:properties", "-version"),
    )
    if java["commandSha256"] != _canonical_sha256(expected_command):
        raise EvidenceValidationError("Java runtime command is not the isolated frozen contract")
    return passed


def _validate_cases(value: Any, image_id: str, run_id: str) -> bool:
    cases = _array(value, "dangerousCases")
    if len(cases) != len(EXPECTED_CASES):
        raise EvidenceValidationError("dangerousCases must contain exactly 15 observations")
    all_pass = True
    for index, (raw, expected) in enumerate(zip(cases, EXPECTED_CASES), start=1):
        item = _object(raw, f"dangerousCases[{index - 1}]")
        _exact(item, CASE_FIELDS, f"dangerousCases[{index - 1}]")
        case_id, changed_keys, rejection_message = expected
        if item["case"] != case_id:
            raise EvidenceValidationError("Dangerous-case order or identifier was changed")
        if _array(item["changedKeys"], f"{case_id}.changedKeys") != sorted(changed_keys):
            raise EvidenceValidationError(f"{case_id} does not bind the exact changed keys")
        rejection_hash = _sha256_bytes((UNSAFE_PREFIX + rejection_message).encode("utf-8"))
        if item["expectedRejectionSha256"] != rejection_hash:
            raise EvidenceValidationError(f"{case_id} expected rejection hash is forged")
        exit_code = _integer(
            item["exitCode"], f"{case_id}.exitCode", minimum=0, maximum=255
        )
        timed_out = _boolean(item["timedOut"], f"{case_id}.timedOut")
        rejection_count = _integer(item["exactRejectionCount"], f"{case_id}.exactRejectionCount", minimum=0)
        rejection_offset = _integer(item["rejectionOffset"], f"{case_id}.rejectionOffset", minimum=-1)
        markers = _marker_counts(
            item["infrastructureMarkersBeforeRejection"], EARLY_MARKER_KEYS,
            f"{case_id}.infrastructureMarkersBeforeRejection",
        )
        _log_fields(item, case_id)
        if rejection_count >= 1 and not (0 <= rejection_offset < item["logBytes"]):
            raise EvidenceValidationError(f"{case_id} rejection offset is inconsistent")
        if rejection_count == 0 and rejection_offset != -1:
            raise EvidenceValidationError(f"{case_id} rejection offset must be -1 when absent")
        expected_checks = {
            "nonZeroExit": exit_code != 0,
            "completedBeforeTimeout": not timed_out,
            "exactRejectionObservedOnce": rejection_count == 1,
            "noInfrastructureBeforeRejection": not any(markers.values()),
        }
        _checks(item["checks"], expected_checks, f"{case_id}.checks")
        failures: list[str] = []
        if timed_out:
            failures.append("timedOut")
        if exit_code == 0:
            failures.append("zeroExit")
        if rejection_count != 1:
            failures.append("exactRejectionCountMismatch")
        if any(markers.values()):
            failures.append("infrastructureStartedBeforeRejection")
        if _array(item["failures"], f"{case_id}.failures") != failures:
            raise EvidenceValidationError(f"{case_id} failures are not independently derived")
        passed = not failures
        if item["status"] != ("PASS" if passed else "FAIL"):
            raise EvidenceValidationError(f"{case_id} status is not independently derived")
        expected_command = _command(
            f"web-starter-ac29-{index:02d}-{run_id}", run_id, image_id,
            HARDENED_ENVIRONMENT_KEYS,
        )
        if item["commandSha256"] != _canonical_sha256(expected_command):
            raise EvidenceValidationError(f"{case_id} command violates the isolation contract")
        all_pass = all_pass and passed
    return all_pass


def _validate_control(value: Any, image_id: str, run_id: str) -> bool:
    control = _object(value, "hardenedControl")
    _exact(control, CONTROL_FIELDS, "hardenedControl")
    if control["case"] != "hardened-networkless-control":
        raise EvidenceValidationError("Hardened control identifier is not frozen")
    exit_code = _integer(
        control["exitCode"], "hardenedControl.exitCode", minimum=0, maximum=255
    )
    timed_out = _boolean(control["timedOut"], "hardenedControl.timedOut")
    unsafe_count = _integer(
        control["unsafeRejectionCount"], "hardenedControl.unsafeRejectionCount", minimum=0
    )
    markers = _marker_counts(control["databaseMarkers"], DATABASE_MARKER_KEYS, "hardenedControl.databaseMarkers")
    _log_fields(control, "hardenedControl")
    expected_checks = {
        "nonZeroExit": exit_code != 0,
        "completedBeforeTimeout": not timed_out,
        "securityValidationPassed": unsafe_count == 0,
        "databaseFailureObserved": any(
            markers[key] for key in DATABASE_FAILURE_MARKER_KEYS
        ),
    }
    _checks(control["checks"], expected_checks, "hardenedControl.checks")
    failures: list[str] = []
    if timed_out:
        failures.append("timedOut")
    if exit_code == 0:
        failures.append("unexpectedStartup")
    if unsafe_count != 0:
        failures.append("securityValidationRejectedControl")
    if not any(markers[key] for key in DATABASE_FAILURE_MARKER_KEYS):
        failures.append("databaseFailureMissing")
    if _array(control["failures"], "hardenedControl.failures") != failures:
        raise EvidenceValidationError("Hardened-control failures are not independently derived")
    passed = not failures
    if control["status"] != ("PASS" if passed else "FAIL"):
        raise EvidenceValidationError("Hardened-control status is not independently derived")
    expected_command = _command(
        f"web-starter-ac29-control-{run_id}", run_id, image_id, HARDENED_ENVIRONMENT_KEYS
    )
    if control["commandSha256"] != _canonical_sha256(expected_command):
        raise EvidenceValidationError("Hardened-control command violates the isolation contract")
    return passed


def _validate_execution(value: Any) -> tuple[str, bool]:
    execution = _object(value, "execution")
    _exact(execution, EXECUTION_FIELDS, "execution")
    run_id = _pattern(execution["runId"], RUN_ID, "execution.runId")
    expected_values = {
        "containerCount": 17,
        "dockerNetwork": "none",
        "readOnlyRootFilesystem": True,
        "publishedPorts": 0,
        "hostBindMounts": 0,
        "namedVolumeMounts": 0,
        "tmpfsMountsPerContainer": 1,
        "pullPolicy": "never",
        "dockerLogDriver": "none",
        "immutableImageIdUsed": True,
        "exactOwnershipLabels": True,
    }
    for key, expected in expected_values.items():
        if execution[key] != expected or type(execution[key]) is not type(expected):
            raise EvidenceValidationError(f"execution.{key} violates the frozen isolation contract")
    cleanup = _object(execution["cleanup"], "execution.cleanup")
    _exact(cleanup, CLEANUP_FIELDS, "execution.cleanup")
    integer_values = {
        key: _integer(cleanup[key], f"execution.cleanup.{key}", minimum=0)
        for key in CLEANUP_FIELDS - {"complete"}
    }
    if (
        integer_values["expectedTargets"] != 17
        or integer_values["cleanupCalls"] != 17
        or integer_values["alreadyAbsentAfterAutoRemove"] + integer_values["ownedContainersRemoved"] != 17
        or integer_values["ownershipLabelsVerifiedBeforeRemoval"] != integer_values["ownedContainersRemoved"]
        or integer_values["unownedRemovalAttempts"] != 0
        or integer_values["residualContainers"] != 0
    ):
        raise EvidenceValidationError("Cleanup accounting is incomplete or unsafe")
    complete = _boolean(cleanup["complete"], "execution.cleanup.complete")
    if not complete:
        raise EvidenceValidationError("Cleanup must be complete before evidence is emitted")
    return run_id, complete


def _validate_report(
    report: Mapping[str, Any], expected_reference: str, expected_image_id: str, repository: Path,
) -> dict[str, Any]:
    _exact(report, TOP_FIELDS, "report")
    if report["schemaVersion"] != 2 or report["acceptanceId"] != "V2-AC-29":
        raise EvidenceValidationError("Report schemaVersion/acceptanceId are not the frozen AC-29 contract")
    timestamp = _string(report["generatedAt"], "generatedAt")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exception:
        raise EvidenceValidationError("generatedAt must be an RFC 3339 timestamp") from exception
    if not timestamp.endswith("Z") or parsed.tzinfo is None:
        raise EvidenceValidationError("generatedAt must use explicit UTC")

    candidate, _ = _verify_candidate(report["candidate"], repository)
    source_hashes = _object(candidate["sourceSha256"], "candidate.sourceSha256")
    tool = _object(report["tool"], "tool")
    _exact(tool, TOOL_FIELDS, "tool")
    expected_tool_values = {
        "path": TOOL_PATH,
        "sha256": source_hashes[TOOL_PATH],
        "validatorPath": VALIDATOR_PATH,
        "validatorSha256": source_hashes[VALIDATOR_PATH],
        "schemaPath": SCHEMA_PATH,
        "schemaSha256": source_hashes[SCHEMA_PATH],
    }
    if tool != expected_tool_values:
        raise EvidenceValidationError("Tool/validator/schema bindings do not match the candidate")

    expected_reference, expected_digest = _validate_expected_reference(expected_reference)
    expected_image_id = _pattern(expected_image_id, IMAGE_ID, "expected App image ID")
    image = _object(report["image"], "image")
    _exact(image, IMAGE_FIELDS, "image")
    if image["requestedReference"] != expected_reference or image["manifestDigest"] != expected_digest:
        raise EvidenceValidationError("App digest reference does not match the caller expectation")
    if image["id"] != expected_image_id:
        raise EvidenceValidationError("App image ID does not match the caller expectation")
    if image["ociVersion"] != candidate["mavenVersion"] or image["ociRevision"] != candidate["head"]:
        raise EvidenceValidationError("App OCI labels do not bind the Git candidate")
    if image["operatingSystem"] != "linux" or image["architecture"] not in {"amd64", "arm64"}:
        raise EvidenceValidationError("App image platform identity is unsupported")
    java_home = _string(image["javaHome"], "image.javaHome")
    if SAFE_JAVA_HOME.fullmatch(java_home) is None:
        raise EvidenceValidationError("App image JAVA_HOME identity is unsafe")

    run_id, cleanup_complete = _validate_execution(report["execution"])
    java_pass = _validate_java(report["javaRuntime"], expected_image_id, run_id)
    cases_pass = _validate_cases(report["dangerousCases"], expected_image_id, run_id)
    control_pass = _validate_control(report["hardenedControl"], expected_image_id, run_id)

    rsa = _object(report["rsa"], "rsa")
    _exact(rsa, RSA_FIELDS, "rsa")
    if rsa != {"generatedBits": 3072, "persisted": False}:
        raise EvidenceValidationError("RSA fixture policy is not the frozen ephemeral contract")
    policy = _object(report["evidencePolicy"], "evidencePolicy")
    _exact(policy, POLICY_FIELDS, "evidencePolicy")
    expected_policy = {
        "outsideRepository": True,
        "directoryMode": "0700",
        "fileMode": "0600",
        "onlyReportAndChecksum": True,
        "rawLogsPersisted": False,
        "fixtureMaterialPersisted": False,
    }
    if policy != expected_policy:
        raise EvidenceValidationError("Evidence persistence policy is not fail-closed")
    passed = cases_pass and control_pass and java_pass and cleanup_complete
    expected_status = "PASS" if passed else "FAIL"
    if report["status"] != expected_status:
        raise EvidenceValidationError("Top-level status is not independently derived")
    return {
        "acceptanceId": "V2-AC-29",
        "status": expected_status,
        "candidateHead": candidate["head"],
        "candidateTree": candidate["tree"],
        "candidateTag": candidate["tag"],
        "imageReference": expected_reference,
        "imageId": expected_image_id,
        "caseCount": 15,
        "sourceCount": len(SOURCE_PATHS),
    }


def validate_evidence(
    evidence_path: Path,
    *,
    expected_app_reference: str,
    expected_app_image_id: str,
    repository_root: Path = REPOSITORY_ROOT,
    require_pass: bool = False,
) -> dict[str, Any]:
    repository = _repository_root(repository_root)
    before = _evidence_snapshot(evidence_path, repository)
    report = _load_report(before.report_bytes)
    result = _validate_report(report, expected_app_reference, expected_app_image_id, repository)
    after = _evidence_snapshot(evidence_path, repository)
    if before != after:
        raise EvidenceValidationError("Evidence report or checksum changed during validation")
    # Re-run all Git/object checks to close the candidate/source TOCTOU window.
    _verify_candidate(report["candidate"], repository)
    if require_pass and result["status"] != "PASS":
        raise EvidenceNotPassingError("AC-29 evidence did not independently validate as PASS")
    return result


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Independently validate candidate-bound V2-AC-29 evidence"
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--expected-app-reference", required=True,
        help="exact caller-trusted App repository@sha256 reference",
    )
    parser.add_argument(
        "--expected-app-image-id", required=True,
        help="exact caller-trusted local immutable sha256 image ID",
    )
    parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = validate_evidence(
            args.evidence,
            expected_app_reference=args.expected_app_reference,
            expected_app_image_id=args.expected_app_image_id,
            repository_root=args.repository_root,
            require_pass=args.require_pass,
        )
    except EvidenceNotPassingError as exception:
        print(f"AC-29 evidence is valid but not passing: {exception}", file=sys.stderr)
        return 1
    except EvidenceValidationError as exception:
        print(f"AC-29 evidence validation failed: {exception}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
