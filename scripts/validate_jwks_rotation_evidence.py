#!/usr/bin/env python3
"""Independently validate formal V2-AC-26 JWKS rotation evidence.

This module deliberately does not import the producer and never invokes Docker
or a network.  It recomputes PASS from sanitized protocol observations, binds
them to an exact clean annotated Git candidate and a separate runtime identity
document, and optionally writes one canonical mode-0600 summary.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse
import xml.etree.ElementTree as ElementTree


RESULT_NAME = "v2-ac26-jwks-rotation.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"
SUMMARY_NAME = "v2-ac26-jwks-rotation-summary.json"
TOOL_PATH = "scripts/rehearse_jwks_rotation.py"
VALIDATOR_PATH = "scripts/validate_jwks_rotation_evidence.py"
SCHEMA_PATH = "security/v2-ac26-jwks-rotation.schema.json"
ACCEPTANCE_NETWORK_PATH = "scripts/acceptance_network.py"
KEY_RING_PATH = (
    "web-starter-security/src/main/java/dev/webstarter/security/oauth/"
    "OAuthSigningKeyRing.java"
)
KEY_RING_TEST_PATH = (
    "web-starter-security/src/test/java/dev/webstarter/security/oauth/"
    "OAuthSigningKeyRingTest.java"
)
SECURITY_CONFIG_PATH = (
    "web-starter-security/src/main/java/dev/webstarter/security/config/"
    "WebStarterSecurityConfiguration.java"
)
SECURITY_PROPERTIES_PATH = (
    "web-starter-security/src/main/java/dev/webstarter/security/config/"
    "WebStarterSecurityProperties.java"
)
MCP_INVOCATION_PATH = (
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpInvocationService.java"
)
MCP_CATALOG_PATH = (
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolCatalog.java"
)
TRACE_FILTER_PATH = (
    "web-starter-admin/src/main/java/dev/webstarter/admin/web/TraceIdFilter.java"
)
COMPOSE_PATH = "compose.production.yaml"
ROOT_POM_PATH = "pom.xml"
SECURITY_POM_PATH = "web-starter-security/pom.xml"
MCP_POM_PATH = "web-starter-mcp/pom.xml"
FRONTEND_MANIFEST_PATH = "web-starter-web/package.json"
SOURCE_PATHS = (
    TOOL_PATH,
    VALIDATOR_PATH,
    SCHEMA_PATH,
    ACCEPTANCE_NETWORK_PATH,
    KEY_RING_PATH,
    KEY_RING_TEST_PATH,
    SECURITY_CONFIG_PATH,
    SECURITY_PROPERTIES_PATH,
    MCP_INVOCATION_PATH,
    MCP_CATALOG_PATH,
    TRACE_FILTER_PATH,
    COMPOSE_PATH,
    ROOT_POM_PATH,
    SECURITY_POM_PATH,
    MCP_POM_PATH,
    FRONTEND_MANIFEST_PATH,
)

SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_REFERENCE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}@(?P<digest>sha256:[0-9a-f]{64})$"
)
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
KID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROJECT = re.compile(r"^web-starter-ac26-[a-z0-9][a-z0-9-]{0,39}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
TRACE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
TRACE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,31}$")
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_RUNTIME_IDENTITY_BYTES = 256 * 1024
MAX_GIT_BYTES = 8 * 1024 * 1024

TOP_FIELDS = frozenset({
    "schemaVersion", "acceptanceId", "status", "generatedAt", "candidate", "tool",
    "runtime", "keyRing", "observations", "supplementalConfigurationGuards",
    "evidencePolicy",
})
CANDIDATE_FIELDS = frozenset({
    "head", "tree", "tag", "tagObject", "mavenVersion", "frontendVersion",
    "cleanWorktree", "sourceSha256",
})
TOOL_FIELDS = frozenset({
    "path", "sha256", "validatorPath", "validatorSha256", "schemaPath", "schemaSha256",
})
RUNTIME_FIELDS = frozenset({
    "composeProject", "publicOriginSha256", "privateOriginSha256", "runtimeIdentitySha256",
    "privatePort", "publicPort", "tracePrefix", "app", "nginx", "containerTransitions",
})
APP_FIELDS = frozenset({
    "requestedReference", "id", "manifestDigest", "ociVersion", "ociRevision",
})
TRANSITION_FIELDS = frozenset({
    "phase", "previousContainerId", "currentContainerId", "imageId",
    "previousIngressContainerIds", "currentIngressContainerIds", "nginxImageId",
    "nginxReference", "projectLabelMatched", "serviceLabelMatched", "fixedServices",
    "allContainersHealthy", "portBindingsMatched", "noBuild", "noPull", "noDependencies",
})
KEY_RING_FIELDS = frozenset({
    "oldKid", "newKid", "oldPublicFingerprintSha256", "newPublicFingerprintSha256",
    "retainUntilEpochSeconds", "terminalMode", "initialPrivateKeyCount",
    "rotatedPrivateKeyCount", "retiringPrivateMaterialPresent",
    "terminalRevocationConfigured",
})
OBSERVATION_FIELDS = frozenset({"baseline", "rotated", "terminal"})
BASELINE_FIELDS = frozenset({"observedAtEpochSeconds", "jwks", "oldOauthGrant", "oldMcp"})
ROTATED_FIELDS = frozenset({
    "observedAtEpochSeconds", "jwks", "newOauthGrant", "oldWithinWindowMcp",
    "newActiveMcp", "oldTraceAudit", "newTraceAudit",
})
TERMINAL_FIELDS = frozenset({
    "observedAtEpochSeconds", "jwks", "oldCredentialRejected", "newActiveMcp",
    "newTraceAudit",
})
JWKS_FIELDS = frozenset({
    "httpStatus", "responseContentTypeJson", "observedAtEpochSeconds", "keyCount", "kids",
    "publicFingerprintSha256",
    "privateParametersAbsent", "metadataIssuerMatched", "metadataJwksUriMatched",
    "responseSha256",
})
CREDENTIAL_FIELDS = frozenset({
    "httpStatus", "responseContentTypeJson", "kid", "algorithm", "issuedAtEpochSeconds",
    "expiresAtEpochSeconds", "protectedHeaderSha256", "claimsSha256", "responseSha256",
    "issuerMatched", "audienceMatched", "requiredScopesMatched",
})
MCP_FIELDS = frozenset({
    "initializeHttpStatus", "initializedHttpStatus", "toolCallHttpStatus", "deleteHttpStatus",
    "protocolVersion", "serverName", "toolName", "toolResultSuccess", "traceId",
    "startedAtEpochSeconds", "completedAtEpochSeconds", "traceHeaderMatched",
    "sessionIdSha256", "initializeResponseSha256", "toolResponseSha256",
})
AUDIT_FIELDS = frozenset({
    "httpStatus", "sourceTraceId", "auditTraceId", "rowMatched", "toolNameMatched",
    "successOutcomeMatched", "responseSha256", "attempt",
})
REJECTION_FIELDS = frozenset({
    "httpStatus", "startedAtEpochSeconds", "completedAtEpochSeconds", "traceId",
    "traceHeaderMatched", "wwwAuthenticateBearer",
    "noSessionIssued", "responseSha256",
})
SUPPLEMENTAL_FIELDS = frozenset({
    "status", "unknownKidRuntime", "invalidActiveRuntime", "unitTestSourcePath",
    "unitTestSourceSha256",
})
POLICY_FIELDS = frozenset({
    "outsideRepository", "directoryMode", "fileMode", "onlyReportAndChecksum",
    "rawHttpBodiesPersisted", "credentialsPersisted", "privateKeyMaterialPersisted",
    "arbitraryHookAccepted", "dockerResourcesRemoved",
})

SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        rb'(?:["\'](?:password|access_token|refresh_token|client_secret|authorization|cookie|bearer)'
        rb'["\']\s*:|(?:password|access_token|refresh_token|client_secret|authorization|cookie|bearer)\s*=)',
        re.IGNORECASE,
    ),
    re.compile(rb"\b(?:pat|svc)_[0-9A-Za-z_-]{16,}\b", re.IGNORECASE),
    re.compile(rb"https?://[^/\s:@]+:[^@\s/]+@", re.IGNORECASE),
)


class EvidenceValidationError(ValueError):
    """Evidence is malformed, unsafe, forged, stale, or not candidate-bound."""


class EvidenceNotPassingError(EvidenceValidationError):
    """A caller explicitly required PASS but the document is not passing."""


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
    directory: Path
    report: FileIdentity
    checksum: FileIdentity
    report_bytes: bytes
    checksum_bytes: bytes


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _exact(value: Mapping[str, Any], fields: Iterable[str], label: str) -> None:
    actual = set(value)
    expected = set(fields)
    if actual != expected:
        raise EvidenceValidationError(
            f"{label} fields are not exact (missing={','.join(sorted(expected - actual))}; "
            f"unknown={','.join(sorted(actual - expected))})"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceValidationError(f"{label} must be an array")
    return value


def _string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or (pattern is not None and pattern.fullmatch(value) is None):
        raise EvidenceValidationError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceValidationError(f"{label} must be an integer >= {minimum}")
    return value


def _true(value: Any, label: str) -> None:
    if value is not True:
        raise EvidenceValidationError(f"{label} must be true")


def _false(value: Any, label: str) -> None:
    if value is not False:
        raise EvidenceValidationError(f"{label} must be false")


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceValidationError(f"{label} repeats JSON member: {key}")
            result[key] = value
        return result

    def reject(value: str) -> None:
        raise EvidenceValidationError(f"{label} contains non-finite number: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_constant=reject,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceValidationError(f"{label} is not strict UTF-8 JSON") from exception
    return _object(value, label)


def _read_regular(path: Path, maximum: int, label: str, required_mode: int = 0o600) -> tuple[FileIdentity, bytes]:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_file():
        raise EvidenceValidationError(f"{label} must be a real regular file")
    before = expanded.stat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > maximum
        or (os.name == "posix" and stat.S_IMODE(before.st_mode) != required_mode)
    ):
        raise EvidenceValidationError(f"{label} has an invalid size or mode")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(expanded, flags)
    except OSError as exception:
        raise EvidenceValidationError(f"{label} cannot be opened safely") from exception
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, maximum + 1)
        if os.read(descriptor, 1):
            raise EvidenceValidationError(f"{label} changed or exceeded its bound")
    finally:
        os.close(descriptor)
    after = expanded.stat()
    tuple_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    tuple_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    tuple_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if tuple_before != tuple_opened or tuple_opened != tuple_after or len(payload) != opened.st_size:
        raise EvidenceValidationError(f"{label} changed while being read")
    identity = FileIdentity(
        device=opened.st_dev,
        inode=opened.st_ino,
        size=opened.st_size,
        modified_ns=opened.st_mtime_ns,
        mode=stat.S_IMODE(opened.st_mode),
        sha256=_sha256(payload),
    )
    return identity, payload


def snapshot_evidence(report_path: Path) -> EvidenceSnapshot:
    absolute = report_path.expanduser().absolute()
    if absolute.name != RESULT_NAME:
        raise EvidenceValidationError(f"AC-26 report must be named {RESULT_NAME}")
    directory = absolute.parent
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceValidationError("AC-26 evidence parent must be a real directory")
    if os.name == "posix" and stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise EvidenceValidationError("AC-26 evidence directory must have mode 0700")
    names = {item.name for item in directory.iterdir()}
    if names != {RESULT_NAME, CHECKSUM_NAME}:
        raise EvidenceValidationError("AC-26 evidence directory must contain exactly report and checksum")
    report, report_bytes = _read_regular(absolute, MAX_REPORT_BYTES, "AC-26 report")
    checksum, checksum_bytes = _read_regular(
        directory / CHECKSUM_NAME, 256, "AC-26 checksum"
    )
    expected = f"{report.sha256}  {RESULT_NAME}\n".encode()
    if checksum_bytes != expected:
        raise EvidenceValidationError("AC-26 checksum does not exactly bind the report")
    for pattern in SECRET_PATTERNS:
        if pattern.search(report_bytes):
            raise EvidenceValidationError("AC-26 report appears to contain credential or private material")
    return EvidenceSnapshot(directory.resolve(strict=True), report, checksum, report_bytes, checksum_bytes)


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in {
            "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        } or name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(name, None)
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
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=_git_environment(),
        )
    except OSError as exception:
        raise EvidenceValidationError("Git is required for AC-26 candidate binding") from exception
    if len(completed.stdout) > MAX_GIT_BYTES or len(completed.stderr) > MAX_GIT_BYTES:
        raise EvidenceValidationError("Git AC-26 candidate output is too large")
    if completed.returncode != 0:
        raise EvidenceValidationError("Git could not verify the AC-26 candidate")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError("Git returned non-ASCII AC-26 identity") from exception
    if not value or any(character in value for character in "\r\n\0"):
        raise EvidenceValidationError("Git returned malformed AC-26 identity")
    return value


def _repository(path: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise EvidenceValidationError("Repository root must be a real directory")
    repository = expanded.resolve(strict=True)
    top = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != repository:
        raise EvidenceValidationError("Repository root is not the exact Git top-level")
    return repository


def _blob(repository: Path, commit: str, relative: str) -> bytes:
    workspace = repository.joinpath(*relative.split("/"))
    if workspace.is_symlink() or not workspace.is_file():
        raise EvidenceValidationError(f"Candidate source is not a regular file: {relative}")
    entry = _git(repository, "ls-tree", "-z", commit, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise EvidenceValidationError(f"Candidate source is not one Git blob: {relative}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or encoded_path != relative.encode()
    ):
        raise EvidenceValidationError(f"Candidate source has an unsafe Git mode: {relative}")
    payload = _git(repository, "cat-file", "blob", f"{commit}:{relative}")
    if workspace.read_bytes() != payload:
        raise EvidenceValidationError(f"Workspace source differs from candidate blob: {relative}")
    return payload


def _root_version(payload: bytes) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise EvidenceValidationError("Candidate root pom.xml is invalid") from exception
    node = root.find("{http://maven.apache.org/POM/4.0.0}version")
    version = "" if node is None or node.text is None else node.text.strip()
    if VERSION.fullmatch(version) is None or version.endswith("-SNAPSHOT"):
        raise EvidenceValidationError("Candidate version is not a non-SNAPSHOT release")
    return version


def _module_parent_version(payload: bytes, label: str) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise EvidenceValidationError(f"Candidate {label} is invalid") from exception
    namespace = "{http://maven.apache.org/POM/4.0.0}"
    node = root.find(f"{namespace}parent/{namespace}version")
    version = "" if node is None or node.text is None else node.text.strip()
    if VERSION.fullmatch(version) is None or version.endswith("-SNAPSHOT"):
        raise EvidenceValidationError(f"Candidate {label} parent version is not a release")
    return version


def verify_candidate(
    value: Any,
    repository: Path,
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
) -> tuple[dict[str, Any], Mapping[str, bytes]]:
    candidate = _object(value, "candidate")
    _exact(candidate, CANDIDATE_FIELDS, "candidate")
    if (
        GIT_OBJECT.fullmatch(expected_commit) is None
        or VERSION.fullmatch(expected_version) is None
        or expected_version.endswith("-SNAPSHOT")
        or expected_tag != f"v{expected_version}"
    ):
        raise EvidenceValidationError("Expected AC-26 candidate identity is invalid")
    head = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if head != expected_commit or candidate.get("head") != head or candidate.get("tree") != tree:
        raise EvidenceValidationError("AC-26 candidate commit/tree differs from the expected HEAD")
    index = _git(repository, "ls-files", "-v", "-z")
    records = [record for record in index.split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise EvidenceValidationError("AC-26 candidate Git index contains hidden entries")
    if _git(
        repository, "status", "--porcelain=v1", "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise EvidenceValidationError("AC-26 candidate must be clean, including untracked files")
    tag_commit = _git_text(repository, "rev-parse", "--verify", f"refs/tags/{expected_tag}^{{commit}}")
    tag_object = _git_text(repository, "rev-parse", "--verify", f"refs/tags/{expected_tag}^{{tag}}")
    if (
        tag_commit != head
        or candidate.get("tag") != expected_tag
        or candidate.get("tagObject") != tag_object
        or GIT_OBJECT.fullmatch(tag_object) is None
    ):
        raise EvidenceValidationError("AC-26 candidate is not bound to the annotated release tag")
    blobs = {path: _blob(repository, head, path) for path in SOURCE_PATHS}
    if _root_version(blobs[ROOT_POM_PATH]) != expected_version:
        raise EvidenceValidationError("AC-26 root Maven version differs from the expected release")
    for module_path in (SECURITY_POM_PATH, MCP_POM_PATH):
        if _module_parent_version(blobs[module_path], module_path) != expected_version:
            raise EvidenceValidationError(
                f"AC-26 {module_path} parent version differs from the expected release"
            )
    frontend = _strict_json(blobs[FRONTEND_MANIFEST_PATH], "candidate frontend manifest")
    if frontend.get("version") != expected_version:
        raise EvidenceValidationError("AC-26 frontend version differs from the expected release")
    if (
        candidate.get("mavenVersion") != expected_version
        or candidate.get("frontendVersion") != expected_version
        or candidate.get("cleanWorktree") is not True
    ):
        raise EvidenceValidationError("AC-26 candidate self-binding fields differ from the release")
    hashes = _object(candidate.get("sourceSha256"), "candidate.sourceSha256")
    if set(hashes) != set(SOURCE_PATHS):
        raise EvidenceValidationError("AC-26 candidate source hash set is not exact")
    expected_hashes = {path: _sha256(payload) for path, payload in blobs.items()}
    if hashes != expected_hashes:
        raise EvidenceValidationError("AC-26 candidate source hashes differ from committed blobs")
    return candidate, blobs


def verify_runtime_identity(
    path: Path,
    repository: Path,
    expected_commit: str,
    expected_version: str,
    expected_reference: str,
    expected_image_id: str,
    expected_nginx_reference: str,
    expected_nginx_image_id: str,
) -> tuple[dict[str, Any], dict[str, Any], FileIdentity]:
    absolute = path.expanduser().absolute()
    if _inside(absolute.resolve(strict=True), repository):
        raise EvidenceValidationError("Runtime identity must be outside the Git candidate")
    identity, payload = _read_regular(
        absolute, MAX_RUNTIME_IDENTITY_BYTES, "runtime identity"
    )
    document = _strict_json(payload, "runtime identity")
    if document.get("schemaVersion") != 2 or document.get("status") != "PASS":
        raise EvidenceValidationError("Runtime identity is not schemaVersion 2 PASS")
    if document.get("release") != {"version": expected_version, "gitCommit": expected_commit}:
        raise EvidenceValidationError("Runtime identity release differs from the AC-26 candidate")
    images = _object(document.get("images"), "runtime identity images")
    if set(images) != {"app", "nginx", "mysql", "redis"}:
        raise EvidenceValidationError("Runtime identity must contain the exact four services")
    app = _object(images.get("app"), "runtime identity app")
    nginx = _object(images.get("nginx"), "runtime identity nginx")
    expected_fields = {"reference", "imageId", "ociVersion", "ociRevision"}
    if set(app) != expected_fields or set(nginx) != expected_fields:
        raise EvidenceValidationError("Runtime identity release image fields are not exact")
    if (
        app.get("reference") != expected_reference
        or app.get("imageId") != expected_image_id
        or app.get("ociVersion") != expected_version
        or app.get("ociRevision") != expected_commit
    ):
        raise EvidenceValidationError("Runtime identity app differs from caller expectations")
    if (
        nginx.get("reference") != expected_nginx_reference
        or nginx.get("imageId") != expected_nginx_image_id
        or nginx.get("ociVersion") != expected_version
        or nginx.get("ociRevision") != expected_commit
    ):
        raise EvidenceValidationError("Runtime identity Nginx differs from caller expectations")
    for dependency in ("mysql", "redis"):
        value = _object(images.get(dependency), f"runtime identity {dependency}")
        if (
            set(value) != expected_fields
            or not isinstance(value.get("reference"), str)
            or DIGEST_REFERENCE.fullmatch(value["reference"]) is None
            or not isinstance(value.get("imageId"), str)
            or IMAGE_ID.fullmatch(value["imageId"]) is None
            or value.get("ociVersion") is not None
            or value.get("ociRevision") is not None
        ):
            raise EvidenceValidationError("Runtime dependency identity is malformed")
    return app, nginx, identity


def _validate_jwks(
    value: Any,
    expected_fingerprints: Mapping[str, str],
    label: str,
) -> int:
    jwks = _object(value, label)
    _exact(jwks, JWKS_FIELDS, label)
    if jwks.get("httpStatus") != 200:
        raise EvidenceValidationError(f"{label} was not observed over HTTP 200")
    for field in (
        "responseContentTypeJson", "privateParametersAbsent", "metadataIssuerMatched",
        "metadataJwksUriMatched",
    ):
        _true(jwks.get(field), f"{label}.{field}")
    observed_at = _integer(
        jwks.get("observedAtEpochSeconds"), f"{label}.observedAtEpochSeconds", 1
    )
    kids = _array(jwks.get("kids"), f"{label}.kids")
    if (
        kids != sorted(expected_fingerprints)
        or len(kids) != len(set(kids))
        or jwks.get("keyCount") != len(kids)
    ):
        raise EvidenceValidationError(f"{label} does not contain the exact expected kids")
    fingerprints = _object(
        jwks.get("publicFingerprintSha256"), f"{label}.publicFingerprintSha256"
    )
    if fingerprints != dict(sorted(expected_fingerprints.items())):
        raise EvidenceValidationError(f"{label} public fingerprints differ from the key-ring binding")
    _string(jwks.get("responseSha256"), f"{label}.responseSha256", SHA256)
    return observed_at


def _validate_credential(value: Any, expected_kid: str, label: str) -> tuple[int, int]:
    credential = _object(value, label)
    _exact(credential, CREDENTIAL_FIELDS, label)
    if credential.get("httpStatus") != 200 or credential.get("algorithm") != "RS256":
        raise EvidenceValidationError(f"{label} was not a successful RS256 issuance")
    if credential.get("kid") != expected_kid:
        raise EvidenceValidationError(f"{label} was not issued by the active kid")
    for field in (
        "responseContentTypeJson", "issuerMatched", "audienceMatched", "requiredScopesMatched",
    ):
        _true(credential.get(field), f"{label}.{field}")
    issued = _integer(credential.get("issuedAtEpochSeconds"), f"{label}.issuedAt", 1)
    expires = _integer(credential.get("expiresAtEpochSeconds"), f"{label}.expiresAt", 1)
    if expires <= issued:
        raise EvidenceValidationError(f"{label} lifetime is invalid")
    for field in ("protectedHeaderSha256", "claimsSha256", "responseSha256"):
        _string(credential.get(field), f"{label}.{field}", SHA256)
    return issued, expires


def _validate_mcp(
    value: Any, expected_trace: str | None, label: str
) -> tuple[str, int, int]:
    mcp = _object(value, label)
    _exact(mcp, MCP_FIELDS, label)
    if (
        mcp.get("initializeHttpStatus") != 200
        or mcp.get("initializedHttpStatus") not in {200, 202, 204}
        or mcp.get("toolCallHttpStatus") != 200
        or mcp.get("deleteHttpStatus") not in {200, 202, 204}
        or mcp.get("protocolVersion") != "2025-11-25"
        or mcp.get("serverName") != "web-starter-mcp"
        or mcp.get("toolName") != "system.info"
    ):
        raise EvidenceValidationError(f"{label} is not a complete real MCP system.info exchange")
    _true(mcp.get("toolResultSuccess"), f"{label}.toolResultSuccess")
    _true(mcp.get("traceHeaderMatched"), f"{label}.traceHeaderMatched")
    started = _integer(mcp.get("startedAtEpochSeconds"), f"{label}.startedAt", 1)
    completed = _integer(mcp.get("completedAtEpochSeconds"), f"{label}.completedAt", 1)
    if completed < started:
        raise EvidenceValidationError(f"{label} completion precedes its start")
    trace = _string(mcp.get("traceId"), f"{label}.traceId", TRACE_ID)
    if expected_trace is not None and trace != expected_trace:
        raise EvidenceValidationError(f"{label} trace differs from its audit binding")
    for field in ("sessionIdSha256", "initializeResponseSha256", "toolResponseSha256"):
        _string(mcp.get(field), f"{label}.{field}", SHA256)
    return trace, started, completed


def _validate_audit(value: Any, source_trace: str, label: str) -> str:
    audit = _object(value, label)
    _exact(audit, AUDIT_FIELDS, label)
    if audit.get("httpStatus") != 200 or audit.get("sourceTraceId") != source_trace:
        raise EvidenceValidationError(f"{label} does not bind the source MCP trace")
    for field in ("rowMatched", "toolNameMatched", "successOutcomeMatched"):
        _true(audit.get(field), f"{label}.{field}")
    audit_trace = _string(audit.get("auditTraceId"), f"{label}.auditTraceId", TRACE_ID)
    if audit_trace == source_trace:
        raise EvidenceValidationError(f"{label} must use a distinct query trace")
    _string(audit.get("responseSha256"), f"{label}.responseSha256", SHA256)
    _integer(audit.get("attempt"), f"{label}.attempt", 1)
    if audit["attempt"] > 10:
        raise EvidenceValidationError(f"{label}.attempt exceeds the bounded retry policy")
    return audit_trace


def _validate_rejection(value: Any, label: str) -> tuple[str, int, int]:
    rejection = _object(value, label)
    _exact(rejection, REJECTION_FIELDS, label)
    if rejection.get("httpStatus") != 401:
        raise EvidenceValidationError(f"{label} is not an HTTP 401 bearer rejection")
    for field in ("traceHeaderMatched", "wwwAuthenticateBearer", "noSessionIssued"):
        _true(rejection.get(field), f"{label}.{field}")
    started = _integer(rejection.get("startedAtEpochSeconds"), f"{label}.startedAt", 1)
    completed = _integer(rejection.get("completedAtEpochSeconds"), f"{label}.completedAt", 1)
    if completed < started:
        raise EvidenceValidationError(f"{label} completion precedes its start")
    trace = _string(rejection.get("traceId"), f"{label}.traceId", TRACE_ID)
    _string(rejection.get("responseSha256"), f"{label}.responseSha256", SHA256)
    return trace, started, completed


def _transition_ingress_ids(value: Any, label: str) -> dict[str, str]:
    identifiers = _object(value, label)
    _exact(identifiers, {"nginx", "mcp-public-nginx"}, label)
    result = {
        service: _string(identifiers.get(service), f"{label}.{service}", CONTAINER_ID)
        for service in ("nginx", "mcp-public-nginx")
    }
    if len(set(result.values())) != 2:
        raise EvidenceValidationError(f"{label} reuses an ingress container ID")
    return result


def _validate_transition(
    value: Any,
    phase: str,
    previous: str | None,
    previous_ingress: Mapping[str, str] | None,
    image_id: str,
    nginx_reference: str,
    nginx_image_id: str,
) -> tuple[str, dict[str, str]]:
    transition = _object(value, f"runtime transition {phase}")
    _exact(transition, TRANSITION_FIELDS, f"runtime transition {phase}")
    if transition.get("phase") != phase:
        raise EvidenceValidationError("AC-26 container transitions are out of phase order")
    before = _string(
        transition.get("previousContainerId"), f"transition {phase}.previous", CONTAINER_ID
    )
    current = _string(
        transition.get("currentContainerId"), f"transition {phase}.current", CONTAINER_ID
    )
    if before == current or (previous is not None and before != previous):
        raise EvidenceValidationError("AC-26 app recreation chain is not continuous")
    if transition.get("imageId") != image_id:
        raise EvidenceValidationError("AC-26 app recreation used a different image ID")
    before_ingress = _transition_ingress_ids(
        transition.get("previousIngressContainerIds"), f"transition {phase}.previousIngress"
    )
    current_ingress = _transition_ingress_ids(
        transition.get("currentIngressContainerIds"), f"transition {phase}.currentIngress"
    )
    if (
        (previous_ingress is not None and before_ingress != dict(previous_ingress))
        or any(before_ingress[service] == current_ingress[service] for service in before_ingress)
        or transition.get("nginxReference") != nginx_reference
        or transition.get("nginxImageId") != nginx_image_id
    ):
        raise EvidenceValidationError("AC-26 ingress recreation chain or image identity is invalid")
    if transition.get("fixedServices") != ["app", "mcp-public-nginx", "nginx"]:
        raise EvidenceValidationError("AC-26 recreation services are not the fixed ingress set")
    for field in (
        "projectLabelMatched", "serviceLabelMatched", "allContainersHealthy",
        "portBindingsMatched", "noBuild", "noPull", "noDependencies",
    ):
        _true(transition.get(field), f"transition {phase}.{field}")
    return current, current_ingress


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        raise EvidenceValidationError(f"{label} is not a bounded UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exception:
        raise EvidenceValidationError(f"{label} is not an ISO timestamp") from exception
    return parsed.astimezone(timezone.utc)


def _expected_origin(value: str, label: str, *, public: bool) -> tuple[str, int]:
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    try:
        port = parsed.port
    except ValueError as exception:
        raise EvidenceValidationError(f"Expected {label} origin port is invalid") from exception
    if (
        not parsed.hostname
        or port is None
        or not 1024 <= port <= 65535
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceValidationError(f"Expected {label} origin is invalid")
    if public:
        if parsed.scheme != "https" or not parsed.hostname.endswith(".test"):
            raise EvidenceValidationError("Expected public origin must be an explicit HTTPS .test host")
    elif parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise EvidenceValidationError("Expected private origin must use HTTP loopback")
    return normalized, port


def validate_evidence(
    report_path: Path,
    repository_root: Path,
    runtime_identity_path: Path,
    *,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    expected_compose_project: str,
    expected_app_reference: str,
    expected_app_image_id: str,
    expected_nginx_reference: str,
    expected_nginx_image_id: str,
    expected_public_origin: str,
    expected_private_origin: str,
    expected_trace_prefix: str,
    expected_terminal_mode: str,
    require_pass: bool = True,
) -> dict[str, Any]:
    repository = _repository(repository_root)
    snapshot = snapshot_evidence(report_path)
    if snapshot.directory == repository or _inside(snapshot.directory, repository):
        raise EvidenceValidationError("AC-26 raw evidence must be outside the Git candidate")
    document = _strict_json(snapshot.report_bytes, "AC-26 report")
    _exact(document, TOP_FIELDS, "AC-26 report")
    if document.get("schemaVersion") != 2 or document.get("acceptanceId") != "V2-AC-26":
        raise EvidenceValidationError("AC-26 report identity is invalid")
    if document.get("status") != "PASS":
        if require_pass:
            raise EvidenceNotPassingError("V2-AC-26 evidence is not PASS")
        raise EvidenceValidationError("V2-AC-26 supports only independently recomputed PASS evidence")
    generated_at = _parse_time(document.get("generatedAt"), "generatedAt")

    candidate, blobs = verify_candidate(
        document.get("candidate"), repository, expected_candidate_commit,
        expected_candidate_version, expected_candidate_tag,
    )
    tool = _object(document.get("tool"), "tool")
    _exact(tool, TOOL_FIELDS, "tool")
    expected_tool = {
        "path": TOOL_PATH,
        "sha256": _sha256(blobs[TOOL_PATH]),
        "validatorPath": VALIDATOR_PATH,
        "validatorSha256": _sha256(blobs[VALIDATOR_PATH]),
        "schemaPath": SCHEMA_PATH,
        "schemaSha256": _sha256(blobs[SCHEMA_PATH]),
    }
    if tool != expected_tool:
        raise EvidenceValidationError("AC-26 tool/schema hashes differ from candidate blobs")

    if PROJECT.fullmatch(expected_compose_project) is None:
        raise EvidenceValidationError("Expected AC-26 Compose project is not isolated")
    if DIGEST_REFERENCE.fullmatch(expected_app_reference) is None:
        raise EvidenceValidationError("Expected AC-26 app reference is not immutable")
    if IMAGE_ID.fullmatch(expected_app_image_id) is None:
        raise EvidenceValidationError("Expected AC-26 app image ID is invalid")
    if DIGEST_REFERENCE.fullmatch(expected_nginx_reference) is None:
        raise EvidenceValidationError("Expected AC-26 Nginx reference is not immutable")
    if IMAGE_ID.fullmatch(expected_nginx_image_id) is None:
        raise EvidenceValidationError("Expected AC-26 Nginx image ID is invalid")
    public_origin, public_port = _expected_origin(
        expected_public_origin, "public", public=True
    )
    private_origin, private_port = _expected_origin(
        expected_private_origin, "private", public=False
    )
    if TRACE_PREFIX.fullmatch(expected_trace_prefix) is None:
        raise EvidenceValidationError("Expected AC-26 trace prefix is invalid")
    if expected_terminal_mode not in {"expiry", "revocation"}:
        raise EvidenceValidationError("Expected AC-26 terminal mode is invalid")
    runtime_app, runtime_nginx, runtime_identity = verify_runtime_identity(
        runtime_identity_path, repository, expected_candidate_commit, expected_candidate_version,
        expected_app_reference, expected_app_image_id,
        expected_nginx_reference, expected_nginx_image_id,
    )
    runtime = _object(document.get("runtime"), "runtime")
    _exact(runtime, RUNTIME_FIELDS, "runtime")
    if runtime.get("composeProject") != expected_compose_project:
        raise EvidenceValidationError("AC-26 Compose project differs from caller expectation")
    for field in ("publicOriginSha256", "privateOriginSha256", "runtimeIdentitySha256"):
        _string(runtime.get(field), f"runtime.{field}", SHA256)
    if (
        runtime.get("publicOriginSha256") != _sha256(public_origin.encode())
        or runtime.get("privateOriginSha256") != _sha256(private_origin.encode())
        or runtime.get("publicPort") != public_port
        or runtime.get("privatePort") != private_port
        or runtime.get("tracePrefix") != expected_trace_prefix
    ):
        raise EvidenceValidationError(
            "AC-26 runtime origin, port, or trace prefix differs from caller expectations"
        )
    if runtime.get("runtimeIdentitySha256") != runtime_identity.sha256:
        raise EvidenceValidationError("AC-26 evidence does not bind the supplied runtime identity")
    app = _object(runtime.get("app"), "runtime.app")
    _exact(app, APP_FIELDS, "runtime.app")
    reference_match = DIGEST_REFERENCE.fullmatch(expected_app_reference)
    assert reference_match is not None
    if app != {
        "requestedReference": expected_app_reference,
        "id": expected_app_image_id,
        "manifestDigest": reference_match.group("digest"),
        "ociVersion": expected_candidate_version,
        "ociRevision": expected_candidate_commit,
    }:
        raise EvidenceValidationError("AC-26 runtime app identity differs from the immutable candidate")
    if runtime_app != {
        "reference": expected_app_reference,
        "imageId": expected_app_image_id,
        "ociVersion": expected_candidate_version,
        "ociRevision": expected_candidate_commit,
    }:
        raise EvidenceValidationError("AC-26 runtime identity was changed during validation")
    nginx = _object(runtime.get("nginx"), "runtime.nginx")
    _exact(nginx, APP_FIELDS, "runtime.nginx")
    nginx_reference_match = DIGEST_REFERENCE.fullmatch(expected_nginx_reference)
    assert nginx_reference_match is not None
    if nginx != {
        "requestedReference": expected_nginx_reference,
        "id": expected_nginx_image_id,
        "manifestDigest": nginx_reference_match.group("digest"),
        "ociVersion": expected_candidate_version,
        "ociRevision": expected_candidate_commit,
    } or runtime_nginx != {
        "reference": expected_nginx_reference,
        "imageId": expected_nginx_image_id,
        "ociVersion": expected_candidate_version,
        "ociRevision": expected_candidate_commit,
    }:
        raise EvidenceValidationError("AC-26 runtime Nginx identity differs from the immutable candidate")

    key_ring = _object(document.get("keyRing"), "keyRing")
    _exact(key_ring, KEY_RING_FIELDS, "keyRing")
    old_kid = _string(key_ring.get("oldKid"), "keyRing.oldKid", KID)
    new_kid = _string(key_ring.get("newKid"), "keyRing.newKid", KID)
    if old_kid == new_kid:
        raise EvidenceValidationError("AC-26 old and new kid must differ")
    old_fingerprint = _string(
        key_ring.get("oldPublicFingerprintSha256"), "keyRing.oldFingerprint", SHA256
    )
    new_fingerprint = _string(
        key_ring.get("newPublicFingerprintSha256"), "keyRing.newFingerprint", SHA256
    )
    if old_fingerprint == new_fingerprint:
        raise EvidenceValidationError("AC-26 old and new public key fingerprints must differ")
    retain_until = _integer(
        key_ring.get("retainUntilEpochSeconds"), "keyRing.retainUntilEpochSeconds", 1
    )
    terminal_mode = key_ring.get("terminalMode")
    if terminal_mode != expected_terminal_mode:
        raise EvidenceValidationError("AC-26 terminal mode differs from caller expectation")
    if key_ring.get("initialPrivateKeyCount") != 1 or key_ring.get("rotatedPrivateKeyCount") != 1:
        raise EvidenceValidationError("AC-26 key phases do not contain exactly one private signer")
    _false(
        key_ring.get("retiringPrivateMaterialPresent"),
        "keyRing.retiringPrivateMaterialPresent",
    )
    if key_ring.get("terminalRevocationConfigured") is not (terminal_mode == "revocation"):
        raise EvidenceValidationError("AC-26 terminal revocation flag differs from terminal mode")

    transitions = _array(runtime.get("containerTransitions"), "runtime.containerTransitions")
    expected_phases = ["baseline", "rotated"] + (["terminal"] if terminal_mode == "revocation" else [])
    if len(transitions) != len(expected_phases):
        raise EvidenceValidationError("AC-26 evidence lacks the exact fixed app recreations")
    previous: str | None = None
    previous_ingress: dict[str, str] | None = None
    seen_containers: set[str] = set()
    for transition, phase in zip(transitions, expected_phases):
        current, current_ingress = _validate_transition(
            transition,
            phase,
            previous,
            previous_ingress,
            expected_app_image_id,
            expected_nginx_reference,
            expected_nginx_image_id,
        )
        before = transition["previousContainerId"]
        before_ingress = transition["previousIngressContainerIds"]
        current_ids = {current, *current_ingress.values()}
        if current_ids.intersection(seen_containers) or len(current_ids) != 3:
            raise EvidenceValidationError("AC-26 container recreation reused an earlier container ID")
        if previous is None:
            seen_containers.add(before)
            seen_containers.update(before_ingress.values())
        seen_containers.update(current_ids)
        previous = current
        previous_ingress = current_ingress

    observations = _object(document.get("observations"), "observations")
    _exact(observations, OBSERVATION_FIELDS, "observations")
    baseline = _object(observations.get("baseline"), "observations.baseline")
    rotated = _object(observations.get("rotated"), "observations.rotated")
    terminal = _object(observations.get("terminal"), "observations.terminal")
    _exact(baseline, BASELINE_FIELDS, "observations.baseline")
    _exact(rotated, ROTATED_FIELDS, "observations.rotated")
    _exact(terminal, TERMINAL_FIELDS, "observations.terminal")
    baseline_at = _integer(baseline.get("observedAtEpochSeconds"), "baseline.observedAt", 1)
    rotated_at = _integer(rotated.get("observedAtEpochSeconds"), "rotated.observedAt", 1)
    terminal_at = _integer(terminal.get("observedAtEpochSeconds"), "terminal.observedAt", 1)
    if not baseline_at <= rotated_at <= terminal_at:
        raise EvidenceValidationError("AC-26 runtime observation times are not monotonic")
    baseline_jwks_at = _validate_jwks(
        baseline.get("jwks"), {old_kid: old_fingerprint}, "baseline.jwks"
    )
    rotated_jwks_at = _validate_jwks(
        rotated.get("jwks"), {old_kid: old_fingerprint, new_kid: new_fingerprint},
        "rotated.jwks",
    )
    terminal_jwks_at = _validate_jwks(
        terminal.get("jwks"), {new_kid: new_fingerprint}, "terminal.jwks"
    )
    old_issued, old_expires = _validate_credential(
        baseline.get("oldOauthGrant"), old_kid, "baseline.oldOauthGrant"
    )
    new_issued, new_expires = _validate_credential(
        rotated.get("newOauthGrant"), new_kid, "rotated.newOauthGrant"
    )
    expected_traces = {
        "baseline": f"{expected_trace_prefix}-old-base",
        "oldWindow": f"{expected_trace_prefix}-old-window",
        "newActive": f"{expected_trace_prefix}-new-active",
        "auditOld": f"{expected_trace_prefix}-audit-old",
        "auditNew": f"{expected_trace_prefix}-audit-new",
        "rejected": f"{expected_trace_prefix}-old-reject",
        "final": f"{expected_trace_prefix}-new-final",
        "auditFinal": f"{expected_trace_prefix}-audit-final",
    }
    baseline_trace, baseline_started, baseline_completed = _validate_mcp(
        baseline.get("oldMcp"), expected_traces["baseline"], "baseline.oldMcp"
    )
    old_window_trace, old_window_started, old_window_completed = _validate_mcp(
        rotated.get("oldWithinWindowMcp"), expected_traces["oldWindow"],
        "rotated.oldWithinWindowMcp",
    )
    new_trace, new_started, new_completed = _validate_mcp(
        rotated.get("newActiveMcp"), expected_traces["newActive"],
        "rotated.newActiveMcp",
    )
    final_trace, final_started, final_completed = _validate_mcp(
        terminal.get("newActiveMcp"), expected_traces["final"],
        "terminal.newActiveMcp",
    )
    old_audit_trace = _validate_audit(
        rotated.get("oldTraceAudit"), old_window_trace, "rotated.oldTraceAudit"
    )
    new_audit_trace = _validate_audit(
        rotated.get("newTraceAudit"), new_trace, "rotated.newTraceAudit"
    )
    final_audit_trace = _validate_audit(
        terminal.get("newTraceAudit"), final_trace, "terminal.newTraceAudit"
    )
    rejected_trace, rejected_started, rejected_completed = _validate_rejection(
        terminal.get("oldCredentialRejected"), "terminal.oldCredentialRejected"
    )
    if (
        old_audit_trace != expected_traces["auditOld"]
        or new_audit_trace != expected_traces["auditNew"]
        or final_audit_trace != expected_traces["auditFinal"]
        or rejected_trace != expected_traces["rejected"]
    ):
        raise EvidenceValidationError("AC-26 traces differ from the caller-bound trace prefix")
    if not (
        baseline_jwks_at <= baseline_started <= baseline_completed == baseline_at
        <= rotated_jwks_at <= old_window_started <= old_window_completed == rotated_at
        <= new_started <= new_completed <= terminal_jwks_at
        <= rejected_started <= rejected_completed == terminal_at
        <= final_started <= final_completed
    ):
        raise EvidenceValidationError("AC-26 concrete HTTP observation times are not ordered")
    if old_issued > baseline_started or old_expires <= rejected_completed:
        raise EvidenceValidationError("AC-26 old JWT lifetime does not isolate key retirement")
    if new_issued > new_started or new_expires <= final_completed:
        raise EvidenceValidationError("AC-26 new active JWT did not remain valid through terminal checks")
    if rotated_jwks_at >= retain_until or old_window_completed >= retain_until:
        raise EvidenceValidationError("AC-26 old JWT did not complete inside the retiring window")
    if terminal_mode == "expiry" and (
        terminal_jwks_at < retain_until or rejected_started < retain_until
    ):
        raise EvidenceValidationError("AC-26 expiry rejection occurred before the exclusive boundary")
    if terminal_mode == "revocation" and (
        terminal_jwks_at >= retain_until or rejected_completed >= retain_until
    ):
        raise EvidenceValidationError("AC-26 revocation rejection did not complete before exp")
    if int(generated_at.timestamp()) < final_completed:
        raise EvidenceValidationError("AC-26 generatedAt precedes the final runtime observation")
    traces = {
        baseline_trace, old_window_trace, new_trace, final_trace, old_audit_trace,
        new_audit_trace, final_audit_trace, rejected_trace,
    }
    if len(traces) != 8:
        raise EvidenceValidationError("AC-26 protocol and audit traces must be unique")

    supplemental = _object(
        document.get("supplementalConfigurationGuards"), "supplementalConfigurationGuards"
    )
    _exact(supplemental, SUPPLEMENTAL_FIELDS, "supplementalConfigurationGuards")
    if supplemental != {
        "status": "SOURCE_BOUND_ONLY",
        "unknownKidRuntime": "NOT_COVERED",
        "invalidActiveRuntime": "NOT_COVERED",
        "unitTestSourcePath": KEY_RING_TEST_PATH,
        "unitTestSourceSha256": _sha256(blobs[KEY_RING_TEST_PATH]),
    }:
        raise EvidenceValidationError("AC-26 supplemental guards overstate runtime coverage")

    policy = _object(document.get("evidencePolicy"), "evidencePolicy")
    _exact(policy, POLICY_FIELDS, "evidencePolicy")
    expected_policy = {
        "outsideRepository": True,
        "directoryMode": "0700",
        "fileMode": "0600",
        "onlyReportAndChecksum": True,
        "rawHttpBodiesPersisted": False,
        "credentialsPersisted": False,
        "privateKeyMaterialPersisted": False,
        "arbitraryHookAccepted": False,
        "dockerResourcesRemoved": False,
    }
    if policy != expected_policy:
        raise EvidenceValidationError("AC-26 evidence privacy/safety policy is not exact")

    # Re-stat all caller-controlled evidence after Git and runtime validation.
    after = snapshot_evidence(report_path)
    if after.report != snapshot.report or after.checksum != snapshot.checksum:
        raise EvidenceValidationError("AC-26 evidence changed during validation")
    _, _, runtime_after = verify_runtime_identity(
        runtime_identity_path, repository, expected_candidate_commit, expected_candidate_version,
        expected_app_reference, expected_app_image_id,
        expected_nginx_reference, expected_nginx_image_id,
    )
    if runtime_after != runtime_identity:
        raise EvidenceValidationError("Runtime identity changed during AC-26 validation")
    candidate_after, blobs_after = verify_candidate(
        document.get("candidate"), repository, expected_candidate_commit,
        expected_candidate_version, expected_candidate_tag,
    )
    if candidate_after != candidate or blobs_after != blobs:
        raise EvidenceValidationError("AC-26 candidate changed during validation")

    return {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-26",
        "status": "PASS",
        "candidate": {
            "commit": expected_candidate_commit,
            "tag": expected_candidate_tag,
            "version": expected_candidate_version,
        },
        "runtime": {
            "composeProject": expected_compose_project,
            "appReference": expected_app_reference,
            "appImageId": expected_app_image_id,
            "nginxReference": expected_nginx_reference,
            "nginxImageId": expected_nginx_image_id,
            "publicOriginSha256": _sha256(public_origin.encode()),
            "privateOriginSha256": _sha256(private_origin.encode()),
            "publicPort": public_port,
            "privatePort": private_port,
            "tracePrefix": expected_trace_prefix,
        },
        "rotation": {
            "oldKid": old_kid,
            "newKid": new_kid,
            "terminalMode": terminal_mode,
            "retainUntilEpochSeconds": retain_until,
        },
        "checks": {
            "realOAuthIssuance": "PASS",
            "activeAndRetiringJwks": "PASS",
            "newCredentialUsesActiveKid": "PASS",
            "oldCredentialWithinWindowMcp": "PASS",
            "oldCredentialTerminalRejection": "PASS",
            "newCredentialContinuity": "PASS",
            "traceAuditCorrelation": "PASS",
            "privateMaterialNotPersisted": "PASS",
            "unknownKidRuntime": "NOT_COVERED",
            "invalidActiveRuntime": "NOT_COVERED",
        },
        "evidence": {
            "reportSha256": snapshot.report.sha256,
            "runtimeIdentitySha256": runtime_identity.sha256,
            "sourceSha256": candidate["sourceSha256"],
        },
    }


def write_canonical_summary(path: Path, summary: Mapping[str, Any]) -> None:
    expanded = path.expanduser().absolute()
    if expanded.name != SUMMARY_NAME:
        raise EvidenceValidationError(f"Canonical AC-26 summary must be named {SUMMARY_NAME}")
    if expanded.exists() or expanded.is_symlink():
        raise EvidenceValidationError("Canonical AC-26 summary must not already exist")
    parent = expanded.parent
    if parent.is_symlink() or not parent.is_dir():
        raise EvidenceValidationError("Canonical AC-26 summary parent must be a real directory")
    if os.name == "posix" and stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise EvidenceValidationError("Canonical AC-26 summary parent must have mode 0700")
    payload = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(expanded, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate V2-AC-26 JWKS rotation evidence")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--runtime-identity", required=True, type=Path)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-tag", required=True)
    parser.add_argument("--expected-compose-project", required=True)
    parser.add_argument("--expected-app-reference", required=True)
    parser.add_argument("--expected-app-image-id", required=True)
    parser.add_argument("--expected-nginx-reference", required=True)
    parser.add_argument("--expected-nginx-image-id", required=True)
    parser.add_argument("--expected-public-origin", required=True)
    parser.add_argument("--expected-private-origin", required=True)
    parser.add_argument("--expected-trace-prefix", required=True)
    parser.add_argument(
        "--expected-terminal-mode", required=True, choices=("expiry", "revocation")
    )
    parser.add_argument("--summary-output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_evidence(
            args.evidence,
            args.repository_root,
            args.runtime_identity,
            expected_candidate_commit=args.expected_candidate_commit,
            expected_candidate_version=args.expected_candidate_version,
            expected_candidate_tag=args.expected_candidate_tag,
            expected_compose_project=args.expected_compose_project,
            expected_app_reference=args.expected_app_reference,
            expected_app_image_id=args.expected_app_image_id,
            expected_nginx_reference=args.expected_nginx_reference,
            expected_nginx_image_id=args.expected_nginx_image_id,
            expected_public_origin=args.expected_public_origin,
            expected_private_origin=args.expected_private_origin,
            expected_trace_prefix=args.expected_trace_prefix,
            expected_terminal_mode=args.expected_terminal_mode,
            require_pass=True,
        )
        write_canonical_summary(args.summary_output, summary)
    except (EvidenceValidationError, OSError, ValueError) as error:
        print(f"FAIL V2-AC-26 evidence: {error}", file=sys.stderr)
        return 1
    print(
        "PASS V2-AC-26 evidence: independently verified real OAuth/JWKS/MCP rotation "
        "and terminal rejection"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
