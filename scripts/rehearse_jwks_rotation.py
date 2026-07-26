#!/usr/bin/env python3
"""Produce candidate-bound V2-AC-26 JWKS rotation runtime evidence.

The producer is intentionally limited to an already-created disposable
``web-starter-ac26-*`` Compose project.  It accepts no command hook and never
builds, pulls, removes, or prunes Docker resources.  The only permitted Docker
mutation is a fixed, no-dependency recreation of the existing app and its two
ingress containers with one of three caller-supplied private JWK-set files.

Tokens, client secrets, cookies, private JWK members, and HTTP bodies remain in
memory.  The evidence directory contains only a sanitized JSON observation and
its checksum, both mode 0600.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
import xml.etree.ElementTree as ElementTree

from acceptance_network import (
    RejectRedirectHandler,
    is_isolated_acceptance_host,
    isolated_loopback_resolution,
    loopback_aliases,
    reject_tls_key_logging,
)


RESULT_NAME = "v2-ac26-jwks-rotation.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"
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

PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
REQUIRED_SCOPES = frozenset({"system:info", "audit:list"})
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
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
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_HTTP_BYTES = 2 * 1024 * 1024
MAX_GIT_BYTES = 8 * 1024 * 1024
MIN_RSA_BITS = 3072


class RehearsalError(RuntimeError):
    """A safe, non-secret-bearing orchestration failure."""


@dataclass(frozen=True)
class CandidateIdentity:
    head: str
    tree: str
    tag: str
    tag_object: str
    version: str
    source_sha256: Mapping[str, str]


@dataclass(frozen=True)
class AppIdentity:
    reference: str
    image_id: str
    manifest_digest: str
    oci_version: str
    oci_revision: str
    nginx_reference: str
    nginx_image_id: str
    nginx_manifest_digest: str
    nginx_oci_version: str
    nginx_oci_revision: str
    runtime_identity_sha256: str


@dataclass(frozen=True)
class RingMaterial:
    active_kid: str
    retiring_kid: str | None
    retain_until: int | None
    revoked: bool
    active_public_fingerprint: str
    retiring_public_fingerprint: str | None
    private_key_count: int
    retiring_has_private_material: bool
    compact_json: str


@dataclass(frozen=True)
class ContainerIdentity:
    container_id: str
    image_id: str
    configured_reference: str


@dataclass(frozen=True)
class RuntimeContainers:
    app: ContainerIdentity
    ingress_container_ids: Mapping[str, str]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _private_file(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> tuple[Path, bytes]:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_file():
        raise RehearsalError(f"{label} must be a real regular file")
    resolved = expanded.resolve(strict=True)
    before = resolved.stat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exception:
        raise RehearsalError(f"{label} cannot be opened safely") from exception
    try:
        opened = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    after = resolved.stat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, stat.S_IMODE(item.st_mode))
        for item in (before, opened, after)
    }
    if len(identities) != 1 or len(payload) != opened.st_size:
        raise RehearsalError(f"{label} changed while being read")
    if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or opened.st_size > maximum:
        raise RehearsalError(f"{label} has an invalid size")
    if os.name == "posix" and stat.S_IMODE(opened.st_mode) != 0o600:
        raise RehearsalError(f"{label} must have mode 0600")
    return resolved, bytes(payload)


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RehearsalError(f"{label} repeats a JSON member")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise RehearsalError(f"{label} contains a non-finite number: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RehearsalError(f"{label} is not strict UTF-8 JSON") from exception
    if not isinstance(value, dict):
        raise RehearsalError(f"{label} must contain one JSON object")
    return value


def ensure_output_directory(path: Path, repository: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink():
        raise RehearsalError("AC-26 evidence directory must not be a symbolic link")
    resolved = expanded.resolve()
    if resolved == repository or _inside(resolved, repository):
        raise RehearsalError("AC-26 evidence directory must be outside the Git candidate")
    if expanded.exists():
        if not expanded.is_dir() or any(expanded.iterdir()):
            raise RehearsalError("AC-26 evidence directory must be an empty directory")
    else:
        expanded.mkdir(parents=True, mode=0o700)
    if os.name == "posix" and stat.S_IMODE(expanded.stat().st_mode) != 0o700:
        raise RehearsalError("AC-26 evidence directory must have mode 0700")
    return expanded.resolve(strict=True)


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


def _run(command: Sequence[str], *, timeout: int = 60, environment: Mapping[str, str] | None = None) -> bytes:
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=None if environment is None else dict(environment),
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        raise RehearsalError("A fixed local verification command could not complete") from exception
    if len(completed.stdout) > MAX_GIT_BYTES or len(completed.stderr) > MAX_GIT_BYTES:
        raise RehearsalError("A fixed local verification command produced excessive output")
    if completed.returncode != 0:
        raise RehearsalError("A fixed local verification command failed")
    return completed.stdout


def _local_docker_environment() -> dict[str, str]:
    """Return a sanitized environment only after proving a local Unix endpoint."""
    dangerous = [
        name for name, value in os.environ.items()
        if value and (
            name in {
                "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
                "DOCKER_TLS", "DOCKER_TLS_VERIFY", "COMPOSE_FILE", "COMPOSE_PROJECT_NAME",
                "COMPOSE_PROFILES", "COMPOSE_ENV_FILES", "COMPOSE_PATH_SEPARATOR",
            }
            or name.startswith("COMPOSE_EXPERIMENTAL_")
        )
    ]
    if dangerous:
        raise RehearsalError("AC-26 refuses Docker/Compose endpoint or project environment overrides")
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith(("DOCKER_", "COMPOSE_")):
            environment.pop(name, None)
    context_raw = _run(["docker", "context", "show"], timeout=30, environment=environment)
    try:
        context_name = context_raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise RehearsalError("Docker context name is not ASCII") from exception
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", context_name):
        raise RehearsalError("Docker context name is invalid")
    context_payload = _run(
        ["docker", "context", "inspect", context_name], timeout=30, environment=environment
    )
    contexts = _strict_json_array(context_payload, "Docker context inspection")
    if len(contexts) != 1 or not isinstance(contexts[0], dict):
        raise RehearsalError("Docker context inspection did not return one context")
    endpoints = contexts[0].get("Endpoints")
    docker_endpoint = endpoints.get("docker") if isinstance(endpoints, dict) else None
    host = docker_endpoint.get("Host") if isinstance(docker_endpoint, dict) else None
    if not isinstance(host, str) or not host.startswith("unix://"):
        raise RehearsalError("AC-26 Docker context must use a local Unix socket")
    parsed = urlparse(host)
    socket_path = Path(unquote(parsed.path)).expanduser().resolve(strict=True)
    if not socket_path.is_socket():
        raise RehearsalError("AC-26 Docker context endpoint is not a local Unix socket")
    return environment


def _git(repository: Path, *arguments: str) -> bytes:
    return _run(
        [
            "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-C", str(repository), *arguments,
        ],
        environment=_git_environment(),
    )


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise RehearsalError("Git returned a non-ASCII candidate identity") from exception
    if not value or "\n" in value or "\r" in value or "\0" in value:
        raise RehearsalError("Git returned an invalid candidate identity")
    return value


def _repository_root(path: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise RehearsalError("Repository root must be a real directory")
    repository = expanded.resolve(strict=True)
    top = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != repository:
        raise RehearsalError("Repository root must be the exact Git top-level")
    return repository


def _candidate_blob(repository: Path, head: str, relative: str) -> bytes:
    workspace = repository.joinpath(*relative.split("/"))
    if workspace.is_symlink() or not workspace.is_file():
        raise RehearsalError(f"Candidate source is not a regular file: {relative}")
    entry = _git(repository, "ls-tree", "-z", head, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise RehearsalError(f"Candidate source is not one tracked blob: {relative}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or encoded_path != relative.encode()
    ):
        raise RehearsalError(f"Candidate source has an unsafe Git mode: {relative}")
    payload = _git(repository, "cat-file", "blob", f"{head}:{relative}")
    if payload != workspace.read_bytes():
        raise RehearsalError(f"Workspace source differs from candidate blob: {relative}")
    return payload


def _maven_version(payload: bytes) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise RehearsalError("Root pom.xml is not valid XML") from exception
    namespace = "{http://maven.apache.org/POM/4.0.0}"
    node = root.find(f"{namespace}version")
    value = "" if node is None or node.text is None else node.text.strip()
    if VERSION.fullmatch(value) is None or value.endswith("-SNAPSHOT"):
        raise RehearsalError("Candidate Maven version must be a non-SNAPSHOT release")
    return value


def _module_parent_version(payload: bytes, label: str) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise RehearsalError(f"{label} is not valid XML") from exception
    namespace = "{http://maven.apache.org/POM/4.0.0}"
    node = root.find(f"{namespace}parent/{namespace}version")
    value = "" if node is None or node.text is None else node.text.strip()
    if VERSION.fullmatch(value) is None or value.endswith("-SNAPSHOT"):
        raise RehearsalError(f"{label} parent version must be a non-SNAPSHOT release")
    return value


def candidate_identity(repository: Path) -> CandidateIdentity:
    head = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if GIT_OBJECT.fullmatch(head) is None or GIT_OBJECT.fullmatch(tree) is None:
        raise RehearsalError("Git candidate object identity is malformed")
    index = _git(repository, "ls-files", "-v", "-z")
    records = [record for record in index.split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise RehearsalError("Git index contains hidden or non-cached entries")
    if _git(
        repository, "status", "--porcelain=v1", "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise RehearsalError("Git candidate must be clean, including untracked files")

    payloads = {path: _candidate_blob(repository, head, path) for path in SOURCE_PATHS}
    version = _maven_version(payloads[ROOT_POM_PATH])
    for module_path in (SECURITY_POM_PATH, MCP_POM_PATH):
        if _module_parent_version(payloads[module_path], module_path) != version:
            raise RehearsalError(f"{module_path} parent version differs from the root release")
    try:
        frontend = _strict_json(payloads[FRONTEND_MANIFEST_PATH], "frontend package manifest")
    except RehearsalError:
        raise
    if frontend.get("version") != version:
        raise RehearsalError("Frontend and Maven candidate versions differ")
    tag = f"v{version}"
    peeled = _git_text(repository, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if peeled != head:
        raise RehearsalError("Release tag does not resolve to candidate HEAD")
    tag_object = _git_text(repository, "rev-parse", "--verify", f"refs/tags/{tag}^{{tag}}")
    if GIT_OBJECT.fullmatch(tag_object) is None:
        raise RehearsalError("Release tag must be an annotated tag object")
    return CandidateIdentity(
        head=head,
        tree=tree,
        tag=tag,
        tag_object=tag_object,
        version=version,
        source_sha256={path: _sha256(payload) for path, payload in payloads.items()},
    )


def load_runtime_identity(path: Path, candidate: CandidateIdentity, repository: Path) -> AppIdentity:
    resolved, payload = _private_file(path, "runtime identity")
    if _inside(resolved, repository):
        raise RehearsalError("Runtime identity must be outside the Git candidate")
    document = _strict_json(payload, "runtime identity")
    if document.get("schemaVersion") != 2 or document.get("status") != "PASS":
        raise RehearsalError("Runtime identity is not a schemaVersion 2 PASS document")
    if document.get("release") != {"version": candidate.version, "gitCommit": candidate.head}:
        raise RehearsalError("Runtime identity release differs from the Git candidate")
    images = document.get("images")
    if not isinstance(images, dict) or set(images) != {"app", "nginx", "mysql", "redis"}:
        raise RehearsalError("Runtime identity must contain the exact four release services")
    app = images.get("app")
    nginx = images.get("nginx")
    expected_fields = {"reference", "imageId", "ociVersion", "ociRevision"}
    if (
        not isinstance(app, dict)
        or not isinstance(nginx, dict)
        or set(app) != expected_fields
        or set(nginx) != expected_fields
    ):
        raise RehearsalError("Runtime release image identity has unexpected fields")
    reference = app.get("reference")
    image_id = app.get("imageId")
    match = DIGEST_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
    if match is None or not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
        raise RehearsalError("Runtime app image identity is malformed")
    if app.get("ociVersion") != candidate.version or app.get("ociRevision") != candidate.head:
        raise RehearsalError("Runtime app OCI identity differs from the candidate")
    nginx_reference = nginx.get("reference")
    nginx_image_id = nginx.get("imageId")
    nginx_match = (
        DIGEST_REFERENCE.fullmatch(nginx_reference)
        if isinstance(nginx_reference, str) else None
    )
    if (
        nginx_match is None
        or not isinstance(nginx_image_id, str)
        or IMAGE_ID.fullmatch(nginx_image_id) is None
        or nginx.get("ociVersion") != candidate.version
        or nginx.get("ociRevision") != candidate.head
    ):
        raise RehearsalError("Runtime Nginx identity differs from the candidate release")
    for dependency in ("mysql", "redis"):
        value = images.get(dependency)
        if not isinstance(value, dict) or set(value) != expected_fields:
            raise RehearsalError("Runtime dependency image identity has unexpected fields")
        if (
            not isinstance(value.get("reference"), str)
            or DIGEST_REFERENCE.fullmatch(value["reference"]) is None
            or not isinstance(value.get("imageId"), str)
            or IMAGE_ID.fullmatch(value["imageId"]) is None
            or value.get("ociVersion") is not None
            or value.get("ociRevision") is not None
        ):
            raise RehearsalError("Runtime dependency image identity is malformed")
    return AppIdentity(
        reference=reference,
        image_id=image_id,
        manifest_digest=match.group("digest"),
        oci_version=candidate.version,
        oci_revision=candidate.head,
        nginx_reference=nginx_reference,
        nginx_image_id=nginx_image_id,
        nginx_manifest_digest=nginx_match.group("digest"),
        nginx_oci_version=candidate.version,
        nginx_oci_revision=candidate.head,
        runtime_identity_sha256=_sha256(payload),
    )


def _base64url_integer(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,1024}", value):
        raise RehearsalError(f"{label} is not a bounded base64url integer")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exception:
        raise RehearsalError(f"{label} is not valid base64url") from exception
    if not decoded or decoded[0] == 0:
        raise RehearsalError(f"{label} is not a minimal positive integer")
    return int.from_bytes(decoded, "big")


def _public_fingerprint(jwk: Mapping[str, Any]) -> str:
    return _canonical_sha256({"kty": "RSA", "n": jwk["n"], "e": jwk["e"]})


def _validate_rsa_key(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RehearsalError(f"{label} must be a JSON object")
    allowed = {
        "kty", "use", "alg", "kid", "n", "e", "d", "p", "q", "dp", "dq", "qi",
        "oth", "exp", "nbf", "iat", "rev",
    }
    if not set(value).issubset(allowed):
        raise RehearsalError(f"{label} contains unsupported JWK members")
    if value.get("kty") != "RSA" or value.get("use") not in {None, "sig"}:
        raise RehearsalError(f"{label} must be an RSA signing key")
    if value.get("alg") not in {None, "RS256"}:
        raise RehearsalError(f"{label} must use RS256")
    kid = value.get("kid")
    if not isinstance(kid, str) or KID.fullmatch(kid) is None:
        raise RehearsalError(f"{label} has an invalid kid")
    modulus = _base64url_integer(value.get("n"), f"{label}.n")
    exponent = _base64url_integer(value.get("e"), f"{label}.e")
    if modulus.bit_length() < MIN_RSA_BITS or exponent < 3 or exponent % 2 == 0:
        raise RehearsalError(f"{label} does not contain a safe RSA public key")
    private = PRIVATE_JWK_MEMBERS.intersection(value)
    if private and not {"d", "p", "q", "dp", "dq", "qi"}.issubset(value):
        raise RehearsalError(f"{label} contains incomplete private RSA material")
    return value


def load_key_ring(
    path: Path,
    active_kid: str,
    mode: str,
    repository: Path | None = None,
) -> RingMaterial:
    resolved, payload = _private_file(path, f"{mode} JWK set")
    if repository is not None and _inside(resolved, repository):
        raise RehearsalError("AC-26 JWK sets must remain outside the Git candidate")
    document = _strict_json(payload, f"{mode} JWK set")
    if set(document) != {"keys"} or not isinstance(document["keys"], list):
        raise RehearsalError(f"{mode} JWK set must contain only a keys array")
    keys = [_validate_rsa_key(value, f"{mode} JWK") for value in document["keys"]]
    if len(keys) not in {1, 2}:
        raise RehearsalError(f"{mode} JWK set must contain one or two keys")
    if len({key["kid"] for key in keys}) != len(keys):
        raise RehearsalError(f"{mode} JWK set repeats a kid")
    active_matches = [key for key in keys if key["kid"] == active_kid]
    if len(active_matches) != 1:
        raise RehearsalError(f"{mode} JWK set does not contain exactly one active kid")
    active = active_matches[0]
    if not PRIVATE_JWK_MEMBERS.intersection(active):
        raise RehearsalError(f"{mode} active JWK must contain private signing material")
    if "exp" in active or "rev" in active:
        raise RehearsalError(f"{mode} active JWK must not be expiring or revoked")
    retiring = next((key for key in keys if key is not active), None)
    retain_until: int | None = None
    revoked = False
    retiring_private = False
    if retiring is not None:
        retain_until = retiring.get("exp")
        if isinstance(retain_until, bool) or not isinstance(retain_until, int) or retain_until <= 0:
            raise RehearsalError(f"{mode} retiring JWK needs a positive exp NumericDate")
        retiring_private = bool(PRIVATE_JWK_MEMBERS.intersection(retiring))
        rev = retiring.get("rev")
        if rev is not None and (not isinstance(rev, dict) or not rev):
            raise RehearsalError(f"{mode} retiring JWK rev member must be a non-empty object")
        revoked = rev is not None
    compact = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return RingMaterial(
        active_kid=active["kid"],
        retiring_kid=None if retiring is None else retiring["kid"],
        retain_until=retain_until,
        revoked=revoked,
        active_public_fingerprint=_public_fingerprint(active),
        retiring_public_fingerprint=None if retiring is None else _public_fingerprint(retiring),
        private_key_count=sum(bool(PRIVATE_JWK_MEMBERS.intersection(key)) for key in keys),
        retiring_has_private_material=retiring_private,
        compact_json=compact,
    )


def validate_ring_sequence(
    initial: RingMaterial,
    rotated: RingMaterial,
    terminal: RingMaterial | None,
    terminal_mode: str,
) -> None:
    if initial.retiring_kid is not None or initial.private_key_count != 1 or initial.revoked:
        raise RehearsalError("Initial JWK set must contain only the old active private key")
    if rotated.retiring_kid != initial.active_kid:
        raise RehearsalError("Rotated JWK set must retain the old active kid")
    if rotated.active_kid == initial.active_kid:
        raise RehearsalError("Rotated JWK set must select a different active kid")
    if rotated.retiring_has_private_material or rotated.private_key_count != 1 or rotated.revoked:
        raise RehearsalError("Rotated JWK set must expose the old key as non-revoked public-only material")
    if rotated.retiring_public_fingerprint != initial.active_public_fingerprint:
        raise RehearsalError("Rotated retiring public key does not match the initial active key")
    if terminal_mode == "expiry":
        if terminal is not None:
            raise RehearsalError("Expiry mode must not supply a terminal JWK set")
        return
    if terminal_mode != "revocation" or terminal is None:
        raise RehearsalError("Revocation mode requires a terminal revoked JWK set")
    if (
        terminal.active_kid != rotated.active_kid
        or terminal.retiring_kid != rotated.retiring_kid
        or terminal.active_public_fingerprint != rotated.active_public_fingerprint
        or terminal.retiring_public_fingerprint != rotated.retiring_public_fingerprint
        or terminal.retain_until != rotated.retain_until
        or not terminal.revoked
        or terminal.retiring_has_private_material
        or terminal.private_key_count != 1
    ):
        raise RehearsalError("Terminal JWK set must add rev only to the same public retiring key")


def _parse_env(path: Path, repository: Path) -> tuple[Path, dict[str, str]]:
    resolved, payload = _private_file(path, "Compose environment", maximum=512 * 1024)
    if _inside(resolved, repository):
        raise RehearsalError("Compose environment must be outside the Git candidate")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise RehearsalError("Compose environment is not UTF-8") from exception
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RehearsalError("Compose environment contains an invalid line")
        key, value = line.split("=", 1)
        if ENV_KEY.fullmatch(key) is None or key in values or "\0" in value:
            raise RehearsalError("Compose environment contains an invalid or duplicate key")
        values[key] = value
    required = {
        "WEB_STARTER_APP_IMAGE", "WEB_STARTER_APP_DIGEST", "WEB_STARTER_NGINX_IMAGE",
        "WEB_STARTER_NGINX_DIGEST", "WEB_STARTER_OAUTH_ISSUER",
        "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE", "WEB_STARTER_PUBLIC_TLS_CERT_FILE",
        "WEB_STARTER_PUBLIC_TLS_KEY_FILE",
    }
    if not required.issubset(values):
        raise RehearsalError("Compose environment is missing required immutable runtime values")
    return resolved, values


def _validate_runtime_env_files(
    values: Mapping[str, str], repository: Path
) -> dict[str, bytes]:
    app_reference = values["WEB_STARTER_APP_IMAGE"] + "@" + values["WEB_STARTER_APP_DIGEST"]
    nginx_reference = values["WEB_STARTER_NGINX_IMAGE"] + "@" + values["WEB_STARTER_NGINX_DIGEST"]
    if DIGEST_REFERENCE.fullmatch(app_reference) is None or DIGEST_REFERENCE.fullmatch(nginx_reference) is None:
        raise RehearsalError("Compose app and ingress images must use immutable digest references")
    if values.get("WEB_STARTER_HTTP_BIND_ADDRESS", "127.0.0.1") != "127.0.0.1":
        raise RehearsalError("AC-26 private ingress must remain bound to 127.0.0.1")
    if values.get("WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS", "") != "127.0.0.1":
        raise RehearsalError("AC-26 public ingress must remain bound to 127.0.0.1")
    for name in ("WEB_STARTER_HTTP_PORT", "WEB_STARTER_PUBLIC_MCP_PORT"):
        raw = values.get(name, "")
        if not raw.isdigit() or not 1024 <= int(raw) <= 65535:
            raise RehearsalError(f"{name} must be an explicit unprivileged acceptance port")
    tls_payloads: dict[str, bytes] = {}
    for name in ("WEB_STARTER_PUBLIC_TLS_CERT_FILE", "WEB_STARTER_PUBLIC_TLS_KEY_FILE"):
        resolved, payload = _private_file(Path(values[name]), name, maximum=128 * 1024)
        if _inside(resolved, repository):
            raise RehearsalError(f"{name} must remain outside the Git candidate")
        tls_payloads[name] = payload
    forbidden = [name for name in values if name.startswith(("COMPOSE_", "DOCKER_"))]
    if forbidden:
        raise RehearsalError("Compose environment must not contain Docker or Compose control variables")
    return tls_payloads


def _validate_origins_against_runtime(
    public_origin: str,
    private_origin: str,
    values: Mapping[str, str],
) -> tuple[int, int]:
    public = urlparse(public_origin)
    private = urlparse(private_origin)
    try:
        public_port = public.port
        private_port = private.port
    except ValueError as exception:
        raise RehearsalError("AC-26 runtime origin contains an invalid port") from exception
    expected_public_port = int(values["WEB_STARTER_PUBLIC_MCP_PORT"])
    expected_private_port = int(values["WEB_STARTER_HTTP_PORT"])
    aliases, loopback_target = loopback_aliases()
    if (
        public.scheme != "https"
        or public_port != expected_public_port
        or (public.hostname or "").lower() not in aliases
        or loopback_target != values["WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS"]
    ):
        raise RehearsalError("Public AC-26 origin does not bind the isolated public ingress port")
    if (
        private.scheme != "http"
        or private.hostname != values["WEB_STARTER_HTTP_BIND_ADDRESS"]
        or private_port != expected_private_port
    ):
        raise RehearsalError("Private AC-26 origin does not bind the isolated private ingress port")
    return private_port, public_port


def _write_phase_env(path: Path, base: Mapping[str, str], ring: RingMaterial) -> None:
    if path.exists() or path.is_symlink():
        raise RehearsalError("Private phase environment already exists")
    values = dict(base)
    values.update({
        "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": "",
        "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": "",
        "WEB_STARTER_OAUTH_RSA_JWK_SET": ring.compact_json,
        "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": ring.active_kid,
    })
    _write_env_values(path, values)


def _validated_override(path: Path | None, repository: Path) -> tuple[Path, bytes] | None:
    if path is None:
        return None
    resolved, payload = _private_file(path, "Compose management override", maximum=2048)
    if _inside(resolved, repository):
        raise RehearsalError("Compose management override must be outside the Git candidate")
    pattern = re.compile(
        rb'\Aservices:\n  app:\n    ports:\n      - "127\.0\.0\.1:'
        rb'(?:[1-9][0-9]{3,4}):8081"\n\Z'
    )
    if pattern.fullmatch(payload) is None:
        raise RehearsalError("Compose override may expose only app management on loopback")
    return resolved, payload


def _write_private_bytes(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise RehearsalError("Private AC-26 snapshot already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def _write_env_values(path: Path, values: Mapping[str, str]) -> None:
    _write_private_bytes(
        path,
        "".join(f"{key}={values[key]}\n" for key in sorted(values)).encode(),
    )


class ComposeController:
    """Fixed-command controller for one already-running isolated project."""

    def __init__(
        self,
        repository: Path,
        compose_file: Path,
        project: str,
        base_env_path: Path,
        base_env_values: Mapping[str, str],
        override: Path | None,
        expected_app: AppIdentity,
        work_directory: Path,
        docker_environment: Mapping[str, str],
    ) -> None:
        if PROJECT.fullmatch(project) is None:
            raise RehearsalError("Compose project must use the isolated web-starter-ac26-* namespace")
        self.repository = repository
        self.compose_file = compose_file
        self.project = project
        self.base_env_path = base_env_path
        self.base_env_values = dict(base_env_values)
        self.override = override
        self.expected_app = expected_app
        self.work_directory = work_directory
        self.docker_environment = dict(docker_environment)
        self.private_port = int(self.base_env_values["WEB_STARTER_HTTP_PORT"])
        self.public_port = int(self.base_env_values["WEB_STARTER_PUBLIC_MCP_PORT"])

    def _base(self, env_path: Path) -> list[str]:
        command = [
            "docker", "compose", "--env-file", str(env_path),
            "-f", str(self.compose_file),
        ]
        if self.override is not None:
            command.extend(["-f", str(self.override)])
        command.extend(["-p", self.project])
        return command

    def inspect_app(self, env_path: Path) -> ContainerIdentity:
        raw_id = _run(
            [*self._base(env_path), "ps", "-q", "app"],
            timeout=30,
            environment=self.docker_environment,
        )
        try:
            container_id = raw_id.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as exception:
            raise RehearsalError("Compose returned a non-ASCII app container ID") from exception
        if CONTAINER_ID.fullmatch(container_id) is None:
            raise RehearsalError("Compose project does not have exactly one running app container")
        inspect_payload = _run(
            ["docker", "inspect", container_id],
            timeout=30,
            environment=self.docker_environment,
        )
        document = _strict_json_array(inspect_payload, "Docker app inspection")
        if len(document) != 1 or not isinstance(document[0], dict):
            raise RehearsalError("Docker inspection did not return exactly one app container")
        item = document[0]
        config = item.get("Config")
        if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict):
            raise RehearsalError("Docker app inspection lacks Compose labels")
        labels = config["Labels"]
        if (
            labels.get("com.docker.compose.project") != self.project
            or labels.get("com.docker.compose.service") != "app"
        ):
            raise RehearsalError("Docker app container does not belong to the exact isolated project")
        if item.get("Image") != self.expected_app.image_id:
            raise RehearsalError("Docker app container image ID differs from runtime identity")
        if config.get("Image") != self.expected_app.reference:
            raise RehearsalError("Docker app configured reference differs from runtime identity")
        state = item.get("State")
        health = state.get("Health") if isinstance(state, dict) else None
        if (
            not isinstance(state, dict)
            or state.get("Running") is not True
            or not isinstance(health, dict)
            or health.get("Status") != "healthy"
        ):
            raise RehearsalError("Docker app container is not running and healthy")
        return ContainerIdentity(container_id, item["Image"], config["Image"])

    def inspect_ingresses(self, env_path: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for service in ("nginx", "mcp-public-nginx"):
            raw_id = _run(
                [*self._base(env_path), "ps", "-q", service],
                timeout=30,
                environment=self.docker_environment,
            )
            try:
                container_id = raw_id.decode("ascii", errors="strict").strip()
            except UnicodeDecodeError as exception:
                raise RehearsalError("Compose returned a non-ASCII ingress container ID") from exception
            if CONTAINER_ID.fullmatch(container_id) is None:
                raise RehearsalError("Both AC-26 ingress containers must already be running")
            inspect_payload = _run(
                ["docker", "inspect", container_id],
                timeout=30,
                environment=self.docker_environment,
            )
            document = _strict_json_array(inspect_payload, "Docker ingress inspection")
            if len(document) != 1 or not isinstance(document[0], dict):
                raise RehearsalError("Docker ingress inspection is invalid")
            config = document[0].get("Config")
            state = document[0].get("State")
            labels = config.get("Labels") if isinstance(config, dict) else None
            health = state.get("Health") if isinstance(state, dict) else None
            if (
                not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != self.project
                or labels.get("com.docker.compose.service") != service
                or not isinstance(state, dict)
                or state.get("Running") is not True
                or not isinstance(health, dict)
                or health.get("Status") != "healthy"
                or document[0].get("Image") != self.expected_app.nginx_image_id
                or not isinstance(config, dict)
                or config.get("Image") != self.expected_app.nginx_reference
            ):
                raise RehearsalError(
                    "Ingress container does not match the exact healthy release project"
                )
            target_port = "8080/tcp" if service == "nginx" else "8443/tcp"
            host_port = self.private_port if service == "nginx" else self.public_port
            network = document[0].get("NetworkSettings")
            ports = network.get("Ports") if isinstance(network, dict) else None
            binding = ports.get(target_port) if isinstance(ports, dict) else None
            nonempty_bindings = {
                key for key, value in ports.items()
                if value is not None and value != []
            } if isinstance(ports, dict) else set()
            if (
                not isinstance(binding, list)
                or len(binding) != 1
                or not isinstance(binding[0], dict)
                or binding[0] != {"HostIp": "127.0.0.1", "HostPort": str(host_port)}
                or nonempty_bindings != {target_port}
            ):
                raise RehearsalError("Ingress container host port binding is not exact")
            result[service] = container_id
        return result

    def inspect_runtime(self, env_path: Path) -> RuntimeContainers:
        return RuntimeContainers(
            app=self.inspect_app(env_path),
            ingress_container_ids=self.inspect_ingresses(env_path),
        )

    def recreate(
        self,
        phase: str,
        ring: RingMaterial,
        previous: RuntimeContainers,
    ) -> tuple[RuntimeContainers, dict[str, Any]]:
        if phase not in {"baseline", "rotated", "terminal"}:
            raise RehearsalError("Unknown fixed AC-26 recreation phase")
        phase_env = self.work_directory / f"{phase}.env"
        _write_phase_env(phase_env, self.base_env_values, ring)
        _run(
            [
                *self._base(phase_env), "up", "--detach", "--no-deps", "--force-recreate",
                "--wait", "--wait-timeout", "300", "app", "nginx", "mcp-public-nginx",
            ],
            timeout=360,
            environment=self.docker_environment,
        )
        current = self.inspect_runtime(phase_env)
        if (
            current.app.container_id == previous.app.container_id
            or any(
                current.ingress_container_ids[service]
                == previous.ingress_container_ids[service]
                for service in ("nginx", "mcp-public-nginx")
            )
        ):
            raise RehearsalError("Fixed Compose recreation did not replace every release container")
        return current, {
            "phase": phase,
            "previousContainerId": previous.app.container_id,
            "currentContainerId": current.app.container_id,
            "previousIngressContainerIds": dict(previous.ingress_container_ids),
            "currentIngressContainerIds": dict(current.ingress_container_ids),
            "imageId": current.app.image_id,
            "nginxImageId": self.expected_app.nginx_image_id,
            "nginxReference": self.expected_app.nginx_reference,
            "projectLabelMatched": True,
            "serviceLabelMatched": True,
            "fixedServices": ["app", "mcp-public-nginx", "nginx"],
            "allContainersHealthy": True,
            "portBindingsMatched": True,
            "noBuild": True,
            "noPull": True,
            "noDependencies": True,
        }


def _strict_json_array(payload: bytes, label: str) -> list[Any]:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RehearsalError(f"{label} is not valid UTF-8 JSON") from exception
    if not isinstance(value, list):
        raise RehearsalError(f"{label} must be a JSON array")
    return value


def _origin(value: Any, label: str, *, public: bool) -> str:
    if not isinstance(value, str):
        raise RehearsalError(f"{label} origin is missing")
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    schemes = {"https"} if public else {"http", "https"}
    if (
        parsed.scheme not in schemes
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RehearsalError(f"{label} must be a credential-free origin")
    if public:
        if not parsed.hostname.endswith(".test") or not is_isolated_acceptance_host(parsed.hostname):
            raise RehearsalError("Public AC-26 origin must be an explicit loopback-mapped .test host")
    else:
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise RehearsalError("Private AC-26 origin must be loopback-only")
    return normalized


def load_runtime_manifest(path: Path, repository: Path) -> tuple[str, str, str, str]:
    resolved, payload = _private_file(path, "runtime manifest")
    if _inside(resolved, repository):
        raise RehearsalError("Runtime manifest must be outside the Git candidate")
    document = _strict_json(payload, "runtime manifest")
    if document.get("schemaVersion") != 1:
        raise RehearsalError("Runtime manifest uses an unsupported schema")
    public_origin = _origin(document.get("publicBaseUrl"), "public", public=True)
    private_origin = _origin(document.get("privateBaseUrl"), "private", public=False)
    files = document.get("tokenFiles")
    if not isinstance(files, dict) or not isinstance(files.get("oauthClient"), str):
        raise RehearsalError("Runtime manifest lacks the OAuth client reference")
    client_path, client_payload = _private_file(Path(files["oauthClient"]), "OAuth client")
    if _inside(client_path, repository):
        raise RehearsalError("OAuth client fixture must be outside the Git candidate")
    client = _strict_json(client_payload, "OAuth client")
    if set(client) != {"client_id", "client_secret"}:
        raise RehearsalError("OAuth client fixture has unexpected fields")
    client_id = client.get("client_id")
    client_secret = client.get("client_secret")
    if (
        not isinstance(client_id, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{3,128}", client_id)
        or not isinstance(client_secret, str)
        or len(client_secret) < 24
        or any(character in client_secret for character in "\r\n\0")
    ):
        raise RehearsalError("OAuth client fixture is malformed")
    return public_origin, private_origin, client_id, client_secret


def _tls_context(public_origin: str) -> ssl.SSLContext:
    try:
        reject_tls_key_logging()
    except ValueError as exception:
        raise RehearsalError("AC-26 refuses TLS session key logging") from exception
    raw = os.environ.get("WEB_STARTER_ACCEPTANCE_INSECURE_TLS", "false")
    if raw not in {"true", "false"}:
        raise RehearsalError("WEB_STARTER_ACCEPTANCE_INSECURE_TLS must be true or false")
    if raw == "false":
        context = ssl.create_default_context()
        context.keylog_filename = None
        return context
    hostname = urlparse(public_origin).hostname or ""
    if not is_isolated_acceptance_host(hostname):
        raise RehearsalError("Insecure TLS is restricted to the isolated loopback acceptance host")
    context = ssl._create_unverified_context()  # noqa: SLF001 - isolated self-signed TLS only
    context.keylog_filename = None
    return context


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
            payload = response.read(MAX_HTTP_BYTES + 1)
            status_code = response.status
            response_headers = {name.lower(): value for name, value in response.headers.items()}
    except HTTPError as error:
        payload = error.read(MAX_HTTP_BYTES + 1)
        status_code = error.code
        response_headers = {name.lower(): value for name, value in error.headers.items()}
    except (URLError, TimeoutError, OSError) as exception:
        raise RehearsalError("Isolated AC-26 HTTP request could not complete") from exception
    if len(payload) > MAX_HTTP_BYTES:
        raise RehearsalError("Isolated AC-26 HTTP response is too large")
    return status_code, payload, response_headers


def _json_response(status_code: int, payload: bytes, label: str) -> dict[str, Any]:
    if status_code != 200:
        raise RehearsalError(f"{label} did not return HTTP 200")
    return _strict_json(payload, label)


def _jwt_segment(segment: str, label: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,16384}", segment):
        raise RehearsalError(f"Issued credential has an invalid {label} segment")
    try:
        payload = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except ValueError as exception:
        raise RehearsalError(f"Issued credential has an invalid {label} segment") from exception
    return _strict_json(payload, f"issued credential {label}")


def issue_credential(
    opener: Any,
    public_origin: str,
    client_id: str,
    client_secret: str,
    expected_kid: str,
) -> tuple[str, dict[str, Any]]:
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    request_body = urlencode({
        "grant_type": "client_credentials",
        "scope": "audit:list system:info",
    }).encode()
    status_code, payload, headers = _request(
        opener,
        "POST",
        f"{public_origin}/oauth2/token",
        request_body,
        {
            "Accept": "application/json",
            "Authorization": "Basic " + basic,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    document = _json_response(status_code, payload, "OAuth credential endpoint")
    credential = document.get("access_token")
    if not isinstance(credential, str) or len(credential) > 32768:
        raise RehearsalError("OAuth response lacks one bounded access credential")
    segments = credential.split(".")
    if len(segments) != 3:
        raise RehearsalError("OAuth access credential is not a compact JWT")
    header = _jwt_segment(segments[0], "protected header")
    claims = _jwt_segment(segments[1], "claims")
    if header.get("kid") != expected_kid or header.get("alg") != "RS256":
        raise RehearsalError("OAuth access credential was not signed by the expected active kid")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
    ):
        raise RehearsalError("OAuth access credential lacks a valid lifetime")
    if claims.get("iss") != public_origin:
        raise RehearsalError("OAuth access credential issuer differs from the public ingress")
    audience = claims.get("aud")
    audiences = {audience} if isinstance(audience, str) else set(audience) if isinstance(audience, list) else set()
    if f"{public_origin}/mcp" not in audiences:
        raise RehearsalError("OAuth access credential lacks the MCP resource audience")
    raw_scope = claims.get("scope")
    scopes = set(raw_scope.split()) if isinstance(raw_scope, str) else set(raw_scope) if isinstance(raw_scope, list) else set()
    if not REQUIRED_SCOPES.issubset(scopes):
        raise RehearsalError("OAuth access credential lacks AC-26 read and audit scopes")
    observation = {
        "httpStatus": 200,
        "responseContentTypeJson": "json" in headers.get("content-type", "").lower(),
        "kid": expected_kid,
        "algorithm": "RS256",
        "issuedAtEpochSeconds": issued_at,
        "expiresAtEpochSeconds": expires_at,
        "protectedHeaderSha256": _canonical_sha256(header),
        "claimsSha256": _canonical_sha256(claims),
        "responseSha256": _sha256(payload),
        "issuerMatched": True,
        "audienceMatched": True,
        "requiredScopesMatched": True,
    }
    return credential, observation


def observe_jwks(
    opener: Any,
    public_origin: str,
    expected: Mapping[str, str],
) -> dict[str, Any]:
    metadata_status, metadata_payload, _ = _request(
        opener,
        "GET",
        f"{public_origin}/.well-known/oauth-authorization-server",
        headers={"Accept": "application/json"},
    )
    metadata = _json_response(metadata_status, metadata_payload, "authorization metadata")
    if metadata.get("issuer") != public_origin or metadata.get("jwks_uri") != f"{public_origin}/oauth2/jwks":
        raise RehearsalError("Authorization metadata does not bind the isolated public ingress")
    status_code, payload, headers = _request(
        opener,
        "GET",
        f"{public_origin}/oauth2/jwks",
        headers={"Accept": "application/json"},
    )
    document = _json_response(status_code, payload, "authorization JWKS")
    keys = document.get("keys")
    if not isinstance(keys, list) or not all(isinstance(key, dict) for key in keys):
        raise RehearsalError("Authorization JWKS lacks a key array")
    observed: dict[str, str] = {}
    for raw in keys:
        key = _validate_rsa_key(raw, "published JWKS key")
        if PRIVATE_JWK_MEMBERS.intersection(key):
            raise RehearsalError("Authorization JWKS exposed private RSA material")
        if key["kid"] in observed:
            raise RehearsalError("Authorization JWKS published a duplicate kid")
        observed[key["kid"]] = _public_fingerprint(key)
    if observed != dict(expected):
        raise RehearsalError("Authorization JWKS kids or public fingerprints differ from the phase")
    return {
        "httpStatus": 200,
        "responseContentTypeJson": "json" in headers.get("content-type", "").lower(),
        "observedAtEpochSeconds": int(time.time()),
        "keyCount": len(keys),
        "kids": sorted(observed),
        "publicFingerprintSha256": {key: observed[key] for key in sorted(observed)},
        "privateParametersAbsent": True,
        "metadataIssuerMatched": True,
        "metadataJwksUriMatched": True,
        "responseSha256": _sha256(payload),
    }


def _rpc_document(payload: bytes, expected_id: int) -> dict[str, Any]:
    stripped = payload.strip()
    candidates: list[bytes]
    if stripped.startswith(b"{"):
        candidates = [stripped]
    else:
        candidates = [line[5:].strip() for line in payload.splitlines() if line.startswith(b"data:")]
    for candidate in reversed(candidates):
        try:
            document = _strict_json(candidate, "MCP JSON-RPC response")
        except RehearsalError:
            continue
        if document.get("id") == expected_id:
            return document
    raise RehearsalError("MCP response lacks the expected JSON-RPC message")


def _mcp_headers(credential: str, trace_id: str, session_id: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + credential,
        "Content-Type": "application/json",
        "X-Trace-Id": trace_id,
    }
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    return headers


def _validate_structured_tool_result(
    tool_name: str,
    arguments: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        raise RehearsalError("MCP Tool response lacks structured content")
    if tool_name == "system.info":
        if (
            structured.get("product") != "启程 Web Starter"
            or structured.get("server") != "web-starter-mcp"
        ):
            raise RehearsalError("MCP system.info response differs from the expected server")
        return
    if tool_name != "audit.list":
        raise RehearsalError("AC-26 MCP Tool result validator received an unknown tool")
    source_trace = arguments.get("traceId")
    records = structured.get("records")
    if (
        not isinstance(source_trace, str)
        or structured.get("total") != 1
        or structured.get("page") != 1
        or structured.get("size") != 20
        or not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
    ):
        raise RehearsalError("MCP audit.list did not return one exact source record")
    record = records[0]
    if (
        record.get("traceId") != source_trace
        or record.get("toolName") != "system.info"
        or record.get("permissionCode") != "system:info"
        or record.get("result") != "SUCCESS"
    ):
        raise RehearsalError("MCP audit.list source record is not the successful system.info call")


def mcp_call(
    opener: Any,
    public_origin: str,
    credential: str,
    trace_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    if TRACE_ID.fullmatch(trace_id) is None or tool_name not in {"system.info", "audit.list"}:
        raise RehearsalError("AC-26 MCP call requested an unsafe trace or tool")
    started_at = int(time.time())
    initialize_body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "web-starter-ac26", "version": "1.0.0"},
        },
    }, separators=(",", ":")).encode()
    init_status, init_payload, init_headers = _request(
        opener, "POST", f"{public_origin}/mcp", initialize_body,
        _mcp_headers(credential, trace_id + "-init"),
    )
    if init_status != 200:
        raise RehearsalError("Valid OAuth credential could not initialize MCP")
    initialized = _rpc_document(init_payload, 1)
    result = initialized.get("result")
    if (
        not isinstance(result, dict)
        or result.get("protocolVersion") != "2025-11-25"
        or not isinstance(result.get("serverInfo"), dict)
        or result["serverInfo"].get("name") != "web-starter-mcp"
    ):
        raise RehearsalError("MCP initialization returned an unexpected server contract")
    session_id = init_headers.get("mcp-session-id")
    if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{8,256}", session_id):
        raise RehearsalError("MCP initialization did not establish a bounded session")
    notification = json.dumps({
        "jsonrpc": "2.0", "method": "notifications/initialized",
    }, separators=(",", ":")).encode()
    notify_status, notify_payload, _ = _request(
        opener, "POST", f"{public_origin}/mcp", notification,
        _mcp_headers(credential, trace_id + "-ready", session_id),
    )
    if notify_status not in {200, 202, 204} or notify_payload.strip():
        raise RehearsalError("MCP initialized notification was not accepted cleanly")
    call_body = json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": tool_name, "arguments": dict(arguments)},
    }, separators=(",", ":")).encode()
    call_status, call_payload, call_headers = _request(
        opener, "POST", f"{public_origin}/mcp", call_body,
        _mcp_headers(credential, trace_id, session_id),
    )
    if call_status != 200 or call_headers.get("x-trace-id") != trace_id:
        raise RehearsalError("MCP Tool call did not preserve the required trace")
    call = _rpc_document(call_payload, 2)
    if "error" in call or not isinstance(call.get("result"), dict) or call["result"].get("isError") is True:
        raise RehearsalError("MCP Tool call returned an error")
    _validate_structured_tool_result(tool_name, arguments, call["result"])
    delete_status, delete_payload, _ = _request(
        opener, "DELETE", f"{public_origin}/mcp", None,
        _mcp_headers(credential, trace_id + "-close", session_id),
    )
    if delete_status not in {200, 202, 204} or delete_payload.strip():
        raise RehearsalError("MCP session could not be closed cleanly")
    completed_at = int(time.time())
    return {
        "initializeHttpStatus": 200,
        "initializedHttpStatus": notify_status,
        "toolCallHttpStatus": 200,
        "deleteHttpStatus": delete_status,
        "protocolVersion": "2025-11-25",
        "serverName": "web-starter-mcp",
        "toolName": tool_name,
        "toolResultSuccess": True,
        "startedAtEpochSeconds": started_at,
        "completedAtEpochSeconds": completed_at,
        "traceId": trace_id,
        "traceHeaderMatched": True,
        "sessionIdSha256": _sha256(session_id.encode()),
        "initializeResponseSha256": _sha256(init_payload),
        "toolResponseSha256": _sha256(call_payload),
    }


def mcp_rejected(
    opener: Any,
    public_origin: str,
    credential: str,
    trace_id: str,
) -> dict[str, Any]:
    started_at = int(time.time())
    request_body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "web-starter-ac26-rejected", "version": "1.0.0"},
        },
    }, separators=(",", ":")).encode()
    status_code, payload, headers = _request(
        opener, "POST", f"{public_origin}/mcp", request_body,
        _mcp_headers(credential, trace_id),
    )
    if (
        status_code != 401
        or headers.get("x-trace-id") != trace_id
        or "bearer" not in headers.get("www-authenticate", "").lower()
        or "mcp-session-id" in headers
    ):
        raise RehearsalError("Retiring credential was not rejected by MCP as an unauthenticated bearer")
    completed_at = int(time.time())
    return {
        "httpStatus": 401,
        "startedAtEpochSeconds": started_at,
        "completedAtEpochSeconds": completed_at,
        "traceId": trace_id,
        "traceHeaderMatched": True,
        "wwwAuthenticateBearer": True,
        "noSessionIssued": True,
        "responseSha256": _sha256(payload),
    }


def confirm_audit(
    opener: Any,
    public_origin: str,
    credential: str,
    source_trace_id: str,
    audit_trace_id: str,
) -> dict[str, Any]:
    last_error: RehearsalError | None = None
    for attempt in range(1, 11):
        try:
            observation = mcp_call(
                opener,
                public_origin,
                credential,
                audit_trace_id,
                "audit.list",
                {
                    "page": 1,
                    "size": 20,
                    "traceId": source_trace_id,
                    "toolName": "system.info",
                    "result": "SUCCESS",
                },
            )
        except RehearsalError as error:
            last_error = error
        else:
            return {
                "httpStatus": 200,
                "sourceTraceId": source_trace_id,
                "auditTraceId": audit_trace_id,
                "rowMatched": True,
                "toolNameMatched": True,
                "successOutcomeMatched": True,
                "responseSha256": observation["toolResponseSha256"],
                "attempt": attempt,
            }
        time.sleep(0.2)
    raise RehearsalError(
        "MCP audit.list did not return the exact successful source trace"
    ) from last_error


def _wait_for_terminal(retain_until: int, maximum_wait: int) -> int:
    remaining = retain_until - int(time.time()) + 1
    if remaining < 0:
        remaining = 0
    if remaining > maximum_wait:
        raise RehearsalError("Retiring exp boundary is outside the bounded AC-26 wait window")
    if remaining:
        time.sleep(remaining)
    observed = int(time.time())
    if observed < retain_until:
        raise RehearsalError("Clock did not reach the exclusive retiring exp boundary")
    return observed


def _write_evidence(output: Path, document: Mapping[str, Any]) -> None:
    report_path = output / RESULT_NAME
    checksum_path = output / CHECKSUM_NAME
    if report_path.exists() or report_path.is_symlink() or checksum_path.exists() or checksum_path.is_symlink():
        raise RehearsalError("AC-26 evidence output files must not already exist")
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    report_descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(report_descriptor, payload)
    finally:
        os.close(report_descriptor)
    checksum = f"{_sha256(payload)}  {RESULT_NAME}\n".encode()
    checksum_descriptor = os.open(checksum_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(checksum_descriptor, checksum)
    finally:
        os.close(checksum_descriptor)
    if set(item.name for item in output.iterdir()) != {RESULT_NAME, CHECKSUM_NAME}:
        raise RehearsalError("AC-26 evidence directory contains unexpected files")


def rehearse(args: argparse.Namespace) -> dict[str, Any]:
    repository = _repository_root(args.repository_root)
    candidate = candidate_identity(repository)
    output = ensure_output_directory(args.output_dir, repository)
    app = load_runtime_identity(args.runtime_identity, candidate, repository)
    if not PROJECT.fullmatch(args.compose_project):
        raise RehearsalError("Compose project must use the isolated web-starter-ac26-* namespace")
    public_origin, private_origin, client_id, client_secret = load_runtime_manifest(
        args.runtime_manifest, repository
    )
    env_path, env_values = _parse_env(args.compose_env_file, repository)
    tls_payloads = _validate_runtime_env_files(env_values, repository)
    private_port, public_port = _validate_origins_against_runtime(
        public_origin, private_origin, env_values
    )
    if env_values["WEB_STARTER_APP_IMAGE"] + "@" + env_values["WEB_STARTER_APP_DIGEST"] != app.reference:
        raise RehearsalError("Compose app digest reference differs from runtime identity")
    if (
        env_values["WEB_STARTER_NGINX_IMAGE"]
        + "@"
        + env_values["WEB_STARTER_NGINX_DIGEST"]
        != app.nginx_reference
    ):
        raise RehearsalError("Compose Nginx digest reference differs from runtime identity")
    if env_values["WEB_STARTER_OAUTH_ISSUER"] != public_origin:
        raise RehearsalError("Compose issuer differs from the runtime manifest")
    if env_values["WEB_STARTER_OAUTH_RESOURCE_AUDIENCE"] != public_origin + "/mcp":
        raise RehearsalError("Compose audience differs from the public MCP resource")
    override_input = _validated_override(args.compose_override, repository)

    initial = load_key_ring(args.initial_jwk_set, args.old_kid, "initial", repository)
    rotated = load_key_ring(args.rotated_jwk_set, args.new_kid, "rotated", repository)
    terminal = (
        load_key_ring(args.terminal_jwk_set, args.new_kid, "terminal", repository)
        if args.terminal_jwk_set is not None else None
    )
    validate_ring_sequence(initial, rotated, terminal, args.terminal_mode)
    if rotated.retain_until is None:
        raise RehearsalError("Rotated key ring lacks a retiring exp boundary")
    now = int(time.time())
    if rotated.retain_until <= now + 5:
        raise RehearsalError("Rotated retain-until must leave time for a real within-window call")
    if rotated.retain_until > now + args.max_wait_seconds:
        raise RehearsalError("Rotated retain-until exceeds the bounded AC-26 window")

    trace_prefix = args.trace_prefix
    work_parent = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve(strict=True)
    if work_parent.is_symlink() or not work_parent.is_dir():
        raise RehearsalError("Private temporary parent is invalid")
    if work_parent == repository or _inside(work_parent, repository):
        raise RehearsalError("Private temporary parent must remain outside the Git candidate")
    work = Path(tempfile.mkdtemp(prefix="web-starter-ac26-", dir=work_parent))
    work.chmod(0o700)
    transitions: list[dict[str, Any]] = []
    try:
        compose_payload = (repository / COMPOSE_PATH).read_bytes()
        if _sha256(compose_payload) != candidate.source_sha256[COMPOSE_PATH]:
            raise RehearsalError("Candidate Compose file changed after Git binding")
        compose_snapshot = work / COMPOSE_PATH
        _write_private_bytes(compose_snapshot, compose_payload)
        env_values = dict(env_values)
        for name, filename in (
            ("WEB_STARTER_PUBLIC_TLS_CERT_FILE", "tls-cert.pem"),
            ("WEB_STARTER_PUBLIC_TLS_KEY_FILE", "tls-key.pem"),
        ):
            snapshot_path = work / filename
            _write_private_bytes(snapshot_path, tls_payloads[name])
            env_values[name] = str(snapshot_path)
        base_env_snapshot = work / "base.env"
        _write_env_values(base_env_snapshot, env_values)
        override_snapshot: Path | None = None
        if override_input is not None:
            _, override_payload = override_input
            override_snapshot = work / "management.override.yaml"
            _write_private_bytes(override_snapshot, override_payload)
        docker_environment = _local_docker_environment()
        controller = ComposeController(
            repository,
            compose_snapshot,
            args.compose_project,
            base_env_snapshot,
            env_values,
            override_snapshot,
            app,
            work,
            docker_environment,
        )
        current = controller.inspect_runtime(base_env_snapshot)
        current, transition = controller.recreate("baseline", initial, current)
        transitions.append(transition)

        opener = build_opener(
            ProxyHandler({}),
            RejectRedirectHandler(),
            HTTPSHandler(context=_tls_context(public_origin)),
        )
        baseline_jwks = observe_jwks(
            opener, public_origin, {initial.active_kid: initial.active_public_fingerprint}
        )
        old_credential, old_observation = issue_credential(
            opener, public_origin, client_id, client_secret, initial.active_kid
        )
        baseline_trace = f"{trace_prefix}-old-base"
        baseline_mcp = mcp_call(
            opener, public_origin, old_credential, baseline_trace,
            "system.info", {},
        )
        baseline_at = baseline_mcp["completedAtEpochSeconds"]

        current, transition = controller.recreate("rotated", rotated, current)
        transitions.append(transition)
        rotated_jwks = observe_jwks(opener, public_origin, {
            rotated.active_kid: rotated.active_public_fingerprint,
            initial.active_kid: initial.active_public_fingerprint,
        })
        new_credential, new_observation = issue_credential(
            opener, public_origin, client_id, client_secret, rotated.active_kid
        )
        if rotated_jwks["observedAtEpochSeconds"] >= rotated.retain_until:
            raise RehearsalError("Real rotated checks did not start inside the retiring window")
        old_window_trace = f"{trace_prefix}-old-window"
        new_active_trace = f"{trace_prefix}-new-active"
        old_window_mcp = mcp_call(
            opener, public_origin, old_credential, old_window_trace,
            "system.info", {},
        )
        if old_window_mcp["completedAtEpochSeconds"] >= rotated.retain_until:
            raise RehearsalError("Old JWT MCP call did not complete inside the retiring window")
        new_active_mcp = mcp_call(
            opener, public_origin, new_credential, new_active_trace,
            "system.info", {},
        )
        old_audit = confirm_audit(
            opener, public_origin, new_credential, old_window_trace,
            f"{trace_prefix}-audit-old",
        )
        new_audit = confirm_audit(
            opener, public_origin, new_credential, new_active_trace,
            f"{trace_prefix}-audit-new",
        )
        rotated_at = old_window_mcp["completedAtEpochSeconds"]

        if args.terminal_mode == "expiry":
            _wait_for_terminal(rotated.retain_until, args.max_wait_seconds)
        else:
            assert terminal is not None
            current, transition = controller.recreate("terminal", terminal, current)
            transitions.append(transition)
            if int(time.time()) >= rotated.retain_until:
                raise RehearsalError("Emergency revocation was not observed before the exp boundary")
        terminal_jwks = observe_jwks(
            opener, public_origin, {rotated.active_kid: rotated.active_public_fingerprint}
        )
        old_rejected_trace = f"{trace_prefix}-old-reject"
        old_rejected = mcp_rejected(
            opener, public_origin, old_credential, old_rejected_trace
        )
        terminal_at = old_rejected["completedAtEpochSeconds"]
        if terminal_at >= old_observation["expiresAtEpochSeconds"]:
            raise RehearsalError("Old JWT expired before key-retirement rejection was observed")
        if args.terminal_mode == "revocation" and terminal_at >= rotated.retain_until:
            raise RehearsalError("Emergency revocation rejection did not complete before exp")
        terminal_new_trace = f"{trace_prefix}-new-final"
        terminal_new_mcp = mcp_call(
            opener, public_origin, new_credential, terminal_new_trace,
            "system.info", {},
        )
        if terminal_new_mcp["completedAtEpochSeconds"] >= new_observation["expiresAtEpochSeconds"]:
            raise RehearsalError("New JWT expired before terminal continuity was observed")
        terminal_new_audit = confirm_audit(
            opener, public_origin, new_credential, terminal_new_trace,
            f"{trace_prefix}-audit-final",
        )

        document: dict[str, Any] = {
            "schemaVersion": 2,
            "acceptanceId": "V2-AC-26",
            "status": "PASS",
            "generatedAt": _utc_now(),
            "candidate": {
                "head": candidate.head,
                "tree": candidate.tree,
                "tag": candidate.tag,
                "tagObject": candidate.tag_object,
                "mavenVersion": candidate.version,
                "frontendVersion": candidate.version,
                "cleanWorktree": True,
                "sourceSha256": dict(candidate.source_sha256),
            },
            "tool": {
                "path": TOOL_PATH,
                "sha256": candidate.source_sha256[TOOL_PATH],
                "validatorPath": VALIDATOR_PATH,
                "validatorSha256": candidate.source_sha256[VALIDATOR_PATH],
                "schemaPath": SCHEMA_PATH,
                "schemaSha256": candidate.source_sha256[SCHEMA_PATH],
            },
            "runtime": {
                "composeProject": args.compose_project,
                "publicOriginSha256": _sha256(public_origin.encode()),
                "privateOriginSha256": _sha256(private_origin.encode()),
                "privatePort": private_port,
                "publicPort": public_port,
                "tracePrefix": trace_prefix,
                "runtimeIdentitySha256": app.runtime_identity_sha256,
                "app": {
                    "requestedReference": app.reference,
                    "id": app.image_id,
                    "manifestDigest": app.manifest_digest,
                    "ociVersion": app.oci_version,
                    "ociRevision": app.oci_revision,
                },
                "nginx": {
                    "requestedReference": app.nginx_reference,
                    "id": app.nginx_image_id,
                    "manifestDigest": app.nginx_manifest_digest,
                    "ociVersion": app.nginx_oci_version,
                    "ociRevision": app.nginx_oci_revision,
                },
                "containerTransitions": transitions,
            },
            "keyRing": {
                "oldKid": initial.active_kid,
                "newKid": rotated.active_kid,
                "oldPublicFingerprintSha256": initial.active_public_fingerprint,
                "newPublicFingerprintSha256": rotated.active_public_fingerprint,
                "retainUntilEpochSeconds": rotated.retain_until,
                "terminalMode": args.terminal_mode,
                "initialPrivateKeyCount": initial.private_key_count,
                "rotatedPrivateKeyCount": rotated.private_key_count,
                "retiringPrivateMaterialPresent": rotated.retiring_has_private_material,
                "terminalRevocationConfigured": args.terminal_mode == "revocation",
            },
            "observations": {
                "baseline": {
                    "observedAtEpochSeconds": baseline_at,
                    "jwks": baseline_jwks,
                    "oldOauthGrant": old_observation,
                    "oldMcp": baseline_mcp,
                },
                "rotated": {
                    "observedAtEpochSeconds": rotated_at,
                    "jwks": rotated_jwks,
                    "newOauthGrant": new_observation,
                    "oldWithinWindowMcp": old_window_mcp,
                    "newActiveMcp": new_active_mcp,
                    "oldTraceAudit": old_audit,
                    "newTraceAudit": new_audit,
                },
                "terminal": {
                    "observedAtEpochSeconds": terminal_at,
                    "jwks": terminal_jwks,
                    "oldCredentialRejected": old_rejected,
                    "newActiveMcp": terminal_new_mcp,
                    "newTraceAudit": terminal_new_audit,
                },
            },
            "supplementalConfigurationGuards": {
                "status": "SOURCE_BOUND_ONLY",
                "unknownKidRuntime": "NOT_COVERED",
                "invalidActiveRuntime": "NOT_COVERED",
                "unitTestSourcePath": KEY_RING_TEST_PATH,
                "unitTestSourceSha256": candidate.source_sha256[KEY_RING_TEST_PATH],
            },
            "evidencePolicy": {
                "outsideRepository": True,
                "directoryMode": "0700",
                "fileMode": "0600",
                "onlyReportAndChecksum": True,
                "rawHttpBodiesPersisted": False,
                "credentialsPersisted": False,
                "privateKeyMaterialPersisted": False,
                "arbitraryHookAccepted": False,
                "dockerResourcesRemoved": False,
            },
        }
        _write_evidence(output, document)
        return document
    finally:
        try:
            if work.parent == work_parent and work.name.startswith("web-starter-ac26-"):
                shutil.rmtree(work)
        except OSError as exception:
            raise RehearsalError("Private AC-26 temporary material could not be removed") from exception


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Produce V2-AC-26 runtime rotation evidence")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--runtime-manifest", required=True, type=Path)
    parser.add_argument("--runtime-identity", required=True, type=Path)
    parser.add_argument("--compose-env-file", required=True, type=Path)
    parser.add_argument("--compose-override", type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--trace-prefix", required=True)
    parser.add_argument("--initial-jwk-set", required=True, type=Path)
    parser.add_argument("--rotated-jwk-set", required=True, type=Path)
    parser.add_argument("--terminal-jwk-set", type=Path)
    parser.add_argument("--old-kid", required=True)
    parser.add_argument("--new-kid", required=True)
    parser.add_argument("--terminal-mode", choices=("expiry", "revocation"), required=True)
    parser.add_argument("--max-wait-seconds", type=int, default=180)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if not KID.fullmatch(args.old_kid) or not KID.fullmatch(args.new_kid) or args.old_kid == args.new_kid:
        parser.error("old/new kid values must be distinct bounded identifiers")
    if TRACE_PREFIX.fullmatch(args.trace_prefix) is None:
        parser.error("--trace-prefix must be a bounded 8-32 character identifier")
    if args.max_wait_seconds < 15 or args.max_wait_seconds > 600:
        parser.error("--max-wait-seconds must be between 15 and 600")
    if args.terminal_mode == "expiry" and args.terminal_jwk_set is not None:
        parser.error("expiry mode must not receive --terminal-jwk-set")
    if args.terminal_mode == "revocation" and args.terminal_jwk_set is None:
        parser.error("revocation mode requires --terminal-jwk-set")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        with isolated_loopback_resolution():
            rehearse(args)
    except (RehearsalError, OSError, ValueError) as error:
        print(f"FAIL V2-AC-26 JWKS rotation: {error}", file=sys.stderr)
        return 1
    print(
        "PASS V2-AC-26 JWKS rotation: real OAuth issuance, active/retiring JWKS, "
        "MCP calls, terminal rejection and trace audit observed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
