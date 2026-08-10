#!/usr/bin/env python3
"""Run isolated AC10/AC14 acceptance from one clean committed template.

The orchestrator creates a renamed project, proves the project-only runtime,
then generates one explicit MCP CRUD module and proves that runtime. It writes
the final PASS bundle only after every disposable Docker and filesystem target
has been removed. It never accepts an existing Compose project or output tree.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from http.client import RemoteDisconnected
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Iterable, Sequence
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener
import xml.etree.ElementTree as ET


IMMUTABLE_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMANTIC_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RUN_ID = re.compile(r"^[a-z0-9]{12}$")
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
EVIDENCE_FILE = "generator-acceptance.json"
CHECKSUM_FILE = EVIDENCE_FILE + ".sha256"
VALIDATOR_PATH = "scripts/validate_generator_acceptance_evidence.py"
SCHEMA_PATH = "security/v2-generator-acceptance.schema.json"
PRODUCER_PATH = "scripts/rehearse_generator_acceptance.py"
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
OUTER_LABEL = "dev.webstarter.generator-acceptance.run"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
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
    "metadata",
    "multiKeyJwks",
    "activeSigningKid",
    "oauthMetadataConsistency",
    "dynamicClientRegistrationDisabled",
    "wwwAuthenticate",
    "clientCredentials",
    "clientCredentialsShortLived",
    "oauthPublicMcp",
    "patPrivateMcp",
    "patPublicRejected",
    "invalidOriginRejected",
    "publicManagementApiHidden",
    "publicOperationsEndpointsHidden",
})
METRIC_CHECKS = frozenset({
    "authorizationMatrix",
    "hikariUsageCounterIncreased",
    "loginAttemptCounterIncreased",
    "loginProtocolCounterIncreased",
    "mcpCallCounterIncreased",
    "mcpCallDurationCounterIncreased",
    "mcpProtocolCounterIncreased",
    "mcpSessionCounterIncreased",
    "oauth_tokenProtocolCounterIncreased",
    "operationAuditCounterIncreased",
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
SENSITIVE_ARTIFACT = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[0-9A-Za-z._~+/=-]{12,}"),
    re.compile(r"(?i)\bwst_(?:pat|svc)_[0-9A-Za-z._~-]{8,}"),
    re.compile(
        r"(?i)[\"'](?:password|access_?token|refresh_?token|client_?secret|"
        r"code_?verifier|private_?key)[\"']\s*:\s*[\"'][^\"']+"
    ),
)


class GeneratorAcceptanceError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class Inputs:
    repository: Path
    output: Path
    forbidden_terms: Path
    mysql_image: str
    redis_image: str
    registry_image: str
    project_name: str
    product_name: str
    group_id: str
    database: str
    environment_prefix: str
    module_name: str
    module_label: str
    migration_version: str
    permission_id_base: str
    menu_id: str


@dataclass(frozen=True)
class BuiltImage:
    role: str
    repository: str
    tag: str
    digest: str
    digest_reference: str
    image_id: str


@dataclass(frozen=True)
class Stage:
    name: str
    version: str
    commit: str
    tree: str
    build_context_sha256: str
    compose_project: str
    expected_modules: str
    expected_mcp_modules: str
    app: BuiltImage
    nginx: BuiltImage
    artifacts: dict[str, str]


@dataclass(frozen=True)
class Candidate:
    commit: str
    tree: str
    tag: str
    tag_object: str
    maven_version: str
    frontend_version: str
    source_blobs: dict[str, dict[str, str]]


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GeneratorAcceptanceError("final evidence target already exists", 2)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("evidence write made no progress")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    capture: bool = False,
    timeout: int = 3600,
    label: str,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GeneratorAcceptanceError(f"{label} did not complete") from error
    if completed.returncode != 0:
        raise GeneratorAcceptanceError(f"{label} failed with exit {completed.returncode}")
    return completed


def _captured(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    label: str,
) -> str:
    return _run(
        command, cwd=cwd, environment=environment, capture=True, timeout=120, label=label
    ).stdout.strip()


def _isolated_git_environment() -> dict[str, str]:
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


def _safe_inputs(options: argparse.Namespace) -> Inputs:
    repository_input = options.repository.expanduser()
    if repository_input.is_symlink() or not repository_input.is_dir():
        raise GeneratorAcceptanceError("repository must be a non-symlink directory", 2)
    repository = repository_input.resolve(strict=True)

    output_input = options.output.expanduser()
    if output_input.exists() or output_input.is_symlink():
        raise GeneratorAcceptanceError("output directory must not already exist", 2)
    output_parent_input = output_input.parent
    if output_parent_input.is_symlink() or not output_parent_input.is_dir():
        raise GeneratorAcceptanceError("output parent must be a non-symlink directory", 2)
    output_parent = output_parent_input.resolve(strict=True)
    output = output_parent / output_input.name
    if _inside(output, repository) or _inside(repository, output):
        raise GeneratorAcceptanceError("output and repository must not contain one another", 2)

    terms_input = options.forbidden_terms.expanduser()
    if terms_input.is_symlink() or not terms_input.is_file():
        raise GeneratorAcceptanceError("forbidden-term input must be a non-symlink file", 2)
    forbidden_terms = terms_input.resolve(strict=True)
    if _inside(forbidden_terms, repository):
        raise GeneratorAcceptanceError("forbidden-term input must remain outside the repository", 2)

    for name in ("mysql_image", "redis_image", "registry_image"):
        if not IMMUTABLE_IMAGE.fullmatch(getattr(options, name)):
            raise GeneratorAcceptanceError(
                f"{name.replace('_', '-')} must be an immutable @sha256 reference", 2
            )
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,49}", options.project_name):
        raise GeneratorAcceptanceError("derived project name is invalid", 2)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,62}_", options.environment_prefix):
        raise GeneratorAcceptanceError("derived environment prefix is invalid", 2)
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,62}", options.database):
        raise GeneratorAcceptanceError("derived database name is invalid", 2)
    if not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", options.group_id):
        raise GeneratorAcceptanceError("derived group/package identity is invalid", 2)
    if not re.fullmatch(r"[a-z][a-z0-9]{1,30}", options.module_name):
        raise GeneratorAcceptanceError("generated module name is invalid", 2)

    return Inputs(
        repository=repository,
        output=output,
        forbidden_terms=forbidden_terms,
        mysql_image=options.mysql_image,
        redis_image=options.redis_image,
        registry_image=options.registry_image,
        project_name=options.project_name,
        product_name=options.product_name,
        group_id=options.group_id,
        database=options.database,
        environment_prefix=options.environment_prefix,
        module_name=options.module_name,
        module_label=options.module_label,
        migration_version=options.migration_version,
        permission_id_base=options.permission_id_base,
        menu_id=options.menu_id,
    )


def _git_identity(repository: Path) -> tuple[str, str]:
    environment = _isolated_git_environment()
    status = _captured(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
         "-C", str(repository), "status", "--porcelain=v1", "--untracked-files=all"],
        environment=environment,
        label="candidate clean-worktree check",
    )
    if status:
        raise GeneratorAcceptanceError(
            "formal generator acceptance requires a clean committed candidate", 2
        )
    commit = _captured(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        environment=environment,
        label="candidate commit resolution",
    )
    tree = _captured(
        ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
        environment=environment,
        label="candidate tree resolution",
    )
    if not GIT_COMMIT.fullmatch(commit) or not GIT_COMMIT.fullmatch(tree):
        raise GeneratorAcceptanceError("candidate Git identity is malformed", 2)
    return commit, tree


def _source_blobs(repository: Path) -> dict[str, dict[str, str]]:
    environment = _isolated_git_environment()
    result: dict[str, dict[str, str]] = {}
    for relative in SOURCE_PATHS:
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise GeneratorAcceptanceError(
                f"candidate source is missing or unsafe: {relative}", 2
            )
        blob = _captured(
            ["git", "-C", str(repository), "rev-parse", f"HEAD:{relative}"],
            environment=environment,
            label=f"candidate source blob resolution: {relative}",
        )
        object_type = _captured(
            ["git", "-C", str(repository), "cat-file", "-t", blob],
            environment=environment,
            label=f"candidate source blob type: {relative}",
        )
        if not GIT_COMMIT.fullmatch(blob) or object_type != "blob":
            raise GeneratorAcceptanceError(
                f"candidate source is not one committed blob: {relative}", 2
            )
        result[relative] = {"gitBlob": blob, "sha256": sha256_file(path)}
    return result


def _frontend_version(repository: Path) -> str:
    manifest = _read_exact_json(repository / "web-starter-web/package.json")
    version = manifest.get("version")
    if not isinstance(version, str) or SEMANTIC_VERSION.fullmatch(version) is None:
        raise GeneratorAcceptanceError("frontend version is not semantic", 2)
    return version


def _formal_candidate(repository: Path) -> Candidate:
    environment = _isolated_git_environment()
    commit, tree = _git_identity(repository)
    maven_version = _project_version(repository)
    frontend_version = _frontend_version(repository)
    if "snapshot" in maven_version.lower() or "snapshot" in frontend_version.lower():
        raise GeneratorAcceptanceError(
            "formal generator acceptance requires non-SNAPSHOT versions", 2
        )
    if frontend_version != maven_version:
        raise GeneratorAcceptanceError(
            "frontend and Maven candidate versions must match", 2
        )
    tag = "v" + maven_version
    tag_object = _captured(
        ["git", "-C", str(repository), "rev-parse", f"refs/tags/{tag}"],
        environment=environment,
        label="candidate release tag resolution",
    )
    tag_type = _captured(
        ["git", "-C", str(repository), "cat-file", "-t", tag_object],
        environment=environment,
        label="candidate release tag type",
    )
    tagged_commit = _captured(
        ["git", "-C", str(repository), "rev-parse", f"refs/tags/{tag}^{{commit}}"],
        environment=environment,
        label="candidate tagged commit resolution",
    )
    tagged_tree = _captured(
        ["git", "-C", str(repository), "rev-parse", f"refs/tags/{tag}^{{tree}}"],
        environment=environment,
        label="candidate tagged tree resolution",
    )
    if (
        tag_type != "tag"
        or not GIT_COMMIT.fullmatch(tag_object)
        or tagged_commit != commit
        or tagged_tree != tree
    ):
        raise GeneratorAcceptanceError(
            "formal generator acceptance requires the exact annotated release tag at HEAD", 2
        )
    source_blobs = _source_blobs(repository)
    executing_producer_input = Path(__file__)
    executing_producer = executing_producer_input.resolve(strict=True)
    if (
        executing_producer_input.is_symlink()
        or sha256_file(executing_producer)
        != source_blobs[PRODUCER_PATH]["sha256"]
    ):
        raise GeneratorAcceptanceError(
            "executing generator producer differs from the committed candidate", 2
        )
    return Candidate(
        commit=commit,
        tree=tree,
        tag=tag,
        tag_object=tag_object,
        maven_version=maven_version,
        frontend_version=frontend_version,
        source_blobs=source_blobs,
    )


def _docker_json(command: Sequence[str], label: str) -> dict[str, Any]:
    raw = _captured(command, label=label)
    try:
        documents = json.loads(raw)
    except json.JSONDecodeError as error:
        raise GeneratorAcceptanceError(f"{label} returned malformed JSON", 2) from error
    if not isinstance(documents, list) or len(documents) != 1 or not isinstance(documents[0], dict):
        raise GeneratorAcceptanceError(f"{label} did not resolve exactly one object", 2)
    return documents[0]


def _canonical_repository_digest(reference: str) -> tuple[str, str] | None:
    if IMMUTABLE_IMAGE.fullmatch(reference) is None:
        return None
    repository, digest = reference.rsplit("@", 1)
    last_slash = repository.rfind("/")
    last_colon = repository.rfind(":")
    if last_colon > last_slash:
        repository = repository[:last_colon]
    components = repository.split("/")
    if not components or any(not component for component in components):
        return None
    first = components[0]
    if len(components) == 1:
        components = ["docker.io", "library", first]
    elif "." not in first and ":" not in first and first != "localhost":
        components = ["docker.io", *components]
    elif first == "index.docker.io":
        components[0] = "docker.io"
    if components[0] == "docker.io" and len(components) == 2:
        components.insert(1, "library")
    return "/".join(components), digest


def _require_local_immutable_image(reference: str, label: str) -> None:
    document = _docker_json(["docker", "image", "inspect", reference], label)
    repo_digests = document.get("RepoDigests")
    requested = _canonical_repository_digest(reference)
    observed: set[tuple[str, str]] = set()
    if isinstance(repo_digests, list):
        for value in repo_digests:
            parsed = (
                _canonical_repository_digest(value)
                if isinstance(value, str)
                else None
            )
            if parsed is None:
                observed.clear()
                break
            observed.add(parsed)
    if requested is None or requested not in observed:
        raise GeneratorAcceptanceError(f"{label} is not locally bound to the requested digest", 2)


def _free_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
        ports = [int(listener.getsockname()[1]) for listener in sockets]
        if len(ports) != len(set(ports)):
            raise GeneratorAcceptanceError("could not reserve distinct loopback acceptance ports", 2)
        return ports
    finally:
        for listener in sockets:
            listener.close()


def _wait_registry(address: str) -> None:
    opener = build_opener(ProxyHandler({}))
    request = Request(f"http://{address}/v2/", method="GET")
    for _ in range(60):
        try:
            with opener.open(request, timeout=2) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError, RemoteDisconnected):
            pass
        time.sleep(0.5)
    raise GeneratorAcceptanceError("private loopback registry did not become ready")


def _start_registry(inputs: Inputs, name: str, run_id: str) -> str:
    port = _free_ports(1)[0]
    _run(
        [
            "docker", "container", "create",
            "--name", name,
            "--label", f"{OUTER_LABEL}={run_id}",
            "--publish", f"127.0.0.1:{port}:5000",
            "--publish", f"[::1]:{port}:5000",
            inputs.registry_image,
        ],
        capture=True,
        timeout=120,
        label="private registry creation",
    )
    _run(["docker", "container", "start", name], capture=True, timeout=120,
         label="private registry start")
    port_output = _captured(
        ["docker", "container", "port", name, "5000/tcp"],
        label="private registry port resolution",
    )
    expected_bindings = {f"127.0.0.1:{port}", f"[::1]:{port}"}
    if set(port_output.splitlines()) != expected_bindings:
        raise GeneratorAcceptanceError(
            "private registry is not bound to the same IPv4 and IPv6 loopback port"
        )
    # Docker treats localhost registries as private HTTP endpoints. Binding the
    # same port on both loopback families keeps the endpoint private while
    # avoiding Docker Desktop's platform-dependent localhost address order.
    address = f"localhost:{port}"
    _wait_registry(address)
    return address


def _project_version(project: Path) -> str:
    try:
        root = ET.parse(project / "pom.xml").getroot()
    except (OSError, ET.ParseError) as error:
        raise GeneratorAcceptanceError("derived root POM is invalid") from error
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"
    version = root.findtext(namespace + "version", default="").strip()
    if not SEMANTIC_VERSION.fullmatch(version):
        raise GeneratorAcceptanceError("derived project version is not semantic")
    return version


def _commit_project(project: Path, message: str) -> tuple[str, str]:
    git_environment = _isolated_git_environment()
    if not (project / ".git").exists():
        template = project.parent / f".{project.name}-empty-git-template"
        if template.exists() or template.is_symlink():
            raise GeneratorAcceptanceError("derived Git template target already exists")
        template.mkdir(mode=0o700)
        try:
            _run(
                ["git", "-c", "core.hooksPath=/dev/null", "init", "--quiet",
                 f"--template={template}"],
                cwd=project,
                environment=git_environment,
                label="derived Git initialization",
            )
        finally:
            try:
                template.rmdir()
            except OSError as error:
                raise GeneratorAcceptanceError("derived Git template could not be removed") from error
    _run(
        ["git", "-c", "core.hooksPath=/dev/null", "add", "--all"],
        cwd=project,
        environment=git_environment,
        label="derived Git staging",
    )
    _run(
        [
            "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
            "-c", "user.name=Web Starter Acceptance",
            "-c", "user.email=acceptance@example.invalid",
            "commit", "--quiet", "-m", message,
        ],
        cwd=project,
        environment=git_environment,
        label="derived Git commit",
    )
    commit = _run(
        ["git", "rev-parse", "HEAD"], cwd=project, environment=git_environment,
        capture=True, timeout=120, label="derived commit resolution",
    ).stdout.strip()
    tree = _run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=project, environment=git_environment,
        capture=True, timeout=120, label="derived tree resolution",
    ).stdout.strip()
    if not GIT_COMMIT.fullmatch(commit) or not GIT_COMMIT.fullmatch(tree):
        raise GeneratorAcceptanceError("derived Git identity is malformed")
    return commit, tree


def _require_tracked_clean(project: Path, label: str) -> None:
    status = _captured(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=project,
        label=label,
    )
    if status:
        raise GeneratorAcceptanceError(f"{label} found tracked source drift")


def _create_derived_project(inputs: Inputs, template: Path, project: Path) -> None:
    wrapper = template / "bin/web-starter"
    _run(
        [
            str(wrapper), "project", "init",
            "--source", str(template),
            "--name", inputs.project_name,
            "--product-name", inputs.product_name,
            "--group-id", inputs.group_id,
            "--package-prefix", inputs.group_id,
            "--database", inputs.database,
            "--env-prefix", inputs.environment_prefix,
            "--output", str(project),
        ],
        cwd=template,
        label="derived project initialization",
    )
    expected = (
        project / f"{inputs.project_name}-admin/src/main/java"
        / Path(inputs.group_id.replace(".", "/"))
    )
    if not expected.is_dir() or (project / ".git").exists():
        raise GeneratorAcceptanceError("project initializer did not publish the expected isolated identity")


def _policy_gates(inputs: Inputs, project: Path) -> None:
    script = project / "scripts/repository_policy.py"
    _run([sys.executable, "-B", str(script), "secrets", "--root", str(project)],
         cwd=project, label="derived secret scan")
    _run(
        [
            sys.executable, "-B", str(script), "forbidden", "--root", str(project),
            "--forbidden-terms-file", str(inputs.forbidden_terms),
        ],
        cwd=project,
        label="derived forbidden-term scan",
    )


def _install_frontend(project: Path, project_name: str) -> None:
    _run(
        ["pnpm", "install", "--frozen-lockfile"],
        cwd=project / f"{project_name}-web",
        label="derived frontend dependency installation",
    )


def _resolve_pushed_image(tag: str, repository: str, role: str) -> BuiltImage:
    document = _docker_json(["docker", "image", "inspect", tag], f"{role} image inspection")
    image_id = document.get("Id")
    repo_digests = document.get("RepoDigests")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise GeneratorAcceptanceError(f"{role} image has no immutable local image ID")
    if not isinstance(repo_digests, list):
        raise GeneratorAcceptanceError(f"{role} image has no pushed repository digest")
    matches = sorted(
        value for value in repo_digests
        if isinstance(value, str) and value.startswith(repository + "@sha256:")
    )
    if len(matches) != 1 or not IMMUTABLE_IMAGE.fullmatch(matches[0]):
        raise GeneratorAcceptanceError(f"{role} image did not resolve one repository digest")
    digest = matches[0].split("@", 1)[1]
    return BuiltImage(role, repository, tag, digest, matches[0], image_id)


def _export_build_context(
    project: Path,
    commit: str,
    expected_tree: str,
    destination: Path,
) -> str:
    """Export one committed tree into a fresh, link-free Docker context."""
    if destination.exists() or destination.is_symlink():
        raise GeneratorAcceptanceError("build context target already exists")
    git_environment = _isolated_git_environment()
    actual_commit = _run(
        ["git", "rev-parse", f"{commit}^{{commit}}"], cwd=project,
        environment=git_environment, capture=True, timeout=120,
        label="build context commit resolution",
    ).stdout.strip()
    actual_tree = _run(
        ["git", "rev-parse", f"{commit}^{{tree}}"], cwd=project,
        environment=git_environment, capture=True, timeout=120,
        label="build context tree resolution",
    ).stdout.strip()
    if actual_commit != commit or actual_tree != expected_tree:
        raise GeneratorAcceptanceError("build context Git identity differs from the recorded stage")

    archive = destination.parent / f"{destination.name}.tar"
    if archive.exists() or archive.is_symlink():
        raise GeneratorAcceptanceError("build context archive target already exists")
    try:
        _run(
            ["git", "archive", "--format=tar", f"--output={archive}", commit],
            cwd=project,
            environment=git_environment,
            label="committed build context export",
        )
        archive_sha256 = sha256_file(archive)
        destination.mkdir(mode=0o700)
        seen: set[str] = set()
        with tarfile.open(archive, mode="r:") as source:
            for member in source:
                relative = PurePosixPath(member.name)
                if relative.is_absolute() or not relative.parts \
                        or any(part in {"", ".", ".."} for part in relative.parts):
                    raise GeneratorAcceptanceError("committed build context has an unsafe path")
                normalized = relative.as_posix()
                if normalized in seen:
                    raise GeneratorAcceptanceError("committed build context has a duplicate path")
                seen.add(normalized)
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    if target.exists() and not target.is_dir():
                        raise GeneratorAcceptanceError("committed build context path collides")
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise GeneratorAcceptanceError(
                        "committed build context contains a link or special file"
                    )
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    raise GeneratorAcceptanceError("committed build context path collides")
                stream = source.extractfile(member)
                if stream is None:
                    raise GeneratorAcceptanceError("committed build context file is unreadable")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags, 0o600)
                try:
                    while True:
                        block = stream.read(1024 * 1024)
                        if not block:
                            break
                        remaining = memoryview(block)
                        while remaining:
                            written = os.write(descriptor, remaining)
                            if written <= 0:
                                raise OSError("build context write made no progress")
                            remaining = remaining[written:]
                finally:
                    stream.close()
                    os.close(descriptor)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
        return archive_sha256
    except (OSError, tarfile.TarError) as error:
        raise GeneratorAcceptanceError("committed build context could not be exported") from error
    finally:
        try:
            archive.unlink(missing_ok=True)
        except OSError as error:
            raise GeneratorAcceptanceError("build context archive could not be removed") from error


def _build_images(
    project: Path,
    inputs: Inputs,
    registry: str,
    run_id: str,
    stage: str,
    version: str,
    commit: str,
    tree: str,
    work_root: Path,
    built_images: list[BuiltImage],
) -> tuple[BuiltImage, BuiltImage, str]:
    environment = os.environ.copy()
    environment["DOCKER_BUILDKIT"] = "1"
    context = work_root / f"build-context-{stage}"
    context_sha256 = _export_build_context(project, commit, tree, context)
    result: list[BuiltImage] = []
    for role, dockerfile in (("app", "Dockerfile"), ("nginx", "deploy/nginx/Dockerfile")):
        repository = f"{registry}/{inputs.project_name}-{run_id}/{role}"
        tag = f"{repository}:{stage}-{commit[:12]}"
        _run(
            [
                "docker", "build", "--pull=false",
                "--file", dockerfile,
                "--tag", tag,
                "--label", f"org.opencontainers.image.revision={commit}",
                "--label", f"org.opencontainers.image.version={version}",
                "--label", f"{OUTER_LABEL}={run_id}",
                ".",
            ],
            cwd=context,
            environment=environment,
            label=f"{stage} {role} image build",
        )
        _run(["docker", "push", tag], cwd=context, label=f"{stage} {role} image push")
        image = _resolve_pushed_image(tag, repository, f"{stage} {role}")
        result.append(image)
        built_images.append(image)
    return result[0], result[1], context_sha256


def runtime_environment(
    *,
    inputs: Inputs,
    stage: str,
    run_id: str,
    version: str,
    commit: str,
    app: BuiltImage,
    nginx: BuiltImage,
    artifact_root: Path,
    runner_temp: Path,
    expected_modules: str,
    expected_mcp_modules: str,
    ports: Sequence[int],
) -> tuple[dict[str, str], str]:
    if len(ports) != 3:
        raise GeneratorAcceptanceError("each runtime stage requires three isolated ports")
    prefix = inputs.environment_prefix
    github_run_id = f"gen{run_id}{stage}"
    compose_project = f"wsgen-{run_id}-{stage}"
    environment = os.environ.copy()
    environment.update({
        prefix + "MYSQL_IMAGE": inputs.mysql_image,
        prefix + "REDIS_IMAGE": inputs.redis_image,
        prefix + "APP_IMAGE": app.repository,
        prefix + "APP_DIGEST": app.digest,
        prefix + "NGINX_IMAGE": nginx.repository,
        prefix + "NGINX_DIGEST": nginx.digest,
        prefix + "RELEASE_TAG": "v" + version,
        prefix + "RELEASE_VERSION": version,
        prefix + "RELEASE_ARTIFACT_DIR": str(artifact_root),
        prefix + "EXPECTED_GENERATED_MODULES": expected_modules,
        prefix + "EXPECTED_GENERATED_MCP_MODULES": expected_mcp_modules,
        prefix + "ACCEPTANCE_PRIVATE_PORT": str(ports[0]),
        prefix + "ACCEPTANCE_PUBLIC_PORT": str(ports[1]),
        prefix + "ACCEPTANCE_MANAGEMENT_PORT": str(ports[2]),
        prefix + "ACCEPTANCE_COMPOSE_PROJECT": compose_project,
        "GITHUB_SHA": commit,
        "GITHUB_RUN_ID": github_run_id,
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_TEMP": str(runner_temp),
        "CI": "true",
    })
    return environment, compose_project


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GeneratorAcceptanceError(f"runtime artifact repeats field: {key}")
        document[key] = value
    return document


def _reject_json_constant(value: str) -> None:
    raise GeneratorAcceptanceError(f"runtime artifact contains non-finite number: {value}")


def _read_exact_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise GeneratorAcceptanceError(f"runtime artifact is invalid: {path.name}") from error
    if any(pattern.search(raw) for pattern in SENSITIVE_ARTIFACT):
        raise GeneratorAcceptanceError(
            f"runtime artifact contains sensitive material: {path.name}"
        )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise GeneratorAcceptanceError(f"runtime artifact is invalid: {path.name}") from error
    if not isinstance(value, dict):
        raise GeneratorAcceptanceError(f"runtime artifact is not an object: {path.name}")
    return value


def _require_exact_fields(value: dict[str, Any], expected: set[str] | frozenset[str], label: str) -> None:
    if set(value) != set(expected):
        raise GeneratorAcceptanceError(f"{label} has unexpected or missing fields")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GeneratorAcceptanceError(f"{label} must be an object")
    return value


def _require_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise GeneratorAcceptanceError(f"{label} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GeneratorAcceptanceError(
            f"{label} must be a timezone-aware timestamp"
        ) from error
    if parsed.tzinfo is None:
        raise GeneratorAcceptanceError(f"{label} must be a timezone-aware timestamp")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise GeneratorAcceptanceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_metric_snapshot(
    document: dict[str, Any],
    *,
    inputs: Inputs,
    baseline: dict[str, Any] | None,
) -> None:
    common_fields = {
        "schemaVersion", "status", "observedAt", "authorization", "metrics",
        "protocolEndpoints",
    }
    expected_fields = common_fields if baseline is None else common_fields | {
        "baselineObservedAt", "checks", "structuredLog",
    }
    _require_exact_fields(document, expected_fields, "operational metrics evidence")
    expected_status = "SNAPSHOT" if baseline is None else "PASS"
    if document.get("schemaVersion") != 1 or document.get("status") != expected_status:
        raise GeneratorAcceptanceError("operational metrics evidence status is invalid")
    _require_timestamp(document.get("observedAt"), "operational metrics observedAt")
    authorization = _require_object(
        document.get("authorization"), "operational metrics authorization"
    )
    if authorization != AUTHORIZATION_MATRIX:
        raise GeneratorAcceptanceError("operational metrics authorization matrix is invalid")

    compact_name = inputs.project_name.replace("-", "")
    allowed_tags = {
        f"{compact_name}.audit.operations": {"boundary", "result"},
        f"{compact_name}.audit.persist.failures": {"type"},
        f"{compact_name}.login.attempts": {"result"},
        f"{compact_name}.mcp.calls": {"tool", "result"},
        f"{compact_name}.mcp.call.duration": {"tool", "result"},
        f"{compact_name}.mcp.rate_limited": {"risk"},
        f"{compact_name}.mcp.sessions": {"event"},
        f"{compact_name}.protocol.requests": {"endpoint", "method", "outcome"},
        f"{compact_name}.rate_limited": {"endpoint"},
        "hikaricp.connections.usage": None,
    }
    metrics = _require_object(document.get("metrics"), "operational metrics")
    if set(metrics) != set(allowed_tags):
        raise GeneratorAcceptanceError("operational metrics set differs from expectation")
    safe_name = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
    for metric_name, allowed_metric_tags in allowed_tags.items():
        metric = _require_object(metrics.get(metric_name), f"metric {metric_name}")
        _require_exact_fields(metric, {"present", "measurements", "tags"}, f"metric {metric_name}")
        if not isinstance(metric.get("present"), bool):
            raise GeneratorAcceptanceError(f"metric {metric_name} presence is invalid")
        measurements = _require_object(
            metric.get("measurements"), f"metric {metric_name} measurements"
        )
        for statistic, measurement in measurements.items():
            if not isinstance(statistic, str) or not safe_name.fullmatch(statistic):
                raise GeneratorAcceptanceError(f"metric {metric_name} statistic is unsafe")
            if isinstance(measurement, bool) or not isinstance(measurement, (int, float)) \
                    or not math.isfinite(float(measurement)):
                raise GeneratorAcceptanceError(f"metric {metric_name} measurement is invalid")
        tags = _require_object(metric.get("tags"), f"metric {metric_name} tags")
        if allowed_metric_tags is not None and not set(tags).issubset(allowed_metric_tags):
            raise GeneratorAcceptanceError(f"metric {metric_name} has an unexpected tag")
        for tag, values in tags.items():
            if not isinstance(tag, str) or not safe_name.fullmatch(tag) or not isinstance(values, list):
                raise GeneratorAcceptanceError(f"metric {metric_name} tag metadata is invalid")
            if values != sorted(set(values)) or any(
                not isinstance(value, str)
                or len(value) > 128
                or any(character in value for character in "\r\n\0")
                or any(pattern.search(value) for pattern in SENSITIVE_ARTIFACT)
                for value in values
            ):
                raise GeneratorAcceptanceError(f"metric {metric_name} tag values are unsafe")

    protocol_endpoints = _require_object(
        document.get("protocolEndpoints"), "operational protocol endpoint metrics"
    )
    if set(protocol_endpoints) != set(PROTOCOL_ENDPOINTS):
        raise GeneratorAcceptanceError(
            "operational protocol endpoint metric set differs from expectation"
        )
    for endpoint in PROTOCOL_ENDPOINTS:
        metric = _require_object(
            protocol_endpoints.get(endpoint),
            f"operational protocol endpoint metric {endpoint}",
        )
        _require_exact_fields(
            metric,
            {"present", "measurements", "tags"},
            f"operational protocol endpoint metric {endpoint}",
        )
        measurements = _require_object(
            metric.get("measurements"),
            f"operational protocol endpoint metric {endpoint} measurements",
        )
        tags = _require_object(
            metric.get("tags"),
            f"operational protocol endpoint metric {endpoint} tags",
        )
        count = measurements.get("COUNT")
        if (
            metric.get("present") is not True
            or set(measurements) != {"COUNT"}
            or isinstance(count, bool)
            or not isinstance(count, (int, float))
            or not math.isfinite(float(count))
            or tags != {
                "method": list(PROTOCOL_METHODS),
                "outcome": list(PROTOCOL_OUTCOMES),
            }
        ):
            raise GeneratorAcceptanceError(
                f"operational protocol endpoint metric {endpoint} is not exact and bounded"
            )

    if baseline is not None:
        if document.get("baselineObservedAt") != baseline.get("observedAt"):
            raise GeneratorAcceptanceError("operational metrics baseline binding is invalid")
        checks = _require_object(document.get("checks"), "operational metrics checks")
        if set(checks) != set(METRIC_CHECKS) or any(value is not True for value in checks.values()):
            raise GeneratorAcceptanceError("operational metrics runtime checks are not all PASS")
        structured_log = _require_object(
            document.get("structuredLog"), "operational structured log proof"
        )
        _require_exact_fields(
            structured_log,
            {
                "format", "timestamp", "level", "message", "traceId", "endpoint",
                "method", "outcome", "sourceLineSha256",
            },
            "operational structured log proof",
        )
        if (
            structured_log.get("format") != "ecs"
            or not isinstance(structured_log.get("timestamp"), str)
            or ECS_TIMESTAMP.fullmatch(structured_log["timestamp"]) is None
            or structured_log.get("level") != "INFO"
            or structured_log.get("message") != "protocol_request"
            or not isinstance(structured_log.get("traceId"), str)
            or TRACE_ID.fullmatch(structured_log["traceId"]) is None
            or structured_log.get("endpoint") not in PROTOCOL_ENDPOINTS
            or structured_log.get("method") not in PROTOCOL_METHODS
            or structured_log.get("outcome") not in PROTOCOL_OUTCOMES
            or not isinstance(structured_log.get("sourceLineSha256"), str)
            or SHA256_HEX.fullmatch(structured_log["sourceLineSha256"]) is None
        ):
            raise GeneratorAcceptanceError(
                "operational structured log proof is not exact and bounded"
            )


def _validate_stage_identity(
    artifact_root: Path,
    *,
    inputs: Inputs,
    version: str,
    commit: str,
    compose_project: str,
    app: BuiltImage,
    nginx: BuiltImage,
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_layers = {name: "PASS" for name in sorted(VERIFY_LAYERS)}
    unified = _read_exact_json(artifact_root / "unified-verify-summary.json")
    if unified != {"schemaVersion": 1, "status": "PASS", "layers": expected_layers}:
        raise GeneratorAcceptanceError("unified seven-layer verify summary is not exact PASS")

    identity = _read_exact_json(artifact_root / "runtime-version-identity.json")
    _require_exact_fields(
        identity,
        {"schemaVersion", "status", "observedAt", "release", "java", "actuator", "images"},
        "runtime version identity",
    )
    if identity.get("schemaVersion") != 2 or identity.get("status") != "PASS":
        raise GeneratorAcceptanceError("runtime version identity is not PASS")
    _require_timestamp(identity.get("observedAt"), "runtime identity observedAt")
    if identity.get("release") != {"version": version, "gitCommit": commit}:
        raise GeneratorAcceptanceError("runtime identity release differs from the stage commit")
    java = _require_object(identity.get("java"), "runtime Java identity")
    _require_exact_fields(java, {"specificationVersion", "runtimeVersion"}, "runtime Java identity")
    runtime_version = java.get("runtimeVersion")
    if java.get("specificationVersion") != "21" or not isinstance(runtime_version, str) \
            or re.match(r"^21(?:[.+-]|$)", runtime_version) is None \
            or len(runtime_version) > 128 or any(character in runtime_version for character in "\r\n\0"):
        raise GeneratorAcceptanceError("runtime identity does not prove an actual Java 21 runtime")
    expected_actuator = {
        "applicationVersion": version,
        "buildVersion": version,
        "buildArtifact": inputs.project_name + "-admin",
        "buildGroup": inputs.group_id,
    }
    if identity.get("actuator") != expected_actuator:
        raise GeneratorAcceptanceError("runtime Actuator identity differs from the derived stage")
    expected_images = {
        "app": {
            "reference": app.digest_reference,
            "imageId": app.image_id,
            "ociVersion": version,
            "ociRevision": commit,
        },
        "nginx": {
            "reference": nginx.digest_reference,
            "imageId": nginx.image_id,
            "ociVersion": version,
            "ociRevision": commit,
        },
    }
    actual_images = _require_object(identity.get("images"), "runtime image identities")
    if set(actual_images) != {"app", "nginx", "mysql", "redis"}:
        raise GeneratorAcceptanceError("runtime image identity set is incomplete")
    for name, expected in expected_images.items():
        if actual_images.get(name) != expected:
            raise GeneratorAcceptanceError("runtime image identity differs from the stage digests")
    dependency_references = {
        "mysql": inputs.mysql_image,
        "redis": inputs.redis_image,
    }
    for name, reference in dependency_references.items():
        dependency = _require_object(
            actual_images.get(name), f"runtime {name} image identity"
        )
        _require_exact_fields(
            dependency,
            {"reference", "imageId", "ociVersion", "ociRevision"},
            f"runtime {name} image identity",
        )
        if (
            dependency.get("reference") != reference
            or not isinstance(dependency.get("imageId"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", dependency["imageId"]) is None
            or dependency.get("ociVersion") is not None
            or dependency.get("ociRevision") is not None
        ):
            raise GeneratorAcceptanceError(
                f"runtime {name} image identity differs from the immutable input"
            )
    if any(actual_images[name]["imageId"] == actual_images[other]["imageId"]
           for index, name in enumerate(("app", "nginx", "mysql", "redis"))
           for other in ("app", "nginx", "mysql", "redis")[index + 1:]):
        raise GeneratorAcceptanceError("runtime container image identities are unexpectedly aliased")
    if any(actual_images[name]["reference"] == actual_images[other]["reference"]
           for index, name in enumerate(("app", "nginx", "mysql", "redis"))
           for other in ("app", "nginx", "mysql", "redis")[index + 1:]):
        raise GeneratorAcceptanceError("runtime image identity differs from the stage digests")

    release = _read_exact_json(artifact_root / "release-runtime-acceptance.json")
    _require_exact_fields(
        release,
        {"schemaVersion", "status", "observedAt", "release", "images", "identity", "checks", "unifiedVerify"},
        "release runtime acceptance",
    )
    _require_timestamp(release.get("observedAt"), "release runtime observedAt")
    expected_release = {"tag": "v" + version, "version": version, "gitCommit": commit}
    expected_references = {
        "app": app.digest_reference,
        "nginx": nginx.digest_reference,
    }
    expected_release_identity = {
        "javaSpecificationVersion": "21",
        "applicationVersion": version,
        "buildVersion": version,
        "composeProject": compose_project,
        "mcpCrudTracePrefix": MCP_CRUD_TRACE_PREFIX,
        "appImage": app.digest_reference,
        "nginxImage": nginx.digest_reference,
        "appOciVersion": version,
        "appOciRevision": commit,
        "nginxOciVersion": version,
        "nginxOciRevision": commit,
    }
    checks = _require_object(release.get("checks"), "release runtime checks")
    expected_unified = {
        "path": "unified-verify-summary.json",
        "sha256": sha256_file(artifact_root / "unified-verify-summary.json"),
        "status": "PASS",
        "layers": expected_layers,
    }
    if (
        release.get("schemaVersion") != 1
        or release.get("status") != "PASS"
        or release.get("release") != expected_release
        or release.get("images") != expected_references
        or release.get("identity") != expected_release_identity
        or set(checks) != set(RUNTIME_CHECKS)
        or any(value != "PASS" for value in checks.values())
        or release.get("unifiedVerify") != expected_unified
    ):
        raise GeneratorAcceptanceError("release runtime evidence is partial or stage-mismatched")
    return identity, release


def validate_stage_artifacts(
    artifact_root: Path,
    *,
    inputs: Inputs,
    version: str,
    commit: str,
    compose_project: str,
    app: BuiltImage,
    nginx: BuiltImage,
    expected_module: str | None,
) -> dict[str, str]:
    expected = set(EXPECTED_ARTIFACTS)
    if expected_module is not None:
        expected.add(GENERATED_ARTIFACT)
    actual: set[str] = set()
    for path in artifact_root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise GeneratorAcceptanceError("runtime evidence contains an unsafe entry")
        actual.add(path.name)
    if actual != expected:
        raise GeneratorAcceptanceError(
            f"runtime evidence file set is not exact: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    _validate_stage_identity(
        artifact_root,
        inputs=inputs,
        version=version,
        commit=commit,
        compose_project=compose_project,
        app=app,
        nginx=nginx,
    )

    policy = _read_exact_json(artifact_root / "runtime-production-compose-policy.json")
    _require_exact_fields(
        policy, {"schemaVersion", "status", "composeSha256", "errors"},
        "runtime production Compose policy",
    )
    if policy.get("schemaVersion") != 1 or policy.get("status") != "PASS" \
            or policy.get("errors") != []:
        raise GeneratorAcceptanceError("runtime production Compose policy is not exact PASS")
    _require_sha256(policy.get("composeSha256"), "runtime production Compose digest")

    oauth = _read_exact_json(artifact_root / "oauth-runtime.json")
    _require_exact_fields(oauth, {"schemaVersion", "status", "checks"}, "OAuth runtime evidence")
    oauth_checks = _require_object(oauth.get("checks"), "OAuth runtime checks")
    if oauth.get("schemaVersion") != 1 or oauth.get("status") != "PASS" \
            or set(oauth_checks) != set(OAUTH_CHECKS) \
            or any(value != "PASS" for value in oauth_checks.values()):
        raise GeneratorAcceptanceError("OAuth runtime evidence is not exact PASS")

    metrics_baseline = _read_exact_json(
        artifact_root / "operational-metrics-baseline.json"
    )
    _validate_metric_snapshot(metrics_baseline, inputs=inputs, baseline=None)
    metrics_runtime = _read_exact_json(
        artifact_root / "operational-metrics-runtime.json"
    )
    _validate_metric_snapshot(metrics_runtime, inputs=inputs, baseline=metrics_baseline)

    compose_status = _read_exact_json(artifact_root / "runtime-compose-ps.json")
    _require_exact_fields(compose_status, {"schemaVersion", "services"}, "runtime Compose status")
    services = compose_status.get("services")
    if compose_status.get("schemaVersion") != 1 or not isinstance(services, list) \
            or len(services) != len(COMPOSE_SERVICES):
        raise GeneratorAcceptanceError("runtime Compose status is incomplete")
    observed_services: set[str] = set()
    for service in services:
        if not isinstance(service, dict):
            raise GeneratorAcceptanceError("runtime Compose service status is invalid")
        _require_exact_fields(service, {"service", "state", "health"}, "runtime Compose service")
        name = service.get("service")
        if name not in COMPOSE_SERVICES or name in observed_services \
                or service.get("state") != "running" or service.get("health") != "healthy":
            raise GeneratorAcceptanceError("runtime Compose service is not uniquely healthy")
        observed_services.add(name)
    if observed_services != set(COMPOSE_SERVICES):
        raise GeneratorAcceptanceError("runtime Compose service set differs from expectation")

    generated_path = artifact_root / GENERATED_ARTIFACT
    if expected_module is None:
        if generated_path.exists() or generated_path.is_symlink():
            raise GeneratorAcceptanceError("project-only stage unexpectedly emitted module evidence")
    else:
        generated = _read_exact_json(generated_path)
        _require_exact_fields(generated, {"schemaVersion", "status", "modules"}, "generated module runtime")
        modules = generated.get("modules")
        if generated.get("schemaVersion") != 1 or generated.get("status") != "PASS" \
                or not isinstance(modules, list) or len(modules) != 1:
            raise GeneratorAcceptanceError("generated module runtime summary is not one PASS module")
        module = modules[0]
        if not isinstance(module, dict):
            raise GeneratorAcceptanceError("generated module runtime summary differs from expectation")
        _require_exact_fields(
            module,
            {"module", "artifactId", "migrationSha256", "planSha256", "browserTestSha256",
             "browserStatus", "mcpRuntimeTestSha256", "mcpStatus"},
            "generated module runtime item",
        )
        if module.get("module") != expected_module \
                or module.get("artifactId") != f"{inputs.project_name}-{expected_module}" \
                or module.get("browserStatus") != "PASS" or module.get("mcpStatus") != "PASS":
            raise GeneratorAcceptanceError("generated module runtime summary differs from expectation")
        for field in (
            "migrationSha256", "planSha256", "browserTestSha256", "mcpRuntimeTestSha256",
        ):
            _require_sha256(module.get(field), f"generated module {field}")
    return {name: sha256_file(artifact_root / name) for name in sorted(expected)}


def _run_stage(
    *,
    project: Path,
    inputs: Inputs,
    stage_name: str,
    run_id: str,
    version: str,
    commit: str,
    tree: str,
    registry: str,
    bundle: Path,
    work_root: Path,
    expected_modules: str,
    expected_mcp_modules: str,
    expected_module: str | None,
    built_images: list[BuiltImage],
    compose_projects: list[str],
) -> Stage:
    _require_tracked_clean(project, f"{stage_name} pre-build clean check")
    app, nginx, build_context_sha256 = _build_images(
        project, inputs, registry, run_id, stage_name, version, commit, tree, work_root,
        built_images,
    )
    artifact_root = bundle / "stages" / stage_name
    runner_temp = work_root / f"runner-{stage_name}"
    runner_temp.mkdir(mode=0o700)
    ports = _free_ports(3)
    environment, compose_project = runtime_environment(
        inputs=inputs,
        stage=stage_name,
        run_id=run_id,
        version=version,
        commit=commit,
        app=app,
        nginx=nginx,
        artifact_root=artifact_root,
        runner_temp=runner_temp,
        expected_modules=expected_modules,
        expected_mcp_modules=expected_mcp_modules,
        ports=ports,
    )
    compose_projects.append(compose_project)
    _run(
        ["bash", "scripts/run_release_runtime_acceptance.sh"],
        cwd=project,
        environment=environment,
        label=f"{stage_name} immutable full-stack acceptance",
    )
    _require_tracked_clean(project, f"{stage_name} post-runtime clean check")
    artifacts = validate_stage_artifacts(
        artifact_root,
        inputs=inputs,
        version=version,
        commit=commit,
        compose_project=compose_project,
        app=app,
        nginx=nginx,
        expected_module=expected_module,
    )
    return Stage(
        stage_name, version, commit, tree, build_context_sha256, compose_project, expected_modules,
        expected_mcp_modules, app, nginx, artifacts
    )


def _generate_module(inputs: Inputs, project: Path) -> None:
    wrapper = project / f"bin/{inputs.project_name}"
    common = [
        "--workspace", str(project),
        "--name", inputs.module_name,
        "--label", inputs.module_label,
        "--migration-version", inputs.migration_version,
        "--permission-id-base", inputs.permission_id_base,
        "--menu-id", inputs.menu_id,
        "--with-mcp",
    ]
    for operation in ("validate", "dry-run", "generate"):
        _run(
            [str(wrapper), "module", operation, *common],
            cwd=project,
            label=f"generated module {operation}",
        )


def _docker_ids(filter_arguments: Sequence[str], noun: str) -> list[str]:
    output = _captured(["docker", noun, "ls", "--quiet", *filter_arguments],
                       label=f"Docker {noun} cleanup inspection")
    return [line for line in output.splitlines() if line]


def _verify_compose_cleanup(projects: Iterable[str]) -> None:
    failures: list[str] = []
    for project in projects:
        label = f"label=com.docker.compose.project={project}"
        for noun in ("container", "volume", "network"):
            filters = ["--filter", label]
            if noun == "container":
                filters.insert(0, "--all")
            try:
                if _docker_ids(filters, noun):
                    failures.append(f"{project}:{noun}:leftover")
            except BaseException:
                failures.append(f"{project}:{noun}:inspection")
    if failures:
        raise GeneratorAcceptanceError(
            "cleanup left or could not inspect Compose resources: " + ", ".join(failures)
        )


def _force_compose_cleanup(projects: Iterable[str]) -> None:
    failures: list[str] = []
    for project in projects:
        label = f"label=com.docker.compose.project={project}"
        for noun, filters, remove_prefix in (
            ("container", ["--all", "--filter", label],
             ["docker", "container", "rm", "--force"]),
            ("volume", ["--filter", label], ["docker", "volume", "rm"]),
            ("network", ["--filter", label], ["docker", "network", "rm"]),
        ):
            try:
                identifiers = _docker_ids(filters, noun)
                if identifiers:
                    _run(
                        [*remove_prefix, *identifiers], capture=True, timeout=180,
                        label=f"generator Compose {noun} cleanup",
                    )
            except BaseException:
                failures.append(f"{project}:{noun}")
    if failures:
        raise GeneratorAcceptanceError(
            "generator Compose cleanup failed for: " + ", ".join(failures)
        )


def _remove_if_present(command_prefix: Sequence[str], reference: str, label: str) -> None:
    inspect = subprocess.run(
        [*command_prefix, "inspect", reference],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if inspect.returncode == 0:
        noun = command_prefix[1]
        _run(["docker", noun, "rm", reference], capture=True, timeout=180,
             label=label)


def _cleanup_docker(
    run_id: str,
    registry_name: str | None,
    images: Sequence[BuiltImage],
    compose_projects: Sequence[str],
) -> None:
    failures: list[str] = []

    def attempt(label: str, operation) -> None:
        try:
            operation()
        except BaseException:
            failures.append(label)

    attempt("Compose resources", lambda: _force_compose_cleanup(compose_projects))
    if registry_name is not None:
        def remove_registry() -> None:
            present = subprocess.run(
                ["docker", "container", "inspect", registry_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0
            if present:
                _run(["docker", "container", "rm", "--force", registry_name], capture=True,
                     timeout=180, label="private registry cleanup")
        attempt("private registry", remove_registry)
    for reference in dict.fromkeys(
        [image.digest_reference for image in images] + [image.tag for image in images]
    ):
        attempt(
            "generated image reference",
            lambda reference=reference: _remove_if_present(
                ["docker", "image"], reference, "generated image reference cleanup"
            ),
        )
    for image_id in dict.fromkeys(image.image_id for image in images):
        attempt(
            "generated image ID",
            lambda image_id=image_id: _remove_if_present(
                ["docker", "image"], image_id, "generated image ID cleanup"
            ),
        )

    def remove_labeled_images() -> None:
        output = _captured(
            ["docker", "image", "ls", "--quiet", "--filter", f"label={OUTER_LABEL}={run_id}"],
            label="partially built generator image inspection",
        )
        for image_id in dict.fromkeys(line for line in output.splitlines() if line):
            _remove_if_present(
                ["docker", "image"], image_id, "partially built generator image cleanup"
            )

    attempt("partially built generated images", remove_labeled_images)

    def verify() -> None:
        outer_filter = ["--all", "--filter", f"label={OUTER_LABEL}={run_id}"]
        if _docker_ids(outer_filter, "container"):
            raise GeneratorAcceptanceError("cleanup left generator-owned containers")
        image_output = _captured(
            ["docker", "image", "ls", "--quiet", "--filter", f"label={OUTER_LABEL}={run_id}"],
            label="generator-owned image cleanup inspection",
        )
        if image_output:
            raise GeneratorAcceptanceError("cleanup left generator-owned final images")
        _verify_compose_cleanup(compose_projects)

    attempt("post-cleanup verification", verify)
    if failures:
        raise GeneratorAcceptanceError(
            "generator-owned Docker cleanup did not complete: " + ", ".join(sorted(set(failures)))
        )


def _stage_document(stage: Stage) -> dict[str, Any]:
    return {
        "name": stage.name,
        "version": stage.version,
        "commit": stage.commit,
        "tree": stage.tree,
        "buildContextSha256": stage.build_context_sha256,
        "composeProject": stage.compose_project,
        "expectedModules": stage.expected_modules,
        "expectedMcpModules": stage.expected_mcp_modules,
        "images": {
            "app": {"reference": stage.app.digest_reference, "imageId": stage.app.image_id},
            "nginx": {"reference": stage.nginx.digest_reference, "imageId": stage.nginx.image_id},
        },
        "artifacts": stage.artifacts,
        "status": "PASS",
    }


def _harden_evidence_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise GeneratorAcceptanceError("generator evidence root is unsafe")
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        if current_path.is_symlink():
            raise GeneratorAcceptanceError("generator evidence contains a symbolic link")
        os.chmod(current_path, 0o700)
        for name in directories:
            child = current_path / name
            if child.is_symlink() or not child.is_dir():
                raise GeneratorAcceptanceError("generator evidence contains an unsafe directory")
        for name in files:
            child = current_path / name
            if child.is_symlink() or not child.is_file():
                raise GeneratorAcceptanceError("generator evidence contains an unsafe file")
            os.chmod(child, 0o600)


def _write_checksum(path: Path, evidence_path: Path) -> None:
    payload = f"{sha256_file(evidence_path)}  {evidence_path.name}\n".encode("ascii")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("checksum write made no progress")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)


def _remove_tree_checked(path: Path | None, label: str) -> None:
    if path is None:
        return
    if path.is_symlink():
        raise GeneratorAcceptanceError(f"{label} became a symbolic link")
    try:
        if path.exists():
            shutil.rmtree(path)
    except OSError as error:
        raise GeneratorAcceptanceError(f"{label} could not be removed") from error
    if path.exists() or path.is_symlink():
        raise GeneratorAcceptanceError(f"{label} still exists")


def execute(inputs: Inputs) -> dict[str, Any]:
    candidate = _formal_candidate(inputs.repository)
    candidate_commit = candidate.commit
    candidate_tree = candidate.tree
    for reference, label in (
        (inputs.mysql_image, "MySQL acceptance image"),
        (inputs.redis_image, "Redis acceptance image"),
        (inputs.registry_image, "registry acceptance image"),
    ):
        _require_local_immutable_image(reference, label)

    run_id = hashlib.sha256(os.urandom(32)).hexdigest()[:12]
    if not RUN_ID.fullmatch(run_id):
        raise GeneratorAcceptanceError("could not create an isolated acceptance run id")
    work_root: Path | None = None
    bundle: Path | None = None
    registry_name: str | None = None
    built_images: list[BuiltImage] = []
    compose_projects: list[str] = []
    stages: list[Stage] = []
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None

    try:
        work_root = Path(
            tempfile.mkdtemp(prefix=f"web-starter-generator-{run_id}-")
        ).resolve()
        os.chmod(work_root, 0o700)
        bundle = Path(tempfile.mkdtemp(
            prefix=inputs.output.name + ".tmp-", dir=inputs.output.parent
        )).resolve()
        os.chmod(bundle, 0o700)
        template = work_root / "template"
        project = work_root / inputs.project_name
        git_environment = _isolated_git_environment()
        empty_git_template = work_root / ".empty-clone-template"
        empty_git_template.mkdir(mode=0o700)
        try:
            _run(
                [
                    "git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet",
                    "--no-local", "--no-checkout", f"--template={empty_git_template}",
                    str(inputs.repository), str(template),
                ],
                environment=git_environment,
                label="candidate isolated clone",
            )
        finally:
            try:
                empty_git_template.rmdir()
            except OSError as error:
                raise GeneratorAcceptanceError(
                    "candidate Git template could not be removed"
                ) from error
        _run(
            ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--quiet",
             "--detach", candidate_commit],
            cwd=template,
            environment=git_environment,
            label="candidate isolated checkout",
        )
        isolated_head = _run(
            ["git", "rev-parse", "HEAD"], cwd=template, environment=git_environment,
            capture=True, timeout=120, label="isolated checkout identity",
        ).stdout.strip()
        if isolated_head != candidate_commit:
            raise GeneratorAcceptanceError("isolated checkout differs from the candidate commit")
        _run(
            ["./mvnw", "--batch-mode", "--no-transfer-progress", "-pl", "web-starter-tooling",
             "-am", "package", "-DskipTests"],
            cwd=template,
            label="candidate tooling build",
        )
        _create_derived_project(inputs, template, project)
        _policy_gates(inputs, project)
        _install_frontend(project, inputs.project_name)
        project_commit, project_tree = _commit_project(
            project, "Initialize isolated generated project acceptance"
        )
        version = _project_version(project)
        if version != candidate.maven_version:
            raise GeneratorAcceptanceError(
                "derived project version differs from the release candidate"
            )

        registry_name = f"web-starter-generator-registry-{run_id}"
        registry_address = _start_registry(inputs, registry_name, run_id)
        project_stage = _run_stage(
            project=project,
            inputs=inputs,
            stage_name="project",
            run_id=run_id,
            version=version,
            commit=project_commit,
            tree=project_tree,
            registry=registry_address,
            bundle=bundle,
            work_root=work_root,
            expected_modules="-",
            expected_mcp_modules="-",
            expected_module=None,
            built_images=built_images,
            compose_projects=compose_projects,
        )
        stages.append(project_stage)

        _generate_module(inputs, project)
        _policy_gates(inputs, project)
        module_commit, module_tree = _commit_project(
            project, "Generate isolated CRUD module with explicit MCP acceptance"
        )
        module_stage = _run_stage(
            project=project,
            inputs=inputs,
            stage_name="module",
            run_id=run_id,
            version=version,
            commit=module_commit,
            tree=module_tree,
            registry=registry_address,
            bundle=bundle,
            work_root=work_root,
            expected_modules=inputs.module_name,
            expected_mcp_modules=inputs.module_name,
            expected_module=inputs.module_name,
            built_images=built_images,
            compose_projects=compose_projects,
        )
        stages.append(module_stage)
        if len(stages) != 2:
            raise GeneratorAcceptanceError("generator acceptance did not complete both stages")
    except BaseException as error:
        failure = error

    try:
        _cleanup_docker(run_id, registry_name, built_images, compose_projects)
    except BaseException as error:
        cleanup_failure = error
    try:
        _remove_tree_checked(work_root, "temporary generated project tree")
    except BaseException as error:
        cleanup_failure = cleanup_failure or error

    if failure is not None or cleanup_failure is not None:
        try:
            _remove_tree_checked(bundle, "temporary generator evidence bundle")
        except BaseException as error:
            cleanup_failure = cleanup_failure or error
        if cleanup_failure is not None:
            raise GeneratorAcceptanceError(
                f"generator acceptance cleanup failed: {cleanup_failure}"
            ) from cleanup_failure
        if isinstance(failure, GeneratorAcceptanceError):
            raise failure
        raise GeneratorAcceptanceError("generator acceptance failed unexpectedly") from failure

    if bundle is None:
        raise GeneratorAcceptanceError("generator acceptance evidence bundle was not created")
    if _formal_candidate(inputs.repository) != candidate:
        raise GeneratorAcceptanceError(
            "candidate identity or source changed before evidence publication", 2
        )
    document = {
        "schemaVersion": 2,
        "acceptanceIds": list(ACCEPTANCE_IDS),
        "status": "PASS",
        "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "candidate": {
            "commit": candidate.commit,
            "tree": candidate.tree,
            "tag": candidate.tag,
            "tagObject": candidate.tag_object,
            "mavenVersion": candidate.maven_version,
            "frontendVersion": candidate.frontend_version,
            "cleanWorktree": True,
            "sourceBlobs": candidate.source_blobs,
        },
        "tooling": {
            "producerPath": PRODUCER_PATH,
            "validatorPath": VALIDATOR_PATH,
            "schemaPath": SCHEMA_PATH,
            "sourceCount": len(SOURCE_PATHS),
        },
        "derivedProject": {
            "name": inputs.project_name,
            "productName": inputs.product_name,
            "groupId": inputs.group_id,
            "database": inputs.database,
            "environmentPrefix": inputs.environment_prefix,
            "forbiddenTermsSha256": sha256_file(inputs.forbidden_terms),
        },
        "generatedModule": {
            "name": inputs.module_name,
            "label": inputs.module_label,
            "migrationVersion": inputs.migration_version,
            "permissionIdBase": inputs.permission_id_base,
            "menuId": inputs.menu_id,
            "withMcp": True,
        },
        "stages": [_stage_document(stage) for stage in stages],
        "cleanup": {
            "composeProjectsRemoved": sorted(compose_projects),
            "registryContainerRemoved": registry_name,
            "generatedImageReferencesRemoved": sorted(
                image.digest_reference for image in built_images
            ),
            "temporaryProjectTreeRemoved": True,
            "status": "PASS",
        },
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
            "onlyExpectedFiles": True,
            "rawSecretsPersisted": False,
        },
    }
    encoded_document = json.dumps(document, ensure_ascii=False, sort_keys=True)
    if any(pattern.search(encoded_document) for pattern in SENSITIVE_ARTIFACT):
        raise GeneratorAcceptanceError("generator evidence contains sensitive material")
    publication_failure: BaseException | None = None
    published = False
    try:
        evidence_path = bundle / EVIDENCE_FILE
        _write_private_json(evidence_path, document)
        _write_checksum(bundle / CHECKSUM_FILE, evidence_path)
        _harden_evidence_tree(bundle)
        if _formal_candidate(inputs.repository) != candidate:
            raise GeneratorAcceptanceError(
                "candidate identity or source changed during evidence publication", 2
            )
        if inputs.output.exists() or inputs.output.is_symlink():
            raise GeneratorAcceptanceError("output appeared before evidence publication", 2)
        os.rename(bundle, inputs.output)
        published = True
    except BaseException as error:
        publication_failure = error
    if not published:
        try:
            _remove_tree_checked(bundle, "temporary generator evidence bundle")
        except BaseException as error:
            raise GeneratorAcceptanceError(
                f"generator evidence publication and cleanup failed: {error}"
            ) from error
        if isinstance(publication_failure, GeneratorAcceptanceError):
            raise publication_failure
        raise GeneratorAcceptanceError(
            "generator evidence publication failed unexpectedly"
        ) from publication_failure
    return document


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--forbidden-terms", required=True, type=Path)
    result.add_argument("--mysql-image", required=True)
    result.add_argument("--redis-image", required=True)
    result.add_argument("--registry-image", required=True)
    result.add_argument("--project-name", default="journey-admin")
    result.add_argument("--product-name", default="启程派生管理系统")
    result.add_argument("--group-id", default="dev.journey.admin")
    result.add_argument("--database", default="journey_admin")
    result.add_argument("--environment-prefix", default="JOURNEY_ADMIN_")
    result.add_argument("--module-name", default="asset")
    result.add_argument("--module-label", default="资产")
    result.add_argument("--migration-version", default="202607200001")
    result.add_argument("--permission-id-base", default="5100")
    result.add_argument("--menu-id", default="6100")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        inputs = _safe_inputs(parser().parse_args(sys.argv[1:] if argv is None else argv))
        execute(inputs)
    except GeneratorAcceptanceError as error:
        print(f"FAIL generator-acceptance: {error}", file=sys.stderr)
        return error.exit_code
    except (OSError, ValueError) as error:
        print(f"FAIL generator-acceptance: {error}", file=sys.stderr)
        return 1
    print("PASS generator-acceptance: project-only and generated MCP module runtimes passed and cleaned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
