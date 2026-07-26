#!/usr/bin/env python3
"""Produce sanitized V2-AC-29 production fail-fast observations.

Formal observations are bound to one clean, annotated release candidate and a
caller-supplied digest reference.  Application output and generated fixtures
remain memory-only; the sibling validator independently recomputes PASS from
the sanitized counters in the public report.
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
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Mapping, Sequence
import xml.etree.ElementTree as ElementTree


REPO_ROOT = Path(__file__).resolve().parents[1]
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

DIGEST_REFERENCE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}@(?P<digest>sha256:[0-9a-f]{64})$"
)
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
CONTAINER_NAME = re.compile(
    r"^web-starter-ac29-(?:[0-9]{2}|java|control)-[0-9a-f]{12}$"
)
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
SAFE_RUNTIME_VALUE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+() /:-]{0,159}$")
SAFE_JAVA_HOME = re.compile(r"^/[0-9A-Za-z][0-9A-Za-z._+()/ -]{0,158}$")
LABEL_OWNER = "dev.webstarter.acceptance"
LABEL_RUN = "dev.webstarter.acceptance.run"

UNSAFE_PREFIX = "Unsafe production configuration: "
EARLY_MARKERS = {
    "tomcat": "Tomcat",
    "flyway": "Flyway",
    "hikari": "Hikari",
    "jdbcMysql": "jdbc:mysql",
    "communicationsLinkFailure": "Communications link failure",
    "unableDatabaseConnection": "Unable to obtain connection from database",
}
DATABASE_MARKERS = {
    **EARLY_MARKERS,
    "networkUnreachable": "Network is unreachable",
    "connectionRefused": "Connection refused",
    "mysqlDriver": "com.mysql.cj.jdbc",
}
DATABASE_FAILURE_MARKER_KEYS = (
    "communicationsLinkFailure",
    "unableDatabaseConnection",
    "networkUnreachable",
    "connectionRefused",
)


class RehearsalError(RuntimeError):
    """A safe, non-secret-bearing AC-29 orchestration failure."""


@dataclass(frozen=True)
class CandidateIdentity:
    head: str
    tree: str
    tag: str
    tag_object: str
    version: str
    source_sha256: Mapping[str, str]


@dataclass(frozen=True)
class ImageIdentity:
    reference: str
    image_id: str
    digest: str
    oci_version: str
    oci_revision: str
    operating_system: str
    architecture: str
    java_home: str


@dataclass(frozen=True)
class DangerousCase:
    case_id: str
    overrides: Mapping[str, str]
    expected_rejection: str


@dataclass(frozen=True)
class CleanupResult:
    already_absent: bool
    labels_verified: bool
    removed: bool
    residual: bool


@dataclass(frozen=True)
class ContainerResult:
    exit_code: int
    output: bytes
    timed_out: bool = False
    command_sha256: str = ""
    cleanup: CleanupResult | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def ensure_external_output_directory(path: Path, repository: Path = REPO_ROOT) -> Path:
    """Create an empty 0700 directory outside the exact repository root."""
    expanded = path.expanduser().absolute()
    if expanded.is_symlink():
        raise RehearsalError("AC-29 output directory must not be a symbolic link")
    resolved = expanded.resolve()
    repository = repository.resolve()
    if resolved == repository or _inside(resolved, repository):
        raise RehearsalError("AC-29 output directory must be outside the Git working tree")
    if expanded.exists():
        if not expanded.is_dir():
            raise RehearsalError("AC-29 output path is not a directory")
        if any(expanded.iterdir()):
            raise RehearsalError("AC-29 output directory must be empty")
        if stat.S_IMODE(expanded.stat().st_mode) != 0o700:
            raise RehearsalError("AC-29 output directory mode must be exactly 0700")
    else:
        expanded.mkdir(mode=0o700, parents=True)
    if stat.S_IMODE(expanded.stat().st_mode) != 0o700:
        raise RehearsalError("AC-29 output directory mode must be exactly 0700")
    return resolved


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


def _run_quiet(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    options: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "check": False,
        **kwargs,
    }
    if "input" not in options:
        options["stdin"] = subprocess.DEVNULL
    try:
        return subprocess.run(list(command), **options)
    except OSError as exception:
        raise RehearsalError("Required local executable could not be started") from exception


def _git(repository: Path, *arguments: str) -> bytes:
    completed = _run_quiet(
        [
            "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-C", str(repository), *arguments,
        ],
        env=_git_environment(),
    )
    if completed.returncode != 0:
        raise RehearsalError(f"Git candidate query failed: {arguments[0]}")
    return completed.stdout


def _git_id(repository: Path, expression: str, label: str) -> str:
    try:
        value = _git(repository, "rev-parse", "--verify", expression).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise RehearsalError(f"Git returned a non-ASCII {label}") from exception
    if GIT_OBJECT.fullmatch(value) is None:
        raise RehearsalError(f"Git returned a malformed {label}")
    return value


def _exact_repository_root(repository: Path) -> Path:
    expanded = repository.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise RehearsalError("Repository root must be a real directory")
    resolved = expanded.resolve()
    try:
        top = Path(_git(resolved, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    except UnicodeDecodeError as exception:
        raise RehearsalError("Git repository root is not UTF-8") from exception
    if top != resolved:
        raise RehearsalError("Repository root must be the exact Git worktree top level")
    return resolved


def _require_clean_candidate(repository: Path) -> None:
    tracked = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if not tracked or any(not record.startswith(b"H ") for record in tracked):
        raise RehearsalError(
            "AC-29 rejects skip-worktree, assume-unchanged, or non-normal Git entries"
        )
    if _git(
        repository, "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise RehearsalError("Formal AC-29 evidence requires a clean Git candidate")


def _committed_blob(repository: Path, head: str, relative: str) -> bytes:
    relative_path = Path(relative)
    if relative_path.is_absolute() or not relative_path.parts or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise RehearsalError("AC-29 source path is unsafe")
    workspace = repository.joinpath(*relative_path.parts)
    try:
        metadata = workspace.lstat()
        resolved = workspace.resolve(strict=True)
    except OSError as exception:
        raise RehearsalError(f"AC-29 candidate source is missing: {relative}") from exception
    if not stat.S_ISREG(metadata.st_mode) or workspace.is_symlink() or not _inside(resolved, repository):
        raise RehearsalError(f"AC-29 candidate source is unsafe: {relative}")
    records = [
        record for record in _git(repository, "ls-tree", "-z", head, "--", relative).split(b"\0")
        if record
    ]
    if len(records) != 1:
        raise RehearsalError(f"AC-29 candidate commit does not contain: {relative}")
    metadata_raw, separator, encoded_path = records[0].partition(b"\t")
    fields = metadata_raw.split()
    if (
        not separator
        or encoded_path.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise RehearsalError(f"AC-29 candidate source is not a regular Git blob: {relative}")
    committed = _git(repository, "show", f"{head}:{relative}")
    if committed != workspace.read_bytes():
        raise RehearsalError(f"AC-29 workspace source differs from candidate: {relative}")
    return committed


def _release_version(root_pom: bytes, admin_pom: bytes, frontend_manifest: bytes) -> str:
    try:
        root = ElementTree.fromstring(root_pom)
        admin = ElementTree.fromstring(admin_pom)
        package = json.loads(frontend_manifest.decode("utf-8"))
    except (ElementTree.ParseError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RehearsalError("Cannot read Maven/frontend release versions") from exception
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    node = root.find("m:version", namespace)
    admin_node = admin.find("m:parent/m:version", namespace)
    maven = node.text.strip() if node is not None and node.text else ""
    admin_version = (
        admin_node.text.strip() if admin_node is not None and admin_node.text else ""
    )
    frontend = package.get("version") if isinstance(package, dict) else None
    if (
        not isinstance(frontend, str)
        or VERSION.fullmatch(maven) is None
        or VERSION.fullmatch(frontend) is None
        or "SNAPSHOT" in maven.upper()
        or "SNAPSHOT" in frontend.upper()
        or maven != admin_version
        or maven != frontend
    ):
        raise RehearsalError(
            "Formal AC-29 evidence requires equal non-SNAPSHOT root/admin/frontend versions"
        )
    return maven


def capture_candidate(repository_root: Path = REPO_ROOT) -> CandidateIdentity:
    repository = _exact_repository_root(repository_root)
    _require_clean_candidate(repository)
    head = _git_id(repository, "HEAD^{commit}", "HEAD commit")
    tree = _git_id(repository, "HEAD^{tree}", "HEAD tree")
    blobs = {relative: _committed_blob(repository, head, relative) for relative in SOURCE_PATHS}
    version = _release_version(
        blobs[ROOT_POM_PATH], blobs[ADMIN_POM_PATH], blobs[FRONTEND_MANIFEST_PATH]
    )
    tag = f"v{version}"
    tag_ref = f"refs/tags/{tag}"
    try:
        tag_type = _git(repository, "cat-file", "-t", tag_ref).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise RehearsalError("Release tag type is not ASCII") from exception
    if tag_type != "tag":
        raise RehearsalError("Formal AC-29 evidence requires the annotated semantic release tag")
    tag_object = _git_id(repository, tag_ref, "annotated tag object")
    if _git_id(repository, f"{tag_ref}^{{commit}}", "tag commit") != head:
        raise RehearsalError("Release tag and HEAD do not identify the same candidate")
    _require_clean_candidate(repository)
    if (
        _git_id(repository, "HEAD^{commit}", "final HEAD commit") != head
        or _git_id(repository, "HEAD^{tree}", "final HEAD tree") != tree
        or _git_id(repository, tag_ref, "final annotated tag object") != tag_object
    ):
        raise RehearsalError("Git candidate changed while its identity was captured")
    return CandidateIdentity(
        head=head,
        tree=tree,
        tag=tag,
        tag_object=tag_object,
        version=version,
        source_sha256={relative: _sha256_bytes(content) for relative, content in blobs.items()},
    )


def validate_image_reference(reference: str) -> tuple[str, str]:
    if reference != reference.strip() or "://" in reference or ".." in reference or reference.count("@") != 1:
        raise RehearsalError("App image must be a safe caller-supplied digest reference")
    match = DIGEST_REFERENCE.fullmatch(reference)
    if match is None:
        raise RehearsalError("App image must be a caller-supplied repository@sha256 reference")
    return reference, match.group("digest")


def inspect_local_app_image(
    reference: str,
    candidate: CandidateIdentity,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] = _run_quiet,
) -> ImageIdentity:
    """Bind a digest reference and OCI metadata to one immutable local image ID."""
    validated, digest = validate_image_reference(reference)
    completed = run_command(["docker", "image", "inspect", validated])
    if completed.returncode != 0:
        raise RehearsalError("Explicit digest-bound App image is not in the local image store")
    try:
        documents = json.loads(completed.stdout)
        document = documents[0]
        image_id = document["Id"]
        config = document["Config"]
        labels = config.get("Labels") or {}
        env_items = config.get("Env") or []
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exception:
        raise RehearsalError("Docker returned malformed App image metadata") from exception
    if len(documents) != 1 or not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
        raise RehearsalError("Docker did not resolve exactly one immutable App image ID")
    repo_digests = document.get("RepoDigests") or []
    if validated not in repo_digests:
        raise RehearsalError("Local image metadata is not bound to the requested manifest digest")
    if not isinstance(labels, dict) or (
        labels.get("org.opencontainers.image.version") != candidate.version
        or labels.get("org.opencontainers.image.revision") != candidate.head
    ):
        raise RehearsalError("App OCI version/revision do not match the Git candidate")
    entrypoint = config.get("Entrypoint")
    user = str(config.get("User") or "").strip().lower()
    if (
        not isinstance(entrypoint, list)
        or not entrypoint
        or not all(isinstance(item, str) for item in entrypoint)
        or "java" not in Path(entrypoint[0]).name
        or "/app/app.jar" not in entrypoint
        or config.get("WorkingDir") != "/app"
        or user in {"", "0", "0:0", "root", "root:root"}
    ):
        raise RehearsalError("Docker target does not retain the non-root Web Starter App contract")
    if not isinstance(env_items, list) or not all(isinstance(item, str) for item in env_items):
        raise RehearsalError("App image environment metadata is malformed")
    java_home = next((item.split("=", 1)[1] for item in env_items if item.startswith("JAVA_HOME=")), "")
    if SAFE_JAVA_HOME.fullmatch(java_home) is None:
        raise RehearsalError("App image does not declare a safe absolute JAVA_HOME")
    operating_system = document.get("Os")
    architecture = document.get("Architecture")
    if operating_system != "linux" or architecture not in {"amd64", "arm64"}:
        raise RehearsalError("App image must be a supported Linux runtime image")
    return ImageIdentity(
        reference=validated,
        image_id=image_id,
        digest=digest,
        oci_version=candidate.version,
        oci_revision=candidate.head,
        operating_system=operating_system,
        architecture=architecture,
        java_home=java_home,
    )


def generate_rsa_material(openssl: str) -> tuple[str, str]:
    """Generate a 3072-bit PKCS#8/X.509 pair entirely through memory pipes."""
    generated = _run_quiet([
        openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
    ])
    if generated.returncode != 0 or not generated.stdout:
        raise RehearsalError("OpenSSL could not generate in-memory 3072-bit RSA material")
    private_der = _run_quiet([
        openssl, "pkcs8", "-topk8", "-nocrypt", "-outform", "DER",
    ], input=generated.stdout)
    public_der = _run_quiet([
        openssl, "pkey", "-pubout", "-outform", "DER",
    ], input=generated.stdout)
    if private_der.returncode != 0 or public_der.returncode != 0:
        raise RehearsalError("OpenSSL could not encode temporary RSA material")
    return (
        base64.b64encode(private_der.stdout).decode("ascii"),
        base64.b64encode(public_der.stdout).decode("ascii"),
    )


def hardened_environment(
        private_key: str, public_key: str, marker: str, git_commit: str) -> dict[str, str]:
    if GIT_OBJECT.fullmatch(git_commit) is None:
        raise RehearsalError("AC-29 requires an exact candidate Git commit")
    return {
        "WEB_STARTER_RUNTIME_MODE": "production",
        "WEB_STARTER_GIT_COMMIT": git_commit,
        "WEB_STARTER_OAUTH_ISSUER": "https://auth.ac29.example.invalid",
        "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": "https://mcp.ac29.example.invalid/mcp",
        "WEB_STARTER_COOKIE_SECURE": "true",
        "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "false",
        "WEB_STARTER_DB_URL": (
            "jdbc:mysql://192.0.2.1:3306/web_starter_ac29"
            "?connectTimeout=1000&socketTimeout=1000&useSSL=false&allowPublicKeyRetrieval=true"
        ),
        "WEB_STARTER_DB_USERNAME": "web_starter_ac29",
        "WEB_STARTER_DB_PASSWORD": f"Ac29Db_{marker}_password_0123456789abcdef",
        "WEB_STARTER_DB_CONNECTION_TIMEOUT_MS": "1000",
        "WEB_STARTER_DB_VALIDATION_TIMEOUT_MS": "1000",
        "WEB_STARTER_REDIS_HOST": "192.0.2.2",
        "WEB_STARTER_REDIS_PASSWORD": f"Ac29Redis_{marker}_pass",
        "WEB_STARTER_TOKEN_PEPPER": f"Ac29TokenPepper_{marker}_0123456789abcdef",
        "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": "",
        "WEB_STARTER_MANAGEMENT_USERNAME": f"ac29_ops_{marker}",
        "WEB_STARTER_MANAGEMENT_PASSWORD": f"Ac29Ops_{marker}_0123456789abcdef",
        "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": private_key,
        "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": public_key,
        "WEB_STARTER_OAUTH_RSA_JWK_SET": "",
        "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": "",
        "WEB_STARTER_MCP_ALLOWED_HOSTS": "mcp.ac29.example.invalid:443",
        "WEB_STARTER_MCP_ALLOWED_ORIGINS": "https://agent.ac29.example.invalid",
        "LOGGING_LEVEL_ROOT": "INFO",
        "LOGGING_LEVEL_DEV_WEBSTARTER": "INFO",
    }


def dangerous_cases(base: Mapping[str, str], marker: str) -> tuple[DangerousCase, ...]:
    exact = lambda message: UNSAFE_PREFIX + message
    return (
        DangerousCase("http-issuer", {"WEB_STARTER_OAUTH_ISSUER": f"http://auth-{marker}.example.invalid"}, exact("WEB_STARTER_OAUTH_ISSUER must be a non-local absolute HTTPS URI")),
        DangerousCase("localhost-issuer", {"WEB_STARTER_OAUTH_ISSUER": "https://localhost:8443"}, exact("WEB_STARTER_OAUTH_ISSUER must be a non-local absolute HTTPS URI")),
        DangerousCase("http-audience", {"WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": f"http://mcp-{marker}.example.invalid/mcp"}, exact("WEB_STARTER_OAUTH_RESOURCE_AUDIENCE must be a non-local absolute HTTPS URI")),
        DangerousCase("insecure-cookie", {"WEB_STARTER_COOKIE_SECURE": "false"}, exact("WEB_STARTER_COOKIE_SECURE must be true in production")),
        DangerousCase("development-rsa", {"WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "true"}, exact("WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED must be false in production")),
        DangerousCase("empty-secret", {"WEB_STARTER_REDIS_PASSWORD": ""}, exact("WEB_STARTER_REDIS_PASSWORD must not be empty in production")),
        DangerousCase("placeholder-secret", {"WEB_STARTER_TOKEN_PEPPER": f"replace-with-ac29-fixture-{marker}"}, exact("WEB_STARTER_TOKEN_PEPPER contains a weak or placeholder value")),
        DangerousCase("missing-rsa", {"WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": "", "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": ""}, exact("production requires an injected RSA JWK set or private/public PEM pair")),
        DangerousCase("broad-host", {"WEB_STARTER_MCP_ALLOWED_HOSTS": "*.ac29.example.invalid"}, exact("WEB_STARTER_MCP_ALLOWED_HOSTS must contain exact non-local hosts")),
        DangerousCase("local-host", {"WEB_STARTER_MCP_ALLOWED_HOSTS": "localhost:8443"}, exact("WEB_STARTER_MCP_ALLOWED_HOSTS must contain exact non-local hosts")),
        DangerousCase("broad-origin", {"WEB_STARTER_MCP_ALLOWED_ORIGINS": "https://*.ac29.example.invalid"}, exact("WEB_STARTER_MCP_ALLOWED_ORIGINS must contain exact non-local HTTPS origins")),
        DangerousCase("http-origin", {"WEB_STARTER_MCP_ALLOWED_ORIGINS": f"http://agent-{marker}.example.invalid"}, exact("WEB_STARTER_MCP_ALLOWED_ORIGINS must contain exact non-local HTTPS origins")),
        DangerousCase("dangerous-log-level", {"LOGGING_LEVEL_DEV_WEBSTARTER": "DEBUG"}, exact("production logging level must not be ALL, TRACE, or DEBUG")),
        DangerousCase("management-username-reuse", {"WEB_STARTER_MANAGEMENT_USERNAME": "admin"}, exact("WEB_STARTER_MANAGEMENT_USERNAME must differ from the Web bootstrap administrator")),
        DangerousCase("management-password-reuse", {"WEB_STARTER_MANAGEMENT_PASSWORD": base["WEB_STARTER_DB_PASSWORD"]}, exact("WEB_STARTER_MANAGEMENT_PASSWORD must not reuse another application secret")),
    )


def validate_container_identity(name: str, run_id: str) -> None:
    if CONTAINER_NAME.fullmatch(name) is None or RUN_ID.fullmatch(run_id) is None or not name.endswith(run_id):
        raise RehearsalError("Refusing an unsafe AC-29 Docker container target")


def docker_command(
    name: str,
    run_id: str,
    image_id: str,
    environment: Mapping[str, str],
    *,
    entrypoint: str | None = None,
    arguments: Sequence[str] = (),
) -> list[str]:
    validate_container_identity(name, run_id)
    if IMAGE_ID.fullmatch(image_id) is None:
        raise RehearsalError("Refusing a mutable or malformed App image target")
    command = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--name", name,
        "--label", f"{LABEL_OWNER}=ac29",
        "--label", f"{LABEL_RUN}={run_id}",
        "--log-driver", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "1g", "--cpus", "1.5",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
    ]
    for key in sorted(environment):
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key) is None:
            raise RehearsalError("Refusing an unsafe environment variable name")
        command.extend(("--env", key))
    if entrypoint is not None:
        if re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", entrypoint) is None:
            raise RehearsalError("Refusing an unsafe entrypoint override")
        command.extend(("--entrypoint", entrypoint))
    command.append(image_id)
    command.extend(arguments)
    return command


def _container_names(name: str, run_command: Callable[..., subprocess.CompletedProcess[bytes]]) -> tuple[str, ...]:
    completed = run_command([
        "docker", "container", "ls", "--all", "--filter", f"name=^/{name}$", "--format", "{{.Names}}",
    ])
    if completed.returncode != 0:
        raise RehearsalError("Could not establish the AC-29 container cleanup state")
    try:
        names = tuple(line for line in completed.stdout.decode("utf-8").splitlines() if line)
    except UnicodeDecodeError as exception:
        raise RehearsalError("Docker returned malformed container names") from exception
    if any(item != name for item in names) or len(names) > 1:
        raise RehearsalError("Docker returned an ambiguous AC-29 container target")
    return names


def cleanup_owned_container(
    name: str,
    run_id: str,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] = _run_quiet,
) -> CleanupResult:
    """Remove only the exact container carrying both AC-29 ownership labels."""
    validate_container_identity(name, run_id)
    if not _container_names(name, run_command):
        return CleanupResult(True, False, False, False)
    inspected = run_command([
        "docker", "container", "inspect", "--format",
        "{{.Id}}\n{{.Name}}\n{{json .Config.Labels}}", name,
    ])
    if inspected.returncode != 0:
        raise RehearsalError("Could not verify AC-29 container ownership")
    try:
        lines = inspected.stdout.decode("utf-8").splitlines()
        container_id, docker_name = lines[0], lines[1]
        labels = json.loads(lines[2])
    except (IndexError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RehearsalError("Refusing malformed AC-29 ownership metadata") from exception
    if (
        len(lines) != 3
        or CONTAINER_ID.fullmatch(container_id) is None
        or docker_name != f"/{name}"
        or not isinstance(labels, dict)
        or labels.get(LABEL_OWNER) != "ac29"
        or labels.get(LABEL_RUN) != run_id
    ):
        raise RehearsalError("Refusing to clean a container not owned by this AC-29 run")
    removed = run_command(["docker", "container", "rm", "--force", container_id])
    if removed.returncode != 0:
        raise RehearsalError("Could not remove the owned AC-29 container")
    residual = bool(_container_names(name, run_command))
    if residual:
        raise RehearsalError("Owned AC-29 container remains after cleanup")
    return CleanupResult(False, True, True, False)


def run_container(
    name: str,
    run_id: str,
    image_id: str,
    environment: Mapping[str, str],
    timeout_seconds: int,
    *,
    entrypoint: str | None = None,
    arguments: Sequence[str] = (),
) -> ContainerResult:
    command = docker_command(
        name, run_id, image_id, environment, entrypoint=entrypoint, arguments=arguments
    )
    child_environment = os.environ.copy()
    child_environment.update(environment)
    try:
        completed = subprocess.run(
            command,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode < 0 or completed.returncode > 255:
            raise RehearsalError("Docker returned an invalid process exit status")
        result = ContainerResult(completed.returncode, completed.stdout)
    except subprocess.TimeoutExpired as exception:
        raw = exception.output if isinstance(exception.output, bytes) else b""
        result = ContainerResult(124, raw, timed_out=True)
    except OSError as exception:
        raise RehearsalError("Docker could not start the isolated AC-29 container") from exception
    finally:
        cleanup = cleanup_owned_container(name, run_id)
    return ContainerResult(
        result.exit_code,
        result.output,
        result.timed_out,
        _canonical_sha256(command),
        cleanup,
    )


def ensure_no_fixture_literals(output: bytes, fixture_literals: Sequence[str]) -> None:
    for literal in fixture_literals:
        if literal and literal.encode("utf-8") in output:
            raise RehearsalError("Application output exposed generated AC-29 fixture material")


def _marker_counts(text: str, markers: Mapping[str, str]) -> dict[str, int]:
    normalized = text.lower()
    return {key: normalized.count(marker.lower()) for key, marker in markers.items()}


def _semantic_rejection(text: str, expected: str) -> tuple[int, int]:
    """Count structured rejection events without recounting their stack traces."""
    events = 0
    first_offset = -1
    offset = 0
    structured_log_seen = False
    for line in text.splitlines(keepends=True):
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            offset += len(line)
            continue
        if not isinstance(document, dict):
            offset += len(line)
            continue
        structured_log_seen = True
        error = document.get("error")
        error_message = error.get("message") if isinstance(error, dict) else None
        if document.get("message") == expected or error_message == expected:
            events += 1
            if first_offset < 0:
                position = line.find(expected)
                first_offset = offset + (position if position >= 0 else 0)
        offset += len(line)
    if structured_log_seen:
        return events, first_offset
    return text.count(expected), text.find(expected)


def evaluate_dangerous_case(case: DangerousCase, result: ContainerResult) -> tuple[bool, tuple[str, ...]]:
    text = result.output.decode("utf-8", errors="replace")
    failures: list[str] = []
    rejection_count, rejection_position = _semantic_rejection(text, case.expected_rejection)
    if result.timed_out:
        failures.append("timedOut")
    if result.exit_code == 0:
        failures.append("zeroExit")
    if rejection_count != 1:
        failures.append("exactRejectionCountMismatch")
    before = text[:rejection_position] if rejection_position >= 0 else ""
    if any(_marker_counts(before, EARLY_MARKERS).values()):
        failures.append("infrastructureStartedBeforeRejection")
    return not failures, tuple(failures)


def evaluate_hardened_control(result: ContainerResult) -> tuple[bool, tuple[str, ...]]:
    text = result.output.decode("utf-8", errors="replace")
    failures: list[str] = []
    if result.timed_out:
        failures.append("timedOut")
    if result.exit_code == 0:
        failures.append("unexpectedStartup")
    if text.count(UNSAFE_PREFIX) != 0:
        failures.append("securityValidationRejectedControl")
    marker_counts = _marker_counts(text, DATABASE_MARKERS)
    if not any(marker_counts[key] for key in DATABASE_FAILURE_MARKER_KEYS):
        failures.append("databaseFailureMissing")
    return not failures, tuple(failures)


def _case_evidence(case: DangerousCase, result: ContainerResult) -> dict[str, object]:
    text = result.output.decode("utf-8", errors="replace")
    rejection_count, rejection_position = _semantic_rejection(text, case.expected_rejection)
    before = text[:rejection_position] if rejection_position >= 0 else ""
    marker_counts = _marker_counts(before, EARLY_MARKERS)
    passed, failures = evaluate_dangerous_case(case, result)
    return {
        "case": case.case_id,
        "changedKeys": sorted(case.overrides),
        "status": "PASS" if passed else "FAIL",
        "exitCode": result.exit_code,
        "timedOut": result.timed_out,
        "logBytes": len(result.output),
        "logSha256": _sha256_bytes(result.output),
        "commandSha256": result.command_sha256,
        "expectedRejectionSha256": _sha256_bytes(case.expected_rejection.encode("utf-8")),
        "exactRejectionCount": rejection_count,
        "rejectionOffset": rejection_position,
        "infrastructureMarkersBeforeRejection": marker_counts,
        "checks": {
            "nonZeroExit": result.exit_code != 0,
            "completedBeforeTimeout": not result.timed_out,
            "exactRejectionObservedOnce": rejection_count == 1,
            "noInfrastructureBeforeRejection": not any(marker_counts.values()),
        },
        "failures": list(failures),
    }


def _control_evidence(result: ContainerResult) -> dict[str, object]:
    text = result.output.decode("utf-8", errors="replace")
    markers = _marker_counts(text, DATABASE_MARKERS)
    passed, failures = evaluate_hardened_control(result)
    return {
        "case": "hardened-networkless-control",
        "status": "PASS" if passed else "FAIL",
        "exitCode": result.exit_code,
        "timedOut": result.timed_out,
        "logBytes": len(result.output),
        "logSha256": _sha256_bytes(result.output),
        "commandSha256": result.command_sha256,
        "unsafeRejectionCount": text.count(UNSAFE_PREFIX),
        "databaseMarkers": markers,
        "checks": {
            "nonZeroExit": result.exit_code != 0,
            "completedBeforeTimeout": not result.timed_out,
            "securityValidationPassed": text.count(UNSAFE_PREFIX) == 0,
            "databaseFailureObserved": any(
                markers[key] for key in DATABASE_FAILURE_MARKER_KEYS
            ),
        },
        "failures": list(failures),
    }


def _java_evidence(result: ContainerResult, image_id: str) -> dict[str, object]:
    text = result.output.decode("utf-8", errors="replace")
    def property_value(name: str) -> str:
        match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*(.+?)\s*$", text)
        return match.group(1) if match else ""
    specification = property_value("java.specification.version")
    runtime = property_value("java.runtime.version")
    vendor = property_value("java.vendor")
    safe_values = all(
        SAFE_RUNTIME_VALUE.fullmatch(value) is not None for value in (specification, runtime, vendor)
    )
    runtime_is_21 = re.match(r"^21(?:[.+_-]|$)", runtime) is not None
    passed = (
        result.exit_code == 0
        and not result.timed_out
        and specification == "21"
        and runtime_is_21
        and safe_values
    )
    failures: list[str] = []
    if result.exit_code != 0:
        failures.append("nonZeroExit")
    if result.timed_out:
        failures.append("timedOut")
    if specification != "21":
        failures.append("notJava21")
    if not runtime_is_21:
        failures.append("runtimeVersionNot21")
    if not safe_values:
        failures.append("runtimeIdentityMissingOrUnsafe")
    return {
        "status": "PASS" if passed else "FAIL",
        "imageId": image_id,
        "exitCode": result.exit_code,
        "timedOut": result.timed_out,
        "logBytes": len(result.output),
        "logSha256": _sha256_bytes(result.output),
        "commandSha256": result.command_sha256,
        "specificationVersion": specification,
        "runtimeVersion": runtime,
        "vendor": vendor,
        "checks": {
            "exitZero": result.exit_code == 0,
            "completedBeforeTimeout": not result.timed_out,
            "specificationIs21": specification == "21",
            "runtimeVersionIs21": runtime_is_21,
            "identityValuesSanitized": safe_values,
        },
        "failures": failures,
    }


def _fixture_literals(environments: Sequence[Mapping[str, str]], marker: str) -> tuple[str, ...]:
    literals: set[str] = set()
    sensitive_fragments = ("PASSWORD", "PEPPER", "RSA", "TOKEN", "SECRET", "JWK")
    for environment in environments:
        for key, value in environment.items():
            if value and (marker in value or any(fragment in key for fragment in sensitive_fragments)):
                literals.add(value)
    return tuple(sorted(literals, key=len, reverse=True))


def _cleanup_evidence(results: Sequence[ContainerResult]) -> dict[str, object]:
    cleanups = [result.cleanup for result in results]
    if any(cleanup is None for cleanup in cleanups):
        raise RehearsalError("AC-29 cleanup accounting is incomplete")
    concrete = [cleanup for cleanup in cleanups if cleanup is not None]
    already_absent = sum(cleanup.already_absent for cleanup in concrete)
    removed = sum(cleanup.removed for cleanup in concrete)
    residual = sum(cleanup.residual for cleanup in concrete)
    labels_verified = sum(cleanup.labels_verified for cleanup in concrete)
    complete = len(concrete) == 17 and already_absent + removed == 17 and residual == 0
    return {
        "expectedTargets": 17,
        "cleanupCalls": len(concrete),
        "alreadyAbsentAfterAutoRemove": already_absent,
        "ownedContainersRemoved": removed,
        "ownershipLabelsVerifiedBeforeRemoval": labels_verified,
        "unownedRemovalAttempts": 0,
        "residualContainers": residual,
        "complete": complete,
    }


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def write_evidence(output: Path, report: Mapping[str, object]) -> tuple[Path, str]:
    if any(output.iterdir()):
        raise RehearsalError("AC-29 output directory changed before evidence write")
    document = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    result_path = output / RESULT_NAME
    _write_private(result_path, document)
    digest = _sha256_bytes(document)
    _write_private(output / CHECKSUM_NAME, f"{digest}  {RESULT_NAME}\n".encode("ascii"))
    names = {item.name for item in output.iterdir()}
    if names != {RESULT_NAME, CHECKSUM_NAME} or any(
        item.is_symlink() or stat.S_IMODE(item.stat().st_mode) != 0o600 for item in output.iterdir()
    ):
        raise RehearsalError("AC-29 evidence directory does not contain exactly two 0600 files")
    return result_path, digest


def rehearse(
    image_reference: str,
    output_directory: Path,
    timeout_seconds: int,
    repository_root: Path = REPO_ROOT,
) -> tuple[dict[str, object], str]:
    if timeout_seconds < 10 or timeout_seconds > 180:
        raise RehearsalError("Per-container timeout must be between 10 and 180 seconds")
    if shutil.which("docker") is None or shutil.which("openssl") is None or shutil.which("git") is None:
        raise RehearsalError("Docker, OpenSSL, and Git are required for AC-29 rehearsal")
    repository = _exact_repository_root(repository_root)
    candidate = capture_candidate(repository)
    output = ensure_external_output_directory(output_directory, repository)
    image = inspect_local_app_image(image_reference, candidate)
    run_id = secrets.token_hex(6)
    marker = secrets.token_hex(8)

    with tempfile.TemporaryDirectory(prefix="web-starter-ac29-") as temporary_name:
        temporary = Path(temporary_name)
        temporary.chmod(0o700)
        private_key, public_key = generate_rsa_material("openssl")
        base = hardened_environment(private_key, public_key, marker, candidate.head)
        cases = dangerous_cases(base, marker)
        environments = [{**base, **case.overrides} for case in cases] + [base]
        literals = _fixture_literals(environments, marker)
        results: list[ContainerResult] = []
        evidence: list[dict[str, object]] = []

        for index, (case, environment) in enumerate(zip(cases, environments), start=1):
            name = f"web-starter-ac29-{index:02d}-{run_id}"
            result = run_container(name, run_id, image.image_id, environment, timeout_seconds)
            results.append(result)
            ensure_no_fixture_literals(result.output, literals)
            evidence.append(_case_evidence(case, result))

        java_result = run_container(
            f"web-starter-ac29-java-{run_id}", run_id, image.image_id, {}, timeout_seconds,
            entrypoint="java", arguments=("-XshowSettings:properties", "-version"),
        )
        results.append(java_result)
        java_evidence = _java_evidence(java_result, image.image_id)

        control = run_container(
            f"web-starter-ac29-control-{run_id}", run_id, image.image_id, base, timeout_seconds
        )
        results.append(control)
        ensure_no_fixture_literals(control.output, literals)
        control_evidence = _control_evidence(control)
        cleanup_evidence = _cleanup_evidence(results)

        candidate_after = capture_candidate(repository)
        if candidate_after != candidate:
            raise RehearsalError("Git candidate changed during AC-29 execution")
        image_after = inspect_local_app_image(image_reference, candidate_after)
        if image_after != image:
            raise RehearsalError("App image identity changed during AC-29 execution")

        passed = (
            len(evidence) == 15
            and all(item["status"] == "PASS" for item in evidence)
            and control_evidence["status"] == "PASS"
            and java_evidence["status"] == "PASS"
            and cleanup_evidence["complete"] is True
        )
        report: dict[str, object] = {
            "schemaVersion": 2,
            "acceptanceId": "V2-AC-29",
            "status": "PASS" if passed else "FAIL",
            "generatedAt": utc_now(),
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
            "image": {
                "requestedReference": image.reference,
                "id": image.image_id,
                "manifestDigest": image.digest,
                "ociVersion": image.oci_version,
                "ociRevision": image.oci_revision,
                "operatingSystem": image.operating_system,
                "architecture": image.architecture,
                "javaHome": image.java_home,
            },
            "javaRuntime": java_evidence,
            "execution": {
                "runId": run_id,
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
                "cleanup": cleanup_evidence,
            },
            "rsa": {"generatedBits": 3072, "persisted": False},
            "dangerousCases": evidence,
            "hardenedControl": control_evidence,
            "evidencePolicy": {
                "outsideRepository": True,
                "directoryMode": "0700",
                "fileMode": "0600",
                "onlyReportAndChecksum": True,
                "rawLogsPersisted": False,
                "fixtureMaterialPersisted": False,
            },
        }
        _, digest = write_evidence(output, report)
        return report, digest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Produce candidate-bound V2-AC-29 fail-fast evidence"
    )
    parser.add_argument(
        "--image", required=True,
        help="caller-supplied local App repository@sha256 reference",
    )
    parser.add_argument(
        "--output-dir", required=True, type=Path,
        help="new or empty 0700 directory outside the Git working tree",
    )
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, digest = rehearse(
            args.image, args.output_dir, args.timeout_seconds, args.repository_root
        )
    except RehearsalError as exception:
        print(f"AC-29 rehearsal failed safely: {exception}", file=sys.stderr)
        return 2
    print(json.dumps({
        "acceptanceId": "V2-AC-29",
        "status": report["status"],
        "evidence": RESULT_NAME,
        "sha256": digest,
    }, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
