#!/usr/bin/env python3
"""Rehearse the fail-closed portion of V2-AC-07 with isolated Docker resources.

The rehearsal resolves three explicit local image references to immutable image
IDs, creates one private Docker network and three short-lived containers, and
mounts an additional failing Flyway migration read-only into the application.
No host ports, Docker volumes, existing Compose projects, or external networks
are used. Raw logs and generated secrets remain in memory and are discarded
after their SHA-256 digests and non-secret observations are recorded.
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
import time
from typing import Callable, Mapping, Sequence
import xml.etree.ElementTree as ElementTree

import validate_v1_upgrade_evidence as ac40_validator


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "security" / "v2-ac07-migration-failure.schema.json"
AC40_VALIDATOR_PATH = REPO_ROOT / "scripts" / "validate_v1_upgrade_evidence.py"
RESULT_NAME = "v2-ac07-migration-failure.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"
IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_BOUND_REFERENCE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,181}@(?P<digest>sha256:[0-9a-f]{64})$"
)
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
RELEASE_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
NETWORK_NAME = re.compile(r"^web-starter-ac07-[0-9a-f]{12}$")
CONTAINER_NAME = re.compile(
    r"^web-starter-ac07-(?:mysql|redis|app)-[0-9a-f]{12}$"
)
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

LABEL_OWNER = "dev.webstarter.acceptance"
LABEL_RUN = "dev.webstarter.acceptance.run"
LABEL_ROLE = "dev.webstarter.acceptance.role"
OWNER_VALUE = "ac07"
ACCEPTANCE_STATUSES = frozenset({"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"})
MIGRATION_VERSION = "999999"
MIGRATION_FILE = f"V{MIGRATION_VERSION}__ac07_intentional_failure.sql"
MIGRATION_TARGET = "/ac07-migration"
READINESS_URL = "http://127.0.0.1:8081/actuator/health/readiness"
CANDIDATE_SOURCE_PATHS = (
    "scripts/rehearse_migration_failure.py",
    "security/v2-ac07-migration-failure.schema.json",
    "scripts/validate_v1_upgrade_evidence.py",
)
OCI_VERSION_LABEL = "org.opencontainers.image.version"
OCI_REVISION_LABEL = "org.opencontainers.image.revision"


class RehearsalError(RuntimeError):
    """A non-secret-bearing AC-07 orchestration failure."""


@dataclass(frozen=True)
class ResolvedImages:
    app: str
    mysql: str
    redis: str


@dataclass(frozen=True)
class CandidateIdentity:
    head: str
    tree: str
    version: str
    source_sha256: dict[str, str]


@dataclass(frozen=True)
class ImageInspection:
    image_id: str
    requested_reference_sha256: str
    requested_digest: str | None
    oci_version: str | None
    oci_revision: str | None


@dataclass(frozen=True)
class ResourceNames:
    run_id: str
    network: str
    mysql: str
    redis: str
    app: str


@dataclass(frozen=True)
class AppRuntime:
    exit_code: int
    timed_out: bool
    readiness_attempts: int
    readiness_successes: int


@dataclass(frozen=True)
class FlywayState:
    successful_base_rows: int
    successful_failure_version_rows: int
    unsuccessful_failure_version_rows: int
    total_failure_version_rows: int
    latest_successful_version: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def ensure_external_output_directory(path: Path) -> Path:
    """Create or accept an empty private evidence directory outside the repository."""
    expanded = path.expanduser().absolute()
    if expanded.is_symlink():
        raise RehearsalError("AC-07 output directory must not be a symbolic link")
    resolved = expanded.resolve()
    repository = REPO_ROOT.resolve()
    if resolved == repository or _inside(resolved, repository):
        raise RehearsalError("AC-07 output directory must be outside the Git working tree")
    if expanded.exists():
        if not expanded.is_dir():
            raise RehearsalError("AC-07 output path is not a directory")
        if any(expanded.iterdir()):
            raise RehearsalError("AC-07 output directory must be empty")
        if stat.S_IMODE(expanded.stat().st_mode) & 0o077:
            raise RehearsalError(
                "AC-07 output directory must not be accessible by group or other"
            )
    else:
        expanded.mkdir(mode=0o700, parents=True)
    return resolved


def validate_image_reference(reference: str, role: str) -> str:
    candidate = reference.strip()
    if role not in {"App", "MySQL", "Redis"}:
        raise RehearsalError("Unknown image role")
    if (
        not candidate
        or candidate != reference
        or not IMAGE_REFERENCE.fullmatch(candidate)
        or "://" in candidate
        or ".." in candidate
        or candidate.startswith("-")
    ):
        raise RehearsalError(f"{role} image reference contains unsafe characters")
    if role == "App" and DIGEST_BOUND_REFERENCE.fullmatch(candidate) is None:
        raise RehearsalError("App image reference must be repository@sha256 digest-bound")
    return candidate


def _run_quiet(
    command: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    child_environment = os.environ.copy()
    if environment:
        child_environment.update(environment)
    try:
        return subprocess.run(
            list(command),
            env=child_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exception:
        raise RehearsalError("A local Docker operation exceeded its bounded timeout") from exception
    except OSError as exception:
        raise RehearsalError("A required local executable could not be started") from exception


def _image_command_text(config: Mapping[str, object]) -> str:
    values: list[str] = []
    for field in ("Entrypoint", "Cmd"):
        raw = config.get(field)
        if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            values.extend(raw)
    return " ".join(values).lower()


def inspect_local_image(
    reference: str,
    role: str,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] = _run_quiet,
    *,
    candidate_version: str | None = None,
    candidate_revision: str | None = None,
) -> ImageInspection:
    """Resolve and shape-check one explicit image from the local Docker store."""
    validated = validate_image_reference(reference, role)
    requested_digest: str | None = None
    if role == "App":
        digest_match = DIGEST_BOUND_REFERENCE.fullmatch(validated)
        if digest_match is None:
            raise RehearsalError("App image reference must be repository@sha256 digest-bound")
        requested_digest = digest_match.group("digest")
        if (
            candidate_version is None
            or RELEASE_VERSION.fullmatch(candidate_version) is None
            or "snapshot" in candidate_version.lower()
            or candidate_revision is None
            or GIT_OBJECT.fullmatch(candidate_revision) is None
        ):
            raise RehearsalError("App image inspection requires an exact release candidate identity")
    completed = run_command(["docker", "image", "inspect", validated])
    if completed.returncode != 0:
        raise RehearsalError(f"Explicit {role} image is not present in the local Docker store")
    try:
        documents = json.loads(completed.stdout)
        document = documents[0]
        image_id = document["Id"]
        config = document["Config"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exception:
        raise RehearsalError(f"Docker returned malformed {role} image metadata") from exception
    if (
        len(documents) != 1
        or not isinstance(image_id, str)
        or not IMAGE_ID.fullmatch(image_id)
        or not isinstance(config, dict)
    ):
        raise RehearsalError(f"Docker did not resolve exactly one immutable {role} image ID")

    command_text = _image_command_text(config)
    exposed = config.get("ExposedPorts") or {}
    if not isinstance(exposed, dict):
        raise RehearsalError(f"Docker returned malformed {role} image port metadata")
    if role == "App":
        entrypoint = config.get("Entrypoint")
        user = str(config.get("User") or "").strip().lower()
        working_dir = config.get("WorkingDir")
        tags = tuple(document.get("RepoTags") or ()) + tuple(document.get("RepoDigests") or ())
        repo_digests = document.get("RepoDigests") or []
        labels = config.get("Labels") or {}
        if (
            not isinstance(entrypoint, list)
            or not all(isinstance(item, str) for item in entrypoint)
            or not entrypoint
            or "java" not in Path(entrypoint[0]).name
            or "/app/app.jar" not in entrypoint
            or working_dir != "/app"
            or user in {"", "0", "0:0", "root", "root:root"}
            or not any(
                isinstance(tag, str) and "web-starter" in tag.lower() for tag in tags
            )
            or not isinstance(repo_digests, list)
            or validated not in repo_digests
            or not isinstance(labels, dict)
            or labels.get(OCI_VERSION_LABEL) != candidate_version
            or labels.get(OCI_REVISION_LABEL) != candidate_revision
        ):
            raise RehearsalError(
                "Docker target is not the digest-bound non-root App for this candidate"
            )
    elif role == "MySQL":
        if "3306/tcp" not in exposed or "mysql" not in command_text:
            raise RehearsalError("Docker target does not retain the expected MySQL contract")
    elif role == "Redis":
        if "6379/tcp" not in exposed or "redis" not in command_text:
            raise RehearsalError("Docker target does not retain the expected Redis contract")
    return ImageInspection(
        image_id=image_id,
        requested_reference_sha256=hashlib.sha256(validated.encode("utf-8")).hexdigest(),
        requested_digest=requested_digest,
        oci_version=candidate_version if role == "App" else None,
        oci_revision=candidate_revision if role == "App" else None,
    )


def resource_names(run_id: str) -> ResourceNames:
    if not RUN_ID.fullmatch(run_id):
        raise RehearsalError("AC-07 run identifier is malformed")
    names = ResourceNames(
        run_id=run_id,
        network=f"web-starter-ac07-{run_id}",
        mysql=f"web-starter-ac07-mysql-{run_id}",
        redis=f"web-starter-ac07-redis-{run_id}",
        app=f"web-starter-ac07-app-{run_id}",
    )
    if not NETWORK_NAME.fullmatch(names.network) or not all(
        CONTAINER_NAME.fullmatch(name) for name in (names.mysql, names.redis, names.app)
    ):
        raise RehearsalError("Generated AC-07 Docker resource name is unsafe")
    return names


def _labels(run_id: str, role: str) -> list[str]:
    if not RUN_ID.fullmatch(run_id) or role not in {"network", "mysql", "redis", "app"}:
        raise RehearsalError("Refusing malformed AC-07 ownership labels")
    return [
        "--label",
        f"{LABEL_OWNER}={OWNER_VALUE}",
        "--label",
        f"{LABEL_RUN}={run_id}",
        "--label",
        f"{LABEL_ROLE}={role}",
    ]


def network_create_command(names: ResourceNames) -> list[str]:
    return [
        "docker",
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        *_labels(names.run_id, "network"),
        names.network,
    ]


def _add_environment(command: list[str], environment: Mapping[str, str]) -> None:
    for key in sorted(environment):
        if not ENVIRONMENT_NAME.fullmatch(key):
            raise RehearsalError("Refusing an unsafe environment variable name")
        command.extend(("--env", key))


def mysql_create_command(
    names: ResourceNames, image_id: str, environment: Mapping[str, str]
) -> list[str]:
    if not IMAGE_ID.fullmatch(image_id):
        raise RehearsalError("Refusing a mutable or malformed MySQL image target")
    command = [
        "docker",
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        names.mysql,
        "--network",
        names.network,
        "--network-alias",
        "mysql",
        *_labels(names.run_id, "mysql"),
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "1g",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/var/lib/mysql:rw,noexec,nosuid,nodev,size=512m",
    ]
    _add_environment(command, environment)
    command.extend(
        (
            image_id,
            "--character-set-server=utf8mb4",
            "--collation-server=utf8mb4_0900_ai_ci",
            "--default-time-zone=+00:00",
        )
    )
    return command


def redis_create_command(
    names: ResourceNames, image_id: str, environment: Mapping[str, str]
) -> list[str]:
    if not IMAGE_ID.fullmatch(image_id):
        raise RehearsalError("Refusing a mutable or malformed Redis image target")
    command = [
        "docker",
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        names.redis,
        "--network",
        names.network,
        "--network-alias",
        "redis",
        *_labels(names.run_id, "redis"),
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "256m",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/data:rw,noexec,nosuid,nodev,size=128m",
    ]
    _add_environment(command, environment)
    command.extend(
        (
            image_id,
            "sh",
            "-ec",
            'exec redis-server --save "" --appendonly no --requirepass "$WEB_STARTER_REDIS_PASSWORD"',
        )
    )
    return command


def validate_migration_directory(path: Path) -> Path:
    absolute = path.absolute()
    if absolute.is_symlink() or not absolute.is_dir() or "," in str(absolute):
        raise RehearsalError("Temporary migration directory is unsafe")
    migration = absolute / MIGRATION_FILE
    if migration.is_symlink() or not migration.is_file():
        raise RehearsalError("Temporary migration file is missing or unsafe")
    return absolute


def app_create_command(
    names: ResourceNames,
    image_id: str,
    environment: Mapping[str, str],
    migration_directory: Path,
) -> list[str]:
    if not IMAGE_ID.fullmatch(image_id):
        raise RehearsalError("Refusing a mutable or malformed App image target")
    migration = validate_migration_directory(migration_directory)
    command = [
        "docker",
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        names.app,
        "--network",
        names.network,
        *_labels(names.run_id, "app"),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "1g",
        "--cpus",
        "1.5",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1770,uid=10001,gid=10001",
        "--mount",
        (
            f"type=bind,src={migration},dst={MIGRATION_TARGET},"
            "readonly,bind-propagation=rprivate"
        ),
    ]
    _add_environment(command, environment)
    command.append(image_id)
    return command


def _create_resource(
    command: Sequence[str], environment: Mapping[str, str] | None = None
) -> None:
    completed = _run_quiet(command, environment=environment, timeout=30)
    if completed.returncode != 0:
        raise RehearsalError("Docker could not create an isolated AC-07 resource")


def _start_container(name: str) -> None:
    completed = _run_quiet(["docker", "container", "start", name], timeout=30)
    if completed.returncode != 0:
        raise RehearsalError("Docker could not start an isolated AC-07 container")


def _container_document(name: str) -> dict[str, object] | None:
    completed = _run_quiet(["docker", "container", "inspect", name], timeout=15)
    if completed.returncode != 0:
        return None
    try:
        documents = json.loads(completed.stdout)
    except json.JSONDecodeError as exception:
        raise RehearsalError("Docker returned malformed container inspection metadata") from exception
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise RehearsalError("Docker returned ambiguous container inspection metadata")
    return documents[0]


def _network_document(name: str) -> dict[str, object] | None:
    completed = _run_quiet(["docker", "network", "inspect", name], timeout=15)
    if completed.returncode != 0:
        return None
    try:
        documents = json.loads(completed.stdout)
    except json.JSONDecodeError as exception:
        raise RehearsalError("Docker returned malformed network inspection metadata") from exception
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise RehearsalError("Docker returned ambiguous network inspection metadata")
    return documents[0]


def _assert_labels(document: Mapping[str, object], run_id: str, role: str) -> None:
    labels = document.get("Labels")
    if labels is None:
        config = document.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or (
        labels.get(LABEL_OWNER) != OWNER_VALUE
        or labels.get(LABEL_RUN) != run_id
        or labels.get(LABEL_ROLE) != role
    ):
        raise RehearsalError("Refusing a Docker resource without exact AC-07 ownership labels")


def inspect_runtime_isolation(
    names: ResourceNames,
    images: ResolvedImages,
    migration_directory: Path,
) -> dict[str, object]:
    """Fail closed unless the created runtime has the exact isolated topology."""
    network = _network_document(names.network)
    if network is None:
        raise RehearsalError("Isolated AC-07 network disappeared before inspection")
    _assert_labels(network, names.run_id, "network")
    if network.get("Internal") is not True:
        raise RehearsalError("AC-07 network must be internal")

    expected_images = {
        names.mysql: (images.mysql, "mysql"),
        names.redis: (images.redis, "redis"),
        names.app: (images.app, "app"),
    }
    volume_mounts = 0
    bind_mounts = 0
    published_bindings = 0
    app_migration_read_only = False
    app_root_read_only = False
    for name, (image_id, role) in expected_images.items():
        document = _container_document(name)
        if document is None:
            raise RehearsalError("An isolated AC-07 container disappeared before inspection")
        _assert_labels(document, names.run_id, role)
        if document.get("Image") != image_id:
            raise RehearsalError("AC-07 container is not bound to the resolved immutable image ID")
        host = document.get("HostConfig")
        network_settings = document.get("NetworkSettings")
        mounts = document.get("Mounts")
        if not isinstance(host, dict) or not isinstance(network_settings, dict) or not isinstance(mounts, list):
            raise RehearsalError("Docker returned incomplete AC-07 isolation metadata")
        if host.get("NetworkMode") != names.network or host.get("PublishAllPorts") is True:
            raise RehearsalError("AC-07 container escaped its exact private network")
        port_bindings = host.get("PortBindings") or {}
        if not isinstance(port_bindings, dict):
            raise RehearsalError("Docker returned malformed port binding metadata")
        published_bindings += sum(bool(value) for value in port_bindings.values())
        attached_networks = network_settings.get("Networks") or {}
        if not isinstance(attached_networks, dict) or set(attached_networks) != {names.network}:
            raise RehearsalError("AC-07 container has an unexpected network attachment")
        for mount in mounts:
            if not isinstance(mount, dict):
                raise RehearsalError("Docker returned malformed mount metadata")
            mount_type = mount.get("Type")
            if mount_type == "volume":
                volume_mounts += 1
            elif mount_type == "bind":
                bind_mounts += 1
                if role != "app":
                    raise RehearsalError("Infrastructure containers must not use host bind mounts")
                source = Path(str(mount.get("Source") or "")).resolve()
                expected_source = migration_directory.resolve()
                if (
                    source != expected_source
                    or mount.get("Destination") != MIGRATION_TARGET
                    or mount.get("RW") is not False
                ):
                    raise RehearsalError("App migration bind mount is not the exact read-only fixture")
                app_migration_read_only = True
        if role == "app":
            app_root_read_only = host.get("ReadonlyRootfs") is True

    if published_bindings != 0 or volume_mounts != 0 or bind_mounts != 1:
        raise RehearsalError("AC-07 runtime contains a port, volume, or unexpected bind mount")
    if not app_migration_read_only or not app_root_read_only:
        raise RehearsalError("AC-07 App filesystem isolation is incomplete")
    return {
        "internalNetwork": True,
        "publishedHostPorts": published_bindings,
        "dockerVolumeMounts": volume_mounts,
        "hostBindMounts": bind_mounts,
        "migrationBindReadOnly": app_migration_read_only,
        "appRootFilesystemReadOnly": app_root_read_only,
        "immutableImageIds": True,
        "exactOwnershipLabels": True,
    }


def wait_for_infrastructure(name: str, role: str, timeout_seconds: int) -> int:
    if role == "mysql":
        probe = [
            "docker",
            "container",
            "exec",
            name,
            "sh",
            "-ec",
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqladmin ping -h 127.0.0.1 -u root --silent',
        ]
    elif role == "redis":
        probe = [
            "docker",
            "container",
            "exec",
            name,
            "sh",
            "-ec",
            'REDISCLI_AUTH="$WEB_STARTER_REDIS_PASSWORD" exec redis-cli --raw ping',
        ]
    else:
        raise RehearsalError("Unknown AC-07 infrastructure role")
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        completed = _run_quiet(probe, timeout=5)
        if completed.returncode == 0:
            normalized = completed.stdout.decode("utf-8", errors="replace").strip().lower()
            if role == "mysql" or normalized == "pong":
                return attempts
        document = _container_document(name)
        state = document.get("State") if document else None
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise RehearsalError(f"Isolated {role} container exited before becoming ready")
        time.sleep(0.5)
    raise RehearsalError(f"Isolated {role} container did not become ready before timeout")


def wait_for_app_exit_and_probe(name: str, timeout_seconds: int) -> AppRuntime:
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    successes = 0
    while time.monotonic() < deadline:
        document = _container_document(name)
        state = document.get("State") if document else None
        if not isinstance(state, dict):
            raise RehearsalError("App container state disappeared during AC-07 rehearsal")
        if state.get("Running") is not True:
            exit_code = state.get("ExitCode")
            if not isinstance(exit_code, int):
                raise RehearsalError("Docker returned a malformed App exit code")
            return AppRuntime(exit_code, False, attempts, successes)
        attempts += 1
        ready = _run_quiet(
            [
                "docker",
                "container",
                "exec",
                name,
                "curl",
                "-fsS",
                "--max-time",
                "1",
                READINESS_URL,
            ],
            timeout=3,
        )
        if ready.returncode == 0:
            successes += 1
        time.sleep(0.2)
    return AppRuntime(124, True, attempts, successes)


def _container_logs(name: str) -> bytes:
    completed = _run_quiet(["docker", "container", "logs", name], timeout=20)
    if completed.returncode != 0:
        raise RehearsalError("Docker could not read bounded in-memory AC-07 logs")
    return completed.stdout + b"\n" + completed.stderr


def ensure_no_fixture_literals(logs: Sequence[bytes], fixture_literals: Sequence[str]) -> None:
    for output in logs:
        for literal in fixture_literals:
            if literal and literal.encode("utf-8") in output:
                raise RehearsalError("Runtime logs exposed generated AC-07 fixture material")


def _mysql_scalar(name: str, query: str) -> int:
    completed = _run_quiet(
        [
            "docker",
            "container",
            "exec",
            name,
            "sh",
            "-ec",
            (
                'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --protocol=TCP '
                '-h 127.0.0.1 -u root --batch --skip-column-names "$MYSQL_DATABASE" -e "$1"'
            ),
            "web-starter-ac07",
            query,
        ],
        timeout=20,
    )
    if completed.returncode != 0:
        raise RehearsalError("Could not inspect isolated Flyway history")
    value = completed.stdout.decode("ascii", errors="strict").strip()
    if not value.isdigit():
        raise RehearsalError("Flyway history query returned a non-integer value")
    return int(value)


def read_flyway_state(mysql_name: str) -> FlywayState:
    version = MIGRATION_VERSION
    return FlywayState(
        successful_base_rows=_mysql_scalar(
            mysql_name,
            f"SELECT COUNT(*) FROM flyway_schema_history WHERE success=1 AND version<>'{version}'",
        ),
        successful_failure_version_rows=_mysql_scalar(
            mysql_name,
            f"SELECT COUNT(*) FROM flyway_schema_history WHERE version='{version}' AND success=1",
        ),
        unsuccessful_failure_version_rows=_mysql_scalar(
            mysql_name,
            f"SELECT COUNT(*) FROM flyway_schema_history WHERE version='{version}' AND success=0",
        ),
        total_failure_version_rows=_mysql_scalar(
            mysql_name,
            f"SELECT COUNT(*) FROM flyway_schema_history WHERE version='{version}'",
        ),
        latest_successful_version=_mysql_scalar(
            mysql_name,
            "SELECT COALESCE(MAX(CAST(version AS UNSIGNED)),0) "
            "FROM flyway_schema_history WHERE success=1",
        ),
    )


def migration_content(run_id: str) -> bytes:
    if not RUN_ID.fullmatch(run_id):
        raise RehearsalError("Refusing a malformed migration fixture identifier")
    return (
        "-- V2-AC-07 isolated intentional failure; never ship this file.\n"
        f"SELECT id FROM ac07_missing_{run_id};\n"
    ).encode("ascii")


def generate_rsa_material(directory: Path) -> tuple[str, str]:
    private_path = directory / "ac07-rsa-private.pem"
    generated = _run_quiet(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            str(private_path),
        ],
        timeout=45,
    )
    if generated.returncode != 0 or not private_path.is_file():
        raise RehearsalError("OpenSSL could not generate temporary AC-07 RSA material")
    private_path.chmod(0o600)
    private_der = _run_quiet(
        [
            "openssl",
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            str(private_path),
            "-outform",
            "DER",
        ],
        timeout=20,
    )
    public_der = _run_quiet(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_path),
            "-pubout",
            "-outform",
            "DER",
        ],
        timeout=20,
    )
    if private_der.returncode != 0 or public_der.returncode != 0:
        raise RehearsalError("OpenSSL could not encode temporary AC-07 RSA material")
    return (
        base64.b64encode(private_der.stdout).decode("ascii"),
        base64.b64encode(public_der.stdout).decode("ascii"),
    )


def generated_environment(
    run_id: str, git_commit: str, private_key: str, public_key: str
) -> tuple[dict[str, str], dict[str, str], dict[str, str], tuple[str, ...]]:
    if not RUN_ID.fullmatch(run_id) or not GIT_OBJECT.fullmatch(git_commit):
        raise RehearsalError("Refusing malformed AC-07 runtime identity")
    marker = secrets.token_hex(12)
    db_password = f"Ac07Db_{marker}_0123456789abcdef"
    db_root_password = f"Ac07Root_{marker}_0123456789abcdef"
    redis_password = f"Ac07Redis_{marker}_0123456789abcdef"
    token_pepper = f"Ac07TokenPepper_{marker}_0123456789abcdef"
    credential_pepper = f"Ac07CredentialPepper_{marker}_0123456789abcdef"
    management_password = f"Ac07Operations_{marker}_0123456789abcdef"
    mysql = {
        "MYSQL_DATABASE": "web_starter",
        "MYSQL_USER": "web_starter_ac07",
        "MYSQL_PASSWORD": db_password,
        "MYSQL_ROOT_PASSWORD": db_root_password,
    }
    redis = {"WEB_STARTER_REDIS_PASSWORD": redis_password}
    app = {
        "SPRING_FLYWAY_LOCATIONS": f"classpath:db/migration,filesystem:{MIGRATION_TARGET}",
        "WEB_STARTER_RUNTIME_MODE": "production",
        "WEB_STARTER_GIT_COMMIT": git_commit,
        "WEB_STARTER_DB_URL": (
            "jdbc:mysql://mysql:3306/web_starter?useUnicode=true&characterEncoding=utf8"
            "&preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"
            "&allowPublicKeyRetrieval=true&useSSL=false"
        ),
        "WEB_STARTER_DB_USERNAME": mysql["MYSQL_USER"],
        "WEB_STARTER_DB_PASSWORD": db_password,
        "WEB_STARTER_DB_POOL_MIN_IDLE": "1",
        "WEB_STARTER_DB_POOL_MAX_SIZE": "4",
        "WEB_STARTER_DB_CONNECTION_TIMEOUT_MS": "3000",
        "WEB_STARTER_DB_VALIDATION_TIMEOUT_MS": "1500",
        "WEB_STARTER_REDIS_HOST": "redis",
        "WEB_STARTER_REDIS_PORT": "6379",
        "WEB_STARTER_REDIS_PASSWORD": redis_password,
        "WEB_STARTER_TOKEN_PEPPER": token_pepper,
        "WEB_STARTER_CREDENTIAL_PEPPER": credential_pepper,
        "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION": "ac07",
        "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "",
        "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": "",
        "WEB_STARTER_MANAGEMENT_USERNAME": f"ac07_ops_{run_id}",
        "WEB_STARTER_MANAGEMENT_PASSWORD": management_password,
        "WEB_STARTER_OAUTH_ISSUER": "https://auth.ac07.example.invalid",
        "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": "https://mcp.ac07.example.invalid/mcp",
        "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "false",
        "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": private_key,
        "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": public_key,
        "WEB_STARTER_COOKIE_SECURE": "true",
        "WEB_STARTER_MCP_ALLOWED_HOSTS": "mcp.ac07.example.invalid:443",
        "WEB_STARTER_MCP_ALLOWED_ORIGINS": "https://agent.ac07.example.invalid",
        "WEB_STARTER_SERVER_PORT": "8080",
        "WEB_STARTER_MANAGEMENT_PORT": "8081",
        "WEB_STARTER_MANAGEMENT_BIND_ADDRESS": "127.0.0.1",
        "WEB_STARTER_LOG_FORMAT": "ecs",
        "WEB_STARTER_LOG_LEVEL": "INFO",
        "LOGGING_LEVEL_ROOT": "INFO",
    }
    fixture_literals = tuple(
        value
        for value in (
            db_password,
            db_root_password,
            redis_password,
            token_pepper,
            credential_pepper,
            management_password,
            private_key,
            public_key,
        )
        if value
    )
    return mysql, redis, app, fixture_literals


def evaluate_failure_protection(
    runtime: AppRuntime,
    flyway: FlywayState,
    app_logs: bytes,
) -> tuple[bool, dict[str, bool]]:
    markers = sanitized_application_log_markers(app_logs)
    checks = {
        "appExitedNonZero": runtime.exit_code != 0,
        "appCompletedBeforeTimeout": not runtime.timed_out,
        "readinessNeverSucceeded": runtime.readiness_successes == 0,
        "applicationStartedMarkerAbsent": markers["applicationStarted"] == 0,
        "intentionalMigrationFailureObserved": markers["intentionalMigrationFailure"] > 0,
        "productionPolicyAcceptedFixture": markers["unsafeProductionConfiguration"] == 0,
        "baseMigrationsSucceeded": flyway.successful_base_rows > 0,
        "failedVersionNotRecordedSuccessful": flyway.successful_failure_version_rows == 0,
        "failureVersionHistoryConsistent": (
            flyway.total_failure_version_rows
            == flyway.unsuccessful_failure_version_rows
        ),
    }
    return all(checks.values()), checks


def sanitized_application_log_markers(app_logs: bytes) -> dict[str, int]:
    normalized = app_logs.decode("utf-8", errors="replace").lower()
    migration_marker = MIGRATION_FILE.lower() in normalized or (
        MIGRATION_VERSION in normalized
        and "flyway" in normalized
        and ("failed" in normalized or "doesn't exist" in normalized or "not exist" in normalized)
    )
    return {
        "applicationStarted": normalized.count("started webstarterapplication"),
        "intentionalMigrationFailure": 1 if migration_marker else 0,
        "unsafeProductionConfiguration": normalized.count("unsafe production configuration"),
    }


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_read(repository: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    completed = _run_quiet(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-C",
            str(repository),
            *arguments,
        ],
        environment=environment,
        timeout=20,
    )
    if completed.returncode != 0:
        raise RehearsalError("Could not bind AC-07 evidence to the Git candidate")
    return completed.stdout


def _git_object(repository: Path, expression: str, label: str) -> str:
    try:
        value = _git_read(repository, "rev-parse", "--verify", expression).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise RehearsalError(f"Git returned a non-ASCII {label}") from exception
    if GIT_OBJECT.fullmatch(value) is None:
        raise RehearsalError(f"Git returned a malformed {label}")
    return value


def _require_clean_candidate(repository: Path) -> None:
    tracked = [
        record
        for record in _git_read(repository, "ls-files", "-v", "-z").split(b"\0")
        if record
    ]
    if not tracked or any(not record.startswith(b"H ") for record in tracked):
        raise RehearsalError("AC-07 candidate index is empty or uses hidden file state")
    if _git_read(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise RehearsalError("AC-07 release candidate must be a clean Git worktree")


def _committed_candidate_file(repository: Path, head: str, relative: str) -> bytes:
    relative_path = Path(relative)
    if relative_path.is_absolute() or not relative_path.parts or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise RehearsalError("AC-07 candidate source path is unsafe")
    workspace = repository.joinpath(*relative_path.parts)
    if workspace.is_symlink() or not workspace.is_file() or not _inside(
        workspace.resolve(), repository
    ):
        raise RehearsalError(f"AC-07 candidate source is missing or unsafe: {relative}")
    entry = _git_read(repository, "ls-tree", "-z", head, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1:
        raise RehearsalError(f"AC-07 candidate commit does not contain: {relative}")
    metadata, separator, encoded_path = records[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or encoded_path.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise RehearsalError(f"AC-07 candidate source is not a regular Git blob: {relative}")
    committed = _git_read(repository, "show", f"{head}:{relative}")
    if workspace.read_bytes() != committed:
        raise RehearsalError(f"AC-07 workspace bytes differ from candidate: {relative}")
    return committed


def _candidate_version(repository: Path, head: str) -> str:
    pom = _committed_candidate_file(repository, head, "pom.xml")
    package = _committed_candidate_file(repository, head, "web-starter-web/package.json")
    try:
        root = ElementTree.fromstring(pom)
        namespace = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
        version_element = root.find(f"{namespace}version")
        maven_version = (
            version_element.text.strip()
            if version_element is not None and version_element.text
            else ""
        )
        frontend_version = json.loads(package)["version"]
    except (ElementTree.ParseError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exception:
        raise RehearsalError("AC-07 candidate version manifests are invalid") from exception
    if (
        not isinstance(frontend_version, str)
        or maven_version != frontend_version
        or RELEASE_VERSION.fullmatch(maven_version) is None
        or "snapshot" in maven_version.lower()
    ):
        raise RehearsalError(
            "AC-07 candidate Maven and frontend versions must match a non-SNAPSHOT release"
        )
    return maven_version


def capture_candidate_identity(repository_root: Path = REPO_ROOT) -> CandidateIdentity:
    expanded = repository_root.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise RehearsalError("AC-07 repository root must be a real directory")
    repository = expanded.resolve()
    try:
        top = Path(
            _git_read(repository, "rev-parse", "--show-toplevel")
            .decode("utf-8")
            .strip()
        ).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exception:
        raise RehearsalError("Git returned an invalid AC-07 repository root") from exception
    if top != repository:
        raise RehearsalError("AC-07 repository root must be the exact Git worktree top level")
    head = _git_object(repository, "HEAD^{commit}", "candidate HEAD")
    tree = _git_object(repository, "HEAD^{tree}", "candidate tree")
    _require_clean_candidate(repository)
    version = _candidate_version(repository, head)
    source_sha256 = {
        relative: _sha256_bytes(_committed_candidate_file(repository, head, relative))
        for relative in CANDIDATE_SOURCE_PATHS
    }
    if (
        _git_object(repository, "HEAD^{commit}", "candidate HEAD") != head
        or _git_object(repository, "HEAD^{tree}", "candidate tree") != tree
    ):
        raise RehearsalError("AC-07 Git candidate changed while it was being captured")
    _require_clean_candidate(repository)
    return CandidateIdentity(head, tree, version, source_sha256)


def read_ac40_reference(path: Path | None) -> dict[str, object]:
    if path is None:
        return {
            "status": "NOT_COVERED",
            "statusDetail": "AC40_EVIDENCE_NOT_SUPPLIED",
            "promotionAllowed": False,
            "reason": "No accepted V2-AC-40 PASS evidence was supplied",
        }
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_file() or expanded.stat().st_size > 1024 * 1024:
        raise RehearsalError("AC-40 evidence must be a small regular non-symlink JSON file")
    if _inside(expanded.resolve(), REPO_ROOT.resolve()):
        raise RehearsalError("AC-40 runtime evidence must remain outside the Git working tree")
    expected_validator = AC40_VALIDATOR_PATH
    actual_validator = Path(ac40_validator.__file__).absolute()
    if (
        actual_validator.is_symlink()
        or actual_validator.resolve() != expected_validator.resolve()
        or not expected_validator.is_file()
    ):
        raise RehearsalError("AC-40 independent validator did not load from the repository")
    digest_before = _sha256_file(expanded)
    try:
        summary = ac40_validator.validate_document_path(
            expanded,
            repository_root=REPO_ROOT,
            require_pass=False,
        )
    except ac40_validator.EvidenceValidationError as exception:
        raise RehearsalError(
            "AC-40 evidence failed independent structure, semantics, filesystem, or candidate validation"
        ) from exception
    digest_after = _sha256_file(expanded)
    if digest_before != digest_after:
        raise RehearsalError("AC-40 evidence changed during independent validation")
    status = summary.get("status")
    if status not in ACCEPTANCE_STATUSES:
        raise RehearsalError("AC-40 validator returned a non-contract acceptance status")
    return {
        "status": status,
        "statusDetail": f"AC40_INDEPENDENT_VALIDATION_{status}",
        "promotionAllowed": status == "PASS",
        "evidenceSha256": digest_after,
        "validator": {
            "path": "scripts/validate_v1_upgrade_evidence.py",
            "sha256": _sha256_file(expected_validator),
            "checkCount": summary["checkCount"],
            "acceptanceCount": summary["acceptanceCount"],
            "phaseCount": summary["phaseCount"],
        },
    }


def acceptance_outcome(
    failure_protection_passed: bool, recovery_status: object
) -> tuple[str, str]:
    if recovery_status not in ACCEPTANCE_STATUSES:
        raise RehearsalError("Recovery evidence returned a non-contract acceptance status")
    if not failure_protection_passed:
        return "FAIL", "FAILURE_PROTECTION_FAILED"
    if recovery_status == "PASS":
        return "PASS", "COMPLETE"
    if recovery_status == "FAIL":
        return "FAIL", "RECOVERY_FAILED"
    if recovery_status == "ENV_REQUIRED":
        return "ENV_REQUIRED", "RECOVERY_ENV_REQUIRED"
    return "NOT_COVERED", "PENDING_AC40"


def process_exit_code(status: object) -> int:
    if status == "PASS":
        return 0
    if status == "FAIL":
        return 1
    if status in {"NOT_COVERED", "ENV_REQUIRED"}:
        return 6
    raise RehearsalError("Refusing a non-contract AC-07 process status")


def cleanup_owned_container(name: str, run_id: str, role: str) -> bool:
    document = _container_document(name)
    if document is None:
        return False
    _assert_labels(document, run_id, role)
    removed = _run_quiet(
        ["docker", "container", "rm", "--force", "--volumes", name], timeout=30
    )
    if removed.returncode != 0 or _container_document(name) is not None:
        raise RehearsalError("Could not remove the exact labelled AC-07 container")
    return True


def cleanup_owned_network(name: str, run_id: str) -> bool:
    document = _network_document(name)
    if document is None:
        return False
    _assert_labels(document, run_id, "network")
    removed = _run_quiet(["docker", "network", "rm", name], timeout=30)
    if removed.returncode != 0 or _network_document(name) is not None:
        raise RehearsalError("Could not remove the exact labelled AC-07 network")
    return True


def cleanup_owned_resources(names: ResourceNames) -> dict[str, object]:
    removed = {
        "app": cleanup_owned_container(names.app, names.run_id, "app"),
        "redis": cleanup_owned_container(names.redis, names.run_id, "redis"),
        "mysql": cleanup_owned_container(names.mysql, names.run_id, "mysql"),
        "network": cleanup_owned_network(names.network, names.run_id),
    }
    residual = {
        "app": _container_document(names.app) is not None,
        "redis": _container_document(names.redis) is not None,
        "mysql": _container_document(names.mysql) is not None,
        "network": _network_document(names.network) is not None,
    }
    if any(residual.values()):
        raise RehearsalError("Exact AC-07 resource cleanup left a residual Docker object")
    return {
        "exactLabelsVerifiedBeforeRemoval": True,
        "removed": removed,
        "residual": residual,
        "complete": True,
    }


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def write_evidence(output: Path, report: Mapping[str, object]) -> tuple[Path, str]:
    document = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    result_path = output / RESULT_NAME
    _write_private(result_path, document)
    digest = _sha256_bytes(document)
    _write_private(output / CHECKSUM_NAME, f"{digest}  {RESULT_NAME}\n".encode("ascii"))
    return result_path, digest


def rehearse(
    app_reference: str,
    mysql_reference: str,
    redis_reference: str,
    output_directory: Path,
    timeout_seconds: int,
    infrastructure_timeout_seconds: int,
    ac40_evidence: Path | None = None,
) -> tuple[dict[str, object], str]:
    if timeout_seconds < 15 or timeout_seconds > 180:
        raise RehearsalError("App timeout must be between 15 and 180 seconds")
    if infrastructure_timeout_seconds < 20 or infrastructure_timeout_seconds > 180:
        raise RehearsalError("Infrastructure timeout must be between 20 and 180 seconds")
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise RehearsalError("Docker and OpenSSL are required for AC-07 rehearsal")

    output = ensure_external_output_directory(output_directory)
    candidate = capture_candidate_identity()
    app_image = inspect_local_image(
        app_reference,
        "App",
        candidate_version=candidate.version,
        candidate_revision=candidate.head,
    )
    mysql_image = inspect_local_image(mysql_reference, "MySQL")
    redis_image = inspect_local_image(redis_reference, "Redis")
    images = ResolvedImages(
        app=app_image.image_id,
        mysql=mysql_image.image_id,
        redis=redis_image.image_id,
    )
    recovery = read_ac40_reference(ac40_evidence)
    names = resource_names(secrets.token_hex(6))

    runtime: AppRuntime | None = None
    flyway: FlywayState | None = None
    isolation: dict[str, object] | None = None
    infrastructure_attempts: dict[str, int] = {}
    app_logs = b""
    mysql_logs = b""
    redis_logs = b""
    fixture_literals: tuple[str, ...] = ()
    migration_sha256 = ""
    cleanup: dict[str, object] | None = None
    pending_error: Exception | None = None

    with tempfile.TemporaryDirectory(prefix="web-starter-ac07-") as temporary_name:
        temporary = Path(temporary_name)
        temporary.chmod(0o700)
        migration_directory = temporary / "migration"
        migration_directory.mkdir(mode=0o755)
        migration_path = migration_directory / MIGRATION_FILE
        content = migration_content(names.run_id)
        migration_path.write_bytes(content)
        migration_path.chmod(0o444)
        migration_sha256 = _sha256_bytes(content)
        private_key, public_key = generate_rsa_material(temporary)
        mysql_environment, redis_environment, app_environment, fixture_literals = (
            generated_environment(names.run_id, candidate.head, private_key, public_key)
        )

        try:
            _create_resource(network_create_command(names))
            _create_resource(
                mysql_create_command(names, images.mysql, mysql_environment),
                mysql_environment,
            )
            _create_resource(
                redis_create_command(names, images.redis, redis_environment),
                redis_environment,
            )
            _start_container(names.mysql)
            _start_container(names.redis)
            infrastructure_attempts["mysql"] = wait_for_infrastructure(
                names.mysql, "mysql", infrastructure_timeout_seconds
            )
            infrastructure_attempts["redis"] = wait_for_infrastructure(
                names.redis, "redis", infrastructure_timeout_seconds
            )
            _create_resource(
                app_create_command(
                    names,
                    images.app,
                    app_environment,
                    migration_directory,
                ),
                app_environment,
            )
            isolation = inspect_runtime_isolation(names, images, migration_directory)
            _start_container(names.app)
            runtime = wait_for_app_exit_and_probe(names.app, timeout_seconds)
            app_logs = _container_logs(names.app)
            mysql_logs = _container_logs(names.mysql)
            redis_logs = _container_logs(names.redis)
            ensure_no_fixture_literals(
                (app_logs, mysql_logs, redis_logs), fixture_literals
            )
            flyway = read_flyway_state(names.mysql)
        except Exception as exception:  # cleanup must run for every bounded failure
            pending_error = exception
        finally:
            try:
                cleanup = cleanup_owned_resources(names)
            except Exception as cleanup_error:
                pending_error = cleanup_error

    if temporary.exists():
        raise RehearsalError("Temporary AC-07 migration and key material were not removed")
    if pending_error is not None:
        if isinstance(pending_error, RehearsalError):
            raise pending_error
        raise RehearsalError("Unexpected AC-07 orchestration failure") from pending_error
    if runtime is None or flyway is None or isolation is None or cleanup is None:
        raise RehearsalError("AC-07 rehearsal ended without complete observations")

    failure_passed, checks = evaluate_failure_protection(runtime, flyway, app_logs)
    failure_status = "PASS" if failure_passed else "FAIL"
    overall_status, status_detail = acceptance_outcome(
        failure_passed, recovery["status"]
    )
    if capture_candidate_identity() != candidate:
        raise RehearsalError("AC-07 Git candidate changed during the rehearsal")

    report: dict[str, object] = {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-07",
        "status": overall_status,
        "statusDetail": status_detail,
        "processExitCode": process_exit_code(overall_status),
        "generatedAt": utc_now(),
        "candidate": {
            "head": candidate.head,
            "tree": candidate.tree,
            "version": candidate.version,
            "cleanWorktree": True,
            "sourceSha256": candidate.source_sha256,
        },
        "tool": {
            "path": "scripts/rehearse_migration_failure.py",
            "sha256": candidate.source_sha256["scripts/rehearse_migration_failure.py"],
            "evidenceSchemaPath": "security/v2-ac07-migration-failure.schema.json",
            "evidenceSchemaSha256": candidate.source_sha256[
                "security/v2-ac07-migration-failure.schema.json"
            ],
        },
        "failureProtection": {
            "status": failure_status,
            "checks": checks,
        },
        "recovery": recovery,
        "images": {
            "app": {
                "id": app_image.image_id,
                "requestedReferenceSha256": app_image.requested_reference_sha256,
                "requestedDigest": app_image.requested_digest,
                "ociVersion": app_image.oci_version,
                "ociRevision": app_image.oci_revision,
            },
            "mysql": {
                "id": mysql_image.image_id,
                "requestedReferenceSha256": mysql_image.requested_reference_sha256,
            },
            "redis": {
                "id": redis_image.image_id,
                "requestedReferenceSha256": redis_image.requested_reference_sha256,
            },
        },
        "resources": {
            "prefix": "web-starter-ac07-",
            "runId": names.run_id,
            "network": names.network,
            "containers": {
                "mysql": names.mysql,
                "redis": names.redis,
                "app": names.app,
            },
            "isolation": isolation,
            "cleanup": cleanup,
        },
        "infrastructure": {
            "mysqlReady": True,
            "redisReady": True,
            "probeAttempts": infrastructure_attempts,
            "hostPorts": 0,
            "sharedVolumes": 0,
        },
        "migration": {
            "version": MIGRATION_VERSION,
            "file": MIGRATION_FILE,
            "contentSha256": migration_sha256,
            "temporaryReadOnlyMount": True,
            "persistedAfterRun": False,
            "successfulBaseRows": flyway.successful_base_rows,
            "successfulFailureVersionRows": flyway.successful_failure_version_rows,
            "unsuccessfulFailureVersionRows": flyway.unsuccessful_failure_version_rows,
            "totalFailureVersionRows": flyway.total_failure_version_rows,
            "latestSuccessfulVersion": flyway.latest_successful_version,
        },
        "application": {
            "exitCode": runtime.exit_code,
            "timedOut": runtime.timed_out,
            "readinessAttempts": runtime.readiness_attempts,
            "readinessSuccesses": runtime.readiness_successes,
            "logMarkers": sanitized_application_log_markers(app_logs),
        },
        "logs": {
            "rawPersisted": False,
            "fixtureMaterialPersisted": False,
            "fixtureLeakDetected": False,
            "app": {"bytes": len(app_logs), "sha256": _sha256_bytes(app_logs)},
            "mysql": {"bytes": len(mysql_logs), "sha256": _sha256_bytes(mysql_logs)},
            "redis": {"bytes": len(redis_logs), "sha256": _sha256_bytes(redis_logs)},
        },
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
        },
    }
    _, digest = write_evidence(output, report)
    return report, digest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rehearse fail-closed V2-AC-07 Flyway migration failure protection"
    )
    parser.add_argument(
        "--app-image",
        required=True,
        help="local Web Starter App repository@sha256 manifest-digest reference",
    )
    parser.add_argument(
        "--mysql-image", required=True, help="explicit local MySQL image reference or ID"
    )
    parser.add_argument(
        "--redis-image", required=True, help="explicit local Redis image reference or ID"
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="new or empty private directory outside the Git working tree",
    )
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--infrastructure-timeout-seconds", type=int, default=120)
    parser.add_argument(
        "--ac40-evidence",
        type=Path,
        help=(
            "optional external V2-AC-40 JSON; PASS is accepted only after independent "
            "schema, semantics, filesystem and clean Git candidate validation"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, digest = rehearse(
            args.app_image,
            args.mysql_image,
            args.redis_image,
            args.output_dir,
            args.timeout_seconds,
            args.infrastructure_timeout_seconds,
            args.ac40_evidence,
        )
    except RehearsalError as exception:
        print(f"AC-07 rehearsal failed safely: {exception}", file=sys.stderr)
        return 2
    summary = {
        "acceptanceId": "V2-AC-07",
        "status": report["status"],
        "failureProtection": report["failureProtection"]["status"],
        "recovery": report["recovery"]["status"],
        "evidence": RESULT_NAME,
        "sha256": digest,
    }
    print(json.dumps(summary, sort_keys=True))
    return process_exit_code(report["status"])


if __name__ == "__main__":
    raise SystemExit(main())
