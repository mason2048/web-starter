#!/usr/bin/env python3
"""Verify Java, Actuator build info and OCI identity for a running release stack.

Operational credentials are read only from the process environment and used in
memory.  The report contains version and immutable-image metadata only.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

from acceptance_network import RejectRedirectHandler, reject_tls_key_logging


COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)


class RuntimeIdentityError(RuntimeError):
    """A non-secret-bearing runtime identity failure."""


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or any(character in value for character in "\r\n\0"):
        raise RuntimeIdentityError(f"{name} is required and must be a single line")
    return value


def _loopback_origin(value: str) -> str:
    parsed = urlparse(value.rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeIdentityError("management base URL must be an HTTP(S) origin")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} \
            or parsed.query or parsed.fragment:
        raise RuntimeIdentityError("management base URL must not contain credentials or a path")
    host = parsed.hostname.lower()
    if host not in {"localhost", "::1"} and not host.startswith("127."):
        raise RuntimeIdentityError("runtime identity accepts only a loopback management origin")
    return value.rstrip("/")


def _validate_inputs(
    project: str,
    container_ids: dict[str, str],
    references: dict[str, str],
    version: str,
    commit: str,
) -> None:
    if not PROJECT.fullmatch(project):
        raise RuntimeIdentityError("Compose project name contains unsafe characters")
    expected_services = {"app", "nginx", "mysql", "redis"}
    if set(container_ids) != expected_services or set(references) != expected_services:
        raise RuntimeIdentityError("runtime identity requires App, Nginx, MySQL and Redis")
    if any(not CONTAINER_ID.fullmatch(value) for value in container_ids.values()):
        raise RuntimeIdentityError("runtime container ID is malformed")
    if len(set(container_ids.values())) != len(expected_services):
        raise RuntimeIdentityError("runtime container IDs must be unique")
    if any(not DIGEST_REFERENCE.fullmatch(value) for value in references.values()):
        raise RuntimeIdentityError("runtime images must use immutable sha256 references")
    if not VERSION.fullmatch(version):
        raise RuntimeIdentityError("release version is not semantic")
    if not COMMIT.fullmatch(commit):
        raise RuntimeIdentityError("release commit is not a lowercase Git object ID")


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeIdentityError("Docker runtime identity command did not complete") from error


def _docker_document(
    command: Sequence[str],
    label: str,
    run_command: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    completed = run_command(command)
    if completed.returncode != 0:
        raise RuntimeIdentityError(f"Docker could not inspect the {label}")
    try:
        documents = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeIdentityError(f"Docker returned malformed {label} metadata") from error
    if not isinstance(documents, list) or len(documents) != 1 or not isinstance(documents[0], dict):
        raise RuntimeIdentityError(f"Docker did not resolve exactly one {label}")
    return documents[0]


def inspect_runtime_image(
    *,
    container_id: str,
    reference: str,
    project: str,
    service: str,
    version: str,
    commit: str,
    run_command: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
) -> dict[str, str]:
    container = _docker_document(
        ["docker", "container", "inspect", container_id],
        f"{service} container",
        run_command,
    )
    state = container.get("State")
    config = container.get("Config")
    if not isinstance(state, dict) or state.get("Running") is not True or not isinstance(config, dict):
        raise RuntimeIdentityError(f"{service} container is not running")
    labels = config.get("Labels")
    if not isinstance(labels, dict) \
            or labels.get("com.docker.compose.project") != project \
            or labels.get("com.docker.compose.service") != service:
        raise RuntimeIdentityError(f"{service} container is not owned by the expected Compose project")
    if config.get("Image") != reference:
        raise RuntimeIdentityError(f"{service} container was not created from the expected digest reference")
    image_id = container.get("Image")
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise RuntimeIdentityError(f"{service} container has no immutable image ID")

    image = _docker_document(
        ["docker", "image", "inspect", reference],
        f"{service} image",
        run_command,
    )
    if image.get("Id") != image_id:
        raise RuntimeIdentityError(f"{service} container image ID differs from the inspected digest")
    image_config = image.get("Config")
    image_labels = image_config.get("Labels") if isinstance(image_config, dict) else None
    if not isinstance(image_labels, dict):
        raise RuntimeIdentityError(f"{service} image has no OCI labels")
    if image_labels.get("org.opencontainers.image.version") != version:
        raise RuntimeIdentityError(f"{service} OCI version label differs from the release version")
    if image_labels.get("org.opencontainers.image.revision") != commit:
        raise RuntimeIdentityError(f"{service} OCI revision label differs from the release commit")
    return {
        "reference": reference,
        "imageId": image_id,
        "ociVersion": version,
        "ociRevision": commit,
    }


def inspect_runtime_dependency_image(
    *,
    container_id: str,
    reference: str,
    project: str,
    service: str,
    run_command: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
) -> dict[str, str | None]:
    """Bind an infrastructure container to its exact digest and image ID.

    MySQL and Redis are third-party inputs, so they must not be credited with
    Web Starter OCI version/revision labels.
    """
    if service not in {"mysql", "redis"}:
        raise RuntimeIdentityError("runtime dependency service is unsupported")
    container = _docker_document(
        ["docker", "container", "inspect", container_id],
        f"{service} container",
        run_command,
    )
    state = container.get("State")
    config = container.get("Config")
    if not isinstance(state, dict) or state.get("Running") is not True or not isinstance(config, dict):
        raise RuntimeIdentityError(f"{service} container is not running")
    labels = config.get("Labels")
    if not isinstance(labels, dict) \
            or labels.get("com.docker.compose.project") != project \
            or labels.get("com.docker.compose.service") != service:
        raise RuntimeIdentityError(f"{service} container is not owned by the expected Compose project")
    if config.get("Image") != reference:
        raise RuntimeIdentityError(f"{service} container was not created from the expected digest reference")
    image_id = container.get("Image")
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise RuntimeIdentityError(f"{service} container has no immutable image ID")
    image = _docker_document(
        ["docker", "image", "inspect", reference],
        f"{service} image",
        run_command,
    )
    if image.get("Id") != image_id:
        raise RuntimeIdentityError(f"{service} container image ID differs from the inspected digest")
    return {
        "reference": reference,
        "imageId": image_id,
        "ociVersion": None,
        "ociRevision": None,
    }


def java_identity(
    container_id: str,
    run_command: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
) -> dict[str, str]:
    completed = run_command(
        ["docker", "container", "exec", container_id, "java", "-XshowSettings:properties", "-version"]
    )
    if completed.returncode != 0:
        raise RuntimeIdentityError("Java runtime identity command failed")
    output = completed.stdout + "\n" + completed.stderr
    specification = re.search(r"(?m)^\s*java\.specification\.version\s*=\s*([^\s]+)\s*$", output)
    runtime = re.search(r"(?m)^\s*java\.runtime\.version\s*=\s*([^\s]+)\s*$", output)
    if specification is None or specification.group(1) != "21" or runtime is None:
        raise RuntimeIdentityError("App image does not provide the required Java 21 runtime")
    runtime_version = runtime.group(1)
    if len(runtime_version) > 128 or any(character in runtime_version for character in "\r\n\0"):
        raise RuntimeIdentityError("Java runtime version is malformed")
    return {"specificationVersion": "21", "runtimeVersion": runtime_version}


def fetch_actuator_info(base_url: str, username: str, password: str) -> dict[str, Any]:
    try:
        reject_tls_key_logging()
    except ValueError as error:
        raise RuntimeIdentityError(str(error)) from error
    basic = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = Request(
        base_url + "/actuator/info",
        headers={"Accept": "application/json", "Authorization": "Basic " + basic},
        method="GET",
    )
    try:
        with build_opener(ProxyHandler({}), RejectRedirectHandler()).open(
            request, timeout=20
        ) as response:
            raw = response.read()
            if response.status != 200:
                raise RuntimeIdentityError("Actuator info did not return HTTP 200")
    except HTTPError as error:
        error.read()
        raise RuntimeIdentityError(f"Actuator info returned HTTP {error.code}") from error
    except (URLError, TimeoutError) as error:
        raise RuntimeIdentityError("Actuator info is unreachable") from error
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeIdentityError("Actuator info returned malformed JSON") from error
    if not isinstance(document, dict):
        raise RuntimeIdentityError("Actuator info returned an invalid document")
    return document


def validate_actuator_info(document: dict[str, Any], version: str) -> dict[str, str]:
    app = document.get("app")
    build = document.get("build")
    if not isinstance(app, dict) or not isinstance(build, dict):
        raise RuntimeIdentityError("Actuator info lacks app or build identity")
    if app.get("version") != version or build.get("version") != version:
        raise RuntimeIdentityError("Actuator app/build version differs from the release version")
    if build.get("artifact") != "web-starter-admin" or build.get("group") != "dev.webstarter":
        raise RuntimeIdentityError("Actuator build identity is not the Web Starter Admin artifact")
    return {
        "applicationVersion": version,
        "buildVersion": version,
        "buildArtifact": "web-starter-admin",
        "buildGroup": "dev.webstarter",
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
    if path.exists() or path.is_symlink():
        temporary.unlink(missing_ok=True)
        raise RuntimeIdentityError("runtime identity output already exists")
    temporary.replace(path)
    path.chmod(0o600)


def verify(args: argparse.Namespace) -> dict[str, Any]:
    container_ids = {
        "app": args.app_container_id,
        "nginx": args.nginx_container_id,
        "mysql": args.mysql_container_id,
        "redis": args.redis_container_id,
    }
    references = {
        "app": args.app_reference,
        "nginx": args.nginx_reference,
        "mysql": args.mysql_reference,
        "redis": args.redis_reference,
    }
    _validate_inputs(
        args.compose_project,
        container_ids,
        references,
        args.expected_version,
        args.expected_commit,
    )
    base_url = _loopback_origin(args.management_base_url)
    username = _required_environment("WEB_STARTER_ACCEPTANCE_MANAGEMENT_USERNAME")
    password = _required_environment("WEB_STARTER_ACCEPTANCE_MANAGEMENT_PASSWORD")
    app_image = inspect_runtime_image(
        container_id=args.app_container_id,
        reference=args.app_reference,
        project=args.compose_project,
        service="app",
        version=args.expected_version,
        commit=args.expected_commit,
    )
    nginx_image = inspect_runtime_image(
        container_id=args.nginx_container_id,
        reference=args.nginx_reference,
        project=args.compose_project,
        service="nginx",
        version=args.expected_version,
        commit=args.expected_commit,
    )
    mysql_image = inspect_runtime_dependency_image(
        container_id=args.mysql_container_id,
        reference=args.mysql_reference,
        project=args.compose_project,
        service="mysql",
    )
    redis_image = inspect_runtime_dependency_image(
        container_id=args.redis_container_id,
        reference=args.redis_reference,
        project=args.compose_project,
        service="redis",
    )
    java = java_identity(args.app_container_id)
    actuator = validate_actuator_info(
        fetch_actuator_info(base_url, username, password), args.expected_version
    )
    document: dict[str, Any] = {
        "schemaVersion": 2,
        "status": "PASS",
        "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "release": {"version": args.expected_version, "gitCommit": args.expected_commit},
        "java": java,
        "actuator": actuator,
        "images": {
            "app": app_image,
            "nginx": nginx_image,
            "mysql": mysql_image,
            "redis": redis_image,
        },
    }
    _write_private(args.output, document)
    return document


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify runtime release version identity")
    parser.add_argument("--management-base-url", required=True)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--app-container-id", required=True)
    parser.add_argument("--nginx-container-id", required=True)
    parser.add_argument("--mysql-container-id", required=True)
    parser.add_argument("--redis-container-id", required=True)
    parser.add_argument("--app-reference", required=True)
    parser.add_argument("--nginx-reference", required=True)
    parser.add_argument("--mysql-reference", required=True)
    parser.add_argument("--redis-reference", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        verify(args)
    except (RuntimeIdentityError, OSError, ValueError) as error:
        print(f"FAIL runtime-identity: {error}", file=sys.stderr)
        return 1
    print("PASS runtime-identity: Java, Actuator and OCI release identity match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
