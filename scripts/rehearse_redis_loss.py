#!/usr/bin/env python3
"""Run the destructive Redis portion of V2-AC-41 in an isolated Compose project."""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.recovery_common import (  # noqa: E402
    ComposeContext,
    RecoveryError,
    audit_counts,
    ensure_audit_not_lost,
    prepare_external_report_file,
    sha256_file,
    stable_domain_fingerprints,
    utc_now,
    validate_ac41_project,
    validate_database_identifier,
    write_private_json,
    write_private_text,
)
from scripts import validate_redis_loss_evidence as formal_validator  # noqa: E402
from scripts.acceptance_network import (  # noqa: E402
    RejectRedirectHandler,
    is_isolated_acceptance_host,
    isolated_loopback_resolution,
    reject_tls_key_logging,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORMAL_SOURCE_FILES = (
    "scripts/rehearse_redis_loss.py",
    "scripts/recovery_common.py",
    "scripts/validate_redis_loss_evidence.py",
    "security/v2-ac41-redis-loss.schema.json",
    "pom.xml",
    "web-starter-web/package.json",
)
SERVICES = ("app", "nginx", "mysql", "redis")
OCI_SERVICES = ("app", "nginx")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RELOGIN_MAX_ATTEMPTS = 5
RELOGIN_RETRY_DELAY_SECONDS = 1.0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Flush one Redis database only after proving that Redis and MySQL use named volumes "
            "owned by an isolated web-starter-ac41-* Compose project. No volume is deleted."
        )
    )
    result.add_argument("--compose-project", required=True)
    result.add_argument("--confirm-project", required=True)
    result.add_argument(
        "--compose-file",
        action="append",
        type=Path,
        default=[],
        help="Compose file; repeat for overrides (defaults to compose.yaml)",
    )
    result.add_argument(
        "--env-file",
        type=Path,
        help=(
            "private 0600 Docker Compose env file, passed structurally as --env-file "
            "and never evaluated by a host shell"
        ),
    )
    result.add_argument("--expected-database", required=True)
    result.add_argument(
        "--mode",
        choices=("diagnostic", "formal"),
        required=True,
        help="formal is the only mode that can produce independently validatable PASS evidence",
    )
    result.add_argument(
        "--base-url",
        required=True,
        help=(
            "formal mode requires the isolated public HTTPS acceptance origin; "
            "diagnostic mode also permits the loopback private HTTP origin"
        ),
    )
    result.add_argument("--report-file", required=True, type=Path)
    for service in SERVICES:
        result.add_argument(f"--expected-{service}-reference")
        result.add_argument(f"--expected-{service}-image-id")
    return result


class WebSessionClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        handlers: list[object] = [
            urllib.request.ProxyHandler({}),
            RejectRedirectHandler(),
            urllib.request.HTTPCookieProcessor(self.cookies),
        ]
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme == "https":
            try:
                reject_tls_key_logging()
                insecure = os.environ.get(
                    "WEB_STARTER_ACCEPTANCE_INSECURE_TLS", "false"
                ).lower() == "true"
                if insecure:
                    if not is_isolated_acceptance_host(parsed.hostname or ""):
                        raise RecoveryError(
                            "insecure AC-41 TLS is allowed only for an isolated acceptance host"
                        )
                    context = ssl._create_unverified_context()  # noqa: SLF001 - isolated test TLS
                else:
                    context = ssl.create_default_context()
            except ValueError as error:
                raise RecoveryError(str(error)) from error
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "web-starter-ac41-rehearsal/1",
            **(headers or {}),
        }
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except urllib.error.URLError as error:
            raise RecoveryError(f"HTTP request failed for {path}: {error.reason}") from error

    def login(self, username: str, password: str) -> int:
        csrf_status, csrf_body = self.request("/api/auth/csrf")
        if csrf_status != 200:
            raise RecoveryError(f"CSRF endpoint returned HTTP {csrf_status}")
        try:
            envelope = json.loads(csrf_body)
            csrf = envelope["data"]
            header_name = csrf["headerName"]
            token = csrf["token"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise RecoveryError("CSRF endpoint returned an unexpected contract") from error
        if not isinstance(header_name, str) or not isinstance(token, str):
            raise RecoveryError("CSRF endpoint did not return string header/token values")
        status, _ = self.request(
            "/api/auth/login",
            method="POST",
            body={"username": username, "password": password},
            headers={header_name: token},
        )
        if status != 200:
            raise RecoveryError(f"login returned HTTP {status}")
        me_status, _ = self.request("/api/auth/me")
        if me_status != 200:
            raise RecoveryError(f"authenticated /api/auth/me returned HTTP {me_status}")
        return me_status


def relogin_after_redis_loss(
    base_url: str,
    username: str,
    password: str,
    *,
    max_attempts: int = RELOGIN_MAX_ATTEMPTS,
    retry_delay_seconds: float = RELOGIN_RETRY_DELAY_SECONDS,
    client_factory=WebSessionClient,
    sleeper=time.sleep,
) -> tuple[int, int]:
    if max_attempts < 1 or max_attempts > RELOGIN_MAX_ATTEMPTS:
        raise RecoveryError("Redis-loss re-login attempt bound is invalid")
    if retry_delay_seconds < 0 or retry_delay_seconds > RELOGIN_RETRY_DELAY_SECONDS:
        raise RecoveryError("Redis-loss re-login delay bound is invalid")
    last_error: RecoveryError | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            status = client_factory(base_url).login(username, password)
            return status, attempt
        except RecoveryError as error:
            last_error = error
            if attempt < max_attempts:
                sleeper(retry_delay_seconds)
    raise RecoveryError(
        f"re-login did not establish an authenticated Session within {max_attempts} attempts"
    ) from last_error


def _git(*arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                str(REPOSITORY_ROOT),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
    except OSError as error:
        raise RecoveryError("Git is required for formal AC-41 evidence") from error
    if completed.returncode != 0:
        raise RecoveryError(f"Git candidate query failed: {arguments[0]}")
    return completed.stdout


def _git_id(expression: str, label: str) -> str:
    try:
        value = _git("rev-parse", "--verify", expression).decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RecoveryError(f"{label} is not ASCII") from error
    if GIT_OBJECT.fullmatch(value) is None:
        raise RecoveryError(f"{label} is not a full Git object ID")
    return value


def _require_clean_candidate() -> None:
    records = [record for record in _git("ls-files", "-v", "-z").split(b"\0") if record]
    if not records or any(not record.startswith(b"H ") for record in records):
        raise RecoveryError(
            "formal AC-41 evidence rejects skip-worktree, assume-unchanged, or non-normal Git entries"
        )
    if _git(
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise RecoveryError("formal AC-41 evidence requires a clean Git candidate")


def _release_versions() -> tuple[str, str]:
    try:
        root = ET.fromstring((REPOSITORY_ROOT / "pom.xml").read_bytes())
        package = json.loads((REPOSITORY_ROOT / "web-starter-web/package.json").read_text("utf-8"))
    except (OSError, ET.ParseError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryError("cannot read the Maven/frontend release versions") from error
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    maven_node = root.find("m:version", namespace)
    maven = maven_node.text.strip() if maven_node is not None and maven_node.text else ""
    frontend = package.get("version") if isinstance(package, dict) else None
    if (
        not isinstance(frontend, str)
        or VERSION.fullmatch(maven) is None
        or VERSION.fullmatch(frontend) is None
        or "SNAPSHOT" in maven.upper()
        or "SNAPSHOT" in frontend.upper()
        or maven != frontend
    ):
        raise RecoveryError(
            "formal AC-41 evidence requires equal non-SNAPSHOT Maven and frontend versions"
        )
    return maven, frontend


def _repository_relative_source(path: Path) -> str:
    repository = REPOSITORY_ROOT.resolve()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(repository).as_posix()
    except (OSError, ValueError) as error:
        raise RecoveryError("formal Compose files must be regular files inside the repository") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or relative.startswith("../"):
        raise RecoveryError("formal Compose files must be regular files inside the repository")
    if not relative.endswith((".yaml", ".yml")):
        raise RecoveryError("formal Compose files must use a .yaml or .yml suffix")
    return relative


def _committed_source(commit: str, relative: str) -> bytes:
    path = REPOSITORY_ROOT / relative
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(REPOSITORY_ROOT.resolve())
    except (OSError, ValueError) as error:
        raise RecoveryError(f"candidate source is missing or unsafe: {relative}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise RecoveryError(f"candidate source is not a regular file: {relative}")
    records = [
        record for record in _git("ls-tree", "-z", commit, "--", relative).split(b"\0") if record
    ]
    if len(records) != 1:
        raise RecoveryError(f"candidate commit does not contain source: {relative}")
    header, separator, encoded_path = records[0].partition(b"\t")
    fields = header.split()
    if (
        not separator
        or encoded_path.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise RecoveryError(f"candidate source is not a regular committed blob: {relative}")
    committed = _git("show", f"{commit}:{relative}")
    if path.read_bytes() != committed:
        raise RecoveryError(f"candidate source bytes differ from the commit: {relative}")
    return committed


def _formal_candidate(compose_files: tuple[Path, ...]) -> tuple[dict[str, object], list[str]]:
    try:
        top = Path(_git("rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    except UnicodeDecodeError as error:
        raise RecoveryError("Git repository root is not UTF-8") from error
    if top != REPOSITORY_ROOT.resolve():
        raise RecoveryError("formal rehearsal must run against the exact web-starter Git root")
    _require_clean_candidate()
    commit = _git_id("HEAD^{commit}", "candidate commit")
    tree = _git_id("HEAD^{tree}", "candidate tree")
    maven, frontend = _release_versions()
    compose_relative = [_repository_relative_source(path) for path in compose_files]
    if len(compose_relative) != len(set(compose_relative)):
        raise RecoveryError("formal Compose file list contains duplicates")
    source_files = sorted(set(FORMAL_SOURCE_FILES) | set(compose_relative))
    hashes = {
        relative: hashlib.sha256(_committed_source(commit, relative)).hexdigest()
        for relative in source_files
    }
    if _git_id("HEAD^{commit}", "candidate commit") != commit \
            or _git_id("HEAD^{tree}", "candidate tree") != tree:
        raise RecoveryError("Git candidate changed during formal source binding")
    _require_clean_candidate()
    return {
        "gitCommit": commit,
        "gitTree": tree,
        "cleanWorktree": True,
        "mavenVersion": maven,
        "frontendVersion": frontend,
        "sourceSha256": hashes,
    }, compose_relative


def _expected_images(
    args: argparse.Namespace,
    *,
    required: bool,
) -> dict[str, dict[str, str]]:
    raw = {
        service: {
            "reference": getattr(args, f"expected_{service}_reference"),
            "imageId": getattr(args, f"expected_{service}_image_id"),
        }
        for service in SERVICES
    }
    supplied = [value for fields in raw.values() for value in fields.values() if value is not None]
    if not supplied and not required:
        return {}
    if len(supplied) != len(SERVICES) * 2:
        raise RecoveryError(
            "all expected image references and image IDs must be supplied together"
        )
    for service, fields in raw.items():
        reference = fields["reference"]
        image_id = fields["imageId"]
        if not isinstance(reference, str) or DIGEST_REFERENCE.fullmatch(reference) is None:
            raise RecoveryError(f"expected {service} reference must include an immutable @sha256 digest")
        if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
            raise RecoveryError(f"expected {service} image ID must be a full sha256 ID")
    return raw  # type: ignore[return-value]


def _compose_configuration(context: ComposeContext) -> dict[str, dict[str, str]]:
    try:
        payload = json.loads(context.run(["config", "--format", "json"]).stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryError("Docker Compose resolved configuration is not valid JSON") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), dict):
        raise RecoveryError("Docker Compose resolved configuration has no service catalog")
    services = payload["services"]
    configured_images: dict[str, str] = {}
    configured_volumes: dict[str, str] = {}
    destinations = {"mysql": "/var/lib/mysql", "redis": "/data"}
    for service in SERVICES:
        config = services.get(service)
        if not isinstance(config, dict) or not isinstance(config.get("image"), str):
            raise RecoveryError(f"resolved Compose configuration has no image for {service}")
        configured_images[service] = config["image"]
        if service not in destinations:
            continue
        mounts = config.get("volumes")
        if not isinstance(mounts, list):
            raise RecoveryError(f"resolved Compose configuration has no volume list for {service}")
        matches = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("target") == destinations[service]
        ]
        if (
            len(matches) != 1
            or matches[0].get("type") != "volume"
            or not isinstance(matches[0].get("source"), str)
            or not matches[0]["source"]
        ):
            raise RecoveryError(
                f"resolved Compose {service} data path must use one named volume"
            )
        configured_volumes[service] = matches[0]["source"]
    volume_catalog = payload.get("volumes")
    if not isinstance(volume_catalog, dict):
        raise RecoveryError("resolved Compose configuration has no volume catalog")
    for service, logical in configured_volumes.items():
        definition = volume_catalog.get(logical)
        if not isinstance(definition, dict) or definition.get("external", False) is not False:
            raise RecoveryError(f"resolved Compose {service} volume must not be external")
    return {"images": configured_images, "volumes": configured_volumes}


def _image_inspect(reference: str, service: str) -> dict[str, object]:
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", reference],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise RecoveryError("docker command was not found") from error
    if completed.returncode != 0:
        raise RecoveryError(f"cannot inspect the expected {service} image")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RecoveryError(f"Docker returned invalid image metadata for {service}") from error
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise RecoveryError(f"Docker returned ambiguous image metadata for {service}")
    return payload[0]


def _runtime_service_evidence(
    context: ComposeContext,
    service: str,
    compose_reference: str,
    expected: dict[str, str],
    candidate: dict[str, object],
) -> dict[str, object]:
    reference = expected["reference"]
    expected_image_id = expected["imageId"]
    if compose_reference != reference:
        raise RecoveryError(f"resolved Compose {service} image does not match the expected reference")
    container = context.inspect_container(service)
    config = container.get("Config")
    state = container.get("State")
    if not isinstance(config, dict) or not isinstance(state, dict) or state.get("Running") is not True:
        raise RecoveryError(f"Compose {service} container is not running")
    labels = config.get("Labels") or {}
    if not isinstance(labels, dict) or (
        labels.get("com.docker.compose.project") != context.project
        or labels.get("com.docker.compose.service") != service
    ):
        raise RecoveryError(f"Compose {service} container labels do not match the isolated project")
    container_id = container.get("Id")
    container_reference = config.get("Image")
    image_id = container.get("Image")
    if not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise RecoveryError(f"Compose {service} container has no full immutable ID")
    if container_reference != reference:
        raise RecoveryError(f"Compose {service} container reference does not match the expected digest")
    if image_id != expected_image_id:
        raise RecoveryError(f"Compose {service} container image ID does not match the expected ID")
    image = _image_inspect(reference, service)
    if image.get("Id") != expected_image_id:
        raise RecoveryError(f"locally resolved {service} image ID does not match the expected ID")
    image_config = image.get("Config")
    image_labels = image_config.get("Labels") if isinstance(image_config, dict) else None
    image_labels = image_labels or {}
    if not isinstance(image_labels, dict):
        raise RecoveryError(f"{service} image labels are invalid")
    oci_version = image_labels.get("org.opencontainers.image.version")
    oci_revision = image_labels.get("org.opencontainers.image.revision")
    if service in OCI_SERVICES:
        if (
            oci_version != candidate["mavenVersion"]
            or oci_revision != candidate["gitCommit"]
        ):
            raise RecoveryError(f"{service} OCI version/revision does not match the candidate")
    else:
        oci_version = None
        oci_revision = None
    return {
        "containerId": container_id,
        "project": context.project,
        "composeReference": compose_reference,
        "containerReference": container_reference,
        "expectedReference": reference,
        "imageId": image_id,
        "expectedImageId": expected_image_id,
        "ociVersion": oci_version,
        "ociRevision": oci_revision,
    }


def _java_identity(context: ComposeContext) -> dict[str, str]:
    completed = context.run(
        ["exec", "-T", "app", "java", "-XshowSettings:properties", "-version"]
    )
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    specification = re.search(
        r"^\s*java\.specification\.version\s*=\s*(\S+)\s*$", output, re.MULTILINE
    )
    runtime = re.search(r"^\s*java\.runtime\.version\s*=\s*(\S+)\s*$", output, re.MULTILINE)
    if (
        specification is None
        or runtime is None
        or specification.group(1) != "21"
        or re.match(r"^21(?:[.+_-]|$)", runtime.group(1)) is None
    ):
        raise RecoveryError("app runtime does not prove Java specification version 21")
    runtime_version = runtime.group(1)
    if len(runtime_version) > 128 or any(character in runtime_version for character in "\r\n\0"):
        raise RecoveryError("app Java runtime version is invalid")
    return {"specificationVersion": "21", "runtimeVersion": runtime_version}


def _published_ports(context: ComposeContext, service: str, container_port: str) -> set[int]:
    published = context.run(["port", service, container_port]).stdout.decode("utf-8").splitlines()
    ports: set[int] = set()
    for endpoint in published:
        try:
            ports.add(int(endpoint.strip().rsplit(":", 1)[1]))
        except (IndexError, ValueError):
            continue
    return ports


def _validated_base_url(context: ComposeContext, value: str, *, formal: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RecoveryError("AC-41 base URL must be an origin without path or credentials")
    try:
        base_port = parsed.port
    except ValueError as error:
        raise RecoveryError("AC-41 base URL has an invalid port") from error
    if base_port is None or base_port < 1024 or base_port > 65535:
        raise RecoveryError("AC-41 base URL must use an explicit unprivileged port")
    if formal:
        try:
            isolated = parsed.scheme == "https" and is_isolated_acceptance_host(
                parsed.hostname or ""
            )
        except ValueError as error:
            raise RecoveryError(str(error)) from error
        if not isolated:
            raise RecoveryError(
                "formal AC-41 requires an isolated reserved HTTPS acceptance origin"
            )
        ports = _published_ports(context, "mcp-public-nginx", "8443")
    else:
        if parsed.scheme != "http" or parsed.hostname not in {
            "localhost", "127.0.0.1", "::1"
        }:
            raise RecoveryError("diagnostic AC-41 requires a plain HTTP loopback origin")
        ports = _published_ports(context, "nginx", "8080")
    if base_port not in ports:
        raise RecoveryError(
            f"base URL port {base_port} is not published by the isolated acceptance ingress"
        )
    return value.rstrip("/")


def _container_database(context: ComposeContext) -> str:
    value = context.exec("mysql", ["printenv", "MYSQL_DATABASE"]).decode("utf-8").strip()
    return validate_database_identifier(value, field="container MYSQL_DATABASE")


def _redis_database(context: ComposeContext) -> int:
    value = context.exec(
        "app",
        ["sh", "-ec", 'printf "%s" "${WEB_STARTER_REDIS_DATABASE:-0}"'],
    ).decode("ascii").strip()
    try:
        database = int(value)
    except ValueError as error:
        raise RecoveryError("app Redis database is not an integer") from error
    if database < 0 or database > 15:
        raise RecoveryError("AC-41 harness only supports Redis databases 0 through 15")
    return database


def _redis_command(context: ComposeContext, database: int, command: str) -> str:
    if command not in {"DBSIZE", "FLUSHDB"}:
        raise RecoveryError("unsupported Redis rehearsal command")
    output = context.exec(
        "redis",
        [
            "sh",
            "-ec",
            'REDISCLI_AUTH="$WEB_STARTER_REDIS_PASSWORD" exec redis-cli --raw -n "$1" "$2"',
            "web-starter-ac41",
            str(database),
            command,
        ],
    ).decode("utf-8").strip()
    return output


def rehearse(args: argparse.Namespace) -> dict[str, object]:
    project = validate_ac41_project(args.compose_project)
    if args.confirm_project != project:
        raise RecoveryError("--confirm-project must exactly match the isolated Compose project")
    expected_database = validate_database_identifier(args.expected_database, field="expected database")
    context = ComposeContext.create(project, args.compose_file, env_file=args.env_file)
    expected_images = _expected_images(args, required=args.mode == "formal")
    candidate: dict[str, object] | None = None
    compose_files: list[str] | None = None
    if args.mode == "formal":
        candidate, compose_files = _formal_candidate(context.files)

    username = os.environ.get("WEB_STARTER_REHEARSAL_USERNAME", "").strip()
    password = os.environ.get("WEB_STARTER_REHEARSAL_PASSWORD", "")
    if not username or not password:
        raise RecoveryError(
            "set WEB_STARTER_REHEARSAL_USERNAME and WEB_STARTER_REHEARSAL_PASSWORD for the isolated stack"
        )
    report_path, checksum_path = prepare_external_report_file(args.report_file)

    for service in SERVICES:
        context.require_container(service)
    configuration = _compose_configuration(context)
    mysql_volume = context.isolated_named_volume_evidence(
        "mysql",
        "/var/lib/mysql",
        expected_compose_volume=configuration["volumes"]["mysql"],
    )
    redis_volume = context.isolated_named_volume_evidence(
        "redis",
        "/data",
        expected_compose_volume=configuration["volumes"]["redis"],
    )
    if mysql_volume["name"] == redis_volume["name"]:
        raise RecoveryError("MySQL and Redis must not share the same named volume")
    runtime_services: dict[str, object] | None = None
    java_identity: dict[str, str] | None = None
    if args.mode == "formal":
        assert candidate is not None
        runtime_services = {
            service: _runtime_service_evidence(
                context,
                service,
                configuration["images"][service],
                expected_images[service],
                candidate,
            )
            for service in SERVICES
        }
        java_identity = _java_identity(context)

    actual_database = _container_database(context)
    if actual_database != expected_database:
        raise RecoveryError(
            f"refusing rehearsal: expected database {expected_database}, container uses {actual_database}"
        )
    base_url = _validated_base_url(context, args.base_url, formal=args.mode == "formal")
    redis_database = _redis_database(context)

    old_session = WebSessionClient(base_url)
    before_loss_me_status = old_session.login(username, password)
    before_fingerprints = stable_domain_fingerprints(context)
    before_audits = audit_counts(context)
    before_redis_keys_text = _redis_command(context, redis_database, "DBSIZE")
    try:
        before_redis_keys = int(before_redis_keys_text)
    except ValueError as error:
        raise RecoveryError("Redis DBSIZE returned an unexpected value") from error
    if before_redis_keys < 1:
        raise RecoveryError("authenticated Web session did not create Redis data; refusing FLUSHDB")

    flush_result = _redis_command(context, redis_database, "FLUSHDB")
    if flush_result != "OK":
        raise RecoveryError("Redis FLUSHDB did not return OK")
    after_flush_size = _redis_command(context, redis_database, "DBSIZE")
    if after_flush_size != "0":
        raise RecoveryError("isolated Redis database was not empty immediately after FLUSHDB")

    expired_session_status, _ = old_session.request("/api/auth/me")
    relogin_me_status, relogin_attempts = relogin_after_redis_loss(
        base_url, username, password
    )
    after_fingerprints = stable_domain_fingerprints(context)
    after_audits = audit_counts(context)

    if expired_session_status != 401:
        raise RecoveryError(
            f"pre-loss Web session remained usable or failed unexpectedly: HTTP {expired_session_status}"
        )
    if after_fingerprints != before_fingerprints:
        changed = sorted(
            key for key in before_fingerprints if before_fingerprints[key] != after_fingerprints.get(key)
        )
        raise RecoveryError("MySQL fact fingerprint changed after Redis loss: " + ", ".join(changed))
    ensure_audit_not_lost(before_audits, after_audits)

    if args.mode == "formal":
        assert candidate is not None
        assert compose_files is not None
        assert runtime_services is not None
        assert java_identity is not None
        report = {
            "schemaVersion": 1,
            "acceptanceId": "V2-AC-41",
            "mode": "formal",
            "status": "PASS",
            "executedAtUtc": utc_now(),
            "candidate": candidate,
            "compose": {
                "project": project,
                "files": compose_files,
                "baseUrl": base_url,
                "mysqlDatabase": actual_database,
            },
            "runtime": {"services": runtime_services, "java": java_identity},
            "isolation": {
                "volumes": {"mysql": mysql_volume, "redis": redis_volume},
                "volumeDeletionPerformed": False,
                "containerDeletionPerformed": False,
                "projectDeletionPerformed": False,
            },
            "redis": {
                "database": redis_database,
                "keysBefore": before_redis_keys,
                "command": "FLUSHDB",
                "result": flush_result,
                "keysImmediatelyAfterFlush": 0,
            },
            "webSession": {
                "authenticatedBeforeLoss": True,
                "beforeLossMeStatus": before_loss_me_status,
                "oldSessionStatusAfterLoss": expired_session_status,
                "reloginSucceeded": True,
                "reloginMeStatus": relogin_me_status,
                "reloginAttempts": relogin_attempts,
            },
            "mysqlFacts": {
                "fingerprintsBefore": before_fingerprints,
                "fingerprintsAfter": after_fingerprints,
            },
            "audit": {"rowsBefore": before_audits, "rowsAfter": after_audits},
            "safety": {
                "redisScope": "SELECTED_DATABASE_ONLY",
                "flushAllExecuted": False,
                "volumeDeletionPerformed": False,
                "containerDeletionPerformed": False,
                "projectDeletionPerformed": False,
            },
        }
        try:
            formal_validator.validate_document(
                report,
                repository_root=REPOSITORY_ROOT,
                expected_images=expected_images,
            )
        except formal_validator.RedisLossEvidenceError as error:
            raise RecoveryError(f"independent formal evidence validation failed: {error}") from error
    else:
        report = {
            "schemaVersion": 1,
            "acceptanceId": "V2-AC-41",
            "mode": "diagnostic",
            "status": "DIAGNOSTIC",
            "formalEvidence": False,
            "executedAtUtc": utc_now(),
            "composeProject": project,
            "baseUrl": base_url,
            "mysqlDatabase": actual_database,
            "isolation": {
                "mysqlNamedVolume": mysql_volume,
                "redisNamedVolume": redis_volume,
                "volumeDeletionPerformed": False,
                "containerDeletionPerformed": False,
                "projectDeletionPerformed": False,
            },
            "redis": {
                "database": redis_database,
                "keysBefore": before_redis_keys,
                "command": "FLUSHDB",
                "result": flush_result,
                "keysImmediatelyAfterFlush": 0,
            },
            "webSession": {
                "beforeLossMeStatus": before_loss_me_status,
                "oldSessionStatusAfterLoss": expired_session_status,
                "reloginMeStatus": relogin_me_status,
                "reloginAttempts": relogin_attempts,
            },
            "mysqlFacts": {
                "fingerprintsBefore": before_fingerprints,
                "fingerprintsAfter": after_fingerprints,
            },
            "audit": {"rowsBefore": before_audits, "rowsAfter": after_audits},
        }

    write_private_json(report_path, report)
    write_private_text(checksum_path, f"{sha256_file(report_path)}  {report_path.name}\n")
    if args.mode == "formal":
        try:
            formal_validator.validate_document_path(
                report_path,
                repository_root=REPOSITORY_ROOT,
                expected_images=expected_images,
            )
        except formal_validator.RedisLossEvidenceError as error:
            raise RecoveryError(f"written formal evidence validation failed: {error}") from error
    return report


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        with isolated_loopback_resolution():
            report = rehearse(args)
    except (RecoveryError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
