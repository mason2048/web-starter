#!/usr/bin/env python3
"""Exercise doctor/up/down against a disposable real Docker Compose project."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
from typing import Any, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


REPORT_NAME = "v2-tooling-lifecycle-runtime.json"
OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
PROJECT = re.compile(r"^web-starter-tooling-[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
REFERENCE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
DOCTOR_LINE = re.compile(r"^(PASS|WARN|FAIL)\s+([^\s]+)\s+(.+)$")
EXPECTED_DOCTOR_CHECKS = {
    "workspace", "maven-wrapper", "launcher", "frontend", "java", "maven",
    "node", "pnpm", "docker-engine", "docker-compose", "compose-wait", "env-file",
    "config:WEB_STARTER_DB_USERNAME", "config:WEB_STARTER_DB_PASSWORD",
    "config:WEB_STARTER_DB_ROOT_PASSWORD", "config:WEB_STARTER_REDIS_PASSWORD",
    "config:WEB_STARTER_TOKEN_PEPPER",
    "config:WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD",
    "port:mysql", "port:redis", "port:app", "port:nginx",
}
SENSITIVE = re.compile(
    r"(?i)(?:wst_(?:pat|svc)_[A-Za-z0-9._~-]{8,}|bearer\s+|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"BEGIN (?:RSA )?PRIVATE KEY)"
)
BUSINESS_FIXTURE_BASE_ID = 8_000_000_000_000_000_000
BUSINESS_FIXTURE_ID_RANGE = 100_000_000_000_000_000
BUSINESS_FIXTURE_NAME = "Tooling persistence fixture"
BUSINESS_FIXTURE_OWNER = "tooling-rehearsal"
BUSINESS_FIXTURE_DESCRIPTION = "AC-37 compose restart persistence"
BUSINESS_FIXTURE_TIMESTAMP = "2026-01-01 00:00:00.000000"
MYSQL_RESULT = re.compile(r"^([0-9]+)\t([0-9a-f]{64})$")


class ToolingRehearsalError(RuntimeError):
    """The disposable tooling runtime did not satisfy the acceptance contract."""


def _safe_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("GIT_", "WEB_STARTER_"))
    }
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C", "LANG": "C"})
    return environment


def _run(
    command: Sequence[str], root: Path, *, timeout: int = 360, accepted: set[int] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    if input_text is not None and len(input_text.encode("utf-8")) > 64 * 1024:
        raise ToolingRehearsalError("tooling command input exceeded its bound")
    input_options: dict[str, Any] = (
        {"stdin": subprocess.DEVNULL} if input_text is None else {"input": input_text}
    )
    completed = subprocess.run(
        list(command), cwd=root, env=_safe_environment(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="strict",
        timeout=timeout, check=False, **input_options,
    )
    if len(completed.stdout.encode()) > 4 * 1024 * 1024 \
            or len(completed.stderr.encode()) > 4 * 1024 * 1024:
        raise ToolingRehearsalError("tooling command output exceeded its bound")
    allowed = {0} if accepted is None else accepted
    if completed.returncode not in allowed:
        raise ToolingRehearsalError(
            f"tooling command failed safely with exit {completed.returncode}: {command[0]}"
        )
    return completed


def _git(root: Path, *arguments: str) -> str:
    return _run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
         *arguments], root, timeout=30,
    ).stdout.strip()


def _candidate(root: Path, commit: str, version: str, tag: str) -> dict[str, str]:
    candidate = root.resolve(strict=True)
    if OBJECT_ID.fullmatch(commit) is None or VERSION.fullmatch(version) is None \
            or tag != "v" + version or "SNAPSHOT" in version.upper():
        raise ToolingRehearsalError("tooling candidate release identity is invalid")
    if _git(candidate, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ToolingRehearsalError("tooling candidate must be clean")
    if _git(candidate, "rev-parse", "HEAD") != commit \
            or _git(candidate, "cat-file", "-t", f"refs/tags/{tag}") != "tag" \
            or _git(candidate, "rev-list", "-n", "1", tag) != commit:
        raise ToolingRehearsalError("tooling candidate commit or annotated tag differs")
    return {
        "gitCommit": commit,
        "gitTree": _git(candidate, "rev-parse", "HEAD^{tree}"),
        "tagObject": _git(candidate, "rev-parse", f"refs/tags/{tag}"),
        "releaseVersion": version,
        "releaseTag": tag,
    }


def _private_empty_directory(path: Path, label: str) -> Path:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise ToolingRehearsalError(f"{label} must be a real directory")
    metadata = requested.stat()
    if (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700) \
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()) \
            or any(requested.iterdir()):
        raise ToolingRehearsalError(f"{label} must be owned mode-0700 and empty")
    return requested.resolve(strict=True)


def _ports() -> dict[str, int]:
    sockets: list[socket.socket] = []
    try:
        result: dict[str, int] = {}
        for name in ("mysql", "redis", "app", "nginx"):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
            result[name] = int(listener.getsockname()[1])
        return result
    finally:
        for listener in sockets:
            listener.close()


def _write_env(
    target: Path, commit: str, app_reference: str, nginx_reference: str,
    mysql_reference: str, redis_reference: str, ports: dict[str, int],
) -> str:
    app_base = app_reference.rsplit("@", 1)[0]
    nginx_base = nginx_reference.rsplit("@", 1)[0]
    image_tag = "candidate-" + commit
    random_values = [secrets.token_urlsafe(36) for _ in range(7)]
    values = {
        "WEB_STARTER_APP_IMAGE": app_base,
        "WEB_STARTER_NGINX_IMAGE": nginx_base,
        "WEB_STARTER_IMAGE_TAG": image_tag,
        "WEB_STARTER_MYSQL_IMAGE": mysql_reference,
        "WEB_STARTER_REDIS_IMAGE": redis_reference,
        "WEB_STARTER_RUNTIME_MODE": "development",
        "WEB_STARTER_GIT_COMMIT": commit,
        "WEB_STARTER_DB_ROOT_PASSWORD": random_values[0],
        "WEB_STARTER_DB_USERNAME": "web_starter",
        "WEB_STARTER_DB_PASSWORD": random_values[1],
        "WEB_STARTER_REDIS_PASSWORD": random_values[2],
        "WEB_STARTER_TOKEN_PEPPER": random_values[3],
        "WEB_STARTER_CREDENTIAL_PEPPER": random_values[4],
        "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": random_values[5],
        "WEB_STARTER_MANAGEMENT_USERNAME": "tooling_ops",
        "WEB_STARTER_MANAGEMENT_PASSWORD": random_values[6],
        "WEB_STARTER_OAUTH_ISSUER": f"http://127.0.0.1:{ports['nginx']}",
        "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": f"http://127.0.0.1:{ports['nginx']}/mcp",
        "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "true",
        "WEB_STARTER_INTERNAL_TOKENS_ENABLED": "true",
        "WEB_STARTER_MCP_ALLOWED_HOSTS": "127.0.0.1,127.0.0.1:*",
        "WEB_STARTER_MCP_ALLOWED_ORIGINS": f"http://127.0.0.1:{ports['nginx']}",
        "WEB_STARTER_COOKIE_SECURE": "false",
        "WEB_STARTER_HTTP_BIND_ADDRESS": "127.0.0.1",
        "WEB_STARTER_DB_PORT": str(ports["mysql"]),
        "WEB_STARTER_REDIS_PORT": str(ports["redis"]),
        "WEB_STARTER_SERVER_PORT": str(ports["app"]),
        "WEB_STARTER_HTTP_PORT": str(ports["nginx"]),
        "WEB_STARTER_LOG_FORMAT": "ecs",
        "WEB_STARTER_LOG_LEVEL": "INFO",
    }
    payload = "".join(f"{name}={value}\n" for name, value in values.items()).encode()
    descriptor = os.open(
        target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
    return random_values[5]


def _remove_bootstrap_password(target: Path, expected_password: str) -> None:
    payload = target.read_text(encoding="utf-8")
    expected = f"WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD={expected_password}\n"
    if payload.count(expected) != 1:
        raise ToolingRehearsalError("bootstrap password environment entry is not exact")
    updated = payload.replace(expected, "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD=\n")
    replacement = target.with_name(target.name + ".next")
    descriptor = os.open(
        replacement,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(replacement, target)
    except BaseException:
        replacement.unlink(missing_ok=True)
        raise
    if expected_password in target.read_text(encoding="utf-8"):
        raise ToolingRehearsalError("bootstrap password remained in the restart environment")


def _login_snapshot(base_url: str, username: str, password: str) -> dict[str, Any]:
    cookies = CookieJar()
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(cookies))

    def request(path: str, method: str = "GET", body: dict[str, str] | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        message = Request(
            base_url + path,
            data=payload,
            headers=request_headers,
            method=method,
        )
        try:
            with opener.open(message, timeout=20) as response:
                status = response.status
                raw = response.read()
        except HTTPError as error:
            status = error.code
            raw = error.read()
        except URLError as error:
            raise ToolingRehearsalError("bootstrap login transport failed") from error
        try:
            document = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ToolingRehearsalError("bootstrap login response is not JSON") from error
        if not isinstance(document, dict):
            raise ToolingRehearsalError("bootstrap login response is not an object")
        return status, document

    csrf_status, csrf = request("/api/auth/csrf")
    csrf_data = csrf.get("data")
    if (
        csrf_status != 200
        or not isinstance(csrf_data, dict)
        or not isinstance(csrf_data.get("token"), str)
        or len(csrf_data["token"]) < 16
    ):
        raise ToolingRehearsalError("bootstrap login CSRF setup failed")
    header = str(csrf_data.get("headerName") or "X-XSRF-TOKEN")
    status, login = request(
        "/api/auth/login",
        "POST",
        {"username": username, "password": password},
        {header: csrf_data["token"]},
    )
    caller = login.get("data")
    has_session = any(cookie.name == "WEB_STARTER_SESSION" for cookie in cookies)
    if (
        status != 200
        or not isinstance(caller, dict)
        or not str(caller.get("subjectId", "")).isdigit()
        or not has_session
    ):
        raise ToolingRehearsalError("bootstrap administrator login failed")
    return {"status": status, "sessionCookie": True}


def _admin_password_hash(
    root: Path, env_file: Path, project: str, username: str,
) -> str:
    if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", username) is None:
        raise ToolingRehearsalError("bootstrap administrator username is unsafe")
    shell = (
        'export MYSQL_PWD="${MYSQL_PASSWORD:?}"; '
        'exec mysql --protocol=socket --batch --skip-column-names --raw '
        '--default-character-set=utf8mb4 --user="${MYSQL_USER:?}" "${MYSQL_DATABASE:?}"'
    )
    query = (
        "SELECT COUNT(*), COALESCE(LOWER(MAX(SHA2(password_hash, 256))), '') "
        f"FROM sys_user WHERE username = '{username}' AND deleted = 0;\n"
    )
    completed = _run([
        "docker", "compose", "--project-name", project, "--env-file", str(env_file),
        "-f", str(root / "compose.yaml"), "-f", str(root / "compose.dev.yaml"),
        "exec", "-T", "mysql", "sh", "-ceu", shell,
    ], root, timeout=60, input_text=query)
    lines = [line for line in completed.stdout.splitlines() if line]
    match = MYSQL_RESULT.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None or int(match.group(1)) != 1:
        raise ToolingRehearsalError("bootstrap administrator password hash query differs")
    return match.group(2)


def _runtime_log_snapshot(
    root: Path, env_file: Path, project: str, bootstrap_password: str,
) -> dict[str, Any]:
    completed = _run([
        "docker", "compose", "--project-name", project, "--env-file", str(env_file),
        "-f", str(root / "compose.yaml"), "-f", str(root / "compose.dev.yaml"),
        "logs", "--no-color", "--no-log-prefix",
    ], root, timeout=60)
    payload = (completed.stdout + completed.stderr).encode("utf-8")
    if bootstrap_password.encode("utf-8") in payload:
        raise ToolingRehearsalError("bootstrap password appeared in runtime logs")
    return {
        "byteCount": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "secretMatches": 0,
    }


def _docker_lines(arguments: Sequence[str], root: Path) -> list[str]:
    return [line for line in _run(["docker", *arguments], root, timeout=60).stdout.splitlines() if line]


def _snapshot(root: Path, project: str) -> dict[str, Any]:
    rows = _docker_lines([
        "ps", "--all", "--filter", f"label=com.docker.compose.project={project}",
        "--format", '{{.ID}}|{{.Label "com.docker.compose.service"}}',
    ], root)
    containers: dict[str, dict[str, str]] = {}
    for row in rows:
        identifier, service = row.split("|", 1)
        inspected = _docker_lines([
            "inspect", "--format",
            '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.Image}}',
            identifier,
        ], root)
        if len(inspected) != 1 or service in containers:
            raise ToolingRehearsalError("tooling Compose container inventory is ambiguous")
        status, health, image_id = inspected[0].split("|", 2)
        containers[service] = {"status": status, "health": health, "imageId": image_id}
    return {
        "containers": dict(sorted(containers.items())),
        "volumes": sorted(_docker_lines([
            "volume", "ls", "--filter", f"label=com.docker.compose.project={project}",
            "--format", "{{.Name}}",
        ], root)),
        "networks": sorted(_docker_lines([
            "network", "ls", "--filter", f"label=com.docker.compose.project={project}",
            "--format", "{{.Name}}",
        ], root)),
    }


def _doctor_checks(output: str) -> dict[str, dict[str, str]]:
    checks: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        match = DOCTOR_LINE.fullmatch(line)
        if match is None:
            continue
        status, name, detail = match.groups()
        if name in checks:
            raise ToolingRehearsalError("doctor emitted a duplicate check")
        action = "none"
        marker = "; action: "
        if marker in detail:
            detail, action = detail.split(marker, 1)
        checks[name] = {"status": status, "detail": detail, "action": action}
    if set(checks) != EXPECTED_DOCTOR_CHECKS \
            or any(value["status"] != "PASS" for value in checks.values()) \
            or "DOCTOR PASS failures=0 warnings=0" not in output:
        raise ToolingRehearsalError("doctor did not produce the exact all-PASS inventory")
    if SENSITIVE.search(output):
        raise ToolingRehearsalError("doctor output contains credential-shaped material")
    return checks


def _tool(root: Path, env_file: Path, project: str, *arguments: str,
          accepted: set[int] | None = None, timeout: int = 420) -> subprocess.CompletedProcess[str]:
    command = [
        str(root / "bin/web-starter"), *arguments,
        "--workspace", str(root), "--env-file", str(env_file),
    ]
    if arguments and arguments[0] in {"up", "down"}:
        command.extend(("--project-name", project))
    return _run(command, root, timeout=timeout, accepted=accepted)


def _compose_cleanup(root: Path, env_file: Path, project: str) -> None:
    if not env_file.exists():
        return
    _run([
        "docker", "compose", "--project-name", project, "--env-file", str(env_file),
        "-f", str(root / "compose.yaml"), "-f", str(root / "compose.dev.yaml"),
        "down", "--volumes", "--remove-orphans",
    ], root, timeout=180, accepted={0, 1})


def _business_fixture(project: str) -> tuple[int, str]:
    if PROJECT.fullmatch(project) is None:
        raise ToolingRehearsalError("business fixture Compose project is invalid")
    digest = hashlib.sha256(project.encode("utf-8")).hexdigest()
    fixture_id = BUSINESS_FIXTURE_BASE_ID + (
        int(digest[:16], 16) % BUSINESS_FIXTURE_ID_RANGE
    )
    return fixture_id, "TOOLING_" + digest[:16].upper()


def _expected_business_sha256(fixture_id: int, fixture_code: str) -> str:
    fields = (
        str(fixture_id), BUSINESS_FIXTURE_NAME, fixture_code, str(fixture_id),
        BUSINESS_FIXTURE_OWNER, "ACTIVE", BUSINESS_FIXTURE_DESCRIPTION, "0",
        BUSINESS_FIXTURE_TIMESTAMP, BUSINESS_FIXTURE_TIMESTAMP, "0",
    )
    return hashlib.sha256("\x1f".join(fields).encode("utf-8")).hexdigest()


def _business_sql(fixture_id: int, fixture_code: str, create: bool) -> str:
    statements: list[str] = []
    if create:
        statements.extend((
            "START TRANSACTION;",
            "INSERT INTO biz_project "
            "(id, name, code, owner_id, owner_name, status, description, version, "
            "created_at, updated_at, deleted) VALUES "
            f"({fixture_id}, '{BUSINESS_FIXTURE_NAME}', '{fixture_code}', {fixture_id}, "
            f"'{BUSINESS_FIXTURE_OWNER}', 'ACTIVE', '{BUSINESS_FIXTURE_DESCRIPTION}', 0, "
            f"TIMESTAMP('{BUSINESS_FIXTURE_TIMESTAMP}'), "
            f"TIMESTAMP('{BUSINESS_FIXTURE_TIMESTAMP}'), 0);",
            "COMMIT;",
        ))
    statements.append(
        "SELECT COUNT(*), COALESCE(LOWER(MAX(SHA2(CONCAT_WS(CHAR(31), "
        "CAST(id AS CHAR), name, code, CAST(owner_id AS CHAR), owner_name, status, "
        "description, CAST(version AS CHAR), "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s.%f'), "
        "DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s.%f'), CAST(deleted AS CHAR)), 256))), '') "
        f"FROM biz_project WHERE id = {fixture_id} AND code = '{fixture_code}';"
    )
    return "\n".join(statements) + "\n"


def _business_snapshot(
    root: Path, env_file: Path, project: str, *, create: bool,
) -> dict[str, Any]:
    fixture_id, fixture_code = _business_fixture(project)
    shell = (
        'export MYSQL_PWD="${MYSQL_PASSWORD:?}"; '
        'exec mysql --protocol=socket --batch --skip-column-names --raw '
        '--default-character-set=utf8mb4 --user="${MYSQL_USER:?}" "${MYSQL_DATABASE:?}"'
    )
    completed = _run([
        "docker", "compose", "--project-name", project, "--env-file", str(env_file),
        "-f", str(root / "compose.yaml"), "-f", str(root / "compose.dev.yaml"),
        "exec", "-T", "mysql", "sh", "-ceu", shell,
    ], root, timeout=60, input_text=_business_sql(fixture_id, fixture_code, create))
    lines = [line for line in completed.stdout.splitlines() if line]
    match = MYSQL_RESULT.fullmatch(lines[0]) if len(lines) == 1 else None
    expected_sha256 = _expected_business_sha256(fixture_id, fixture_code)
    if match is None or int(match.group(1)) != 1 or match.group(2) != expected_sha256:
        raise ToolingRehearsalError("business persistence fixture query differs")
    return {
        "fixtureId": fixture_id,
        "fixtureCode": fixture_code,
        "rowCount": 1,
        "rowSha256": expected_sha256,
    }


def rehearse(args: argparse.Namespace) -> dict[str, Any]:
    root = args.candidate_root.resolve(strict=True)
    evidence_dir = _private_empty_directory(args.evidence_dir, "tooling evidence directory")
    runtime_dir = _private_empty_directory(args.runtime_dir, "tooling runtime directory")
    if evidence_dir == runtime_dir or evidence_dir in runtime_dir.parents \
            or runtime_dir in evidence_dir.parents:
        raise ToolingRehearsalError("tooling evidence and runtime directories must differ")
    for reference in (
        args.app_reference, args.nginx_reference, args.mysql_reference, args.redis_reference,
    ):
        if REFERENCE.fullmatch(reference) is None:
            raise ToolingRehearsalError("tooling runtime images must be digest references")
    if PROJECT.fullmatch(args.compose_project) is None:
        raise ToolingRehearsalError("tooling Compose project name is invalid")
    candidate = _candidate(root, args.commit, args.version, args.tag)
    env_file = runtime_dir / "tooling.env"
    ports = _ports()
    bootstrap_password = _write_env(
        env_file, args.commit, args.app_reference, args.nginx_reference,
        args.mysql_reference, args.redis_reference, ports,
    )
    report_path = evidence_dir / REPORT_NAME
    try:
        initial = _snapshot(root, args.compose_project)
        if any(initial.values()):
            raise ToolingRehearsalError("tooling Compose project is not initially empty")
        _run([
            str(root / "mvnw"), "-B", "-ntp", "-pl", "web-starter-tooling", "-am",
            "package", "-DskipTests",
        ], root, timeout=600)
        doctor = _tool(root, env_file, args.compose_project, "doctor")
        doctor_checks = _doctor_checks(doctor.stdout)

        first_up = _tool(
            root, env_file, args.compose_project, "up", "--no-build",
            "--timeout-seconds", "300", timeout=600,
        )
        if "READY project=" + args.compose_project not in first_up.stdout:
            raise ToolingRehearsalError("tooling up did not report readiness")
        first_up_snapshot = _snapshot(root, args.compose_project)
        first_login = _login_snapshot(
            f"http://127.0.0.1:{ports['nginx']}", "admin", bootstrap_password,
        )
        password_hash_before = _admin_password_hash(
            root, env_file, args.compose_project, "admin",
        )
        first_logs = _runtime_log_snapshot(
            root, env_file, args.compose_project, bootstrap_password,
        )
        business_before_restart = _business_snapshot(
            root, env_file, args.compose_project, create=True,
        )

        default_down = _tool(root, env_file, args.compose_project, "down")
        if "volumes=preserved" not in default_down.stdout:
            raise ToolingRehearsalError("default tooling down did not report preserved volumes")
        default_down_snapshot = _snapshot(root, args.compose_project)

        without_volumes = _tool(
            root, env_file, args.compose_project, "down",
            "--confirm-delete-volumes", args.compose_project, accepted={2},
        )
        wrong_confirmation = _tool(
            root, env_file, args.compose_project, "down", "--volumes",
            "--confirm-delete-volumes", args.compose_project + "-wrong", accepted={2},
        )
        missing_confirmation = _tool(
            root, env_file, args.compose_project, "down", "--volumes", accepted={3},
        )
        after_rejections = _snapshot(root, args.compose_project)

        _remove_bootstrap_password(env_file, bootstrap_password)
        second_up = _tool(
            root, env_file, args.compose_project, "up", "--no-build",
            "--timeout-seconds", "300", timeout=600,
        )
        if "READY project=" + args.compose_project not in second_up.stdout:
            raise ToolingRehearsalError("tooling restart did not report readiness")
        second_up_snapshot = _snapshot(root, args.compose_project)
        second_login = _login_snapshot(
            f"http://127.0.0.1:{ports['nginx']}", "admin", bootstrap_password,
        )
        password_hash_after = _admin_password_hash(
            root, env_file, args.compose_project, "admin",
        )
        if password_hash_after != password_hash_before:
            raise ToolingRehearsalError(
                "bootstrap administrator password changed after password removal and restart"
            )
        second_logs = _runtime_log_snapshot(
            root, env_file, args.compose_project, bootstrap_password,
        )
        business_after_restart = _business_snapshot(
            root, env_file, args.compose_project, create=False,
        )
        if business_after_restart != business_before_restart:
            raise ToolingRehearsalError("business data changed across tooling restart")

        explicit_delete = _tool(
            root, env_file, args.compose_project, "down", "--volumes",
            "--confirm-delete-volumes", args.compose_project,
        )
        if "volumes=deleted-after-confirmation" not in explicit_delete.stdout:
            raise ToolingRehearsalError("confirmed tooling down did not report deleted volumes")
        final = _snapshot(root, args.compose_project)
        if any(final.values()):
            raise ToolingRehearsalError("tooling Compose project left resources after confirmed down")

        report = {
            "schemaVersion": 1,
            "evidenceType": "toolingLifecycleRuntime",
            "status": "PASS",
            "acceptanceIds": ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"],
            "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "candidate": candidate,
            "runtime": {
                "composeProject": args.compose_project,
                "images": {
                    "app": args.app_reference,
                    "nginx": args.nginx_reference,
                    "mysql": args.mysql_reference,
                    "redis": args.redis_reference,
                },
                "ports": ports,
            },
            "doctor": {
                "checks": doctor_checks,
                "outputSha256": hashlib.sha256(doctor.stdout.encode()).hexdigest(),
            },
            "lifecycle": {
                "initial": initial,
                "firstUp": first_up_snapshot,
                "businessPersistence": {
                    "beforeRestart": business_before_restart,
                    "afterRestart": business_after_restart,
                },
                "bootstrapCredential": {
                    "firstLogin": first_login,
                    "passwordHashBeforeRestart": password_hash_before,
                    "environmentPasswordRemovedBeforeRestart": True,
                    "secondLogin": second_login,
                    "passwordHashAfterRestart": password_hash_after,
                    "firstRuntimeLogs": first_logs,
                    "secondRuntimeLogs": second_logs,
                },
                "defaultDown": default_down_snapshot,
                "rejections": {
                    "confirmationWithoutVolumes": without_volumes.returncode,
                    "wrongProjectConfirmation": wrong_confirmation.returncode,
                    "missingNonInteractiveConfirmation": missing_confirmation.returncode,
                },
                "afterRejections": after_rejections,
                "secondUp": second_up_snapshot,
                "confirmedVolumeDelete": final,
            },
        }
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        if SENSITIVE.search(payload.decode(errors="strict")):
            raise ToolingRehearsalError("tooling report contains credential-shaped material")
        descriptor = os.open(
            report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
        return report
    finally:
        try:
            _compose_cleanup(root, env_file, args.compose_project)
        finally:
            env_file.unlink(missing_ok=True)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--app-reference", required=True)
    parser.add_argument("--nginx-reference", required=True)
    parser.add_argument("--mysql-reference", required=True)
    parser.add_argument("--redis-reference", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        report = rehearse(parse_arguments(sys.argv[1:] if argv is None else argv))
    except (ToolingRehearsalError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL tooling-lifecycle-rehearsal: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "acceptanceIds": report["acceptanceIds"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
