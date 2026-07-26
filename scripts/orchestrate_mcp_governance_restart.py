#!/usr/bin/env python3
"""Perform and attest the graceful app restart used by V2-AC-34.

This helper is intentionally Docker-specific.  It stops and starts only the
already verified application container, records the old/stopped/new process
states, and proves that the Redis container and one short-lived marker survive
the restart unchanged.  It never receives or emits an MCP bearer token.
"""

from __future__ import annotations

import argparse
import calendar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import shutil
import signal
import stat
import subprocess
import time
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
RECEIPT_FILE = "mcp-governance-restart-receipt.json"
STATE_FILE = "mcp-governance-shutdown-probe.properties"
APP_SERVICE = "app"
REDIS_SERVICE = "redis"
PRIVATE_NGINX_SERVICE = "nginx"
PUBLIC_NGINX_SERVICE = "mcp-public-nginx"
STOP_TIMEOUT_SECONDS = 40
COMMAND_TIMEOUT_SECONDS = 55
HEALTH_TIMEOUT_SECONDS = 90
MARKER_TTL_SECONDS = 180
PROBE_MAX_AGE_SECONDS = 40
MAX_COMMAND_STDOUT = 2 * 1024 * 1024
MAX_COMMAND_STDERR = 256 * 1024
MAX_STATE_BYTES = 2 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
PRODUCER_FILE = "orchestrate_mcp_governance_restart.py"

HEX_ID = re.compile(r"[0-9a-f]{64}")
OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VERSION = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
TRACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
IMAGE_REFERENCE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
DOCKER_TIMESTAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z"
)
STATE = re.compile(
    rb"schemaVersion=1\n"
    rb"sessionId=[A-Za-z0-9._~-]{8,512}\n"
    rb"createdAtEpochMillis=([1-9][0-9]{12})\n"
    rb"tracePrefix=([A-Za-z0-9][A-Za-z0-9._-]{0,31})\n"
    rb"expectedIdleTtlSeconds=50\n"
    rb"expectedAbsoluteTtlSeconds=60\n"
)
DOCKER_INSPECT_TEMPLATE = (
    '{"id":{{json .Id}},"imageId":{{json .Image}},'
    '"imageReference":{{json .Config.Image}},"labels":{{json .Config.Labels}},'
    '"stopSignal":{{json (index .Config "StopSignal")}},'
    '"state":{{json .State}},"restartCount":{{json .RestartCount}},'
    '"mounts":{{json .Mounts}}}'
)


class RestartEvidenceError(RuntimeError):
    """Raised when a safe, graceful, identity-bound restart is not proven."""


@dataclass(frozen=True)
class FileSnapshot:
    payload: bytes
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    mode: int
    uid: int
    links: int


@dataclass(frozen=True)
class ContainerSnapshot:
    container_id: str
    image_id: str
    image_reference: str
    labels: Mapping[str, str]
    stop_signal: str
    running: bool
    status: str
    pid: int
    started_at: str
    finished_at: str
    exit_code: int
    oom_killed: bool
    dead: bool
    error: str
    health: str | None
    restart_count: int
    mounts: tuple[tuple[str, str, str, bool], ...]


@dataclass
class ReceiptReservation:
    parent: Path
    directory: int
    temporary: int
    temporary_name: str
    final_name: str
    directory_device: int
    directory_inode: int
    device: int
    inode: int
    published: bool = False


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _trusted_docker() -> str:
    executable = shutil.which(
        "docker", path="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"
    )
    if executable is None:
        raise RestartEvidenceError("Docker is required for MCP governance restart evidence")
    return executable


def _command_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in (
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    if extra:
        environment.update(extra)
    return environment


def _run_bounded(
    command: Sequence[str],
    *,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if timeout_seconds <= 0:
        raise RestartEvidenceError("command timeout must be positive")
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment) if environment is not None else _command_environment(),
            start_new_session=True,
        )
    except OSError as exception:
        raise RestartEvidenceError("unable to start Docker evidence command") from exception
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, (stdout, MAX_COMMAND_STDOUT, "stdout"))
    selector.register(process.stderr, selectors.EVENT_READ, (stderr, MAX_COMMAND_STDERR, "stderr"))
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RestartEvidenceError("Docker evidence command timed out")
            events = selector.select(min(remaining, 1.0))
            if not events and process.poll() is not None:
                # Drain EOF after the child exits.
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _ in events:
                destination, maximum, label = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(destination) + len(chunk) > maximum:
                    raise RestartEvidenceError(
                        f"Docker evidence command {label} exceeded its byte limit"
                    )
                destination.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RestartEvidenceError("Docker evidence command timed out")
        return_code = process.wait(timeout=remaining)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(list(command), return_code, bytes(stdout), bytes(stderr))


def _docker(
    *arguments: str,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
    extra_environment: Mapping[str, str] | None = None,
) -> bytes:
    result = _run_bounded(
        [_trusted_docker(), *arguments],
        timeout_seconds=timeout_seconds,
        environment=_command_environment(extra_environment),
    )
    if result.returncode != 0:
        operation = arguments[0] if arguments and arguments[0] in {
            "inspect", "exec", "stop", "start"
        } else "operation"
        raise RestartEvidenceError(
            f"Docker {operation} could not complete the restart evidence operation"
        )
    return result.stdout


def _strict_json(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_reject_constant)
    except UnicodeDecodeError as exception:
        raise RestartEvidenceError(f"{label} is not UTF-8 JSON") from exception
    except (json.JSONDecodeError, TypeError, ValueError) as exception:
        raise RestartEvidenceError(f"{label} is not valid JSON") from exception


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RestartEvidenceError("Docker inspect JSON repeats a field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RestartEvidenceError(f"Docker inspect JSON contains non-finite value {value}")


def _parse_timestamp(value: str, label: str, *, allow_zero: bool = False) -> int | None:
    if value == "0001-01-01T00:00:00Z":
        if allow_zero:
            return None
        raise RestartEvidenceError(f"{label} timestamp is invalid")
    if not isinstance(value, str):
        raise RestartEvidenceError(f"{label} timestamp is invalid")
    match = DOCKER_TIMESTAMP.fullmatch(value)
    if match is None:
        raise RestartEvidenceError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exception:
        raise RestartEvidenceError(f"{label} timestamp is invalid") from exception
    fraction = (match.group(2) or "").ljust(9, "0")
    return calendar.timegm(parsed.utctimetuple()) * 1_000_000_000 + int(fraction)


def _snapshot_container(container_id: str) -> ContainerSnapshot:
    if HEX_ID.fullmatch(container_id) is None:
        raise RestartEvidenceError("container ID must be an exact lowercase 64-character ID")
    document = _strict_json(
        _docker(
            "inspect", "--type", "container", "--format",
            DOCKER_INSPECT_TEMPLATE, container_id,
        ),
        "Docker inspect output",
    )
    if not isinstance(document, dict) or set(document) != {
        "id", "imageId", "imageReference", "labels", "stopSignal",
        "state", "restartCount", "mounts"
    }:
        raise RestartEvidenceError("Docker inspect output has an unexpected envelope")
    labels = document["labels"]
    state = document["state"]
    mounts = document["mounts"]
    stop_signal = document["stopSignal"]
    if stop_signal is None:
        stop_signal = ""
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
    ):
        raise RestartEvidenceError("container labels are invalid")
    if not isinstance(state, dict) or not isinstance(mounts, list):
        raise RestartEvidenceError("container state or mounts are invalid")
    health_document = state.get("Health")
    health = health_document.get("Status") if isinstance(health_document, dict) else None
    normalized_mounts: list[tuple[str, str, str, bool]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            raise RestartEvidenceError("container mount is invalid")
        name = mount.get("Name", "")
        destination = mount.get("Destination")
        mount_type = mount.get("Type")
        writable = mount.get("RW")
        if not isinstance(name, str) or not isinstance(destination, str) \
                or not isinstance(mount_type, str) or not isinstance(writable, bool):
            raise RestartEvidenceError("container mount identity is invalid")
        normalized_mounts.append((name, destination, mount_type, writable))
    snapshot = ContainerSnapshot(
        container_id=document["id"],
        image_id=document["imageId"],
        image_reference=document["imageReference"],
        labels=dict(labels),
        stop_signal=stop_signal,
        running=state.get("Running"),
        status=state.get("Status"),
        pid=state.get("Pid"),
        started_at=state.get("StartedAt"),
        finished_at=state.get("FinishedAt"),
        exit_code=state.get("ExitCode"),
        oom_killed=state.get("OOMKilled"),
        dead=state.get("Dead"),
        error=state.get("Error"),
        health=health,
        restart_count=document["restartCount"],
        mounts=tuple(sorted(normalized_mounts)),
    )
    if snapshot.container_id != container_id or HEX_ID.fullmatch(snapshot.image_id.removeprefix("sha256:")) is None:
        raise RestartEvidenceError("container or image identity is invalid")
    if not isinstance(snapshot.image_reference, str) or not snapshot.image_reference:
        raise RestartEvidenceError("container image reference is invalid")
    if not isinstance(snapshot.stop_signal, str) or len(snapshot.stop_signal) > 32 \
            or any(character in snapshot.stop_signal for character in "\r\n\0"):
        raise RestartEvidenceError("container stop signal is invalid")
    if not isinstance(snapshot.running, bool) or not isinstance(snapshot.status, str) \
            or not isinstance(snapshot.pid, int) or snapshot.pid < 0 \
            or not isinstance(snapshot.exit_code, int) \
            or not isinstance(snapshot.oom_killed, bool) or not isinstance(snapshot.dead, bool) \
            or not isinstance(snapshot.error, str) or not isinstance(snapshot.restart_count, int) \
            or snapshot.restart_count < 0:
        raise RestartEvidenceError("container process state is invalid")
    _parse_timestamp(snapshot.started_at, "container startedAt", allow_zero=True)
    _parse_timestamp(snapshot.finished_at, "container finishedAt", allow_zero=True)
    return snapshot


def _require_identity(
    snapshot: ContainerSnapshot,
    *,
    container_id: str,
    image_id: str,
    image_reference: str,
    project: str,
    service: str,
    version: str | None = None,
    commit: str | None = None,
) -> None:
    if snapshot.container_id != container_id or snapshot.image_id != image_id \
            or snapshot.image_reference != image_reference:
        raise RestartEvidenceError(f"{service} container or image identity changed")
    if snapshot.labels.get("com.docker.compose.project") != project \
            or snapshot.labels.get("com.docker.compose.service") != service:
        raise RestartEvidenceError(f"{service} does not belong to the expected Compose project")
    if version is not None and snapshot.labels.get("org.opencontainers.image.version") != version:
        raise RestartEvidenceError("app OCI version label differs from the candidate")
    if commit is not None and snapshot.labels.get("org.opencontainers.image.revision") != commit:
        raise RestartEvidenceError("app OCI revision label differs from the candidate")


def _require_running(snapshot: ContainerSnapshot, label: str, *, healthy: bool) -> None:
    if not snapshot.running or snapshot.status != "running" or snapshot.pid <= 0 \
            or snapshot.dead or snapshot.oom_killed or snapshot.error:
        raise RestartEvidenceError(f"{label} is not a clean running container")
    if _parse_timestamp(snapshot.started_at, f"{label} startedAt") is None:
        raise RestartEvidenceError(f"{label} has no start timestamp")
    if healthy and snapshot.health != "healthy":
        raise RestartEvidenceError(f"{label} is not healthy")


def _resolved_stop_signal(snapshot: ContainerSnapshot) -> str:
    # Docker uses SIGTERM when Config.StopSignal is empty. Any explicit
    # alternative changes the shutdown contract and is rejected.
    if snapshot.stop_signal not in {"", "SIGTERM"}:
        raise RestartEvidenceError("app container stop signal must resolve to SIGTERM")
    return "SIGTERM"


def _require_redis_volume(snapshot: ContainerSnapshot) -> None:
    data_mounts = [
        mount for mount in snapshot.mounts
        if mount[1] == "/data" and mount[2] == "volume" and mount[3] is True and mount[0]
    ]
    if len(data_mounts) != 1:
        raise RestartEvidenceError("Redis must use exactly one writable named /data volume")


def _redis_cli(container_id: str, password: str, *arguments: str) -> str:
    if not password or any(character in password for character in "\r\n\0"):
        raise RestartEvidenceError("Redis password is missing or malformed")
    payload = _docker(
        "exec", "--env", "REDISCLI_AUTH", container_id,
        "redis-cli", "--raw", *arguments,
        extra_environment={"REDISCLI_AUTH": password},
    )
    try:
        value = payload.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise RestartEvidenceError("Redis continuity result is not valid UTF-8") from exception
    if "AUTH" in value.upper() or "ERROR" in value.upper():
        raise RestartEvidenceError("Redis continuity command failed")
    return value


def _snapshot_file_at(directory: int, name: str, maximum: int, label: str) -> FileSnapshot:
    if not name or "/" in name or "\0" in name or name in {".", ".."}:
        raise RestartEvidenceError(f"{label} filename is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as exception:
        raise RestartEvidenceError(f"cannot open {label}") from exception
    try:
        before_path = os.stat(name, dir_fd=directory, follow_symlinks=False)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum \
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid() \
                or before.st_nlink != 1 \
                or (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino):
            raise RestartEvidenceError(f"{label} is not an owned private regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
            item.st_ctime_ns, stat.S_IMODE(item.st_mode), item.st_uid, item.st_nlink,
        )
        if len(payload) != before.st_size or identity(before) != identity(after):
            raise RestartEvidenceError(f"{label} changed while being read")
        return FileSnapshot(
            payload, before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns, stat.S_IMODE(before.st_mode),
            before.st_uid, before.st_nlink,
        )
    finally:
        os.close(descriptor)


def _snapshot_executing_source(repository: Path) -> FileSnapshot:
    source = Path(__file__).expanduser().absolute()
    expected = repository / "scripts" / PRODUCER_FILE
    if source != expected or expected.parent.is_symlink():
        raise RestartEvidenceError(
            "restart producer must execute from the exact candidate scripts directory"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = os.lstat(source)
        descriptor = os.open(source, flags)
    except OSError as exception:
        raise RestartEvidenceError("cannot open the executing restart producer") from exception
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 \
                or before.st_size > MAX_SOURCE_BYTES or before.st_uid != os.geteuid() \
                or before.st_nlink != 1 \
                or (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino):
            raise RestartEvidenceError(
                "executing restart producer is not an owned regular candidate file"
            )
        chunks: list[bytes] = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        after_path = os.lstat(source)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
            item.st_ctime_ns, stat.S_IMODE(item.st_mode), item.st_uid, item.st_nlink,
        )
        if len(payload) != before.st_size or identity(before) != identity(after) \
                or (after_path.st_dev, after_path.st_ino) != (after.st_dev, after.st_ino):
            raise RestartEvidenceError("executing restart producer changed while being read")
        return FileSnapshot(
            payload, before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns, stat.S_IMODE(before.st_mode),
            before.st_uid, before.st_nlink,
        )
    finally:
        os.close(descriptor)


def _require_unchanged_executing_source(
    repository: Path, snapshot: FileSnapshot
) -> None:
    if _snapshot_executing_source(repository) != snapshot:
        raise RestartEvidenceError("executing restart producer changed during restart")


def _unchanged_file_at(
    directory: int, name: str, snapshot: FileSnapshot, label: str
) -> None:
    current = _snapshot_file_at(directory, name, max(snapshot.size, 1), label)
    if current != snapshot:
        raise RestartEvidenceError(f"{label} changed during restart")


def _wait_for_healthy(container_id: str) -> ContainerSnapshot:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        snapshot = _snapshot_container(container_id)
        if snapshot.running and snapshot.status == "running" and snapshot.health == "healthy":
            return snapshot
        if snapshot.dead or snapshot.oom_killed \
                or snapshot.status in {"dead", "removing"}:
            raise RestartEvidenceError("restarted app entered a terminal unhealthy state")
        time.sleep(0.5)
    raise RestartEvidenceError("restarted app did not become healthy before timeout")


def _reserve_receipt(path: Path, repository: Path) -> ReceiptReservation:
    requested = path.expanduser().absolute()
    if requested.name != RECEIPT_FILE or requested.parent.is_symlink():
        raise RestartEvidenceError("restart receipt must use the fixed filename")
    parent = requested.parent.resolve(strict=True)
    if _inside(parent, repository) or _inside(repository, parent):
        raise RestartEvidenceError("restart receipt must stay outside the Git workspace")
    before_path = os.lstat(parent)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(parent, directory_flags)
    metadata = os.fstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 \
            or metadata.st_uid != os.geteuid() \
            or (before_path.st_dev, before_path.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(directory)
        raise RestartEvidenceError("restart receipt directory must be owned mode 0700")
    temporary_name = f".{RECEIPT_FILE}.pending-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        if requested.name in os.listdir(directory):
            raise RestartEvidenceError("restart receipt already exists")
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory)
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode) or stat.S_IMODE(created.st_mode) != 0o600 \
                or created.st_uid != os.geteuid() or created.st_nlink != 1:
            raise RestartEvidenceError("restart receipt reservation is not an owned private file")
    except BaseException:
        try:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                finally:
                    try:
                        os.unlink(temporary_name, dir_fd=directory)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(directory)
        raise
    assert descriptor is not None
    return ReceiptReservation(
        parent, directory, descriptor, temporary_name, requested.name,
        metadata.st_dev, metadata.st_ino,
        created.st_dev, created.st_ino,
    )


def _require_reservation_parent(reservation: ReceiptReservation) -> None:
    try:
        path_metadata = os.lstat(reservation.parent)
        opened_metadata = os.fstat(reservation.directory)
    except OSError as exception:
        raise RestartEvidenceError("restart receipt directory identity is unavailable") from exception
    expected = (reservation.directory_device, reservation.directory_inode)
    if not stat.S_ISDIR(path_metadata.st_mode) \
            or not stat.S_ISDIR(opened_metadata.st_mode) \
            or (path_metadata.st_dev, path_metadata.st_ino) != expected \
            or (opened_metadata.st_dev, opened_metadata.st_ino) != expected \
            or stat.S_IMODE(path_metadata.st_mode) != 0o700 \
            or path_metadata.st_uid != os.geteuid():
        raise RestartEvidenceError("restart receipt directory changed during publication")


def _publish_receipt(
    reservation: ReceiptReservation, document: Mapping[str, Any]
) -> None:
    payload = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    _require_reservation_parent(reservation)
    before = os.fstat(reservation.temporary)
    if (before.st_dev, before.st_ino) != (reservation.device, reservation.inode) \
            or before.st_size != 0 or before.st_nlink != 1:
        raise RestartEvidenceError("restart receipt reservation changed before publication")
    view = memoryview(payload)
    while view:
        written = os.write(reservation.temporary, view)
        if written <= 0:
            raise RestartEvidenceError("restart receipt write made no progress")
        view = view[written:]
    os.fsync(reservation.temporary)
    after = os.fstat(reservation.temporary)
    if (after.st_dev, after.st_ino) != (reservation.device, reservation.inode) \
            or after.st_size != len(payload) or stat.S_IMODE(after.st_mode) != 0o600 \
            or after.st_uid != os.geteuid() or after.st_nlink != 1:
        raise RestartEvidenceError("restart receipt reservation changed while being written")
    try:
        os.link(
            reservation.temporary_name,
            reservation.final_name,
            src_dir_fd=reservation.directory,
            dst_dir_fd=reservation.directory,
            follow_symlinks=False,
        )
    except OSError as exception:
        raise RestartEvidenceError("restart receipt could not be published exclusively") from exception
    reservation.published = True
    os.unlink(reservation.temporary_name, dir_fd=reservation.directory)
    os.fsync(reservation.directory)
    _require_reservation_parent(reservation)
    final = os.stat(
        reservation.final_name, dir_fd=reservation.directory, follow_symlinks=False)
    if (final.st_dev, final.st_ino) != (reservation.device, reservation.inode) \
            or final.st_size != len(payload) or final.st_nlink != 1 \
            or stat.S_IMODE(final.st_mode) != 0o600:
        raise RestartEvidenceError("published restart receipt identity is invalid")


def _close_receipt_reservation(reservation: ReceiptReservation, *, discard: bool) -> None:
    try:
        if discard:
            for name in (reservation.temporary_name, reservation.final_name):
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=reservation.directory,
                        follow_symlinks=False,
                    )
                    if (metadata.st_dev, metadata.st_ino) \
                            == (reservation.device, reservation.inode):
                        os.unlink(name, dir_fd=reservation.directory)
                except FileNotFoundError:
                    pass
    finally:
        try:
            os.close(reservation.temporary)
        finally:
            os.close(reservation.directory)


def _public_process(snapshot: ContainerSnapshot) -> dict[str, Any]:
    return {
        "containerId": snapshot.container_id,
        "imageId": snapshot.image_id,
        "imageReference": snapshot.image_reference,
        "pid": snapshot.pid,
        "startedAt": snapshot.started_at,
        "restartCount": snapshot.restart_count,
    }


def _snapshot_ingress_pair(
    *,
    private_container_id: str,
    public_container_id: str,
    expected_image_id: str,
    expected_reference: str,
    compose_project: str,
    candidate_version: str,
    candidate_commit: str,
) -> tuple[ContainerSnapshot, ContainerSnapshot]:
    private = _snapshot_container(private_container_id)
    public = _snapshot_container(public_container_id)
    for snapshot, container_id, service in (
        (private, private_container_id, PRIVATE_NGINX_SERVICE),
        (public, public_container_id, PUBLIC_NGINX_SERVICE),
    ):
        _require_identity(
            snapshot,
            container_id=container_id,
            image_id=expected_image_id,
            image_reference=expected_reference,
            project=compose_project,
            service=service,
            version=candidate_version,
            commit=candidate_commit,
        )
        _require_running(snapshot, service, healthy=True)
    if private.container_id == public.container_id:
        raise RestartEvidenceError("private and public Nginx must be distinct containers")
    return private, public


def _require_ingress_process_continuity(
    before: ContainerSnapshot,
    after: ContainerSnapshot,
    label: str,
) -> None:
    if after != before:
        raise RestartEvidenceError(f"{label} changed across the app restart")


def _recover_app_after_failure(
    *,
    app_container_id: str,
    expected_app_image_id: str,
    expected_app_reference: str,
    compose_project: str,
    candidate_version: str,
    candidate_commit: str,
    original: ContainerSnapshot,
) -> None:
    current = _snapshot_container(app_container_id)
    _require_identity(
        current, container_id=app_container_id, image_id=expected_app_image_id,
        image_reference=expected_app_reference, project=compose_project,
        service=APP_SERVICE, version=candidate_version, commit=candidate_commit,
    )
    _resolved_stop_signal(current)
    if not current.running:
        _docker("start", app_container_id)
        current = _wait_for_healthy(app_container_id)
    elif current.health != "healthy":
        current = _wait_for_healthy(app_container_id)
    _require_identity(
        current, container_id=app_container_id, image_id=expected_app_image_id,
        image_reference=expected_app_reference, project=compose_project,
        service=APP_SERVICE, version=candidate_version, commit=candidate_commit,
    )
    _require_running(current, "recovered app", healthy=True)
    if current.restart_count != original.restart_count or current.mounts != original.mounts:
        raise RestartEvidenceError("failed restart recovery changed the app container")


def orchestrate(
    *,
    repository_root: Path,
    state_file: Path,
    output: Path,
    compose_project: str,
    app_container_id: str,
    redis_container_id: str,
    nginx_container_id: str,
    public_nginx_container_id: str,
    expected_app_image_id: str,
    expected_app_reference: str,
    expected_redis_image_id: str,
    expected_redis_reference: str,
    expected_nginx_image_id: str,
    expected_nginx_reference: str,
    candidate_version: str,
    candidate_commit: str,
    trace_prefix: str,
    redis_password: str,
) -> dict[str, Any]:
    repository = repository_root.expanduser().absolute()
    if repository.is_symlink() or not repository.is_dir():
        raise RestartEvidenceError("repository root must be a non-symlink directory")
    repository = repository.resolve(strict=True)
    if PROJECT.fullmatch(compose_project) is None or VERSION.fullmatch(candidate_version) is None \
            or "SNAPSHOT" in candidate_version.upper() \
            or OBJECT_ID.fullmatch(candidate_commit) is None \
            or TRACE.fullmatch(trace_prefix) is None:
        raise RestartEvidenceError("restart candidate identity is invalid")
    if IMAGE_REFERENCE.fullmatch(expected_app_reference) is None \
            or IMAGE_REFERENCE.fullmatch(expected_redis_reference) is None \
            or IMAGE_REFERENCE.fullmatch(expected_nginx_reference) is None \
            or HEX_ID.fullmatch(expected_app_image_id.removeprefix("sha256:")) is None \
            or HEX_ID.fullmatch(expected_redis_image_id.removeprefix("sha256:")) is None \
            or HEX_ID.fullmatch(expected_nginx_image_id.removeprefix("sha256:")) is None:
        raise RestartEvidenceError("restart image identity is invalid")

    producer_source = _snapshot_executing_source(repository)
    producer_sha256 = hashlib.sha256(producer_source.payload).hexdigest()

    state_path = state_file.expanduser().absolute()
    if state_path.name != STATE_FILE:
        raise RestartEvidenceError("shutdown probe state must use the fixed filename")
    marker_value = secrets.token_hex(32)
    reservation = _reserve_receipt(output, repository)
    discard_receipt = True
    try:
        operation_failure: BaseException | None = None
        recovery_failures: list[str] = []
        document: dict[str, Any] | None = None
        marker_created = False
        stop_attempted = False
        old_app: ContainerSnapshot | None = None
        old_redis: ContainerSnapshot | None = None
        old_private_nginx: ContainerSnapshot | None = None
        old_public_nginx: ContainerSnapshot | None = None
        marker_key = f"web-starter:acceptance:mcp-governance-restart:{trace_prefix}"
        try:
            if state_path.parent.is_symlink() \
                    or state_path.parent.resolve(strict=True) != reservation.parent:
                raise RestartEvidenceError(
                    "shutdown state and restart receipt must share one private raw directory"
                )
            state = _snapshot_file_at(
                reservation.directory, STATE_FILE, MAX_STATE_BYTES, "shutdown probe state"
            )
            state_match = STATE.fullmatch(state.payload)
            if state_match is None or state_match.group(2).decode("ascii") != trace_prefix:
                raise RestartEvidenceError("shutdown probe state is not the fixed trace-bound contract")
            state_created_ns = int(state_match.group(1)) * 1_000_000
            now_ns = time.time_ns()
            age_ns = now_ns - state_created_ns
            if age_ns < 0 or age_ns >= PROBE_MAX_AGE_SECONDS * 1_000_000_000 \
                    or state.modified_ns < state_created_ns \
                    or state.modified_ns > now_ns + 5_000_000_000:
                raise RestartEvidenceError(
                    "shutdown probe state is stale, future-dated, or outside the restart window"
                )

            old_app = _snapshot_container(app_container_id)
            old_redis = _snapshot_container(redis_container_id)
            old_private_nginx, old_public_nginx = _snapshot_ingress_pair(
                private_container_id=nginx_container_id,
                public_container_id=public_nginx_container_id,
                expected_image_id=expected_nginx_image_id,
                expected_reference=expected_nginx_reference,
                compose_project=compose_project,
                candidate_version=candidate_version,
                candidate_commit=candidate_commit,
            )
            _require_identity(
                old_app, container_id=app_container_id, image_id=expected_app_image_id,
                image_reference=expected_app_reference, project=compose_project,
                service=APP_SERVICE, version=candidate_version, commit=candidate_commit,
            )
            _require_identity(
                old_redis, container_id=redis_container_id, image_id=expected_redis_image_id,
                image_reference=expected_redis_reference, project=compose_project,
                service=REDIS_SERVICE,
            )
            _require_running(old_app, "old app", healthy=True)
            _require_running(old_redis, "Redis", healthy=True)
            _require_redis_volume(old_redis)
            resolved_stop_signal = _resolved_stop_signal(old_app)

            if _redis_cli(
                redis_container_id, redis_password, "SET", marker_key, marker_value,
                "NX", "EX", str(MARKER_TTL_SECONDS),
            ) != "OK":
                raise RestartEvidenceError("Redis continuity marker already existed or was not written")
            marker_created = True
            if _redis_cli(redis_container_id, redis_password, "GET", marker_key) != marker_value:
                raise RestartEvidenceError("Redis continuity marker was not readable before restart")

            stop_requested_ns = time.time_ns()
            # From this point the daemon may have accepted the stop even if the CLI
            # later times out or disconnects. Failure handling must inspect and
            # recover the container instead of trusting the command result.
            stop_attempted = True
            _docker(
                "stop", "--timeout", str(STOP_TIMEOUT_SECONDS), app_container_id,
                timeout_seconds=STOP_TIMEOUT_SECONDS + 10,
            )
            stop_completed_ns = time.time_ns()
            stopped_app = _snapshot_container(app_container_id)
            redis_while_stopped = _snapshot_container(redis_container_id)
            _require_identity(
                stopped_app, container_id=app_container_id, image_id=expected_app_image_id,
                image_reference=expected_app_reference, project=compose_project,
                service=APP_SERVICE, version=candidate_version, commit=candidate_commit,
            )
            _require_identity(
                redis_while_stopped, container_id=redis_container_id,
                image_id=expected_redis_image_id, image_reference=expected_redis_reference,
                project=compose_project, service=REDIS_SERVICE,
            )
            if stopped_app.running or stopped_app.status != "exited" or stopped_app.pid != 0 \
                    or stopped_app.exit_code not in {0, 143} or stopped_app.oom_killed \
                    or stopped_app.dead or stopped_app.error:
                raise RestartEvidenceError("app did not complete a graceful SIGTERM stop")
            old_started = _parse_timestamp(old_app.started_at, "old app startedAt")
            stopped_finished = _parse_timestamp(stopped_app.finished_at, "stopped app finishedAt")
            if old_started is None or stopped_finished is None or stopped_finished <= old_started:
                raise RestartEvidenceError("app stop timestamps are not ordered")
            if stopped_app.restart_count != old_app.restart_count \
                    or stopped_app.mounts != old_app.mounts:
                raise RestartEvidenceError("app container was recreated during stop")
            if redis_while_stopped != old_redis:
                raise RestartEvidenceError("Redis identity or process changed while the app stopped")
            if _redis_cli(redis_container_id, redis_password, "GET", marker_key) != marker_value:
                raise RestartEvidenceError("Redis continuity marker disappeared while app was stopped")

            start_requested_ns = time.time_ns()
            _docker("start", app_container_id)
            new_app = _wait_for_healthy(app_container_id)
            start_healthy_ns = time.time_ns()
            new_redis = _snapshot_container(redis_container_id)
            new_private_nginx, new_public_nginx = _snapshot_ingress_pair(
                private_container_id=nginx_container_id,
                public_container_id=public_nginx_container_id,
                expected_image_id=expected_nginx_image_id,
                expected_reference=expected_nginx_reference,
                compose_project=compose_project,
                candidate_version=candidate_version,
                candidate_commit=candidate_commit,
            )
            _require_identity(
                new_app, container_id=app_container_id, image_id=expected_app_image_id,
                image_reference=expected_app_reference, project=compose_project,
                service=APP_SERVICE, version=candidate_version, commit=candidate_commit,
            )
            _require_identity(
                new_redis, container_id=redis_container_id, image_id=expected_redis_image_id,
                image_reference=expected_redis_reference, project=compose_project,
                service=REDIS_SERVICE,
            )
            _require_running(new_app, "restarted app", healthy=True)
            _require_running(new_redis, "Redis after restart", healthy=True)
            if _resolved_stop_signal(new_app) != resolved_stop_signal:
                raise RestartEvidenceError("app stop signal changed across restart")
            if new_app.restart_count != old_app.restart_count or new_app.mounts != old_app.mounts:
                raise RestartEvidenceError("app container was recreated during start")
            new_started = _parse_timestamp(new_app.started_at, "new app startedAt")
            if new_started is None or stopped_finished is None or new_started <= stopped_finished:
                raise RestartEvidenceError("new app process did not start after the old process exited")
            if new_app.started_at == old_app.started_at:
                raise RestartEvidenceError("app process start identity did not change")
            if new_redis != old_redis:
                raise RestartEvidenceError("Redis container, process, health, or volume changed across restart")
            _require_ingress_process_continuity(
                old_private_nginx, new_private_nginx, PRIVATE_NGINX_SERVICE
            )
            _require_ingress_process_continuity(
                old_public_nginx, new_public_nginx, PUBLIC_NGINX_SERVICE
            )
            marker_after = _redis_cli(redis_container_id, redis_password, "GET", marker_key)
            ttl_after = _redis_cli(redis_container_id, redis_password, "TTL", marker_key)
            if marker_after != marker_value:
                raise RestartEvidenceError("Redis continuity marker did not survive app restart")
            try:
                ttl_seconds = int(ttl_after)
            except ValueError as exception:
                raise RestartEvidenceError("Redis continuity marker TTL is malformed") from exception
            if ttl_seconds <= 0 or ttl_seconds > MARKER_TTL_SECONDS:
                raise RestartEvidenceError("Redis continuity marker TTL is invalid after restart")
            _unchanged_file_at(
                reservation.directory, STATE_FILE, state, "shutdown probe state"
            )
            if time.time_ns() - state_created_ns >= PROBE_MAX_AGE_SECONDS * 1_000_000_000:
                raise RestartEvidenceError("restart completed after the shutdown probe window")

            document = {
                "schemaVersion": SCHEMA_VERSION,
                "status": "PASS",
                "producerSha256": producer_sha256,
                "candidate": {
                    "version": candidate_version,
                    "gitCommit": candidate_commit,
                },
                "runtime": {
                    "composeProject": compose_project,
                    "tracePrefix": trace_prefix,
                },
                "gracefulRestart": {
                    "signal": resolved_stop_signal,
                    "configuredStopSignal": old_app.stop_signal or "DOCKER_DEFAULT_SIGTERM",
                    "timeoutSeconds": STOP_TIMEOUT_SECONDS,
                    "stopCommandExitCode": 0,
                    "old": _public_process(old_app),
                    "stopped": {
                        "containerId": stopped_app.container_id,
                        "exitCode": stopped_app.exit_code,
                        "oomKilled": stopped_app.oom_killed,
                        "dead": stopped_app.dead,
                        "finishedAt": stopped_app.finished_at,
                    },
                    "new": _public_process(new_app),
                    "health": "healthy",
                },
                "redisContinuity": {
                    "containerId": old_redis.container_id,
                    "imageId": old_redis.image_id,
                    "imageReference": old_redis.image_reference,
                    "pid": old_redis.pid,
                    "startedAt": old_redis.started_at,
                    "restartCount": old_redis.restart_count,
                    "dataVolumeNameSha256": hashlib.sha256(
                        next(mount[0] for mount in old_redis.mounts if mount[1] == "/data").encode()
                    ).hexdigest(),
                    "markerSurvived": True,
                    "markerTtlSecondsAfterRestart": ttl_seconds,
                },
                "ingressContinuity": {
                    "services": {
                        PRIVATE_NGINX_SERVICE: _public_process(old_private_nginx),
                        PUBLIC_NGINX_SERVICE: _public_process(old_public_nginx),
                    },
                    "healthyAfterRestart": True,
                    "unchangedAcrossAppRestart": True,
                },
                "shutdownProbeState": {
                    "file": STATE_FILE,
                    "sha256": hashlib.sha256(state.payload).hexdigest(),
                    "createdAtEpochMillis": state_created_ns // 1_000_000,
                    "modifiedAtEpochNs": state.modified_ns,
                },
                "timing": {
                    "stopRequestedAtEpochNs": stop_requested_ns,
                    "stopCompletedAtEpochNs": stop_completed_ns,
                    "startRequestedAtEpochNs": start_requested_ns,
                    "healthyAtEpochNs": start_healthy_ns,
                },
            }
        except BaseException as exception:  # Cleanup and recovery are handled below.
            operation_failure = exception

        if operation_failure is not None and stop_attempted and old_app is not None:
            try:
                _recover_app_after_failure(
                    app_container_id=app_container_id,
                    expected_app_image_id=expected_app_image_id,
                    expected_app_reference=expected_app_reference,
                    compose_project=compose_project,
                    candidate_version=candidate_version,
                    candidate_commit=candidate_commit,
                    original=old_app,
                )
            except BaseException as recovery_failure:
                recovery_failures.append(
                    "app recovery failed with " + recovery_failure.__class__.__name__
                )

        if marker_created:
            try:
                deleted = _redis_cli(redis_container_id, redis_password, "DEL", marker_key)
                if deleted != "1":
                    raise RestartEvidenceError("Redis continuity marker was not removed")
            except BaseException as cleanup_failure:
                recovery_failures.append(
                    "Redis marker cleanup failed with " + cleanup_failure.__class__.__name__
                )

        if operation_failure is not None or recovery_failures:
            if recovery_failures:
                message = "; ".join(recovery_failures)
                if operation_failure is not None:
                    raise RestartEvidenceError(message) from operation_failure
                raise RestartEvidenceError(message)
            raise operation_failure

        if document is None:
            raise RestartEvidenceError("restart evidence completed without a document")
        _require_unchanged_executing_source(repository, producer_source)
        _publish_receipt(reservation, document)
        discard_receipt = False
        return document
    finally:
        _close_receipt_reservation(reservation, discard=discard_receipt)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--state-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--app-container-id", required=True)
    parser.add_argument("--redis-container-id", required=True)
    parser.add_argument("--nginx-container-id", required=True)
    parser.add_argument("--public-nginx-container-id", required=True)
    parser.add_argument("--expected-app-image-id", required=True)
    parser.add_argument("--expected-app-reference", required=True)
    parser.add_argument("--expected-redis-image-id", required=True)
    parser.add_argument("--expected-redis-reference", required=True)
    parser.add_argument("--expected-nginx-image-id", required=True)
    parser.add_argument("--expected-nginx-reference", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--trace-prefix", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        document = orchestrate(
            repository_root=arguments.repository_root,
            state_file=arguments.state_file,
            output=arguments.output,
            compose_project=arguments.compose_project,
            app_container_id=arguments.app_container_id,
            redis_container_id=arguments.redis_container_id,
            nginx_container_id=arguments.nginx_container_id,
            public_nginx_container_id=arguments.public_nginx_container_id,
            expected_app_image_id=arguments.expected_app_image_id,
            expected_app_reference=arguments.expected_app_reference,
            expected_redis_image_id=arguments.expected_redis_image_id,
            expected_redis_reference=arguments.expected_redis_reference,
            expected_nginx_image_id=arguments.expected_nginx_image_id,
            expected_nginx_reference=arguments.expected_nginx_reference,
            candidate_version=arguments.candidate_version,
            candidate_commit=arguments.candidate_commit,
            trace_prefix=arguments.trace_prefix,
            redis_password=os.environ.get("WEB_STARTER_REDIS_PASSWORD", ""),
        )
    except (OSError, ValueError, RestartEvidenceError) as exception:
        print(f"MCP governance restart evidence failed: {exception}")
        return 1
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
