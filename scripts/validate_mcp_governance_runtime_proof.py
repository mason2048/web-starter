#!/usr/bin/env python3
"""Independently validate V2-AC-34/35 raw evidence and emit a canonical summary."""

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
import shutil
import signal
import stat
import subprocess
import threading
import time
from typing import Any, Mapping
import xml.etree.ElementTree as ET


ACCEPTANCE_IDS = ("V2-AC-34", "V2-AC-35")
MAIN_TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT"
MAIN_TEST_METHOD = "provesOfficialHttpSessionLifecycleIndependentRateLimitsAndAudit"
SHUTDOWN_TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT"
SHUTDOWN_TEST_METHOD = "provesGracefulShutdownRemovedUnexpiredSessionBeforeRestart"
MAIN_REPORT = f"TEST-{MAIN_TEST_CLASS}.xml"
SHUTDOWN_REPORT = f"TEST-{SHUTDOWN_TEST_CLASS}.xml"
STATE_FILE = "mcp-governance-shutdown-probe.properties"
RESTART_RECEIPT = "mcp-governance-restart-receipt.json"
PROOF_FILE = "mcp-governance-runtime-proof.properties"
SUMMARY_FILE = "mcp-governance-runtime-proof-summary.json"
SUMMARY_SCHEMA = "security/v2-ac34-ac35-mcp-governance-summary.schema.json"
RAW_OBSERVATION_FILES = frozenset(
    {MAIN_REPORT, SHUTDOWN_REPORT, STATE_FILE, RESTART_RECEIPT})
RAW_PROOF_FILES = frozenset({*RAW_OBSERVATION_FILES, PROOF_FILE})

SOURCE_PATHS = {
    "mainTestSha256": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpSdkGovernanceRuntimeIT.java"
    ),
    "shutdownTestSha256": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpSdkGovernanceShutdownRuntimeIT.java"
    ),
    "runtimeSupportSha256": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpGovernanceRuntimeSupport.java"
    ),
    "sessionRegistrySha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/"
        "RedisMcpSessionRegistry.java"
    ),
    "rateLimiterSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/RedisMcpRateLimiter.java"
    ),
    "governanceFilterSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/web/McpGovernanceFilter.java"
    ),
    "shutdownCleanupSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/"
        "McpSessionShutdownCleanup.java"
    ),
    "sessionPropertiesSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/config/McpSessionProperties.java"
    ),
    "ratePropertiesSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/config/McpRateLimitProperties.java"
    ),
    "rootPomSha256": "pom.xml",
    "modulePomSha256": "web-starter-mcp/pom.xml",
    "frontendPackageSha256": "web-starter-web/package.json",
    "producerSha256": "scripts/create_mcp_governance_runtime_proof.py",
    "validatorSha256": "scripts/validate_mcp_governance_runtime_proof.py",
    "restartOrchestratorSha256": "scripts/orchestrate_mcp_governance_restart.py",
    "summarySchemaSha256": SUMMARY_SCHEMA,
}
REVIEWED_BEHAVIOR_SHA256 = {
    SOURCE_PATHS["mainTestSha256"]:
        "03f9e6179d2b382c6cefe0b7416947a3bd5da208812c657a3227fceaee52b612",
    SOURCE_PATHS["shutdownTestSha256"]:
        "06a1155b1e389cf8bafaaba920e1c1c400b6403a6f912a3db6bdc9af586130be",
    SOURCE_PATHS["runtimeSupportSha256"]:
        "644369d4ab15b7baf9ca0f073bf3ee4493ad4f5725e9ce62747e304f0a72c0bf",
}
FIXED_KEYS = (
    "schemaVersion",
    "mainTestClass",
    "mainTestMethod",
    "mainReportFile",
    "mainReportSha256",
    "shutdownTestClass",
    "shutdownTestMethod",
    "shutdownReportFile",
    "shutdownReportSha256",
    "stateFile",
    "stateSha256",
    "restartReceiptFile",
    "restartReceiptSha256",
    "candidateCommit",
    "candidateTree",
    "candidateVersion",
    "candidateTag",
    "composeProject",
    "tracePrefix",
    "mainStartedAtEpochNs",
    "restartStartedAtEpochNs",
)
PROOF_KEYS = FIXED_KEYS + tuple(SOURCE_PATHS)

OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
SDK_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
TRACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
HEX_ID = re.compile(r"[0-9a-f]{64}")
IMAGE_REFERENCE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
DOCKER_TIMESTAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z"
)
KEY = re.compile(r"[A-Za-z][A-Za-z0-9]*")
STATE = re.compile(
    rb"schemaVersion=1\n"
    rb"sessionId=[A-Za-z0-9._~-]{8,512}\n"
    rb"createdAtEpochMillis=([1-9][0-9]{12})\n"
    rb"tracePrefix=([A-Za-z0-9][A-Za-z0-9._-]{0,31})\n"
    rb"expectedIdleTtlSeconds=50\n"
    rb"expectedAbsoluteTtlSeconds=60\n"
)
FORBIDDEN_XML = re.compile(
    rb"(?i)(authorization\s*[:=]|bearer\s+[A-Za-z0-9._~-]|"
    rb"access_token\s*[:=]|refresh_token\s*[:=]|client_secret\s*[:=]|"
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
MAX_GIT_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 2 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_PROOF_BYTES = 64 * 1024
GIT_TIMEOUT_SECONDS = 20.0
READ_CHUNK_BYTES = 64 * 1024


class ProofValidationError(RuntimeError):
    """Raised when evidence cannot be promoted to an independently checked PASS."""


@dataclass(frozen=True)
class Snapshot:
    payload: bytes
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    mode: int
    uid: int
    gid: int
    links: int


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class Candidate:
    commit: str
    tree: str
    sources: Mapping[str, bytes]
    hashes: Mapping[str, str]
    sdk_version: str


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _trusted_git() -> str:
    executable = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
    if executable is None:
        raise ProofValidationError("Git is required to validate MCP governance evidence")
    return executable


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_ALLOW_PROTOCOL": "file",
    }
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _bounded_process(
    command: list[str],
    *,
    environment: dict[str, str],
    limit: int,
    timeout_seconds: float,
) -> tuple[int, bytes, bytes]:
    if limit <= 0 or timeout_seconds <= 0:
        raise ValueError("process bounds must be positive")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=os.name == "posix",
        )
    except OSError as exception:
        raise ProofValidationError(
            "Git is required to validate MCP governance evidence") from exception
    assert process.stdout is not None and process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    lock = threading.Lock()
    exceeded = threading.Event()

    def drain(name: str, stream: object) -> None:
        try:
            while True:
                chunk = stream.read(READ_CHUNK_BYTES)  # type: ignore[attr-defined]
                if not chunk:
                    return
                with lock:
                    used = len(buffers["stdout"]) + len(buffers["stderr"])
                    remaining = max(0, limit - used)
                    buffers[name].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        exceeded.set()
                if exceeded.is_set():
                    _kill_process(process)
                    return
        finally:
            stream.close()  # type: ignore[attr-defined]

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exception:
            _kill_process(process)
            raise ProofValidationError(
                "Git process did not terminate after timeout") from exception
    finally:
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            _kill_process(process)
            for thread in threads:
                thread.join(timeout=1)
            raise ProofValidationError("Git output readers did not terminate")
    if timed_out:
        raise ProofValidationError("Git candidate verification timed out")
    if exceeded.is_set():
        raise ProofValidationError("Git candidate verification output is unexpectedly large")
    return process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _git(
    repository: Path,
    *arguments: str,
    limit: int = MAX_GIT_BYTES,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
) -> bytes:
    try:
        returncode, stdout, _stderr = _bounded_process(
            [
                _trusted_git(),
                "--no-replace-objects",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                "-c", f"core.hooksPath={os.devnull}",
                "-C", str(repository),
                *arguments,
            ],
            environment=_git_environment(),
            limit=limit,
            timeout_seconds=timeout_seconds,
        )
    except (OSError, ValueError) as exception:
        raise ProofValidationError("Git is required to validate MCP governance evidence") from exception
    if returncode != 0:
        raise ProofValidationError("Git could not verify the MCP governance candidate")
    return stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        text = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise ProofValidationError("Git candidate identity is not valid UTF-8") from exception
    if not text or any(character in text for character in ("\0", "\n", "\r")):
        raise ProofValidationError("Git candidate identity is malformed")
    return text


def _repository(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    if absolute.is_symlink() or not absolute.is_dir():
        raise ProofValidationError("repository root must be a non-symlink directory")
    repository = absolute.resolve(strict=True)
    try:
        top = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exception:
        raise ProofValidationError("Git top-level cannot be resolved") from exception
    if top != repository:
        raise ProofValidationError("repository root is not the exact Git top-level")
    return repository


def _clean(repository: Path) -> None:
    git_directory = Path(_git_text(repository, "rev-parse", "--absolute-git-dir"))
    for alternate in (
        git_directory / "objects" / "info" / "alternates",
        git_directory / "objects" / "info" / "http-alternates",
    ):
        if alternate.exists():
            raise ProofValidationError("Git object alternates are forbidden for candidate evidence")
    if (git_directory / "info" / "grafts").exists():
        raise ProofValidationError("Git grafts are forbidden for candidate evidence")
    index = _git(repository, "ls-files", "-v", "-z")
    records = [record for record in index.split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise ProofValidationError("Git index contains hidden or non-cached entries")
    if _git(repository, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
        raise ProofValidationError("Git candidate worktree must be clean, including untracked files")
    if _git(repository, "for-each-ref", "--format=%(refname)", "refs/replace").strip():
        raise ProofValidationError("Git replacement refs are forbidden for candidate evidence")


def _current_uid() -> int | None:
    return os.geteuid() if hasattr(os, "geteuid") else None


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _directory_identity(metadata: os.stat_result) -> DirectoryIdentity:
    return DirectoryIdentity(
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _open_owned_directory(
    path: Path,
    label: str,
    *,
    expected_mode: int | None = None,
) -> tuple[int, DirectoryIdentity]:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        before = os.stat(path, follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = os.stat(path, follow_symlinks=False)
    except OSError as exception:
        if descriptor is not None:
            os.close(descriptor)
        raise ProofValidationError(f"cannot open {label} as a stable directory") from exception
    if not stat.S_ISDIR(opened.st_mode) \
            or _metadata_signature(before) != _metadata_signature(opened) \
            or _metadata_signature(after) != _metadata_signature(opened):
        os.close(descriptor)
        raise ProofValidationError(f"{label} changed while it was opened")
    uid = _current_uid()
    if uid is not None and opened.st_uid != uid:
        os.close(descriptor)
        raise ProofValidationError(f"{label} must be owned by the current user")
    if expected_mode is not None and os.name == "posix" \
            and stat.S_IMODE(opened.st_mode) != expected_mode:
        os.close(descriptor)
        raise ProofValidationError(f"{label} must have mode {expected_mode:04o}")
    return descriptor, _directory_identity(opened)


def _assert_directory_identity(
    path: Path,
    descriptor: int,
    expected: DirectoryIdentity,
    label: str,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError as exception:
        raise ProofValidationError(f"cannot recheck {label}") from exception
    if not stat.S_ISDIR(opened.st_mode) \
            or _directory_identity(opened) != expected \
            or _directory_identity(current) != expected:
        raise ProofValidationError(f"{label} identity changed during validation")


def _open_child_directory(parent: int, name: str, label: str) -> int:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ProofValidationError(f"{label} contains an invalid path component")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent)
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exception:
        if descriptor is not None:
            os.close(descriptor)
        raise ProofValidationError(f"cannot open {label} as a stable directory") from exception
    if not stat.S_ISDIR(opened.st_mode) \
            or _metadata_signature(before) != _metadata_signature(opened) \
            or _metadata_signature(after) != _metadata_signature(opened):
        os.close(descriptor)
        raise ProofValidationError(f"{label} changed while it was opened")
    uid = _current_uid()
    if uid is not None and opened.st_uid != uid:
        os.close(descriptor)
        raise ProofValidationError(f"{label} must be owned by the current user")
    return descriptor


def _snapshot_at(
    directory: int,
    name: str,
    maximum: int,
    label: str,
    *,
    expected_modes: frozenset[int],
) -> Snapshot:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ProofValidationError(f"{label} has an invalid filename")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=directory)
        opened = os.fstat(descriptor)
    except OSError as exception:
        if descriptor is not None:
            os.close(descriptor)
        raise ProofValidationError(f"cannot open {label} as a regular file") from exception
    try:
        mode = stat.S_IMODE(opened.st_mode)
        uid = _current_uid()
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 \
                or opened.st_size > maximum or opened.st_nlink != 1:
            raise ProofValidationError(f"{label} size, link count, or file type is invalid")
        if mode not in expected_modes:
            expected = "/".join(f"{item:04o}" for item in sorted(expected_modes))
            raise ProofValidationError(f"{label} must have mode {expected}")
        if uid is not None and opened.st_uid != uid:
            raise ProofValidationError(f"{label} must be owned by the current user")
        if _metadata_signature(before) != _metadata_signature(opened):
            raise ProofValidationError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=directory, follow_symlinks=False)
        payload = b"".join(chunks)
        if total != opened.st_size or total > maximum \
                or _metadata_signature(after_fd) != _metadata_signature(opened) \
                or _metadata_signature(after_path) != _metadata_signature(opened):
            raise ProofValidationError(f"{label} changed while it was read")
        return Snapshot(
            payload,
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
            mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_nlink,
        )
    finally:
        os.close(descriptor)


def _snapshot_repository_source(repository: Path, relative: str) -> Snapshot:
    root, identity = _open_owned_directory(repository, "repository root")
    current = root
    components = relative.split("/")
    try:
        for index, component in enumerate(components[:-1]):
            child = _open_child_directory(
                current,
                component,
                f"candidate source directory {components[:index + 1]}",
            )
            if current != root:
                os.close(current)
            current = child
        snapshot = _snapshot_at(
            current,
            components[-1],
            MAX_SOURCE_BYTES,
            f"candidate source {relative}",
            expected_modes=frozenset({0o600, 0o644, 0o700, 0o755}),
        )
        _assert_directory_identity(repository, root, identity, "repository root")
        return snapshot
    finally:
        if current != root:
            os.close(current)
        os.close(root)


def _snapshot_path(path: Path, maximum: int, label: str) -> Snapshot:
    requested = path.expanduser().absolute()
    if requested.is_symlink():
        raise ProofValidationError(f"{label} must not be a symlink")
    parent = requested.parent.resolve(strict=True)
    directory, _identity = _open_owned_directory(parent, f"{label} parent")
    try:
        return _snapshot_at(
            directory,
            requested.name,
            maximum,
            label,
            expected_modes=frozenset({0o600, 0o644, 0o700, 0o755}),
        )
    finally:
        os.close(directory)


def _candidate_blob(repository: Path, commit: str, relative: str) -> bytes:
    entry = _git(repository, "ls-tree", "-z", commit, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise ProofValidationError(f"candidate does not contain exactly one tracked {relative}")
    metadata, name = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or OBJECT_ID.fullmatch(fields[2].decode("ascii", errors="ignore")) is None
        or name != relative.encode("utf-8")
    ):
        raise ProofValidationError(f"candidate {relative} is not one regular Git blob")
    return _git(repository, "cat-file", "blob", f"{commit}:{relative}", limit=MAX_SOURCE_BYTES)


def _direct_child_text(root: ET.Element, name: str) -> str | None:
    for child in list(root):
        if child.tag.rsplit("}", 1)[-1] == name:
            return child.text.strip() if child.text else ""
    return None


def _parse_candidate_metadata(sources: Mapping[str, bytes], version: str) -> str:
    try:
        root = ET.fromstring(sources["pom.xml"].decode("utf-8", errors="strict"))
        module = ET.fromstring(
            sources["web-starter-mcp/pom.xml"].decode("utf-8", errors="strict"))
        package = json.loads(
            sources["web-starter-web/package.json"].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ET.ParseError, json.JSONDecodeError) as exception:
        raise ProofValidationError("candidate version metadata is invalid") from exception
    if _direct_child_text(root, "version") != version or package.get("version") != version:
        raise ProofValidationError("candidate Maven and frontend versions must match")
    sdk_version = None
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "mcp-sdk.version" and element.text:
            sdk_version = element.text.strip()
            break
    if sdk_version is None or SDK_VERSION.fullmatch(sdk_version) is None:
        raise ProofValidationError("candidate does not lock an official MCP SDK version")
    dependencies = []
    for dependency in module.iter():
        if dependency.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        values = {
            child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
            for child in list(dependency)
        }
        dependencies.append((values.get("groupId"), values.get("artifactId")))
    if ("io.modelcontextprotocol.sdk", "mcp") not in dependencies:
        raise ProofValidationError("MCP module is missing the official MCP SDK dependency")
    return sdk_version


def _candidate(
    repository: Path,
    commit: str,
    tree: str,
    tag: str,
    version: str,
) -> Candidate:
    actual_commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    actual_tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if actual_commit != commit or actual_tree != tree:
        raise ProofValidationError("declared candidate commit or tree does not match HEAD")
    if OBJECT_ID.fullmatch(commit) is None or OBJECT_ID.fullmatch(tree) is None:
        raise ProofValidationError("candidate object identity is invalid")
    if _git_text(repository, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise ProofValidationError("candidate tag must be an annotated Git tag")
    if _git_text(repository, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != commit:
        raise ProofValidationError("candidate tag does not resolve to the candidate commit")
    _clean(repository)
    payloads: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for relative in SOURCE_PATHS.values():
        workspace = _snapshot_repository_source(repository, relative).payload
        committed = _candidate_blob(repository, commit, relative)
        if not workspace or len(workspace) > MAX_SOURCE_BYTES or workspace != committed:
            raise ProofValidationError(f"workspace source differs from candidate: {relative}")
        payloads[relative] = committed
        hashes[relative] = _digest(committed)
    for relative, expected in REVIEWED_BEHAVIOR_SHA256.items():
        if hashes[relative] != expected:
            raise ProofValidationError(
                f"human-reviewed MCP governance behavior source drifted: {relative}")
    validator_path = Path(__file__).resolve(strict=True)
    if _snapshot_path(
        validator_path, MAX_SOURCE_BYTES, "executing MCP governance validator"
    ).payload != payloads[SOURCE_PATHS["validatorSha256"]]:
        raise ProofValidationError("executing MCP governance validator differs from candidate blob")
    sdk_version = _parse_candidate_metadata(payloads, version)
    return Candidate(commit, tree, payloads, hashes, sdk_version)


def _unchanged_at(
    directory: int,
    name: str,
    snapshot: Snapshot,
    maximum: int,
    label: str,
) -> None:
    current = _snapshot_at(
        directory,
        name,
        maximum,
        label,
        expected_modes=frozenset({0o600}),
    )
    if current != snapshot:
        raise ProofValidationError(f"{label} changed during validation")


def _parse_properties(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError("proof is not valid UTF-8") from exception
    if "\r" in text or not text.endswith("\n"):
        raise ProofValidationError("proof must use canonical LF lines")
    values: dict[str, str] = {}
    order: list[str] = []
    for line in text.splitlines():
        if not line or "=" not in line:
            raise ProofValidationError("proof contains an invalid line")
        key, value = line.split("=", 1)
        if KEY.fullmatch(key) is None or key in values or not value:
            raise ProofValidationError("proof contains an invalid or duplicate key")
        values[key] = value
        order.append(key)
    if tuple(order) != PROOF_KEYS or set(values) != set(PROOF_KEYS):
        raise ProofValidationError("proof does not use the canonical exact schema")
    return values


def _report(snapshot: Snapshot, test_class: str, test_method: str, started: int) -> None:
    if snapshot.modified_ns < started or snapshot.modified_ns > time.time_ns() + 5_000_000_000:
        raise ProofValidationError("Surefire report is stale or future-dated")
    payload = snapshot.payload
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", payload, flags=re.IGNORECASE):
        raise ProofValidationError("Surefire report must not contain declarations")
    if FORBIDDEN_XML.search(payload):
        raise ProofValidationError("Surefire report appears to contain credential material")
    try:
        root = ET.fromstring(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ET.ParseError) as exception:
        raise ProofValidationError("Surefire report is not valid XML") from exception
    local = lambda name: name.rsplit("}", 1)[-1].lower()
    if local(root.tag) != "testsuite" or root.attrib.get("name") != test_class:
        raise ProofValidationError("Surefire report identifies a different suite")
    expected = {"tests": "1", "failures": "0", "errors": "0", "skipped": "0", "flakes": "0"}
    if any(root.attrib.get(key, "0" if key == "flakes" else None) != value for key, value in expected.items()):
        raise ProofValidationError("runtime result is not exactly one clean passing test")
    cases = [item for item in list(root) if local(item.tag) == "testcase"]
    if (
        len(cases) != 1
        or [item for item in root.iter() if local(item.tag) == "testcase"] != cases
        or cases[0].attrib.get("classname") != test_class
        or cases[0].attrib.get("name") != test_method
    ):
        raise ProofValidationError("Surefire report identifies a different test method")
    for element in root.iter():
        name = local(element.tag)
        if name in {"failure", "error", "skipped", "flakyfailure", "flakyerror", "rerunfailure", "rerunerror"} \
                or "retry" in name or "rerun" in name or ("flak" in name and name != "testsuite"):
            raise ProofValidationError("Surefire report contains failure, skip, retry, or flake evidence")
        for attribute in element.attrib:
            name = local(attribute)
            if "retry" in name or "rerun" in name or ("flak" in name and name != "flakes"):
                raise ProofValidationError("Surefire report contains retry or flake evidence")


def _state(snapshot: Snapshot, main_started: int, restart_started: int, trace: str) -> None:
    match = STATE.fullmatch(snapshot.payload)
    if match is None or match.group(2).decode("ascii") != trace:
        raise ProofValidationError("shutdown state is not the fixed canonical contract")
    created = int(match.group(1)) * 1_000_000
    if created < main_started or created > restart_started:
        raise ProofValidationError("shutdown state timestamp is outside the pre-restart run")
    if snapshot.modified_ns < main_started or snapshot.modified_ns > restart_started:
        raise ProofValidationError("shutdown state file timestamp is outside the pre-restart run")


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProofValidationError("restart receipt repeats a JSON field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ProofValidationError(f"restart receipt contains non-finite JSON value {value}")


def _strict_json(payload: bytes) -> dict[str, object]:
    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exception:
        raise ProofValidationError("restart receipt is not strict UTF-8 JSON") from exception
    if not isinstance(document, dict):
        raise ProofValidationError("restart receipt must be a JSON object")
    canonical = (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if canonical != payload:
        raise ProofValidationError("restart receipt is not canonical JSON")
    return document


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProofValidationError(f"restart receipt {label} contract drifted")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProofValidationError(f"restart receipt {label} is invalid")
    return value


def _timestamp(value: object, label: str) -> int:
    if not isinstance(value, str):
        raise ProofValidationError(f"restart receipt {label} timestamp is invalid")
    match = DOCKER_TIMESTAMP.fullmatch(value)
    if match is None or value == "0001-01-01T00:00:00Z":
        raise ProofValidationError(f"restart receipt {label} timestamp is invalid")
    try:
        parsed = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exception:
        raise ProofValidationError(f"restart receipt {label} timestamp is invalid") from exception
    fraction = (match.group(2) or "").ljust(9, "0")
    return calendar.timegm(parsed.utctimetuple()) * 1_000_000_000 + int(fraction)


def _receipt_process(value: object, label: str) -> tuple[dict[str, object], int]:
    process = _exact_object(
        value,
        {"containerId", "imageId", "imageReference", "pid", "startedAt", "restartCount"},
        label,
    )
    container = process["containerId"]
    image = process["imageId"]
    reference = process["imageReference"]
    if not isinstance(container, str) or HEX_ID.fullmatch(container) is None \
            or not isinstance(image, str) or not image.startswith("sha256:") \
            or HEX_ID.fullmatch(image.removeprefix("sha256:")) is None \
            or not isinstance(reference, str) or IMAGE_REFERENCE.fullmatch(reference) is None:
        raise ProofValidationError(
            f"restart receipt {label} container image identity is invalid")
    _integer(process["pid"], f"{label} pid", minimum=1)
    _integer(process["restartCount"], f"{label} restartCount")
    return process, _timestamp(process["startedAt"], f"{label} startedAt")


def _receipt_ingress(
    value: object,
    expected_reference: str,
    expected_image_id: str,
) -> tuple[int, int]:
    ingress = _exact_object(
        value,
        {"services", "healthyAfterRestart", "unchangedAcrossAppRestart"},
        "ingressContinuity",
    )
    services = _exact_object(
        ingress["services"], {"nginx", "mcp-public-nginx"}, "ingress services"
    )
    private, private_started = _receipt_process(services["nginx"], "private Nginx")
    public, public_started = _receipt_process(
        services["mcp-public-nginx"], "public Nginx"
    )
    if ingress["healthyAfterRestart"] is not True \
            or ingress["unchangedAcrossAppRestart"] is not True \
            or private["containerId"] == public["containerId"] \
            or any(
                process["imageReference"] != expected_reference
                or process["imageId"] != expected_image_id
                for process in (private, public)
            ):
        raise ProofValidationError(
            "restart receipt Nginx ingress identity differs from the expected release runtime"
        )
    return private_started, public_started


def _restart_receipt(
    snapshot: Snapshot,
    state: Snapshot,
    candidate_commit: str,
    candidate_version: str,
    compose_project: str,
    trace_prefix: str,
    main_started_ns: int,
    restart_started_ns: int,
    shutdown_report_modified_ns: int,
    expected_producer_sha256: str,
    expected_app_reference: str,
    expected_app_image_id: str,
    expected_nginx_reference: str,
    expected_nginx_image_id: str,
    expected_redis_reference: str,
    expected_redis_image_id: str,
) -> None:
    document = _strict_json(snapshot.payload)
    _exact_object(
        document,
        {
            "schemaVersion", "status", "candidate", "runtime", "gracefulRestart",
            "redisContinuity", "ingressContinuity", "shutdownProbeState", "timing",
            "producerSha256",
        },
        "envelope",
    )
    if _integer(document["schemaVersion"], "schemaVersion") != 1 \
            or document["status"] != "PASS":
        raise ProofValidationError("restart receipt is not a fixed PASS observation")
    if document["producerSha256"] != expected_producer_sha256:
        raise ProofValidationError(
            "restart receipt producer differs from the candidate orchestrator")
    candidate = _exact_object(document["candidate"], {"version", "gitCommit"}, "candidate")
    runtime = _exact_object(document["runtime"], {"composeProject", "tracePrefix"}, "runtime")
    if candidate != {"version": candidate_version, "gitCommit": candidate_commit} \
            or runtime != {"composeProject": compose_project, "tracePrefix": trace_prefix}:
        raise ProofValidationError(
            "restart receipt candidate or runtime identity differs from the proof")
    restart = _exact_object(
        document["gracefulRestart"],
        {
            "signal", "configuredStopSignal", "timeoutSeconds", "stopCommandExitCode",
            "old", "stopped", "new", "health",
        },
        "gracefulRestart",
    )
    if restart["signal"] != "SIGTERM" \
            or restart["configuredStopSignal"] not in {"SIGTERM", "DOCKER_DEFAULT_SIGTERM"} \
            or _integer(restart["timeoutSeconds"], "restart timeout") != 40 \
            or _integer(restart["stopCommandExitCode"], "stop command exit code") != 0 \
            or restart["health"] != "healthy":
        raise ProofValidationError(
            "restart receipt does not prove the fixed graceful-stop contract")
    old, old_started = _receipt_process(restart["old"], "old app")
    new, new_started = _receipt_process(restart["new"], "new app")
    if old["imageReference"] != expected_app_reference \
            or new["imageReference"] != expected_app_reference \
            or old["imageId"] != expected_app_image_id \
            or new["imageId"] != expected_app_image_id:
        raise ProofValidationError(
            "restart receipt app image identity differs from the expected release runtime")
    stopped = _exact_object(
        restart["stopped"],
        {"containerId", "exitCode", "oomKilled", "dead", "finishedAt"},
        "stopped app",
    )
    stopped_finished = _timestamp(stopped["finishedAt"], "stopped app finishedAt")
    stopped_exit = _integer(stopped["exitCode"], "stopped app exit code")
    if stopped["containerId"] != old["containerId"] or new["containerId"] != old["containerId"] \
            or stopped_exit not in {0, 143} \
            or stopped["oomKilled"] is not False or stopped["dead"] is not False \
            or new["imageId"] != old["imageId"] \
            or new["imageReference"] != old["imageReference"] \
            or new["restartCount"] != old["restartCount"] \
            or new["startedAt"] == old["startedAt"] \
            or not old_started < stopped_finished < new_started:
        raise ProofValidationError("restart receipt app process continuity is invalid")
    redis = _exact_object(
        document["redisContinuity"],
        {
            "containerId", "imageId", "imageReference", "pid", "startedAt",
            "restartCount", "dataVolumeNameSha256", "markerSurvived",
            "markerTtlSecondsAfterRestart",
        },
        "redisContinuity",
    )
    if not isinstance(redis["containerId"], str) \
            or HEX_ID.fullmatch(redis["containerId"]) is None \
            or not isinstance(redis["imageId"], str) \
            or not redis["imageId"].startswith("sha256:") \
            or HEX_ID.fullmatch(redis["imageId"].removeprefix("sha256:")) is None \
            or not isinstance(redis["imageReference"], str) \
            or IMAGE_REFERENCE.fullmatch(redis["imageReference"]) is None \
            or not isinstance(redis["dataVolumeNameSha256"], str) \
            or HEX_ID.fullmatch(redis["dataVolumeNameSha256"]) is None \
            or redis["markerSurvived"] is not True:
        raise ProofValidationError("restart receipt Redis continuity identity is invalid")
    if redis["imageReference"] != expected_redis_reference \
            or redis["imageId"] != expected_redis_image_id:
        raise ProofValidationError(
            "restart receipt Redis image identity differs from the expected release runtime")
    _integer(redis["pid"], "Redis pid", minimum=1)
    _integer(redis["restartCount"], "Redis restartCount")
    redis_started = _timestamp(redis["startedAt"], "Redis startedAt")
    marker_ttl = _integer(
        redis["markerTtlSecondsAfterRestart"], "Redis marker TTL", minimum=1)
    if marker_ttl > 180:
        raise ProofValidationError(
            "restart receipt Redis marker TTL exceeds the fixed contract")
    private_nginx_started, public_nginx_started = _receipt_ingress(
        document["ingressContinuity"], expected_nginx_reference, expected_nginx_image_id
    )
    probe = _exact_object(
        document["shutdownProbeState"],
        {"file", "sha256", "createdAtEpochMillis", "modifiedAtEpochNs"},
        "shutdownProbeState",
    )
    probe_modified = _integer(
        probe["modifiedAtEpochNs"], "shutdown state modified time", minimum=1)
    state_match = STATE.fullmatch(state.payload)
    if state_match is None:
        raise ProofValidationError(
            "restart receipt references a noncanonical shutdown state")
    state_created_ms = int(state_match.group(1))
    if probe["file"] != STATE_FILE or probe["sha256"] != _digest(state.payload) \
            or _integer(
                probe["createdAtEpochMillis"], "shutdown state creation time", minimum=1
            ) != state_created_ms \
            or probe_modified != state.modified_ns:
        raise ProofValidationError("restart receipt shutdown state binding is invalid")
    timing = _exact_object(
        document["timing"],
        {
            "stopRequestedAtEpochNs", "stopCompletedAtEpochNs",
            "startRequestedAtEpochNs", "healthyAtEpochNs",
        },
        "timing",
    )
    stop_requested = _integer(timing["stopRequestedAtEpochNs"], "stop requested", minimum=1)
    stop_completed = _integer(timing["stopCompletedAtEpochNs"], "stop completed", minimum=1)
    start_requested = _integer(timing["startRequestedAtEpochNs"], "start requested", minimum=1)
    healthy = _integer(timing["healthyAtEpochNs"], "healthy", minimum=1)
    now = time.time_ns()
    if not main_started_ns <= state.modified_ns <= restart_started_ns <= stop_requested \
            <= stop_completed <= start_requested <= healthy <= snapshot.modified_ns \
            <= shutdown_report_modified_ns <= now + 5_000_000_000:
        raise ProofValidationError("restart receipt timing is not causally ordered")
    if old_started > main_started_ns or redis_started > main_started_ns \
            or private_nginx_started > main_started_ns \
            or public_nginx_started > main_started_ns \
            or not stop_requested - 5_000_000_000 <= stopped_finished \
                <= stop_completed + 5_000_000_000 \
            or not start_requested - 5_000_000_000 <= new_started \
                <= healthy + 5_000_000_000:
        raise ProofValidationError(
            "restart receipt Docker and epoch timestamps are not cross-bound")
    if stop_completed - stop_requested > 50_000_000_000 \
            or healthy - start_requested > 95_000_000_000:
        raise ProofValidationError(
            "restart receipt exceeds the fixed stop or health timeout")


def _strict_summary(summary: Mapping[str, Any]) -> None:
    if set(summary) != {
        "schemaVersion", "acceptanceIds", "status", "candidate", "runtime",
        "sessionLifecycle", "rateLimiting", "shutdown", "sources",
    }:
        raise ProofValidationError("summary top-level contract drifted")
    if summary["schemaVersion"] != 1 or summary["acceptanceIds"] != list(ACCEPTANCE_IDS) \
            or summary["status"] != "PASS":
        raise ProofValidationError("summary identity contract drifted")
    if set(summary["candidate"]) != {"commit", "tree", "version", "tag"}:
        raise ProofValidationError("summary candidate contract drifted")
    if set(summary["runtime"]) != {
        "composeProject", "tracePrefix", "transport", "officialSdk", "sdkVersion", "reports"
    } or summary["runtime"]["transport"] != "Streamable HTTP" \
            or summary["runtime"]["officialSdk"] is not True \
            or summary["runtime"]["reports"] != [MAIN_REPORT, SHUTDOWN_REPORT]:
        raise ProofValidationError("summary runtime contract drifted")
    session = summary["sessionLifecycle"]
    if session != {
        "idleTtlSeconds": 50,
        "absoluteTtlSeconds": 60,
        "maxPerSubject": 2,
        "observations": [
            "IDLE_EXPIRED_404",
            "ABSOLUTE_EXPIRED_WHILE_IDLE_ACTIVE_404",
            "SUBJECT_SESSION_CAP_429_RETRY_AFTER",
            "EXPLICIT_DELETE_THEN_404",
            "EXPIRED_SESSION_REJECTED_BEFORE_TOOL",
        ],
    }:
        raise ProofValidationError("summary session contract drifted")
    rate = summary["rateLimiting"]
    if rate != {
        "windowSeconds": 15,
        "maxPerSubject": 5,
        "maxPerClient": 5,
        "riskLimits": {"read": 5, "write": 5, "destructive": 1, "protocol": 5},
        "observations": [
            "SUBJECT_BUCKET_429_RETRY_AFTER",
            "CLIENT_BUCKET_429_RETRY_AFTER",
            "DESTRUCTIVE_RISK_BUCKET_429_RETRY_AFTER",
            "RATE_LIMITED_AUDIT_FAILED_OUTCOME",
        ],
    }:
        raise ProofValidationError("summary rate-limit contract drifted")
    if summary["shutdown"] != {
        "gracefulRestart": True,
        "ingressContinuity": True,
        "probeBeforeIdleExpiry": True,
        "oldSessionOutcome": "SESSION_NOT_FOUND_404",
        "nginxImageId": summary["shutdown"].get("nginxImageId"),
        "nginxImageReferenceSha256": summary["shutdown"].get(
            "nginxImageReferenceSha256"
        ),
        "restartReceipt": RESTART_RECEIPT,
        "restartReceiptSha256": summary["shutdown"].get("restartReceiptSha256"),
        "restartProducerSha256": summary["shutdown"].get("restartProducerSha256"),
    }:
        raise ProofValidationError("summary shutdown contract drifted")
    if not isinstance(summary["shutdown"]["nginxImageId"], str) \
            or not summary["shutdown"]["nginxImageId"].startswith("sha256:") \
            or SHA256.fullmatch(
                summary["shutdown"]["nginxImageId"].removeprefix("sha256:")
            ) is None \
            or not isinstance(summary["shutdown"]["nginxImageReferenceSha256"], str) \
            or SHA256.fullmatch(
                summary["shutdown"]["nginxImageReferenceSha256"]
            ) is None \
            or not isinstance(summary["shutdown"]["restartReceiptSha256"], str) \
            or not isinstance(summary["shutdown"]["restartProducerSha256"], str) \
            or SHA256.fullmatch(summary["shutdown"]["restartReceiptSha256"]) is None \
            or SHA256.fullmatch(summary["shutdown"]["restartProducerSha256"]) is None:
        raise ProofValidationError("summary restart hash contract drifted")
    if set(summary["sources"]) != set(SOURCE_PATHS.values()) \
            or any(SHA256.fullmatch(value) is None for value in summary["sources"].values()):
        raise ProofValidationError("summary source contract drifted")


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    _strict_summary(summary)
    return (json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _write_summary(directory: Path, payload: bytes, repository: Path) -> None:
    requested = directory.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise ProofValidationError("summary output must be a non-symlink directory")
    output_directory = requested.resolve(strict=True)
    if _inside(output_directory, repository):
        raise ProofValidationError("summary output must stay outside the Git workspace")
    directory_fd, identity = _open_owned_directory(
        output_directory, "summary output directory", expected_mode=0o700)
    try:
        if os.listdir(directory_fd):
            raise ProofValidationError("summary output directory must be empty")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(SUMMARY_FILE, flags, 0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise ProofValidationError("could not write canonical summary")
                offset += written
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            uid = _current_uid()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 \
                    or metadata.st_size != len(payload) \
                    or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600) \
                    or (uid is not None and metadata.st_uid != uid):
                raise ProofValidationError("created canonical summary metadata is invalid")
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
        _assert_directory_identity(
            output_directory, directory_fd, identity, "summary output directory")
    finally:
        os.close(directory_fd)


def validate_proof(
    proof_path: Path,
    repository_root: Path,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    expected_compose_project: str,
    expected_trace_prefix: str,
    *,
    expected_app_reference: str,
    expected_app_image_id: str,
    expected_nginx_reference: str,
    expected_nginx_image_id: str,
    expected_redis_reference: str,
    expected_redis_image_id: str,
    require_pass: bool = False,
    summary_output: Path | None = None,
) -> dict[str, Any]:
    repository = _repository(repository_root)
    requested = proof_path.expanduser().absolute()
    if requested.name != PROOF_FILE or requested.parent.is_symlink():
        raise ProofValidationError("proof must use the fixed filename")
    raw = requested.parent.resolve(strict=True)
    if _inside(raw, repository):
        raise ProofValidationError("raw evidence must stay outside the Git workspace")
    raw_fd, raw_identity = _open_owned_directory(
        raw, "raw evidence directory", expected_mode=0o700)
    try:
        return _validate_opened_proof(
            repository,
            raw,
            raw_fd,
            raw_identity,
            expected_candidate_commit,
            expected_candidate_version,
            expected_candidate_tag,
            expected_compose_project,
            expected_trace_prefix,
            expected_app_reference,
            expected_app_image_id,
            expected_nginx_reference,
            expected_nginx_image_id,
            expected_redis_reference,
            expected_redis_image_id,
            require_pass=require_pass,
            summary_output=summary_output,
        )
    finally:
        os.close(raw_fd)


def _validate_opened_proof(
    repository: Path,
    raw: Path,
    raw_fd: int,
    raw_identity: DirectoryIdentity,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    expected_compose_project: str,
    expected_trace_prefix: str,
    expected_app_reference: str,
    expected_app_image_id: str,
    expected_nginx_reference: str,
    expected_nginx_image_id: str,
    expected_redis_reference: str,
    expected_redis_image_id: str,
    *,
    require_pass: bool,
    summary_output: Path | None,
) -> dict[str, Any]:
    if set(os.listdir(raw_fd)) != RAW_PROOF_FILES:
        raise ProofValidationError("raw evidence directory has an unexpected file set")
    proof_snapshot = _snapshot_at(
        raw_fd,
        PROOF_FILE,
        MAX_PROOF_BYTES,
        "proof",
        expected_modes=frozenset({0o600}),
    )
    main_snapshot = _snapshot_at(
        raw_fd,
        MAIN_REPORT,
        MAX_REPORT_BYTES,
        "main report",
        expected_modes=frozenset({0o600}),
    )
    shutdown_snapshot = _snapshot_at(
        raw_fd,
        SHUTDOWN_REPORT,
        MAX_REPORT_BYTES,
        "shutdown report",
        expected_modes=frozenset({0o600}),
    )
    state_snapshot = _snapshot_at(
        raw_fd,
        STATE_FILE,
        MAX_STATE_BYTES,
        "shutdown state",
        expected_modes=frozenset({0o600}),
    )
    receipt_snapshot = _snapshot_at(
        raw_fd,
        RESTART_RECEIPT,
        MAX_RECEIPT_BYTES,
        "restart receipt",
        expected_modes=frozenset({0o600}),
    )
    values = _parse_properties(proof_snapshot.payload)

    fixed = {
        "schemaVersion": "1",
        "mainTestClass": MAIN_TEST_CLASS,
        "mainTestMethod": MAIN_TEST_METHOD,
        "mainReportFile": MAIN_REPORT,
        "shutdownTestClass": SHUTDOWN_TEST_CLASS,
        "shutdownTestMethod": SHUTDOWN_TEST_METHOD,
        "shutdownReportFile": SHUTDOWN_REPORT,
        "stateFile": STATE_FILE,
        "restartReceiptFile": RESTART_RECEIPT,
    }
    if any(values[key] != value for key, value in fixed.items()):
        raise ProofValidationError("proof fixed test identity drifted")
    if VERSION.fullmatch(values["candidateVersion"]) is None \
            or "SNAPSHOT" in values["candidateVersion"].upper():
        raise ProofValidationError("candidate version must be explicit and non-SNAPSHOT")
    if values["candidateTag"] != f"v{values['candidateVersion']}":
        raise ProofValidationError("candidate tag must equal v plus candidate version")
    if PROJECT.fullmatch(values["composeProject"]) is None or TRACE.fullmatch(values["tracePrefix"]) is None:
        raise ProofValidationError("runtime identity has an invalid format")
    expected = {
        "candidateCommit": expected_candidate_commit,
        "candidateVersion": expected_candidate_version,
        "candidateTag": expected_candidate_tag,
        "composeProject": expected_compose_project,
        "tracePrefix": expected_trace_prefix,
    }
    if any(values[key] != value for key, value in expected.items()):
        raise ProofValidationError("proof does not match the expected candidate or runtime identity")
    for key in (
        "mainReportSha256", "shutdownReportSha256", "stateSha256",
        "restartReceiptSha256", *SOURCE_PATHS,
    ):
        if SHA256.fullmatch(values[key]) is None:
            raise ProofValidationError("proof contains an invalid SHA-256")
    if values["mainReportSha256"] != _digest(main_snapshot.payload) \
            or values["shutdownReportSha256"] != _digest(shutdown_snapshot.payload) \
            or values["stateSha256"] != _digest(state_snapshot.payload) \
            or values["restartReceiptSha256"] != _digest(receipt_snapshot.payload):
        raise ProofValidationError("raw evidence hash does not match proof")
    try:
        main_started = int(values["mainStartedAtEpochNs"])
        restart_started = int(values["restartStartedAtEpochNs"])
    except ValueError as exception:
        raise ProofValidationError("runtime timestamps must be integers") from exception
    if main_started <= 0 or restart_started <= main_started or restart_started > time.time_ns():
        raise ProofValidationError("runtime timestamp ordering is invalid")
    _report(main_snapshot, MAIN_TEST_CLASS, MAIN_TEST_METHOD, main_started)
    _report(shutdown_snapshot, SHUTDOWN_TEST_CLASS, SHUTDOWN_TEST_METHOD, restart_started)
    _state(state_snapshot, main_started, restart_started, values["tracePrefix"])
    candidate = _candidate(
        repository,
        values["candidateCommit"],
        values["candidateTree"],
        values["candidateTag"],
        values["candidateVersion"],
    )
    _restart_receipt(
        receipt_snapshot,
        state_snapshot,
        values["candidateCommit"],
        values["candidateVersion"],
        values["composeProject"],
        values["tracePrefix"],
        main_started,
        restart_started,
        shutdown_snapshot.modified_ns,
        candidate.hashes[SOURCE_PATHS["restartOrchestratorSha256"]],
        expected_app_reference,
        expected_app_image_id,
        expected_nginx_reference,
        expected_nginx_image_id,
        expected_redis_reference,
        expected_redis_image_id,
    )
    for key, relative in SOURCE_PATHS.items():
        if values[key] != candidate.hashes[relative]:
            raise ProofValidationError(f"candidate source hash mismatch: {relative}")

    # The schema is an independently published strict contract, while this
    # validator also enforces every emitted field without trusting the schema.
    try:
        schema = json.loads(candidate.sources[SUMMARY_SCHEMA].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ProofValidationError("summary schema is not valid JSON") from exception
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" \
            or schema.get("type") != "object" or schema.get("additionalProperties") is not False \
            or set(schema.get("required", [])) != {
                "schemaVersion", "acceptanceIds", "status", "candidate", "runtime",
                "sessionLifecycle", "rateLimiting", "shutdown", "sources",
            }:
        raise ProofValidationError("summary schema is not the strict expected envelope")

    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "acceptanceIds": list(ACCEPTANCE_IDS),
        "status": "PASS",
        "candidate": {
            "commit": candidate.commit,
            "tree": candidate.tree,
            "version": values["candidateVersion"],
            "tag": values["candidateTag"],
        },
        "runtime": {
            "composeProject": values["composeProject"],
            "tracePrefix": values["tracePrefix"],
            "transport": "Streamable HTTP",
            "officialSdk": True,
            "sdkVersion": candidate.sdk_version,
            "reports": [MAIN_REPORT, SHUTDOWN_REPORT],
        },
        "sessionLifecycle": {
            "idleTtlSeconds": 50,
            "absoluteTtlSeconds": 60,
            "maxPerSubject": 2,
            "observations": [
                "IDLE_EXPIRED_404",
                "ABSOLUTE_EXPIRED_WHILE_IDLE_ACTIVE_404",
                "SUBJECT_SESSION_CAP_429_RETRY_AFTER",
                "EXPLICIT_DELETE_THEN_404",
                "EXPIRED_SESSION_REJECTED_BEFORE_TOOL",
            ],
        },
        "rateLimiting": {
            "windowSeconds": 15,
            "maxPerSubject": 5,
            "maxPerClient": 5,
            "riskLimits": {"read": 5, "write": 5, "destructive": 1, "protocol": 5},
            "observations": [
                "SUBJECT_BUCKET_429_RETRY_AFTER",
                "CLIENT_BUCKET_429_RETRY_AFTER",
                "DESTRUCTIVE_RISK_BUCKET_429_RETRY_AFTER",
                "RATE_LIMITED_AUDIT_FAILED_OUTCOME",
            ],
        },
        "shutdown": {
            "gracefulRestart": True,
            "ingressContinuity": True,
            "probeBeforeIdleExpiry": True,
            "oldSessionOutcome": "SESSION_NOT_FOUND_404",
            "nginxImageId": expected_nginx_image_id,
            "nginxImageReferenceSha256": hashlib.sha256(
                expected_nginx_reference.encode("utf-8")
            ).hexdigest(),
            "restartReceipt": RESTART_RECEIPT,
            "restartReceiptSha256": values["restartReceiptSha256"],
            "restartProducerSha256": candidate.hashes[
                SOURCE_PATHS["restartOrchestratorSha256"]],
        },
        "sources": {relative: candidate.hashes[relative] for relative in SOURCE_PATHS.values()},
    }
    payload = canonical_summary_bytes(summary)

    final_candidate = _candidate(
        repository,
        values["candidateCommit"],
        values["candidateTree"],
        values["candidateTag"],
        values["candidateVersion"],
    )
    if final_candidate != candidate:
        raise ProofValidationError("candidate identity changed during validation")
    _unchanged_at(raw_fd, PROOF_FILE, proof_snapshot, MAX_PROOF_BYTES, "proof")
    _unchanged_at(raw_fd, MAIN_REPORT, main_snapshot, MAX_REPORT_BYTES, "main report")
    _unchanged_at(
        raw_fd, SHUTDOWN_REPORT, shutdown_snapshot, MAX_REPORT_BYTES, "shutdown report")
    _unchanged_at(raw_fd, STATE_FILE, state_snapshot, MAX_STATE_BYTES, "shutdown state")
    _unchanged_at(
        raw_fd,
        RESTART_RECEIPT,
        receipt_snapshot,
        MAX_RECEIPT_BYTES,
        "restart receipt",
    )
    if set(os.listdir(raw_fd)) != RAW_PROOF_FILES:
        raise ProofValidationError("raw evidence file set changed during validation")
    _assert_directory_identity(raw, raw_fd, raw_identity, "raw evidence directory")
    if summary_output is not None:
        if not require_pass:
            raise ProofValidationError("summary output requires --require-pass")
        _write_summary(summary_output, payload, repository)
    if require_pass is not True:
        # Returning the independently derived summary is useful for inspection,
        # but callers may only publish it after making PASS intent explicit.
        return summary
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-tag", required=True)
    parser.add_argument("--expected-compose-project", required=True)
    parser.add_argument("--expected-trace-prefix", required=True)
    parser.add_argument("--expected-app-reference", required=True)
    parser.add_argument("--expected-app-image-id", required=True)
    parser.add_argument("--expected-nginx-reference", required=True)
    parser.add_argument("--expected-nginx-image-id", required=True)
    parser.add_argument("--expected-redis-reference", required=True)
    parser.add_argument("--expected-redis-image-id", required=True)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--summary-output", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        summary = validate_proof(
            arguments.proof,
            arguments.repository_root,
            arguments.expected_candidate_commit,
            arguments.expected_candidate_version,
            arguments.expected_candidate_tag,
            arguments.expected_compose_project,
            arguments.expected_trace_prefix,
            expected_app_reference=arguments.expected_app_reference,
            expected_app_image_id=arguments.expected_app_image_id,
            expected_nginx_reference=arguments.expected_nginx_reference,
            expected_nginx_image_id=arguments.expected_nginx_image_id,
            expected_redis_reference=arguments.expected_redis_reference,
            expected_redis_image_id=arguments.expected_redis_image_id,
            require_pass=arguments.require_pass,
            summary_output=arguments.summary_output,
        )
    except (OSError, ValueError, ProofValidationError) as exception:
        print(f"MCP governance proof validation failed: {exception}")
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
