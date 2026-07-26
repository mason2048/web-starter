#!/usr/bin/env python3
"""Create private candidate-bound raw proof for V2-AC-34 and V2-AC-35.

The producer never emits PASS.  It binds two exact Surefire reports and the
private shutdown probe state to one clean, annotated, non-SNAPSHOT candidate.
The independent validator is solely responsible for deriving a public result.
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
import shutil
import signal
import stat
import subprocess
import threading
import time
import xml.etree.ElementTree as ET


MAIN_TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT"
MAIN_TEST_METHOD = "provesOfficialHttpSessionLifecycleIndependentRateLimitsAndAudit"
SHUTDOWN_TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT"
SHUTDOWN_TEST_METHOD = "provesGracefulShutdownRemovedUnexpiredSessionBeforeRestart"
MAIN_REPORT = f"TEST-{MAIN_TEST_CLASS}.xml"
SHUTDOWN_REPORT = f"TEST-{SHUTDOWN_TEST_CLASS}.xml"
STATE_FILE = "mcp-governance-shutdown-probe.properties"
RESTART_RECEIPT = "mcp-governance-restart-receipt.json"
PROOF_FILE = "mcp-governance-runtime-proof.properties"
RAW_OBSERVATION_FILES = frozenset(
    {MAIN_REPORT, SHUTDOWN_REPORT, STATE_FILE, RESTART_RECEIPT})
RAW_PROOF_FILES = frozenset({*RAW_OBSERVATION_FILES, PROOF_FILE})

SOURCE_PATHS = {
    "mainTestSha256": Path(
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpSdkGovernanceRuntimeIT.java"
    ),
    "shutdownTestSha256": Path(
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpSdkGovernanceShutdownRuntimeIT.java"
    ),
    "runtimeSupportSha256": Path(
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpGovernanceRuntimeSupport.java"
    ),
    "sessionRegistrySha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/"
        "RedisMcpSessionRegistry.java"
    ),
    "rateLimiterSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/"
        "RedisMcpRateLimiter.java"
    ),
    "governanceFilterSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/web/McpGovernanceFilter.java"
    ),
    "shutdownCleanupSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/"
        "McpSessionShutdownCleanup.java"
    ),
    "sessionPropertiesSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/config/McpSessionProperties.java"
    ),
    "ratePropertiesSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/config/McpRateLimitProperties.java"
    ),
    "rootPomSha256": Path("pom.xml"),
    "modulePomSha256": Path("web-starter-mcp/pom.xml"),
    "frontendPackageSha256": Path("web-starter-web/package.json"),
    "producerSha256": Path("scripts/create_mcp_governance_runtime_proof.py"),
    "validatorSha256": Path("scripts/validate_mcp_governance_runtime_proof.py"),
    "restartOrchestratorSha256": Path("scripts/orchestrate_mcp_governance_restart.py"),
    "summarySchemaSha256": Path(
        "security/v2-ac34-ac35-mcp-governance-summary.schema.json"
    ),
}

# These three hashes are a human-review boundary, not values learned from the
# proof.  They are deliberately updated only after the runtime assertions are
# reviewed.  The final values are synchronized with the validator and tests.
REVIEWED_BEHAVIOR_SHA256 = {
    SOURCE_PATHS["mainTestSha256"].as_posix():
        "03f9e6179d2b382c6cefe0b7416947a3bd5da208812c657a3227fceaee52b612",
    SOURCE_PATHS["shutdownTestSha256"].as_posix():
        "06a1155b1e389cf8bafaaba920e1c1c400b6403a6f912a3db6bdc9af586130be",
    SOURCE_PATHS["runtimeSupportSha256"].as_posix():
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
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
TRACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
HEX_ID = re.compile(r"[0-9a-f]{64}")
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
GIT_TIMEOUT_SECONDS = 20.0
READ_CHUNK_BYTES = 64 * 1024


class ProofError(RuntimeError):
    """Raised when raw observations cannot be bound safely."""


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


def _sha256(payload: bytes) -> str:
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
        raise ProofError("Git is required to bind MCP governance evidence")
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
    """Run one command with execution-time output and wall-clock bounds."""
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
        raise ProofError("Git is required to bind MCP governance evidence") from exception
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
            raise ProofError("Git process did not terminate after timeout") from exception
    finally:
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            _kill_process(process)
            for thread in threads:
                thread.join(timeout=1)
            raise ProofError("Git output readers did not terminate")
    if timed_out:
        raise ProofError("Git candidate verification timed out")
    if exceeded.is_set():
        raise ProofError("Git candidate verification output is unexpectedly large")
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
        raise ProofError("Git is required to bind MCP governance evidence") from exception
    if returncode != 0:
        raise ProofError("Git could not verify the MCP governance candidate")
    return stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise ProofError("Git candidate identity is not valid UTF-8") from exception
    if not value or any(character in value for character in ("\0", "\n", "\r")):
        raise ProofError("Git candidate identity is malformed")
    return value


def _resolve_repository(configured: Path) -> Path:
    absolute = configured.expanduser().absolute()
    if absolute.is_symlink() or not absolute.is_dir():
        raise ProofError("repository root must be a non-symlink directory")
    repository = absolute.resolve(strict=True)
    try:
        top = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exception:
        raise ProofError("Git top-level cannot be resolved") from exception
    if top != repository:
        raise ProofError("repository root is not the exact Git top-level")
    return repository


def _require_clean_candidate(repository: Path) -> None:
    git_directory = Path(_git_text(repository, "rev-parse", "--absolute-git-dir"))
    for alternate in (
        git_directory / "objects" / "info" / "alternates",
        git_directory / "objects" / "info" / "http-alternates",
    ):
        if alternate.exists():
            raise ProofError("Git object alternates are forbidden for candidate evidence")
    if (git_directory / "info" / "grafts").exists():
        raise ProofError("Git grafts are forbidden for candidate evidence")
    index = _git(repository, "ls-files", "-v", "-z")
    records = [record for record in index.split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise ProofError("Git index contains hidden or non-cached entries")
    if _git(repository, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
        raise ProofError("Git candidate worktree must be clean, including untracked files")
    if _git(repository, "for-each-ref", "--format=%(refname)", "refs/replace").strip():
        raise ProofError("Git replacement refs are forbidden for candidate evidence")


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
        raise ProofError(f"cannot open {label} as a stable directory") from exception
    if not stat.S_ISDIR(opened.st_mode) \
            or _metadata_signature(before) != _metadata_signature(opened) \
            or _metadata_signature(after) != _metadata_signature(opened):
        os.close(descriptor)
        raise ProofError(f"{label} changed while it was opened")
    uid = _current_uid()
    if uid is not None and opened.st_uid != uid:
        os.close(descriptor)
        raise ProofError(f"{label} must be owned by the current user")
    if expected_mode is not None and os.name == "posix" \
            and stat.S_IMODE(opened.st_mode) != expected_mode:
        os.close(descriptor)
        raise ProofError(f"{label} must have mode {expected_mode:04o}")
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
        raise ProofError(f"cannot recheck {label}") from exception
    if not stat.S_ISDIR(opened.st_mode) \
            or _directory_identity(opened) != expected \
            or _directory_identity(current) != expected:
        raise ProofError(f"{label} identity changed during proof creation")


def _open_child_directory(parent: int, name: str, label: str) -> int:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ProofError(f"{label} contains an invalid path component")
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
        raise ProofError(f"cannot open {label} as a stable directory") from exception
    if not stat.S_ISDIR(opened.st_mode) \
            or _metadata_signature(before) != _metadata_signature(opened) \
            or _metadata_signature(after) != _metadata_signature(opened):
        os.close(descriptor)
        raise ProofError(f"{label} changed while it was opened")
    uid = _current_uid()
    if uid is not None and opened.st_uid != uid:
        os.close(descriptor)
        raise ProofError(f"{label} must be owned by the current user")
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
        raise ProofError(f"{label} has an invalid filename")
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
        raise ProofError(f"cannot open {label} as a regular file") from exception
    try:
        mode = stat.S_IMODE(opened.st_mode)
        uid = _current_uid()
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 \
                or opened.st_size > maximum or opened.st_nlink != 1:
            raise ProofError(f"{label} size, link count, or file type is invalid")
        if mode not in expected_modes:
            expected = "/".join(f"{item:04o}" for item in sorted(expected_modes))
            raise ProofError(f"{label} must have mode {expected}")
        if uid is not None and opened.st_uid != uid:
            raise ProofError(f"{label} must be owned by the current user")
        if _metadata_signature(before) != _metadata_signature(opened):
            raise ProofError(f"{label} changed while it was opened")
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
            raise ProofError(f"{label} changed while it was read")
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


def _snapshot_repository_source(repository: Path, relative: Path) -> Snapshot:
    root, identity = _open_owned_directory(repository, "repository root")
    current = root
    try:
        for index, component in enumerate(relative.parts[:-1]):
            child = _open_child_directory(
                current,
                component,
                f"candidate source directory {relative.parts[:index + 1]}",
            )
            if current != root:
                os.close(current)
            current = child
        snapshot = _snapshot_at(
            current,
            relative.name,
            MAX_SOURCE_BYTES,
            f"candidate source {relative.as_posix()}",
            expected_modes=frozenset({0o600, 0o644, 0o700, 0o755}),
        )
        _assert_directory_identity(repository, root, identity, "repository root")
        return snapshot
    finally:
        if current != root:
            os.close(current)
        os.close(root)


def _candidate_blob(repository: Path, commit: str, relative: Path) -> bytes:
    name = relative.as_posix()
    entry = _git(repository, "ls-tree", "-z", commit, "--", name)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise ProofError(f"candidate does not contain exactly one tracked {name}")
    metadata, encoded_name = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or OBJECT_ID.fullmatch(fields[2].decode("ascii", errors="ignore")) is None
        or encoded_name != name.encode("utf-8")
    ):
        raise ProofError(f"candidate {name} is not one regular Git blob")
    return _git(repository, "cat-file", "blob", f"{commit}:{name}", limit=MAX_SOURCE_BYTES)


def _candidate_sources(repository: Path, commit: str) -> tuple[str, dict[str, bytes]]:
    actual_commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if actual_commit != commit or OBJECT_ID.fullmatch(commit) is None or OBJECT_ID.fullmatch(tree) is None:
        raise ProofError("Git HEAD does not equal the declared candidate commit")
    _require_clean_candidate(repository)
    payloads: dict[str, bytes] = {}
    for key, relative in SOURCE_PATHS.items():
        current = _snapshot_repository_source(repository, relative).payload
        committed = _candidate_blob(repository, commit, relative)
        if not current or len(current) > MAX_SOURCE_BYTES or current != committed:
            raise ProofError(f"workspace source differs from candidate commit: {relative}")
        payloads[key] = committed
    for relative, expected in REVIEWED_BEHAVIOR_SHA256.items():
        actual = _sha256(payloads[next(
            key for key, path in SOURCE_PATHS.items() if path.as_posix() == relative
        )])
        if actual != expected:
            raise ProofError(f"human-reviewed MCP governance behavior source drifted: {relative}")
    return tree, payloads


def _require_annotated_tag(repository: Path, tag: str, commit: str) -> None:
    if _git_text(repository, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise ProofError("candidate tag must be an annotated Git tag")
    if _git_text(repository, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != commit:
        raise ProofError("candidate tag does not resolve to the candidate commit")


def _validate_report(
    snapshot: Snapshot,
    test_class: str,
    test_method: str,
    started_ns: int,
) -> bytes:
    payload = snapshot.payload
    now = time.time_ns()
    if started_ns <= 0 or started_ns > now:
        raise ProofError("runtime start timestamp is invalid")
    if snapshot.modified_ns < started_ns or snapshot.modified_ns > now + 5_000_000_000:
        raise ProofError("Surefire report is stale or future-dated")
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", payload, flags=re.IGNORECASE):
        raise ProofError("Surefire report must not contain declarations")
    if FORBIDDEN_XML.search(payload):
        raise ProofError("Surefire report appears to contain credential material")
    try:
        root = ET.fromstring(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ET.ParseError) as exception:
        raise ProofError("Surefire report is not valid XML") from exception
    local = lambda name: name.rsplit("}", 1)[-1].lower()
    if local(root.tag) != "testsuite" or root.attrib.get("name") != test_class:
        raise ProofError("Surefire report identifies a different test suite")
    expected = {"tests": "1", "failures": "0", "errors": "0", "skipped": "0", "flakes": "0"}
    if any(root.attrib.get(key, "0" if key == "flakes" else None) != value for key, value in expected.items()):
        raise ProofError("runtime result is not exactly one clean passing test")
    cases = [item for item in list(root) if local(item.tag) == "testcase"]
    all_cases = [item for item in root.iter() if local(item.tag) == "testcase"]
    if (
        len(cases) != 1
        or all_cases != cases
        or cases[0].attrib.get("classname") != test_class
        or cases[0].attrib.get("name") != test_method
    ):
        raise ProofError("Surefire report identifies a different test method")
    for element in root.iter():
        name = local(element.tag)
        if name in {"failure", "error", "skipped", "flakyfailure", "flakyerror", "rerunfailure", "rerunerror"} \
                or "retry" in name or "rerun" in name or ("flak" in name and name != "testsuite"):
            raise ProofError("Surefire report contains failure, skip, retry, or flake evidence")
        if any("retry" in local(key) or "rerun" in local(key) for key in element.attrib):
            raise ProofError("Surefire report contains retry evidence")
    return payload


def _validate_state(
    snapshot: Snapshot,
    main_started_ns: int,
    restart_started_ns: int,
    trace: str,
) -> bytes:
    payload = snapshot.payload
    match = STATE.fullmatch(payload)
    if match is None or match.group(2).decode("ascii") != trace:
        raise ProofError("shutdown state is not the fixed canonical contract")
    created_ns = int(match.group(1)) * 1_000_000
    if created_ns < main_started_ns or created_ns > restart_started_ns:
        raise ProofError("shutdown state timestamp is outside the pre-restart run")
    if snapshot.modified_ns < main_started_ns or snapshot.modified_ns > restart_started_ns:
        raise ProofError("shutdown state file timestamp is outside the pre-restart run")
    return payload


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProofError("restart receipt repeats a JSON field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ProofError(f"restart receipt contains non-finite JSON value {value}")


def _strict_json(payload: bytes) -> dict[str, object]:
    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exception:
        raise ProofError("restart receipt is not strict UTF-8 JSON") from exception
    if not isinstance(document, dict):
        raise ProofError("restart receipt must be a JSON object")
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
        raise ProofError("restart receipt is not canonical JSON")
    return document


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProofError(f"restart receipt {label} contract drifted")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProofError(f"restart receipt {label} is invalid")
    return value


def _timestamp(value: object, label: str) -> int:
    if not isinstance(value, str):
        raise ProofError(f"restart receipt {label} timestamp is invalid")
    match = DOCKER_TIMESTAMP.fullmatch(value)
    if match is None or value == "0001-01-01T00:00:00Z":
        raise ProofError(f"restart receipt {label} timestamp is invalid")
    try:
        parsed = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exception:
        raise ProofError(f"restart receipt {label} timestamp is invalid") from exception
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
            or not isinstance(image, str) \
            or HEX_ID.fullmatch(image.removeprefix("sha256:")) is None \
            or not image.startswith("sha256:") \
            or not isinstance(reference, str) or IMAGE_REFERENCE.fullmatch(reference) is None:
        raise ProofError(f"restart receipt {label} container image identity is invalid")
    _integer(process["pid"], f"{label} pid", minimum=1)
    _integer(process["restartCount"], f"{label} restartCount")
    return process, _timestamp(process["startedAt"], f"{label} startedAt")


def _receipt_ingress(value: object) -> tuple[int, int]:
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
            or private["imageId"] != public["imageId"] \
            or private["imageReference"] != public["imageReference"]:
        raise ProofError("restart receipt Nginx ingress continuity is invalid")
    return private_started, public_started


def _validate_restart_receipt(
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
) -> bytes:
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
        raise ProofError("restart receipt is not a fixed PASS observation")
    if document["producerSha256"] != expected_producer_sha256:
        raise ProofError("restart receipt producer differs from the candidate orchestrator")
    candidate = _exact_object(document["candidate"], {"version", "gitCommit"}, "candidate")
    runtime = _exact_object(document["runtime"], {"composeProject", "tracePrefix"}, "runtime")
    if candidate != {"version": candidate_version, "gitCommit": candidate_commit} \
            or runtime != {"composeProject": compose_project, "tracePrefix": trace_prefix}:
        raise ProofError("restart receipt candidate or runtime identity differs from the proof")

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
        raise ProofError("restart receipt does not prove the fixed graceful-stop contract")
    old, old_started = _receipt_process(restart["old"], "old app")
    new, new_started = _receipt_process(restart["new"], "new app")
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
        raise ProofError("restart receipt app process continuity is invalid")

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
        raise ProofError("restart receipt Redis continuity identity is invalid")
    _integer(redis["pid"], "Redis pid", minimum=1)
    _integer(redis["restartCount"], "Redis restartCount")
    redis_started = _timestamp(redis["startedAt"], "Redis startedAt")
    marker_ttl = _integer(
        redis["markerTtlSecondsAfterRestart"], "Redis marker TTL", minimum=1)
    if marker_ttl > 180:
        raise ProofError("restart receipt Redis marker TTL exceeds the fixed contract")

    private_nginx_started, public_nginx_started = _receipt_ingress(
        document["ingressContinuity"]
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
        raise ProofError("restart receipt references a noncanonical shutdown state")
    state_created_ms = int(state_match.group(1))
    if probe["file"] != STATE_FILE or probe["sha256"] != _sha256(state.payload) \
            or _integer(
                probe["createdAtEpochMillis"], "shutdown state creation time", minimum=1
            ) != state_created_ms \
            or probe_modified != state.modified_ns:
        raise ProofError("restart receipt shutdown state binding is invalid")
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
        raise ProofError("restart receipt timing is not causally ordered")
    if old_started > main_started_ns or redis_started > main_started_ns \
            or private_nginx_started > main_started_ns \
            or public_nginx_started > main_started_ns \
            or not stop_requested - 5_000_000_000 <= stopped_finished \
                <= stop_completed + 5_000_000_000 \
            or not start_requested - 5_000_000_000 <= new_started \
                <= healthy + 5_000_000_000:
        raise ProofError("restart receipt Docker and epoch timestamps are not cross-bound")
    if stop_completed - stop_requested > 50_000_000_000 \
            or healthy - start_requested > 95_000_000_000:
        raise ProofError("restart receipt exceeds the fixed stop or health timeout")
    return snapshot.payload


def _unchanged_at(
    directory: int,
    name: str,
    snapshot: Snapshot,
    maximum: int,
    label: str,
    *,
    expected_modes: frozenset[int] = frozenset({0o600}),
) -> None:
    current = _snapshot_at(
        directory, name, maximum, label, expected_modes=expected_modes)
    if current != snapshot:
        raise ProofError(f"{label} changed during proof creation")


def _write_exclusive_at(directory: int, name: str, payload: bytes, label: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ProofError(f"{label} has an invalid filename")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ProofError(f"could not write {label}")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        uid = _current_uid()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 \
                or metadata.st_size != len(payload) \
                or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600) \
                or (uid is not None and metadata.st_uid != uid):
            raise ProofError(f"created {label} metadata is invalid")
    finally:
        os.close(descriptor)
    os.fsync(directory)


def stage_surefire_report(
    report_directory: Path,
    report_name: str,
    raw_directory: Path,
) -> None:
    """Copy one isolated Surefire XML into raw with no-follow/O_EXCL semantics."""
    if report_name not in {MAIN_REPORT, SHUTDOWN_REPORT}:
        raise ProofError("only the two fixed governance reports may be staged")
    source_requested = report_directory.expanduser().absolute()
    raw_requested = raw_directory.expanduser().absolute()
    if source_requested.is_symlink() or raw_requested.is_symlink():
        raise ProofError("Surefire stage and raw directories must not be symlinks")
    source_path = source_requested.resolve(strict=True)
    raw_path = raw_requested.resolve(strict=True)
    source_fd, source_identity = _open_owned_directory(
        source_path, "Surefire stage directory", expected_mode=0o700)
    raw_fd, raw_identity = _open_owned_directory(
        raw_path, "raw evidence directory", expected_mode=0o700)
    try:
        if set(os.listdir(source_fd)) != {report_name}:
            raise ProofError("Surefire stage directory must contain exactly the expected XML")
        current_raw = set(os.listdir(raw_fd))
        if not current_raw.issubset(RAW_OBSERVATION_FILES) or report_name in current_raw:
            raise ProofError("raw evidence directory is not ready for exact report staging")
        source = _snapshot_at(
            source_fd,
            report_name,
            MAX_REPORT_BYTES,
            "staged Surefire report",
            expected_modes=frozenset({0o600}),
        )
        _write_exclusive_at(raw_fd, report_name, source.payload, "raw Surefire report")
        copied = _snapshot_at(
            raw_fd,
            report_name,
            MAX_REPORT_BYTES,
            "raw Surefire report",
            expected_modes=frozenset({0o600}),
        )
        if copied.payload != source.payload:
            raise ProofError("staged Surefire report differs from its isolated source")
        _unchanged_at(
            source_fd,
            report_name,
            source,
            MAX_REPORT_BYTES,
            "staged Surefire report",
        )
        _assert_directory_identity(
            source_path, source_fd, source_identity, "Surefire stage directory")
        _assert_directory_identity(raw_path, raw_fd, raw_identity, "raw evidence directory")
    finally:
        os.close(raw_fd)
        os.close(source_fd)


def create_proof(
    repository_root: Path,
    raw_directory: Path,
    output_path: Path,
    candidate_commit: str,
    candidate_version: str,
    candidate_tag: str,
    compose_project: str,
    trace_prefix: str,
    main_started_at_epoch_ns: int,
    restart_started_at_epoch_ns: int,
) -> None:
    repository = _resolve_repository(repository_root)
    if VERSION.fullmatch(candidate_version) is None or "SNAPSHOT" in candidate_version.upper():
        raise ProofError("candidate version must be an explicit non-SNAPSHOT version")
    if candidate_tag != f"v{candidate_version}":
        raise ProofError("candidate tag must equal v plus candidate version")
    if PROJECT.fullmatch(compose_project) is None:
        raise ProofError("Compose project identity is invalid")
    if TRACE.fullmatch(trace_prefix) is None:
        raise ProofError("trace prefix is invalid")
    if restart_started_at_epoch_ns <= main_started_at_epoch_ns:
        raise ProofError("restart start must follow the main runtime start")

    raw_requested = raw_directory.expanduser().absolute()
    if raw_requested.is_symlink() or not raw_requested.is_dir():
        raise ProofError("raw evidence directory must be a non-symlink directory")
    raw = raw_requested.resolve(strict=True)
    if _inside(raw, repository):
        raise ProofError("raw evidence directory must stay outside the Git workspace")
    output = output_path.expanduser().absolute()
    if output.parent.resolve(strict=True) != raw or output.name != PROOF_FILE:
        raise ProofError("proof output must use the fixed filename in the raw directory")
    raw_fd, raw_identity = _open_owned_directory(
        raw, "raw evidence directory", expected_mode=0o700)
    try:
        if set(os.listdir(raw_fd)) != RAW_OBSERVATION_FILES:
            raise ProofError(
                "raw directory must contain exactly two reports, shutdown state, and restart receipt")
        main_snapshot = _snapshot_at(
            raw_fd,
            MAIN_REPORT,
            MAX_REPORT_BYTES,
            "main Surefire report",
            expected_modes=frozenset({0o600}),
        )
        shutdown_snapshot = _snapshot_at(
            raw_fd,
            SHUTDOWN_REPORT,
            MAX_REPORT_BYTES,
            "shutdown Surefire report",
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
        main_payload = _validate_report(
            main_snapshot, MAIN_TEST_CLASS, MAIN_TEST_METHOD, main_started_at_epoch_ns)
        shutdown_payload = _validate_report(
            shutdown_snapshot, SHUTDOWN_TEST_CLASS, SHUTDOWN_TEST_METHOD,
            restart_started_at_epoch_ns)
        state_payload = _validate_state(
            state_snapshot,
            main_started_at_epoch_ns,
            restart_started_at_epoch_ns,
            trace_prefix,
        )
        tree, sources = _candidate_sources(repository, candidate_commit)
        _require_annotated_tag(repository, candidate_tag, candidate_commit)
        receipt_payload = _validate_restart_receipt(
            receipt_snapshot,
            state_snapshot,
            candidate_commit,
            candidate_version,
            compose_project,
            trace_prefix,
            main_started_at_epoch_ns,
            restart_started_at_epoch_ns,
            shutdown_snapshot.modified_ns,
            _sha256(sources["restartOrchestratorSha256"]),
        )
        values = {
            "schemaVersion": "1",
            "mainTestClass": MAIN_TEST_CLASS,
            "mainTestMethod": MAIN_TEST_METHOD,
            "mainReportFile": MAIN_REPORT,
            "mainReportSha256": _sha256(main_payload),
            "shutdownTestClass": SHUTDOWN_TEST_CLASS,
            "shutdownTestMethod": SHUTDOWN_TEST_METHOD,
            "shutdownReportFile": SHUTDOWN_REPORT,
            "shutdownReportSha256": _sha256(shutdown_payload),
            "stateFile": STATE_FILE,
            "stateSha256": _sha256(state_payload),
            "restartReceiptFile": RESTART_RECEIPT,
            "restartReceiptSha256": _sha256(receipt_payload),
            "candidateCommit": candidate_commit,
            "candidateTree": tree,
            "candidateVersion": candidate_version,
            "candidateTag": candidate_tag,
            "composeProject": compose_project,
            "tracePrefix": trace_prefix,
            "mainStartedAtEpochNs": str(main_started_at_epoch_ns),
            "restartStartedAtEpochNs": str(restart_started_at_epoch_ns),
        }
        values.update({key: _sha256(payload) for key, payload in sources.items()})
        proof = "".join(f"{key}={values[key]}\n" for key in PROOF_KEYS).encode("utf-8")

        # Re-read every candidate source and all raw inputs immediately before
        # the exclusive write.  A clean check performed only at the beginning
        # is not a final candidate binding.
        final_tree, final_sources = _candidate_sources(repository, candidate_commit)
        _require_annotated_tag(repository, candidate_tag, candidate_commit)
        if final_tree != tree or final_sources != sources:
            raise ProofError("candidate identity changed during proof creation")
        _unchanged_at(
            raw_fd, MAIN_REPORT, main_snapshot, MAX_REPORT_BYTES, "main Surefire report")
        _unchanged_at(
            raw_fd,
            SHUTDOWN_REPORT,
            shutdown_snapshot,
            MAX_REPORT_BYTES,
            "shutdown Surefire report",
        )
        _unchanged_at(
            raw_fd, STATE_FILE, state_snapshot, MAX_STATE_BYTES, "shutdown state")
        _unchanged_at(
            raw_fd,
            RESTART_RECEIPT,
            receipt_snapshot,
            MAX_RECEIPT_BYTES,
            "restart receipt",
        )
        if set(os.listdir(raw_fd)) != RAW_OBSERVATION_FILES:
            raise ProofError("raw evidence file set changed during proof creation")
        _assert_directory_identity(raw, raw_fd, raw_identity, "raw evidence directory")
        _write_exclusive_at(raw_fd, PROOF_FILE, proof, "MCP governance proof")
    finally:
        os.close(raw_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--raw-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--trace-prefix", required=True)
    parser.add_argument("--main-started-at-epoch-ns", required=True, type=int)
    parser.add_argument("--restart-started-at-epoch-ns", required=True, type=int)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        create_proof(
            arguments.repository_root,
            arguments.raw_directory,
            arguments.output,
            arguments.candidate_commit,
            arguments.candidate_version,
            arguments.candidate_tag,
            arguments.compose_project,
            arguments.trace_prefix,
            arguments.main_started_at_epoch_ns,
            arguments.restart_started_at_epoch_ns,
        )
    except (OSError, ValueError, ProofError) as exception:
        print(f"MCP governance proof creation failed: {exception}")
        return 1
    print("MCP governance raw proof created; independent validation is still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
