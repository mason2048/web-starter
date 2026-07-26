#!/usr/bin/env python3
"""Independently validate the single-run official MCP SDK CRUD proof.

This validator deliberately does not import the proof producer.  It validates
the private properties manifest and Surefire XML from fixed, independently
declared rules, binds them to a clean tagged Git candidate, and can emit one
small canonical JSON artifact for a later release gate.  It uses only the
Python standard library and never contacts Docker, the runtime, or a network.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping
import xml.etree.ElementTree as ET


TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"
TEST_METHOD = "provesEachWriteCommitsOnceAcrossConcurrencyRetryConflictAndAudit"
TEST_SOURCE = "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkCrudRuntimeIT.java"
ROOT_POM = "pom.xml"
MODULE_POM = "web-starter-mcp/pom.xml"
FRONTEND_PACKAGE = "web-starter-web/package.json"
PRODUCER_SOURCE = "scripts/create_mcp_crud_runtime_proof.py"
VALIDATOR_SOURCE = "scripts/validate_mcp_crud_runtime_proof.py"
REPORT_FILE = f"TEST-{TEST_CLASS}.xml"
TRANSACTION_RECEIPT_FILE = "mcp-crud-transaction-receipt.properties"
PROOF_FILE = "mcp-crud-runtime-proof.properties"
SUMMARY_FILE = "mcp-crud-runtime-proof-summary.json"
SUMMARY_SCHEMA_SOURCE = "security/v1-ac16-v2-ac31-ac32-mcp-crud-summary.schema.json"
RUNNER_SOURCE = "scripts/run_release_runtime_acceptance.sh"
PROJECT_SERVICE_SOURCE = (
    "web-starter-project/src/main/java/dev/webstarter/project/service/impl/ProjectServiceImpl.java"
)
MCP_INVOCATION_SOURCE = (
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpInvocationService.java"
)
MCP_FAILURE_AUDIT_SOURCE = (
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpFailureAuditService.java"
)
MCP_TOOL_SUPPORT_SOURCE = (
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolSupport.java"
)
AUDIT_RECORDER_SOURCE = (
    "web-starter-system/src/main/java/dev/webstarter/system/service/impl/AuditLogRecorderImpl.java"
)
TRANSACTION_CONSTRAINT = "chk_webstarter_ac16_tx_audit"
TRANSACTION_PROJECT_CODE = "MCP_TX_ROLLBACK"
TRANSACTION_IDEMPOTENCY_KEY = "crud-transaction-rollback"

PROOF_KEYS = frozenset({
    "schemaVersion",
    "testClass",
    "testMethod",
    "sourcePath",
    "sourceSha256",
    "rootPomPath",
    "rootPomSha256",
    "modulePomPath",
    "modulePomSha256",
    "reportFile",
    "reportSha256",
    "transactionReceiptFile",
    "transactionReceiptSha256",
    "candidateCommit",
    "candidateTree",
    "candidateVersion",
    "candidateTag",
    "composeProject",
    "tracePrefix",
    "startedAtEpochNs",
})
TRANSACTION_RECEIPT_KEYS = frozenset({
    "schemaVersion",
    "databaseName",
    "constraintName",
    "failureTrace",
    "failureProjectCode",
    "failureIdempotencyKeyHash",
    "successTrace",
    "constraintRowsDuringFault",
    "constraintRowsAfterCleanup",
    "failedProjectRows",
    "failedOperationAuditRows",
    "failedMcpAuditRows",
    "failedMcpAuditExpectedRows",
    "failedIdempotencyRows",
    "successBusinessOperationMcpRows",
    "transactionalTableRows",
})
BOUND_SOURCE_PATHS = (
    TEST_SOURCE,
    ROOT_POM,
    MODULE_POM,
    FRONTEND_PACKAGE,
    PRODUCER_SOURCE,
    VALIDATOR_SOURCE,
    RUNNER_SOURCE,
    PROJECT_SERVICE_SOURCE,
    MCP_INVOCATION_SOURCE,
    MCP_FAILURE_AUDIT_SOURCE,
    MCP_TOOL_SUPPORT_SOURCE,
    AUDIT_RECORDER_SOURCE,
    SUMMARY_SCHEMA_SOURCE,
)

KEY_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
OBJECT_ID_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
PROJECT_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
TRACE_PREFIX_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_PROOF_BYTES = 32 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_TRANSACTION_RECEIPT_BYTES = 16 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
FORBIDDEN_RESULT_ELEMENTS = frozenset({
    "failure",
    "error",
    "skipped",
    "flakyfailure",
    "flakyerror",
    "rerunfailure",
    "rerunerror",
})
SECRET_PATTERN = re.compile(
    r"(?i)(authorization|bearer|cookie|password|passwd|secret|token|private[-_ ]?key|"
    r"client[-_ ]?secret|access[-_ ]?key|-----BEGIN)"
)


class ProofValidationError(RuntimeError):
    """Raised when evidence cannot be promoted to an independently verified PASS."""


@dataclass(frozen=True)
class FileSnapshot:
    payload: bytes
    sha256: str
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int


@dataclass(frozen=True)
class CandidateBinding:
    commit: str
    tree: str
    source_sha256: Mapping[str, str]
    source_payloads: Mapping[str, bytes]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def _require_pattern(value: str, pattern: re.Pattern[str], label: str) -> None:
    if pattern.fullmatch(value) is None:
        raise ProofValidationError(f"{label} has an invalid format")


def _git(repository: Path, *arguments: str, limit: int = MAX_GIT_OUTPUT_BYTES) -> bytes:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        completed = subprocess.run(
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
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exception:
        raise ProofValidationError("Git is required to validate the MCP CRUD proof") from exception
    if len(completed.stdout) > limit or len(completed.stderr) > limit:
        raise ProofValidationError("Git candidate verification output is unexpectedly large")
    if completed.returncode != 0:
        raise ProofValidationError("Git could not verify the MCP CRUD candidate")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    raw = _git(repository, *arguments)
    try:
        value = raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise ProofValidationError("Git candidate identity is not valid UTF-8") from exception
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise ProofValidationError("Git candidate identity output is invalid")
    return value


def _resolve_repository(configured: Path) -> Path:
    absolute = configured.expanduser().absolute()
    if absolute.is_symlink() or not absolute.is_dir():
        raise ProofValidationError("repository root must be a non-symlink directory")
    try:
        repository = absolute.resolve(strict=True)
    except OSError as exception:
        raise ProofValidationError("repository root cannot be resolved") from exception
    top_level = _git_text(repository, "rev-parse", "--show-toplevel")
    try:
        resolved_top_level = Path(top_level).resolve(strict=True)
    except OSError as exception:
        raise ProofValidationError("Git top-level cannot be resolved") from exception
    if resolved_top_level != repository:
        raise ProofValidationError("repository root is not the exact Git top-level")
    return repository


def _require_clean_candidate(repository: Path) -> None:
    index = _git(repository, "ls-files", "-v", "-z")
    records = [record for record in index.split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise ProofValidationError(
            "Git index contains skip-worktree, assume-unchanged, or non-cached entries"
        )
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        raise ProofValidationError("Git candidate worktree must be clean, including untracked files")


def _safe_workspace_file(repository: Path, relative: str) -> Path:
    target = repository.joinpath(*relative.split("/"))
    if target.is_symlink() or not target.is_file():
        raise ProofValidationError(f"candidate source must be a non-symlink regular file: {relative}")
    try:
        resolved = target.resolve(strict=True)
    except OSError as exception:
        raise ProofValidationError(f"candidate source cannot be resolved: {relative}") from exception
    if not _inside(resolved, repository):
        raise ProofValidationError(f"candidate source escaped the repository: {relative}")
    return resolved


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exception:
        raise ProofValidationError(f"cannot open {label} as a regular file") from exception
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > maximum:
            raise ProofValidationError(f"{label} size or file type is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > maximum:
            raise ProofValidationError(f"{label} changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _candidate_blob(repository: Path, commit: str, relative: str) -> bytes:
    entry = _git(repository, "ls-tree", "-z", commit, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise ProofValidationError(f"candidate does not contain exactly one tracked {relative}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or OBJECT_ID_PATTERN.fullmatch(fields[2].decode("ascii", errors="ignore")) is None
        or encoded_path != relative.encode("utf-8")
    ):
        raise ProofValidationError(f"candidate {relative} is not one regular Git blob")
    return _git(repository, "cat-file", "blob", f"{commit}:{relative}", limit=MAX_SOURCE_BYTES)


def _validate_candidate(
    repository: Path,
    declared_commit: str,
    declared_tree: str,
    candidate_tag: str,
) -> CandidateBinding:
    actual_commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    actual_tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if actual_commit != declared_commit:
        raise ProofValidationError("Git HEAD does not equal the declared candidate commit")
    if actual_tree != declared_tree:
        raise ProofValidationError("Git HEAD tree does not equal the declared candidate tree")
    _require_pattern(actual_commit, OBJECT_ID_PATTERN, "candidate commit")
    _require_pattern(actual_tree, OBJECT_ID_PATTERN, "candidate tree")

    tag_type = _git_text(repository, "cat-file", "-t", f"refs/tags/{candidate_tag}")
    if tag_type != "tag":
        raise ProofValidationError("candidate tag must be an annotated Git tag")
    tagged_commit = _git_text(
        repository, "rev-parse", "--verify", f"refs/tags/{candidate_tag}^{{commit}}"
    )
    if tagged_commit != actual_commit:
        raise ProofValidationError("candidate tag does not resolve to the candidate commit")

    _require_clean_candidate(repository)
    source_payloads: dict[str, bytes] = {}
    source_hashes: dict[str, str] = {}
    for relative in BOUND_SOURCE_PATHS:
        workspace_path = _safe_workspace_file(repository, relative)
        workspace = _read_regular_file(workspace_path, MAX_SOURCE_BYTES, relative)
        committed = _candidate_blob(repository, actual_commit, relative)
        if workspace != committed:
            raise ProofValidationError(
                f"workspace source differs from the candidate commit blob: {relative}"
            )
        source_payloads[relative] = committed
        source_hashes[relative] = _sha256(committed)

    executing_validator = _read_regular_file(
        Path(__file__).resolve(strict=True), MAX_SOURCE_BYTES, "executing MCP CRUD validator"
    )
    if executing_validator != source_payloads[VALIDATOR_SOURCE]:
        raise ProofValidationError(
            "executing MCP CRUD validator differs from the candidate validator source"
        )
    return CandidateBinding(
        commit=actual_commit,
        tree=actual_tree,
        source_sha256=dict(sorted(source_hashes.items())),
        source_payloads=source_payloads,
    )


def _open_evidence_directory(proof_path: Path, repository: Path) -> tuple[Path, int]:
    requested = proof_path.expanduser().absolute()
    if requested.name != PROOF_FILE or requested.is_symlink():
        raise ProofValidationError(f"proof must be a non-symlink file named {PROOF_FILE}")
    parent = requested.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProofValidationError("proof directory must be a non-symlink directory")
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exception:
        raise ProofValidationError("proof directory cannot be resolved") from exception
    if _inside(resolved_parent, repository) or _inside(repository, resolved_parent):
        raise ProofValidationError("proof directory must be outside and must not contain the repository")

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved_parent, flags)
    except OSError as exception:
        raise ProofValidationError("proof directory cannot be opened safely") from exception
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ProofValidationError("proof directory must be a real directory with mode 0700")
    return resolved_parent, descriptor


def _directory_names(descriptor: int) -> set[str]:
    try:
        return set(os.listdir(descriptor))
    except OSError as exception:
        raise ProofValidationError("proof directory cannot be listed safely") from exception


def _read_private_evidence_file(
    directory_descriptor: int,
    name: str,
    maximum: int,
    label: str,
) -> FileSnapshot:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exception:
        raise ProofValidationError(f"{label} must be a non-symlink regular file") from exception
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or mode != 0o600:
            raise ProofValidationError(f"{label} must be a regular mode 0600 file")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            raise ProofValidationError(f"{label} size is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > maximum:
            raise ProofValidationError(f"{label} changed while it was read")
        return FileSnapshot(
            payload=payload,
            sha256=_sha256(payload),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            mode=mode,
        )
    finally:
        os.close(descriptor)


def _same_snapshot(before: FileSnapshot, after: FileSnapshot, label: str) -> None:
    if before != after:
        raise ProofValidationError(f"{label} changed during validation")


def _parse_properties(payload: bytes) -> dict[str, str]:
    if len(payload) <= 0 or len(payload) > MAX_PROOF_BYTES:
        raise ProofValidationError("MCP CRUD proof size is invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError("MCP CRUD proof is not valid UTF-8") from exception
    if text.startswith("\ufeff") or "\r" in text or "\0" in text or not text.endswith("\n"):
        raise ProofValidationError("MCP CRUD proof uses a non-canonical text encoding")
    values: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise ProofValidationError("MCP CRUD proof contains invalid properties syntax")
        key, value = line.split("=", 1)
        if KEY_PATTERN.fullmatch(key) is None:
            raise ProofValidationError("MCP CRUD proof contains an invalid key")
        if not value or value != value.strip() or any(ord(character) < 0x20 for character in value):
            raise ProofValidationError("MCP CRUD proof contains an empty or malformed value")
        if key in values:
            raise ProofValidationError("MCP CRUD proof contains a duplicate key")
        values[key] = value
    if frozenset(values) != PROOF_KEYS:
        raise ProofValidationError("MCP CRUD proof keys differ from the exact schema")
    return values


def _parse_transaction_receipt(
    payload: bytes,
    *,
    expected_trace_prefix: str,
) -> dict[str, str]:
    if len(payload) <= 0 or len(payload) > MAX_TRANSACTION_RECEIPT_BYTES:
        raise ProofValidationError("AC-16 transaction receipt size is invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError(
            "AC-16 transaction receipt is not valid UTF-8"
        ) from exception
    if text.startswith("\ufeff") or "\r" in text or "\0" in text or not text.endswith("\n"):
        raise ProofValidationError(
            "AC-16 transaction receipt uses a non-canonical text encoding"
        )
    values: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise ProofValidationError(
                "AC-16 transaction receipt contains invalid properties syntax"
            )
        key, value = line.split("=", 1)
        if KEY_PATTERN.fullmatch(key) is None or not value or value != value.strip():
            raise ProofValidationError(
                "AC-16 transaction receipt contains a malformed key or value"
            )
        if key in values:
            raise ProofValidationError(
                "AC-16 transaction receipt contains a duplicate key"
            )
        values[key] = value
    if frozenset(values) != TRANSACTION_RECEIPT_KEYS:
        raise ProofValidationError(
            "AC-16 transaction receipt keys differ from the exact schema"
        )

    failure_trace = f"{expected_trace_prefix}-transaction-audit-failure"
    success_trace = f"{expected_trace_prefix}-create-first"
    expected_fixed = {
        "schemaVersion": "1",
        "databaseName": "web_starter",
        "constraintName": TRANSACTION_CONSTRAINT,
        "failureTrace": failure_trace,
        "failureProjectCode": TRANSACTION_PROJECT_CODE,
        "failureIdempotencyKeyHash": hashlib.sha256(
            TRANSACTION_IDEMPOTENCY_KEY.encode("utf-8")
        ).hexdigest(),
        "successTrace": success_trace,
        "constraintRowsDuringFault": "1",
        "constraintRowsAfterCleanup": "0",
        "failedProjectRows": "0",
        "failedOperationAuditRows": "0",
        "failedMcpAuditRows": "1",
        "failedMcpAuditExpectedRows": "1",
        "failedIdempotencyRows": "0",
        "successBusinessOperationMcpRows": "1",
        "transactionalTableRows": "4",
    }
    for key, expected in expected_fixed.items():
        if values[key] != expected:
            raise ProofValidationError(
                f"AC-16 transaction receipt {key} does not prove the required value"
            )
    return values


def _require_proof_values(
    values: Mapping[str, str],
    *,
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
    expected_compose_project: str,
    expected_trace_prefix: str,
) -> int:
    fixed = {
        "schemaVersion": "2",
        "testClass": TEST_CLASS,
        "testMethod": TEST_METHOD,
        "sourcePath": TEST_SOURCE,
        "rootPomPath": ROOT_POM,
        "modulePomPath": MODULE_POM,
        "reportFile": REPORT_FILE,
        "transactionReceiptFile": TRANSACTION_RECEIPT_FILE,
        "candidateCommit": expected_commit,
        "candidateVersion": expected_version,
        "candidateTag": expected_tag,
        "composeProject": expected_compose_project,
        "tracePrefix": expected_trace_prefix,
    }
    for key, expected in fixed.items():
        if values[key] != expected:
            raise ProofValidationError(f"MCP CRUD proof {key} does not match the expected value")
    for key in (
        "sourceSha256",
        "rootPomSha256",
        "modulePomSha256",
        "reportSha256",
        "transactionReceiptSha256",
    ):
        _require_pattern(values[key], SHA256_PATTERN, f"proof {key}")
    _require_pattern(values["candidateTree"], OBJECT_ID_PATTERN, "proof candidateTree")
    try:
        started_at = int(values["startedAtEpochNs"], 10)
    except ValueError as exception:
        raise ProofValidationError("MCP CRUD proof start time is invalid") from exception
    if started_at <= 0 or str(started_at) != values["startedAtEpochNs"]:
        raise ProofValidationError("MCP CRUD proof start time is invalid")
    return started_at


def _validate_expected_inputs(
    commit: str,
    version: str,
    tag: str,
    compose_project: str,
    trace_prefix: str,
) -> None:
    _require_pattern(commit, OBJECT_ID_PATTERN, "expected candidate commit")
    _require_pattern(version, VERSION_PATTERN, "expected candidate version")
    if "SNAPSHOT" in version.upper():
        raise ProofValidationError("candidate version must not be a SNAPSHOT")
    if tag != f"v{version}":
        raise ProofValidationError("expected candidate tag must equal v plus candidate version")
    _require_pattern(compose_project, PROJECT_PATTERN, "expected Compose project")
    _require_pattern(trace_prefix, TRACE_PREFIX_PATTERN, "expected trace prefix")


def _parse_xml(payload: bytes, label: str) -> ET.Element:
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", payload, flags=re.IGNORECASE):
        raise ProofValidationError(f"{label} must not contain a DOCTYPE or entity declaration")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError(f"{label} is not valid UTF-8") from exception
    try:
        return ET.fromstring(text)
    except ET.ParseError as exception:
        raise ProofValidationError(f"{label} is not valid XML") from exception


def _validate_surefire(report: FileSnapshot, started_at_epoch_ns: int) -> None:
    if report.modified_ns < started_at_epoch_ns:
        raise ProofValidationError("MCP CRUD Surefire report is stale")
    suite = _parse_xml(report.payload, "MCP CRUD Surefire report")
    if suite.tag != "testsuite" or suite.attrib.get("name") != TEST_CLASS:
        raise ProofValidationError("MCP CRUD Surefire report identifies a different test suite")
    suites = [element for element in suite.iter() if _local_name(element.tag) == "testsuite"]
    if suites != [suite]:
        raise ProofValidationError("MCP CRUD Surefire report must contain exactly one test suite")
    expected_counters = {
        "tests": "1",
        "failures": "0",
        "errors": "0",
        "skipped": "0",
        "flakes": "0",
    }
    if any(suite.attrib.get(name) != value for name, value in expected_counters.items()):
        raise ProofValidationError("MCP CRUD result is not exactly one clean passing test")

    all_cases = [element for element in suite.iter() if _local_name(element.tag) == "testcase"]
    direct_cases = [element for element in list(suite) if element.tag == "testcase"]
    if len(all_cases) != 1 or len(direct_cases) != 1:
        raise ProofValidationError("MCP CRUD Surefire report must contain exactly one testcase")
    case = direct_cases[0]
    if case.attrib.get("classname") != TEST_CLASS or case.attrib.get("name") != TEST_METHOD:
        raise ProofValidationError("MCP CRUD Surefire report identifies a different test method")

    for element in suite.iter():
        local = _local_name(element.tag).lower()
        if local in FORBIDDEN_RESULT_ELEMENTS or "rerun" in local or "retry" in local:
            raise ProofValidationError(
                "MCP CRUD Surefire report contains failure, skip, retry, or flake evidence"
            )
        if "flak" in local and local != "testsuite":
            raise ProofValidationError(
                "MCP CRUD Surefire report contains failure, skip, retry, or flake evidence"
            )
        if local != "property":
            for attribute in element.attrib:
                attribute_name = _local_name(attribute).lower()
                if "rerun" in attribute_name or "retry" in attribute_name or (
                    "flak" in attribute_name and attribute_name != "flakes"
                ):
                    raise ProofValidationError(
                        "MCP CRUD Surefire report contains failure, skip, retry, or flake evidence"
                    )


def _project_version(payload: bytes, label: str, *, parent: bool = False) -> str:
    root = _parse_xml(payload, label)
    if _local_name(root.tag) != "project":
        raise ProofValidationError(f"{label} root element must be project")
    container = root
    if parent:
        parents = [child for child in list(root) if _local_name(child.tag) == "parent"]
        if len(parents) != 1:
            raise ProofValidationError(f"{label} must contain exactly one Maven parent")
        container = parents[0]
    versions = [child for child in list(container) if _local_name(child.tag) == "version"]
    if len(versions) != 1 or versions[0].text is None:
        raise ProofValidationError(f"{label} must contain exactly one explicit version")
    version = versions[0].text.strip()
    if not version or "${" in version:
        raise ProofValidationError(f"{label} version is not explicit")
    return version


def _json_without_duplicates(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError(f"{label} is not valid UTF-8") from exception

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProofValidationError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(value: str) -> Any:
        raise ProofValidationError(f"{label} contains a non-finite number: {value}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except ProofValidationError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exception:
        raise ProofValidationError(f"{label} is not valid JSON") from exception


def _validate_versions(binding: CandidateBinding, expected_version: str) -> None:
    root_version = _project_version(binding.source_payloads[ROOT_POM], "root pom.xml")
    module_parent_version = _project_version(
        binding.source_payloads[MODULE_POM], "MCP module pom.xml", parent=True
    )
    frontend = _json_without_duplicates(
        binding.source_payloads[FRONTEND_PACKAGE], "frontend package.json"
    )
    if not isinstance(frontend, dict) or set(frontend).isdisjoint({"version"}):
        raise ProofValidationError("frontend package.json must contain a version")
    frontend_version = frontend.get("version")
    if not isinstance(frontend_version, str):
        raise ProofValidationError("frontend package.json version must be a string")
    versions = (root_version, module_parent_version, frontend_version, expected_version)
    if any("SNAPSHOT" in value.upper() for value in versions) or len(set(versions)) != 1:
        raise ProofValidationError(
            "root Maven, MCP module parent, frontend, and candidate versions must match and be non-SNAPSHOT"
        )


def _summary_secret_free(value: Any, path: str = "summary") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _summary_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _summary_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_PATTERN.search(value):
        raise ProofValidationError(f"summary would contain secret-shaped content at {path}")


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _write_summary(directory: Path, repository: Path, summary: Mapping[str, Any]) -> Path:
    requested = directory.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise ProofValidationError("summary output must be an existing non-symlink directory")
    resolved = requested.resolve(strict=True)
    if _inside(resolved, repository) or _inside(repository, resolved):
        raise ProofValidationError("summary output directory must be outside the repository")
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise ProofValidationError("summary output directory must have mode 0700")

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(resolved, flags)
    created = False
    try:
        identity = os.fstat(descriptor)
        if os.listdir(descriptor):
            raise ProofValidationError(
                "summary output directory must be empty; existing summaries are never overwritten"
            )
        _summary_secret_free(summary)
        payload = _canonical_json(summary)
        output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            output_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            output_flags |= os.O_NOFOLLOW
        try:
            output = os.open(SUMMARY_FILE, output_flags, 0o600, dir_fd=descriptor)
        except FileExistsError as exception:
            raise ProofValidationError("summary output already exists and will not be overwritten") from exception
        created = True
        try:
            if os.name == "posix":
                os.fchmod(output, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(output, remaining)
                if written <= 0:
                    raise ProofValidationError("summary output write made no progress")
                remaining = remaining[written:]
            os.fsync(output)
            metadata = os.fstat(output)
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ProofValidationError("summary output must have mode 0600")
        finally:
            os.close(output)
        current = resolved.stat()
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise ProofValidationError("summary output directory changed during validation")
        if set(os.listdir(descriptor)) != {SUMMARY_FILE}:
            raise ProofValidationError("summary output directory changed during validation")
        return resolved / SUMMARY_FILE
    except Exception:
        if created:
            try:
                os.unlink(SUMMARY_FILE, dir_fd=descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(descriptor)


def validate_proof(
    proof_path: Path,
    *,
    repository_root: Path,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    expected_compose_project: str,
    expected_trace_prefix: str,
    require_pass: bool = False,
    summary_output: Path | None = None,
) -> dict[str, Any]:
    """Validate a proof and optionally write a canonical PASS-only summary."""
    _validate_expected_inputs(
        expected_candidate_commit,
        expected_candidate_version,
        expected_candidate_tag,
        expected_compose_project,
        expected_trace_prefix,
    )
    if summary_output is not None and not require_pass:
        raise ProofValidationError("--summary-output requires --require-pass")
    repository = _resolve_repository(repository_root)
    evidence_directory, directory_descriptor = _open_evidence_directory(proof_path, repository)
    try:
        expected_evidence_files = {
            PROOF_FILE,
            REPORT_FILE,
            TRANSACTION_RECEIPT_FILE,
        }
        if _directory_names(directory_descriptor) != expected_evidence_files:
            raise ProofValidationError(
                "proof directory must contain only the proof, report, and AC-16 receipt"
            )
        proof_before = _read_private_evidence_file(
            directory_descriptor, PROOF_FILE, MAX_PROOF_BYTES, "MCP CRUD proof"
        )
        report_before = _read_private_evidence_file(
            directory_descriptor, REPORT_FILE, MAX_REPORT_BYTES, "MCP CRUD Surefire report"
        )
        transaction_receipt_before = _read_private_evidence_file(
            directory_descriptor,
            TRANSACTION_RECEIPT_FILE,
            MAX_TRANSACTION_RECEIPT_BYTES,
            "AC-16 transaction receipt",
        )
        values = _parse_properties(proof_before.payload)
        started_at = _require_proof_values(
            values,
            expected_commit=expected_candidate_commit,
            expected_version=expected_candidate_version,
            expected_tag=expected_candidate_tag,
            expected_compose_project=expected_compose_project,
            expected_trace_prefix=expected_trace_prefix,
        )
        if values["reportSha256"] != report_before.sha256:
            raise ProofValidationError("proof reportSha256 does not match the Surefire report")
        if values["transactionReceiptSha256"] != transaction_receipt_before.sha256:
            raise ProofValidationError(
                "proof transactionReceiptSha256 does not match the AC-16 receipt"
            )
        _validate_surefire(report_before, started_at)
        if transaction_receipt_before.modified_ns < started_at:
            raise ProofValidationError("AC-16 transaction receipt is stale")
        transaction_observations = _parse_transaction_receipt(
            transaction_receipt_before.payload,
            expected_trace_prefix=expected_trace_prefix,
        )

        binding = _validate_candidate(
            repository,
            values["candidateCommit"],
            values["candidateTree"],
            values["candidateTag"],
        )
        proof_source_hashes = {
            TEST_SOURCE: values["sourceSha256"],
            ROOT_POM: values["rootPomSha256"],
            MODULE_POM: values["modulePomSha256"],
        }
        for relative, declared_hash in proof_source_hashes.items():
            if binding.source_sha256[relative] != declared_hash:
                raise ProofValidationError(
                    f"proof source hash does not match candidate commit bytes: {relative}"
                )
        _validate_versions(binding, expected_candidate_version)

        if _directory_names(directory_descriptor) != expected_evidence_files:
            raise ProofValidationError("proof directory changed during validation")
        proof_after = _read_private_evidence_file(
            directory_descriptor, PROOF_FILE, MAX_PROOF_BYTES, "MCP CRUD proof"
        )
        report_after = _read_private_evidence_file(
            directory_descriptor, REPORT_FILE, MAX_REPORT_BYTES, "MCP CRUD Surefire report"
        )
        transaction_receipt_after = _read_private_evidence_file(
            directory_descriptor,
            TRANSACTION_RECEIPT_FILE,
            MAX_TRANSACTION_RECEIPT_BYTES,
            "AC-16 transaction receipt",
        )
        _same_snapshot(proof_before, proof_after, "MCP CRUD proof")
        _same_snapshot(report_before, report_after, "MCP CRUD Surefire report")
        _same_snapshot(
            transaction_receipt_before,
            transaction_receipt_after,
            "AC-16 transaction receipt",
        )
        directory_now = evidence_directory.stat()
        descriptor_now = os.fstat(directory_descriptor)
        if (directory_now.st_dev, directory_now.st_ino) != (
            descriptor_now.st_dev,
            descriptor_now.st_ino,
        ):
            raise ProofValidationError("proof directory changed during validation")

        final_binding = _validate_candidate(
            repository,
            values["candidateCommit"],
            values["candidateTree"],
            values["candidateTag"],
        )
        if final_binding.source_sha256 != binding.source_sha256:
            raise ProofValidationError("candidate source changed during validation")
        _validate_versions(final_binding, expected_candidate_version)
        final_proof = _read_private_evidence_file(
            directory_descriptor, PROOF_FILE, MAX_PROOF_BYTES, "MCP CRUD proof"
        )
        final_report = _read_private_evidence_file(
            directory_descriptor, REPORT_FILE, MAX_REPORT_BYTES, "MCP CRUD Surefire report"
        )
        final_transaction_receipt = _read_private_evidence_file(
            directory_descriptor,
            TRANSACTION_RECEIPT_FILE,
            MAX_TRANSACTION_RECEIPT_BYTES,
            "AC-16 transaction receipt",
        )
        _same_snapshot(proof_before, final_proof, "MCP CRUD proof")
        _same_snapshot(report_before, final_report, "MCP CRUD Surefire report")
        _same_snapshot(
            transaction_receipt_before,
            final_transaction_receipt,
            "AC-16 transaction receipt",
        )
    finally:
        os.close(directory_descriptor)

    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "acceptanceIds": ["AC-16", "V2-AC-31", "V2-AC-32"],
        "status": "PASS",
        "candidate": {
            "commit": binding.commit,
            "tree": binding.tree,
            "version": expected_candidate_version,
            "tag": expected_candidate_tag,
        },
        "runtime": {
            "composeProject": expected_compose_project,
            "tracePrefix": expected_trace_prefix,
            "transactionFailureTrace": transaction_observations["failureTrace"],
            "transactionSuccessTrace": transaction_observations["successTrace"],
        },
        "test": {
            "class": TEST_CLASS,
            "method": TEST_METHOD,
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "flakes": 0,
        },
        "sources": dict(binding.source_sha256),
        "checks": {
            "officialSdkRuntime": "PASS",
            "businessTransactionRollback": "PASS",
            "successBusinessAuditAtomicity": "PASS",
            "failedMcpAuditPersists": "PASS",
            "idempotencyReservationRollback": "PASS",
            "faultInjectionCleaned": "PASS",
            "transactionalStorage": "PASS",
        },
        "evidence": {
            "proofFile": PROOF_FILE,
            "proofSha256": proof_before.sha256,
            "reportFile": REPORT_FILE,
            "reportSha256": report_before.sha256,
            "transactionReceiptFile": TRANSACTION_RECEIPT_FILE,
            "transactionReceiptSha256": transaction_receipt_before.sha256,
        },
    }
    if summary_output is not None:
        _write_summary(summary_output, repository, summary)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--proof", type=Path, required=True)
    result.add_argument("--expected-candidate-commit", required=True)
    result.add_argument("--expected-candidate-version", required=True)
    result.add_argument("--expected-candidate-tag", required=True)
    result.add_argument("--expected-compose-project", required=True)
    result.add_argument("--expected-trace-prefix", required=True)
    result.add_argument(
        "--require-pass",
        action="store_true",
        help="fail closed unless the proof is a complete independently verified PASS",
    )
    result.add_argument(
        "--summary-output",
        type=Path,
        help=(
            "existing empty mode-0700 artifact directory in which the fixed canonical "
            f"{SUMMARY_FILE} will be created; requires --require-pass"
        ),
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_proof(
            args.proof,
            repository_root=args.repository_root,
            expected_candidate_commit=args.expected_candidate_commit,
            expected_candidate_version=args.expected_candidate_version,
            expected_candidate_tag=args.expected_candidate_tag,
            expected_compose_project=args.expected_compose_project,
            expected_trace_prefix=args.expected_trace_prefix,
            require_pass=args.require_pass,
            summary_output=args.summary_output,
        )
    except (OSError, ProofValidationError) as exception:
        print(f"FAIL validate-mcp-crud-runtime-proof: {exception}", file=sys.stderr)
        return 1
    print(
        "PASS validate-mcp-crud-runtime-proof: "
        f"status={summary['status']} candidate={summary['candidate']['commit']} "
        f"test={summary['test']['class']}#{summary['test']['method']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
