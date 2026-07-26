#!/usr/bin/env python3
"""Independently validate V2-AC-33 MCP Tool-contract evidence and emit a safe summary."""

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
import time
from typing import Any, Mapping
import xml.etree.ElementTree as ET


ACCEPTANCE_ID = "V2-AC-33"
TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT"
TEST_METHOD = "provesExactBaselineSchemasAnnotationsErrorsAndV1WriteCompatibility"
REPORT_FILE = f"TEST-{TEST_CLASS}.xml"
PROOF_FILE = "mcp-tool-contract-runtime-proof.properties"
SUMMARY_FILE = "mcp-tool-contract-runtime-proof-summary.json"
SUMMARY_SCHEMA = "security/v2-ac33-mcp-tool-contract-summary.schema.json"
BASELINE_TOOLS = (
    "system.info",
    "project.list",
    "project.get",
    "project.create",
    "project.update",
    "project.remove",
    "audit.list",
)
WRITE_TOOLS = {
    "project.create": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    "project.update": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "project.remove": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}
ERROR_CODE_PATTERN = (
    "^(?:FORBIDDEN|INVALID_ARGUMENT|IDEMPOTENCY_CONFLICT|"
    "IDEMPOTENCY_IN_PROGRESS|INTERNAL_ERROR|BUSINESS_[0-9]{4})$"
)
OBSERVED_ERROR_CODES = (
    "INVALID_ARGUMENT",
    "BUSINESS_4090",
    "BUSINESS_4004",
)
SOURCE_PATHS = {
    "runtimeTestSha256": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpSdkToolContractRuntimeIT.java"
    ),
    "expectationsSha256": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpRuntimeToolExpectations.java"
    ),
    "catalogSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolCatalog.java"
    ),
    "invocationSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpInvocationService.java"
    ),
    "rootPomSha256": "pom.xml",
    "modulePomSha256": "web-starter-mcp/pom.xml",
    "frontendPackageSha256": "web-starter-web/package.json",
    "producerSha256": "scripts/create_mcp_tool_contract_runtime_proof.py",
    "validatorSha256": "scripts/validate_mcp_tool_contract_runtime_proof.py",
    "summarySchemaSha256": SUMMARY_SCHEMA,
}
FIXED_PROOF_KEYS = (
    "schemaVersion",
    "testClass",
    "testMethod",
    "reportFile",
    "reportSha256",
    "candidateCommit",
    "candidateTree",
    "candidateVersion",
    "candidateTag",
    "composeProject",
    "tracePrefix",
    "startedAtEpochNs",
)
PROOF_KEYS = FIXED_PROOF_KEYS + tuple(SOURCE_PATHS)

KEY_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
OBJECT_ID_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
PROJECT_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
TRACE_PREFIX_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SECRET_PATTERN = re.compile(
    r"(?i)(authorization|bearer|cookie|password|passwd|secret|private[-_ ]?key|"
    r"client[-_ ]?secret|access[-_ ]?key|-----BEGIN)"
)
MAX_PROOF_BYTES = 32 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
FORBIDDEN_RESULT_ELEMENTS = {
    "failure", "error", "skipped", "flakyfailure", "flakyerror",
    "rerunfailure", "rerunerror",
}


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
    sdk_version: str


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
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        completed = subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(repository), *arguments,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exception:
        raise ProofValidationError("Git is required to validate Tool contract evidence") from exception
    if completed.returncode != 0:
        raise ProofValidationError("Git could not verify the Tool contract candidate")
    if len(completed.stdout) > limit or len(completed.stderr) > limit:
        raise ProofValidationError("Git candidate verification output is unexpectedly large")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
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
        top_level = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(
            strict=True
        )
    except OSError as exception:
        raise ProofValidationError("repository root cannot be resolved") from exception
    if top_level != repository:
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


def _safe_workspace_file(repository: Path, relative: str) -> bytes:
    target = repository.joinpath(*relative.split("/"))
    if target.is_symlink() or not target.is_file():
        raise ProofValidationError(f"candidate source must be a regular file: {relative}")
    resolved = target.resolve(strict=True)
    if not _inside(resolved, repository):
        raise ProofValidationError(f"candidate source escaped the repository: {relative}")
    payload = resolved.read_bytes()
    if not payload or len(payload) > MAX_SOURCE_BYTES:
        raise ProofValidationError(f"candidate source size is invalid: {relative}")
    return payload


def _parse_xml(payload: bytes, label: str) -> ET.Element:
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", payload, flags=re.IGNORECASE):
        raise ProofValidationError(f"{label} must not contain a DOCTYPE or entity declaration")
    try:
        return ET.fromstring(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ET.ParseError) as exception:
        raise ProofValidationError(f"{label} is not valid XML") from exception


def _direct_text(root: ET.Element, child_name: str, label: str) -> str:
    matches = [child for child in list(root) if _local_name(child.tag) == child_name]
    if len(matches) != 1 or matches[0].text is None or not matches[0].text.strip():
        raise ProofValidationError(f"{label} must contain exactly one {child_name}")
    return matches[0].text.strip()


def _project_versions_and_sdk(
    root_payload: bytes,
    module_payload: bytes,
    frontend_payload: bytes,
    expected_version: str,
) -> str:
    root = _parse_xml(root_payload, "root pom.xml")
    module = _parse_xml(module_payload, "MCP module pom.xml")
    if _local_name(root.tag) != "project" or _local_name(module.tag) != "project":
        raise ProofValidationError("Maven source root must be project")
    root_version = _direct_text(root, "version", "root pom.xml")
    parents = [child for child in list(module) if _local_name(child.tag) == "parent"]
    if len(parents) != 1:
        raise ProofValidationError("MCP module pom.xml must have one parent")
    module_version = _direct_text(parents[0], "version", "MCP module parent")
    frontend = _json_without_duplicates(frontend_payload, "frontend package.json")
    if not isinstance(frontend, dict) or not isinstance(frontend.get("version"), str):
        raise ProofValidationError("frontend package.json must have a string version")
    versions = (root_version, module_version, frontend["version"], expected_version)
    if len(set(versions)) != 1 or any("SNAPSHOT" in value.upper() for value in versions):
        raise ProofValidationError(
            "root Maven, MCP module parent, frontend, and candidate versions must match and be non-SNAPSHOT"
        )

    properties_nodes = [child for child in list(root) if _local_name(child.tag) == "properties"]
    if len(properties_nodes) != 1:
        raise ProofValidationError("root pom.xml must contain one properties block")
    sdk_versions = [
        child.text.strip()
        for child in list(properties_nodes[0])
        if _local_name(child.tag) == "mcp-sdk.version" and child.text
    ]
    if len(sdk_versions) != 1 or VERSION_PATTERN.fullmatch(sdk_versions[0]) is None:
        raise ProofValidationError("root pom.xml must pin one MCP SDK version")
    if "SNAPSHOT" in sdk_versions[0].upper():
        raise ProofValidationError("root pom.xml MCP SDK version must not be a SNAPSHOT")

    root_dependencies = [
        element for element in root.iter() if _local_name(element.tag) == "dependency"
    ]
    bom_matches = []
    for dependency in root_dependencies:
        fields: dict[str, list[str]] = {}
        for child in list(dependency):
            if child.text:
                fields.setdefault(_local_name(child.tag), []).append(child.text.strip())
        if fields.get("groupId") == ["io.modelcontextprotocol.sdk"] \
                and fields.get("artifactId") == ["mcp-bom"]:
            bom_matches.append(fields)
    if len(bom_matches) != 1 or bom_matches[0].get("version") != ["${mcp-sdk.version}"] \
            or bom_matches[0].get("type") != ["pom"] \
            or bom_matches[0].get("scope") != ["import"]:
        raise ProofValidationError("root pom.xml must import one pinned official MCP SDK BOM")

    dependencies = [element for element in module.iter() if _local_name(element.tag) == "dependency"]
    coordinates = []
    for dependency in dependencies:
        group = [child.text.strip() for child in list(dependency)
                 if _local_name(child.tag) == "groupId" and child.text]
        artifact = [child.text.strip() for child in list(dependency)
                    if _local_name(child.tag) == "artifactId" and child.text]
        if len(group) == 1 and len(artifact) == 1:
            coordinates.append((group[0], artifact[0]))
    if coordinates.count(("io.modelcontextprotocol.sdk", "mcp")) != 1:
        raise ProofValidationError("MCP module must use exactly one official MCP SDK dependency")
    return sdk_versions[0]


def _validate_candidate(
    repository: Path,
    declared_commit: str,
    declared_tree: str,
    candidate_tag: str,
    expected_version: str,
) -> CandidateBinding:
    actual_commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    actual_tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if actual_commit != declared_commit or actual_tree != declared_tree:
        raise ProofValidationError("Git HEAD does not equal the declared candidate identity")
    _require_pattern(actual_commit, OBJECT_ID_PATTERN, "candidate commit")
    _require_pattern(actual_tree, OBJECT_ID_PATTERN, "candidate tree")
    if _git_text(repository, "cat-file", "-t", f"refs/tags/{candidate_tag}") != "tag":
        raise ProofValidationError("candidate tag must be an annotated Git tag")
    if _git_text(repository, "rev-parse", "--verify", f"refs/tags/{candidate_tag}^{{commit}}") \
            != actual_commit:
        raise ProofValidationError("candidate tag does not resolve to the candidate commit")
    _require_clean_candidate(repository)

    payloads: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for relative in SOURCE_PATHS.values():
        workspace = _safe_workspace_file(repository, relative)
        committed = _candidate_blob(repository, actual_commit, relative)
        if workspace != committed:
            raise ProofValidationError(
                f"workspace source differs from candidate commit blob: {relative}"
            )
        payloads[relative] = committed
        hashes[relative] = _sha256(committed)

    executing = Path(__file__).resolve(strict=True).read_bytes()
    if executing != payloads[SOURCE_PATHS["validatorSha256"]]:
        raise ProofValidationError(
            "executing Tool contract validator differs from candidate validator source"
        )
    sdk_version = _project_versions_and_sdk(
        payloads[SOURCE_PATHS["rootPomSha256"]],
        payloads[SOURCE_PATHS["modulePomSha256"]],
        payloads[SOURCE_PATHS["frontendPackageSha256"]],
        expected_version,
    )
    _validate_summary_schema_source(payloads[SUMMARY_SCHEMA])
    return CandidateBinding(
        actual_commit,
        actual_tree,
        dict(sorted(hashes.items())),
        payloads,
        sdk_version,
    )


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
    except json.JSONDecodeError as exception:
        raise ProofValidationError(f"{label} is not valid JSON") from exception


def _validate_summary_schema_source(payload: bytes) -> None:
    schema = _json_without_duplicates(payload, "Tool contract summary schema")
    if not isinstance(schema, dict):
        raise ProofValidationError("Tool contract summary schema must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ProofValidationError("Tool contract summary schema draft is invalid")
    if schema.get("$id") != (
        "https://web-starter.invalid/schema/v2-ac33-mcp-tool-contract-summary.schema.json"
    ):
        raise ProofValidationError("Tool contract summary schema id is invalid")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise ProofValidationError("Tool contract summary schema root must be closed")
    required = schema.get("required")
    properties = schema.get("properties")
    expected = {
        "schemaVersion", "status", "acceptanceId", "candidate", "runtime", "protocol",
        "writeTools", "stableErrors", "legacyCompatibility", "sources", "evidence",
    }
    if not isinstance(required, list) or set(required) != expected:
        raise ProofValidationError("Tool contract summary schema required fields drifted")
    if not isinstance(properties, dict) or set(properties) != expected:
        raise ProofValidationError("Tool contract summary schema properties drifted")
    if properties.get("status", {}).get("const") != "PASS" \
            or properties.get("acceptanceId", {}).get("const") != ACCEPTANCE_ID:
        raise ProofValidationError("Tool contract summary schema identity drifted")


def _open_evidence_directory(proof_path: Path, repository: Path) -> tuple[Path, int]:
    requested = proof_path.expanduser().absolute()
    if requested.name != PROOF_FILE or requested.is_symlink():
        raise ProofValidationError(f"proof must be a non-symlink file named {PROOF_FILE}")
    parent = requested.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProofValidationError("proof directory must be a non-symlink directory")
    resolved = parent.resolve(strict=True)
    if _inside(resolved, repository) or _inside(repository, resolved):
        raise ProofValidationError("proof directory must be outside and must not contain the repository")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(resolved, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ProofValidationError("proof directory must be a real directory with mode 0700")
    return resolved, descriptor


def _directory_names(descriptor: int) -> set[str]:
    names = os.listdir(descriptor)
    if any(not isinstance(name, str) or not name or "/" in name or "\0" in name for name in names):
        raise ProofValidationError("proof directory contains an invalid entry")
    return set(names)


def _read_private_file(descriptor: int, name: str, maximum: int, label: str) -> FileSnapshot:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    child = os.open(name, flags, dir_fd=descriptor)
    try:
        metadata = os.fstat(child)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode) or mode != 0o600:
            raise ProofValidationError(f"{label} must be a regular file with mode 0600")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            raise ProofValidationError(f"{label} size is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(child, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(child)
        if (
            len(payload) != metadata.st_size
            or len(payload) > maximum
            or (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ProofValidationError(f"{label} changed while it was read")
        return FileSnapshot(
            payload, _sha256(payload), metadata.st_dev, metadata.st_ino,
            metadata.st_size, metadata.st_mtime_ns, mode,
        )
    finally:
        os.close(child)


def _parse_properties(payload: bytes) -> dict[str, str]:
    if not payload or len(payload) > MAX_PROOF_BYTES:
        raise ProofValidationError("Tool contract proof size is invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError("Tool contract proof is not valid UTF-8") from exception
    if text.startswith("\ufeff") or "\r" in text or "\0" in text or not text.endswith("\n"):
        raise ProofValidationError("Tool contract proof uses non-canonical text encoding")
    values: dict[str, str] = {}
    order: list[str] = []
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise ProofValidationError("Tool contract proof contains invalid properties syntax")
        key, value = line.split("=", 1)
        if KEY_PATTERN.fullmatch(key) is None or key in values:
            raise ProofValidationError("Tool contract proof contains an invalid or duplicate key")
        if not value or value != value.strip() or any(ord(character) < 0x20 for character in value):
            raise ProofValidationError("Tool contract proof contains an empty or malformed value")
        values[key] = value
        order.append(key)
    if tuple(order) != PROOF_KEYS:
        raise ProofValidationError("Tool contract proof keys differ from the canonical exact schema")
    return values


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
    if SECRET_PATTERN.search(trace_prefix):
        raise ProofValidationError("expected trace prefix contains secret-shaped content")


def _validate_proof_values(
    values: Mapping[str, str],
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
    expected_compose_project: str,
    expected_trace_prefix: str,
) -> int:
    expected = {
        "schemaVersion": "1",
        "testClass": TEST_CLASS,
        "testMethod": TEST_METHOD,
        "reportFile": REPORT_FILE,
        "candidateCommit": expected_commit,
        "candidateVersion": expected_version,
        "candidateTag": expected_tag,
        "composeProject": expected_compose_project,
        "tracePrefix": expected_trace_prefix,
    }
    for key, expected_value in expected.items():
        if values[key] != expected_value:
            raise ProofValidationError(f"Tool contract proof {key} does not match expected input")
    _require_pattern(values["candidateTree"], OBJECT_ID_PATTERN, "proof candidate tree")
    for key in ("reportSha256", *SOURCE_PATHS):
        _require_pattern(values[key], SHA256_PATTERN, f"proof {key}")
    try:
        started_at = int(values["startedAtEpochNs"], 10)
    except ValueError as exception:
        raise ProofValidationError("Tool contract proof start time is invalid") from exception
    if started_at <= 0 or str(started_at) != values["startedAtEpochNs"] \
            or started_at > time.time_ns():
        raise ProofValidationError("Tool contract proof start time is invalid")
    return started_at


def _validate_surefire(report: FileSnapshot, started_at: int) -> None:
    now = time.time_ns()
    if report.modified_ns < started_at or report.modified_ns > now + 5_000_000_000:
        raise ProofValidationError("Tool contract Surefire report is stale or future-dated")
    suite = _parse_xml(report.payload, "Tool contract Surefire report")
    if _local_name(suite.tag) != "testsuite" or suite.attrib.get("name") != TEST_CLASS:
        raise ProofValidationError("Tool contract Surefire report identifies a different suite")
    suites = [element for element in suite.iter() if _local_name(element.tag) == "testsuite"]
    cases = [element for element in suite.iter() if _local_name(element.tag) == "testcase"]
    direct_cases = [element for element in list(suite) if _local_name(element.tag) == "testcase"]
    expected = {
        "tests": "1", "failures": "0", "errors": "0", "skipped": "0", "flakes": "0"
    }
    if suites != [suite] or any(suite.attrib.get(key) != value for key, value in expected.items()):
        raise ProofValidationError("Tool contract result is not exactly one clean passing test")
    if len(cases) != 1 or len(direct_cases) != 1 \
            or cases[0] is not direct_cases[0] \
            or cases[0].attrib.get("classname") != TEST_CLASS \
            or cases[0].attrib.get("name") != TEST_METHOD:
        raise ProofValidationError("Tool contract Surefire report identifies a different method")
    for element in suite.iter():
        local = _local_name(element.tag).lower()
        if local in FORBIDDEN_RESULT_ELEMENTS or "retry" in local or "rerun" in local \
                or ("flak" in local and local != "testsuite"):
            raise ProofValidationError(
                "Tool contract Surefire report contains failure, skip, retry, or flake evidence"
            )
        for attribute in element.attrib:
            attribute_name = _local_name(attribute).lower()
            if "retry" in attribute_name or "rerun" in attribute_name \
                    or ("flak" in attribute_name and attribute_name != "flakes"):
                raise ProofValidationError(
                    "Tool contract Surefire report contains failure, skip, retry, or flake evidence"
                )


def _same_snapshot(before: FileSnapshot, after: FileSnapshot, label: str) -> None:
    if before != after:
        raise ProofValidationError(f"{label} changed during validation")


def _summary_secret_free(value: Any, path: str = "summary") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _summary_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _summary_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_PATTERN.search(value):
        raise ProofValidationError(f"summary would contain secret-shaped content at {path}")


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    _summary_secret_free(summary)
    return (
        json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _write_summary(output_directory: Path, repository: Path, summary: Mapping[str, Any]) -> Path:
    requested = output_directory.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise ProofValidationError("summary output must be a non-symlink directory")
    directory = requested.resolve(strict=True)
    if _inside(directory, repository) or _inside(repository, directory):
        raise ProofValidationError("summary output must be outside and must not contain repository")
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ProofValidationError("summary output directory must be empty with mode 0700")
    payload = canonical_summary_bytes(summary)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_descriptor = os.open(directory, directory_flags)
    created = False
    try:
        identity = os.fstat(directory_descriptor)
        if os.listdir(directory_descriptor):
            raise ProofValidationError("summary output directory must be empty with mode 0700")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(SUMMARY_FILE, flags, 0o600, dir_fd=directory_descriptor)
        created = True
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise ProofValidationError("summary output write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise ProofValidationError("summary output must have mode 0600")
        finally:
            os.close(descriptor)
        current = directory.stat()
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino) \
                or set(os.listdir(directory_descriptor)) != {SUMMARY_FILE}:
            raise ProofValidationError("summary output changed during creation")
        return directory / SUMMARY_FILE
    except Exception:
        if created:
            try:
                os.unlink(SUMMARY_FILE, dir_fd=directory_descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(directory_descriptor)


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
    """Validate private raw evidence and optionally emit one canonical PASS summary."""
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
    evidence_directory, descriptor = _open_evidence_directory(proof_path, repository)
    try:
        expected_names = {PROOF_FILE, REPORT_FILE}
        if _directory_names(descriptor) != expected_names:
            raise ProofValidationError("proof directory must contain only proof and report")
        proof_before = _read_private_file(
            descriptor, PROOF_FILE, MAX_PROOF_BYTES, "Tool contract proof"
        )
        report_before = _read_private_file(
            descriptor, REPORT_FILE, MAX_REPORT_BYTES, "Tool contract Surefire report"
        )
        values = _parse_properties(proof_before.payload)
        started_at = _validate_proof_values(
            values,
            expected_candidate_commit,
            expected_candidate_version,
            expected_candidate_tag,
            expected_compose_project,
            expected_trace_prefix,
        )
        if values["reportSha256"] != report_before.sha256:
            raise ProofValidationError("proof report hash does not match Surefire report")
        _validate_surefire(report_before, started_at)

        binding = _validate_candidate(
            repository,
            values["candidateCommit"],
            values["candidateTree"],
            values["candidateTag"],
            expected_candidate_version,
        )
        for key, relative in SOURCE_PATHS.items():
            if values[key] != binding.source_sha256[relative]:
                raise ProofValidationError(
                    f"proof source hash does not match candidate bytes: {relative}"
                )

        if _directory_names(descriptor) != expected_names:
            raise ProofValidationError("proof directory changed during validation")
        proof_after = _read_private_file(
            descriptor, PROOF_FILE, MAX_PROOF_BYTES, "Tool contract proof"
        )
        report_after = _read_private_file(
            descriptor, REPORT_FILE, MAX_REPORT_BYTES, "Tool contract Surefire report"
        )
        _same_snapshot(proof_before, proof_after, "Tool contract proof")
        _same_snapshot(report_before, report_after, "Tool contract Surefire report")
        current = evidence_directory.stat()
        opened = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProofValidationError("proof directory changed during validation")

        final_binding = _validate_candidate(
            repository,
            values["candidateCommit"],
            values["candidateTree"],
            values["candidateTag"],
            expected_candidate_version,
        )
        if final_binding.source_sha256 != binding.source_sha256 \
                or final_binding.sdk_version != binding.sdk_version:
            raise ProofValidationError("candidate source changed during validation")
        _same_snapshot(
            proof_before,
            _read_private_file(descriptor, PROOF_FILE, MAX_PROOF_BYTES, "Tool contract proof"),
            "Tool contract proof",
        )
        _same_snapshot(
            report_before,
            _read_private_file(
                descriptor, REPORT_FILE, MAX_REPORT_BYTES, "Tool contract Surefire report"
            ),
            "Tool contract Surefire report",
        )
    finally:
        os.close(descriptor)

    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "PASS",
        "acceptanceId": ACCEPTANCE_ID,
        "candidate": {
            "commit": binding.commit,
            "tree": binding.tree,
            "version": expected_candidate_version,
            "tag": expected_candidate_tag,
        },
        "runtime": {
            "composeProject": expected_compose_project,
            "tracePrefix": expected_trace_prefix,
        },
        "protocol": {
            "sdkArtifact": "io.modelcontextprotocol.sdk:mcp",
            "sdkVersion": binding.sdk_version,
            "protocolVersion": "2025-11-25",
            "testClass": TEST_CLASS,
            "testMethod": TEST_METHOD,
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "flakes": 0,
            "baselineTools": list(BASELINE_TOOLS),
        },
        "writeTools": {
            name: {"outputSchema": True, "annotations": annotations}
            for name, annotations in WRITE_TOOLS.items()
        },
        "stableErrors": {
            "schemaPattern": ERROR_CODE_PATTERN,
            "observed": list(OBSERVED_ERROR_CODES),
        },
        "legacyCompatibility": {
            "clientName": "web-starter-v1-contract-client",
            "clientVersion": "1.0.0",
            "omittedArgument": "idempotencyKey",
            "successfulCalls": ["project.create", "project.update", "project.remove"],
            "migration": "V2 clients should send a retry key; the V1 no-key path remains accepted",
        },
        "sources": dict(binding.source_sha256),
        "evidence": {
            "proofFile": PROOF_FILE,
            "proofSha256": proof_before.sha256,
            "reportFile": REPORT_FILE,
            "reportSha256": report_before.sha256,
        },
    }
    canonical_summary_bytes(summary)
    if summary_output is not None:
        _write_summary(summary_output, repository, summary)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--proof", required=True, type=Path)
    result.add_argument("--repository-root", required=True, type=Path)
    result.add_argument("--expected-candidate-commit", required=True)
    result.add_argument("--expected-candidate-version", required=True)
    result.add_argument("--expected-candidate-tag", required=True)
    result.add_argument("--expected-compose-project", required=True)
    result.add_argument("--expected-trace-prefix", required=True)
    result.add_argument("--require-pass", action="store_true")
    result.add_argument("--summary-output", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        summary = validate_proof(
            arguments.proof,
            repository_root=arguments.repository_root,
            expected_candidate_commit=arguments.expected_candidate_commit,
            expected_candidate_version=arguments.expected_candidate_version,
            expected_candidate_tag=arguments.expected_candidate_tag,
            expected_compose_project=arguments.expected_compose_project,
            expected_trace_prefix=arguments.expected_trace_prefix,
            require_pass=arguments.require_pass,
            summary_output=arguments.summary_output,
        )
    except (OSError, ProofValidationError) as exception:
        raise SystemExit(f"MCP Tool contract evidence rejected: {exception}") from exception
    print(
        f"status={summary['status']} acceptance={summary['acceptanceId']} "
        f"candidate={summary['candidate']['commit']} test={TEST_CLASS}#{TEST_METHOD}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
