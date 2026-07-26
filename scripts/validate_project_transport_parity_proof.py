#!/usr/bin/env python3
"""Independently validate V1 AC-15 Project transport-parity raw evidence."""

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


ACCEPTANCE_ID = "AC-15"
TEST_CLASS = "dev.webstarter.admin.acceptance.ProjectTransportParityIT"
TEST_METHOD = "provesRestAndMcpShareProjectServiceWithoutProjectPersistenceDependency"
REPORT_FILE = f"TEST-{TEST_CLASS}.xml"
PROOF_FILE = "project-transport-parity-proof.properties"
SUMMARY_FILE = "project-transport-parity-proof-summary.json"
SUMMARY_SCHEMA = "security/v1-ac15-project-transport-parity-summary.schema.json"
FIXED_TEST_SHA256 = "aa6a9732e2fdc925bbb01f9e83634b4c3157f6323b4790133acab20dc5997487"
ADAPTER_CLASSES = (
    "dev.webstarter.project.web.ProjectController",
    "dev.webstarter.mcp.service.McpToolCatalog",
    "dev.webstarter.mcp.service.McpContentCatalog",
)
SHARED_SERVICE = "dev.webstarter.project.service.ProjectService"
FORBIDDEN_PROJECT_PERSISTENCE_REFERENCES = (
    "dev/webstarter/project/persistence/",
    "dev.webstarter.project.persistence.",
    "ProjectMapper",
)
SOURCE_PATHS = {
    "integrationTestSha256": (
        "web-starter-admin/src/test/java/dev/webstarter/admin/acceptance/"
        "ProjectTransportParityIT.java"
    ),
    "projectServiceSha256": (
        "web-starter-project/src/main/java/dev/webstarter/project/service/ProjectService.java"
    ),
    "projectServiceImplSha256": (
        "web-starter-project/src/main/java/dev/webstarter/project/service/impl/"
        "ProjectServiceImpl.java"
    ),
    "projectControllerSha256": (
        "web-starter-project/src/main/java/dev/webstarter/project/web/ProjectController.java"
    ),
    "mcpToolCatalogSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolCatalog.java"
    ),
    "mcpContentCatalogSha256": (
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpContentCatalog.java"
    ),
    "rootPomSha256": "pom.xml",
    "projectPomSha256": "web-starter-project/pom.xml",
    "mcpPomSha256": "web-starter-mcp/pom.xml",
    "adminPomSha256": "web-starter-admin/pom.xml",
    "producerSha256": "scripts/create_project_transport_parity_proof.py",
    "validatorSha256": "scripts/validate_project_transport_parity_proof.py",
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
    "startedAtEpochNs",
)
PROOF_KEYS = FIXED_PROOF_KEYS + tuple(SOURCE_PATHS)
KEY_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
OBJECT_ID_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
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
    """Raised when AC-15 evidence cannot become an independently verified PASS."""


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


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git(repository: Path, *arguments: str, limit: int = MAX_GIT_OUTPUT_BYTES) -> bytes:
    environment = _git_environment()
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
        raise ProofValidationError("Git is required to validate AC-15 evidence") from exception
    if completed.returncode != 0:
        raise ProofValidationError("Git could not verify the AC-15 candidate")
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
    repository = absolute.resolve(strict=True)
    top_level = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(
        strict=True
    )
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
        raise ProofValidationError(f"candidate source escaped repository: {relative}")
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


def _parent_version(root: ET.Element, label: str) -> str:
    parents = [child for child in list(root) if _local_name(child.tag) == "parent"]
    if len(parents) != 1:
        raise ProofValidationError(f"{label} must contain exactly one parent")
    return _direct_text(parents[0], "version", f"{label} parent")


def _dependency_coordinates(root: ET.Element) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    direct_dependencies = [
        child for child in list(root) if _local_name(child.tag) == "dependencies"
    ]
    if len(direct_dependencies) > 1:
        raise ProofValidationError("POM contains multiple direct dependencies blocks")
    if not direct_dependencies:
        return result
    for dependency in list(direct_dependencies[0]):
        if _local_name(dependency.tag) != "dependency":
            continue
        result.append((
            _direct_text(dependency, "groupId", "dependency"),
            _direct_text(dependency, "artifactId", "dependency"),
        ))
    return result


def _validate_poms(payloads: Mapping[str, bytes], expected_version: str) -> None:
    root = _parse_xml(payloads[SOURCE_PATHS["rootPomSha256"]], "root pom.xml")
    project = _parse_xml(payloads[SOURCE_PATHS["projectPomSha256"]], "Project pom.xml")
    mcp = _parse_xml(payloads[SOURCE_PATHS["mcpPomSha256"]], "MCP pom.xml")
    admin = _parse_xml(payloads[SOURCE_PATHS["adminPomSha256"]], "Admin pom.xml")
    if any(_local_name(element.tag) != "project" for element in (root, project, mcp, admin)):
        raise ProofValidationError("all Maven sources must have a project root")
    versions = (
        _direct_text(root, "version", "root pom.xml"),
        _parent_version(project, "Project pom.xml"),
        _parent_version(mcp, "MCP pom.xml"),
        _parent_version(admin, "Admin pom.xml"),
        expected_version,
    )
    if len(set(versions)) != 1 or any("SNAPSHOT" in value.upper() for value in versions):
        raise ProofValidationError(
            "root and module Maven versions must match candidate and be non-SNAPSHOT"
        )
    mcp_dependencies = _dependency_coordinates(mcp)
    admin_dependencies = _dependency_coordinates(admin)
    project_coordinate = ("dev.webstarter", "web-starter-project")
    mcp_coordinate = ("dev.webstarter", "web-starter-mcp")
    if mcp_dependencies.count(project_coordinate) != 1:
        raise ProofValidationError("MCP module must depend on Project module exactly once")
    if admin_dependencies.count(project_coordinate) != 1 \
            or admin_dependencies.count(mcp_coordinate) != 1:
        raise ProofValidationError(
            "Admin module must depend on Project and MCP modules exactly once"
        )

    properties = [child for child in list(admin) if _local_name(child.tag) == "properties"]
    if len(properties) != 1:
        raise ProofValidationError("Admin pom.xml must contain one properties block")
    report_properties = [
        child.text.strip()
        for child in list(properties[0])
        if _local_name(child.tag) == "web-starter.admin.surefire-reports-directory"
        and child.text
    ]
    if report_properties != ["${project.build.directory}/surefire-reports"]:
        raise ProofValidationError("Admin Surefire report directory property drifted")
    surefire_plugins = []
    for plugin in admin.iter():
        if _local_name(plugin.tag) != "plugin":
            continue
        artifacts = [
            child.text.strip() for child in list(plugin)
            if _local_name(child.tag) == "artifactId" and child.text
        ]
        if artifacts == ["maven-surefire-plugin"]:
            surefire_plugins.append(plugin)
    if len(surefire_plugins) != 1:
        raise ProofValidationError("Admin pom.xml must configure one Surefire plugin")
    configurations = [
        child for child in list(surefire_plugins[0])
        if _local_name(child.tag) == "configuration"
    ]
    if len(configurations) != 1 or _direct_text(
        configurations[0], "reportsDirectory", "Admin Surefire configuration"
    ) != "${web-starter.admin.surefire-reports-directory}":
        raise ProofValidationError("Admin Surefire report routing drifted")


def _json_without_duplicates(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError(f"{label} is not valid UTF-8") from exception

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProofValidationError(f"{label} contains duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(value: str) -> Any:
        raise ProofValidationError(f"{label} contains non-finite number: {value}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except ProofValidationError:
        raise
    except json.JSONDecodeError as exception:
        raise ProofValidationError(f"{label} is not valid JSON") from exception


def _validate_summary_schema_source(payload: bytes) -> None:
    schema = _json_without_duplicates(payload, "AC-15 summary schema")
    expected = {
        "schemaVersion", "status", "acceptanceId", "candidate", "springContext",
        "persistenceBoundary", "sources", "evidence",
    }
    if not isinstance(schema, dict) \
            or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" \
            or schema.get("$id") != (
                "https://web-starter.invalid/schema/"
                "v1-ac15-project-transport-parity-summary.schema.json"
            ) \
            or schema.get("type") != "object" \
            or schema.get("additionalProperties") is not False:
        raise ProofValidationError("AC-15 summary schema root identity drifted")
    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or set(required) != expected \
            or not isinstance(properties, dict) or set(properties) != expected:
        raise ProofValidationError("AC-15 summary schema fields drifted")
    if properties.get("status", {}).get("const") != "PASS" \
            or properties.get("acceptanceId", {}).get("const") != ACCEPTANCE_ID:
        raise ProofValidationError("AC-15 summary schema PASS identity drifted")


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
        raise ProofValidationError("Git HEAD does not equal declared candidate identity")
    _require_pattern(actual_commit, OBJECT_ID_PATTERN, "candidate commit")
    _require_pattern(actual_tree, OBJECT_ID_PATTERN, "candidate tree")
    if _git_text(repository, "cat-file", "-t", f"refs/tags/{candidate_tag}") != "tag":
        raise ProofValidationError("candidate tag must be an annotated Git tag")
    if _git_text(repository, "rev-parse", "--verify", f"refs/tags/{candidate_tag}^{{commit}}") \
            != actual_commit:
        raise ProofValidationError("candidate tag does not resolve to candidate commit")
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
    if hashes[SOURCE_PATHS["integrationTestSha256"]] != FIXED_TEST_SHA256:
        raise ProofValidationError("AC-15 fixed integration test source has drifted")
    executing = Path(__file__).resolve(strict=True).read_bytes()
    if executing != payloads[SOURCE_PATHS["validatorSha256"]]:
        raise ProofValidationError("executing AC-15 validator differs from candidate source")
    _validate_poms(payloads, expected_version)
    _validate_summary_schema_source(payloads[SUMMARY_SCHEMA])
    return CandidateBinding(
        actual_commit,
        actual_tree,
        dict(sorted(hashes.items())),
        dict(payloads),
    )


def _open_evidence_directory(proof_path: Path, repository: Path) -> tuple[Path, int]:
    requested = proof_path.expanduser().absolute()
    if requested.name != PROOF_FILE or requested.is_symlink():
        raise ProofValidationError(f"proof must be non-symlink file named {PROOF_FILE}")
    parent = requested.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProofValidationError("proof directory must be a non-symlink directory")
    resolved = parent.resolve(strict=True)
    if _inside(resolved, repository) or _inside(repository, resolved):
        raise ProofValidationError("proof directory must be outside and not contain repository")
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
        raise ProofValidationError("proof directory must be real directory with mode 0700")
    return resolved, descriptor


def _directory_names(descriptor: int) -> set[str]:
    names = os.listdir(descriptor)
    if any(not isinstance(name, str) or not name or "/" in name or "\0" in name for name in names):
        raise ProofValidationError("proof directory contains invalid entry")
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
            raise ProofValidationError(f"{label} must be regular file with mode 0600")
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
            raise ProofValidationError(f"{label} changed while read")
        return FileSnapshot(
            payload,
            _sha256(payload),
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            mode,
        )
    finally:
        os.close(child)


def _parse_properties(payload: bytes) -> dict[str, str]:
    if not payload or len(payload) > MAX_PROOF_BYTES:
        raise ProofValidationError("AC-15 proof size is invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError("AC-15 proof is not valid UTF-8") from exception
    if text.startswith("\ufeff") or "\r" in text or "\0" in text or not text.endswith("\n"):
        raise ProofValidationError("AC-15 proof uses non-canonical text encoding")
    values: dict[str, str] = {}
    order: list[str] = []
    for line in text[:-1].split("\n"):
        if line.count("=") != 1:
            raise ProofValidationError("AC-15 proof contains invalid properties syntax")
        key, value = line.split("=", 1)
        if KEY_PATTERN.fullmatch(key) is None or key in values:
            raise ProofValidationError("AC-15 proof contains invalid or duplicate key")
        if not value or value != value.strip() \
                or any(ord(character) < 0x20 for character in value):
            raise ProofValidationError("AC-15 proof contains empty or malformed value")
        values[key] = value
        order.append(key)
    if tuple(order) != PROOF_KEYS:
        raise ProofValidationError("AC-15 proof keys differ from canonical exact schema")
    return values


def _validate_expected_inputs(commit: str, version: str, tag: str) -> None:
    _require_pattern(commit, OBJECT_ID_PATTERN, "expected candidate commit")
    _require_pattern(version, VERSION_PATTERN, "expected candidate version")
    if "SNAPSHOT" in version.upper():
        raise ProofValidationError("candidate version must not be SNAPSHOT")
    if tag != f"v{version}":
        raise ProofValidationError("expected candidate tag must equal v plus version")


def _validate_proof_values(
    values: Mapping[str, str],
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
) -> int:
    expected = {
        "schemaVersion": "1",
        "testClass": TEST_CLASS,
        "testMethod": TEST_METHOD,
        "reportFile": REPORT_FILE,
        "candidateCommit": expected_commit,
        "candidateVersion": expected_version,
        "candidateTag": expected_tag,
    }
    for key, expected_value in expected.items():
        if values[key] != expected_value:
            raise ProofValidationError(f"AC-15 proof {key} does not match expected input")
    _require_pattern(values["candidateTree"], OBJECT_ID_PATTERN, "proof candidate tree")
    for key in ("reportSha256", *SOURCE_PATHS):
        _require_pattern(values[key], SHA256_PATTERN, f"proof {key}")
    try:
        started_at = int(values["startedAtEpochNs"], 10)
    except ValueError as exception:
        raise ProofValidationError("AC-15 proof start time is invalid") from exception
    if started_at <= 0 or str(started_at) != values["startedAtEpochNs"] \
            or started_at > time.time_ns():
        raise ProofValidationError("AC-15 proof start time is invalid")
    return started_at


def _validate_surefire(report: FileSnapshot, started_at: int) -> None:
    now = time.time_ns()
    if report.modified_ns < started_at or report.modified_ns > now + 5_000_000_000:
        raise ProofValidationError("AC-15 Surefire report is stale or future-dated")
    suite = _parse_xml(report.payload, "AC-15 Surefire report")
    suites = [element for element in suite.iter() if _local_name(element.tag) == "testsuite"]
    cases = [element for element in suite.iter() if _local_name(element.tag) == "testcase"]
    direct_cases = [element for element in list(suite) if _local_name(element.tag) == "testcase"]
    expected = {"tests": "1", "failures": "0", "errors": "0", "skipped": "0", "flakes": "0"}
    if (
        _local_name(suite.tag) != "testsuite"
        or suite.attrib.get("name") != TEST_CLASS
        or suites != [suite]
        or any(suite.attrib.get(key) != value for key, value in expected.items())
        or len(cases) != 1
        or cases != direct_cases
        or cases[0].attrib.get("classname") != TEST_CLASS
        or cases[0].attrib.get("name") != TEST_METHOD
    ):
        raise ProofValidationError("AC-15 result is not exactly one clean passing test")
    for element in suite.iter():
        local = _local_name(element.tag).lower()
        if local in FORBIDDEN_RESULT_ELEMENTS or "retry" in local or "rerun" in local \
                or ("flak" in local and local != "testsuite"):
            raise ProofValidationError(
                "AC-15 Surefire report contains failure, skip, retry, or flake evidence"
            )
        for attribute in element.attrib:
            name = _local_name(attribute).lower()
            if "retry" in name or "rerun" in name or ("flak" in name and name != "flakes"):
                raise ProofValidationError(
                    "AC-15 Surefire report contains failure, skip, retry, or flake evidence"
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
        raise ProofValidationError(f"summary contains secret-shaped content at {path}")


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    _summary_secret_free(summary)
    return (
        json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _write_summary(output_directory: Path, repository: Path, summary: Mapping[str, Any]) -> Path:
    requested = output_directory.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise ProofValidationError("summary output must be non-symlink directory")
    directory = requested.resolve(strict=True)
    if _inside(directory, repository) or _inside(repository, directory):
        raise ProofValidationError("summary output must be outside and not contain repository")
    if stat.S_IMODE(directory.stat().st_mode) != 0o700 or os.listdir(directory):
        raise ProofValidationError("summary output directory must be empty with mode 0700")
    payload = canonical_summary_bytes(summary)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(directory / SUMMARY_FILE, flags, 0o600)
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
    finally:
        os.close(descriptor)
    if set(os.listdir(directory)) != {SUMMARY_FILE} \
            or stat.S_IMODE((directory / SUMMARY_FILE).stat().st_mode) != 0o600:
        (directory / SUMMARY_FILE).unlink(missing_ok=True)
        raise ProofValidationError("summary output changed during creation")
    return directory / SUMMARY_FILE


def validate_proof(
    proof_path: Path,
    *,
    repository_root: Path,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    require_pass: bool = False,
    summary_output: Path | None = None,
) -> dict[str, Any]:
    """Validate private raw evidence and optionally emit one canonical PASS summary."""
    _validate_expected_inputs(
        expected_candidate_commit,
        expected_candidate_version,
        expected_candidate_tag,
    )
    if summary_output is not None and not require_pass:
        raise ProofValidationError("--summary-output requires --require-pass")
    repository = _resolve_repository(repository_root)
    _evidence_directory, descriptor = _open_evidence_directory(proof_path, repository)
    try:
        if _directory_names(descriptor) != {PROOF_FILE, REPORT_FILE}:
            raise ProofValidationError("proof directory must contain only proof and report")
        proof = _read_private_file(descriptor, PROOF_FILE, MAX_PROOF_BYTES, "AC-15 proof")
        report = _read_private_file(descriptor, REPORT_FILE, MAX_REPORT_BYTES, "Surefire report")
        values = _parse_properties(proof.payload)
        started_at = _validate_proof_values(
            values,
            expected_candidate_commit,
            expected_candidate_version,
            expected_candidate_tag,
        )
        if values["reportSha256"] != report.sha256:
            raise ProofValidationError("AC-15 proof report hash does not match report")
        _validate_surefire(report, started_at)
        candidate = _validate_candidate(
            repository,
            values["candidateCommit"],
            values["candidateTree"],
            values["candidateTag"],
            values["candidateVersion"],
        )
        for key, relative in SOURCE_PATHS.items():
            if values[key] != candidate.source_sha256[relative]:
                raise ProofValidationError(f"AC-15 proof source hash mismatch: {relative}")

        summary: dict[str, Any] = {
            "schemaVersion": 1,
            "status": "PASS",
            "acceptanceId": ACCEPTANCE_ID,
            "candidate": {
                "commit": candidate.commit,
                "tree": candidate.tree,
                "version": expected_candidate_version,
                "tag": expected_candidate_tag,
            },
            "springContext": {
                "testClass": TEST_CLASS,
                "testMethod": TEST_METHOD,
                "tests": 1,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "flakes": 0,
                "adapters": list(ADAPTER_CLASSES),
                "sharedServiceType": SHARED_SERVICE,
                "sharedServiceImplementation": (
                    "dev.webstarter.project.service.impl.ProjectServiceImpl"
                ),
                "sharedBeanIdentity": True,
            },
            "persistenceBoundary": {
                "projectMapperBeans": 1,
                "projectServiceImplBeans": 1,
                "adapterProjectMapperDependencies": 0,
                "mcpProjectPersistenceBytecodeReferences": 0,
                "forbiddenReferences": list(FORBIDDEN_PROJECT_PERSISTENCE_REFERENCES),
            },
            "sources": dict(candidate.source_sha256),
            "evidence": {
                "proofFile": PROOF_FILE,
                "proofSha256": proof.sha256,
                "reportFile": REPORT_FILE,
                "reportSha256": report.sha256,
            },
        }
        canonical_summary_bytes(summary)
        candidate_after = _validate_candidate(
            repository,
            values["candidateCommit"],
            values["candidateTree"],
            values["candidateTag"],
            values["candidateVersion"],
        )
        if candidate_after != candidate:
            raise ProofValidationError("candidate changed during AC-15 validation")
        if _directory_names(descriptor) != {PROOF_FILE, REPORT_FILE}:
            raise ProofValidationError("proof directory changed during validation")
        _same_snapshot(
            proof,
            _read_private_file(descriptor, PROOF_FILE, MAX_PROOF_BYTES, "AC-15 proof"),
            "AC-15 proof",
        )
        _same_snapshot(
            report,
            _read_private_file(descriptor, REPORT_FILE, MAX_REPORT_BYTES, "Surefire report"),
            "Surefire report",
        )
    finally:
        os.close(descriptor)
    if require_pass and summary["status"] != "PASS":
        raise ProofValidationError("AC-15 proof is not PASS")
    if summary_output is not None:
        _write_summary(summary_output, repository, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-tag", required=True)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--summary-output", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        summary = validate_proof(
            arguments.proof,
            repository_root=arguments.repository_root,
            expected_candidate_commit=arguments.expected_candidate_commit,
            expected_candidate_version=arguments.expected_candidate_version,
            expected_candidate_tag=arguments.expected_candidate_tag,
            require_pass=arguments.require_pass,
            summary_output=arguments.summary_output,
        )
    except (OSError, ProofValidationError) as exception:
        raise SystemExit(f"AC-15 transport parity evidence rejected: {exception}") from exception
    if arguments.summary_output is None:
        print(canonical_summary_bytes(summary).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
