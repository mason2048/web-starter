#!/usr/bin/env python3
"""Create a private, source-bound proof for the one MCP CRUD runtime execution."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import xml.etree.ElementTree as ET


TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"
TEST_METHOD = "provesEachWriteCommitsOnceAcrossConcurrencyRetryConflictAndAudit"
TEST_SOURCE = Path(
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkCrudRuntimeIT.java"
)
ROOT_POM = Path("pom.xml")
MODULE_POM = Path("web-starter-mcp/pom.xml")
REPORT_FILE = f"TEST-{TEST_CLASS}.xml"
TRANSACTION_RECEIPT_FILE = "mcp-crud-transaction-receipt.properties"
PROOF_FILE = "mcp-crud-runtime-proof.properties"
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
TRACE_PREFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class ProofError(RuntimeError):
    """Raised when the runtime result cannot form a trustworthy proof."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git(repository: Path, *arguments: str, max_bytes: int = 4 * 1024 * 1024) -> bytes:
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
        raise ProofError("Git is required to bind the MCP CRUD proof to the candidate") from exception
    if completed.returncode != 0:
        raise ProofError("Git could not verify the MCP CRUD candidate")
    if len(completed.stdout) > max_bytes:
        raise ProofError("Git candidate verification output is unexpectedly large")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        return _git(repository, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exception:
        raise ProofError("Git candidate identity is not valid UTF-8") from exception


def _committed_file(repository: Path, commit: str, relative: Path, workspace_file: Path) -> bytes:
    relative_text = relative.as_posix()
    entry = _git(repository, "ls-tree", "-z", commit, "--", relative_text)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise ProofError(f"candidate does not contain exactly one tracked {relative_text}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or encoded_path != relative_text.encode("utf-8")
        or not re.fullmatch(rb"[0-9a-f]{40}(?:[0-9a-f]{24})?", fields[2])
    ):
        raise ProofError(f"candidate {relative_text} is not one regular Git blob")
    committed = _git(repository, "cat-file", "blob", f"{commit}:{relative_text}")
    if committed != workspace_file.read_bytes():
        raise ProofError(f"workspace {relative_text} differs from the candidate commit blob")
    return committed


def _candidate_sources(
    repository: Path,
    candidate_commit: str,
    source: Path,
    root_pom: Path,
    module_pom: Path,
) -> tuple[str, dict[Path, bytes]]:
    top_level = _git_text(repository, "rev-parse", "--show-toplevel")
    try:
        resolved_top_level = Path(top_level).resolve(strict=True)
    except OSError as exception:
        raise ProofError("Git top-level cannot be resolved") from exception
    if resolved_top_level != repository:
        raise ProofError("repository root is not the exact Git top-level")
    actual_commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    if actual_commit != candidate_commit:
        raise ProofError("Git HEAD does not equal the declared candidate commit")
    candidate_tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if not COMMIT.fullmatch(candidate_tree):
        raise ProofError("Git candidate tree identity is invalid")
    index = _git(repository, "ls-files", "-v", "-z")
    index_records = [record for record in index.split(b"\0") if record]
    if not index_records or any(len(record) < 3 or not record.startswith(b"H ") for record in index_records):
        raise ProofError("Git index contains skip-worktree, assume-unchanged, or non-cached entries")
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        raise ProofError("Git candidate worktree must be clean, including untracked files")
    committed = {
        TEST_SOURCE: _committed_file(repository, candidate_commit, TEST_SOURCE, source),
        ROOT_POM: _committed_file(repository, candidate_commit, ROOT_POM, root_pom),
        MODULE_POM: _committed_file(repository, candidate_commit, MODULE_POM, module_pom),
    }
    return candidate_tree, committed


def _regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ProofError(f"{label} must be an existing non-symlink regular file")
    return path.resolve(strict=True)


def _private(path: Path, label: str) -> None:
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ProofError(f"{label} must be private (chmod 600)")


def _private_directory(path: Path) -> None:
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ProofError("proof directory must be private (chmod 700)")


def _safe_repository_file(repository: Path, relative: Path, label: str) -> Path:
    target = _regular(repository / relative, label)
    try:
        target.relative_to(repository)
    except ValueError as exception:
        raise ProofError(f"{label} escaped the repository") from exception
    return target


def _parse_report(report: Path, started_at_epoch_ns: int) -> None:
    if report.name != REPORT_FILE:
        raise ProofError("Surefire report has an unexpected filename")
    if report.stat().st_mtime_ns < started_at_epoch_ns:
        raise ProofError("MCP CRUD Surefire report is stale")
    payload = report.read_bytes()
    if len(payload) > 2 * 1024 * 1024:
        raise ProofError("MCP CRUD Surefire report is unexpectedly large")
    if b"<!DOCTYPE" in payload.upper():
        raise ProofError("MCP CRUD Surefire report must not contain a DOCTYPE")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exception:
        raise ProofError("MCP CRUD Surefire report is not valid XML") from exception
    if root.tag != "testsuite" or root.attrib.get("name") != TEST_CLASS:
        raise ProofError("MCP CRUD Surefire report identifies a different test suite")
    try:
        counts = {
            name: int(root.attrib.get(name, "-1"))
            for name in ("tests", "failures", "errors", "skipped")
        }
        flakes = int(root.attrib.get("flakes", "0"))
    except ValueError as exception:
        raise ProofError("MCP CRUD Surefire report has invalid counters") from exception
    expected = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}
    if counts != expected or flakes != 0:
        raise ProofError(f"MCP CRUD result is not exactly one clean passing test: {counts}")
    cases = root.findall("testcase")
    if len(cases) != 1:
        raise ProofError("MCP CRUD Surefire report must contain exactly one testcase")
    case = cases[0]
    if case.attrib.get("classname") != TEST_CLASS or case.attrib.get("name") != TEST_METHOD:
        raise ProofError("MCP CRUD Surefire report identifies a different test method")
    forbidden = {"failure", "error", "skipped", "flakyFailure", "flakyError", "rerunFailure", "rerunError"}
    if any(element.tag in forbidden for element in root.iter()):
        raise ProofError("MCP CRUD Surefire report contains failure, skip, retry, or flake evidence")


def create_proof(
    repository_root: Path,
    report_path: Path,
    transaction_receipt_path: Path,
    output_path: Path,
    candidate_commit: str,
    candidate_version: str,
    candidate_tag: str,
    compose_project: str,
    trace_prefix: str,
    started_at_epoch_ns: int,
) -> None:
    repository = repository_root.resolve(strict=True)
    if not repository.is_dir() or repository.is_symlink():
        raise ProofError("repository root must be a non-symlink directory")
    report = _regular(report_path, "Surefire report")
    transaction_receipt = _regular(
        transaction_receipt_path, "AC-16 transaction receipt"
    )
    requested_output = output_path.absolute()
    if requested_output.name != PROOF_FILE or requested_output.parent.is_symlink():
        raise ProofError("proof output must use the fixed filename in a non-symlink directory")
    output = requested_output.parent.resolve(strict=True) / requested_output.name
    if output.exists() or output.is_symlink():
        raise ProofError("proof output must not already exist")
    parent = output.parent.resolve(strict=True)
    if not parent.is_dir() or parent.is_symlink():
        raise ProofError("proof directory must be a non-symlink directory")
    try:
        parent.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ProofError("proof directory must stay outside the Git workspace")
    if (
        report.parent != parent
        or report.name != REPORT_FILE
        or transaction_receipt.parent != parent
        or transaction_receipt.name != TRANSACTION_RECEIPT_FILE
    ):
        raise ProofError(
            "proof, exact Surefire report, and AC-16 receipt must share one private directory"
        )
    _private_directory(parent)
    _private(report, "Surefire report")
    _private(transaction_receipt, "AC-16 transaction receipt")
    if not COMMIT.fullmatch(candidate_commit):
        raise ProofError("candidate commit must be a full lowercase Git object ID")
    if not VERSION.fullmatch(candidate_version) or candidate_tag != f"v{candidate_version}":
        raise ProofError("candidate version and tag are inconsistent")
    if not PROJECT.fullmatch(compose_project):
        raise ProofError("Compose project identity is invalid")
    if not TRACE_PREFIX.fullmatch(trace_prefix):
        raise ProofError("MCP CRUD trace prefix is invalid")
    if started_at_epoch_ns <= 0:
        raise ProofError("runtime test start time is invalid")

    source = _safe_repository_file(repository, TEST_SOURCE, "MCP CRUD test source")
    root_pom = _safe_repository_file(repository, ROOT_POM, "root pom.xml")
    module_pom = _safe_repository_file(repository, MODULE_POM, "MCP module pom.xml")
    candidate_tree, committed = _candidate_sources(
        repository, candidate_commit, source, root_pom, module_pom
    )
    _parse_report(report, started_at_epoch_ns)
    if (
        transaction_receipt.stat().st_mtime_ns < started_at_epoch_ns
        or transaction_receipt.stat().st_size <= 0
        or transaction_receipt.stat().st_size > 16 * 1024
    ):
        raise ProofError("AC-16 transaction receipt is stale or unexpectedly sized")

    values = (
        ("schemaVersion", "2"),
        ("testClass", TEST_CLASS),
        ("testMethod", TEST_METHOD),
        ("sourcePath", TEST_SOURCE.as_posix()),
        ("sourceSha256", _sha256_bytes(committed[TEST_SOURCE])),
        ("rootPomPath", ROOT_POM.as_posix()),
        ("rootPomSha256", _sha256_bytes(committed[ROOT_POM])),
        ("modulePomPath", MODULE_POM.as_posix()),
        ("modulePomSha256", _sha256_bytes(committed[MODULE_POM])),
        ("reportFile", REPORT_FILE),
        ("reportSha256", _sha256(report)),
        ("transactionReceiptFile", TRANSACTION_RECEIPT_FILE),
        ("transactionReceiptSha256", _sha256(transaction_receipt)),
        ("candidateCommit", candidate_commit),
        ("candidateTree", candidate_tree),
        ("candidateVersion", candidate_version),
        ("candidateTag", candidate_tag),
        ("composeProject", compose_project),
        ("tracePrefix", trace_prefix),
        ("startedAtEpochNs", str(started_at_epoch_ns)),
    )
    payload = "".join(f"{key}={value}\n" for key, value in values).encode("utf-8")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("proof write made no progress")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--transaction-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--trace-prefix", required=True)
    parser.add_argument("--started-at-epoch-ns", type=int, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        create_proof(
            args.repository_root,
            args.report,
            args.transaction_receipt,
            args.output,
            args.candidate_commit,
            args.candidate_version,
            args.candidate_tag,
            args.compose_project,
            args.trace_prefix,
            args.started_at_epoch_ns,
        )
    except (OSError, ProofError) as exception:
        raise SystemExit(f"cannot create MCP CRUD runtime proof: {exception}") from exception
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
