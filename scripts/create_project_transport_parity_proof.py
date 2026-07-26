#!/usr/bin/env python3
"""Create private, candidate-bound raw evidence for V1 AC-15 transport parity."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import xml.etree.ElementTree as ET


TEST_CLASS = "dev.webstarter.admin.acceptance.ProjectTransportParityIT"
TEST_METHOD = "provesRestAndMcpShareProjectServiceWithoutProjectPersistenceDependency"
REPORT_FILE = f"TEST-{TEST_CLASS}.xml"
PROOF_FILE = "project-transport-parity-proof.properties"
FIXED_TEST_SHA256 = "aa6a9732e2fdc925bbb01f9e83634b4c3157f6323b4790133acab20dc5997487"
SOURCE_PATHS = {
    "integrationTestSha256": Path(
        "web-starter-admin/src/test/java/dev/webstarter/admin/acceptance/"
        "ProjectTransportParityIT.java"
    ),
    "projectServiceSha256": Path(
        "web-starter-project/src/main/java/dev/webstarter/project/service/ProjectService.java"
    ),
    "projectServiceImplSha256": Path(
        "web-starter-project/src/main/java/dev/webstarter/project/service/impl/"
        "ProjectServiceImpl.java"
    ),
    "projectControllerSha256": Path(
        "web-starter-project/src/main/java/dev/webstarter/project/web/ProjectController.java"
    ),
    "mcpToolCatalogSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolCatalog.java"
    ),
    "mcpContentCatalogSha256": Path(
        "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpContentCatalog.java"
    ),
    "rootPomSha256": Path("pom.xml"),
    "projectPomSha256": Path("web-starter-project/pom.xml"),
    "mcpPomSha256": Path("web-starter-mcp/pom.xml"),
    "adminPomSha256": Path("web-starter-admin/pom.xml"),
    "producerSha256": Path("scripts/create_project_transport_parity_proof.py"),
    "validatorSha256": Path("scripts/validate_project_transport_parity_proof.py"),
    "summarySchemaSha256": Path(
        "security/v1-ac15-project-transport-parity-summary.schema.json"
    ),
}
OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VERSION = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_GIT_BYTES = 8 * 1024 * 1024
FORBIDDEN_RESULT_ELEMENTS = {
    "failure", "error", "skipped", "flakyfailure", "flakyerror",
    "rerunfailure", "rerunerror",
}


class ProofError(RuntimeError):
    """Raised when an AC-15 result cannot become trustworthy raw evidence."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


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


def _git(repository: Path, *arguments: str, limit: int = MAX_GIT_BYTES) -> bytes:
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
        raise ProofError("Git is required to bind AC-15 evidence") from exception
    if completed.returncode != 0:
        raise ProofError("Git could not verify the AC-15 candidate")
    if len(completed.stdout) > limit or len(completed.stderr) > limit:
        raise ProofError("Git candidate verification output is unexpectedly large")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise ProofError("Git candidate identity is not valid UTF-8") from exception
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise ProofError("Git candidate identity is malformed")
    return value


def _resolve_repository(configured: Path) -> Path:
    absolute = configured.expanduser().absolute()
    if absolute.is_symlink() or not absolute.is_dir():
        raise ProofError("repository root must be a non-symlink directory")
    repository = absolute.resolve(strict=True)
    top_level = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(
        strict=True
    )
    if top_level != repository:
        raise ProofError("repository root is not the exact Git top-level")
    return repository


def _require_clean_candidate(repository: Path) -> None:
    index = _git(repository, "ls-files", "-v", "-z")
    records = [record for record in index.split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise ProofError(
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
        raise ProofError("Git candidate worktree must be clean, including untracked files")


def _candidate_blob(repository: Path, commit: str, relative: Path) -> bytes:
    name = relative.as_posix()
    entry = _git(repository, "ls-tree", "-z", commit, "--", name)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise ProofError(f"candidate does not contain exactly one tracked {name}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or OBJECT_ID.fullmatch(fields[2].decode("ascii", errors="ignore")) is None
        or encoded_path != name.encode("utf-8")
    ):
        raise ProofError(f"candidate {name} is not one regular Git blob")
    return _git(repository, "cat-file", "blob", f"{commit}:{name}", limit=MAX_SOURCE_BYTES)


def _candidate_sources(repository: Path, commit: str) -> tuple[str, dict[str, bytes]]:
    actual_commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    if actual_commit != commit or OBJECT_ID.fullmatch(commit) is None:
        raise ProofError("Git HEAD does not equal the declared candidate commit")
    tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if OBJECT_ID.fullmatch(tree) is None:
        raise ProofError("candidate tree identity is invalid")
    _require_clean_candidate(repository)

    payloads: dict[str, bytes] = {}
    for key, relative in SOURCE_PATHS.items():
        workspace_path = repository.joinpath(*relative.parts)
        if workspace_path.is_symlink() or not workspace_path.is_file():
            raise ProofError(f"candidate source is not a regular file: {relative.as_posix()}")
        resolved = workspace_path.resolve(strict=True)
        if not _inside(resolved, repository):
            raise ProofError(f"candidate source escaped repository: {relative.as_posix()}")
        workspace = resolved.read_bytes()
        if not workspace or len(workspace) > MAX_SOURCE_BYTES:
            raise ProofError(f"candidate source size is invalid: {relative.as_posix()}")
        committed = _candidate_blob(repository, commit, relative)
        if committed != workspace:
            raise ProofError(f"workspace source differs from candidate: {relative.as_posix()}")
        payloads[key] = committed

    if _sha256(payloads["integrationTestSha256"]) != FIXED_TEST_SHA256:
        raise ProofError("AC-15 fixed integration test source has drifted")
    executing = Path(__file__).resolve(strict=True).read_bytes()
    if executing != payloads["producerSha256"]:
        raise ProofError("executing AC-15 producer differs from candidate producer source")
    return tree, payloads


def _require_annotated_tag(repository: Path, tag: str, commit: str) -> None:
    if _git_text(repository, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise ProofError("candidate tag must be an annotated Git tag")
    if _git_text(repository, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != commit:
        raise ProofError("candidate tag does not resolve to candidate commit")


def _private_mode(path: Path, expected: int, label: str) -> None:
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != expected:
        raise ProofError(f"{label} must have mode {expected:04o}")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _validate_report(report: Path, started_at_epoch_ns: int) -> bytes:
    if report.name != REPORT_FILE or report.is_symlink() or not report.is_file():
        raise ProofError("Surefire report must be the expected non-symlink regular file")
    _private_mode(report, 0o600, "Surefire report")
    metadata = report.stat()
    now = time.time_ns()
    if started_at_epoch_ns <= 0 or started_at_epoch_ns > now:
        raise ProofError("integration test start time is invalid")
    if metadata.st_mtime_ns < started_at_epoch_ns or metadata.st_mtime_ns > now + 5_000_000_000:
        raise ProofError("AC-15 Surefire report is stale or future-dated")
    payload = report.read_bytes()
    if not payload or len(payload) > MAX_REPORT_BYTES:
        raise ProofError("AC-15 Surefire report size is invalid")
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", payload, flags=re.IGNORECASE):
        raise ProofError("AC-15 Surefire report must not contain declarations")
    try:
        suite = ET.fromstring(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ET.ParseError) as exception:
        raise ProofError("AC-15 Surefire report is not valid XML") from exception
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
        raise ProofError("AC-15 result is not the exact clean integration test")
    for element in suite.iter():
        local = _local_name(element.tag).lower()
        if local in FORBIDDEN_RESULT_ELEMENTS or "retry" in local or "rerun" in local \
                or ("flak" in local and local != "testsuite"):
            raise ProofError("AC-15 report contains failure, skip, retry, or flake evidence")
        for attribute in element.attrib:
            name = _local_name(attribute).lower()
            if "retry" in name or "rerun" in name or ("flak" in name and name != "flakes"):
                raise ProofError("AC-15 report contains failure, skip, retry, or flake evidence")
    return payload


def create_proof(
    repository_root: Path,
    report_path: Path,
    output_path: Path,
    candidate_commit: str,
    candidate_version: str,
    candidate_tag: str,
    started_at_epoch_ns: int,
) -> None:
    repository = _resolve_repository(repository_root)
    if VERSION.fullmatch(candidate_version) is None or "SNAPSHOT" in candidate_version.upper():
        raise ProofError("candidate version must be an explicit non-SNAPSHOT version")
    if candidate_tag != f"v{candidate_version}":
        raise ProofError("candidate tag must equal v plus candidate version")

    requested_report = report_path.expanduser().absolute()
    requested_output = output_path.expanduser().absolute()
    if requested_output.name != PROOF_FILE or requested_output.is_symlink():
        raise ProofError(f"proof output must use fixed name {PROOF_FILE}")
    parent = requested_output.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProofError("proof directory must be a non-symlink directory")
    directory = parent.resolve(strict=True)
    if _inside(directory, repository) or _inside(repository, directory):
        raise ProofError("proof directory must be outside and must not contain repository")
    _private_mode(directory, 0o700, "proof directory")
    if requested_report.parent.resolve(strict=True) != directory:
        raise ProofError("proof and Surefire report must share one private directory")
    if set(os.listdir(directory)) != {REPORT_FILE}:
        raise ProofError("proof directory must initially contain only Surefire report")
    if requested_output.exists() or requested_output.is_symlink():
        raise ProofError("proof output already exists and will not be overwritten")

    report_payload = _validate_report(requested_report, started_at_epoch_ns)
    tree, source_payloads = _candidate_sources(repository, candidate_commit)
    _require_annotated_tag(repository, candidate_tag, candidate_commit)

    values = [
        ("schemaVersion", "1"),
        ("testClass", TEST_CLASS),
        ("testMethod", TEST_METHOD),
        ("reportFile", REPORT_FILE),
        ("reportSha256", _sha256(report_payload)),
        ("candidateCommit", candidate_commit),
        ("candidateTree", tree),
        ("candidateVersion", candidate_version),
        ("candidateTag", candidate_tag),
        ("startedAtEpochNs", str(started_at_epoch_ns)),
    ]
    values.extend((key, _sha256(source_payloads[key])) for key in SOURCE_PATHS)
    payload = "".join(f"{key}={value}\n" for key, value in values).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(directory / PROOF_FILE, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ProofError("proof output write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if set(os.listdir(directory)) != {REPORT_FILE, PROOF_FILE}:
        raise ProofError("proof directory changed during creation")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--started-at-epoch-ns", required=True, type=int)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        create_proof(
            arguments.repository_root,
            arguments.report,
            arguments.output,
            arguments.candidate_commit,
            arguments.candidate_version,
            arguments.candidate_tag,
            arguments.started_at_epoch_ns,
        )
    except (OSError, ProofError) as exception:
        raise SystemExit(f"cannot create AC-15 transport parity proof: {exception}") from exception
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
