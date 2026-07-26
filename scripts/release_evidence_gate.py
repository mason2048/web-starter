#!/usr/bin/env python3
"""Build and independently verify the V2 release evidence ledger.

The gate is intentionally fail closed.  It never invents an acceptance result:
V1 results and V2 AC-01..AC-44 must come from an explicit evidence document.
That tracked input declares only the release tag and version; the Git commit is
derived from the annotated tag and bound by reading the file back from that
commit.  This deliberately avoids an impossible self-referential commit hash.
V2-AC-45 is the only gate-owned result and is derived from this validation.
"""

from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
from typing import Any
import xml.etree.ElementTree as ElementTree

import production_compose_policy as compose_policy
import release_security_gate as security_gate
import validate_jwks_rotation_evidence as jwks_rotation_evidence
import validate_generator_acceptance_evidence as generator_acceptance_evidence
import validate_mcp_crud_runtime_proof as mcp_crud_proof
import validate_mcp_governance_runtime_proof as mcp_governance_proof
import validate_mcp_tool_contract_runtime_proof as mcp_tool_contract_proof
import validate_migration_failure_evidence as migration_failure_evidence
import validate_observability_evidence as observability_evidence
import validate_production_fail_fast_evidence as production_fail_fast_evidence
import validate_project_transport_parity_proof as project_transport_parity_proof
import validate_redis_loss_evidence as redis_loss_evidence
import validate_release_runtime_test_reports_proof as release_runtime_test_reports
import validate_tooling_lifecycle_evidence as tooling_lifecycle_evidence
import validate_v1_operations_documentation_proof as v1_operations_documentation
import validate_v1_source_provenance_proof as v1_source_provenance
import validate_v1_upgrade_evidence as v1_upgrade_evidence
import validate_credential_lifecycle_evidence as credential_lifecycle_evidence


ALLOWED_STATUSES = {"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"}
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RELEASE_TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)$")
BASELINE_ROW = re.compile(r"^\|\s*((?:V2-)?AC-\d{2})\s*\|\s*(P[01])\s*\|")
MIGRATION_FILE = re.compile(r"^V([0-9]+(?:\.[0-9]+)*)__([A-Za-z0-9][A-Za-z0-9_]*)\.sql$")
EVIDENCE_REFERENCE = re.compile(
    r"^(repo|artifact)://([A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*"
    r")#sha256=([0-9a-f]{64})$"
)
SELF_OWNED_ACCEPTANCE_ID = "V2-AC-45"
INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS: dict[str, tuple[str, ...]] = {
    "AC-01": ("releaseRuntimeAcceptance",),
    "AC-02": ("toolingLifecycleSummary", "unifiedVerify"),
    "AC-03": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-04": (
        "releaseRuntimeTestReports", "redisLossRehearsal",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-05": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-06": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-07": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-08": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-09": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-10": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-11": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-12": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-13": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-14": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-15": ("v1ProjectTransportParitySummary",),
    "AC-16": ("mcpCrudRuntimeProofSummary",),
    "AC-17": (
        "credentialLifecycleSummary", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-18": (
        "credentialLifecycleSummary", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-19": (
        "credentialLifecycleSummary", "releaseRuntimeTestReports",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-20": (
        "credentialLifecycleSummary", "releaseRuntimeTestReports",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-21": (
        "credentialLifecycleSummary", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-22": (
        "credentialLifecycleSummary", "releaseRuntimeTestReports",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-23": (
        "credentialLifecycleSummary", "releaseRuntimeTestReports",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-24": (
        "credentialLifecycleSummary", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-25": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-26": (
        "releaseRuntimeTestReports", "mcpToolContractSummary",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-27": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-28": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-29": (
        "releaseRuntimeTestReports", "productionFailFastRehearsal",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-30": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-31": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-32": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-33": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-34": (
        "credentialLifecycleSummary", "releaseRuntimeTestReports",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-35": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-36": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-37": (
        "toolingLifecycleSummary", "productionCompose", "productionComposePolicy",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "AC-38": (
        "v1OperationsDocumentationSummary", "observabilitySummary",
        "releaseRuntimeAcceptance",
    ),
    "AC-39": ("unifiedVerify", "productionFailFastRehearsal"),
    "AC-41": ("unifiedVerify",),
    "AC-42": ("generatorAcceptanceSummary",),
    "V2-AC-01": ("v1SourceProvenanceSummary",),
    "V2-AC-02": ("releaseImages", "runtimeVersionIdentity"),
    "V2-AC-03": ("releaseRuntimeAcceptance",),
    "V2-AC-04": ("v1UpgradeRehearsal",),
    "V2-AC-05": ("v1UpgradeRehearsal",),
    "V2-AC-06": ("v1UpgradeRehearsal",),
    "V2-AC-07": ("migrationFailureRehearsal",),
    "V2-AC-08": ("generatorAcceptanceSummary",),
    "V2-AC-09": ("generatorAcceptanceSummary",),
    "V2-AC-10": ("generatorAcceptanceSummary",),
    "V2-AC-11": ("generatorAcceptanceSummary",),
    "V2-AC-12": ("generatorAcceptanceSummary",),
    "V2-AC-13": ("generatorAcceptanceSummary",),
    "V2-AC-14": ("generatorAcceptanceSummary",),
    "V2-AC-15": ("generatorAcceptanceSummary",),
    "V2-AC-16": ("toolingLifecycleSummary",),
    "V2-AC-17": ("toolingLifecycleSummary",),
    "V2-AC-18": ("unifiedVerify",),
    "V2-AC-19": (
        "releaseRuntimeTestReports", "unifiedVerify",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-20": (
        "releaseRuntimeTestReports", "generatorAcceptanceSummary", "unifiedVerify",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-21": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-22": (
        "releaseRuntimeTestReports", "unifiedVerify",
        "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-23": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-24": ("credentialLifecycleSummary",),
    "V2-AC-25": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-26": ("jwksRotationSummary",),
    "V2-AC-27": ("credentialLifecycleSummary",),
    "V2-AC-28": ("credentialLifecycleSummary",),
    "V2-AC-29": ("productionFailFastRehearsal",),
    "V2-AC-30": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-31": ("mcpCrudRuntimeProofSummary",),
    "V2-AC-32": ("mcpCrudRuntimeProofSummary",),
    "V2-AC-33": ("mcpToolContractSummary",),
    "V2-AC-34": ("mcpGovernanceRuntimeSummary",),
    "V2-AC-35": ("mcpGovernanceRuntimeSummary",),
    "V2-AC-36": ("credentialLifecycleSummary",),
    "V2-AC-37": (
        "observabilitySummary", "runtimeVersionIdentity", "releaseRuntimeAcceptance",
    ),
    "V2-AC-38": ("releaseRuntimeAcceptance",),
    "V2-AC-39": (
        "releaseRuntimeTestReports", "runtimeVersionIdentity",
        "releaseRuntimeAcceptance", "v1UpgradeRehearsal",
    ),
    "V2-AC-40": (
        "v1UpgradeRehearsal", "ac40DependencySeedProvenance",
    ),
    "V2-AC-41": ("redisLossRehearsal",),
    "V2-AC-42": ("releaseRuntimeAcceptance",),
    "V2-AC-43": ("releaseImages", "securityGate"),
    "V2-AC-44": ("productionCompose", "productionComposePolicy"),
}
MCP_CRUD_TRACE_PREFIX = "release-sdk"
MCP_TOOL_CONTRACT_TRACE_PREFIX = "release-tool-contract"
MCP_GOVERNANCE_TRACE_PREFIX = "release-governance"
MCP_GOVERNANCE_SUMMARY_FILE = "mcp-governance-runtime-summary.json"
JWKS_ROTATION_TRACE_PREFIX = "release-ac26"
JWKS_ROTATION_PUBLIC_ORIGIN = "https://mcp.ac26.webstarter.test:28443"
JWKS_ROTATION_PRIVATE_ORIGIN = "http://127.0.0.1:28088"
COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
MCP_GOVERNANCE_COMPOSE_PROJECT = re.compile(
    r"^web-starter-governance-[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$"
)
RUNTIME_CHECKS = {
    "authenticatedOperationalMetrics",
    "emptyVolumesAndMigrations",
    "runtimeVersionIdentity",
    "privateBrowserProjectCrud",
    "privateBrowserAccountSecurity",
    "privateBrowserCredentialLifecycle",
    "oauthPkce",
    "oauthClientCredentials",
    "oauthMultiKeyJwksActiveSigning",
    "publicOperationsEndpointsHidden",
    "patPrivatePublicBoundary",
    "officialMcpSdkPublicOAuth",
    "officialMcpSdkPrivatePat",
    "officialMcpSdkCrudAudit",
    "auditTraceSearchAndCorrelation",
    "mysqlReadinessAndLiveness",
    "redisReadinessAndLiveness",
    "unifiedSevenLayerVerify",
}
VERIFY_LAYERS = {
    "backend",
    "frontend",
    "policy",
    "container",
    "browser",
    "oauth",
    "mcp",
}
SUITES = {
    "v1": Path("docs/acceptance/v1-acceptance-baseline.md"),
    "v2": Path("docs/acceptance/v2-acceptance-baseline.md"),
}
EXPECTED_ACCEPTANCE_IDS = {
    "v1": {f"AC-{number:02d}" for number in range(1, 43)},
    "v2": {f"V2-AC-{number:02d}" for number in range(1, 46)},
}
V1_BASELINE_TAG = "v1.0.0"
V1_BASELINE_COMMIT = "5ebdb238650d182c17e1493adf47aaa3324f19cb"
V1_BASELINE_MIGRATIONS = {
    "web-starter-admin/src/main/resources/db/migration/V1__create_core_schema.sql",
    "web-starter-admin/src/main/resources/db/migration/V2__seed_reference_data.sql",
    "web-starter-admin/src/main/resources/db/migration/V3__add_oauth_refresh_token_families.sql",
}
MAX_GIT_STDOUT_BYTES = 32 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 2 * 1024 * 1024
AC40_DEPENDENCY_SEED_PROVENANCE_PATH = (
    "acceptance/v2-ac40-dependency-seed-provenance.json"
)
AC40_DEPENDENCY_SEED_PROVENANCE_KEYS = {
    "schemaVersion",
    "kind",
    "environment",
    "artifactId",
    "workflowRunId",
    "headRepositoryId",
    "producerHeadSha",
    "archiveSha256",
    "aggregateSha256",
    "manifestSha256",
    "platform",
    "architecture",
}


class EvidenceError(ValueError):
    """Raised when release evidence is structurally missing or untrustworthy."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_file(path: Path, root: Path, label: str) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise EvidenceError(f"{label} must not be a symbolic link")
    resolved = candidate.resolve()
    if not _is_inside(resolved, root):
        raise EvidenceError(f"{label} escapes its allowed root")
    if not resolved.is_file():
        raise EvidenceError(f"{label} is missing or is not a regular file")
    return resolved


def _read_private_fixed_file(path: Path, maximum: int, label: str) -> bytes:
    """Read one owned mode-0600 file without following or racing a replacement."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        before = os.stat(path, follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError as exception:
        if descriptor is not None:
            os.close(descriptor)
        raise EvidenceError(f"{label} cannot be opened as a stable private file") from exception
    try:
        signature = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or opened.st_size > maximum
            or (os.name == "posix" and stat.S_IMODE(opened.st_mode) != 0o600)
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
            or signature(before) != signature(opened)
        ):
            raise EvidenceError(f"{label} is not one owned private fixed file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_descriptor = os.fstat(descriptor)
        after_path = os.stat(path, follow_symlinks=False)
        if (
            len(payload) != opened.st_size
            or len(payload) > maximum
            or signature(after_descriptor) != signature(opened)
            or signature(after_path) != signature(opened)
        ):
            raise EvidenceError(f"{label} changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise EvidenceError(f"JSON object repeats field: {key}")
        document[key] = value
    return document


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceError(f"{label} is missing or invalid JSON") from exception


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], required: set[str], label: str) -> None:
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        unknown = sorted(keys - required)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unknown:
            details.append("unknown=" + ",".join(unknown))
        raise EvidenceError(f"{label} fields are not exact ({'; '.join(details)})")


def _validate_release_values(tag: str, version: str, commit: str) -> None:
    match = RELEASE_TAG.fullmatch(tag)
    if match is None:
        raise EvidenceError("release tag must be v-prefixed semantic version")
    if version != match.group(1):
        raise EvidenceError("release version must exactly match the Git tag without its v prefix")
    if COMMIT.fullmatch(commit) is None:
        raise EvidenceError("Git commit must be a lowercase 40- or 64-character object id")


def _git_environment() -> dict[str, str]:
    """Return an allowlisted environment for every release-gate Git call."""
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


def _run_git_bounded(
    repository_root: Path, *arguments: str
) -> subprocess.CompletedProcess[bytes]:
    command = [
        "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-C", str(repository_root), *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exception:
        raise EvidenceError("unable to start hardened Git validation") from exception
    assert process.stdout is not None and process.stderr is not None
    output = bytearray()
    errors = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, (output, MAX_GIT_STDOUT_BYTES, "stdout"))
    selector.register(process.stderr, selectors.EVENT_READ, (errors, MAX_GIT_STDERR_BYTES, "stderr"))
    try:
        while selector.get_map():
            for key, _ in selector.select():
                destination, limit, label = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(destination) + len(chunk) > limit:
                    raise EvidenceError(f"Git {label} exceeded the release-gate byte limit")
                destination.extend(chunk)
        return_code = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(command, return_code, bytes(output), bytes(errors))


def _git(repository_root: Path, *arguments: str) -> str:
    completed = _run_git_bounded(repository_root, *arguments)
    if completed.returncode != 0:
        raise EvidenceError("unable to resolve the release Git tag and commit")
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise EvidenceError("release Git identity is not valid UTF-8") from exception


def _git_bytes(repository_root: Path, *arguments: str) -> bytes:
    completed = _run_git_bounded(repository_root, *arguments)
    if completed.returncode != 0:
        raise EvidenceError("unable to read a release-bound file from Git")
    return completed.stdout


def _verify_git_binding(repository_root: Path, tag: str, commit: str) -> str:
    head = _git(repository_root, "rev-parse", "HEAD")
    if head != commit:
        raise EvidenceError("declared Git commit does not match checked-out HEAD")
    tag_ref = f"refs/tags/{tag}"
    if _git(repository_root, "cat-file", "-t", tag_ref) != "tag":
        raise EvidenceError("release tag must exist as an annotated Git tag")
    tag_commit = _git(repository_root, "rev-parse", f"{tag_ref}^{{commit}}")
    if tag_commit != commit:
        raise EvidenceError("release Git tag does not resolve to the declared commit")
    index_entries = _git_bytes(repository_root, "ls-files", "-v", "-z").split(b"\0")
    if any(entry and (len(entry) < 3 or entry[:2] != b"H ") for entry in index_entries):
        raise EvidenceError(
            "release checkout uses assume-unchanged, skip-worktree or non-cached index entries"
        )
    tracked_status = _git_bytes(
        repository_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=no",
    )
    if tracked_status:
        raise EvidenceError(
            "release checkout has staged, unstaged or deleted tracked-file drift"
        )
    tag_object = _git(repository_root, "rev-parse", tag_ref)
    if COMMIT.fullmatch(tag_object) is None:
        raise EvidenceError("release tag object id is invalid")
    return tag_object


def _verify_strict_candidate_root(
    candidate_root: Path,
    tag: str,
    commit: str,
) -> Path:
    requested = candidate_root.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise EvidenceError("candidate validation root must be a real non-symlink directory")
    resolved = requested.resolve()
    top_level = Path(_git(resolved, "rev-parse", "--show-toplevel")).resolve()
    if top_level != resolved:
        raise EvidenceError("candidate validation root must be the exact Git worktree top-level")
    _verify_git_binding(resolved, tag, commit)
    status = _git_bytes(
        resolved,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        raise EvidenceError("candidate validation root must be clean, including untracked files")
    return resolved


def _verify_repository_file_binding(repository_root: Path, commit: str, path: Path) -> None:
    path = _safe_file(path, repository_root, "release-bound repository evidence")
    relative = _relative(path, repository_root)
    committed = _git_bytes(repository_root, "show", f"{commit}:{relative}")
    if hashlib.sha256(committed).hexdigest() != _sha256(path):
        raise EvidenceError(f"repository evidence differs from tagged commit: {relative}")


def _parse_baseline(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exception:
        raise EvidenceError(f"acceptance baseline cannot be read: {path.name}") from exception
    for line in lines:
        match = BASELINE_ROW.match(line)
        if match is None:
            continue
        acceptance_id, level = match.groups()
        if acceptance_id in rows:
            raise EvidenceError(f"acceptance baseline duplicates {acceptance_id}")
        rows[acceptance_id] = level
    if not rows:
        raise EvidenceError(f"acceptance baseline contains no P0/P1 rows: {path.name}")
    return rows


def _load_baselines(repository_root: Path) -> dict[str, dict[str, Any]]:
    baselines: dict[str, dict[str, Any]] = {}
    for suite, relative_path in SUITES.items():
        path = _safe_file(relative_path, repository_root, f"{suite} acceptance baseline")
        rows = _parse_baseline(path)
        expected = EXPECTED_ACCEPTANCE_IDS[suite]
        if set(rows) != expected:
            missing = sorted(expected - set(rows))
            unknown = sorted(set(rows) - expected)
            details = []
            if missing:
                details.append("missing=" + ",".join(missing))
            if unknown:
                details.append("unknown=" + ",".join(unknown))
            raise EvidenceError(
                f"{suite} acceptance baseline is not the frozen complete ID set ({'; '.join(details)})"
            )
        baselines[suite] = {
            "path": relative_path.as_posix(),
            "sha256": _sha256(path),
            "rows": rows,
        }
    v2_rows = baselines["v2"]["rows"]
    if v2_rows.get(SELF_OWNED_ACCEPTANCE_ID) != "P0":
        raise EvidenceError("V2 baseline must define V2-AC-45 as P0")
    return baselines


def _parse_observed_at(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise EvidenceError(f"{label} observedAt must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exception:
        raise EvidenceError(f"{label} observedAt must be an RFC 3339 timestamp") from exception
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} observedAt must include a timezone")
    return value


def _validate_acceptance_source(
    source: Any,
    baselines: dict[str, dict[str, Any]],
    tag: str,
    version: str,
    repository_root: Path,
    artifacts_root: Path,
    commit: str,
    verify_git: bool,
) -> tuple[dict[str, Any], list[str]]:
    document = _require_object(source, "acceptance evidence")
    _require_exact_keys(document, {"schemaVersion", "release", "suites"}, "acceptance evidence")
    if document["schemaVersion"] != 1:
        raise EvidenceError("acceptance evidence must use schemaVersion 1")

    release = _require_object(document["release"], "acceptance evidence release")
    _require_exact_keys(release, {"tag", "version"}, "acceptance evidence release")
    if release != {"tag": tag, "version": version}:
        raise EvidenceError("acceptance evidence release identity does not match this release")

    suites = _require_object(document["suites"], "acceptance evidence suites")
    _require_exact_keys(suites, set(SUITES), "acceptance evidence suites")
    output: dict[str, Any] = {}
    blocking: list[str] = []

    for suite in ("v1", "v2"):
        raw_suite = _require_object(suites[suite], f"{suite} acceptance suite")
        _require_exact_keys(raw_suite, {"results"}, f"{suite} acceptance suite")
        raw_results = raw_suite["results"]
        if not isinstance(raw_results, list):
            raise EvidenceError(f"{suite} acceptance results must be an array")

        baseline_rows: dict[str, str] = baselines[suite]["rows"]
        expected = set(baseline_rows)
        if suite == "v2":
            expected.remove(SELF_OWNED_ACCEPTANCE_ID)
        seen: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(raw_results, start=1):
            label = f"{suite} acceptance result #{index}"
            result = _require_object(raw, label)
            _require_exact_keys(result, {"id", "status", "observedAt", "evidence"}, label)
            acceptance_id = result["id"]
            status = result["status"]
            if not isinstance(acceptance_id, str) or acceptance_id not in expected:
                raise EvidenceError(f"{label} has an unknown or gate-owned acceptance id")
            if acceptance_id in seen:
                raise EvidenceError(f"{suite} acceptance results duplicate {acceptance_id}")
            if status not in ALLOWED_STATUSES:
                raise EvidenceError(f"{acceptance_id} uses an unsupported acceptance status")
            observed_at = _parse_observed_at(result["observedAt"], acceptance_id)
            evidence = result["evidence"]
            if not isinstance(evidence, list) or not evidence:
                raise EvidenceError(f"{acceptance_id} must contain at least one evidence reference")
            clean_evidence: list[str] = []
            seen_evidence: set[str] = set()
            for reference in evidence:
                match = EVIDENCE_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
                if (
                    match is None
                    or len(reference) > 1024
                ):
                    raise EvidenceError(
                        f"{acceptance_id} evidence must be a supported content-addressed URI"
                    )
                if reference in seen_evidence:
                    raise EvidenceError(f"{acceptance_id} repeats an evidence reference")
                seen_evidence.add(reference)
                scheme, relative, declared_sha256 = match.groups()
                if scheme == "repo":
                    if verify_git:
                        payload = _git_bytes(repository_root, "show", f"{commit}:{relative}")
                        actual_sha256 = hashlib.sha256(payload).hexdigest()
                    else:
                        actual_sha256 = _sha256(
                            _safe_file(Path(relative), repository_root, f"{acceptance_id} repo evidence")
                        )
                    if actual_sha256 != declared_sha256:
                        raise EvidenceError(f"{acceptance_id} repo evidence checksum does not match")
                elif scheme == "artifact":
                    artifact = _safe_file(
                        Path(relative), artifacts_root, f"{acceptance_id} artifact evidence"
                    )
                    if _sha256(artifact) != declared_sha256:
                        raise EvidenceError(f"{acceptance_id} artifact evidence checksum does not match")
                clean_evidence.append(reference)
            if (
                status == "PASS"
                and acceptance_id not in INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS
            ):
                raise EvidenceError(
                    f"{acceptance_id} PASS is not registered for independent semantic verification"
                )
            normalized = {
                "id": acceptance_id,
                "level": baseline_rows[acceptance_id],
                "status": status,
                "observedAt": observed_at,
                "evidence": clean_evidence,
                "evidenceTrust": "CONTENT_HASH_VERIFIED",
            }
            seen[acceptance_id] = normalized
            if status != "PASS":
                blocking.append(f"{acceptance_id} is {status}, not PASS")

        missing = sorted(expected - set(seen))
        if missing:
            raise EvidenceError(
                f"{suite} acceptance evidence is incomplete; missing P0/P1 results: {','.join(missing)}"
            )
        output[suite] = {
            "baseline": {
                "path": baselines[suite]["path"],
                "sha256": baselines[suite]["sha256"],
            },
            "results": [seen[acceptance_id] for acceptance_id in sorted(seen)],
        }
    return output, blocking


def _bind_independently_verified_acceptance(
    acceptance: dict[str, Any],
    verified_inputs: dict[str, Any],
) -> None:
    """Bind PASS results only to artifacts whose semantics this gate recomputed."""
    for suite in ("v1", "v2"):
        for result in acceptance[suite]["results"]:
            if result["status"] != "PASS":
                continue
            acceptance_id = result["id"]
            binding_names = INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS.get(acceptance_id)
            if binding_names is None:
                raise EvidenceError(
                    f"{acceptance_id} PASS is not registered for independent semantic verification"
                )
            for binding_name in binding_names:
                binding = _require_object(
                    verified_inputs.get(binding_name),
                    f"{acceptance_id} independently verified artifact {binding_name}",
                )
                path = binding.get("path")
                sha256 = binding.get("sha256")
                if (
                    not isinstance(path, str)
                    or EVIDENCE_REFERENCE.fullmatch(
                        f"artifact://{path}#sha256={sha256}"
                    )
                    is None
                ):
                    raise EvidenceError(
                        f"{acceptance_id} independently verified artifact binding is invalid"
                    )
                reference = f"artifact://{path}#sha256={sha256}"
                if reference not in result["evidence"]:
                    result["evidence"].append(reference)
            result["evidenceTrust"] = "GATE_INDEPENDENTLY_VERIFIED"


def _validate_cyclonedx(path: Path, expected_digest: str | None = None) -> None:
    document = _require_object(_load_json(path, f"SBOM {path.name}"), f"SBOM {path.name}")
    if document.get("bomFormat") != "CycloneDX":
        raise EvidenceError(f"{path.name} is not a CycloneDX SBOM")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise EvidenceError(f"{path.name} contains no components")
    if expected_digest is not None:
        metadata = document.get("metadata", {}).get("component", {})
        if expected_digest not in json.dumps(metadata, sort_keys=True):
            raise EvidenceError(f"{path.name} is not bound to its image digest")


def _collect_supply_chain(
    release_images_path: Path,
    security_summary_path: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    repository_root: Path,
    gate_evaluated_at: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    release_images_path = _safe_file(release_images_path, artifacts_root, "release image manifest")
    document = _require_object(
        _load_json(release_images_path, "release image manifest"), "release image manifest"
    )
    if document.get("schemaVersion") != 1:
        raise EvidenceError("release image manifest must use schemaVersion 1")
    if document.get("releaseTag") != tag:
        raise EvidenceError("release image manifest tag does not match this release")
    if document.get("releaseVersion") != version or document.get("gitCommit") != commit:
        raise EvidenceError("release image manifest version or commit does not match this release")

    raw_sboms = _require_object(document.get("sboms"), "release image manifest sboms")
    if set(raw_sboms) != {"backend", "frontend"}:
        raise EvidenceError("release image manifest must name backend and frontend SBOMs")
    sboms: dict[str, Any] = {}
    for name in ("backend", "frontend"):
        path = _safe_file(Path(str(raw_sboms[name])), artifacts_root, f"{name} SBOM")
        _validate_cyclonedx(path)
        sboms[name] = {"path": _relative(path, artifacts_root), "sha256": _sha256(path)}

    raw_images = document.get("images")
    if not isinstance(raw_images, list):
        raise EvidenceError("release image manifest images must be an array")
    images: dict[str, Any] = {}
    for raw in raw_images:
        image = _require_object(raw, "release image entry")
        name = image.get("name")
        if name not in {"app", "nginx"} or name in images:
            raise EvidenceError("release image names must be unique app and nginx entries")
        digest = image.get("digest")
        reference = image.get("reference")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise EvidenceError(f"{name} image digest is invalid")
        if not isinstance(reference, str) or not reference.endswith("@" + digest):
            raise EvidenceError(f"{name} image reference is not digest-bound")
        sbom_path = _safe_file(Path(str(image.get("sbom", ""))), artifacts_root, f"{name} image SBOM")
        _validate_cyclonedx(sbom_path, digest)
        sbom_key = f"{name}Image"
        sboms[sbom_key] = {
            "path": _relative(sbom_path, artifacts_root),
            "sha256": _sha256(sbom_path),
        }
        images[name] = {"reference": reference, "digest": digest}
    if set(images) != {"app", "nginx"}:
        raise EvidenceError("release image manifest must contain app and nginx digest evidence")

    security_summary_path = _safe_file(
        security_summary_path, artifacts_root, "release security gate summary"
    )
    security = _require_object(
        _load_json(security_summary_path, "release security gate summary"),
        "release security gate summary",
    )
    if security.get("schemaVersion") != 1 or security.get("status") != "PASS":
        raise EvidenceError("release security gate summary is missing or not PASS")
    if security.get("releaseVersion") != version or security.get("gitCommit") != commit:
        raise EvidenceError("release security gate summary is bound to a different release")
    try:
        policy_date = date.fromisoformat(str(security.get("policyDate", "")))
        evaluated_at = datetime.fromisoformat(
            str(security.get("evaluatedAt", "")).replace("Z", "+00:00")
        )
    except ValueError as exception:
        raise EvidenceError("release security gate summary has invalid evaluation timestamps") from exception
    if evaluated_at.tzinfo is None:
        raise EvidenceError("release security gate summary evaluation timestamp lacks timezone")
    gate_utc = gate_evaluated_at.astimezone(timezone.utc)
    security_utc = evaluated_at.astimezone(timezone.utc)
    if policy_date != gate_utc.date() or security_utc.date() != gate_utc.date():
        raise EvidenceError("release security gate policy date must match the release gate UTC date")
    if security_utc > gate_utc or gate_utc - security_utc > timedelta(hours=2):
        raise EvidenceError("release security gate summary is future-dated or stale for this release run")
    exceptions_path = _safe_file(
        Path("security/high-vulnerability-exceptions.json"),
        repository_root,
        "High vulnerability exception policy",
    )
    recomputed_security, recomputed_errors = security_gate.evaluate(
        release_images_path,
        exceptions_path,
        policy_date,
        evaluated_at=evaluated_at,
    )
    if recomputed_errors or security != recomputed_security:
        raise EvidenceError(
            "release security gate summary does not match its SBOM, Trivy and exception inputs"
        )
    supply_gate = {
        "path": _relative(security_summary_path, artifacts_root),
        "sha256": _sha256(security_summary_path),
        "status": "PASS",
    }
    inputs = {
        "releaseImages": {
            "path": _relative(release_images_path, artifacts_root),
            "sha256": _sha256(release_images_path),
        },
        "securityGate": supply_gate,
    }
    return images, sboms, inputs


def _collect_runtime_acceptance(
    runtime_acceptance_path: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    images: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    path = _safe_file(
        runtime_acceptance_path, artifacts_root, "release runtime acceptance"
    )
    document = _require_object(
        _load_json(path, "release runtime acceptance"), "release runtime acceptance"
    )
    _require_exact_keys(
        document,
        {
            "schemaVersion",
            "status",
            "observedAt",
            "release",
            "images",
            "identity",
            "checks",
            "unifiedVerify",
        },
        "release runtime acceptance",
    )
    if document["schemaVersion"] != 1 or document["status"] != "PASS":
        raise EvidenceError("release runtime acceptance is missing or not PASS")
    _parse_observed_at(document["observedAt"], "release runtime acceptance")
    release = _require_object(document["release"], "release runtime acceptance release")
    if release != {"tag": tag, "version": version, "gitCommit": commit}:
        raise EvidenceError("release runtime acceptance identity does not match this release")
    runtime_images = _require_object(document["images"], "release runtime acceptance images")
    expected_images = {
        name: images[name]["reference"] for name in ("app", "nginx")
    }
    if runtime_images != expected_images:
        raise EvidenceError("release runtime acceptance did not use the scanned image digests")
    identity = _require_object(document["identity"], "release runtime acceptance identity")
    compose_project = identity.get("composeProject")
    trace_prefix = identity.get("mcpCrudTracePrefix")
    if not isinstance(compose_project, str) or COMPOSE_PROJECT.fullmatch(compose_project) is None:
        raise EvidenceError("release runtime acceptance Compose project identity is invalid")
    if trace_prefix != MCP_CRUD_TRACE_PREFIX:
        raise EvidenceError("release runtime acceptance MCP CRUD trace prefix is invalid")
    expected_identity = {
        "javaSpecificationVersion": "21",
        "applicationVersion": version,
        "buildVersion": version,
        "composeProject": compose_project,
        "mcpCrudTracePrefix": MCP_CRUD_TRACE_PREFIX,
        "appImage": expected_images["app"],
        "nginxImage": expected_images["nginx"],
        "appOciVersion": version,
        "appOciRevision": commit,
        "nginxOciVersion": version,
        "nginxOciRevision": commit,
    }
    if identity != expected_identity:
        raise EvidenceError("release runtime Java, Actuator or OCI identity does not match the release")
    checks = _require_object(document["checks"], "release runtime acceptance checks")
    _require_exact_keys(checks, RUNTIME_CHECKS, "release runtime acceptance checks")
    if any(value != "PASS" for value in checks.values()):
        raise EvidenceError("one or more release runtime acceptance checks are not PASS")
    unified = _require_object(document["unifiedVerify"], "unified verify evidence")
    _require_exact_keys(
        unified,
        {"path", "sha256", "status", "layers"},
        "unified verify evidence",
    )
    unified_path = _safe_file(
        Path(str(unified["path"])), artifacts_root, "unified verify summary"
    )
    if unified["path"] != _relative(unified_path, artifacts_root):
        raise EvidenceError("unified verify summary path is not canonical")
    unified_summary = _require_object(
        _load_json(unified_path, "unified verify summary"), "unified verify summary"
    )
    _require_exact_keys(
        unified_summary,
        {"schemaVersion", "status", "layers"},
        "unified verify summary",
    )
    layers = _require_object(unified_summary["layers"], "unified verify layers")
    _require_exact_keys(layers, VERIFY_LAYERS, "unified verify layers")
    expected_unified = {
        "path": _relative(unified_path, artifacts_root),
        "sha256": _sha256(unified_path),
        "status": "PASS",
        "layers": {name: "PASS" for name in sorted(VERIFY_LAYERS)},
    }
    if (
        unified_summary != {
            "schemaVersion": 1,
            "status": "PASS",
            "layers": expected_unified["layers"],
        }
        or unified != expected_unified
    ):
        raise EvidenceError("unified seven-layer verify evidence is missing, altered, or not PASS")
    runtime_input = {
        "path": _relative(path, artifacts_root),
        "sha256": _sha256(path),
        "status": "PASS",
    }
    unified_input = {
        "path": expected_unified["path"],
        "sha256": expected_unified["sha256"],
        "status": "PASS",
    }
    return (
        runtime_input,
        unified_input,
        {
            "composeProject": compose_project,
            "mcpCrudTracePrefix": MCP_CRUD_TRACE_PREFIX,
        },
    )


def _collect_runtime_identity(
    runtime_identity_path: Path,
    artifacts_root: Path,
    version: str,
    commit: str,
    images: dict[str, Any],
    runtime_references: dict[str, str],
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    path = _safe_file(runtime_identity_path, artifacts_root, "runtime version identity")
    document = _require_object(
        _load_json(path, "runtime version identity"), "runtime version identity"
    )
    _require_exact_keys(
        document,
        {"schemaVersion", "status", "observedAt", "release", "java", "actuator", "images"},
        "runtime version identity",
    )
    if document["schemaVersion"] != 2 or document["status"] != "PASS":
        raise EvidenceError("runtime version identity is missing or not PASS")
    _parse_observed_at(document["observedAt"], "runtime version identity")
    release = _require_object(document["release"], "runtime version identity release")
    if release != {"version": version, "gitCommit": commit}:
        raise EvidenceError("runtime version identity release does not match this release")

    java = _require_object(document["java"], "runtime Java identity")
    _require_exact_keys(java, {"specificationVersion", "runtimeVersion"}, "runtime Java identity")
    runtime_version = java.get("runtimeVersion")
    if (
        java.get("specificationVersion") != "21"
        or not isinstance(runtime_version, str)
        or not runtime_version
        or re.match(r"^21(?:[.+-]|$)", runtime_version) is None
        or len(runtime_version) > 128
        or any(character in runtime_version for character in "\r\n\0")
    ):
        raise EvidenceError("runtime Java identity is not an actual Java 21 runtime")

    actuator = _require_object(document["actuator"], "runtime Actuator identity")
    expected_actuator = {
        "applicationVersion": version,
        "buildVersion": version,
        "buildArtifact": "web-starter-admin",
        "buildGroup": "dev.webstarter",
    }
    if actuator != expected_actuator:
        raise EvidenceError("runtime Actuator build identity does not match the release")

    runtime_images = _require_object(document["images"], "runtime OCI identities")
    _require_exact_keys(
        runtime_images, {"app", "nginx", "mysql", "redis"}, "runtime image identities"
    )
    identities: dict[str, dict[str, str]] = {}
    for name in ("app", "nginx", "mysql", "redis"):
        image = _require_object(runtime_images[name], f"runtime {name} OCI identity")
        reference = runtime_references.get(name)
        if not isinstance(reference, str) or re.fullmatch(
            r"[^\s@]+@sha256:[0-9a-f]{64}", reference
        ) is None:
            raise EvidenceError(f"expected runtime {name} image is not digest-bound")
        expected = {
            "reference": reference,
            "imageId": image.get("imageId"),
            "ociVersion": version if name in {"app", "nginx"} else None,
            "ociRevision": commit if name in {"app", "nginx"} else None,
        }
        if not isinstance(image.get("imageId"), str) or DIGEST.fullmatch(image["imageId"]) is None:
            raise EvidenceError(f"runtime {name} identity lacks an immutable image ID")
        if image != expected:
            raise EvidenceError(f"runtime {name} identity does not match the release image")
        identities[name] = {"reference": reference, "imageId": image["imageId"]}
    return (
        {"path": _relative(path, artifacts_root), "sha256": _sha256(path), "status": "PASS"},
        identities,
    )


def _validated_public_copy(
    original_path: Path,
    artifact_path: Path,
    artifacts_root: Path,
    label: str,
) -> dict[str, str]:
    original = original_path.expanduser().absolute()
    if original.is_symlink() or not original.is_file():
        raise EvidenceError(f"{label} original evidence must be a regular non-symlink file")
    artifact = _safe_file(artifact_path, artifacts_root, f"{label} public artifact copy")
    original_digest = _sha256(original)
    if _sha256(artifact) != original_digest or artifact.read_bytes() != original.read_bytes():
        raise EvidenceError(f"{label} public artifact copy differs from validated evidence")
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": original_digest,
        "status": "PASS",
    }


def _collect_v1_source_provenance_proof(
    *,
    proof_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
) -> dict[str, str] | None:
    if proof_path is None and artifact_path is None:
        return None
    if proof_path is None or artifact_path is None:
        raise EvidenceError(
            "V1 source provenance verification requires both the private raw proof "
            "and canonical summary"
        )
    try:
        summary = v1_source_provenance.validate_proof(
            proof_path,
            repository_root,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            require_pass=True,
        )
        expected_payload = v1_source_provenance.canonical_summary_bytes(summary)
    except (OSError, UnicodeDecodeError, v1_source_provenance.ProofValidationError) as exception:
        raise EvidenceError(
            "V2-AC-01 frozen V1 source provenance is not independently PASS"
        ) from exception

    _require_exact_keys(
        summary,
        {"schemaVersion", "acceptanceId", "status", "candidate", "v1Source", "checks", "evidence"},
        "V2-AC-01 V1 source provenance summary",
    )
    if (
        summary.get("schemaVersion") != 1
        or summary.get("acceptanceId") != "V2-AC-01"
        or summary.get("status") != "PASS"
    ):
        raise EvidenceError("V2-AC-01 V1 source provenance summary is not exact PASS")
    candidate = _require_object(
        summary.get("candidate"), "V2-AC-01 current release candidate binding"
    )
    _require_exact_keys(
        candidate,
        {"commit", "tree", "tag", "version"},
        "V2-AC-01 current release candidate binding",
    )
    if (
        candidate.get("commit") != commit
        or candidate.get("tag") != tag
        or candidate.get("version") != version
        or not isinstance(candidate.get("tree"), str)
        or COMMIT.fullmatch(candidate["tree"]) is None
    ):
        raise EvidenceError("V2-AC-01 current release candidate binding differs")

    v1_source = _require_object(summary.get("v1Source"), "V2-AC-01 frozen V1 binding")
    expected_v1_source = {
        "tag": "v1.0.0",
        "tagObject": "406e73cca6f4d4e257c2aa08e58815d96b7ca722",
        "commit": "5ebdb238650d182c17e1493adf47aaa3324f19cb",
        "tree": "355c61a77f4dd0f16f0f3d945ee6c8d4f02d956a",
        "tagAnnotationSha256": hashlib.sha256(
            "启程 Web Starter V1 verified baseline".encode("utf-8")
        ).hexdigest(),
        "sourceArchiveSha256": "79b220b5a4da72ea3d4bb98203add92bce83fc19e30cd24ebfa084c7bc360ff5",
        "baselinePath": "docs/acceptance/v1-acceptance-baseline.md",
        "baselineBlob": "d59cbbd26c69c0497b6e0bb28e7c2a9306c02a35",
        "baselineSha256": "aa9ef7247246165c451e6910db6da167d1385b6e14f3f65fd72a7705e8263994",
        "acceptanceRecordPath": "docs/acceptance/v1-acceptance-2026-07-19.md",
        "acceptanceRecordBlob": "9e9346046cb4bff5200487281f15fd7621781562",
        "acceptanceRecordSha256": "81ce417c52f004d74275b591d47748f8868226cccaf3e02a21490d42785336f9",
        "acceptanceResultCount": 42,
        "acceptancePassCount": 42,
        "baselineP0Count": 37,
        "baselineP1Count": 5,
        "automationCheckCount": 12,
        "finalCheckedCount": 5,
        "finalConclusion": "PASS",
        "historicalExecutionTrust": "TAGGED_RECORD_ONLY",
    }
    if v1_source != expected_v1_source:
        raise EvidenceError("V2-AC-01 frozen V1 source binding differs from the fixed contract")
    expected_checks = {
        "annotatedTag": "PASS",
        "fixedTagTarget": "PASS",
        "frozenBaselineDefinitions": "PASS",
        "historicalRecordCompleteness": "PASS",
        "historicalAutomationRecord": "PASS",
        "historicalFinalConclusion": "PASS",
        "releaseAncestry": "PASS",
        "currentCandidateV1Regression": "NOT_CLAIMED",
        "historicalRuntimeArtifacts": "NOT_REVALIDATED",
    }
    if summary.get("checks") != expected_checks:
        raise EvidenceError("V2-AC-01 provenance scope or semantic checks differ")
    evidence = _require_object(summary.get("evidence"), "V2-AC-01 evidence binding")
    _require_exact_keys(evidence, {"reportSha256", "sourceSha256"}, "V2-AC-01 evidence binding")
    if not isinstance(evidence.get("reportSha256"), str) or re.fullmatch(
        r"[0-9a-f]{64}", evidence["reportSha256"]
    ) is None:
        raise EvidenceError("V2-AC-01 raw report digest is invalid")
    source_hashes = _require_object(evidence.get("sourceSha256"), "V2-AC-01 source hashes")
    expected_source_paths = {
        "scripts/create_v1_source_provenance_proof.py",
        "scripts/validate_v1_source_provenance_proof.py",
        "security/v2-ac01-v1-source-provenance-summary.schema.json",
        "docs/acceptance/v2-acceptance-baseline.md",
        "pom.xml",
        "web-starter-web/package.json",
    }
    _require_exact_keys(source_hashes, expected_source_paths, "V2-AC-01 source hashes")
    if any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
           for value in source_hashes.values()):
        raise EvidenceError("V2-AC-01 source hash is invalid")

    artifact = _safe_file(
        artifact_path, artifacts_root, "V2-AC-01 V1 source provenance canonical summary"
    )
    if artifact.name != v1_source_provenance.SUMMARY_NAME:
        raise EvidenceError("V2-AC-01 canonical summary has an unexpected file name")
    if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
        raise EvidenceError("V2-AC-01 canonical summary must have mode 0600")
    if artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "V2-AC-01 canonical summary differs from independently recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_v1_operations_documentation_proof(
    *,
    proof_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
) -> dict[str, str] | None:
    supplied = (proof_path, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "V1 AC-38 verification requires both the private raw proof and canonical summary"
        )
    assert proof_path is not None and artifact_path is not None
    try:
        summary = v1_operations_documentation.validate_proof(
            proof_path,
            repository_root=repository_root,
            expected_candidate_commit=commit,
            expected_candidate_tag=tag,
            expected_candidate_version=version,
        )
        expected_payload = v1_operations_documentation.canonical_summary_bytes(summary)
    except (
        OSError,
        UnicodeError,
        v1_operations_documentation.ProofValidationError,
        ValueError,
    ) as exception:
        raise EvidenceError(
            "V1 AC-38 operations documentation proof is not independently PASS"
        ) from exception
    expected_candidate = {
        "commit": commit,
        "tree": summary.get("candidate", {}).get("tree"),
        "tag": tag,
        "version": version,
    }
    if (
        summary.get("schemaVersion") != 1
        or summary.get("acceptanceIds") != ["AC-38"]
        or summary.get("status") != "PASS"
        or summary.get("candidate") != expected_candidate
        or not isinstance(expected_candidate["tree"], str)
        or COMMIT.fullmatch(expected_candidate["tree"]) is None
        or summary.get("checks") != {
            "operationsDocumentationReview": "PASS",
            "sourceIntegrity": "PASS",
        }
    ):
        raise EvidenceError("V1 AC-38 canonical semantics differ from the frozen contract")
    artifact = _safe_file(
        artifact_path,
        artifacts_root,
        "V1 AC-38 operations documentation canonical summary",
    )
    metadata = artifact.stat()
    if (
        artifact.name != v1_operations_documentation.SUMMARY_NAME
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or artifact.read_bytes() != expected_payload
    ):
        raise EvidenceError(
            "V1 AC-38 canonical summary differs from independently recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_release_runtime_test_reports(
    *,
    evidence_directory: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    release_repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    tag_object: str,
    verify_git: bool,
) -> dict[str, str] | None:
    supplied = (evidence_directory, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "release runtime test report verification requires both the private raw "
            "directory and canonical summary"
        )
    assert evidence_directory is not None and artifact_path is not None

    raw_requested = evidence_directory.expanduser().absolute()
    if raw_requested.is_symlink() or not raw_requested.is_dir():
        raise EvidenceError(
            "release runtime test report raw evidence must be a real directory"
        )
    raw = raw_requested.resolve()
    if (
        _is_inside(raw, artifacts_root)
        or _is_inside(artifacts_root, raw)
        or _is_inside(raw, release_repository_root)
        or _is_inside(release_repository_root, raw)
    ):
        raise EvidenceError(
            "release runtime test report raw evidence must be isolated from repositories "
            "and public artifacts"
        )

    artifact = _safe_file(
        artifact_path,
        artifacts_root,
        "release runtime test reports canonical summary",
    )
    metadata = artifact.stat()
    if (
        artifact.name != release_runtime_test_reports.SUMMARY_FILE
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > release_runtime_test_reports.MAX_PROOF_BYTES
    ):
        raise EvidenceError(
            "release runtime test reports canonical summary is not one private fixed file"
        )
    public_document = _require_object(
        _load_json(artifact, "release runtime test reports canonical summary"),
        "release runtime test reports canonical summary",
    )
    public_run = _require_object(
        public_document.get("run"), "release runtime test reports run binding"
    )
    _require_exact_keys(
        public_run,
        {"startedAtEpochNs"},
        "release runtime test reports run binding",
    )
    started_ns = public_run.get("startedAtEpochNs")
    if (
        not isinstance(started_ns, int)
        or isinstance(started_ns, bool)
        or started_ns <= 0
    ):
        raise EvidenceError("release runtime test reports run start is invalid")

    try:
        summary = release_runtime_test_reports.validate_proof(
            raw,
            repository_root=repository_root,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            expected_run_started_at_epoch_ns=started_ns,
            require_pass=True,
        )
        expected_payload = release_runtime_test_reports.canonical_summary_bytes(summary)
    except (
        OSError,
        UnicodeDecodeError,
        release_runtime_test_reports.RuntimeReportValidationError,
    ) as exception:
        raise EvidenceError(
            "release runtime test reports are not independently PASS"
        ) from exception

    expected_top = {
        "schemaVersion", "evidenceType", "status", "candidate", "run",
        "coverage", "reports", "sources",
    }
    _require_exact_keys(summary, expected_top, "release runtime test reports summary")
    if (
        summary.get("schemaVersion") != 1
        or summary.get("evidenceType") != "releaseRuntimeTestReports"
        or summary.get("status") != "PASS"
        or summary.get("run") != {"startedAtEpochNs": started_ns}
    ):
        raise EvidenceError("release runtime test reports summary is not exact PASS")

    candidate = _require_object(
        summary.get("candidate"), "release runtime test reports candidate binding"
    )
    _require_exact_keys(
        candidate,
        {"commit", "tree", "version", "tag", "tagObject"},
        "release runtime test reports candidate binding",
    )
    if (
        candidate.get("commit") != commit
        or candidate.get("version") != version
        or candidate.get("tag") != tag
        or not isinstance(candidate.get("tree"), str)
        or COMMIT.fullmatch(candidate["tree"]) is None
        or not isinstance(candidate.get("tagObject"), str)
        or COMMIT.fullmatch(candidate["tagObject"]) is None
    ):
        raise EvidenceError("release runtime test reports candidate identity differs")
    if verify_git:
        expected_tree = _git(repository_root, "rev-parse", f"{commit}^{{tree}}")
        expected_candidate = {
            "commit": commit,
            "tree": expected_tree,
            "version": version,
            "tag": tag,
            "tagObject": tag_object,
        }
        if candidate != expected_candidate:
            raise EvidenceError(
                "release runtime test reports commit/tree/tag/version binding differs"
            )

    expected_specs = sorted(
        (
            {"file": relative, "title": title}
            for relative, titles in release_runtime_test_reports.PLAYWRIGHT_SPECS.items()
            for title in titles
        ),
        key=lambda item: (item["file"], item["title"]),
    )
    expected_surefire = [
        {
            "reportFile": report,
            "testClass": identity[0],
            "testMethod": identity[1],
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "retries": 0,
        }
        for report, identity in sorted(release_runtime_test_reports.SUREFIRE_TESTS.items())
    ]
    expected_coverage = {
        "playwright": {
            "reportFile": release_runtime_test_reports.PLAYWRIGHT_REPORT,
            "tests": release_runtime_test_reports.PLAYWRIGHT_TEST_COUNT,
            "passed": release_runtime_test_reports.PLAYWRIGHT_TEST_COUNT,
            "skipped": 0,
            "retries": 0,
            "projectName": "default",
            "specs": expected_specs,
        },
        "surefire": expected_surefire,
    }
    if summary.get("coverage") != expected_coverage:
        raise EvidenceError(
            "release runtime test reports do not contain exactly "
            f"{release_runtime_test_reports.PLAYWRIGHT_TEST_COUNT} Playwright and 2 SDK results"
        )

    reports = _require_object(summary.get("reports"), "release runtime report digests")
    _require_exact_keys(
        reports,
        set(release_runtime_test_reports.RAW_REPORT_FILES),
        "release runtime report digests",
    )
    if any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in reports.values()
    ):
        raise EvidenceError("release runtime report digest is invalid")
    sources = _require_object(summary.get("sources"), "release runtime source digests")
    _require_exact_keys(
        sources,
        set(release_runtime_test_reports.SOURCE_PATHS),
        "release runtime source digests",
    )
    if any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in sources.values()
    ):
        raise EvidenceError("release runtime source digest is invalid")

    if public_document != summary or artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "release runtime test reports canonical summary differs from recomputed raw evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_project_transport_parity_proof(
    *,
    proof_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
) -> dict[str, str] | None:
    if proof_path is None and artifact_path is None:
        return None
    if proof_path is None or artifact_path is None:
        raise EvidenceError(
            "V1 AC-15 transport-parity verification requires both the private "
            "raw proof and canonical summary"
        )
    try:
        summary = project_transport_parity_proof.validate_proof(
            proof_path,
            repository_root=repository_root,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            require_pass=True,
        )
        expected_payload = project_transport_parity_proof.canonical_summary_bytes(summary)
    except (OSError, project_transport_parity_proof.ProofValidationError) as exception:
        raise EvidenceError(
            "V1 AC-15 Project transport-parity evidence is not independently PASS"
        ) from exception
    if (
        summary.get("schemaVersion") != 1
        or summary.get("acceptanceId") != "AC-15"
        or summary.get("status") != "PASS"
    ):
        raise EvidenceError("V1 AC-15 Project transport-parity summary is not exact PASS")
    candidate = _require_object(
        summary.get("candidate"), "V1 AC-15 Project transport-parity candidate binding"
    )
    _require_exact_keys(
        candidate,
        {"commit", "tree", "version", "tag"},
        "V1 AC-15 Project transport-parity candidate binding",
    )
    if (
        candidate.get("commit") != commit
        or candidate.get("version") != version
        or candidate.get("tag") != tag
        or not isinstance(candidate.get("tree"), str)
        or COMMIT.fullmatch(candidate["tree"]) is None
    ):
        raise EvidenceError("V1 AC-15 Project transport-parity candidate binding differs")
    artifact = _safe_file(
        artifact_path,
        artifacts_root,
        "V1 AC-15 Project transport-parity canonical summary",
    )
    if artifact.name != "v1-ac15-project-transport-parity-summary.json":
        raise EvidenceError("V1 AC-15 canonical summary has an unexpected file name")
    if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
        raise EvidenceError("V1 AC-15 canonical summary must have mode 0600")
    if artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "V1 AC-15 canonical summary differs from independently recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_migration_failure_evidence(
    *,
    evidence_path: Path | None,
    ac40_evidence_path: Path | None,
    ac40_dependency_seed_path: Path | None,
    expected_ac40_dependency_seed_sha256: str | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    runtime_images: dict[str, dict[str, str]],
) -> dict[str, str] | None:
    supplied = (evidence_path, ac40_evidence_path, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "migration-failure verification requires original AC-07, original AC-40, and artifact copy"
        )
    assert evidence_path is not None and ac40_evidence_path is not None and artifact_path is not None
    try:
        summary = migration_failure_evidence.validate_document_path(
            evidence_path,
            repository_root=repository_root,
            ac40_evidence_path=ac40_evidence_path,
            ac40_dependency_seed=ac40_dependency_seed_path,
            expected_ac40_dependency_seed_sha256=(
                expected_ac40_dependency_seed_sha256
            ),
            expected_app_image_id=runtime_images["app"]["imageId"],
            expected_mysql_image_id=runtime_images["mysql"]["imageId"],
            expected_redis_image_id=runtime_images["redis"]["imageId"],
            expected_app_reference=runtime_images["app"]["reference"],
            require_pass=True,
        )
    except migration_failure_evidence.EvidenceValidationError as exception:
        raise EvidenceError("V2-AC-07 migration-failure evidence is not independently PASS") from exception
    if summary.get("status") != "PASS":
        raise EvidenceError("V2-AC-07 migration-failure evidence is not PASS")
    return _validated_public_copy(
        evidence_path, artifact_path, artifacts_root, "V2-AC-07 migration-failure"
    )


def _collect_v1_upgrade_evidence(
    *,
    evidence_path: Path | None,
    artifact_path: Path | None,
    dependency_seed_path: Path | None,
    expected_dependency_seed_sha256: str | None,
    repository_root: Path,
    artifacts_root: Path,
) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    if evidence_path is None and artifact_path is None:
        return None, None
    if evidence_path is None or artifact_path is None:
        raise EvidenceError(
            "V1 upgrade verification requires both original AC-40 evidence and artifact copy"
        )
    try:
        summary = v1_upgrade_evidence.validate_document_path(
            evidence_path,
            repository_root=repository_root,
            dependency_seed=dependency_seed_path,
            expected_dependency_seed_sha256=expected_dependency_seed_sha256,
            require_pass=True,
        )
    except v1_upgrade_evidence.EvidenceValidationError as exception:
        raise EvidenceError("V2-AC-40 V1 upgrade evidence is not independently PASS") from exception
    if summary.get("status") != "PASS":
        raise EvidenceError("V2-AC-40 V1 upgrade evidence is not PASS")
    return (
        _validated_public_copy(
            evidence_path, artifact_path, artifacts_root, "V2-AC-40 V1 upgrade"
        ),
        summary,
    )


def _collect_ac40_dependency_seed_provenance(
    *,
    provenance_path: Path | None,
    artifacts_root: Path,
    commit: str,
    v1_upgrade_summary: dict[str, Any] | None,
) -> dict[str, str] | None:
    if provenance_path is None:
        return None
    if v1_upgrade_summary is None:
        raise EvidenceError(
            "AC40 dependency-seed provenance requires independently validated AC-40 evidence"
        )
    source = _require_object(v1_upgrade_summary.get("source"), "V2-AC-40 source")
    dependency_seed = _require_object(
        source.get("dependencySeed"), "V2-AC-40 source dependencySeed"
    )

    artifacts_root = artifacts_root.resolve()
    path = _safe_file(
        provenance_path,
        artifacts_root,
        "AC40 dependency-seed provenance",
    )
    expected_path = artifacts_root / AC40_DEPENDENCY_SEED_PROVENANCE_PATH
    if path != expected_path or expected_path.resolve() != expected_path:
        raise EvidenceError(
            "AC40 dependency-seed provenance must use its exact real artifacts path"
        )
    payload = _read_private_fixed_file(
        path,
        32 * 1024,
        "AC40 dependency-seed provenance",
    )
    try:
        document = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_unique_json_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceError("AC40 dependency-seed provenance is invalid JSON") from exception
    document = _require_object(document, "AC40 dependency-seed provenance")
    _require_exact_keys(
        document,
        AC40_DEPENDENCY_SEED_PROVENANCE_KEYS,
        "AC40 dependency-seed provenance",
    )
    canonical = (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if payload != canonical:
        raise EvidenceError("AC40 dependency-seed provenance is not canonical JSON")
    if type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 1:
        raise EvidenceError("AC40 dependency-seed provenance must use schemaVersion 1")
    if document.get("kind") != "web-starter-ac40-dependency-seed-provenance":
        raise EvidenceError("AC40 dependency-seed provenance kind is invalid")
    if document.get("environment") != "release":
        raise EvidenceError("AC40 dependency-seed provenance environment must be release")
    for field in ("artifactId", "workflowRunId", "headRepositoryId"):
        if type(document.get(field)) is not int or document[field] <= 0:
            raise EvidenceError(
                f"AC40 dependency-seed provenance {field} must be a positive integer"
            )
    if document.get("producerHeadSha") != commit:
        raise EvidenceError(
            "AC40 dependency-seed provenance producerHeadSha differs from release commit"
        )
    for field in (
        "archiveSha256", "aggregateSha256", "manifestSha256",
    ):
        value = document.get(field)
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise EvidenceError(
                f"AC40 dependency-seed provenance {field} must be lowercase SHA-256"
            )
    if document.get("platform") != "linux" or document.get("architecture") != "x86_64":
        raise EvidenceError(
            "AC40 dependency-seed provenance must describe Linux x86_64"
        )
    expected_seed_identity = {
        "aggregateSha256": document["aggregateSha256"],
        "manifestSha256": document["manifestSha256"],
        "platform": document["platform"],
        "architecture": document["architecture"],
    }
    actual_seed_identity = {
        field: dependency_seed.get(field) for field in expected_seed_identity
    }
    if actual_seed_identity != expected_seed_identity:
        raise EvidenceError(
            "AC40 dependency-seed provenance differs from independently validated AC-40 evidence"
        )
    return {
        "path": AC40_DEPENDENCY_SEED_PROVENANCE_PATH,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "status": "PASS",
    }


def _collect_redis_loss_evidence(
    *,
    evidence_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    runtime_images: dict[str, dict[str, str]],
) -> dict[str, str] | None:
    if evidence_path is None and artifact_path is None:
        return None
    if evidence_path is None or artifact_path is None:
        raise EvidenceError(
            "Redis-loss verification requires both original AC-41 evidence and its artifact copy"
        )
    expected_images = {
        name: {
            "reference": runtime_images[name]["reference"],
            "imageId": runtime_images[name]["imageId"],
        }
        for name in ("app", "nginx", "mysql", "redis")
    }
    try:
        summary = redis_loss_evidence.validate_document_path(
            evidence_path,
            repository_root=repository_root,
            expected_images=expected_images,
        )
    except redis_loss_evidence.RedisLossEvidenceError as exception:
        raise EvidenceError("V2-AC-41 Redis-loss evidence is not independently PASS") from exception
    if summary.get("status") != "PASS":
        raise EvidenceError("V2-AC-41 Redis-loss evidence is not PASS")
    return _validated_public_copy(
        evidence_path, artifact_path, artifacts_root, "V2-AC-41 Redis-loss"
    )


def _collect_mcp_crud_runtime_proof(
    *,
    proof_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    runtime_binding: dict[str, str],
) -> dict[str, str] | None:
    if proof_path is None and artifact_path is None:
        return None
    if proof_path is None or artifact_path is None:
        raise EvidenceError(
            "MCP CRUD proof verification requires both the private proof and canonical summary"
        )
    try:
        summary = mcp_crud_proof.validate_proof(
            proof_path,
            repository_root=repository_root,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            expected_compose_project=runtime_binding["composeProject"],
            expected_trace_prefix=runtime_binding["mcpCrudTracePrefix"],
            require_pass=True,
        )
    except (OSError, mcp_crud_proof.ProofValidationError) as exception:
        raise EvidenceError(
            "AC-16 and V2-AC-31/32 MCP CRUD runtime proof is not independently PASS"
        ) from exception
    required_checks = {
        "officialSdkRuntime",
        "businessTransactionRollback",
        "successBusinessAuditAtomicity",
        "failedMcpAuditPersists",
        "idempotencyReservationRollback",
        "faultInjectionCleaned",
        "transactionalStorage",
    }
    if (
        summary.get("status") != "PASS"
        or summary.get("acceptanceIds") != ["AC-16", "V2-AC-31", "V2-AC-32"]
        or summary.get("checks") != {name: "PASS" for name in required_checks}
    ):
        raise EvidenceError(
            "AC-16 and V2-AC-31/32 MCP CRUD runtime proof is not PASS"
        )

    artifact = _safe_file(
        artifact_path,
        artifacts_root,
        "AC-16 and V2-AC-31/32 MCP CRUD canonical summary",
    )
    if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
        raise EvidenceError("MCP CRUD canonical summary must have mode 0600")
    expected_payload = (
        json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "MCP CRUD canonical summary differs from the independently validated proof"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_credential_lifecycle_evidence(
    *,
    report_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    release_repository_root: Path,
    artifacts_root: Path,
    runtime_identity_path: Path,
    compose_project: str,
    tag: str,
    version: str,
    commit: str,
) -> dict[str, str] | None:
    supplied = (report_path, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "credential lifecycle verification requires both private raw report and canonical summary"
        )
    assert report_path is not None and artifact_path is not None
    requested = report_path.expanduser().absolute()
    if (
        requested.name != credential_lifecycle_evidence.REPORT_NAME
        or requested.is_symlink()
        or requested.parent.is_symlink()
        or not requested.is_file()
    ):
        raise EvidenceError("credential lifecycle evidence must be the fixed real private report")
    raw = requested.parent.resolve(strict=True)
    metadata = os.stat(raw, follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        or set(os.listdir(raw)) != {credential_lifecycle_evidence.REPORT_NAME}
    ):
        raise EvidenceError("credential lifecycle raw evidence must be one owned mode-0700 directory")
    for root in (
        repository_root.resolve(), release_repository_root.resolve(), artifacts_root.resolve(),
    ):
        if _is_inside(raw, root) or _is_inside(root, raw):
            raise EvidenceError(
                "credential lifecycle raw evidence must be isolated from repositories and public artifacts"
            )
    if not isinstance(compose_project, str) or COMPOSE_PROJECT.fullmatch(compose_project) is None:
        raise EvidenceError("credential lifecycle Compose project must be explicit and bounded")

    runtime_identity = _safe_file(
        runtime_identity_path, artifacts_root, "credential lifecycle runtime identity"
    )
    oauth_runtime = _safe_file(
        artifacts_root / "oauth-runtime.json", artifacts_root,
        "credential lifecycle OAuth runtime prerequisite",
    )
    artifact = _safe_file(
        artifact_path, artifacts_root, "credential lifecycle canonical summary"
    )
    if (
        artifact.name != credential_lifecycle_evidence.SUMMARY_NAME
        or _relative(artifact, artifacts_root)
        != f"acceptance/{credential_lifecycle_evidence.SUMMARY_NAME}"
    ):
        raise EvidenceError("credential lifecycle canonical summary has an unexpected path")
    try:
        summary = credential_lifecycle_evidence.validate(
            requested,
            repository_root,
            runtime_identity,
            oauth_runtime,
            compose_project,
            None,
        )
        expected_payload = credential_lifecycle_evidence.canonical_summary_bytes(summary)
    except (
        OSError,
        UnicodeDecodeError,
        credential_lifecycle_evidence.EvidenceError,
    ) as exception:
        raise EvidenceError(
            "V2-AC-24/27/28/36 credential lifecycle evidence is not independently PASS"
        ) from exception
    candidate = _require_object(summary.get("candidate"), "credential lifecycle candidate")
    if (
        summary.get("acceptanceIds") != ["V2-AC-24", "V2-AC-27", "V2-AC-28", "V2-AC-36"]
        or summary.get("status") != "PASS"
        or candidate.get("releaseTag") != tag
        or candidate.get("releaseVersion") != version
        or candidate.get("gitCommit") != commit
    ):
        raise EvidenceError("credential lifecycle summary release binding differs")
    public_payload = _read_private_fixed_file(
        artifact, 2 * 1024 * 1024, "credential lifecycle canonical summary"
    )
    if public_payload != expected_payload:
        raise EvidenceError(
            "credential lifecycle canonical summary differs byte-for-byte from recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_observability_evidence(
    *,
    baseline_path: Path | None,
    runtime_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    runtime_identity_path: Path,
    compose_project: str,
    tag: str,
    version: str,
    commit: str,
) -> dict[str, str] | None:
    supplied = (baseline_path, runtime_path, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "observability verification requires baseline, runtime report and canonical summary"
        )
    assert baseline_path is not None and runtime_path is not None and artifact_path is not None
    baseline = _safe_file(
        baseline_path, artifacts_root, "observability metrics baseline"
    )
    runtime = _safe_file(
        runtime_path, artifacts_root, "observability metrics runtime report"
    )
    if (
        _relative(baseline, artifacts_root) != "operational-metrics-baseline.json"
        or _relative(runtime, artifacts_root) != "operational-metrics-runtime.json"
    ):
        raise EvidenceError("observability raw reports have unexpected artifact paths")
    runtime_identity = _safe_file(
        runtime_identity_path, artifacts_root, "observability runtime identity"
    )
    artifact = _safe_file(
        artifact_path, artifacts_root, "observability canonical summary"
    )
    if (
        artifact.name != observability_evidence.SUMMARY_NAME
        or _relative(artifact, artifacts_root)
        != f"acceptance/{observability_evidence.SUMMARY_NAME}"
    ):
        raise EvidenceError("observability canonical summary has an unexpected path")
    try:
        summary = observability_evidence.validate(
            baseline,
            runtime,
            repository_root,
            runtime_identity,
            compose_project,
            tag,
            None,
        )
        expected_payload = observability_evidence.canonical_summary_bytes(summary)
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
        observability_evidence.ObservabilityEvidenceError,
    ) as exception:
        raise EvidenceError(
            "V2-AC-37 observability evidence is not independently PASS"
        ) from exception
    candidate = _require_object(summary.get("candidate"), "observability candidate")
    runtime_binding = _require_object(summary.get("runtime"), "observability runtime")
    if (
        summary.get("acceptanceIds") != ["V2-AC-37"]
        or summary.get("status") != "PASS"
        or candidate.get("releaseTag") != tag
        or candidate.get("releaseVersion") != version
        or candidate.get("gitCommit") != commit
        or runtime_binding.get("composeProject") != compose_project
    ):
        raise EvidenceError("observability summary release binding differs")
    public_payload = _read_private_fixed_file(
        artifact, 2 * 1024 * 1024, "observability canonical summary"
    )
    if public_payload != expected_payload:
        raise EvidenceError(
            "observability canonical summary differs byte-for-byte from recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_tooling_lifecycle_evidence(
    *,
    report_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    release_repository_root: Path,
    artifacts_root: Path,
    runtime_identity_path: Path,
    compose_project: str | None,
    tag: str,
    version: str,
    commit: str,
) -> dict[str, str] | None:
    supplied = (report_path, artifact_path, compose_project)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "tooling lifecycle verification requires private report, Compose project and canonical summary"
        )
    assert report_path is not None and artifact_path is not None and compose_project is not None
    requested = report_path.expanduser().absolute()
    if (
        requested.name != tooling_lifecycle_evidence.REPORT_NAME
        or requested.is_symlink()
        or requested.parent.is_symlink()
        or not requested.is_file()
    ):
        raise EvidenceError("tooling lifecycle evidence must be the fixed real private report")
    raw = requested.parent.resolve(strict=True)
    metadata = os.stat(raw, follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        or set(os.listdir(raw)) != {tooling_lifecycle_evidence.REPORT_NAME}
    ):
        raise EvidenceError("tooling lifecycle raw evidence must be one owned mode-0700 directory")
    for root in (
        repository_root.resolve(), release_repository_root.resolve(), artifacts_root.resolve(),
    ):
        if _is_inside(raw, root) or _is_inside(root, raw):
            raise EvidenceError(
                "tooling lifecycle raw evidence must be isolated from repositories and public artifacts"
            )
    runtime_identity = _safe_file(
        runtime_identity_path, artifacts_root, "tooling lifecycle runtime identity"
    )
    artifact = _safe_file(
        artifact_path, artifacts_root, "tooling lifecycle canonical summary"
    )
    if (
        artifact.name != tooling_lifecycle_evidence.SUMMARY_NAME
        or _relative(artifact, artifacts_root)
        != f"acceptance/{tooling_lifecycle_evidence.SUMMARY_NAME}"
    ):
        raise EvidenceError("tooling lifecycle canonical summary has an unexpected path")
    try:
        summary = tooling_lifecycle_evidence.validate(
            requested,
            repository_root,
            runtime_identity,
            compose_project,
            None,
        )
        expected_payload = tooling_lifecycle_evidence.canonical_summary_bytes(summary)
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
        tooling_lifecycle_evidence.ToolingEvidenceError,
    ) as exception:
        raise EvidenceError(
            "AC-02/AC-37/V2-AC-16/17 tooling lifecycle evidence is not independently PASS"
        ) from exception
    candidate = _require_object(summary.get("candidate"), "tooling lifecycle candidate")
    runtime = _require_object(summary.get("runtime"), "tooling lifecycle runtime")
    if (
        summary.get("acceptanceIds")
        != ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"]
        or summary.get("status") != "PASS"
        or candidate.get("releaseTag") != tag
        or candidate.get("releaseVersion") != version
        or candidate.get("gitCommit") != commit
        or runtime.get("composeProject") != compose_project
    ):
        raise EvidenceError("tooling lifecycle summary release binding differs")
    public_payload = _read_private_fixed_file(
        artifact, 2 * 1024 * 1024, "tooling lifecycle canonical summary"
    )
    if public_payload != expected_payload:
        raise EvidenceError(
            "tooling lifecycle canonical summary differs byte-for-byte from recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_mcp_governance_runtime_proof(
    *,
    proof_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    release_repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    runtime_binding: dict[str, str],
    runtime_images: dict[str, dict[str, str]],
    compose_project: str | None,
    ac26_compose_project: str | None,
) -> dict[str, str] | None:
    supplied = (proof_path, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "MCP governance verification requires both the private raw proof directory "
            "and canonical public summary"
        )
    assert proof_path is not None and artifact_path is not None

    if (
        not isinstance(compose_project, str)
        or MCP_GOVERNANCE_COMPOSE_PROJECT.fullmatch(compose_project) is None
        or not isinstance(ac26_compose_project, str)
        or COMPOSE_PROJECT.fullmatch(ac26_compose_project) is None
    ):
        raise EvidenceError(
            "MCP governance verification requires explicit bounded governance and AC-26 "
            "Compose project identities"
        )
    if compose_project in {runtime_binding["composeProject"], ac26_compose_project}:
        raise EvidenceError(
            "MCP governance Compose project must differ from the main and AC-26 runtimes"
        )

    requested = proof_path.expanduser().absolute()
    if (
        requested.name != mcp_governance_proof.PROOF_FILE
        or requested.is_symlink()
        or requested.parent.is_symlink()
        or not requested.is_file()
    ):
        raise EvidenceError("MCP governance proof must be the fixed real private proof file")
    raw = requested.parent.resolve(strict=True)
    metadata = os.stat(raw, follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
    ):
        raise EvidenceError("MCP governance raw evidence directory must be owned mode 0700")
    isolated_roots = {
        artifacts_root.resolve(),
        repository_root.resolve(),
        release_repository_root.resolve(),
    }
    if any(_is_inside(raw, root) or _is_inside(root, raw) for root in isolated_roots):
        raise EvidenceError(
            "MCP governance raw evidence must be isolated from repositories and public artifacts"
        )

    artifact = _safe_file(
        artifact_path,
        artifacts_root,
        "V2-AC-34/35 MCP governance canonical summary",
    )
    if (
        artifact.name != MCP_GOVERNANCE_SUMMARY_FILE
        or _relative(artifact, artifacts_root)
        != f"acceptance/{MCP_GOVERNANCE_SUMMARY_FILE}"
    ):
        raise EvidenceError("MCP governance canonical summary has an unexpected file name")

    try:
        summary = mcp_governance_proof.validate_proof(
            requested,
            repository_root=repository_root,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            expected_compose_project=compose_project,
            expected_trace_prefix=MCP_GOVERNANCE_TRACE_PREFIX,
            expected_app_reference=runtime_images["app"]["reference"],
            expected_app_image_id=runtime_images["app"]["imageId"],
            expected_nginx_reference=runtime_images["nginx"]["reference"],
            expected_nginx_image_id=runtime_images["nginx"]["imageId"],
            expected_redis_reference=runtime_images["redis"]["reference"],
            expected_redis_image_id=runtime_images["redis"]["imageId"],
            require_pass=True,
        )
        expected_payload = mcp_governance_proof.canonical_summary_bytes(summary)
    except (
        OSError,
        UnicodeDecodeError,
        mcp_governance_proof.ProofValidationError,
    ) as exception:
        raise EvidenceError(
            "V2-AC-34/35 MCP governance runtime proof is not independently PASS"
        ) from exception

    _require_exact_keys(
        summary,
        {
            "schemaVersion", "acceptanceIds", "status", "candidate", "runtime",
            "sessionLifecycle", "rateLimiting", "shutdown", "sources",
        },
        "MCP governance summary",
    )
    if (
        summary.get("schemaVersion") != 1
        or summary.get("acceptanceIds") != ["V2-AC-34", "V2-AC-35"]
        or summary.get("status") != "PASS"
    ):
        raise EvidenceError("MCP governance summary is not the exact AC-34/35 PASS contract")
    candidate = _require_object(summary.get("candidate"), "MCP governance candidate binding")
    _require_exact_keys(
        candidate,
        {"commit", "tree", "version", "tag"},
        "MCP governance candidate binding",
    )
    if (
        candidate.get("commit") != commit
        or candidate.get("version") != version
        or candidate.get("tag") != tag
        or not isinstance(candidate.get("tree"), str)
        or COMMIT.fullmatch(candidate["tree"]) is None
    ):
        raise EvidenceError("MCP governance candidate identity differs from this release")
    runtime = _require_object(summary.get("runtime"), "MCP governance runtime binding")
    if (
        runtime.get("composeProject") != compose_project
        or runtime.get("tracePrefix") != MCP_GOVERNANCE_TRACE_PREFIX
    ):
        raise EvidenceError("MCP governance runtime identity differs from release acceptance")

    public_payload = _read_private_fixed_file(
        artifact,
        mcp_governance_proof.MAX_PROOF_BYTES,
        "MCP governance canonical summary",
    )
    if public_payload != expected_payload:
        raise EvidenceError(
            "MCP governance canonical summary differs byte-for-byte from recomputed raw evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_mcp_tool_contract_runtime_proof(
    *,
    proof_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    runtime_binding: dict[str, str],
) -> dict[str, str] | None:
    if proof_path is None and artifact_path is None:
        return None
    if proof_path is None or artifact_path is None:
        raise EvidenceError(
            "MCP Tool contract verification requires both the private raw proof and canonical summary"
        )
    try:
        summary = mcp_tool_contract_proof.validate_proof(
            proof_path,
            repository_root=repository_root,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            expected_compose_project=runtime_binding["composeProject"],
            expected_trace_prefix=MCP_TOOL_CONTRACT_TRACE_PREFIX,
            require_pass=True,
        )
        expected_payload = mcp_tool_contract_proof.canonical_summary_bytes(summary)
    except (OSError, mcp_tool_contract_proof.ProofValidationError) as exception:
        raise EvidenceError(
            "V2-AC-33 MCP Tool contract proof is not independently PASS"
        ) from exception
    expected_summary = {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-33",
        "status": "PASS",
    }
    if any(summary.get(key) != value for key, value in expected_summary.items()):
        raise EvidenceError("V2-AC-33 MCP Tool contract summary is not exact PASS")
    candidate = _require_object(
        summary.get("candidate"), "V2-AC-33 MCP Tool contract candidate binding"
    )
    if (
        set(candidate) != {"commit", "tree", "version", "tag"}
        or candidate.get("commit") != commit
        or not isinstance(candidate.get("tree"), str)
        or COMMIT.fullmatch(candidate["tree"]) is None
        or candidate.get("version") != version
        or candidate.get("tag") != tag
    ):
        raise EvidenceError("V2-AC-33 MCP Tool contract candidate binding differs")
    if summary.get("runtime") != {
        "composeProject": runtime_binding["composeProject"],
        "tracePrefix": MCP_TOOL_CONTRACT_TRACE_PREFIX,
    }:
        raise EvidenceError("V2-AC-33 MCP Tool contract runtime binding differs")

    artifact = _safe_file(
        artifact_path, artifacts_root, "V2-AC-33 MCP Tool contract canonical summary"
    )
    if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
        raise EvidenceError("MCP Tool contract canonical summary must have mode 0600")
    if artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "MCP Tool contract canonical summary differs from the independently validated proof"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_jwks_rotation_evidence(
    *,
    evidence_path: Path | None,
    artifact_path: Path | None,
    runtime_identity_path: Path,
    repository_root: Path,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    runtime_images: dict[str, dict[str, str]],
    compose_project: str | None,
    terminal_mode: str | None,
) -> dict[str, str] | None:
    supplied = (evidence_path, artifact_path, compose_project, terminal_mode)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "JWKS rotation verification requires the private raw report, canonical summary, "
            "isolated Compose project, and terminal mode"
        )
    assert evidence_path is not None
    assert artifact_path is not None
    assert compose_project is not None
    assert terminal_mode is not None
    identity = _safe_file(
        runtime_identity_path, artifacts_root, "runtime version identity for V2-AC-26"
    )
    try:
        summary = jwks_rotation_evidence.validate_evidence(
            evidence_path,
            repository_root,
            identity,
            expected_candidate_commit=commit,
            expected_candidate_version=version,
            expected_candidate_tag=tag,
            expected_compose_project=compose_project,
            expected_app_reference=runtime_images["app"]["reference"],
            expected_app_image_id=runtime_images["app"]["imageId"],
            expected_nginx_reference=runtime_images["nginx"]["reference"],
            expected_nginx_image_id=runtime_images["nginx"]["imageId"],
            expected_public_origin=JWKS_ROTATION_PUBLIC_ORIGIN,
            expected_private_origin=JWKS_ROTATION_PRIVATE_ORIGIN,
            expected_trace_prefix=JWKS_ROTATION_TRACE_PREFIX,
            expected_terminal_mode=terminal_mode,
            require_pass=True,
        )
    except (OSError, jwks_rotation_evidence.EvidenceValidationError) as exception:
        raise EvidenceError(
            "V2-AC-26 JWKS rotation evidence is not independently PASS"
        ) from exception

    _require_exact_keys(
        summary,
        {
            "schemaVersion", "acceptanceId", "status", "candidate", "runtime",
            "rotation", "checks", "evidence",
        },
        "V2-AC-26 JWKS rotation summary",
    )
    if (
        summary.get("schemaVersion") != 1
        or summary.get("acceptanceId") != "V2-AC-26"
        or summary.get("status") != "PASS"
    ):
        raise EvidenceError("V2-AC-26 JWKS rotation summary is not exact PASS")
    if summary.get("candidate") != {"commit": commit, "tag": tag, "version": version}:
        raise EvidenceError("V2-AC-26 JWKS rotation candidate binding differs")
    expected_runtime = {
        "composeProject": compose_project,
        "appReference": runtime_images["app"]["reference"],
        "appImageId": runtime_images["app"]["imageId"],
        "nginxReference": runtime_images["nginx"]["reference"],
        "nginxImageId": runtime_images["nginx"]["imageId"],
        "publicOriginSha256": hashlib.sha256(
            JWKS_ROTATION_PUBLIC_ORIGIN.encode("utf-8")
        ).hexdigest(),
        "privateOriginSha256": hashlib.sha256(
            JWKS_ROTATION_PRIVATE_ORIGIN.encode("utf-8")
        ).hexdigest(),
        "publicPort": 28443,
        "privatePort": 28088,
        "tracePrefix": JWKS_ROTATION_TRACE_PREFIX,
    }
    if summary.get("runtime") != expected_runtime:
        raise EvidenceError("V2-AC-26 JWKS rotation runtime binding differs")
    rotation = _require_object(summary.get("rotation"), "V2-AC-26 rotation binding")
    _require_exact_keys(
        rotation,
        {"oldKid", "newKid", "terminalMode", "retainUntilEpochSeconds"},
        "V2-AC-26 rotation binding",
    )
    if (
        rotation.get("terminalMode") != terminal_mode
        or not isinstance(rotation.get("oldKid"), str)
        or not isinstance(rotation.get("newKid"), str)
        or rotation.get("oldKid") == rotation.get("newKid")
        or isinstance(rotation.get("retainUntilEpochSeconds"), bool)
        or not isinstance(rotation.get("retainUntilEpochSeconds"), int)
        or rotation["retainUntilEpochSeconds"] <= 0
    ):
        raise EvidenceError("V2-AC-26 rotation mode or key binding differs")
    expected_checks = {
        "realOAuthIssuance": "PASS",
        "activeAndRetiringJwks": "PASS",
        "newCredentialUsesActiveKid": "PASS",
        "oldCredentialWithinWindowMcp": "PASS",
        "oldCredentialTerminalRejection": "PASS",
        "newCredentialContinuity": "PASS",
        "traceAuditCorrelation": "PASS",
        "privateMaterialNotPersisted": "PASS",
        "unknownKidRuntime": "NOT_COVERED",
        "invalidActiveRuntime": "NOT_COVERED",
    }
    if summary.get("checks") != expected_checks:
        raise EvidenceError("V2-AC-26 JWKS rotation checks differ from the fixed contract")
    evidence = _require_object(summary.get("evidence"), "V2-AC-26 evidence binding")
    _require_exact_keys(
        evidence,
        {"reportSha256", "runtimeIdentitySha256", "sourceSha256"},
        "V2-AC-26 evidence binding",
    )
    expected_payload = (
        json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    artifact = _safe_file(
        artifact_path, artifacts_root, "V2-AC-26 JWKS rotation canonical summary"
    )
    if artifact.name != jwks_rotation_evidence.SUMMARY_NAME:
        raise EvidenceError("V2-AC-26 canonical summary has an unexpected file name")
    if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
        raise EvidenceError("V2-AC-26 canonical summary must have mode 0600")
    if artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "V2-AC-26 canonical summary differs from independently recomputed evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_generator_acceptance_evidence(
    *,
    bundle_path: Path | None,
    forbidden_terms_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    release_repository_root: Path,
    artifacts_root: Path,
) -> dict[str, str] | None:
    supplied = (bundle_path, forbidden_terms_path, artifact_path)
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise EvidenceError(
            "generator acceptance verification requires the private raw bundle, "
            "external forbidden terms, and canonical public summary"
        )
    assert bundle_path is not None
    assert forbidden_terms_path is not None
    assert artifact_path is not None
    candidate_repository = repository_root.resolve()
    release_repository = release_repository_root.resolve()
    for external_path, label in (
        (bundle_path, "generator raw bundle"),
        (forbidden_terms_path, "generator forbidden terms"),
    ):
        requested = external_path.expanduser().absolute()
        if requested.is_symlink():
            raise EvidenceError(f"{label} must not be a symbolic link")
        try:
            resolved = requested.resolve(strict=True)
        except (OSError, RuntimeError) as exception:
            raise EvidenceError(f"{label} is missing") from exception
        if _is_inside(resolved, candidate_repository) or _is_inside(
            resolved, release_repository
        ):
            raise EvidenceError(f"{label} must remain outside both repository worktrees")
        if external_path is forbidden_terms_path:
            metadata = requested.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise EvidenceError("generator forbidden terms must be a regular mode 0600 file")
    try:
        summary = generator_acceptance_evidence.validate_bundle(
            bundle_path,
            repository_root=candidate_repository,
            forbidden_terms=forbidden_terms_path,
            require_pass=True,
        )
    except (
        generator_acceptance_evidence.GeneratorEvidenceError,
        OSError,
        UnicodeError,
        ValueError,
    ) as exception:
        raise EvidenceError(
            "V2-AC-08..15 generator acceptance evidence is not independently PASS"
        ) from exception
    expected_ids = [f"V2-AC-{number:02d}" for number in range(8, 16)]
    if (
        summary.get("schemaVersion") != 1
        or summary.get("status") != "PASS"
        or summary.get("acceptanceIds") != expected_ids
        or summary.get("coverage") != {
            acceptance_id: "PASS" for acceptance_id in expected_ids
        }
    ):
        raise EvidenceError("V2-AC-08..15 generator acceptance summary is not exact PASS")

    artifact = _safe_file(
        artifact_path,
        artifacts_root,
        "V2-AC-08..15 generator acceptance canonical summary",
    )
    if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
        raise EvidenceError("generator acceptance canonical summary must have mode 0600")
    expected_payload = (
        json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if artifact.read_bytes() != expected_payload:
        raise EvidenceError(
            "generator acceptance canonical summary differs from independently validated evidence"
        )
    return {
        "path": _relative(artifact, artifacts_root),
        "sha256": hashlib.sha256(expected_payload).hexdigest(),
        "status": "PASS",
    }


def _collect_production_fail_fast_evidence(
    *,
    evidence_path: Path | None,
    artifact_path: Path | None,
    repository_root: Path,
    artifacts_root: Path,
    runtime_images: dict[str, dict[str, str]],
    tag: str,
    commit: str,
) -> dict[str, str] | None:
    if evidence_path is None and artifact_path is None:
        return None
    if evidence_path is None or artifact_path is None:
        raise EvidenceError(
            "production fail-fast verification requires both original evidence and artifact copy"
        )
    try:
        result = production_fail_fast_evidence.validate_evidence(
            evidence_path,
            expected_app_reference=runtime_images["app"]["reference"],
            expected_app_image_id=runtime_images["app"]["imageId"],
            repository_root=repository_root,
            require_pass=True,
        )
    except production_fail_fast_evidence.EvidenceValidationError as exception:
        raise EvidenceError(
            "V2-AC-29 production fail-fast evidence is not independently PASS"
        ) from exception
    expected_result = {
        "acceptanceId": "V2-AC-29",
        "status": "PASS",
        "candidateHead": commit,
        "candidateTag": tag,
        "imageReference": runtime_images["app"]["reference"],
        "imageId": runtime_images["app"]["imageId"],
    }
    if any(result.get(key) != value for key, value in expected_result.items()):
        raise EvidenceError("V2-AC-29 production fail-fast evidence is not PASS")
    return _validated_public_copy(
        evidence_path,
        artifact_path,
        artifacts_root,
        "V2-AC-29 production fail-fast",
    )


def _collect_deployment_evidence(
    production_compose_path: Path,
    production_policy_path: Path,
    deployment_images_path: Path,
    artifacts_root: Path,
    repository_root: Path,
    images: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    compose_path = _safe_file(
        production_compose_path, artifacts_root, "expanded production Compose evidence"
    )
    compose = _require_object(
        _load_json(compose_path, "expanded production Compose evidence"),
        "expanded production Compose evidence",
    )
    compose_errors = compose_policy.validate_compose(compose)
    compose_errors.extend(compose_policy.validate_dockerfiles(repository_root))
    if compose_errors:
        raise EvidenceError(
            "expanded production Compose no longer passes policy: " + "; ".join(compose_errors)
        )
    services = _require_object(compose.get("services"), "expanded production Compose services")
    expected_images = {
        "app": images["app"]["reference"],
        "nginx": images["nginx"]["reference"],
        "mcp-public-nginx": images["nginx"]["reference"],
    }
    for service_name, expected_reference in expected_images.items():
        service = _require_object(
            services.get(service_name), f"expanded production Compose {service_name} service"
        )
        if service.get("image") != expected_reference:
            raise EvidenceError(
                f"expanded production Compose {service_name} does not use the scanned release digest"
            )

    policy_path = _safe_file(
        production_policy_path, artifacts_root, "production Compose policy summary"
    )
    policy = _require_object(
        _load_json(policy_path, "production Compose policy summary"),
        "production Compose policy summary",
    )
    if (
        policy.get("schemaVersion") != 1
        or policy.get("status") != "PASS"
        or policy.get("errors") != []
        or policy.get("composeSha256") != _sha256(compose_path)
    ):
        raise EvidenceError("production Compose policy summary is missing, failing, or checksum-drifted")

    deployment_path = _safe_file(
        deployment_images_path, artifacts_root, "deployment image environment"
    )
    expected_environment = {
        "WEB_STARTER_APP_IMAGE": images["app"]["reference"].rsplit("@", 1)[0],
        "WEB_STARTER_APP_DIGEST": images["app"]["digest"],
        "WEB_STARTER_NGINX_IMAGE": images["nginx"]["reference"].rsplit("@", 1)[0],
        "WEB_STARTER_NGINX_DIGEST": images["nginx"]["digest"],
    }
    actual_environment: dict[str, str] = {}
    try:
        lines = deployment_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exception:
        raise EvidenceError("deployment image environment cannot be read") from exception
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key in actual_environment:
            raise EvidenceError("deployment image environment has malformed or duplicate entries")
        actual_environment[key] = value
    if actual_environment != expected_environment:
        raise EvidenceError("deployment image environment is not exactly bound to release digests")

    dependency_references: dict[str, str] = {}
    for service_name in ("mysql", "redis"):
        service = _require_object(
            services.get(service_name), f"expanded production Compose {service_name} service"
        )
        reference = service.get("image")
        if not isinstance(reference, str) or re.fullmatch(
            r"[^\s@]+@sha256:[0-9a-f]{64}", reference
        ) is None:
            raise EvidenceError(
                f"expanded production Compose {service_name} image is not digest-bound"
            )
        dependency_references[service_name] = reference

    return ({
        "productionCompose": {
            "path": _relative(compose_path, artifacts_root),
            "sha256": _sha256(compose_path),
        },
        "productionComposePolicy": {
            "path": _relative(policy_path, artifacts_root),
            "sha256": _sha256(policy_path),
            "status": "PASS",
        },
        "deploymentImages": {
            "path": _relative(deployment_path, artifacts_root),
            "sha256": _sha256(deployment_path),
        },
    }, {
        "app": images["app"]["reference"],
        "nginx": images["nginx"]["reference"],
        **dependency_references,
    })


def _migration_version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _collect_flyway(repository_root: Path) -> dict[str, Any]:
    relative_directory = Path("web-starter-admin/src/main/resources/db/migration")
    directory = (repository_root / relative_directory).resolve()
    if not _is_inside(directory, repository_root.resolve()) or not directory.is_dir():
        raise EvidenceError("Flyway migration directory is missing")
    migrations: list[dict[str, str]] = []
    versions: set[str] = set()
    for candidate in sorted(directory.rglob("*.sql")):
        if candidate.parent != directory:
            raise EvidenceError(
                f"Flyway SQL must be a top-level versioned migration: {_relative(candidate, repository_root)}"
            )
        path = _safe_file(candidate, directory, f"Flyway migration {candidate.name}")
        match = MIGRATION_FILE.fullmatch(candidate.name)
        if match is None:
            raise EvidenceError(
                f"unsupported or unversioned Flyway SQL is forbidden: {candidate.name}"
            )
        version, description = match.groups()
        if version in versions:
            raise EvidenceError(f"Flyway migration version is duplicated: {version}")
        versions.add(version)
        migrations.append(
            {
                "version": version,
                "description": description,
                "path": _relative(path, repository_root),
                "sha256": _sha256(path),
            }
        )
    if not migrations:
        raise EvidenceError("Flyway migration list is empty")
    migrations.sort(key=lambda item: _migration_version_key(item["version"]))
    return {
        "directory": relative_directory.as_posix(),
        "latestVersion": migrations[-1]["version"],
        "migrations": migrations,
        "listSha256": _canonical_sha256(migrations),
    }


def _git_sql_paths(repository_root: Path, commit: str) -> set[str]:
    relative_directory = "web-starter-admin/src/main/resources/db/migration"
    output = _git(
        repository_root,
        "ls-tree",
        "-r",
        "--name-only",
        commit,
        "--",
        relative_directory,
    )
    return {line for line in output.splitlines() if line.endswith(".sql")}


def _verify_migration_inventory_binding(
    repository_root: Path,
    commit: str,
    flyway: dict[str, Any],
) -> None:
    current_paths = {migration["path"] for migration in flyway["migrations"]}
    tagged_paths = _git_sql_paths(repository_root, commit)
    if current_paths != tagged_paths:
        missing = sorted(tagged_paths - current_paths)
        uncommitted = sorted(current_paths - tagged_paths)
        details = []
        if missing:
            details.append("missing-from-worktree=" + ",".join(missing))
        if uncommitted:
            details.append("not-in-release-commit=" + ",".join(uncommitted))
        raise EvidenceError(
            "Flyway SQL inventory differs from the release commit (" + "; ".join(details) + ")"
        )


def _verify_historical_migration_bytes(
    repository_root: Path,
    baseline_commit: str,
    expected_paths: set[str],
    flyway: dict[str, Any],
) -> None:
    baseline_paths = _git_sql_paths(repository_root, baseline_commit)
    if baseline_paths != expected_paths:
        raise EvidenceError("frozen V1 migration inventory no longer matches its known path set")
    current_paths = {migration["path"] for migration in flyway["migrations"]}
    if not expected_paths.issubset(current_paths):
        missing = sorted(expected_paths - current_paths)
        raise EvidenceError("frozen V1 migrations were deleted: " + ",".join(missing))
    for relative in sorted(expected_paths):
        current = _safe_file(
            repository_root / relative,
            repository_root,
            f"frozen V1 migration {relative}",
        )
        baseline_bytes = _git_bytes(repository_root, "show", f"{baseline_commit}:{relative}")
        if hashlib.sha256(baseline_bytes).hexdigest() != _sha256(current):
            raise EvidenceError(f"frozen V1 migration bytes changed since {V1_BASELINE_TAG}: {relative}")


def _verify_v1_migration_anchor(
    repository_root: Path,
    release_commit: str,
    flyway: dict[str, Any],
) -> None:
    tag_ref = f"refs/tags/{V1_BASELINE_TAG}"
    if _git(repository_root, "cat-file", "-t", tag_ref) != "tag":
        raise EvidenceError("frozen V1 migration anchor must remain an annotated Git tag")
    actual_commit = _git(repository_root, "rev-parse", f"{tag_ref}^{{commit}}")
    if actual_commit != V1_BASELINE_COMMIT:
        raise EvidenceError("frozen V1 migration anchor tag resolves to an unexpected commit")
    ancestry = _run_git_bounded(
        repository_root,
        "merge-base",
        "--is-ancestor",
        V1_BASELINE_COMMIT,
        release_commit,
    )
    if ancestry.returncode == 1:
        raise EvidenceError("release commit is not a descendant of the frozen V1 baseline")
    if ancestry.returncode != 0:
        raise EvidenceError("unable to verify V1 release ancestry")
    _verify_historical_migration_bytes(
        repository_root,
        V1_BASELINE_COMMIT,
        V1_BASELINE_MIGRATIONS,
        flyway,
    )


def _project_versions(repository_root: Path, expected_version: str) -> tuple[dict[str, str], list[Path]]:
    pom_path = _safe_file(Path("pom.xml"), repository_root, "root Maven project")
    package_path = _safe_file(
        Path("web-starter-web/package.json"), repository_root, "frontend package manifest"
    )
    try:
        pom_root = ElementTree.parse(pom_path).getroot()
    except (OSError, ElementTree.ParseError) as exception:
        raise EvidenceError("root Maven POM is invalid") from exception
    namespace = ""
    if pom_root.tag.startswith("{"):
        namespace = pom_root.tag.split("}", 1)[0] + "}"
    version_element = pom_root.find(f"{namespace}version")
    maven_version = version_element.text.strip() if version_element is not None and version_element.text else ""
    package = _require_object(_load_json(package_path, "frontend package manifest"), "frontend package manifest")
    frontend_version = package.get("version")
    if maven_version != expected_version or frontend_version != expected_version:
        raise EvidenceError(
            "root Maven and frontend versions must exactly match the release version without SNAPSHOT"
        )
    return {"maven": maven_version, "frontend": frontend_version}, [pom_path, package_path]


def build_ledger(
    *,
    repository_root: Path,
    candidate_validation_root: Path | None = None,
    artifacts_root: Path,
    acceptance_source_path: Path,
    release_images_path: Path,
    security_summary_path: Path,
    production_compose_path: Path,
    production_policy_path: Path,
    deployment_images_path: Path,
    runtime_identity_path: Path,
    runtime_acceptance_path: Path,
    v1_source_provenance_proof_path: Path | None = None,
    v1_source_provenance_summary_artifact_path: Path | None = None,
    v1_operations_documentation_proof_path: Path | None = None,
    v1_operations_documentation_summary_artifact_path: Path | None = None,
    release_runtime_test_reports_directory_path: Path | None = None,
    release_runtime_test_reports_summary_artifact_path: Path | None = None,
    project_transport_parity_proof_path: Path | None = None,
    project_transport_parity_summary_artifact_path: Path | None = None,
    migration_failure_evidence_path: Path | None = None,
    migration_failure_ac40_evidence_path: Path | None = None,
    migration_failure_artifact_path: Path | None = None,
    v1_upgrade_evidence_path: Path | None = None,
    v1_upgrade_artifact_path: Path | None = None,
    ac40_dependency_seed_path: Path | None = None,
    expected_ac40_dependency_seed_sha256: str | None = None,
    ac40_dependency_seed_provenance_path: Path | None = None,
    redis_loss_evidence_path: Path | None = None,
    redis_loss_artifact_path: Path | None = None,
    mcp_crud_proof_path: Path | None = None,
    mcp_crud_summary_artifact_path: Path | None = None,
    credential_lifecycle_report_path: Path | None = None,
    credential_lifecycle_summary_artifact_path: Path | None = None,
    observability_baseline_path: Path | None = None,
    observability_runtime_path: Path | None = None,
    observability_summary_artifact_path: Path | None = None,
    tooling_lifecycle_report_path: Path | None = None,
    tooling_lifecycle_summary_artifact_path: Path | None = None,
    tooling_lifecycle_compose_project: str | None = None,
    mcp_governance_proof_path: Path | None = None,
    mcp_governance_summary_artifact_path: Path | None = None,
    mcp_governance_compose_project: str | None = None,
    jwks_rotation_evidence_path: Path | None = None,
    jwks_rotation_summary_artifact_path: Path | None = None,
    jwks_rotation_compose_project: str | None = None,
    jwks_rotation_terminal_mode: str | None = None,
    mcp_tool_contract_proof_path: Path | None = None,
    mcp_tool_contract_summary_artifact_path: Path | None = None,
    generator_acceptance_bundle_path: Path | None = None,
    generator_forbidden_terms_path: Path | None = None,
    generator_acceptance_artifact_path: Path | None = None,
    production_fail_fast_evidence_path: Path | None = None,
    production_fail_fast_artifact_path: Path | None = None,
    tag: str,
    version: str,
    commit: str,
    evaluated_at: datetime | None = None,
    verify_git: bool = True,
) -> dict[str, Any]:
    repository_root = repository_root.resolve()
    artifacts_root = artifacts_root.resolve()
    _validate_release_values(tag, version, commit)
    if candidate_validation_root is not None:
        candidate_validation_root = (
            _verify_strict_candidate_root(candidate_validation_root, tag, commit)
            if verify_git
            else candidate_validation_root.resolve()
        )
    else:
        candidate_validation_root = repository_root
    now = evaluated_at or datetime.now(timezone.utc).replace(microsecond=0)
    if now.tzinfo is None:
        raise EvidenceError("gate evaluation time must include a timezone")
    tag_object = _verify_git_binding(repository_root, tag, commit) if verify_git else commit
    baselines = _load_baselines(repository_root)

    acceptance_source_path = _safe_file(
        acceptance_source_path, repository_root, "acceptance evidence source"
    )
    acceptance_source = _load_json(acceptance_source_path, "acceptance evidence source")
    acceptance, blocking = _validate_acceptance_source(
        acceptance_source,
        baselines,
        tag,
        version,
        repository_root,
        artifacts_root,
        commit,
        verify_git,
    )
    images, sboms, supply_inputs = _collect_supply_chain(
        release_images_path,
        security_summary_path,
        artifacts_root,
        tag,
        version,
        commit,
        repository_root,
        now,
    )
    deployment_inputs, runtime_references = _collect_deployment_evidence(
        production_compose_path,
        production_policy_path,
        deployment_images_path,
        artifacts_root,
        repository_root,
        images,
    )
    runtime_identity_input, runtime_image_identities = _collect_runtime_identity(
        runtime_identity_path,
        artifacts_root,
        version,
        commit,
        images,
        runtime_references,
    )
    runtime_acceptance_input, unified_verify_input, runtime_binding = _collect_runtime_acceptance(
        runtime_acceptance_path, artifacts_root, tag, version, commit, images
    )
    v1_source_provenance_input = _collect_v1_source_provenance_proof(
        proof_path=v1_source_provenance_proof_path,
        artifact_path=v1_source_provenance_summary_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
    )
    v1_operations_documentation_input = _collect_v1_operations_documentation_proof(
        proof_path=v1_operations_documentation_proof_path,
        artifact_path=v1_operations_documentation_summary_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
    )
    release_runtime_test_reports_input = _collect_release_runtime_test_reports(
        evidence_directory=release_runtime_test_reports_directory_path,
        artifact_path=release_runtime_test_reports_summary_artifact_path,
        repository_root=candidate_validation_root,
        release_repository_root=repository_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
        tag_object=tag_object,
        verify_git=verify_git,
    )
    project_transport_parity_input = _collect_project_transport_parity_proof(
        proof_path=project_transport_parity_proof_path,
        artifact_path=project_transport_parity_summary_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
    )
    migration_failure_input = _collect_migration_failure_evidence(
        evidence_path=migration_failure_evidence_path,
        ac40_evidence_path=migration_failure_ac40_evidence_path,
        ac40_dependency_seed_path=ac40_dependency_seed_path,
        expected_ac40_dependency_seed_sha256=(
            expected_ac40_dependency_seed_sha256
        ),
        artifact_path=migration_failure_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        runtime_images=runtime_image_identities,
    )
    v1_upgrade_input, v1_upgrade_summary = _collect_v1_upgrade_evidence(
        evidence_path=v1_upgrade_evidence_path,
        artifact_path=v1_upgrade_artifact_path,
        dependency_seed_path=ac40_dependency_seed_path,
        expected_dependency_seed_sha256=expected_ac40_dependency_seed_sha256,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
    )
    ac40_dependency_seed_provenance_input = (
        _collect_ac40_dependency_seed_provenance(
            provenance_path=ac40_dependency_seed_provenance_path,
            artifacts_root=artifacts_root,
            commit=commit,
            v1_upgrade_summary=v1_upgrade_summary,
        )
    )
    redis_loss_input = _collect_redis_loss_evidence(
        evidence_path=redis_loss_evidence_path,
        artifact_path=redis_loss_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        runtime_images=runtime_image_identities,
    )
    mcp_crud_proof_input = _collect_mcp_crud_runtime_proof(
        proof_path=mcp_crud_proof_path,
        artifact_path=mcp_crud_summary_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
        runtime_binding=runtime_binding,
    )
    credential_lifecycle_input = _collect_credential_lifecycle_evidence(
        report_path=credential_lifecycle_report_path,
        artifact_path=credential_lifecycle_summary_artifact_path,
        repository_root=candidate_validation_root,
        release_repository_root=repository_root,
        artifacts_root=artifacts_root,
        runtime_identity_path=runtime_identity_path,
        compose_project=runtime_binding["composeProject"],
        tag=tag,
        version=version,
        commit=commit,
    )
    observability_input = _collect_observability_evidence(
        baseline_path=observability_baseline_path,
        runtime_path=observability_runtime_path,
        artifact_path=observability_summary_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        runtime_identity_path=runtime_identity_path,
        compose_project=runtime_binding["composeProject"],
        tag=tag,
        version=version,
        commit=commit,
    )
    tooling_lifecycle_input = _collect_tooling_lifecycle_evidence(
        report_path=tooling_lifecycle_report_path,
        artifact_path=tooling_lifecycle_summary_artifact_path,
        repository_root=candidate_validation_root,
        release_repository_root=repository_root,
        artifacts_root=artifacts_root,
        runtime_identity_path=runtime_identity_path,
        compose_project=tooling_lifecycle_compose_project,
        tag=tag,
        version=version,
        commit=commit,
    )
    mcp_governance_input = _collect_mcp_governance_runtime_proof(
        proof_path=mcp_governance_proof_path,
        artifact_path=mcp_governance_summary_artifact_path,
        repository_root=candidate_validation_root,
        release_repository_root=repository_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
        runtime_binding=runtime_binding,
        runtime_images=runtime_image_identities,
        compose_project=mcp_governance_compose_project,
        ac26_compose_project=jwks_rotation_compose_project,
    )
    jwks_rotation_input = _collect_jwks_rotation_evidence(
        evidence_path=jwks_rotation_evidence_path,
        artifact_path=jwks_rotation_summary_artifact_path,
        runtime_identity_path=runtime_identity_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
        runtime_images=runtime_image_identities,
        compose_project=jwks_rotation_compose_project,
        terminal_mode=jwks_rotation_terminal_mode,
    )
    mcp_tool_contract_input = _collect_mcp_tool_contract_runtime_proof(
        proof_path=mcp_tool_contract_proof_path,
        artifact_path=mcp_tool_contract_summary_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        tag=tag,
        version=version,
        commit=commit,
        runtime_binding=runtime_binding,
    )
    generator_acceptance_input = _collect_generator_acceptance_evidence(
        bundle_path=generator_acceptance_bundle_path,
        forbidden_terms_path=generator_forbidden_terms_path,
        artifact_path=generator_acceptance_artifact_path,
        repository_root=candidate_validation_root,
        release_repository_root=repository_root,
        artifacts_root=artifacts_root,
    )
    production_fail_fast_input = _collect_production_fail_fast_evidence(
        evidence_path=production_fail_fast_evidence_path,
        artifact_path=production_fail_fast_artifact_path,
        repository_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        runtime_images=runtime_image_identities,
        tag=tag,
        commit=commit,
    )
    flyway = _collect_flyway(repository_root)
    project_versions, version_files = _project_versions(repository_root, version)
    verified_inputs = {
        **supply_inputs,
        **deployment_inputs,
        "runtimeVersionIdentity": runtime_identity_input,
        "releaseRuntimeAcceptance": runtime_acceptance_input,
        "unifiedVerify": unified_verify_input,
    }
    if v1_source_provenance_input is not None:
        verified_inputs["v1SourceProvenanceSummary"] = v1_source_provenance_input
    if v1_operations_documentation_input is not None:
        verified_inputs["v1OperationsDocumentationSummary"] = (
            v1_operations_documentation_input
        )
    if release_runtime_test_reports_input is not None:
        verified_inputs["releaseRuntimeTestReports"] = release_runtime_test_reports_input
    if project_transport_parity_input is not None:
        verified_inputs["v1ProjectTransportParitySummary"] = (
            project_transport_parity_input
        )
    if migration_failure_input is not None:
        verified_inputs["migrationFailureRehearsal"] = migration_failure_input
    if v1_upgrade_input is not None:
        verified_inputs["v1UpgradeRehearsal"] = v1_upgrade_input
    if ac40_dependency_seed_provenance_input is not None:
        verified_inputs["ac40DependencySeedProvenance"] = (
            ac40_dependency_seed_provenance_input
        )
    if redis_loss_input is not None:
        verified_inputs["redisLossRehearsal"] = redis_loss_input
    if mcp_crud_proof_input is not None:
        verified_inputs["mcpCrudRuntimeProofSummary"] = mcp_crud_proof_input
    if credential_lifecycle_input is not None:
        verified_inputs["credentialLifecycleSummary"] = credential_lifecycle_input
    if observability_input is not None:
        verified_inputs["observabilitySummary"] = observability_input
    if tooling_lifecycle_input is not None:
        verified_inputs["toolingLifecycleSummary"] = tooling_lifecycle_input
    if mcp_governance_input is not None:
        verified_inputs["mcpGovernanceRuntimeSummary"] = mcp_governance_input
    if jwks_rotation_input is not None:
        verified_inputs["jwksRotationSummary"] = jwks_rotation_input
    if mcp_tool_contract_input is not None:
        verified_inputs["mcpToolContractSummary"] = mcp_tool_contract_input
    if generator_acceptance_input is not None:
        verified_inputs["generatorAcceptanceSummary"] = generator_acceptance_input
    if production_fail_fast_input is not None:
        verified_inputs["productionFailFastRehearsal"] = production_fail_fast_input
    _bind_independently_verified_acceptance(acceptance, verified_inputs)
    if verify_git:
        _verify_migration_inventory_binding(repository_root, commit, flyway)
        _verify_v1_migration_anchor(repository_root, commit, flyway)
        _verify_repository_file_binding(repository_root, commit, acceptance_source_path)
        policy_source_files = [
            repository_root / ".github/workflows/release-supply-chain.yml",
            repository_root / ".github/workflows/build-ac40-dependency-seed.yml",
            repository_root / "compose.production.yaml",
            repository_root / "Dockerfile",
            repository_root / "deploy/nginx/Dockerfile",
            repository_root / "deploy/nginx/nginx.conf",
            repository_root / "deploy/nginx/nginx-public.conf",
            repository_root / "scripts/production_compose_policy.py",
            repository_root / "scripts/release_evidence_gate.py",
            repository_root / "scripts/repository_policy.py",
            repository_root / "scripts/create_v1_operations_documentation_proof.py",
            repository_root / "scripts/validate_v1_operations_documentation_proof.py",
            repository_root / "security/v1-ac38-operations-documentation-summary.schema.json",
            repository_root / "scripts/release_security_gate.py",
            repository_root / "scripts/release_trivy.py",
            repository_root / "scripts/build_v1_upgrade_dependency_seed.py",
            repository_root / "scripts/prepare_release_runtime_acceptance.py",
            repository_root / "scripts/acceptance_jwk_set.py",
            repository_root / "scripts/verify_oauth_runtime.py",
            repository_root / "scripts/verify_runtime_identity.py",
            repository_root / "scripts/sanitize_compose_status.py",
            repository_root / "scripts/run_release_runtime_acceptance.sh",
            repository_root / "scripts/rehearse_migration_failure.py",
            repository_root / "scripts/validate_migration_failure_evidence.py",
            repository_root / "scripts/rehearse_redis_loss.py",
            repository_root / "scripts/validate_redis_loss_evidence.py",
            repository_root / "scripts/create_mcp_crud_runtime_proof.py",
            repository_root / "scripts/validate_mcp_crud_runtime_proof.py",
            repository_root / "bin/web-starter",
            repository_root / "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/DeveloperCommands.java",
            repository_root / "scripts/acceptance_network.py",
            repository_root / "scripts/generated_module_plan.py",
            repository_root / "scripts/prepare_mcp_governance_runtime.py",
            repository_root / "scripts/v1_upgrade_refresh.py",
            repository_root / "scripts/run_mcp_governance_runtime_acceptance.sh",
            repository_root / "scripts/create_mcp_governance_runtime_proof.py",
            repository_root / "scripts/validate_mcp_governance_runtime_proof.py",
            repository_root / "scripts/orchestrate_mcp_governance_restart.py",
            repository_root / "scripts/rehearse_jwks_rotation.py",
            repository_root / "scripts/validate_jwks_rotation_evidence.py",
            repository_root / "scripts/create_mcp_tool_contract_runtime_proof.py",
            repository_root / "scripts/validate_mcp_tool_contract_runtime_proof.py",
            repository_root / "scripts/rehearse_generator_acceptance.py",
            repository_root / "scripts/validate_generator_acceptance_evidence.py",
            repository_root / "scripts/rehearse_production_fail_fast.py",
            repository_root / "scripts/validate_production_fail_fast_evidence.py",
            repository_root / "scripts/recovery_common.py",
            repository_root / "scripts/rehearse_v1_to_v2_upgrade.py",
            repository_root / "scripts/validate_v1_upgrade_evidence.py",
            repository_root / "scripts/create_v1_source_provenance_proof.py",
            repository_root / "scripts/validate_v1_source_provenance_proof.py",
            repository_root / "scripts/create_release_runtime_test_reports_proof.py",
            repository_root / "scripts/validate_release_runtime_test_reports_proof.py",
            repository_root / "scripts/create_project_transport_parity_proof.py",
            repository_root / "scripts/validate_project_transport_parity_proof.py",
            repository_root / "scripts/rehearse_credential_lifecycle.py",
            repository_root / "scripts/validate_credential_lifecycle_evidence.py",
            repository_root / "scripts/verify_operational_metrics.py",
            repository_root / "scripts/validate_observability_evidence.py",
            repository_root / "scripts/rehearse_tooling_lifecycle.py",
            repository_root / "scripts/validate_tooling_lifecycle_evidence.py",
            repository_root / "web-starter-web/playwright.config.ts",
            repository_root / "web-starter-web/e2e/release-runtime.spec.ts",
            repository_root / "web-starter-web/package.json",
            repository_root / "web-starter-web/pnpm-lock.yaml",
            repository_root / "security/high-vulnerability-exceptions.json",
            repository_root / "security/release-acceptance-input.schema.json",
            repository_root / "security/release-evidence.schema.json",
            repository_root / "security/v2-ac01-v1-source-provenance-summary.schema.json",
            repository_root / "security/release-runtime-test-reports-summary.schema.json",
            repository_root / "security/v1-ac15-project-transport-parity-summary.schema.json",
            repository_root / "security/v1-ac16-v2-ac31-ac32-mcp-crud-summary.schema.json",
            repository_root / "security/v2-ac07-migration-failure.schema.json",
            repository_root / "security/v2-ac41-redis-loss.schema.json",
            repository_root / "security/v2-ac29-production-fail-fast.schema.json",
            repository_root / "security/v2-ac26-jwks-rotation.schema.json",
            repository_root / "security/v2-ac33-mcp-tool-contract-summary.schema.json",
            repository_root / "security/v2-ac34-ac35-mcp-governance-summary.schema.json",
            repository_root / "security/v2-credential-lifecycle-runtime-summary.schema.json",
            repository_root / "security/v2-observability-runtime-summary.schema.json",
            repository_root / "security/v2-tooling-lifecycle-runtime-summary.schema.json",
            repository_root / "security/v2-generator-acceptance.schema.json",
            repository_root / "security/v2-v1-upgrade-rehearsal.schema.json",
            repository_root / "security/trivy-release.ignore",
            repository_root / "security/trivy-release.yaml",
            repository_root / "security/trivy-secret-release.yaml",
            repository_root / "web-starter-admin/src/test/java/dev/webstarter/admin/acceptance/ProjectTransportParityIT.java",
        ]
        for bound_file in [*version_files, *policy_source_files]:
            _verify_repository_file_binding(repository_root, commit, bound_file)
        for suite in ("v1", "v2"):
            _verify_repository_file_binding(
                repository_root,
                commit,
                repository_root / acceptance[suite]["baseline"]["path"],
            )
        for migration in flyway["migrations"]:
            _verify_repository_file_binding(
                repository_root,
                commit,
                repository_root / migration["path"],
            )

    evaluated = now.isoformat()
    ac45_status = "PASS" if not blocking else "FAIL"
    acceptance["v2"]["results"].append(
        {
            "id": SELF_OWNED_ACCEPTANCE_ID,
            "level": baselines["v2"]["rows"][SELF_OWNED_ACCEPTANCE_ID],
            "status": ac45_status,
            "observedAt": evaluated,
            "evidenceTrust": "GATE_DERIVED",
            "evidence": [
                "release_evidence_gate.py verified the annotated Git tag, commit, image digests, "
                "SBOM checksums, production Compose, deployment inputs, Flyway checksums and "
                "complete V1/V2 result set"
            ],
        }
    )
    acceptance["v2"]["results"].sort(key=lambda item: item["id"])

    for suite in ("v1", "v2"):
        results = acceptance[suite]["results"]
        counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
        levels = {"P0": 0, "P1": 0}
        for result in results:
            counts[result["status"]] += 1
            levels[result["level"]] += 1
        acceptance[suite]["counts"] = {
            "total": len(results),
            "levels": levels,
            "statuses": counts,
        }

    acceptance_input = {
        "path": _relative(acceptance_source_path, repository_root),
        "sha256": _sha256(acceptance_source_path),
    }
    return {
        "schemaVersion": 1,
        "release": {
            "tag": tag,
            "version": version,
            "gitCommit": commit,
            "gitTagObject": tag_object,
            "projectVersions": project_versions,
        },
        "images": images,
        "sboms": sboms,
        "flyway": flyway,
        "inputs": {
            "acceptanceResults": acceptance_input,
            **verified_inputs,
        },
        "acceptance": acceptance,
        "gate": {
            "status": "PASS" if not blocking else "FAIL",
            "evaluatedAt": evaluated,
            "errors": blocking,
        },
    }


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _parse_evaluated_at(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("release evidence gate timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exception:
        raise EvidenceError("release evidence gate timestamp is invalid") from exception
    if parsed.tzinfo is None:
        raise EvidenceError("release evidence gate timestamp lacks timezone")
    return parsed


def verify_ledger(
    *,
    manifest_path: Path,
    repository_root: Path,
    candidate_validation_root: Path | None = None,
    artifacts_root: Path,
    tag: str,
    version: str,
    commit: str,
    v1_source_provenance_proof_path: Path | None = None,
    v1_operations_documentation_proof_path: Path | None = None,
    release_runtime_test_reports_directory_path: Path | None = None,
    project_transport_parity_proof_path: Path | None = None,
    migration_failure_evidence_path: Path | None = None,
    migration_failure_ac40_evidence_path: Path | None = None,
    v1_upgrade_evidence_path: Path | None = None,
    ac40_dependency_seed_path: Path | None = None,
    expected_ac40_dependency_seed_sha256: str | None = None,
    ac40_dependency_seed_provenance_path: Path | None = None,
    redis_loss_evidence_path: Path | None = None,
    mcp_crud_proof_path: Path | None = None,
    credential_lifecycle_report_path: Path | None = None,
    observability_baseline_path: Path | None = None,
    observability_runtime_path: Path | None = None,
    tooling_lifecycle_report_path: Path | None = None,
    tooling_lifecycle_compose_project: str | None = None,
    mcp_governance_proof_path: Path | None = None,
    mcp_governance_compose_project: str | None = None,
    jwks_rotation_evidence_path: Path | None = None,
    jwks_rotation_compose_project: str | None = None,
    jwks_rotation_terminal_mode: str | None = None,
    mcp_tool_contract_proof_path: Path | None = None,
    generator_acceptance_bundle_path: Path | None = None,
    generator_forbidden_terms_path: Path | None = None,
    production_fail_fast_evidence_path: Path | None = None,
    verify_git: bool = True,
) -> dict[str, Any]:
    manifest_path = _safe_file(manifest_path, artifacts_root, "release evidence manifest")
    actual = _require_object(_load_json(manifest_path, "release evidence manifest"), "release evidence manifest")
    if actual.get("schemaVersion") != 1:
        raise EvidenceError("release evidence manifest must use schemaVersion 1")
    inputs = _require_object(actual.get("inputs"), "release evidence inputs")
    acceptance_input = _require_object(inputs.get("acceptanceResults"), "acceptance results input")
    release_images_input = _require_object(inputs.get("releaseImages"), "release image input")
    security_input = _require_object(inputs.get("securityGate"), "security gate input")
    compose_input = _require_object(inputs.get("productionCompose"), "production Compose input")
    compose_policy_input = _require_object(
        inputs.get("productionComposePolicy"), "production Compose policy input"
    )
    deployment_input = _require_object(inputs.get("deploymentImages"), "deployment image input")
    runtime_acceptance_input = _require_object(
        inputs.get("releaseRuntimeAcceptance"), "release runtime acceptance input"
    )
    runtime_identity_input = _require_object(
        inputs.get("runtimeVersionIdentity"), "runtime version identity input"
    )
    v1_source_provenance_input = inputs.get("v1SourceProvenanceSummary")
    if v1_source_provenance_input is not None:
        v1_source_provenance_input = _require_object(
            v1_source_provenance_input, "V1 source provenance summary input"
        )
    v1_operations_documentation_input = inputs.get(
        "v1OperationsDocumentationSummary"
    )
    if v1_operations_documentation_proof_path is not None:
        v1_operations_documentation_input = _require_object(
            v1_operations_documentation_input,
            "V1 AC-38 operations documentation summary input",
        )
    elif v1_operations_documentation_input is not None:
        raise EvidenceError(
            "V1 AC-38 operations documentation proof must be explicitly supplied "
            "for verification"
        )
    release_runtime_test_reports_input = inputs.get("releaseRuntimeTestReports")
    if release_runtime_test_reports_input is not None:
        release_runtime_test_reports_input = _require_object(
            release_runtime_test_reports_input,
            "release runtime test reports summary input",
        )
    project_transport_parity_input = inputs.get("v1ProjectTransportParitySummary")
    if project_transport_parity_proof_path is not None:
        project_transport_parity_input = _require_object(
            project_transport_parity_input,
            "V1 AC-15 Project transport-parity summary input",
        )
    elif project_transport_parity_input is not None:
        raise EvidenceError(
            "V1 AC-15 Project transport-parity proof must be explicitly supplied "
            "for verification"
        )
    migration_failure_input = inputs.get("migrationFailureRehearsal")
    if migration_failure_input is not None:
        migration_failure_input = _require_object(
            migration_failure_input, "migration-failure rehearsal input"
        )
    v1_upgrade_input = inputs.get("v1UpgradeRehearsal")
    if v1_upgrade_input is not None:
        v1_upgrade_input = _require_object(v1_upgrade_input, "V1 upgrade rehearsal input")
    ac40_dependency_seed_provenance_input = inputs.get(
        "ac40DependencySeedProvenance"
    )
    if ac40_dependency_seed_provenance_path is not None:
        ac40_dependency_seed_provenance_input = _require_object(
            ac40_dependency_seed_provenance_input,
            "AC40 dependency-seed provenance input",
        )
    elif ac40_dependency_seed_provenance_input is not None:
        raise EvidenceError(
            "AC40 dependency-seed provenance must be explicitly supplied for verification"
        )
    redis_loss_input = inputs.get("redisLossRehearsal")
    if redis_loss_input is not None:
        redis_loss_input = _require_object(redis_loss_input, "Redis-loss rehearsal input")
    mcp_crud_proof_input = inputs.get("mcpCrudRuntimeProofSummary")
    if mcp_crud_proof_input is not None:
        mcp_crud_proof_input = _require_object(
            mcp_crud_proof_input, "MCP CRUD runtime proof summary input"
        )
    credential_lifecycle_input = inputs.get("credentialLifecycleSummary")
    if credential_lifecycle_input is not None:
        credential_lifecycle_input = _require_object(
            credential_lifecycle_input, "credential lifecycle summary input"
        )
    observability_input = inputs.get("observabilitySummary")
    if observability_input is not None:
        observability_input = _require_object(
            observability_input, "observability summary input"
        )
    tooling_lifecycle_input = inputs.get("toolingLifecycleSummary")
    if tooling_lifecycle_input is not None:
        tooling_lifecycle_input = _require_object(
            tooling_lifecycle_input, "tooling lifecycle summary input"
        )
    mcp_governance_input = inputs.get("mcpGovernanceRuntimeSummary")
    if mcp_governance_input is not None:
        mcp_governance_input = _require_object(
            mcp_governance_input, "MCP governance runtime summary input"
        )
    jwks_rotation_input = inputs.get("jwksRotationSummary")
    if jwks_rotation_input is not None:
        jwks_rotation_input = _require_object(
            jwks_rotation_input, "JWKS rotation summary input"
        )
    mcp_tool_contract_input = inputs.get("mcpToolContractSummary")
    if mcp_tool_contract_input is not None:
        mcp_tool_contract_input = _require_object(
            mcp_tool_contract_input, "MCP Tool contract summary input"
        )
    generator_acceptance_input = inputs.get("generatorAcceptanceSummary")
    if generator_acceptance_input is not None:
        generator_acceptance_input = _require_object(
            generator_acceptance_input, "generator acceptance summary input"
        )
    production_fail_fast_input = inputs.get("productionFailFastRehearsal")
    if production_fail_fast_input is not None:
        production_fail_fast_input = _require_object(
            production_fail_fast_input, "production fail-fast rehearsal input"
        )
    _require_object(inputs.get("unifiedVerify"), "unified verify input")
    gate = _require_object(actual.get("gate"), "release evidence gate")
    expected = build_ledger(
        repository_root=repository_root,
        candidate_validation_root=candidate_validation_root,
        artifacts_root=artifacts_root,
        acceptance_source_path=Path(str(acceptance_input.get("path", ""))),
        release_images_path=Path(str(release_images_input.get("path", ""))),
        security_summary_path=Path(str(security_input.get("path", ""))),
        production_compose_path=Path(str(compose_input.get("path", ""))),
        production_policy_path=Path(str(compose_policy_input.get("path", ""))),
        deployment_images_path=Path(str(deployment_input.get("path", ""))),
        runtime_identity_path=Path(str(runtime_identity_input.get("path", ""))),
        runtime_acceptance_path=Path(str(runtime_acceptance_input.get("path", ""))),
        v1_source_provenance_proof_path=v1_source_provenance_proof_path,
        v1_source_provenance_summary_artifact_path=(
            Path(str(v1_source_provenance_input.get("path", "")))
            if v1_source_provenance_input is not None
            else None
        ),
        v1_operations_documentation_proof_path=(
            v1_operations_documentation_proof_path
        ),
        v1_operations_documentation_summary_artifact_path=(
            Path(str(v1_operations_documentation_input.get("path", "")))
            if v1_operations_documentation_input is not None
            else None
        ),
        release_runtime_test_reports_directory_path=(
            release_runtime_test_reports_directory_path
        ),
        release_runtime_test_reports_summary_artifact_path=(
            Path(str(release_runtime_test_reports_input.get("path", "")))
            if release_runtime_test_reports_input is not None
            else None
        ),
        project_transport_parity_proof_path=project_transport_parity_proof_path,
        project_transport_parity_summary_artifact_path=(
            Path(str(project_transport_parity_input.get("path", "")))
            if project_transport_parity_input is not None
            else None
        ),
        migration_failure_evidence_path=migration_failure_evidence_path,
        migration_failure_ac40_evidence_path=migration_failure_ac40_evidence_path,
        migration_failure_artifact_path=(
            Path(str(migration_failure_input.get("path", "")))
            if migration_failure_input is not None
            else None
        ),
        v1_upgrade_evidence_path=v1_upgrade_evidence_path,
        v1_upgrade_artifact_path=(
            Path(str(v1_upgrade_input.get("path", "")))
            if v1_upgrade_input is not None
            else None
        ),
        ac40_dependency_seed_provenance_path=(
            ac40_dependency_seed_provenance_path
            if ac40_dependency_seed_provenance_input is not None
            else None
        ),
        ac40_dependency_seed_path=ac40_dependency_seed_path,
        expected_ac40_dependency_seed_sha256=(
            expected_ac40_dependency_seed_sha256
        ),
        redis_loss_evidence_path=redis_loss_evidence_path,
        redis_loss_artifact_path=(
            Path(str(redis_loss_input.get("path", "")))
            if redis_loss_input is not None
            else None
        ),
        mcp_crud_proof_path=mcp_crud_proof_path,
        mcp_crud_summary_artifact_path=(
            Path(str(mcp_crud_proof_input.get("path", "")))
            if mcp_crud_proof_input is not None
            else None
        ),
        credential_lifecycle_report_path=credential_lifecycle_report_path,
        credential_lifecycle_summary_artifact_path=(
            Path(str(credential_lifecycle_input.get("path", "")))
            if credential_lifecycle_input is not None
            else None
        ),
        observability_baseline_path=observability_baseline_path,
        observability_runtime_path=observability_runtime_path,
        observability_summary_artifact_path=(
            Path(str(observability_input.get("path", "")))
            if observability_input is not None
            else None
        ),
        tooling_lifecycle_report_path=tooling_lifecycle_report_path,
        tooling_lifecycle_summary_artifact_path=(
            Path(str(tooling_lifecycle_input.get("path", "")))
            if tooling_lifecycle_input is not None
            else None
        ),
        tooling_lifecycle_compose_project=tooling_lifecycle_compose_project,
        mcp_governance_proof_path=mcp_governance_proof_path,
        mcp_governance_compose_project=mcp_governance_compose_project,
        mcp_governance_summary_artifact_path=(
            Path(str(mcp_governance_input.get("path", "")))
            if mcp_governance_input is not None
            else None
        ),
        jwks_rotation_evidence_path=jwks_rotation_evidence_path,
        jwks_rotation_summary_artifact_path=(
            Path(str(jwks_rotation_input.get("path", "")))
            if jwks_rotation_input is not None
            else None
        ),
        jwks_rotation_compose_project=jwks_rotation_compose_project,
        jwks_rotation_terminal_mode=jwks_rotation_terminal_mode,
        mcp_tool_contract_proof_path=mcp_tool_contract_proof_path,
        mcp_tool_contract_summary_artifact_path=(
            Path(str(mcp_tool_contract_input.get("path", "")))
            if mcp_tool_contract_input is not None
            else None
        ),
        generator_acceptance_bundle_path=generator_acceptance_bundle_path,
        generator_forbidden_terms_path=generator_forbidden_terms_path,
        generator_acceptance_artifact_path=(
            Path(str(generator_acceptance_input.get("path", "")))
            if generator_acceptance_input is not None
            else None
        ),
        production_fail_fast_evidence_path=production_fail_fast_evidence_path,
        production_fail_fast_artifact_path=(
            Path(str(production_fail_fast_input.get("path", "")))
            if production_fail_fast_input is not None
            else None
        ),
        tag=tag,
        version=version,
        commit=commit,
        evaluated_at=_parse_evaluated_at(gate.get("evaluatedAt")),
        verify_git=verify_git,
    )
    if actual != expected:
        raise EvidenceError("release evidence manifest does not match its bound source evidence")
    if expected["gate"]["status"] != "PASS":
        raise EvidenceError("release evidence gate is not PASS")
    return expected


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--candidate-validation-root", type=Path)
    parser.add_argument("--artifacts-root", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    _common_arguments(build)
    build.add_argument("--acceptance-results", required=True, type=Path)
    build.add_argument("--release-images", required=True, type=Path)
    build.add_argument("--security-summary", required=True, type=Path)
    build.add_argument("--production-compose", required=True, type=Path)
    build.add_argument("--production-policy", required=True, type=Path)
    build.add_argument("--deployment-images", required=True, type=Path)
    build.add_argument("--runtime-identity", required=True, type=Path)
    build.add_argument("--runtime-acceptance", required=True, type=Path)
    build.add_argument("--v1-source-provenance-proof", type=Path)
    build.add_argument("--v1-source-provenance-summary-artifact", type=Path)
    build.add_argument("--v1-operations-documentation-proof", type=Path)
    build.add_argument("--v1-operations-documentation-summary-artifact", type=Path)
    build.add_argument("--release-runtime-test-reports-directory", type=Path)
    build.add_argument("--release-runtime-test-reports-summary-artifact", type=Path)
    build.add_argument("--project-transport-parity-proof", type=Path)
    build.add_argument("--project-transport-parity-summary-artifact", type=Path)
    build.add_argument("--migration-failure-evidence", type=Path)
    build.add_argument("--migration-failure-ac40-evidence", type=Path)
    build.add_argument("--migration-failure-artifact", type=Path)
    build.add_argument("--v1-upgrade-evidence", type=Path)
    build.add_argument("--v1-upgrade-artifact", type=Path)
    build.add_argument("--ac40-dependency-seed", required=True, type=Path)
    build.add_argument(
        "--expected-ac40-dependency-seed-sha256", required=True
    )
    build.add_argument(
        "--ac40-dependency-seed-provenance", required=True, type=Path
    )
    build.add_argument("--redis-loss-evidence", type=Path)
    build.add_argument("--redis-loss-artifact", type=Path)
    build.add_argument("--mcp-crud-proof", type=Path)
    build.add_argument("--mcp-crud-summary-artifact", type=Path)
    build.add_argument("--credential-lifecycle-report", type=Path)
    build.add_argument("--credential-lifecycle-summary-artifact", type=Path)
    build.add_argument("--observability-baseline", type=Path)
    build.add_argument("--observability-runtime", type=Path)
    build.add_argument("--observability-summary-artifact", type=Path)
    build.add_argument("--tooling-lifecycle-report", type=Path)
    build.add_argument("--tooling-lifecycle-summary-artifact", type=Path)
    build.add_argument("--tooling-lifecycle-compose-project")
    build.add_argument("--mcp-governance-proof", type=Path)
    build.add_argument("--mcp-governance-summary-artifact", type=Path)
    build.add_argument("--mcp-governance-compose-project")
    build.add_argument("--jwks-rotation-evidence", type=Path)
    build.add_argument("--jwks-rotation-summary-artifact", type=Path)
    build.add_argument("--jwks-rotation-compose-project")
    build.add_argument(
        "--jwks-rotation-terminal-mode", choices=("expiry", "revocation")
    )
    build.add_argument("--mcp-tool-contract-proof", type=Path)
    build.add_argument("--mcp-tool-contract-summary-artifact", type=Path)
    build.add_argument("--generator-acceptance-bundle", type=Path)
    build.add_argument("--generator-forbidden-terms", type=Path)
    build.add_argument("--generator-acceptance-artifact", type=Path)
    build.add_argument("--production-fail-fast-evidence", type=Path)
    build.add_argument("--production-fail-fast-artifact", type=Path)
    build.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify")
    _common_arguments(verify)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--v1-source-provenance-proof", type=Path)
    verify.add_argument("--v1-operations-documentation-proof", type=Path)
    verify.add_argument("--release-runtime-test-reports-directory", type=Path)
    verify.add_argument("--project-transport-parity-proof", type=Path)
    verify.add_argument("--migration-failure-evidence", type=Path)
    verify.add_argument("--migration-failure-ac40-evidence", type=Path)
    verify.add_argument("--v1-upgrade-evidence", type=Path)
    verify.add_argument("--ac40-dependency-seed", required=True, type=Path)
    verify.add_argument(
        "--expected-ac40-dependency-seed-sha256", required=True
    )
    verify.add_argument(
        "--ac40-dependency-seed-provenance", required=True, type=Path
    )
    verify.add_argument("--redis-loss-evidence", type=Path)
    verify.add_argument("--mcp-crud-proof", type=Path)
    verify.add_argument("--credential-lifecycle-report", type=Path)
    verify.add_argument("--observability-baseline", type=Path)
    verify.add_argument("--observability-runtime", type=Path)
    verify.add_argument("--tooling-lifecycle-report", type=Path)
    verify.add_argument("--tooling-lifecycle-compose-project")
    verify.add_argument("--mcp-governance-proof", type=Path)
    verify.add_argument("--mcp-governance-compose-project")
    verify.add_argument("--jwks-rotation-evidence", type=Path)
    verify.add_argument("--jwks-rotation-compose-project")
    verify.add_argument(
        "--jwks-rotation-terminal-mode", choices=("expiry", "revocation")
    )
    verify.add_argument("--mcp-tool-contract-proof", type=Path)
    verify.add_argument("--generator-acceptance-bundle", type=Path)
    verify.add_argument("--generator-forbidden-terms", type=Path)
    verify.add_argument("--production-fail-fast-evidence", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            ledger = build_ledger(
                repository_root=args.repository_root,
                candidate_validation_root=args.candidate_validation_root,
                artifacts_root=args.artifacts_root,
                acceptance_source_path=args.acceptance_results,
                release_images_path=args.release_images,
                security_summary_path=args.security_summary,
                production_compose_path=args.production_compose,
                production_policy_path=args.production_policy,
                deployment_images_path=args.deployment_images,
                runtime_identity_path=args.runtime_identity,
                runtime_acceptance_path=args.runtime_acceptance,
                v1_source_provenance_proof_path=args.v1_source_provenance_proof,
                v1_source_provenance_summary_artifact_path=(
                    args.v1_source_provenance_summary_artifact
                ),
                v1_operations_documentation_proof_path=(
                    args.v1_operations_documentation_proof
                ),
                v1_operations_documentation_summary_artifact_path=(
                    args.v1_operations_documentation_summary_artifact
                ),
                release_runtime_test_reports_directory_path=(
                    args.release_runtime_test_reports_directory
                ),
                release_runtime_test_reports_summary_artifact_path=(
                    args.release_runtime_test_reports_summary_artifact
                ),
                project_transport_parity_proof_path=(
                    args.project_transport_parity_proof
                ),
                project_transport_parity_summary_artifact_path=(
                    args.project_transport_parity_summary_artifact
                ),
                migration_failure_evidence_path=args.migration_failure_evidence,
                migration_failure_ac40_evidence_path=args.migration_failure_ac40_evidence,
                migration_failure_artifact_path=args.migration_failure_artifact,
                v1_upgrade_evidence_path=args.v1_upgrade_evidence,
                v1_upgrade_artifact_path=args.v1_upgrade_artifact,
                ac40_dependency_seed_path=args.ac40_dependency_seed,
                expected_ac40_dependency_seed_sha256=(
                    args.expected_ac40_dependency_seed_sha256
                ),
                ac40_dependency_seed_provenance_path=(
                    args.ac40_dependency_seed_provenance
                ),
                redis_loss_evidence_path=args.redis_loss_evidence,
                redis_loss_artifact_path=args.redis_loss_artifact,
                mcp_crud_proof_path=args.mcp_crud_proof,
                mcp_crud_summary_artifact_path=args.mcp_crud_summary_artifact,
                credential_lifecycle_report_path=args.credential_lifecycle_report,
                credential_lifecycle_summary_artifact_path=(
                    args.credential_lifecycle_summary_artifact
                ),
                observability_baseline_path=args.observability_baseline,
                observability_runtime_path=args.observability_runtime,
                observability_summary_artifact_path=(
                    args.observability_summary_artifact
                ),
                tooling_lifecycle_report_path=args.tooling_lifecycle_report,
                tooling_lifecycle_summary_artifact_path=(
                    args.tooling_lifecycle_summary_artifact
                ),
                tooling_lifecycle_compose_project=(
                    args.tooling_lifecycle_compose_project
                ),
                mcp_governance_proof_path=args.mcp_governance_proof,
                mcp_governance_summary_artifact_path=args.mcp_governance_summary_artifact,
                mcp_governance_compose_project=args.mcp_governance_compose_project,
                jwks_rotation_evidence_path=args.jwks_rotation_evidence,
                jwks_rotation_summary_artifact_path=args.jwks_rotation_summary_artifact,
                jwks_rotation_compose_project=args.jwks_rotation_compose_project,
                jwks_rotation_terminal_mode=args.jwks_rotation_terminal_mode,
                mcp_tool_contract_proof_path=args.mcp_tool_contract_proof,
                mcp_tool_contract_summary_artifact_path=args.mcp_tool_contract_summary_artifact,
                generator_acceptance_bundle_path=args.generator_acceptance_bundle,
                generator_forbidden_terms_path=args.generator_forbidden_terms,
                generator_acceptance_artifact_path=args.generator_acceptance_artifact,
                production_fail_fast_evidence_path=args.production_fail_fast_evidence,
                production_fail_fast_artifact_path=args.production_fail_fast_artifact,
                tag=args.tag,
                version=args.version,
                commit=args.commit,
            )
            _write_json(args.output.resolve(), ledger)
            if ledger["gate"]["status"] != "PASS":
                for error in ledger["gate"]["errors"]:
                    print(f"FAIL release-evidence-gate: {error}")
                return 1
        else:
            verify_ledger(
                manifest_path=args.manifest,
                repository_root=args.repository_root,
                candidate_validation_root=args.candidate_validation_root,
                artifacts_root=args.artifacts_root,
                tag=args.tag,
                version=args.version,
                commit=args.commit,
                v1_source_provenance_proof_path=args.v1_source_provenance_proof,
                v1_operations_documentation_proof_path=(
                    args.v1_operations_documentation_proof
                ),
                release_runtime_test_reports_directory_path=(
                    args.release_runtime_test_reports_directory
                ),
                project_transport_parity_proof_path=(
                    args.project_transport_parity_proof
                ),
                migration_failure_evidence_path=args.migration_failure_evidence,
                migration_failure_ac40_evidence_path=args.migration_failure_ac40_evidence,
                v1_upgrade_evidence_path=args.v1_upgrade_evidence,
                ac40_dependency_seed_path=args.ac40_dependency_seed,
                expected_ac40_dependency_seed_sha256=(
                    args.expected_ac40_dependency_seed_sha256
                ),
                ac40_dependency_seed_provenance_path=(
                    args.ac40_dependency_seed_provenance
                ),
                redis_loss_evidence_path=args.redis_loss_evidence,
                mcp_crud_proof_path=args.mcp_crud_proof,
                credential_lifecycle_report_path=args.credential_lifecycle_report,
                observability_baseline_path=args.observability_baseline,
                observability_runtime_path=args.observability_runtime,
                tooling_lifecycle_report_path=args.tooling_lifecycle_report,
                tooling_lifecycle_compose_project=(
                    args.tooling_lifecycle_compose_project
                ),
                mcp_governance_proof_path=args.mcp_governance_proof,
                mcp_governance_compose_project=args.mcp_governance_compose_project,
                jwks_rotation_evidence_path=args.jwks_rotation_evidence,
                jwks_rotation_compose_project=args.jwks_rotation_compose_project,
                jwks_rotation_terminal_mode=args.jwks_rotation_terminal_mode,
                mcp_tool_contract_proof_path=args.mcp_tool_contract_proof,
                generator_acceptance_bundle_path=args.generator_acceptance_bundle,
                generator_forbidden_terms_path=args.generator_forbidden_terms,
                production_fail_fast_evidence_path=args.production_fail_fast_evidence,
            )
    except EvidenceError as exception:
        print(f"FAIL release-evidence-gate: {exception}")
        return 1
    print("PASS release-evidence-gate: immutable release identity and complete acceptance ledger")
    return 0


if __name__ == "__main__":
    sys.exit(main())
