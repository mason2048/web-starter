#!/usr/bin/env python3
"""Independently validate V1 AC-38 operations-documentation source evidence."""

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
from typing import Any, Mapping, Sequence
import xml.etree.ElementTree as ElementTree


PROOF_NAME = "v1-ac38-operations-documentation-proof.json"
CHECKSUM_NAME = PROOF_NAME + ".sha256"
SUMMARY_NAME = "v1-ac38-operations-documentation-summary.json"
PRODUCER_PATH = "scripts/create_v1_operations_documentation_proof.py"
VALIDATOR_PATH = "scripts/validate_v1_operations_documentation_proof.py"
SCHEMA_PATH = "security/v1-ac38-operations-documentation-summary.schema.json"
DOCUMENT_PATHS = (
    "docs/deployment.md",
    "docs/security.md",
    "docs/recovery-rehearsal.md",
    "docs/v1-to-v2-upgrade-rehearsal.md",
)
MIGRATION_PREFIX = "web-starter-admin/src/main/resources/db/migration/"
MIGRATION = re.compile(r"^V([1-9][0-9]*)__[A-Za-z0-9][A-Za-z0-9_]*\.sql$")
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
MAX_PROOF_BYTES = 8 * 1024 * 1024


class ProofValidationError(ValueError):
    """The raw proof is stale, unsafe, forged, or semantically incomplete."""


@dataclass(frozen=True)
class Snapshot:
    payload: bytes
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofValidationError(f"JSON repeats field: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProofValidationError(f"{label} must be an object")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ProofValidationError(f"{label} fields are not exact")


def _git(root: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(name, None)
    for name in (
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
    ):
        environment.pop(name, None)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    try:
        return subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(root), *arguments,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exception:
        raise ProofValidationError("candidate Git inspection failed") from exception


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _snapshot(path: Path, label: str, maximum: int) -> Snapshot:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise ProofValidationError(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(requested, flags)
    except OSError as exception:
        raise ProofValidationError(f"{label} cannot be opened safely") from exception
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 \
                or before.st_size > maximum \
                or (os.name == "posix" and stat.S_IMODE(before.st_mode) != 0o600):
            raise ProofValidationError(f"{label} size or mode is unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    current = requested.lstat()
    identity = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        stat.S_IMODE(before.st_mode),
    )
    if len(payload) != before.st_size or identity != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        stat.S_IMODE(after.st_mode),
    ) or identity != (
        current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
        stat.S_IMODE(current.st_mode),
    ):
        raise ProofValidationError(f"{label} changed while it was read")
    return Snapshot(payload, *identity)


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ProofValidationError(f"{label} is not strict UTF-8 JSON") from exception
    return _object(value, label)


def _version(root: Path) -> str:
    try:
        pom = ElementTree.fromstring((root / "pom.xml").read_bytes())
        namespace = pom.tag.split("}", 1)[0] + "}" if pom.tag.startswith("{") else ""
        element = pom.find(f"{namespace}version")
        maven = element.text.strip() if element is not None and element.text else ""
        frontend = json.loads(
            (root / "web-starter-web/package.json").read_text(encoding="utf-8")
        ).get("version")
    except (OSError, ElementTree.ParseError, json.JSONDecodeError) as exception:
        raise ProofValidationError("candidate version manifests are invalid") from exception
    if maven != frontend or not isinstance(maven, str) or VERSION.fullmatch(maven) is None \
            or maven.endswith("-SNAPSHOT"):
        raise ProofValidationError("candidate versions are inconsistent or not releasable")
    return maven


def _candidate(
    root: Path,
    expected_commit: str,
    expected_tag: str,
    expected_version: str,
) -> dict[str, str]:
    if COMMIT.fullmatch(expected_commit) is None or VERSION.fullmatch(expected_version) is None \
            or expected_tag != "v" + expected_version:
        raise ProofValidationError("expected release identity is invalid")
    top = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    head = _git(root, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if top != root or head != expected_commit or _version(root) != expected_version:
        raise ProofValidationError("candidate root, commit, or version differs")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ProofValidationError("candidate source tree must be clean")
    reference = "refs/tags/" + expected_tag
    if _git(root, "cat-file", "-t", reference).decode("ascii").strip() != "tag" \
            or _git(root, "rev-parse", reference + "^{commit}").decode("ascii").strip() != head:
        raise ProofValidationError("candidate tag must be annotated and resolve to HEAD")
    return {"commit": head, "tree": tree, "tag": expected_tag, "version": expected_version}


def _source_paths(root: Path, commit: str) -> tuple[str, ...]:
    raw = _git(root, "ls-tree", "-r", "--name-only", commit, "--", MIGRATION_PREFIX)
    migrations = sorted(
        relative
        for relative in raw.decode("utf-8", errors="strict").splitlines()
        if relative.startswith(MIGRATION_PREFIX)
        and MIGRATION.fullmatch(Path(relative).name)
    )
    if not migrations:
        raise ProofValidationError("candidate has no committed Flyway migrations")
    return (*DOCUMENT_PATHS, *migrations, PRODUCER_PATH, VALIDATOR_PATH, SCHEMA_PATH)


def _text(sources: Mapping[str, bytes], path: str) -> str:
    try:
        return sources[path].decode("utf-8", errors="strict")
    except (KeyError, UnicodeDecodeError) as exception:
        raise ProofValidationError(f"source text is unavailable: {path}") from exception


def _validate_semantics(sources: Mapping[str, bytes], versions: list[int]) -> None:
    if versions != list(range(1, max(versions) + 1)):
        raise ProofValidationError("Flyway versions are not a contiguous sequence")
    deployment = _text(sources, "docs/deployment.md")
    security = _text(sources, "docs/security.md")
    recovery = _text(sources, "docs/recovery-rehearsal.md")
    upgrade = _text(sources, "docs/v1-to-v2-upgrade-rehearsal.md")
    if any(token not in deployment for token in (
        "## 日志与故障定位", "## 备份与恢复", "## 升级与回滚",
        "### RSA 签名密钥轮换与回退", "recovery-rehearsal.md",
        "compose.production.yaml", "WEB_STARTER_APP_DIGEST",
    )):
        raise ProofValidationError("deployment operations documentation is incomplete")
    if any(token not in security for token in (
        "### OAuth RSA 签名密钥轮换", "`exp` NumericDate", "`rev`",
        "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID",
    )):
        raise ProofValidationError("RSA lifecycle documentation is incomplete")
    for script in ("recovery_backup.py", "recovery_restore.py", "rehearse_redis_loss.py"):
        if script not in recovery:
            raise ProofValidationError(f"recovery documentation omits {script}")
    if f"V1—V{max(versions)}" not in recovery:
        raise ProofValidationError("recovery documentation is stale relative to Flyway")
    if "rehearse_v1_to_v2_upgrade.py" not in upgrade or "V1 tag" not in upgrade:
        raise ProofValidationError("upgrade rehearsal documentation is incomplete")


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def validate_proof(
    proof_path: Path,
    *,
    repository_root: Path,
    expected_candidate_commit: str,
    expected_candidate_tag: str,
    expected_candidate_version: str,
) -> dict[str, Any]:
    requested_root = repository_root.expanduser().absolute()
    if requested_root.is_symlink() or not requested_root.is_dir():
        raise ProofValidationError("repository root must be a real directory")
    root = requested_root.resolve(strict=True)
    requested_proof = proof_path.expanduser().absolute()
    parent = requested_proof.parent
    if parent.is_symlink() or not parent.is_dir() \
            or (os.name == "posix" and stat.S_IMODE(parent.lstat().st_mode) != 0o700) \
            or _inside(parent.resolve(), root) or _inside(root, parent.resolve()):
        raise ProofValidationError("raw proof must be in an external private directory")
    if requested_proof.name != PROOF_NAME \
            or {entry.name for entry in parent.iterdir()} != {PROOF_NAME, CHECKSUM_NAME}:
        raise ProofValidationError("raw proof directory is not exact")
    proof = _snapshot(requested_proof, "raw proof", MAX_PROOF_BYTES)
    checksum = _snapshot(parent / CHECKSUM_NAME, "raw proof checksum", 256)
    digest = hashlib.sha256(proof.payload).hexdigest()
    if checksum.payload != f"{digest}  {PROOF_NAME}\n".encode("ascii"):
        raise ProofValidationError("raw proof checksum differs")
    document = _json(proof.payload, "raw proof")
    _exact(document, {"schemaVersion", "acceptanceId", "candidate", "observations"}, "raw proof")
    if document.get("schemaVersion") != 1 or document.get("acceptanceId") != "AC-38":
        raise ProofValidationError("raw proof identity differs")
    expected_candidate = _candidate(
        root, expected_candidate_commit, expected_candidate_tag, expected_candidate_version
    )
    if document.get("candidate") != expected_candidate:
        raise ProofValidationError("raw proof candidate binding differs")
    observations = _object(document.get("observations"), "raw proof observations")
    _exact(observations, {"migrationVersions", "sourceBlobs"}, "raw proof observations")
    versions = observations.get("migrationVersions")
    if not isinstance(versions, list) or not versions \
            or any(isinstance(value, bool) or not isinstance(value, int) for value in versions):
        raise ProofValidationError("raw migration version observations are invalid")
    expected_paths = _source_paths(root, expected_candidate_commit)
    source_blobs = _object(observations.get("sourceBlobs"), "raw source blobs")
    if set(source_blobs) != set(expected_paths):
        raise ProofValidationError("raw source inventory differs")
    sources: dict[str, bytes] = {}
    source_hashes: dict[str, str] = {}
    for relative in expected_paths:
        binding = _object(source_blobs[relative], f"source binding {relative}")
        _exact(binding, {"gitBlob", "sha256"}, f"source binding {relative}")
        payload = _git(root, "show", f"{expected_candidate_commit}:{relative}")
        blob = _git(root, "rev-parse", f"{expected_candidate_commit}:{relative}").decode("ascii").strip()
        sha256 = hashlib.sha256(payload).hexdigest()
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload \
                or binding != {"gitBlob": blob, "sha256": sha256} \
                or _git(root, "cat-file", "-t", blob).decode("ascii").strip() != "blob":
            raise ProofValidationError(f"source binding differs: {relative}")
        sources[relative] = payload
        source_hashes[relative] = sha256
    observed_versions = sorted(
        int(MIGRATION.fullmatch(Path(path).name).group(1))
        for path in expected_paths
        if path.startswith(MIGRATION_PREFIX)
    )
    if versions != observed_versions:
        raise ProofValidationError("raw migration versions differ from candidate")
    _validate_semantics(sources, observed_versions)
    schema = _json(sources[SCHEMA_PATH], "AC-38 summary schema")
    if schema.get("$id") != "https://webstarter.dev/schema/v1-ac38-operations-documentation-summary.schema.json":
        raise ProofValidationError("AC-38 summary schema identity differs")
    _candidate(root, expected_candidate_commit, expected_candidate_tag, expected_candidate_version)
    if _snapshot(requested_proof, "raw proof", MAX_PROOF_BYTES) != proof \
            or _snapshot(parent / CHECKSUM_NAME, "raw proof checksum", 256) != checksum:
        raise ProofValidationError("raw proof changed during validation")
    return {
        "schemaVersion": 1,
        "acceptanceIds": ["AC-38"],
        "status": "PASS",
        "candidate": expected_candidate,
        "checks": {
            "operationsDocumentationReview": "PASS",
            "sourceIntegrity": "PASS",
        },
        "evidence": {
            "proofSha256": digest,
            "migrationVersions": observed_versions,
            "sourceSha256": {path: source_hashes[path] for path in sorted(source_hashes)},
        },
    }


def _write_summary(path: Path, payload: bytes) -> None:
    target = path.expanduser().absolute()
    if target.exists() or target.is_symlink() or not target.parent.is_dir() \
            or target.parent.is_symlink():
        raise ProofValidationError("summary output destination is unsafe")
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("summary write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 or target.read_bytes() != payload:
        target.unlink(missing_ok=True)
        raise ProofValidationError("canonical summary publication is not exact")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--proof", required=True, type=Path)
    result.add_argument("--repository-root", required=True, type=Path)
    result.add_argument("--expected-candidate-commit", required=True)
    result.add_argument("--expected-candidate-tag", required=True)
    result.add_argument("--expected-candidate-version", required=True)
    result.add_argument("--summary-output", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        summary = validate_proof(
            args.proof,
            repository_root=args.repository_root,
            expected_candidate_commit=args.expected_candidate_commit,
            expected_candidate_tag=args.expected_candidate_tag,
            expected_candidate_version=args.expected_candidate_version,
        )
        if args.summary_output is not None:
            _write_summary(args.summary_output, canonical_summary_bytes(summary))
    except (OSError, UnicodeError, ProofValidationError, ValueError) as exception:
        print(f"FAIL validate-v1-ac38-proof: {exception}", file=sys.stderr)
        return 1
    print("PASS validate-v1-ac38-proof: AC-38 operations documentation is candidate-bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
