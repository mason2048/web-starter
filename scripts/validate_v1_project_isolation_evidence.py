#!/usr/bin/env python3
"""Independently evaluate and publish the V1 AC-40 project-isolation summary."""

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

import repository_policy
import v1_regression_supplemental_validators as source_validators


SUMMARY_NAME = "v1-ac40-project-isolation-summary.json"
SCHEMA_PATH = "security/v1-ac40-project-isolation-summary.schema.json"
VALIDATOR_PATH = "scripts/validate_v1_project_isolation_evidence.py"
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
MAX_FORBIDDEN_TERMS_BYTES = 64 * 1024


class ProjectIsolationEvidenceError(ValueError):
    """The candidate or its external project-isolation evidence is unsafe."""


@dataclass(frozen=True)
class PrivateFileSnapshot:
    payload: bytes
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int
    uid: int
    links: int


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _git(root: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(name, None)
    for name in (
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
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
        raise ProjectIsolationEvidenceError("Git inspection failed") from exception


def _exact_repository_root(path: Path, label: str) -> Path:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise ProjectIsolationEvidenceError(f"{label} must be a real directory")
    root = requested.resolve(strict=True)
    try:
        top = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    except UnicodeError as exception:
        raise ProjectIsolationEvidenceError(f"{label} Git root is invalid") from exception
    if top != root:
        raise ProjectIsolationEvidenceError(f"{label} must be the exact Git top-level")
    return root


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
        raise ProjectIsolationEvidenceError("candidate version manifests are invalid") from exception
    if (
        not isinstance(maven, str)
        or VERSION.fullmatch(maven) is None
        or maven.endswith("-SNAPSHOT")
        or frontend != maven
    ):
        raise ProjectIsolationEvidenceError("candidate versions are inconsistent or not releasable")
    return maven


def _candidate(
    root: Path,
    expected_commit: str,
    expected_tag: str,
    expected_version: str,
) -> dict[str, str]:
    if (
        COMMIT.fullmatch(expected_commit) is None
        or VERSION.fullmatch(expected_version) is None
        or expected_version.endswith("-SNAPSHOT")
        or expected_tag != "v" + expected_version
    ):
        raise ProjectIsolationEvidenceError("expected release identity is invalid")
    head = _git(root, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if head != expected_commit or COMMIT.fullmatch(tree) is None or _version(root) != expected_version:
        raise ProjectIsolationEvidenceError("candidate commit, tree, or version differs")
    reference = "refs/tags/" + expected_tag
    if (
        _git(root, "cat-file", "-t", reference).decode("ascii").strip() != "tag"
        or _git(root, "rev-parse", reference + "^{commit}").decode("ascii").strip() != head
    ):
        raise ProjectIsolationEvidenceError("candidate tag must be annotated at HEAD")
    status = _git(
        root, "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none",
    )
    index = [entry for entry in _git(root, "ls-files", "-v", "-z").split(b"\0") if entry]
    if status or not index or any(not entry.startswith(b"H ") for entry in index):
        raise ProjectIsolationEvidenceError("candidate worktree is not strictly clean")
    archive_sha256 = hashlib.sha256(
        _git(root, "archive", "--format=tar", head)
    ).hexdigest()
    return {
        "commit": head,
        "tree": tree,
        "tag": expected_tag,
        "version": expected_version,
        "sourceArchiveSha256": archive_sha256,
    }


def _private_file(path: Path, label: str) -> PrivateFileSnapshot:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise ProjectIsolationEvidenceError(f"{label} must be a regular non-symlink file")
    try:
        descriptor = os.open(
            requested,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exception:
        raise ProjectIsolationEvidenceError(f"{label} cannot be opened safely") from exception
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_FORBIDDEN_TERMS_BYTES
            or (os.name == "posix" and stat.S_IMODE(before.st_mode) != 0o600)
            or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
            or before.st_nlink != 1
        ):
            raise ProjectIsolationEvidenceError(f"{label} size, owner, mode, or links are unsafe")
        chunks: list[bytes] = []
        remaining = MAX_FORBIDDEN_TERMS_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
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
        stat.S_IMODE(before.st_mode), before.st_uid, before.st_nlink,
    )
    if (
        len(payload) != before.st_size
        or identity
        != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            stat.S_IMODE(after.st_mode), after.st_uid, after.st_nlink,
        )
        or identity
        != (
            current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
            stat.S_IMODE(current.st_mode), current.st_uid, current.st_nlink,
        )
    ):
        raise ProjectIsolationEvidenceError(f"{label} changed while it was read")
    return PrivateFileSnapshot(payload, *identity)


def _forbidden_terms(snapshot: PrivateFileSnapshot) -> list[str]:
    try:
        text = snapshot.payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProjectIsolationEvidenceError("forbidden terms are not strict UTF-8") from exception
    if any(
        ord(character) < 32 and character not in {"\n", "\r", "\t"}
        for character in text
    ):
        raise ProjectIsolationEvidenceError("forbidden terms contain a control character")
    terms = repository_policy._parse_terms(text)
    if not terms:
        raise ProjectIsolationEvidenceError("forbidden terms contain no effective terms")
    return terms


def _untracked_identity(root: Path) -> tuple[str, int]:
    names = [
        name
        for name in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
        if name
    ]
    names.sort()
    digest = hashlib.sha256()
    for encoded_name in names:
        path = root / os.fsdecode(encoded_name)
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        if path.is_symlink():
            content = os.fsencode(os.readlink(path))
        elif path.is_file():
            content = path.read_bytes()
        else:
            raise ProjectIsolationEvidenceError(
                "reference repository has a non-regular untracked path"
            )
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest(), len(names)


def _reference_identity(root: Path) -> dict[str, Any]:
    untracked_sha256, untracked_count = _untracked_identity(root)
    return {
        "head": hashlib.sha256(_git(root, "rev-parse", "HEAD")).hexdigest(),
        "status": hashlib.sha256(
            _git(root, "status", "--porcelain=v1", "-z")
        ).hexdigest(),
        "worktree": hashlib.sha256(
            _git(root, "diff", "--binary", "--no-ext-diff")
        ).hexdigest(),
        "index": hashlib.sha256(
            _git(root, "diff", "--cached", "--binary", "--no-ext-diff")
        ).hexdigest(),
        "untracked": untracked_sha256,
        "untrackedCount": untracked_count,
    }


def _reference_aggregate(identity: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _candidate_sources(root: Path, commit: str) -> tuple[dict[str, bytes], str]:
    tracked = source_validators._tracked_candidate_files(root, commit)
    sources: dict[str, bytes] = {}
    aggregate = hashlib.sha256()
    for relative in sorted(tracked):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ProjectIsolationEvidenceError(
                f"candidate tracked path is not a regular file: {relative}"
            )
        payload = source_validators._git(root, "cat-file", "blob", f"{commit}:{relative}")
        if path.read_bytes() != payload:
            raise ProjectIsolationEvidenceError(
                f"candidate source differs from commit: {relative}"
            )
        encoded = relative.encode("utf-8")
        aggregate.update(len(encoded).to_bytes(8, "big"))
        aggregate.update(encoded)
        aggregate.update(len(payload).to_bytes(8, "big"))
        aggregate.update(payload)
        sources[relative] = payload
    source_validators._validate_project_isolation(sources)
    return sources, aggregate.hexdigest()


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def evaluate(
    *,
    repository_root: Path,
    forbidden_terms_path: Path,
    reference_repository: Path,
    expected_candidate_commit: str,
    expected_candidate_tag: str,
    expected_candidate_version: str,
) -> dict[str, Any]:
    root = _exact_repository_root(repository_root, "candidate repository")
    reference = _exact_repository_root(reference_repository, "reference repository")
    if _inside(reference, root) or _inside(root, reference):
        raise ProjectIsolationEvidenceError(
            "reference repository must be separate from the candidate"
        )
    requested_terms = forbidden_terms_path.expanduser().absolute()
    resolved_terms = requested_terms.resolve(strict=True)
    if (
        _inside(resolved_terms, root)
        or _inside(root, resolved_terms)
        or _inside(resolved_terms, reference)
        or _inside(reference, resolved_terms)
    ):
        raise ProjectIsolationEvidenceError(
            "forbidden-term file must remain outside both repositories"
        )

    before_reference = _reference_identity(reference)
    candidate = _candidate(
        root,
        expected_candidate_commit,
        expected_candidate_tag,
        expected_candidate_version,
    )
    terms_snapshot = _private_file(requested_terms, "forbidden-term file")
    terms = _forbidden_terms(terms_snapshot)
    sources, source_aggregate = _candidate_sources(root, expected_candidate_commit)

    candidates = repository_policy.repository_candidates(root)
    candidate_paths = {item.relative_path for item in candidates}
    if candidate_paths != set(sources):
        raise ProjectIsolationEvidenceError(
            "forbidden-term scan inventory differs from the committed candidate"
        )
    findings = repository_policy.scan_forbidden_terms(candidates, terms)
    if findings:
        raise ProjectIsolationEvidenceError(
            "candidate contains externally supplied forbidden vocabulary"
        )
    schema = json.loads(sources[SCHEMA_PATH].decode("utf-8", errors="strict"))
    if (
        not isinstance(schema, dict)
        or schema.get("$id")
        != "https://webstarter.dev/schema/v1-ac40-project-isolation-summary.schema.json"
    ):
        raise ProjectIsolationEvidenceError("AC-40 summary schema identity differs")
    _candidate(
        root,
        expected_candidate_commit,
        expected_candidate_tag,
        expected_candidate_version,
    )
    if _private_file(requested_terms, "forbidden-term file") != terms_snapshot:
        raise ProjectIsolationEvidenceError(
            "forbidden-term file changed during project-isolation evaluation"
        )
    after_reference = _reference_identity(reference)
    if before_reference != after_reference:
        raise ProjectIsolationEvidenceError(
            "reference repository changed during project-isolation evaluation"
        )

    java_count = sum(relative.endswith(".java") for relative in sources)
    return {
        "schemaVersion": 1,
        "acceptanceIds": ["AC-40"],
        "status": "PASS",
        "candidate": candidate,
        "checks": {
            "forbiddenTermScan": "PASS",
            "projectIsolationReview": "PASS",
            "referenceRepositoryUnchanged": "PASS",
            "sourceIntegrity": "PASS",
        },
        "evidence": {
            "forbiddenTermsSha256": hashlib.sha256(terms_snapshot.payload).hexdigest(),
            "forbiddenTermCount": len(terms),
            "scannedFileCount": len(candidates),
            "trackedFileCount": len(sources),
            "javaSourceCount": java_count,
            "mavenModules": list(source_validators.EXPECTED_MAVEN_MODULES),
            "sourceAggregateSha256": source_aggregate,
            "referenceFingerprintSha256": _reference_aggregate(before_reference),
        },
    }


def _write_summary(path: Path, payload: bytes) -> None:
    target = path.expanduser().absolute()
    if (
        target.exists()
        or target.is_symlink()
        or not target.parent.is_dir()
        or target.parent.is_symlink()
    ):
        raise ProjectIsolationEvidenceError("summary output destination is unsafe")
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
    if (
        target.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or target.read_bytes() != payload
    ):
        target.unlink(missing_ok=True)
        raise ProjectIsolationEvidenceError("canonical summary publication is not exact")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository-root", required=True, type=Path)
    result.add_argument("--forbidden-terms", required=True, type=Path)
    result.add_argument("--reference-repository", required=True, type=Path)
    result.add_argument("--expected-candidate-commit", required=True)
    result.add_argument("--expected-candidate-tag", required=True)
    result.add_argument("--expected-candidate-version", required=True)
    result.add_argument("--summary-output", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        summary = evaluate(
            repository_root=args.repository_root,
            forbidden_terms_path=args.forbidden_terms,
            reference_repository=args.reference_repository,
            expected_candidate_commit=args.expected_candidate_commit,
            expected_candidate_tag=args.expected_candidate_tag,
            expected_candidate_version=args.expected_candidate_version,
        )
        if args.summary_output is not None:
            _write_summary(args.summary_output, canonical_summary_bytes(summary))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ProjectIsolationEvidenceError,
        source_validators.SupplementalValidationError,
        ValueError,
    ) as exception:
        print(f"FAIL validate-v1-ac40-project-isolation: {exception}", file=sys.stderr)
        return 1
    print(
        "PASS validate-v1-ac40-project-isolation: "
        "candidate, forbidden vocabulary, and reference repository are isolated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
