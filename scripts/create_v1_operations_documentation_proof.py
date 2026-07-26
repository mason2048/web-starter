#!/usr/bin/env python3
"""Create status-free, candidate-bound source observations for V1 AC-38."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Sequence
import xml.etree.ElementTree as ElementTree


PROOF_NAME = "v1-ac38-operations-documentation-proof.json"
CHECKSUM_NAME = PROOF_NAME + ".sha256"
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
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)


class ProofError(ValueError):
    """The source observation cannot be published safely."""


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
        raise ProofError("candidate Git inspection failed") from exception


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


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
        raise ProofError("candidate version manifests are invalid") from exception
    if maven != frontend or not isinstance(maven, str) or VERSION.fullmatch(maven) is None \
            or maven.endswith("-SNAPSHOT"):
        raise ProofError("candidate versions are inconsistent or not releasable")
    return maven


def _candidate(root: Path, commit: str, tag: str, version: str) -> dict[str, str]:
    if COMMIT.fullmatch(commit) is None or VERSION.fullmatch(version) is None \
            or tag != "v" + version:
        raise ProofError("expected release identity is invalid")
    top = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    head = _git(root, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if top != root or head != commit or _version(root) != version:
        raise ProofError("candidate root, commit, or version differs")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ProofError("candidate source tree must be clean")
    reference = "refs/tags/" + tag
    if _git(root, "cat-file", "-t", reference).decode("ascii").strip() != "tag" \
            or _git(root, "rev-parse", reference + "^{commit}").decode("ascii").strip() != head:
        raise ProofError("candidate tag must be annotated and resolve to HEAD")
    return {"commit": head, "tree": tree, "tag": tag, "version": version}


def _source_paths(root: Path, commit: str) -> tuple[str, ...]:
    raw = _git(root, "ls-tree", "-r", "--name-only", commit, "--", MIGRATION_PREFIX)
    migrations = []
    for relative in raw.decode("utf-8", errors="strict").splitlines():
        name = Path(relative).name
        if relative.startswith(MIGRATION_PREFIX) and MIGRATION.fullmatch(name):
            migrations.append(relative)
    if not migrations:
        raise ProofError("candidate has no committed Flyway migrations")
    paths = (*DOCUMENT_PATHS, *sorted(migrations), PRODUCER_PATH, VALIDATOR_PATH, SCHEMA_PATH)
    if len(paths) != len(set(paths)):
        raise ProofError("source inventory is duplicated")
    return paths


def _sources(root: Path, commit: str, paths: Sequence[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ProofError(f"candidate source is missing or symbolic: {relative}")
        payload = path.read_bytes()
        committed = _git(root, "show", f"{commit}:{relative}")
        blob = _git(root, "rev-parse", f"{commit}:{relative}").decode("ascii").strip()
        if payload != committed or COMMIT.fullmatch(blob) is None \
                or _git(root, "cat-file", "-t", blob).decode("ascii").strip() != "blob":
            raise ProofError(f"candidate source differs from commit: {relative}")
        result[relative] = {
            "gitBlob": blob,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    return result


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("proof write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 or path.read_bytes() != payload:
        raise ProofError("private proof publication is not exact")


def create_proof(
    repository_root: Path,
    output_directory: Path,
    expected_commit: str,
    expected_tag: str,
    expected_version: str,
) -> Path:
    requested_root = repository_root.expanduser().absolute()
    if requested_root.is_symlink() or not requested_root.is_dir():
        raise ProofError("repository root must be a real directory")
    root = requested_root.resolve(strict=True)
    requested_output = output_directory.expanduser().absolute()
    if requested_output.exists() or requested_output.is_symlink():
        raise ProofError("output directory must not already exist")
    parent = requested_output.parent.resolve(strict=True)
    output = parent / requested_output.name
    if _inside(output, root) or _inside(root, output):
        raise ProofError("private proof must remain outside the repository")

    candidate = _candidate(root, expected_commit, expected_tag, expected_version)
    paths = _source_paths(root, expected_commit)
    source_blobs = _sources(root, expected_commit, paths)
    versions = sorted(
        int(MIGRATION.fullmatch(Path(path).name).group(1))
        for path in paths
        if path.startswith(MIGRATION_PREFIX)
    )
    document: dict[str, Any] = {
        "schemaVersion": 1,
        "acceptanceId": "AC-38",
        "candidate": candidate,
        "observations": {
            "migrationVersions": versions,
            "sourceBlobs": source_blobs,
        },
    }
    payload = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    output.mkdir(mode=0o700)
    try:
        _write_exclusive(output / PROOF_NAME, payload)
        checksum = f"{hashlib.sha256(payload).hexdigest()}  {PROOF_NAME}\n".encode("ascii")
        _write_exclusive(output / CHECKSUM_NAME, checksum)
        if {entry.name for entry in output.iterdir()} != {PROOF_NAME, CHECKSUM_NAME}:
            raise ProofError("private proof directory contains unexpected entries")
        _candidate(root, expected_commit, expected_tag, expected_version)
    except BaseException:
        raise
    return output / PROOF_NAME


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository-root", required=True, type=Path)
    result.add_argument("--output-directory", required=True, type=Path)
    result.add_argument("--expected-candidate-commit", required=True)
    result.add_argument("--expected-candidate-tag", required=True)
    result.add_argument("--expected-candidate-version", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        proof = create_proof(
            args.repository_root,
            args.output_directory,
            args.expected_candidate_commit,
            args.expected_candidate_tag,
            args.expected_candidate_version,
        )
    except (OSError, UnicodeError, ProofError, ValueError) as exception:
        print(f"FAIL create-v1-ac38-proof: {exception}", file=sys.stderr)
        return 1
    print(json.dumps({"acceptanceId": "AC-38", "proof": str(proof)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
