#!/usr/bin/env python3
"""Create status-free, candidate-bound V1 source-review observations.

The producer records only committed source blob identities. It does not write a
PASS/FAIL field and does not decide acceptance. The source-registered validator
in ``v1_regression_supplemental_validators.py`` independently reads the clean
candidate and recomputes each frozen source-review semantic.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

import v1_regression_supplemental_validators as validators


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OBSERVATION_FILE = "v1-source-review-observation.json"
ARTIFACT_NAMES = {
    "supplemental.sharedProjectServiceBoundary": "shared-project-service-boundary.json",
    "supplemental.forbiddenCapabilitySourceScan": "forbidden-capability-source-scan.json",
    "supplemental.operationsDocumentationReview": "operations-documentation-review.json",
    "supplemental.projectIsolationReview": "project-isolation-review.json",
}
ARTIFACT_IDS = {
    "supplemental.sharedProjectServiceBoundary": "shared-service-boundary",
    "supplemental.forbiddenCapabilitySourceScan": "forbidden-capability-scan",
    "supplemental.operationsDocumentationReview": "operations-doc-review",
    "supplemental.projectIsolationReview": "project-isolation-review",
}
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


class SourceReviewProducerError(ValueError):
    """The producer cannot safely bind or publish the observation bundle."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceReviewProducerError(f"JSON object repeats field: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise SourceReviewProducerError(f"{label} must be a regular non-symlink file")
    metadata = requested.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
        raise SourceReviewProducerError(f"{label} size is invalid")
    payload = requested.read_bytes()
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise SourceReviewProducerError(f"{label} is not strict UTF-8 JSON") from exception
    if not isinstance(value, dict):
        raise SourceReviewProducerError(f"{label} must be a JSON object")
    return value, payload


def _git(root: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
    ):
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
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
        raise SourceReviewProducerError("candidate Git inspection failed") from exception


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _candidate_binding(root: Path, manifest_path: Path) -> dict[str, str]:
    document, payload = _load_json(manifest_path, "candidate manifest")
    if set(document) != {"schemaVersion", "release", "images"} or document.get("schemaVersion") != 1:
        raise SourceReviewProducerError("candidate manifest fields are not exact")
    release = document.get("release")
    images = document.get("images")
    if not isinstance(release, dict) or set(release) != {"tag", "version", "gitCommit"}:
        raise SourceReviewProducerError("candidate release identity is not exact")
    if not isinstance(images, dict) or set(images) != {"app", "nginx", "mysql", "redis"}:
        raise SourceReviewProducerError("candidate image inventory is not exact")
    version = release.get("version")
    tag = release.get("tag")
    commit = release.get("gitCommit")
    if (
        not isinstance(version, str)
        or not VERSION.fullmatch(version)
        or version.endswith("-SNAPSHOT")
        or tag != f"v{version}"
        or not isinstance(commit, str)
        or not validators.GIT_OBJECT.fullmatch(commit)
    ):
        raise SourceReviewProducerError("candidate release identity is malformed")
    for name, image in images.items():
        if not isinstance(image, dict) or set(image) != {"reference", "digest"}:
            raise SourceReviewProducerError(f"candidate {name} image identity is not exact")
        reference, digest = image.get("reference"), image.get("digest")
        if not isinstance(reference, str) or "@" in reference or any(char.isspace() for char in reference) \
                or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) \
                or not DIGEST_REFERENCE.fullmatch(f"{reference}@{digest}"):
            raise SourceReviewProducerError(f"candidate {name} image is not immutable")
    head = _git(root, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if head != commit:
        raise SourceReviewProducerError("candidate manifest commit differs from HEAD")
    tag_ref = f"refs/tags/{tag}"
    if _git(root, "cat-file", "-t", tag_ref).decode("ascii").strip() != "tag" \
            or _git(root, "rev-parse", f"{tag_ref}^{{commit}}").decode("ascii").strip() != head:
        raise SourceReviewProducerError("candidate tag must be annotated and resolve to HEAD")
    binding = {
        "manifestSha256": hashlib.sha256(payload).hexdigest(),
        "gitCommit": head,
        "gitTree": tree,
        "releaseTag": tag,
        "releaseVersion": version,
        "sourceArchiveSha256": hashlib.sha256(
            _git(root, "archive", "--format=tar", head)
        ).hexdigest(),
    }
    validators._verify_candidate_root(binding, root)
    return binding


def _source_blobs(root: Path, commit: str, paths: Sequence[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for relative in paths:
        path = root / relative
        payload = path.read_bytes()
        committed = _git(root, "show", f"{commit}:{relative}")
        blob = _git(root, "rev-parse", f"{commit}:{relative}").decode("ascii").strip()
        if committed != payload or not validators.GIT_OBJECT.fullmatch(blob) \
                or _git(root, "cat-file", "-t", blob).decode("ascii").strip() != "blob":
            raise SourceReviewProducerError(f"candidate source differs from commit: {relative}")
        result[relative] = {
            "gitBlob": blob,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    return result


def _write_private(path: Path, document: Mapping[str, Any]) -> bytes:
    payload = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 or path.read_bytes() != payload:
        path.unlink(missing_ok=True)
        raise SourceReviewProducerError("private evidence publication is not exact")
    return payload


def create_bundle(repository_root: Path, manifest: Path, output_directory: Path) -> Path:
    root_input = repository_root.expanduser().absolute()
    if root_input.is_symlink() or not root_input.is_dir():
        raise SourceReviewProducerError("repository root must be a non-symlink directory")
    root = root_input.resolve(strict=True)
    if Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise SourceReviewProducerError("repository root must be the exact Git top-level")
    output_input = output_directory.expanduser().absolute()
    if output_input.exists() or output_input.is_symlink():
        raise SourceReviewProducerError("output directory must not already exist")
    parent_input = output_input.parent
    if parent_input.is_symlink() or not parent_input.is_dir():
        raise SourceReviewProducerError("output parent must be a real existing directory")
    parent = parent_input.resolve(strict=True)
    output = parent / output_input.name
    if _inside(output, root) or _inside(root, output):
        raise SourceReviewProducerError("output directory must stay outside the repository")

    binding = _candidate_binding(root, manifest)
    output.mkdir(mode=0o700)
    artifacts_root = output / "artifacts"
    artifacts_root.mkdir(mode=0o700)
    artifact_index: list[dict[str, str]] = []
    checks: list[dict[str, Any]] = []
    try:
        for check in sorted(validators.SOURCE_REVIEW_CHECKS):
            artifact_name = ARTIFACT_NAMES[check]
            artifact_id = ARTIFACT_IDS[check]
            artifact = {
                "schemaVersion": 1,
                "suite": "v1",
                "producer": validators.SOURCE_REVIEW_PRODUCER,
                "check": check,
                "candidate": binding,
                "observations": {
                    "schemaVersion": 1,
                    "sourceBlobs": _source_blobs(
                        root,
                        binding["gitCommit"],
                        validators.source_review_paths(check, root, binding["gitCommit"]),
                    ),
                },
            }
            payload = _write_private(artifacts_root / artifact_name, artifact)
            artifact_index.append({
                "id": artifact_id,
                "path": f"artifacts/{artifact_name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            checks.append({"id": check, "artifactIds": [artifact_id]})
        observation = {
            "schemaVersion": 2,
            "suite": "v1",
            "candidate": binding,
            "producer": validators.SOURCE_REVIEW_PRODUCER,
            "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "artifacts": artifact_index,
            "checks": checks,
        }
        observation_path = output / OBSERVATION_FILE
        _write_private(observation_path, observation)
        validators._verify_candidate_root(binding, root)
        if {path.name for path in output.iterdir()} != {"artifacts", OBSERVATION_FILE} \
                or {path.name for path in artifacts_root.iterdir()} != {
                    ARTIFACT_NAMES[check] for check in validators.SOURCE_REVIEW_CHECKS
                }:
            raise SourceReviewProducerError("source-review output file set is not exact")
        return observation_path
    except BaseException:
        # Preserve a partial private bundle for diagnosis. It remains outside
        # the repository and can never be accepted because the file set/index
        # is incomplete. Avoid a recursive delete in the producer.
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    result.add_argument("--candidate", required=True, type=Path)
    result.add_argument("--output-directory", required=True, type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        observation = create_bundle(args.repository_root, args.candidate, args.output_directory)
    except (SourceReviewProducerError, validators.SupplementalValidationError, OSError, ValueError) as exception:
        print(f"FAIL create-v1-source-review-observation: {exception}", file=sys.stderr)
        return 1
    print(json.dumps({
        "producer": validators.SOURCE_REVIEW_PRODUCER,
        "observation": str(observation),
        "checks": len(validators.SOURCE_REVIEW_CHECKS),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
