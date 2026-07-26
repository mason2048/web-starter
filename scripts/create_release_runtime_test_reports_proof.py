#!/usr/bin/env python3
"""Create the private candidate binding for fixed release runtime test reports.

The caller first places exactly one Playwright JSON report and the two fixed
Surefire XML reports in an owned mode-0700 directory outside the repository.
Every report must be mode 0600 and newer than the externally captured run start.
This producer validates that input and atomically adds the fixed proof file; it
never writes PASS.  PASS can only be derived by the independent validator.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
from typing import Any

if __package__:
    # Package callers and tests must share the exact validator module object so
    # exception identity and monkey-patched safety hooks cannot split across a
    # top-level and ``scripts.`` import of the same file.
    from . import validate_release_runtime_test_reports_proof as validation
else:  # direct ``python3 scripts/create_...py`` CLI execution
    import validate_release_runtime_test_reports_proof as validation


class RuntimeReportProofError(RuntimeError):
    """Raised when raw reports are not safe enough to bind."""


def _write_proof(descriptor: int, payload: bytes) -> validation.FileSnapshot:
    created = False
    try:
        child = os.open(
            validation.PROOF_FILE,
            validation._file_flags(write=True, create=True),
            0o600,
            dir_fd=descriptor,
        )
        created = True
        try:
            os.fchmod(child, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(child, remaining)
                if written <= 0:
                    raise RuntimeReportProofError("proof output write made no progress")
                remaining = remaining[written:]
            os.fsync(child)
            metadata = os.fstat(child)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise RuntimeReportProofError("proof output is not one private regular file")
        finally:
            os.close(child)
        return validation._snapshot_file(
            descriptor,
            validation.PROOF_FILE,
            validation.MAX_PROOF_BYTES,
            "runtime report proof",
        )
    except Exception:
        if created:
            try:
                os.unlink(validation.PROOF_FILE, dir_fd=descriptor)
            except OSError:
                pass
        raise


def create_proof(
    evidence_directory: Path,
    *,
    repository_root: Path,
    candidate_commit: str,
    candidate_version: str,
    candidate_tag: str,
    run_started_at_epoch_ns: int,
) -> Path:
    """Validate three fresh reports and atomically add a proof without status."""
    repository = validation._resolve_repository(repository_root)
    candidate = validation._validate_candidate(
        repository,
        candidate_commit,
        candidate_version,
        candidate_tag,
    )
    try:
        executing = Path(__file__).resolve(strict=True).read_bytes()
    except OSError as exception:
        raise RuntimeReportProofError("executing producer source cannot be read") from exception
    producer_relative = "scripts/create_release_runtime_test_reports_proof.py"
    if executing != candidate.source_payloads[producer_relative]:
        raise RuntimeReportProofError("executing producer differs from candidate producer")
    if (
        not isinstance(run_started_at_epoch_ns, int)
        or isinstance(run_started_at_epoch_ns, bool)
        or run_started_at_epoch_ns <= 0
    ):
        raise RuntimeReportProofError("runtime test start time is invalid")

    directory, descriptor, opened = validation._open_private_directory(
        evidence_directory, repository, "raw evidence directory"
    )
    proof_created = False
    try:
        if validation._directory_names(descriptor) != validation.RAW_REPORT_FILES:
            raise RuntimeReportProofError(
                "raw directory must initially contain only the three fixed reports"
            )
        maximums = {
            validation.PLAYWRIGHT_REPORT: validation.MAX_PLAYWRIGHT_BYTES,
            **{
                name: validation.MAX_SUREFIRE_BYTES
                for name in validation.SUREFIRE_TESTS
            },
        }
        before = {
            name: validation._snapshot_file(
                descriptor, name, maximums[name], f"raw {name}"
            )
            for name in sorted(validation.RAW_REPORT_FILES)
        }
        validation._validate_playwright(
            before[validation.PLAYWRIGHT_REPORT], repository, run_started_at_epoch_ns
        )
        for name in sorted(validation.SUREFIRE_TESTS):
            validation._validate_surefire(name, before[name], run_started_at_epoch_ns)
        validation._validate_directory_unchanged(directory, descriptor, opened)
        if validation._directory_names(descriptor) != validation.RAW_REPORT_FILES:
            raise RuntimeReportProofError("raw directory changed before proof creation")
        after = {
            name: validation._snapshot_file(
                descriptor, name, maximums[name], f"raw {name}"
            )
            for name in sorted(validation.RAW_REPORT_FILES)
        }
        if before != after:
            raise RuntimeReportProofError("raw reports changed before proof creation")

        final_candidate = validation._validate_candidate(
            repository,
            candidate_commit,
            candidate_version,
            candidate_tag,
        )
        if final_candidate != candidate:
            raise RuntimeReportProofError("candidate changed before proof creation")
        if validation._directory_names(descriptor) != validation.RAW_REPORT_FILES:
            raise RuntimeReportProofError("raw directory changed during candidate recheck")
        final_reports = {
            name: validation._snapshot_file(
                descriptor, name, maximums[name], f"raw {name}"
            )
            for name in sorted(validation.RAW_REPORT_FILES)
        }
        if before != final_reports:
            raise RuntimeReportProofError("raw reports changed during candidate recheck")

        document: dict[str, Any] = {
            "schemaVersion": 1,
            "candidate": {
                "commit": candidate.commit,
                "tree": candidate.tree,
                "version": candidate.version,
                "tag": candidate_tag,
                "tagObject": candidate.tag_object,
            },
            "runStartedAtEpochNs": run_started_at_epoch_ns,
            "reports": {
                name: {
                    "sha256": before[name].sha256,
                    "size": before[name].size,
                    "modifiedAtEpochNs": before[name].modified_ns,
                }
                for name in sorted(validation.RAW_REPORT_FILES)
            },
            "sources": dict(candidate.source_sha256),
        }
        payload = validation._canonical_json(document)
        if len(payload) > validation.MAX_PROOF_BYTES:
            raise RuntimeReportProofError("proof output is unexpectedly large")
        proof = _write_proof(descriptor, payload)
        proof_created = True
        if proof.payload != payload:
            raise RuntimeReportProofError("proof output readback differs")
        validation._validate_directory_unchanged(directory, descriptor, opened)
        if validation._directory_names(descriptor) != validation.RAW_BUNDLE_FILES:
            raise RuntimeReportProofError("raw directory changed during proof creation")
        for name, snapshot in before.items():
            current = validation._snapshot_file(
                descriptor, name, maximums[name], f"raw {name}"
            )
            if current != snapshot:
                raise RuntimeReportProofError("raw reports changed during proof write")
        if validation._snapshot_file(
            descriptor,
            validation.PROOF_FILE,
            validation.MAX_PROOF_BYTES,
            "runtime report proof",
        ) != proof:
            raise RuntimeReportProofError("proof output changed during final readback")
        return directory / validation.PROOF_FILE
    except Exception:
        if proof_created:
            try:
                os.unlink(validation.PROOF_FILE, dir_fd=descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--run-started-at-epoch-ns", required=True, type=int)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        create_proof(
            arguments.evidence_directory,
            repository_root=arguments.repository_root,
            candidate_commit=arguments.candidate_commit,
            candidate_version=arguments.candidate_version,
            candidate_tag=arguments.candidate_tag,
            run_started_at_epoch_ns=arguments.run_started_at_epoch_ns,
        )
    except (
        OSError,
        RuntimeReportProofError,
        validation.RuntimeReportValidationError,
    ) as exception:
        raise SystemExit(f"cannot create release runtime report proof: {exception}") from exception
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
