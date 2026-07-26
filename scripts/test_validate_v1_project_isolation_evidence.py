from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import repository_policy
import validate_v1_project_isolation_evidence as evidence


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class V1ProjectIsolationEvidenceTest(unittest.TestCase):
    def test_reference_fingerprint_covers_dirty_index_worktree_and_untracked_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "reference"
            root.mkdir()
            git(root, "init", "-q")
            git(root, "config", "user.name", "Web Starter Test")
            git(root, "config", "user.email", "web-starter@example.test")
            (root / "tracked.txt").write_text("one\n", encoding="utf-8")
            git(root, "add", "tracked.txt")
            git(root, "commit", "-qm", "initial")
            clean = evidence._reference_identity(root)

            (root / "tracked.txt").write_text("two\n", encoding="utf-8")
            (root / "untracked.txt").write_text("three\n", encoding="utf-8")
            dirty = evidence._reference_identity(root)
            self.assertNotEqual(clean, dirty)
            self.assertEqual(1, dirty["untrackedCount"])

            git(root, "add", "tracked.txt")
            staged = evidence._reference_identity(root)
            self.assertNotEqual(dirty["index"], staged["index"])
            self.assertNotEqual(
                evidence._reference_aggregate(clean),
                evidence._reference_aggregate(staged),
            )

    def test_forbidden_term_file_requires_effective_utf8_without_controls(self) -> None:
        valid = evidence.PrivateFileSnapshot(
            b"# protected\nBusiness Name\nABC\nbusiness name\n",
            1,
            2,
            45,
            3,
            0o600,
            os.getuid(),
            1,
        )
        self.assertEqual(["Business Name", "ABC"], evidence._forbidden_terms(valid))
        empty = evidence.PrivateFileSnapshot(
            b"# only comment\n", 1, 2, 15, 3, 0o600, os.getuid(), 1
        )
        with self.assertRaisesRegex(
            evidence.ProjectIsolationEvidenceError, "no effective terms"
        ):
            evidence._forbidden_terms(empty)
        control = evidence.PrivateFileSnapshot(
            b"term\x00value\n", 1, 2, 11, 3, 0o600, os.getuid(), 1
        )
        with self.assertRaisesRegex(
            evidence.ProjectIsolationEvidenceError, "control character"
        ):
            evidence._forbidden_terms(control)

    def test_evaluate_recomputes_all_three_ac40_conditions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            candidate = temporary / "candidate"
            reference = temporary / "reference"
            private = temporary / "private"
            for path in (candidate, reference, private):
                path.mkdir()
                git(path, "init", "-q")
            terms = private / "terms.txt"
            terms.write_text("External Business Term\n", encoding="utf-8")
            terms.chmod(0o600)
            schema = {
                "$id": "https://webstarter.dev/schema/"
                "v1-ac40-project-isolation-summary.schema.json"
            }
            sources = {
                evidence.SCHEMA_PATH: json.dumps(schema).encode("utf-8"),
                "web-starter-core/src/main/java/dev/webstarter/core/Foo.java": (
                    b"package dev.webstarter.core;\n"
                ),
            }
            for relative, payload in sources.items():
                path = candidate / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            scan_inputs = [
                repository_policy.ScanInput(relative, candidate / relative)
                for relative in sources
            ]
            candidate_identity = {
                "commit": "a" * 40,
                "tree": "b" * 40,
                "tag": "v2.0.0",
                "version": "2.0.0",
                "sourceArchiveSha256": "c" * 64,
            }
            reference_identity = {
                "head": "1" * 64,
                "status": "2" * 64,
                "worktree": "3" * 64,
                "index": "4" * 64,
                "untracked": "5" * 64,
                "untrackedCount": 0,
            }
            with (
                patch.object(evidence, "_exact_repository_root", side_effect=[candidate, reference]),
                patch.object(evidence, "_candidate", return_value=candidate_identity) as candidate_check,
                patch.object(
                    evidence,
                    "_candidate_sources",
                    return_value=(sources, "d" * 64),
                ),
                patch.object(
                    evidence,
                    "_reference_identity",
                    side_effect=[reference_identity, reference_identity],
                ),
                patch.object(
                    evidence.repository_policy,
                    "repository_candidates",
                    return_value=scan_inputs,
                ),
            ):
                summary = evidence.evaluate(
                    repository_root=candidate,
                    forbidden_terms_path=terms,
                    reference_repository=reference,
                    expected_candidate_commit="a" * 40,
                    expected_candidate_tag="v2.0.0",
                    expected_candidate_version="2.0.0",
                )
            self.assertEqual("PASS", summary["status"])
            self.assertEqual(
                {
                    "forbiddenTermScan": "PASS",
                    "projectIsolationReview": "PASS",
                    "referenceRepositoryUnchanged": "PASS",
                    "sourceIntegrity": "PASS",
                },
                summary["checks"],
            )
            self.assertEqual(
                hashlib.sha256(terms.read_bytes()).hexdigest(),
                summary["evidence"]["forbiddenTermsSha256"],
            )
            self.assertEqual(2, candidate_check.call_count)

    def test_evaluate_rejects_reference_repository_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            candidate = temporary / "candidate"
            reference = temporary / "reference"
            private = temporary / "private"
            for path in (candidate, reference, private):
                path.mkdir()
                git(path, "init", "-q")
            terms = private / "terms.txt"
            terms.write_text("External Business Term\n", encoding="utf-8")
            terms.chmod(0o600)
            schema_payload = json.dumps({
                "$id": "https://webstarter.dev/schema/"
                "v1-ac40-project-isolation-summary.schema.json"
            }).encode("utf-8")
            schema_path = candidate / evidence.SCHEMA_PATH
            schema_path.parent.mkdir(parents=True)
            schema_path.write_bytes(schema_payload)
            sources = {evidence.SCHEMA_PATH: schema_payload}
            scan_inputs = [
                repository_policy.ScanInput(evidence.SCHEMA_PATH, schema_path)
            ]
            before = {
                "head": "1" * 64,
                "status": "2" * 64,
                "worktree": "3" * 64,
                "index": "4" * 64,
                "untracked": "5" * 64,
                "untrackedCount": 0,
            }
            after = dict(before, status="6" * 64)
            with (
                patch.object(evidence, "_exact_repository_root", side_effect=[candidate, reference]),
                patch.object(
                    evidence,
                    "_candidate",
                    return_value={
                        "commit": "a" * 40,
                        "tree": "b" * 40,
                        "tag": "v2.0.0",
                        "version": "2.0.0",
                        "sourceArchiveSha256": "c" * 64,
                    },
                ),
                patch.object(
                    evidence,
                    "_candidate_sources",
                    return_value=(sources, "d" * 64),
                ),
                patch.object(
                    evidence,
                    "_reference_identity",
                    side_effect=[before, after],
                ),
                patch.object(
                    evidence.repository_policy,
                    "repository_candidates",
                    return_value=scan_inputs,
                ),
            ):
                with self.assertRaisesRegex(
                    evidence.ProjectIsolationEvidenceError,
                    "changed during project-isolation evaluation",
                ):
                    evidence.evaluate(
                        repository_root=candidate,
                        forbidden_terms_path=terms,
                        reference_repository=reference,
                        expected_candidate_commit="a" * 40,
                        expected_candidate_tag="v2.0.0",
                        expected_candidate_version="2.0.0",
                    )

    def test_summary_writer_is_exclusive_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / evidence.SUMMARY_NAME
            payload = b'{"status":"PASS"}\n'
            evidence._write_summary(output, payload)
            self.assertEqual(payload, output.read_bytes())
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            with self.assertRaisesRegex(
                evidence.ProjectIsolationEvidenceError, "destination is unsafe"
            ):
                evidence._write_summary(output, payload)


if __name__ == "__main__":
    unittest.main()
