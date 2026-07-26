from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import create_v1_source_provenance_proof as producer
import validate_v1_source_provenance_proof as validator


SOURCE_ROOT = Path(__file__).resolve().parents[1]


def git(root: Path, *arguments: str, input_text: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


class V1SourceFixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.repository = base / "candidate"
        subprocess.run(
            ["git", "clone", "--quiet", "--no-local", str(SOURCE_ROOT), str(self.repository)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(self.repository, "config", "user.name", "V1 Provenance Test")
        git(self.repository, "config", "user.email", "v1-provenance@example.invalid")
        git(self.repository, "checkout", "-q", "-B", "v2-candidate", producer.V1_COMMIT)
        for relative in producer.SOURCE_PATHS:
            source = SOURCE_ROOT / relative
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == producer.ROOT_POM_PATH:
                payload = source.read_text(encoding="utf-8").replace(
                    "<version>2.0.0-SNAPSHOT</version>", "<version>2.0.0</version>", 1
                )
                if "<version>2.0.0</version>" not in payload:
                    payload = payload.replace(
                        "<version>1.0.0</version>", "<version>2.0.0</version>", 1
                    )
                target.write_text(payload, encoding="utf-8")
            elif relative == producer.FRONTEND_MANIFEST_PATH:
                document = json.loads(source.read_text(encoding="utf-8"))
                document["version"] = "2.0.0"
                target.write_text(
                    json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            else:
                shutil.copyfile(source, target)
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-q", "-m", "V2 provenance candidate")
        if "v2.0.0" in git(self.repository, "tag", "--list", "v2.0.0").splitlines():
            git(self.repository, "tag", "-d", "v2.0.0")
        git(self.repository, "tag", "-a", "v2.0.0", "-m", "V2 test candidate")
        self.commit = git(self.repository, "rev-parse", "HEAD^{commit}")
        self.raw = base / "raw"
        self.raw.mkdir(mode=0o700)
        self.summary_dir = base / "summary"
        self.summary_dir.mkdir(mode=0o700)
        self.summary = self.summary_dir / validator.SUMMARY_NAME

    @property
    def report(self) -> Path:
        return self.raw / producer.RESULT_NAME

    def create(self) -> dict:
        return producer.create_proof(
            self.repository,
            self.raw,
            expected_candidate_commit=self.commit,
            expected_candidate_version="2.0.0",
            expected_candidate_tag="v2.0.0",
        )

    def validate(self) -> dict:
        return validator.validate_proof(
            self.report,
            self.repository,
            expected_candidate_commit=self.commit,
            expected_candidate_version="2.0.0",
            expected_candidate_tag="v2.0.0",
            require_pass=True,
        )


class V1SourceProvenanceEvidenceTest(unittest.TestCase):
    def test_producer_and_independent_validator_bind_exact_frozen_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            raw = fixture.create()
            summary = fixture.validate()
            validator.write_canonical_summary(fixture.summary, summary)

            self.assertNotIn("status", raw)
            self.assertEqual("PASS", summary["status"])
            self.assertEqual(42, summary["v1Source"]["acceptanceResultCount"])
            self.assertEqual(42, summary["v1Source"]["acceptancePassCount"])
            self.assertEqual(37, summary["v1Source"]["baselineP0Count"])
            self.assertEqual(5, summary["v1Source"]["baselineP1Count"])
            self.assertEqual(12, summary["v1Source"]["automationCheckCount"])
            self.assertEqual(5, summary["v1Source"]["finalCheckedCount"])
            self.assertEqual(
                "TAGGED_RECORD_ONLY", summary["v1Source"]["historicalExecutionTrust"]
            )
            self.assertEqual(
                "NOT_CLAIMED", summary["checks"]["currentCandidateV1Regression"]
            )
            self.assertEqual(
                "NOT_REVALIDATED", summary["checks"]["historicalRuntimeArtifacts"]
            )
            self.assertEqual(0o700, stat.S_IMODE(fixture.raw.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(fixture.report.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(fixture.summary.stat().st_mode))
            self.assertEqual(
                validator.canonical_summary_bytes(summary), fixture.summary.read_bytes()
            )

    def test_exact_v1_tag_commit_tree_annotation_archive_and_document_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            summary = fixture.validate()["v1Source"]

            self.assertEqual(producer.V1_TAG_OBJECT, summary["tagObject"])
            self.assertEqual(producer.V1_COMMIT, summary["commit"])
            self.assertEqual(producer.V1_TREE, summary["tree"])
            self.assertEqual(producer.V1_ARCHIVE_SHA256, summary["sourceArchiveSha256"])
            self.assertEqual(producer.V1_BASELINE_SHA256, summary["baselineSha256"])
            self.assertEqual(producer.V1_RECORD_SHA256, summary["acceptanceRecordSha256"])

    def test_dirty_or_snapshot_candidate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            (fixture.repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(producer.ProofCreationError, "candidate must be clean"):
                fixture.create()
            (fixture.repository / "untracked.txt").unlink()
            with self.assertRaisesRegex(producer.ProofCreationError, "malformed"):
                producer.create_proof(
                    fixture.repository,
                    fixture.raw,
                    expected_candidate_commit=fixture.commit,
                    expected_candidate_version="2.0.0-SNAPSHOT",
                    expected_candidate_tag="v2.0.0-SNAPSHOT",
                )

    def test_lightweight_or_retargeted_v1_tag_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            git(fixture.repository, "tag", "-d", producer.V1_TAG)
            git(fixture.repository, "tag", producer.V1_TAG, producer.V1_COMMIT)
            with self.assertRaisesRegex(validator.ProofValidationError, "annotated tag"):
                fixture.validate()

        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            git(fixture.repository, "tag", "-d", producer.V1_TAG)
            git(
                fixture.repository,
                "tag", "-a", producer.V1_TAG, fixture.commit, "-m", producer.V1_ANNOTATION,
            )
            with self.assertRaisesRegex(validator.ProofValidationError, "object, commit or tree"):
                fixture.validate()

    def test_candidate_must_descend_from_fixed_v1_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            original = producer._git_result

            def reject_ancestry(repository: Path, *arguments: str):
                result = original(repository, *arguments)
                if arguments[:2] == ("merge-base", "--is-ancestor"):
                    return subprocess.CompletedProcess(result.args, 1, b"", b"")
                return result

            with mock.patch.object(producer, "_git_result", side_effect=reject_ancestry):
                with self.assertRaisesRegex(producer.ProofCreationError, "not a descendant"):
                    fixture.create()

    def test_ambient_git_config_object_index_and_worktree_injection_is_dropped(self) -> None:
        poison = {
            "GIT_DIR": "/poison/git",
            "GIT_COMMON_DIR": "/poison/common",
            "GIT_WORK_TREE": "/poison/worktree",
            "GIT_INDEX_FILE": "/poison/index",
            "GIT_OBJECT_DIRECTORY": "/poison/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/poison/alternates",
            "GIT_CONFIG_GLOBAL": "/poison/global",
            "GIT_CONFIG_SYSTEM": "/poison/system",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/poison/hooks",
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            with mock.patch.dict(os.environ, poison, clear=False):
                fixture.create()
                self.assertEqual("PASS", fixture.validate()["status"])
                for environment in (producer._git_environment(), validator._git_environment()):
                    self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
                    self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
                    self.assertEqual(os.devnull, environment["GIT_CONFIG_SYSTEM"])
                    self.assertEqual("0", environment["GIT_CONFIG_COUNT"])
                    self.assertEqual("1", environment["GIT_NO_REPLACE_OBJECTS"])
                    for name in poison:
                        if name not in {
                            "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT"
                        }:
                            self.assertNotIn(name, environment)

    def test_checksum_mode_and_exact_two_file_contract_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            checksum = fixture.raw / producer.CHECKSUM_NAME
            checksum.write_text("0" * 64 + f"  {producer.RESULT_NAME}\n", encoding="ascii")
            checksum.chmod(0o600)
            with self.assertRaisesRegex(validator.ProofValidationError, "checksum"):
                fixture.validate()

        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            fixture.report.chmod(0o644)
            with self.assertRaisesRegex(validator.ProofValidationError, "mode 0600"):
                fixture.validate()

        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            (fixture.raw / "extra.txt").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(validator.ProofValidationError, "exact report/checksum"):
                fixture.validate()

    def test_producer_observations_cannot_self_upgrade_or_change_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            document = json.loads(fixture.report.read_text(encoding="utf-8"))
            document["observations"]["scope"] = "CURRENT_CANDIDATE_REGRESSION"
            payload = (
                json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            fixture.report.write_bytes(payload)
            fixture.report.chmod(0o600)
            (fixture.raw / producer.CHECKSUM_NAME).write_text(
                f"{hashlib.sha256(payload).hexdigest()}  {producer.RESULT_NAME}\n",
                encoding="ascii",
            )
            (fixture.raw / producer.CHECKSUM_NAME).chmod(0o600)
            with self.assertRaisesRegex(validator.ProofValidationError, "observations differ"):
                fixture.validate()

    def test_historical_record_requires_all_pass_automation_and_checked_conclusion(self) -> None:
        payload = producer._git(
            SOURCE_ROOT, "show", f"{producer.V1_COMMIT}:{producer.V1_RECORD_PATH}"
        )
        for old, new, message in (
            (b"| AC-01 | PASS |", b"| AC-01 | FAIL |", "42 PASS"),
            ("| 前端 lint | `pnpm lint` | PASS |".encode(),
             "| 前端 lint | `pnpm lint` | FAIL |".encode(), "automation"),
            ("- [x] 所有 P0 均为 PASS。".encode(),
             "- [ ] 所有 P0 均为 PASS。".encode(), "final conclusion"),
        ):
            mutated = payload.replace(old, new, 1)
            with mock.patch.object(validator, "V1_RECORD_SHA256", hashlib.sha256(mutated).hexdigest()):
                with self.assertRaisesRegex(validator.ProofValidationError, message):
                    validator._parse_record(mutated)

    def test_canonical_summary_is_exclusive_named_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = V1SourceFixture(Path(directory))
            fixture.create()
            summary = fixture.validate()
            with self.assertRaisesRegex(validator.ProofValidationError, "must be named"):
                validator.write_canonical_summary(fixture.summary_dir / "wrong.json", summary)
            validator.write_canonical_summary(fixture.summary, summary)
            with self.assertRaisesRegex(validator.ProofValidationError, "must not already exist"):
                validator.write_canonical_summary(fixture.summary, summary)
            self.assertEqual(0o600, stat.S_IMODE(fixture.summary.stat().st_mode))


if __name__ == "__main__":
    unittest.main()
