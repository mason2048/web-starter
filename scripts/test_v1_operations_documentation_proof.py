from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

import create_v1_operations_documentation_proof as producer
import validate_v1_operations_documentation_proof as validator


VERSION = "2.0.0"
TAG = "v2.0.0"


def run_git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class V1OperationsDocumentationProofTest(unittest.TestCase):
    def repository(self, root: Path, *, complete: bool = True) -> tuple[Path, str]:
        repository = root / "candidate"
        repository.mkdir()
        (repository / "web-starter-web").mkdir()
        (repository / "docs").mkdir()
        migrations = repository / "web-starter-admin/src/main/resources/db/migration"
        migrations.mkdir(parents=True)
        scripts = repository / "scripts"
        scripts.mkdir()
        security = repository / "security"
        security.mkdir()

        (repository / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            f"<groupId>dev.webstarter</groupId><artifactId>web-starter</artifactId>"
            f"<version>{VERSION}</version></project>\n",
            encoding="utf-8",
        )
        (repository / "web-starter-web/package.json").write_text(
            json.dumps({"name": "web-starter-web", "version": VERSION}),
            encoding="utf-8",
        )
        deployment = "\n".join((
            "## 日志与故障定位",
            "## 备份与恢复",
            "## 升级与回滚",
            "### RSA 签名密钥轮换与回退",
            "recovery-rehearsal.md compose.production.yaml WEB_STARTER_APP_DIGEST",
        ))
        if not complete:
            deployment = "## 日志与故障定位\n"
        (repository / "docs/deployment.md").write_text(deployment + "\n", encoding="utf-8")
        (repository / "docs/security.md").write_text(
            "### OAuth RSA 签名密钥轮换\n`exp` NumericDate `rev` "
            "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID\n",
            encoding="utf-8",
        )
        (repository / "docs/recovery-rehearsal.md").write_text(
            "recovery_backup.py recovery_restore.py rehearse_redis_loss.py V1—V2\n",
            encoding="utf-8",
        )
        (repository / "docs/v1-to-v2-upgrade-rehearsal.md").write_text(
            "rehearse_v1_to_v2_upgrade.py V1 tag\n",
            encoding="utf-8",
        )
        (migrations / "V1__one.sql").write_text("SELECT 1;\n", encoding="utf-8")
        (migrations / "V2__two.sql").write_text("SELECT 2;\n", encoding="utf-8")

        source_root = Path(producer.__file__).resolve().parents[1]
        for relative in (producer.PRODUCER_PATH, producer.VALIDATOR_PATH, producer.SCHEMA_PATH):
            target = repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_root / relative, target)

        run_git(repository, "init", "-q")
        run_git(repository, "config", "user.name", "Acceptance Test")
        run_git(repository, "config", "user.email", "acceptance@example.invalid")
        run_git(repository, "add", ".")
        run_git(repository, "commit", "-qm", "candidate")
        run_git(repository, "tag", "-a", TAG, "-m", "candidate")
        return repository, run_git(repository, "rev-parse", "HEAD")

    def create(self, root: Path, *, complete: bool = True) -> tuple[Path, Path, str]:
        repository, commit = self.repository(root, complete=complete)
        proof = producer.create_proof(
            repository,
            root / "private-proof",
            commit,
            TAG,
            VERSION,
        )
        return repository, proof, commit

    def test_status_free_proof_is_independently_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, proof, commit = self.create(Path(directory))

            raw = json.loads(proof.read_text(encoding="utf-8"))
            self.assertNotIn("status", raw)
            summary = validator.validate_proof(
                proof,
                repository_root=repository,
                expected_candidate_commit=commit,
                expected_candidate_tag=TAG,
                expected_candidate_version=VERSION,
            )

            self.assertEqual(["AC-38"], summary["acceptanceIds"])
            self.assertEqual("PASS", summary["status"])
            self.assertEqual([1, 2], summary["evidence"]["migrationVersions"])
            self.assertEqual(
                {"operationsDocumentationReview": "PASS", "sourceIntegrity": "PASS"},
                summary["checks"],
            )
            self.assertEqual(0o700, stat.S_IMODE(proof.parent.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(proof.stat().st_mode))

    def test_checksum_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, proof, commit = self.create(Path(directory))
            document = json.loads(proof.read_text(encoding="utf-8"))
            document["observations"]["migrationVersions"] = [1]
            proof.write_text(json.dumps(document), encoding="utf-8")
            proof.chmod(0o600)

            with self.assertRaisesRegex(validator.ProofValidationError, "checksum"):
                validator.validate_proof(
                    proof,
                    repository_root=repository,
                    expected_candidate_commit=commit,
                    expected_candidate_tag=TAG,
                    expected_candidate_version=VERSION,
                )

    def test_source_drift_is_rejected_even_when_raw_proof_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, proof, commit = self.create(Path(directory))
            (repository / "docs/deployment.md").write_text("drift\n", encoding="utf-8")

            with self.assertRaisesRegex(validator.ProofValidationError, "clean"):
                validator.validate_proof(
                    proof,
                    repository_root=repository,
                    expected_candidate_commit=commit,
                    expected_candidate_tag=TAG,
                    expected_candidate_version=VERSION,
                )

    def test_incomplete_operations_documentation_cannot_be_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, proof, commit = self.create(Path(directory), complete=False)

            with self.assertRaisesRegex(
                validator.ProofValidationError, "documentation is incomplete"
            ):
                validator.validate_proof(
                    proof,
                    repository_root=repository,
                    expected_candidate_commit=commit,
                    expected_candidate_tag=TAG,
                    expected_candidate_version=VERSION,
                )

    def test_canonical_summary_bytes_are_stable(self) -> None:
        summary = {
            "schemaVersion": 1,
            "status": "PASS",
            "acceptanceIds": ["AC-38"],
        }
        payload = validator.canonical_summary_bytes(summary)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            hashlib.sha256(validator.canonical_summary_bytes(summary)).hexdigest(),
        )
        self.assertTrue(payload.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
