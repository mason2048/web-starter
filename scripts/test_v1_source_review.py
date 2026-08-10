from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import create_v1_source_review_observation as producer
import run_v1_candidate_regression as regression
import v1_regression_supplemental_validators as validators


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class V1SourceReviewTest(unittest.TestCase):
    @staticmethod
    def current_sources() -> dict[str, bytes]:
        root = validators.REPOSITORY_ROOT
        paths = set(validators.SHARED_BOUNDARY_FIXED_PATHS)
        paths.update({"pom.xml", *(f"{module}/pom.xml" for module in validators.RUNTIME_MODULES)})
        paths.update(validators.OPERATIONS_REVIEW_PATHS)
        for module in validators.RUNTIME_MODULES:
            paths.update(
                path.relative_to(root).as_posix()
                for path in (root / module / "src/main/java").rglob("*.java")
                if path.is_file() and not path.is_symlink()
            )
        paths.update(
            path.relative_to(root).as_posix()
            for path in (
                root / "web-starter-admin/src/main/resources/db/migration"
            ).glob("V*__*.sql")
            if path.is_file() and not path.is_symlink()
        )
        return {relative: (root / relative).read_bytes() for relative in paths}

    def test_registry_and_candidate_source_inventories_are_fixed(self) -> None:
        self.assertEqual(
            {
                "supplemental.operationsDocumentationReview",
                "supplemental.projectIsolationReview",
            },
            set(validators.SOURCE_REVIEW_CHECKS),
        )
        self.assertEqual(
            {validators.SOURCE_REVIEW_PRODUCER},
            set(validators.PRODUCER_VALIDATORS),
        )

        tracked = {path: "a" * 40 for path in self.current_sources()}
        with patch.object(validators, "_tracked_candidate_files", return_value=tracked):
            shared = set(validators.source_review_paths(
                "supplemental.sharedProjectServiceBoundary", commit="b" * 40
            ))
            forbidden = set(validators.source_review_paths(
                "supplemental.forbiddenCapabilitySourceScan", commit="b" * 40
            ))
            operations = set(validators.source_review_paths(
                "supplemental.operationsDocumentationReview", commit="b" * 40
            ))
            isolation = set(validators.source_review_paths(
                "supplemental.projectIsolationReview", commit="b" * 40
            ))
        self.assertTrue(validators.SHARED_BOUNDARY_FIXED_PATHS <= shared)
        self.assertTrue(any(path.startswith("web-starter-mcp/src/main/java/") for path in shared))
        self.assertIn("pom.xml", forbidden)
        self.assertNotIn("web-starter-tooling/pom.xml", forbidden)
        self.assertIn("docs/deployment.md", operations)
        self.assertTrue(any("/db/migration/V1__" in path for path in operations))
        self.assertEqual(set(tracked), isolation)

    def test_four_source_semantics_pass_on_the_candidate_source(self) -> None:
        sources = self.current_sources()
        validators._validate_shared_project_service(sources)
        validators._validate_forbidden_capabilities(sources)
        validators._validate_operations_documentation(sources)

        tracked_sources = {
            relative: (validators.REPOSITORY_ROOT / relative).read_bytes()
            for relative in validators._tracked_candidate_files(
                validators.REPOSITORY_ROOT,
                validators._git(
                    validators.REPOSITORY_ROOT, "rev-parse", "HEAD^{commit}"
                ).decode("ascii").strip(),
            )
        }
        validators._validate_project_isolation(tracked_sources)

    def test_project_isolation_rejects_an_extra_business_module_or_foreign_package(self) -> None:
        sources = {
            relative: (validators.REPOSITORY_ROOT / relative).read_bytes()
            for relative in validators._tracked_candidate_files(
                validators.REPOSITORY_ROOT,
                validators._git(
                    validators.REPOSITORY_ROOT, "rev-parse", "HEAD^{commit}"
                ).decode("ascii").strip(),
            )
        }
        sources["copied-business/pom.xml"] = b"<project/>\n"
        with self.assertRaisesRegex(
            validators.SupplementalValidationError, "top-level inventory"
        ):
            validators._validate_project_isolation(sources)

        sources.pop("copied-business/pom.xml")
        sources["release/run.sh"] = b"#!/bin/sh\n"
        with self.assertRaisesRegex(
            validators.SupplementalValidationError, "release evidence inventory"
        ):
            validators._validate_project_isolation(sources)
        sources.pop("release/run.sh")

        current_release = "release/evidence/v2.0.0.json"
        self.assertIn(current_release, sources)
        sources["release/evidence/v2.0.1.json"] = sources[current_release]
        with self.assertRaisesRegex(
            validators.SupplementalValidationError, "identity differs"
        ):
            validators._validate_project_isolation(sources)
        sources.pop("release/evidence/v2.0.1.json")

        source_path = next(
            relative for relative in sources
            if relative.endswith(".java") and "/src/main/java/dev/webstarter/" in relative
        )
        payload = sources.pop(source_path)
        foreign_path = source_path.replace("/dev/webstarter/", "/org/example/", 1)
        sources[foreign_path] = payload
        with self.assertRaisesRegex(
            validators.SupplementalValidationError, "package boundary"
        ):
            validators._validate_project_isolation(sources)

    def test_strict_blob_validation_uses_immutable_commit_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "candidate"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            source = root / "source.txt"
            source.write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "add", "source.txt"], cwd=root, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Acceptance",
                    "-c", "user.email=acceptance@example.invalid",
                    "commit", "-qm", "candidate",
                ],
                cwd=root,
                check=True,
            )
            commit = git(root, "rev-parse", "HEAD^{commit}")
            payload = source.read_bytes()
            observations = {
                "schemaVersion": 1,
                "sourceBlobs": {
                    "source.txt": {
                        "gitBlob": git(root, "rev-parse", f"{commit}:source.txt"),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                },
            }
            accepted = validators._strict_sources(
                observations, ("source.txt",), root.resolve(), commit
            )
            self.assertEqual({"source.txt": b"committed\n"}, accepted)
            source.write_text("tampered\n", encoding="utf-8")
            accepted = validators._strict_sources(
                observations, ("source.txt",), root.resolve(), commit
            )
            self.assertEqual({"source.txt": b"committed\n"}, accepted)

            observations["sourceBlobs"]["source.txt"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(validators.SupplementalValidationError, "blob differs"):
                validators._strict_sources(
                    observations, ("source.txt",), root.resolve(), commit
                )

    def test_candidate_binding_requires_an_annotated_tag_and_clean_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "candidate"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "README.md").write_text("candidate\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Acceptance",
                    "-c", "user.email=acceptance@example.invalid",
                    "commit", "-qm", "candidate",
                ],
                cwd=root,
                check=True,
            )
            commit = git(root, "rev-parse", "HEAD^{commit}")
            subprocess.run(
                [
                    "git", "-c", "user.name=Acceptance",
                    "-c", "user.email=acceptance@example.invalid",
                    "tag", "-a", "v1.2.3", "-m", "candidate",
                ],
                cwd=root,
                check=True,
            )
            digest = "sha256:" + "a" * 64
            manifest = Path(directory) / "candidate.json"
            manifest.write_text(json.dumps({
                "schemaVersion": 1,
                "release": {"tag": "v1.2.3", "version": "1.2.3", "gitCommit": commit},
                "images": {
                    name: {"reference": f"registry.invalid/web-starter-{name}", "digest": digest}
                    for name in ("app", "nginx", "mysql", "redis")
                },
            }), encoding="utf-8")
            candidate_root = root.resolve()
            binding = producer._candidate_binding(candidate_root, manifest)
            self.assertEqual(commit, binding["gitCommit"])
            self.assertEqual(git(root, "rev-parse", "HEAD^{tree}"), binding["gitTree"])
            self.assertEqual("v1.2.3", binding["releaseTag"])
            self.assertEqual("1.2.3", binding["releaseVersion"])
            validators._verify_candidate_root(binding, candidate_root)

            invalid_binding = dict(binding)
            invalid_binding["releaseVersion"] = "1.2.3-SNAPSHOT"
            invalid_binding["releaseTag"] = "v1.2.3-SNAPSHOT"
            with self.assertRaisesRegex(validators.SupplementalValidationError, "malformed"):
                validators._verify_candidate_root(invalid_binding, candidate_root)

            subprocess.run(["git", "tag", "-d", "v1.2.3"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "tag", "v1.2.3"], cwd=root, check=True)
            with self.assertRaisesRegex(producer.SourceReviewProducerError, "annotated"):
                producer._candidate_binding(candidate_root, manifest)

    def test_git_environment_injection_is_ignored_and_tracked_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "candidate"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "source.txt").write_text("source\n", encoding="utf-8")
            (root / "link.txt").symlink_to("source.txt")
            subprocess.run(["git", "add", "source.txt", "link.txt"], cwd=root, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Acceptance",
                    "-c", "user.email=acceptance@example.invalid",
                    "commit", "-qm", "candidate",
                ],
                cwd=root,
                check=True,
            )
            commit = git(root, "rev-parse", "HEAD^{commit}")
            with patch.dict(os.environ, {
                "GIT_DIR": str(Path(directory) / "missing"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
            }, clear=False):
                self.assertEqual(
                    commit,
                    validators._git(root.resolve(), "rev-parse", "HEAD^{commit}")
                    .decode("ascii").strip(),
                )
                with self.assertRaisesRegex(
                    validators.SupplementalValidationError, "non-regular"
                ):
                    validators._tracked_candidate_files(root.resolve(), commit)

    def test_operations_observation_runs_end_to_end_without_trusting_a_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            root = temporary / "candidate"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            content = {
                "docs/deployment.md": "\n".join((
                    "## 日志与故障定位", "## 备份与恢复", "## 升级与回滚",
                    "### RSA 签名密钥轮换与回退", "recovery-rehearsal.md",
                    "compose.production.yaml", "WEB_STARTER_APP_DIGEST",
                )),
                "docs/security.md": (
                    "### OAuth RSA 签名密钥轮换\n`exp` NumericDate\n`rev`\n"
                    "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID\n"
                ),
                "docs/recovery-rehearsal.md": (
                    "recovery_backup.py recovery_restore.py rehearse_redis_loss.py V1—V1\n"
                ),
                "docs/v1-to-v2-upgrade-rehearsal.md": (
                    "rehearse_v1_to_v2_upgrade.py V1 tag\n"
                ),
                "scripts/recovery_backup.py": "def create_backup():\n    pass\n",
                "scripts/recovery_restore.py": "def restore():\n    pass\n",
                "scripts/rehearse_redis_loss.py": "def rehearse():\n    pass\n",
                "scripts/rehearse_v1_to_v2_upgrade.py": "def rehearse():\n    pass\n",
                "compose.production.yaml": "services: {}\n",
                "web-starter-admin/src/main/resources/db/migration/V1__baseline.sql": "-- baseline\n",
            }
            for relative, value in content.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value, encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Acceptance",
                    "-c", "user.email=acceptance@example.invalid",
                    "commit", "-qm", "candidate",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Acceptance",
                    "-c", "user.email=acceptance@example.invalid",
                    "tag", "-a", "v2.0.0", "-m", "candidate",
                ],
                cwd=root,
                check=True,
            )
            commit = git(root, "rev-parse", "HEAD^{commit}")
            tree = git(root, "rev-parse", "HEAD^{tree}")
            digest = "sha256:" + "a" * 64
            manifest = temporary / "candidate.json"
            manifest.write_text(json.dumps({
                "schemaVersion": 1,
                "release": {"tag": "v2.0.0", "version": "2.0.0", "gitCommit": commit},
                "images": {
                    name: {"reference": f"registry.invalid/web-starter-{name}", "digest": digest}
                    for name in ("app", "nginx", "mysql", "redis")
                },
            }), encoding="utf-8")
            output = temporary / "source-review"
            with patch.object(
                validators,
                "SOURCE_REVIEW_CHECKS",
                frozenset({"supplemental.operationsDocumentationReview"}),
            ):
                observation = producer.create_bundle(root.resolve(), manifest, output)
            archive = subprocess.run(
                ["git", "archive", "--format=tar", commit],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            identity = {
                "gitCommit": commit,
                "gitTree": tree,
                "sourceArchiveSha256": hashlib.sha256(archive).hexdigest(),
                "releaseTag": "v2.0.0",
                "releaseVersion": "2.0.0",
            }
            checks: dict[str, str] = {}
            sources: dict[str, dict[str, object]] = {}
            with patch.object(validators, "REPOSITORY_ROOT", root.resolve()):
                regression._load_observations(
                    [observation],
                    hashlib.sha256(manifest.read_bytes()).hexdigest(),
                    identity,
                    set(validators.SOURCE_REVIEW_CHECKS),
                    checks,
                    sources,
                )
            self.assertEqual(
                {"supplemental.operationsDocumentationReview": "PASS"}, checks
            )
            self.assertEqual(
                {"candidate-source-review"},
                {value["producer"] for value in sources.values()},
            )


if __name__ == "__main__":
    unittest.main()
