from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import validate_redis_loss_evidence as validator
from scripts import rehearse_redis_loss as producer


class RedisLossEvidenceValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "candidate"
        self.repository.mkdir()
        self.compose_file = "compose.production.yaml"
        content = {
            validator.TOOL_PATH: "# formal AC-41 producer\n",
            validator.COMMON_PATH: "# recovery safety primitives\n",
            validator.VALIDATOR_PATH: "# independent AC-41 validator\n",
            validator.SCHEMA_PATH: "{}\n",
            validator.MAVEN_PATH: (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                "  <modelVersion>4.0.0</modelVersion>\n"
                "  <groupId>dev.webstarter</groupId>\n"
                "  <artifactId>web-starter</artifactId>\n"
                "  <version>2.0.0-rc.1</version>\n"
                "</project>\n"
            ),
            validator.FRONTEND_PATH: '{"name":"web-starter-web","version":"2.0.0-rc.1"}\n',
            self.compose_file: "services:\n  app:\n    image: example.invalid/app@sha256:00\n",
        }
        for relative, value in content.items():
            path = self.repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
        self._git("init", "-q")
        self._git("config", "user.name", "AC41 Test")
        self._git("config", "user.email", "ac41@example.invalid")
        self._git("add", ".")
        self._git("commit", "-q", "-m", "candidate")

        self.expected_images: dict[str, dict[str, str]] = {}
        # Keep formatting explicit: the digest after each colon must be exactly 64 hex digits.
        for index, service in enumerate(validator.SERVICES, start=1):
            self.expected_images[service] = {
                "reference": (
                    f"registry.example.invalid/web-starter/{service}@sha256:{index:x}" + "0" * 63
                ),
                "imageId": f"sha256:{index + 4:x}" + "0" * 63,
            }

        self.document = self._document()
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir(mode=0o700)
        os.chmod(self.evidence_dir, 0o700)
        self.report = self.evidence_dir / "v2-ac41-redis-loss.json"
        self._write_report(self.document)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return completed.stdout.strip()

    def _document(self) -> dict[str, object]:
        commit = self._git("rev-parse", "HEAD^{commit}")
        tree = self._git("rev-parse", "HEAD^{tree}")
        source_paths = set(validator.FIXED_SOURCE_FILES) | {self.compose_file}
        source_hashes = {
            relative: hashlib.sha256((self.repository / relative).read_bytes()).hexdigest()
            for relative in source_paths
        }
        services: dict[str, object] = {}
        for index, service in enumerate(validator.SERVICES, start=1):
            expected = self.expected_images[service]
            services[service] = {
                "containerId": f"{index + 8:x}" + "0" * 63,
                "project": "web-starter-ac41-test",
                "composeReference": expected["reference"],
                "containerReference": expected["reference"],
                "expectedReference": expected["reference"],
                "imageId": expected["imageId"],
                "expectedImageId": expected["imageId"],
                "ociVersion": "2.0.0-rc.1" if service in validator.OCI_SERVICES else None,
                "ociRevision": commit if service in validator.OCI_SERVICES else None,
            }
        fingerprints = {
            "business": "a" * 64,
            "rbac": "b" * 64,
            "credential_hashes": "c" * 64,
        }
        return {
            "schemaVersion": 1,
            "acceptanceId": "V2-AC-41",
            "mode": "formal",
            "status": "PASS",
            "executedAtUtc": "2026-07-20T01:02:03Z",
            "candidate": {
                "gitCommit": commit,
                "gitTree": tree,
                "cleanWorktree": True,
                "mavenVersion": "2.0.0-rc.1",
                "frontendVersion": "2.0.0-rc.1",
                "sourceSha256": source_hashes,
            },
            "compose": {
                "project": "web-starter-ac41-test",
                "files": [self.compose_file],
                "baseUrl": "https://mcp.ac41.webstarter.test:18443",
                "mysqlDatabase": "web_starter",
            },
            "runtime": {
                "services": services,
                "java": {
                    "specificationVersion": "21",
                    "runtimeVersion": "21.0.8+9-LTS",
                },
            },
            "isolation": {
                "volumes": {
                    "mysql": {
                        "name": "web-starter-ac41-test_mysql-data",
                        "destination": "/var/lib/mysql",
                        "projectLabel": "web-starter-ac41-test",
                        "composeVolumeLabel": "mysql-data",
                        "driver": "local",
                        "external": False,
                    },
                    "redis": {
                        "name": "web-starter-ac41-test_redis-data",
                        "destination": "/data",
                        "projectLabel": "web-starter-ac41-test",
                        "composeVolumeLabel": "redis-data",
                        "driver": "local",
                        "external": False,
                    },
                },
                "volumeDeletionPerformed": False,
                "containerDeletionPerformed": False,
                "projectDeletionPerformed": False,
            },
            "redis": {
                "database": 3,
                "keysBefore": 2,
                "command": "FLUSHDB",
                "result": "OK",
                "keysImmediatelyAfterFlush": 0,
            },
            "webSession": {
                "authenticatedBeforeLoss": True,
                "beforeLossMeStatus": 200,
                "oldSessionStatusAfterLoss": 401,
                "reloginSucceeded": True,
                "reloginMeStatus": 200,
                "reloginAttempts": 1,
            },
            "mysqlFacts": {
                "fingerprintsBefore": fingerprints,
                "fingerprintsAfter": dict(fingerprints),
            },
            "audit": {
                "rowsBefore": {
                    "sys_login_log": 10,
                    "sys_operation_log": 20,
                    "sys_mcp_call_log": 30,
                },
                "rowsAfter": {
                    "sys_login_log": 11,
                    "sys_operation_log": 20,
                    "sys_mcp_call_log": 30,
                },
            },
            "safety": {
                "redisScope": "SELECTED_DATABASE_ONLY",
                "flushAllExecuted": False,
                "volumeDeletionPerformed": False,
                "containerDeletionPerformed": False,
                "projectDeletionPerformed": False,
            },
        }

    def _write_report(self, document: object, *, update_checksum: bool = True) -> None:
        encoded = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.report.write_text(encoded, encoding="utf-8")
        os.chmod(self.report, 0o600)
        checksum = Path(str(self.report) + ".sha256")
        if update_checksum:
            digest = hashlib.sha256(self.report.read_bytes()).hexdigest()
            checksum.write_text(f"{digest}  {self.report.name}\n", encoding="ascii")
            os.chmod(checksum, 0o600)

    def _validate(self, expected_images: dict[str, dict[str, str]] | None = None) -> dict[str, object]:
        return validator.validate_document_path(
            self.report,
            repository_root=self.repository,
            expected_images=expected_images or self.expected_images,
        )

    def test_valid_formal_pass_is_bound_to_candidate_and_expected_images(self) -> None:
        summary = self._validate()
        self.assertEqual("PASS", summary["status"])
        self.assertEqual(self.document["candidate"]["gitCommit"], summary["gitCommit"])

    def test_relogin_uses_new_clients_with_a_bounded_retry_window(self) -> None:
        outcomes: list[object] = [
            producer.RecoveryError("session store is recovering"),
            producer.RecoveryError("session store is still recovering"),
            200,
        ]
        constructed: list[str] = []
        sleeps: list[float] = []

        class Client:
            def __init__(self, base_url: str):
                constructed.append(base_url)

            def login(self, _username: str, _password: str) -> int:
                outcome = outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return int(outcome)

        status, attempts = producer.relogin_after_redis_loss(
            "http://127.0.0.1:18088",
            "release_admin",
            "private-test-value",
            client_factory=Client,
            sleeper=sleeps.append,
        )

        self.assertEqual(200, status)
        self.assertEqual(3, attempts)
        self.assertEqual(3, len(constructed))
        self.assertEqual([1.0, 1.0], sleeps)

    def test_formal_base_url_uses_the_isolated_public_https_ingress(self) -> None:
        class Context:
            def run(self, arguments: list[str]):
                self.arguments = arguments
                return SimpleNamespace(stdout=b"0.0.0.0:18443\n")

        context = Context()
        with mock.patch.dict(os.environ, {
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": "mcp.ac41.webstarter.test",
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS": "127.0.0.1",
        }, clear=False):
            value = producer._validated_base_url(
                context,
                "https://mcp.ac41.webstarter.test:18443",
                formal=True,
            )

        self.assertEqual("https://mcp.ac41.webstarter.test:18443", value)
        self.assertEqual(["port", "mcp-public-nginx", "8443"], context.arguments)

    def test_formal_base_url_rejects_private_http_even_on_loopback(self) -> None:
        with self.assertRaisesRegex(producer.RecoveryError, "reserved HTTPS"):
            producer._validated_base_url(
                mock.Mock(),
                "http://127.0.0.1:18088",
                formal=True,
            )

    def test_formal_evidence_rejects_non_https_session_origins(self) -> None:
        for value in (
            "http://127.0.0.1:18088",
            "https://example.com:18443",
            "https://mcp.ac41.webstarter.test",
        ):
            with self.subTest(value=value):
                invalid = copy.deepcopy(self.document)
                invalid["compose"]["baseUrl"] = value
                self._write_report(invalid)
                with self.assertRaisesRegex(
                    validator.RedisLossEvidenceError,
                    "compose.baseUrl",
                ):
                    self._validate()

    def test_relogin_persistent_failure_remains_blocking(self) -> None:
        class FailingClient:
            def __init__(self, _base_url: str):
                pass

            def login(self, _username: str, _password: str) -> int:
                raise producer.RecoveryError("session store is unavailable")

        with self.assertRaisesRegex(producer.RecoveryError, "within 3 attempts"):
            producer.relogin_after_redis_loss(
                "http://127.0.0.1:18088",
                "release_admin",
                "private-test-value",
                max_attempts=3,
                retry_delay_seconds=0,
                client_factory=FailingClient,
                sleeper=lambda _seconds: None,
            )

    def test_relogin_attempt_evidence_is_bounded(self) -> None:
        for value in (0, 6, True):
            with self.subTest(value=value):
                invalid = copy.deepcopy(self.document)
                invalid["webSession"]["reloginAttempts"] = value
                self._write_report(invalid)
                with self.assertRaisesRegex(
                    validator.RedisLossEvidenceError,
                    "webSession.reloginAttempts",
                ):
                    self._validate()

    def test_self_reported_pass_without_exact_evidence_is_rejected(self) -> None:
        self._write_report({"status": "PASS"})
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "fields are not exact"):
            self._validate()

    def test_diagnostic_result_can_never_validate_as_formal_pass(self) -> None:
        diagnostic = copy.deepcopy(self.document)
        diagnostic["mode"] = "diagnostic"
        diagnostic["status"] = "DIAGNOSTIC"
        self._write_report(diagnostic)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "not a formal"):
            self._validate()

    def test_internally_consistent_forged_source_hashes_are_rejected(self) -> None:
        forged = copy.deepcopy(self.document)
        forged["candidate"]["sourceSha256"] = {
            key: "f" * 64 for key in forged["candidate"]["sourceSha256"]
        }
        self._write_report(forged)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "commit bytes"):
            self._validate()

    def test_candidate_drift_after_report_is_rejected(self) -> None:
        (self.repository / "README.md").write_text("candidate drift\n", encoding="utf-8")
        self._git("add", "README.md")
        self._git("commit", "-q", "-m", "drift")
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "does not match current Git HEAD"):
            self._validate()

    def test_expected_image_mismatch_is_rejected(self) -> None:
        expected = copy.deepcopy(self.expected_images)
        expected["app"]["imageId"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "image ID is not cross-bound"):
            self._validate(expected)

    def test_report_replacement_without_checksum_replacement_is_rejected(self) -> None:
        replaced = copy.deepcopy(self.document)
        replaced["redis"]["keysBefore"] = 99
        self._write_report(replaced, update_checksum=False)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "checksum does not match"):
            self._validate()

    def test_report_and_checksum_replacement_during_validation_is_rejected(self) -> None:
        original_validate = validator.validate_document

        def replace_after_semantic_validation(*args: object, **kwargs: object) -> dict[str, object]:
            summary = original_validate(*args, **kwargs)
            replacement = copy.deepcopy(self.document)
            replacement["redis"]["keysBefore"] = 99
            self._write_report(replacement)
            return summary

        with mock.patch.object(
            validator,
            "validate_document",
            side_effect=replace_after_semantic_validation,
        ), self.assertRaisesRegex(validator.RedisLossEvidenceError, "changed during validation"):
            self._validate()

    def test_duplicate_json_key_nonfinite_number_and_secret_shape_are_rejected(self) -> None:
        duplicate = '{"status":"PASS","status":"PASS"}\n'
        self.report.write_text(duplicate, encoding="utf-8")
        os.chmod(self.report, 0o600)
        checksum = Path(str(self.report) + ".sha256")
        checksum.write_text(
            f"{hashlib.sha256(self.report.read_bytes()).hexdigest()}  {self.report.name}\n",
            encoding="ascii",
        )
        os.chmod(checksum, 0o600)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "repeats field"):
            self._validate()

        nonfinite = copy.deepcopy(self.document)
        nonfinite["redis"]["keysBefore"] = float("nan")
        self._write_report(nonfinite)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "non-finite"):
            self._validate()

        secret = copy.deepcopy(self.document)
        secret["runtime"]["java"]["runtimeVersion"] = "21-password=leaked"
        self._write_report(secret)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "secret-shaped"):
            self._validate()

    def test_java_21_container_and_volume_uniqueness_are_required(self) -> None:
        wrong_java = copy.deepcopy(self.document)
        wrong_java["runtime"]["java"]["runtimeVersion"] = "17.0.12"
        self._write_report(wrong_java)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "Java version"):
            self._validate()

        duplicate_container = copy.deepcopy(self.document)
        duplicate_container["runtime"]["services"]["redis"]["containerId"] = (
            duplicate_container["runtime"]["services"]["mysql"]["containerId"]
        )
        self._write_report(duplicate_container)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "container IDs must be unique"):
            self._validate()

        shared_volume = copy.deepcopy(self.document)
        shared_volume["isolation"]["volumes"]["redis"]["name"] = (
            shared_volume["isolation"]["volumes"]["mysql"]["name"]
        )
        self._write_report(shared_volume)
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "must not share"):
            self._validate()

    def test_evidence_directory_rejects_attachments(self) -> None:
        attachment = self.evidence_dir / "notes.txt"
        attachment.write_text("not part of the evidence contract\n", encoding="utf-8")
        with self.assertRaisesRegex(validator.RedisLossEvidenceError, "only the report"):
            self._validate()

    def test_validator_cli_requires_and_checks_all_expected_images(self) -> None:
        command = [
            sys.executable,
            str(REPO_ROOT / validator.VALIDATOR_PATH),
            "--document",
            str(self.report),
            "--repository-root",
            str(self.repository),
        ]
        for service in validator.SERVICES:
            command.extend(
                [
                    f"--expected-{service}-reference",
                    self.expected_images[service]["reference"],
                    f"--expected-{service}-image-id",
                    self.expected_images[service]["imageId"],
                ]
            )
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env={**os.environ, "PYTHONPYCACHEPREFIX": str(self.root / "pycache")},
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("PASS validate-redis-loss-evidence", completed.stdout)

    def test_formal_producer_requires_all_expected_references_and_image_ids(self) -> None:
        self.assertEqual(set(validator.FIXED_SOURCE_FILES), set(producer.FORMAL_SOURCE_FILES))
        arguments = type("Arguments", (), {})()
        for service in validator.SERVICES:
            setattr(arguments, f"expected_{service}_reference", None)
            setattr(arguments, f"expected_{service}_image_id", None)
        with self.assertRaisesRegex(producer.RecoveryError, "must be supplied together"):
            producer._expected_images(arguments, required=True)

        for service in validator.SERVICES:
            setattr(
                arguments,
                f"expected_{service}_reference",
                self.expected_images[service]["reference"],
            )
            setattr(
                arguments,
                f"expected_{service}_image_id",
                self.expected_images[service]["imageId"],
            )
        self.assertEqual(
            self.expected_images,
            producer._expected_images(arguments, required=True),
        )


if __name__ == "__main__":
    unittest.main()
