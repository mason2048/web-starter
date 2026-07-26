from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from io import StringIO

import rehearse_migration_failure as ac07


APP_ID = "sha256:" + "a" * 64
MYSQL_ID = "sha256:" + "b" * 64
REDIS_ID = "sha256:" + "c" * 64
APP_REFERENCE = "registry.example/web-starter-app@sha256:" + "d" * 64
CANDIDATE_VERSION = "2.0.0"
CANDIDATE_REVISION = "e" * 40
RUN_ID = "0123456789ab"


def completed(stdout: bytes = b"", returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess([], returncode, stdout, b"")


def labels(run_id: str, role: str) -> dict[str, str]:
    return {
        ac07.LABEL_OWNER: ac07.OWNER_VALUE,
        ac07.LABEL_RUN: run_id,
        ac07.LABEL_ROLE: role,
    }


class MigrationFailureRehearsalTest(unittest.TestCase):

    def test_output_directory_must_be_external_empty_and_private(self) -> None:
        with self.assertRaises(ac07.RehearsalError):
            ac07.ensure_external_output_directory(ac07.REPO_ROOT / "artifacts" / "ac07")

        with tempfile.TemporaryDirectory(prefix="web-starter-ac07-output-test-") as temporary:
            root = Path(temporary)
            open_directory = root / "open"
            open_directory.mkdir(mode=0o755)
            open_directory.chmod(0o755)
            with self.assertRaises(ac07.RehearsalError):
                ac07.ensure_external_output_directory(open_directory)

            target = root / "target"
            target.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ac07.RehearsalError):
                ac07.ensure_external_output_directory(alias)

            nonempty = root / "nonempty"
            nonempty.mkdir(mode=0o700)
            (nonempty / "existing").write_text("occupied", encoding="utf-8")
            with self.assertRaises(ac07.RehearsalError):
                ac07.ensure_external_output_directory(nonempty)

            accepted = ac07.ensure_external_output_directory(root / "accepted")
            self.assertEqual(0o700, stat.S_IMODE(accepted.stat().st_mode))

    def test_image_references_reject_option_injection_and_remote_urls(self) -> None:
        self.assertEqual(
            APP_REFERENCE, ac07.validate_image_reference(APP_REFERENCE, "App")
        )
        with self.assertRaisesRegex(ac07.RehearsalError, "digest-bound"):
            ac07.validate_image_reference(APP_ID, "App")
        for value in ("--privileged", " docker.io/mysql:8.4", "https://registry/image"):
            with self.subTest(value=value), self.assertRaises(ac07.RehearsalError):
                ac07.validate_image_reference(value, "MySQL")

    def test_image_inspection_resolves_local_shapes_to_immutable_ids(self) -> None:
        documents = {
            APP_REFERENCE: [{
                "Id": APP_ID,
                "RepoTags": ["web-starter-ac07-app:candidate"],
                "RepoDigests": [APP_REFERENCE],
                "Config": {
                    "Entrypoint": ["java", "-jar", "/app/app.jar"],
                    "Cmd": None,
                    "User": "10001:10001",
                    "WorkingDir": "/app",
                    "ExposedPorts": {"8080/tcp": {}},
                    "Labels": {
                        ac07.OCI_VERSION_LABEL: CANDIDATE_VERSION,
                        ac07.OCI_REVISION_LABEL: CANDIDATE_REVISION,
                    },
                },
            }],
            "mysql": [{
                "Id": MYSQL_ID,
                "Config": {
                    "Entrypoint": ["docker-entrypoint.sh"],
                    "Cmd": ["mysqld"],
                    "ExposedPorts": {"3306/tcp": {}},
                },
            }],
            "redis": [{
                "Id": REDIS_ID,
                "Config": {
                    "Entrypoint": ["docker-entrypoint.sh"],
                    "Cmd": ["redis-server"],
                    "ExposedPorts": {"6379/tcp": {}},
                },
            }],
        }

        def runner(command):
            return completed(json.dumps(documents[command[-1]]).encode())

        app = ac07.inspect_local_image(
            APP_REFERENCE,
            "App",
            runner,
            candidate_version=CANDIDATE_VERSION,
            candidate_revision=CANDIDATE_REVISION,
        )
        self.assertEqual(APP_ID, app.image_id)
        self.assertEqual("sha256:" + "d" * 64, app.requested_digest)
        self.assertEqual(CANDIDATE_VERSION, app.oci_version)
        self.assertEqual(MYSQL_ID, ac07.inspect_local_image("mysql", "MySQL", runner).image_id)
        self.assertEqual(REDIS_ID, ac07.inspect_local_image("redis", "Redis", runner).image_id)

        documents[APP_REFERENCE][0]["Config"]["User"] = "root"
        with self.assertRaises(ac07.RehearsalError):
            ac07.inspect_local_image(
                APP_REFERENCE,
                "App",
                runner,
                candidate_version=CANDIDATE_VERSION,
                candidate_revision=CANDIDATE_REVISION,
            )

    def test_missing_local_image_fails_without_pull(self) -> None:
        def runner(_command):
            return completed(returncode=1)

        with self.assertRaisesRegex(ac07.RehearsalError, "local Docker store"):
            ac07.inspect_local_image("missing:local", "MySQL", runner)

    def test_resource_names_are_random_prefix_scoped(self) -> None:
        names = ac07.resource_names(RUN_ID)
        self.assertEqual(f"web-starter-ac07-{RUN_ID}", names.network)
        self.assertEqual(f"web-starter-ac07-app-{RUN_ID}", names.app)
        with self.assertRaises(ac07.RehearsalError):
            ac07.resource_names("production")

    def test_container_commands_are_immutable_portless_volume_free_and_value_free(self) -> None:
        names = ac07.resource_names(RUN_ID)
        mysql_environment = {
            "MYSQL_PASSWORD": "must-never-appear-in-command",
            "MYSQL_DATABASE": "web_starter",
        }
        redis_environment = {
            "WEB_STARTER_REDIS_PASSWORD": "must-never-appear-in-command",
        }
        app_environment = {
            "WEB_STARTER_DB_PASSWORD": "must-never-appear-in-command",
            "SPRING_FLYWAY_LOCATIONS": "classpath:db/migration,filesystem:/ac07-migration",
        }
        with tempfile.TemporaryDirectory(prefix="web-starter-ac07-command-") as temporary:
            migration = Path(temporary)
            (migration / ac07.MIGRATION_FILE).write_text("SELECT 1;\n", encoding="ascii")
            mysql = ac07.mysql_create_command(names, MYSQL_ID, mysql_environment)
            redis = ac07.redis_create_command(names, REDIS_ID, redis_environment)
            app = ac07.app_create_command(names, APP_ID, app_environment, migration)

        for command, image_id, environment in (
            (mysql, MYSQL_ID, mysql_environment),
            (redis, REDIS_ID, redis_environment),
            (app, APP_ID, app_environment),
        ):
            self.assertIn(image_id, command)
            self.assertEqual("never", command[command.index("--pull") + 1])
            self.assertNotIn("--publish", command)
            self.assertNotIn("-p", command)
            self.assertNotIn("--volume", command)
            self.assertNotIn("-v", command)
            for value in environment.values():
                self.assertNotIn(value, command)
        self.assertIn("--read-only", app)
        mount = app[app.index("--mount") + 1]
        self.assertIn("readonly", mount)
        self.assertIn(f"dst={ac07.MIGRATION_TARGET}", mount)

    def _container_document(
        self,
        names: ac07.ResourceNames,
        role: str,
        image_id: str,
        migration: Path,
    ) -> dict[str, object]:
        mounts: list[dict[str, object]] = []
        if role == "app":
            mounts.append({
                "Type": "bind",
                "Source": str(migration.resolve()),
                "Destination": ac07.MIGRATION_TARGET,
                "RW": False,
            })
        return {
            "Image": image_id,
            "Config": {"Labels": labels(names.run_id, role)},
            "HostConfig": {
                "NetworkMode": names.network,
                "PublishAllPorts": False,
                "PortBindings": {},
                "ReadonlyRootfs": role == "app",
            },
            "NetworkSettings": {"Networks": {names.network: {}}},
            "Mounts": mounts,
        }

    def test_runtime_inspection_requires_internal_portless_volumeless_topology(self) -> None:
        names = ac07.resource_names(RUN_ID)
        images = ac07.ResolvedImages(APP_ID, MYSQL_ID, REDIS_ID)
        with tempfile.TemporaryDirectory(prefix="web-starter-ac07-inspect-") as temporary:
            migration = Path(temporary)
            documents = {
                names.mysql: self._container_document(names, "mysql", MYSQL_ID, migration),
                names.redis: self._container_document(names, "redis", REDIS_ID, migration),
                names.app: self._container_document(names, "app", APP_ID, migration),
            }
            network = {
                "Internal": True,
                "Labels": labels(names.run_id, "network"),
            }
            with (
                patch.object(ac07, "_network_document", return_value=network),
                patch.object(ac07, "_container_document", side_effect=lambda name: documents[name]),
            ):
                result = ac07.inspect_runtime_isolation(names, images, migration)
            self.assertEqual(0, result["publishedHostPorts"])
            self.assertEqual(0, result["dockerVolumeMounts"])
            self.assertTrue(result["migrationBindReadOnly"])

            documents[names.mysql]["HostConfig"]["PortBindings"] = {"3306/tcp": [{"HostPort": "3306"}]}
            with (
                patch.object(ac07, "_network_document", return_value=network),
                patch.object(ac07, "_container_document", side_effect=lambda name: documents[name]),
                self.assertRaises(ac07.RehearsalError),
            ):
                ac07.inspect_runtime_isolation(names, images, migration)

    def test_failure_evaluation_requires_nonzero_exit_never_ready_and_no_success_row(self) -> None:
        runtime = ac07.AppRuntime(
            exit_code=1,
            timed_out=False,
            readiness_attempts=4,
            readiness_successes=0,
        )
        flyway = ac07.FlywayState(
            successful_base_rows=7,
            successful_failure_version_rows=0,
            unsuccessful_failure_version_rows=1,
            total_failure_version_rows=1,
            latest_successful_version=7,
        )
        logs = (
            f"Flyway migration {ac07.MIGRATION_FILE} failed because table does not exist"
        ).encode()
        passed, checks = ac07.evaluate_failure_protection(runtime, flyway, logs)
        self.assertTrue(passed)
        self.assertTrue(all(checks.values()))

        ready_runtime = ac07.AppRuntime(1, False, 1, 1)
        passed, checks = ac07.evaluate_failure_protection(ready_runtime, flyway, logs)
        self.assertFalse(passed)
        self.assertFalse(checks["readinessNeverSucceeded"])

        bad_history = ac07.FlywayState(7, 1, 0, 1, int(ac07.MIGRATION_VERSION))
        passed, checks = ac07.evaluate_failure_protection(runtime, bad_history, logs)
        self.assertFalse(passed)
        self.assertFalse(checks["failedVersionNotRecordedSuccessful"])

    def test_fixture_leak_detection_does_not_echo_the_literal(self) -> None:
        secret = "generated-private-secret"
        with self.assertRaisesRegex(ac07.RehearsalError, "fixture material") as captured:
            ac07.ensure_no_fixture_literals((f"log {secret}".encode(),), (secret,))
        self.assertNotIn(secret, str(captured.exception))

    def test_failing_migration_is_run_scoped_and_non_destructive(self) -> None:
        content = ac07.migration_content(RUN_ID).decode("ascii")
        self.assertIn(f"ac07_missing_{RUN_ID}", content)
        self.assertNotIn("DROP", content.upper())
        self.assertNotIn("DELETE", content.upper())

    def test_generated_production_environment_is_bound_to_candidate_commit(self) -> None:
        _mysql, _redis, app, _fixtures = ac07.generated_environment(
            RUN_ID, CANDIDATE_REVISION, "private-key", "public-key"
        )
        self.assertEqual("production", app["WEB_STARTER_RUNTIME_MODE"])
        self.assertEqual(CANDIDATE_REVISION, app["WEB_STARTER_GIT_COMMIT"])

        for invalid in ("", "A" * 40, "f" * 39, "f" * 41):
            with self.subTest(invalid=invalid), self.assertRaises(ac07.RehearsalError):
                ac07.generated_environment(
                    RUN_ID, invalid, "private-key", "public-key"
                )

    def test_ac40_reference_is_optional_and_only_independent_validator_can_promote(self) -> None:
        self.assertEqual("NOT_COVERED", ac07.read_ac40_reference(None)["status"])
        with tempfile.TemporaryDirectory(prefix="web-starter-ac40-reference-") as temporary:
            root = Path(temporary)
            evidence = root / "ac40.json"
            evidence.write_text(json.dumps({
                "schemaVersion": 1,
                "acceptanceId": "V2-AC-40",
                "status": "PASS",
                "runtimeAcceptance": "PASS",
            }), encoding="utf-8")
            with self.assertRaisesRegex(ac07.RehearsalError, "independent"):
                ac07.read_ac40_reference(evidence)

            summary = {
                "status": "PASS",
                "processExitCode": 0,
                "checkCount": 36,
                "acceptanceCount": 5,
                "phaseCount": 10,
            }
            with patch.object(
                ac07.ac40_validator,
                "validate_document_path",
                return_value=summary,
            ) as validator:
                accepted = ac07.read_ac40_reference(evidence)
            validator.assert_called_once_with(
                evidence.absolute(),
                repository_root=ac07.REPO_ROOT,
                require_pass=False,
            )
            self.assertEqual("PASS", accepted["status"])
            self.assertTrue(accepted["promotionAllowed"])
            self.assertEqual(hashlib.sha256(evidence.read_bytes()).hexdigest(), accepted["evidenceSha256"])
            self.assertEqual(
                ("PASS", "COMPLETE"),
                ac07.acceptance_outcome(True, accepted["status"]),
            )
            self.assertEqual(
                "scripts/validate_v1_upgrade_evidence.py",
                accepted["validator"]["path"],
            )

            def mutate_after_validation(*_args, **_kwargs):
                evidence.write_text('{"changed":true}', encoding="utf-8")
                return summary

            with (
                patch.object(
                    ac07.ac40_validator,
                    "validate_document_path",
                    side_effect=mutate_after_validation,
                ),
                self.assertRaisesRegex(ac07.RehearsalError, "changed during"),
            ):
                ac07.read_ac40_reference(evidence)

    def test_acceptance_outcome_uses_only_frozen_status_values(self) -> None:
        self.assertEqual(
            ("PASS", "COMPLETE"), ac07.acceptance_outcome(True, "PASS")
        )
        self.assertEqual(
            ("NOT_COVERED", "PENDING_AC40"),
            ac07.acceptance_outcome(True, "NOT_COVERED"),
        )
        self.assertEqual(
            ("FAIL", "FAILURE_PROTECTION_FAILED"),
            ac07.acceptance_outcome(False, "PASS"),
        )
        self.assertEqual(
            ("FAIL", "RECOVERY_FAILED"),
            ac07.acceptance_outcome(True, "FAIL"),
        )
        self.assertEqual(
            ("ENV_REQUIRED", "RECOVERY_ENV_REQUIRED"),
            ac07.acceptance_outcome(True, "ENV_REQUIRED"),
        )
        with self.assertRaises(ac07.RehearsalError):
            ac07.acceptance_outcome(True, "PENDING_AC40")

    def test_process_exit_code_cannot_treat_partial_coverage_as_success(self) -> None:
        self.assertEqual(0, ac07.process_exit_code("PASS"))
        self.assertEqual(1, ac07.process_exit_code("FAIL"))
        self.assertEqual(6, ac07.process_exit_code("NOT_COVERED"))
        self.assertEqual(6, ac07.process_exit_code("ENV_REQUIRED"))
        with self.assertRaises(ac07.RehearsalError):
            ac07.process_exit_code("PENDING_AC40")

    def test_main_returns_six_when_failure_protection_passes_but_ac40_is_uncovered(self) -> None:
        report = {
            "status": "NOT_COVERED",
            "failureProtection": {"status": "PASS"},
            "recovery": {"status": "NOT_COVERED"},
        }
        with (
            patch.object(ac07, "rehearse", return_value=(report, "d" * 64)),
            patch("sys.stdout", new_callable=StringIO),
        ):
            exit_code = ac07.main([
                "--app-image", "app:local",
                "--mysql-image", "mysql:local",
                "--redis-image", "redis:local",
                "--output-dir", "/private/tmp/ac07-unit-output",
            ])
        self.assertEqual(6, exit_code)

    def test_evidence_schema_freezes_status_and_pending_detail_contract(self) -> None:
        schema = json.loads(ac07.SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(ac07.ACCEPTANCE_STATUSES),
            sorted(schema["properties"]["status"]["enum"]),
        )
        self.assertNotIn("PENDING_AC40", schema["properties"]["status"]["enum"])
        self.assertIn("PENDING_AC40", schema["properties"]["statusDetail"]["enum"])
        self.assertEqual(
            sorted(ac07.ACCEPTANCE_STATUSES),
            sorted(schema["properties"]["recovery"]["properties"]["status"]["enum"]),
        )
        self.assertEqual(
            "scripts/validate_v1_upgrade_evidence.py",
            schema["$defs"]["ac40Validator"]["properties"]["path"]["const"],
        )
        self.assertIn("candidate", schema["required"])
        self.assertEqual(
            sorted(ac07.CANDIDATE_SOURCE_PATHS),
            sorted(schema["properties"]["candidate"]["properties"]["sourceSha256"]["required"]),
        )
        self.assertEqual(
            ["id", "ociRevision", "ociVersion", "requestedDigest", "requestedReferenceSha256"],
            sorted(schema["$defs"]["appImage"]["required"]),
        )
        self.assertEqual(2, len(schema["properties"]["recovery"]["oneOf"]))

    def test_cleanup_refuses_unlabelled_container(self) -> None:
        document = {"Config": {"Labels": labels(RUN_ID, "redis")}}
        with (
            patch.object(ac07, "_container_document", return_value=document),
            patch.object(ac07, "_run_quiet") as runner,
            self.assertRaises(ac07.RehearsalError),
        ):
            ac07.cleanup_owned_container(f"web-starter-ac07-app-{RUN_ID}", RUN_ID, "app")
        runner.assert_not_called()

    def test_cleanup_removes_only_after_exact_label_validation(self) -> None:
        document = {"Config": {"Labels": labels(RUN_ID, "app")}}
        with (
            patch.object(ac07, "_container_document", side_effect=[document, None]),
            patch.object(ac07, "_run_quiet", return_value=completed()) as runner,
        ):
            removed = ac07.cleanup_owned_container(
                f"web-starter-ac07-app-{RUN_ID}", RUN_ID, "app"
            )
        self.assertTrue(removed)
        command = runner.call_args.args[0]
        self.assertEqual(["docker", "container", "rm", "--force", "--volumes"], command[:5])

    def test_evidence_is_private_and_checksum_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="web-starter-ac07-evidence-") as temporary:
            output = Path(temporary)
            output.chmod(0o700)
            report = {
                "schemaVersion": 1,
                "acceptanceId": "V2-AC-07",
                "status": "NOT_COVERED",
                "statusDetail": "PENDING_AC40",
            }
            result_path, digest = ac07.write_evidence(output, report)
            checksum = output / ac07.CHECKSUM_NAME
            self.assertEqual(0o600, stat.S_IMODE(result_path.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(checksum.stat().st_mode))
            self.assertEqual(hashlib.sha256(result_path.read_bytes()).hexdigest(), digest)
            self.assertEqual(f"{digest}  {ac07.RESULT_NAME}\n", checksum.read_text("ascii"))

    def test_help_does_not_require_docker(self) -> None:
        environment = {**os.environ, "PYTHONPYCACHEPREFIX": tempfile.gettempdir()}
        result = subprocess.run(
            [sys.executable, str(ac07.REPO_ROOT / "scripts" / "rehearse_migration_failure.py"), "--help"],
            cwd=ac07.REPO_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()
