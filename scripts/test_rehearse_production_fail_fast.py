from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import rehearse_production_fail_fast as ac29


IMAGE_ID = "sha256:" + "a" * 64
MANIFEST_DIGEST = "sha256:" + "b" * 64
IMAGE_REFERENCE = f"registry.example.invalid/web-starter-app@{MANIFEST_DIGEST}"
RUN_ID = "0123456789ab"
HEAD = "1" * 40
CONTAINER_ID = "c" * 64


def candidate() -> ac29.CandidateIdentity:
    return ac29.CandidateIdentity(
        head=HEAD,
        tree="2" * 40,
        tag="v2.0.0",
        tag_object="3" * 40,
        version="2.0.0",
        source_sha256={relative: "4" * 64 for relative in ac29.SOURCE_PATHS},
    )


def image_document() -> list[dict[str, object]]:
    return [{
        "Id": IMAGE_ID,
        "RepoTags": ["web-starter-app:candidate"],
        "RepoDigests": [IMAGE_REFERENCE],
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Entrypoint": ["java", "-jar", "/app/app.jar"],
            "User": "10001:10001",
            "WorkingDir": "/app",
            "Env": ["JAVA_HOME=/opt/java/openjdk", "PATH=/opt/java/openjdk/bin:/usr/bin"],
            "Labels": {
                "org.opencontainers.image.version": "2.0.0",
                "org.opencontainers.image.revision": HEAD,
            },
        },
    }]


class ProductionFailFastRehearsalTest(unittest.TestCase):

    def test_output_path_requires_external_empty_exact_0700_directory(self) -> None:
        with self.assertRaises(ac29.RehearsalError):
            ac29.ensure_external_output_directory(ac29.REPO_ROOT / "artifacts" / "ac29")

        with tempfile.TemporaryDirectory(prefix="web-starter-ac29-path-test-") as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ac29.RehearsalError):
                ac29.ensure_external_output_directory(alias)

            open_dir = root / "open"
            open_dir.mkdir(mode=0o750)
            open_dir.chmod(0o750)
            with self.assertRaises(ac29.RehearsalError):
                ac29.ensure_external_output_directory(open_dir)

            accepted = ac29.ensure_external_output_directory(root / "accepted")
            self.assertEqual(0o700, stat.S_IMODE(accepted.stat().st_mode))

    def test_image_inspection_binds_digest_id_oci_candidate_and_java_home(self) -> None:
        document = image_document()

        def runner(_command):
            return subprocess.CompletedProcess([], 0, json.dumps(document).encode(), b"")

        identity = ac29.inspect_local_app_image(IMAGE_REFERENCE, candidate(), runner)
        self.assertEqual(IMAGE_ID, identity.image_id)
        self.assertEqual(MANIFEST_DIGEST, identity.digest)
        self.assertEqual("2.0.0", identity.oci_version)
        self.assertEqual("/opt/java/openjdk", identity.java_home)

        document[0]["Config"]["Labels"]["org.opencontainers.image.revision"] = "9" * 40
        with self.assertRaises(ac29.RehearsalError):
            ac29.inspect_local_app_image(IMAGE_REFERENCE, candidate(), runner)

    def test_image_reference_must_be_caller_supplied_digest_reference(self) -> None:
        self.assertEqual(
            (IMAGE_REFERENCE, MANIFEST_DIGEST),
            ac29.validate_image_reference(IMAGE_REFERENCE),
        )
        for unsafe in (
            "web-starter-app:candidate",
            "https://registry.example.invalid/app@" + MANIFEST_DIGEST,
            "registry.example.invalid/../app@" + MANIFEST_DIGEST,
            "--privileged@" + MANIFEST_DIGEST,
        ):
            with self.assertRaises(ac29.RehearsalError):
                ac29.validate_image_reference(unsafe)

    def test_rsa_generation_uses_only_memory_pipes(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []
        outputs = (b"PRIVATE-PEM-IN-MEMORY", b"PRIVATE-DER", b"PUBLIC-DER")

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, outputs[len(calls) - 1], b"")

        with patch.object(ac29, "_run_quiet", side_effect=runner):
            private, public = ac29.generate_rsa_material("openssl")

        self.assertNotEqual(private, public)
        self.assertNotIn("-out", calls[0][0])
        self.assertEqual(outputs[0], calls[1][1]["input"])
        self.assertEqual(outputs[0], calls[2][1]["input"])
        self.assertFalse(any("rsa-private" in argument for call, _ in calls for argument in call))

    def test_docker_command_is_networkless_read_only_mountless_and_value_free(self) -> None:
        environment = {
            "WEB_STARTER_DB_PASSWORD": "must-never-appear-in-command",
            "WEB_STARTER_RUNTIME_MODE": "production",
        }
        name = f"web-starter-ac29-01-{RUN_ID}"
        command = ac29.docker_command(name, RUN_ID, IMAGE_ID, environment)

        self.assertEqual(["docker", "run", "--rm", "--pull", "never"], command[:5])
        self.assertEqual("none", command[command.index("--network") + 1])
        self.assertIn(f"{ac29.LABEL_OWNER}=ac29", command)
        self.assertIn(f"{ac29.LABEL_RUN}={RUN_ID}", command)
        self.assertEqual("none", command[command.index("--log-driver") + 1])
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges", command)
        self.assertNotIn("--publish", command)
        self.assertNotIn("--volume", command)
        self.assertEqual(IMAGE_ID, command[-1])
        self.assertNotIn(environment["WEB_STARTER_DB_PASSWORD"], command)

    def test_java_probe_uses_same_isolated_contract_and_immutable_image(self) -> None:
        command = ac29.docker_command(
            f"web-starter-ac29-java-{RUN_ID}", RUN_ID, IMAGE_ID, {},
            entrypoint="java", arguments=("-XshowSettings:properties", "-version"),
        )
        self.assertEqual("none", command[command.index("--network") + 1])
        self.assertEqual("java", command[command.index("--entrypoint") + 1])
        self.assertEqual(
            [IMAGE_ID, "-XshowSettings:properties", "-version"], command[-3:]
        )

    def test_case_inventory_is_exactly_the_frozen_fifteen(self) -> None:
        base = {"WEB_STARTER_DB_PASSWORD": "valid-database-password-0123456789abcdef"}
        cases = ac29.dangerous_cases(base, "fixture123")
        self.assertEqual(15, len(cases))
        self.assertEqual(
            [
                "http-issuer", "localhost-issuer", "http-audience", "insecure-cookie",
                "development-rsa", "empty-secret", "placeholder-secret", "missing-rsa",
                "broad-host", "local-host", "broad-origin", "http-origin",
                "dangerous-log-level", "management-username-reuse",
                "management-password-reuse",
            ],
            [case.case_id for case in cases],
        )
        self.assertTrue(all(case.expected_rejection.startswith(ac29.UNSAFE_PREFIX) for case in cases))

    def test_hardened_environment_binds_the_exact_candidate_commit(self) -> None:
        environment = ac29.hardened_environment(
            "private-key", "public-key", "fixture123", HEAD
        )
        self.assertEqual(HEAD, environment["WEB_STARTER_GIT_COMMIT"])

        with self.assertRaisesRegex(ac29.RehearsalError, "candidate Git commit"):
            ac29.hardened_environment(
                "private-key", "public-key", "fixture123", "local"
            )

    def test_dangerous_case_requires_one_exact_early_rejection(self) -> None:
        case = ac29.DangerousCase("sample", {}, ac29.UNSAFE_PREFIX + "exact rejection")
        passed, failures = ac29.evaluate_dangerous_case(
            case, ac29.ContainerResult(1, b"bootstrap\nUnsafe production configuration: exact rejection\n")
        )
        self.assertTrue(passed)
        self.assertEqual((), failures)

        passed, failures = ac29.evaluate_dangerous_case(
            case,
            ac29.ContainerResult(
                1, b"HikariPool starting\nUnsafe production configuration: exact rejection\n",
            ),
        )
        self.assertFalse(passed)
        self.assertIn("infrastructureStartedBeforeRejection", failures)

        passed, failures = ac29.evaluate_dangerous_case(
            case,
            ac29.ContainerResult(
                1,
                b"Unsafe production configuration: exact rejection\n"
                b"Unsafe production configuration: exact rejection\n",
            ),
        )
        self.assertFalse(passed)
        self.assertIn("exactRejectionCountMismatch", failures)

        expected = ac29.UNSAFE_PREFIX + "exact rejection"
        structured = json.dumps({
            "message": "Application run failed",
            "error": {
                "message": expected,
                "stack_trace": f"IllegalStateException: {expected}",
            },
        }).encode()
        passed, failures = ac29.evaluate_dangerous_case(
            case, ac29.ContainerResult(1, structured)
        )
        self.assertTrue(passed)
        self.assertEqual((), failures)

    def test_hardened_control_must_pass_policy_then_fail_at_database(self) -> None:
        passed, failures = ac29.evaluate_hardened_control(
            ac29.ContainerResult(1, b"Flyway failed: Communications link failure")
        )
        self.assertTrue(passed)
        self.assertEqual((), failures)

        passed, failures = ac29.evaluate_hardened_control(
            ac29.ContainerResult(1, b"Flyway starting; HikariPool starting")
        )
        self.assertFalse(passed)
        self.assertIn("databaseFailureMissing", failures)

        passed, failures = ac29.evaluate_hardened_control(
            ac29.ContainerResult(1, b"Unsafe production configuration: rejected")
        )
        self.assertFalse(passed)
        self.assertIn("securityValidationRejectedControl", failures)
        self.assertIn("databaseFailureMissing", failures)

    def test_java_identity_is_parsed_but_raw_output_is_not_returned(self) -> None:
        output = (
            b"Property settings:\n"
            b"    java.runtime.version = 21.0.8+9-LTS\n"
            b"    java.specification.version = 21\n"
            b"    java.vendor = Eclipse Adoptium\n"
        )
        evidence = ac29._java_evidence(
            ac29.ContainerResult(0, output, command_sha256="c" * 64), IMAGE_ID
        )
        self.assertEqual("PASS", evidence["status"])
        self.assertEqual("21", evidence["specificationVersion"])
        self.assertNotIn("output", evidence)

        mismatched = output.replace(b"21.0.8+9-LTS", b"17.0.12+7-LTS")
        evidence = ac29._java_evidence(
            ac29.ContainerResult(0, mismatched, command_sha256="c" * 64), IMAGE_ID
        )
        self.assertEqual("FAIL", evidence["status"])
        self.assertIn("runtimeVersionNot21", evidence["failures"])

    def test_fixture_leak_fails_without_echoing_literal(self) -> None:
        fixture = "AC29_fixture_secret_do_not_log"
        with self.assertRaisesRegex(ac29.RehearsalError, "fixture material") as caught:
            ac29.ensure_no_fixture_literals(f"bad {fixture}".encode(), [fixture])
        self.assertNotIn(fixture, str(caught.exception))

    def test_cleanup_refuses_foreign_and_removes_only_exact_owned_target(self) -> None:
        name = f"web-starter-ac29-01-{RUN_ID}"
        commands: list[list[str]] = []

        def foreign(command):
            commands.append(command)
            if "ls" in command:
                return subprocess.CompletedProcess(command, 0, f"{name}\n".encode(), b"")
            labels = json.dumps({ac29.LABEL_OWNER: "ac40", ac29.LABEL_RUN: RUN_ID})
            body = f"{CONTAINER_ID}\n/{name}\n{labels}\n".encode()
            return subprocess.CompletedProcess(command, 0, body, b"")

        with self.assertRaises(ac29.RehearsalError):
            ac29.cleanup_owned_container(name, RUN_ID, foreign)
        self.assertFalse(any("rm" in command for command in commands))

        commands.clear()
        exists = True

        def owned(command):
            nonlocal exists
            commands.append(command)
            if "ls" in command:
                body = f"{name}\n".encode() if exists else b""
                return subprocess.CompletedProcess(command, 0, body, b"")
            if "inspect" in command:
                labels = json.dumps({ac29.LABEL_OWNER: "ac29", ac29.LABEL_RUN: RUN_ID})
                body = f"{CONTAINER_ID}\n/{name}\n{labels}\n".encode()
                return subprocess.CompletedProcess(command, 0, body, b"")
            if "rm" in command:
                exists = False
            return subprocess.CompletedProcess(command, 0, b"", b"")

        cleanup = ac29.cleanup_owned_container(name, RUN_ID, owned)
        self.assertTrue(cleanup.labels_verified)
        self.assertTrue(cleanup.removed)
        self.assertFalse(cleanup.residual)
        self.assertEqual(
            ["docker", "container", "rm", "--force", CONTAINER_ID], commands[-2]
        )

    def test_evidence_contains_only_sanitized_0600_json_and_matching_sha(self) -> None:
        secret = "raw-secret-must-not-be-persisted"
        with tempfile.TemporaryDirectory(prefix="web-starter-ac29-evidence-test-") as temporary:
            output = Path(temporary)
            output.chmod(0o700)
            report = {
                "status": "PASS",
                "logSha256": hashlib.sha256(secret.encode()).hexdigest(),
                "rawLogsPersisted": False,
            }
            path, digest = ac29.write_evidence(output, report)
            document = path.read_text()
            self.assertNotIn(secret, document)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            checksum = (output / ac29.CHECKSUM_NAME).read_text().split()[0]
            self.assertEqual(digest, checksum)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(
                {ac29.RESULT_NAME, ac29.CHECKSUM_NAME},
                {item.name for item in output.iterdir()},
            )


if __name__ == "__main__":
    unittest.main()
