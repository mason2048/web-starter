from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import rehearse_tooling_lifecycle as rehearsal


class ToolingLifecycleRehearsalTest(unittest.TestCase):

    def test_doctor_parser_requires_every_all_pass_domain_without_secret_values(self) -> None:
        output = "\n".join(
            f"PASS  {name:<38} verified"
            for name in sorted(rehearsal.EXPECTED_DOCTOR_CHECKS)
        ) + "\nDOCTOR PASS failures=0 warnings=0 env=/private/tooling.env\n"
        checks = rehearsal._doctor_checks(output)
        self.assertEqual(rehearsal.EXPECTED_DOCTOR_CHECKS, set(checks))

        failed = output.replace("PASS  java", "FAIL  java")
        with self.assertRaisesRegex(rehearsal.ToolingRehearsalError, "all-PASS"):
            rehearsal._doctor_checks(failed)

        leaked = output + "Bea" + "rer secret-value-12345678\n"
        with self.assertRaisesRegex(rehearsal.ToolingRehearsalError, "credential-shaped"):
            rehearsal._doctor_checks(leaked)

    def test_compose_project_and_images_are_strictly_bounded(self) -> None:
        self.assertIsNotNone(rehearsal.PROJECT.fullmatch("web-starter-tooling-17-1"))
        self.assertIsNone(rehearsal.PROJECT.fullmatch("production"))
        self.assertIsNotNone(
            rehearsal.REFERENCE.fullmatch("registry.invalid/app@sha256:" + "a" * 64)
        )
        self.assertIsNone(rehearsal.REFERENCE.fullmatch("registry.invalid/app:latest"))

    def test_runtime_env_and_compose_prefer_exact_digest_references(self) -> None:
        app_reference = "registry.invalid/app@sha256:" + "a" * 64
        nginx_reference = "registry.invalid/nginx@sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "tooling.env"
            rehearsal._write_env(
                target,
                "c" * 40,
                app_reference,
                nginx_reference,
                "registry.invalid/mysql@sha256:" + "d" * 64,
                "registry.invalid/redis@sha256:" + "e" * 64,
                {"mysql": 31001, "redis": 31002, "app": 31003, "nginx": 31004},
            )
            values = dict(
                line.split("=", 1)
                for line in target.read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(app_reference, values["WEB_STARTER_APP_REFERENCE"])
            self.assertEqual(nginx_reference, values["WEB_STARTER_NGINX_REFERENCE"])

        repository = Path(__file__).resolve().parent.parent
        compose = (repository / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn(
            "image: ${WEB_STARTER_APP_REFERENCE:-${WEB_STARTER_APP_IMAGE:-web-starter-app}:"
            "${WEB_STARTER_IMAGE_TAG:-local}}",
            compose,
        )
        self.assertIn(
            "image: ${WEB_STARTER_NGINX_REFERENCE:-${WEB_STARTER_NGINX_IMAGE:-web-starter-nginx}:"
            "${WEB_STARTER_IMAGE_TAG:-local}}",
            compose,
        )

    def test_business_fixture_is_deterministic_and_within_signed_bigint(self) -> None:
        fixture_id, fixture_code = rehearsal._business_fixture("web-starter-tooling-17-1")
        self.assertEqual(
            (fixture_id, fixture_code),
            rehearsal._business_fixture("web-starter-tooling-17-1"),
        )
        self.assertGreaterEqual(fixture_id, rehearsal.BUSINESS_FIXTURE_BASE_ID)
        self.assertLess(
            fixture_id,
            rehearsal.BUSINESS_FIXTURE_BASE_ID + rehearsal.BUSINESS_FIXTURE_ID_RANGE,
        )
        self.assertLessEqual(fixture_id, 9_223_372_036_854_775_807)
        self.assertRegex(fixture_code, r"^TOOLING_[0-9A-F]{16}$")

    def test_business_query_uses_container_environment_and_sql_stdin(self) -> None:
        project = "web-starter-tooling-17-1"
        fixture_id, fixture_code = rehearsal._business_fixture(project)
        row_sha256 = rehearsal._expected_business_sha256(fixture_id, fixture_code)
        completed = subprocess.CompletedProcess([], 0, f"1\t{row_sha256}\n", "")
        root = Path("/candidate")
        env_file = Path("/private/runtime/tooling.env")
        with mock.patch.object(rehearsal, "_run", return_value=completed) as run:
            snapshot = rehearsal._business_snapshot(
                root, env_file, project, create=True,
            )

        command = run.call_args.args[0]
        sql = run.call_args.kwargs["input_text"]
        self.assertEqual(1, snapshot["rowCount"])
        self.assertEqual(row_sha256, snapshot["rowSha256"])
        self.assertEqual("docker", command[0])
        self.assertIn("exec", command)
        self.assertIn("${MYSQL_PASSWORD:?}", command[-1])
        self.assertNotIn("INSERT INTO", " ".join(command))
        self.assertIn("INSERT INTO biz_project", sql)
        self.assertIn("SELECT COUNT(*)", sql)
        self.assertNotIn("MYSQL_PASSWORD", sql)

    def test_business_query_rejects_missing_or_changed_row(self) -> None:
        project = "web-starter-tooling-17-1"
        completed = subprocess.CompletedProcess([], 0, "0\t" + "0" * 64 + "\n", "")
        with mock.patch.object(rehearsal, "_run", return_value=completed), \
                self.assertRaisesRegex(
                    rehearsal.ToolingRehearsalError, "business persistence fixture",
                ):
            rehearsal._business_snapshot(
                Path("/candidate"), Path("/private/runtime/tooling.env"),
                project, create=False,
            )

    def test_run_streams_bounded_input_without_conflicting_stdin_options(self) -> None:
        completed = rehearsal._run(
            [sys.executable, "-c", "import sys; print(sys.stdin.read(), end='')"],
            Path.cwd(),
            input_text="project-row\n",
        )
        self.assertEqual("project-row\n", completed.stdout)

    def test_bootstrap_password_is_removed_without_changing_other_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "tooling.env"
            target.write_text(
                "WEB_STARTER_DB_USERNAME=web_starter\n"
                "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD=one-time-secret\n"
                "WEB_STARTER_LOG_LEVEL=INFO\n",
                encoding="utf-8",
            )
            target.chmod(0o600)
            rehearsal._remove_bootstrap_password(target, "one-time-secret")
            self.assertEqual(
                "WEB_STARTER_DB_USERNAME=web_starter\n"
                "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD=\n"
                "WEB_STARTER_LOG_LEVEL=INFO\n",
                target.read_text(encoding="utf-8"),
            )

    def test_admin_password_hash_query_uses_sql_stdin_without_secret_arguments(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "1\t" + "a" * 64 + "\n", "")
        with mock.patch.object(rehearsal, "_run", return_value=completed) as run:
            result = rehearsal._admin_password_hash(
                Path("/candidate"),
                Path("/private/runtime/tooling.env"),
                "web-starter-tooling-17-1",
                "admin",
            )
        self.assertEqual("a" * 64, result)
        command = run.call_args.args[0]
        query = run.call_args.kwargs["input_text"]
        self.assertNotIn("password_hash", " ".join(command))
        self.assertIn("SHA2(password_hash, 256)", query)
        self.assertNotIn("WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD", query)


if __name__ == "__main__":
    unittest.main()
