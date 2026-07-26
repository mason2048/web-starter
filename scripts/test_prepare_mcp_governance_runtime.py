from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import prepare_mcp_governance_runtime as fixtures


class McpGovernanceFixtureTest(unittest.TestCase):
    def test_plan_is_exact_and_preserves_required_identity_relationships(self) -> None:
        self.assertEqual(fixtures.EXPECTED_FILES, {
            *fixtures.PAT_PLAN,
            "rate-client-a.json",
            "rate-client-b.json",
        })
        self.assertEqual(
            fixtures.PAT_PLAN["rate-subject-a.json"][0],
            fixtures.PAT_PLAN["rate-subject-b.json"][0],
        )
        self.assertNotEqual(
            fixtures.OAUTH_USERS[0],
            fixtures.OAUTH_USERS[1],
        )
        self.assertEqual(("system:info", "project:create"), fixtures.OAUTH_SCOPES)
        self.assertEqual(("project:remove",), fixtures.PAT_PLAN["rate-risk.json"][1])
        self.assertEqual(("audit:list",), fixtures.PAT_PLAN["audit.json"][1])

    def test_private_writer_is_exclusive_and_inventory_rejects_extras(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            repository = parent / "repository"
            repository.mkdir(mode=0o700)
            root = parent / "credentials"
            output = fixtures._open_output_directory(root, repository.resolve())
            try:
                for name in fixtures.EXPECTED_FILES:
                    fixtures._write_private_json(output, name, {"token": "x" * 32})
                fixtures._require_exact_private_inventory(output)
                self.assertTrue(all(
                    path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir()
                ))
                with self.assertRaises(FileExistsError):
                    fixtures._write_private_json(output, "sdk.json", {"token": "y" * 32})
                extra = root / "extra.json"
                extra.write_text("{}")
                extra.chmod(0o600)
                with self.assertRaisesRegex(
                    fixtures.GovernanceFixtureError, "exact fixture set"
                ):
                    fixtures._require_exact_private_inventory(output)
            finally:
                os.close(output.descriptor)

    def test_url_and_tls_policy_reject_non_loopback_or_unlisted_insecure_host(self) -> None:
        with mock.patch.dict(os.environ, {
            "PRIVATE": "http://example.invalid:8080",
        }, clear=False):
            with self.assertRaisesRegex(
                fixtures.GovernanceFixtureError, "loopback-only"
            ):
                fixtures._base_url("PRIVATE", https=False)

        with mock.patch.dict(os.environ, {
            "PUBLIC": "https://example.invalid:8443",
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": "mcp.governance.webstarter.test",
        }, clear=False):
            with self.assertRaisesRegex(
                fixtures.GovernanceFixtureError, "explicit loopback alias"
            ):
                fixtures._base_url("PUBLIC", https=True)

        with mock.patch.dict(os.environ, {
            "PUBLIC": "https://127.attacker.example:8443",
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": "mcp.governance.webstarter.test",
        }, clear=False):
            with self.assertRaisesRegex(
                fixtures.GovernanceFixtureError, "explicit loopback alias"
            ):
                fixtures._base_url("PUBLIC", https=True)

        with mock.patch.dict(os.environ, {
            "WEB_STARTER_ACCEPTANCE_INSECURE_TLS": "true",
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": "other.webstarter.test",
        }, clear=False):
            with self.assertRaisesRegex(
                fixtures.GovernanceFixtureError, "explicitly isolated"
            ):
                fixtures._tls_context("https://mcp.governance.webstarter.test:38443")

    def test_output_directory_rejects_symlink_before_writing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(
                fixtures.GovernanceFixtureError, "symlinks"
            ):
                fixtures._open_output_directory(alias, repository.resolve())

    def test_open_directory_fd_blocks_rename_and_symlink_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            repository = parent / "repository"
            repository.mkdir(mode=0o700)
            credentials = parent / "credentials"
            output = fixtures._open_output_directory(credentials, repository.resolve())
            moved = parent / "credentials-moved"
            attacker = parent / "attacker"
            attacker.mkdir(mode=0o700)
            credentials.rename(moved)
            credentials.symlink_to(attacker, target_is_directory=True)
            try:
                with self.assertRaisesRegex(
                    fixtures.GovernanceFixtureError, "identity changed"
                ):
                    fixtures._write_private_json(
                        output, "sdk.json", {"token": "secret" * 8}
                    )
            finally:
                os.close(output.descriptor)
            self.assertEqual([], list(attacker.iterdir()))
            self.assertEqual([], list(moved.iterdir()))

    def test_post_write_directory_replacement_removes_credential_via_held_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            repository = parent / "repository"
            repository.mkdir(mode=0o700)
            credentials = parent / "credentials"
            output = fixtures._open_output_directory(credentials, repository.resolve())
            moved = parent / "credentials-moved"
            attacker = parent / "attacker"
            attacker.mkdir(mode=0o700)
            original_assert = fixtures._assert_output_directory
            checks = 0

            def replace_after_write(candidate: fixtures.PrivateOutputDirectory) -> None:
                nonlocal checks
                checks += 1
                if checks == 2:
                    credentials.rename(moved)
                    credentials.symlink_to(attacker, target_is_directory=True)
                original_assert(candidate)

            try:
                with mock.patch.object(
                    fixtures,
                    "_assert_output_directory",
                    side_effect=replace_after_write,
                ):
                    with self.assertRaisesRegex(
                        fixtures.GovernanceFixtureError, "identity changed"
                    ):
                        fixtures._write_private_json(
                            output, "sdk.json", {"token": "secret" * 8}
                        )
            finally:
                os.close(output.descriptor)
            self.assertEqual([], list(attacker.iterdir()))
            self.assertEqual([], list(moved.iterdir()))

    def test_main_redacts_network_exception_text(self) -> None:
        secret = "credential-that-must-not-be-printed"
        with mock.patch.object(
            fixtures,
            "prepare",
            side_effect=fixtures.GovernanceFixtureError(secret),
        ), mock.patch("sys.stderr") as stderr:
            self.assertEqual(1, fixtures.main(["--repository-root", ".", "--output-directory", "."]))
        rendered = "".join(str(call) for call in stderr.write.call_args_list)
        self.assertNotIn(secret, rendered)
        self.assertIn("GovernanceFixtureError", rendered)

    def test_main_reports_only_allowlisted_stage_and_redacts_cause(self) -> None:
        secret = "credential-that-must-not-be-printed"
        error = fixtures.GovernanceFixtureStageError("admin-authentication")
        error.__cause__ = fixtures.release_prepare.AcceptanceSetupError(secret)
        with mock.patch.object(
            fixtures,
            "prepare",
            side_effect=error,
        ), mock.patch("sys.stderr") as stderr:
            self.assertEqual(
                1,
                fixtures.main(["--repository-root", ".", "--output-directory", "."]),
            )
        rendered = "".join(str(call) for call in stderr.write.call_args_list)
        self.assertNotIn(secret, rendered)
        self.assertIn("GovernanceFixtureStageError", rendered)
        self.assertIn("stage=admin-authentication", rendered)

    def test_fixture_stage_wraps_network_detail_without_exposing_it(self) -> None:
        secret = "upstream-response-containing-a-secret"
        with self.assertRaises(fixtures.GovernanceFixtureStageError) as raised:
            with fixtures._fixture_stage("pat-issuance"):
                raise fixtures.release_prepare.AcceptanceSetupError(secret)
        self.assertEqual("pat-issuance", raised.exception.stage)
        self.assertNotIn(secret, str(raised.exception))
        with self.assertRaisesRegex(ValueError, "stage is not allowed"):
            fixtures.GovernanceFixtureStageError(secret)

    def test_public_login_pacer_keeps_ten_starts_below_ingress_rate(self) -> None:
        now = [100.0]
        sleeps: list[float] = []

        def clock() -> float:
            return now[0]

        def sleep(delay: float) -> None:
            sleeps.append(delay)
            now[0] += delay

        pacer = fixtures.PublicLoginPacer(clock=clock, sleeper=sleep)
        starts: list[float] = []
        for _request in range(10):
            pacer.wait()
            starts.append(now[0])
            now[0] += 0.05

        self.assertEqual(9, len(sleeps))
        self.assertTrue(all(
            later - earlier >= fixtures.PUBLIC_LOGIN_MIN_INTERVAL_SECONDS
            for earlier, later in zip(starts[:-1], starts[1:])
        ))
        self.assertGreaterEqual(starts[-1] - starts[0], 56.25)

    def test_public_login_pacer_rejects_a_faster_configuration(self) -> None:
        with self.assertRaisesRegex(ValueError, "below the public ingress limit"):
            fixtures.PublicLoginPacer(
                interval_seconds=fixtures.PUBLIC_LOGIN_MIN_INTERVAL_SECONDS - 0.01
            )

    def test_source_contract_uses_api_pkce_and_never_sql_or_shell(self) -> None:
        source = Path(fixtures.__file__).read_text(encoding="utf-8")
        self.assertIn("/api/users", source)
        self.assertIn("/api/security/personal-tokens", source)
        self.assertIn("/api/security/oauth-clients", source)
        self.assertIn("authorization_code_pkce_once", source)
        for forbidden in ("subprocess", "docker exec", "mysql ", "SELECT ", "INSERT "):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
