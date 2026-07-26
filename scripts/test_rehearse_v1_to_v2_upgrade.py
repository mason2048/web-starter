from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import scripts.rehearse_v1_to_v2_upgrade as upgrade


RUN_ID = "0123456789ab"
COMMIT = "a" * 40


def repository_git(arguments: tuple[str, ...]) -> bytes:
    return subprocess.run(
        ["git", *arguments],
        cwd=upgrade.REPOSITORY_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def create_dependency_seed(root: Path) -> tuple[Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    source = root / "candidate-source"
    source.mkdir(mode=0o700)
    for relative in upgrade.DEPENDENCY_SEED_SOURCE_FILES:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == ".mvn/wrapper/maven-wrapper.properties":
            payload = (
                "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/"
                "apache-maven/3.9.15/apache-maven-3.9.15-bin.zip\n"
                "distributionSha256Sum=" + "a" * 64 + "\n"
            )
        else:
            payload = f"fixture bytes for {relative}\n"
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)
    seed = root / "dependency-seed"
    seed.mkdir(mode=0o700)
    component_roots: dict[str, Path] = {}
    for component, relative in upgrade.DEPENDENCY_SEED_COMPONENTS.items():
        component_root = seed / relative
        component_root.mkdir(mode=0o700)
        component_roots[component] = component_root

    distribution_url = (
        "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.15/"
        "apache-maven-3.9.15-bin.zip"
    )
    maven = (
        component_roots["mavenHome"] / "wrapper" / "dists" / "apache-maven-3.9.15"
        / upgrade._java_string_hash(distribution_url) / "bin" / "mvn"
    )
    maven.parent.mkdir(parents=True)
    maven.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    maven.chmod(0o700)
    (component_roots["mavenRepository"] / "example.jar").write_bytes(b"jar")
    (component_roots["mavenRepository"] / "example.pom").write_bytes(b"pom")
    pnpm_package = (
        component_roots["corepackHome"] / "v1" / "pnpm" / "9.15.9" / "package.json"
    )
    pnpm_package.parent.mkdir(parents=True)
    pnpm_package.write_text('{"version":"9.15.9"}\n', encoding="utf-8")
    pnpm_file = component_roots["pnpmStore"] / "v3" / "files" / "00" / "fixture"
    pnpm_file.parent.mkdir(parents=True)
    pnpm_file.write_bytes(b"pnpm")
    chromium = component_roots["playwrightBrowsers"] / "chromium-1228"
    chromium.mkdir()
    (chromium / "INSTALLATION_COMPLETE").write_text("complete\n", encoding="utf-8")
    chrome = chromium / "chrome"
    chrome.write_bytes(b"browser")
    chrome.chmod(0o700)

    for directory in sorted(seed.rglob("*")):
        if directory.is_dir():
            directory.chmod(0o700)
        elif directory != maven and directory != chrome:
            directory.chmod(0o600)
    source_hashes = upgrade._manifest_source_hashes(source)
    components = {
        component: {
            "path": relative,
            **upgrade._component_tree_summary(seed / relative, component=component),
        }
        for component, relative in upgrade.DEPENDENCY_SEED_COMPONENTS.items()
    }
    manifest = {
        "schemaVersion": 1,
        "kind": upgrade.DEPENDENCY_SEED_KIND,
        "platform": sys.platform,
        "architecture": upgrade.platform.machine().lower(),
        "versions": dict(upgrade.DEPENDENCY_SEED_VERSIONS),
        "sourceSha256": source_hashes,
        "components": components,
    }
    manifest_path = seed / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    return seed, source


def rewrite_dependency_seed_manifest(seed: Path, source: Path) -> None:
    components = {
        component: {
            "path": relative,
            **upgrade._component_tree_summary(seed / relative, component=component),
        }
        for component, relative in upgrade.DEPENDENCY_SEED_COMPONENTS.items()
    }
    manifest = {
        "schemaVersion": upgrade.DEPENDENCY_SEED_SCHEMA_VERSION,
        "kind": upgrade.DEPENDENCY_SEED_KIND,
        "platform": sys.platform,
        "architecture": upgrade.platform.machine().lower(),
        "versions": dict(upgrade.DEPENDENCY_SEED_VERSIONS),
        "sourceSha256": upgrade._manifest_source_hashes(source),
        "components": components,
    }
    manifest_path = seed / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)


def dependency_seed_trust_anchor(seed: Path) -> str:
    manifest = json.loads((seed / "manifest.json").read_text(encoding="utf-8"))
    summaries = {
        component: {
            "treeSha256": manifest["components"][component]["treeSha256"],
            "fileCount": manifest["components"][component]["fileCount"],
            "byteCount": manifest["components"][component]["byteCount"],
        }
        for component in upgrade.DEPENDENCY_SEED_COMPONENTS
    }
    payload = {
        "kind": manifest["kind"],
        "schemaVersion": manifest["schemaVersion"],
        "platform": manifest["platform"],
        "architecture": manifest["architecture"],
        "versions": manifest["versions"],
        "sourceSha256": manifest["sourceSha256"],
        "components": summaries,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class V1ToV2UpgradeHarnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-upgrade-unit-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _http_response(
            status: int,
            payload: bytes = b"",
            headers: dict[str, str] | None = None) -> MagicMock:
        response = MagicMock()
        response.status = status
        response.headers = headers or {}
        response.read.return_value = payload
        context = MagicMock()
        context.__enter__.return_value = response
        context.__exit__.return_value = False
        return context

    def test_lifecycle_initialize_probe_closes_the_created_mcp_session(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-lifecycle-probe",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        token_file = self.root / "lifecycle-token.json"
        token_file.write_text(json.dumps({"token": "p" * 64}), encoding="utf-8")
        session_id = "session-12345678"
        opener = MagicMock()
        opener.open.side_effect = [
            self._http_response(
                200,
                b'{"jsonrpc":"2.0","id":1,"result":{}}',
                {"Mcp-Session-Id": session_id},
            ),
            self._http_response(204),
        ]
        previous_hosts = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS")
        previous_address = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS")

        with patch.object(upgrade, "build_opener", return_value=opener), patch.object(
            upgrade, "isolated_loopback_resolution"
        ) as loopback:
            loopback.return_value.__enter__.return_value = None
            loopback.return_value.__exit__.return_value = False
            status = upgrade._raw_mcp_initialize_status(runtime, token_file)

        self.assertEqual(200, status)
        self.assertEqual(2, opener.open.call_count)
        initialize_request = opener.open.call_args_list[0].args[0]
        close_request = opener.open.call_args_list[1].args[0]
        self.assertEqual("POST", initialize_request.get_method())
        self.assertEqual("DELETE", close_request.get_method())
        close_headers = {
            key.lower(): value for key, value in close_request.header_items()
        }
        self.assertEqual(session_id, close_headers["mcp-session-id"])
        self.assertEqual(
            f"upgrade-lifecycle-{RUN_ID}-close",
            close_headers["x-trace-id"],
        )
        self.assertEqual(
            previous_hosts,
            os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"),
        )
        self.assertEqual(
            previous_address,
            os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"),
        )

    def test_lifecycle_initialize_probe_rejects_a_success_without_session_id(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-missing-session",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        token_file = self.root / "missing-session-token.json"
        token_file.write_text(json.dumps({"token": "p" * 64}), encoding="utf-8")
        opener = MagicMock()
        opener.open.return_value = self._http_response(
            200, b'{"jsonrpc":"2.0","id":1,"result":{}}'
        )

        with patch.object(upgrade, "build_opener", return_value=opener), patch.object(
            upgrade, "isolated_loopback_resolution"
        ) as loopback, self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "valid MCP Session ID"
        ):
            loopback.return_value.__enter__.return_value = None
            loopback.return_value.__exit__.return_value = False
            upgrade._raw_mcp_initialize_status(runtime, token_file)

        self.assertEqual(1, opener.open.call_count)

    def test_lifecycle_personal_credential_is_active_before_browser_acceptance(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-pre-browser-lifecycle",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        token_file = self.root / "lifecycle-personal-token.json"
        fixture = {
            "lifecyclePatFile": str(token_file),
            "lifecyclePatId": "9007199254740993",
            "lifecyclePatName": "upgrade-lifecycle",
        }
        before = {
            "id": fixture["lifecyclePatId"],
            "name": fixture["lifecyclePatName"],
            "revokedAt": None,
            "lastUsedAt": None,
        }
        after = {**before, "lastUsedAt": "2026-07-26T10:00:00Z"}
        api = MagicMock()
        api.request.side_effect = [[before], [after]]

        with patch.object(upgrade, "_AdminApi", return_value=api), patch.object(
            upgrade, "_raw_mcp_initialize_status", return_value=200
        ) as probe:
            upgrade._pre_browser_lifecycle_probe(runtime, fixture)

        api.login.assert_called_once_with()
        probe.assert_called_once_with(runtime, token_file)
        self.assertEqual(2, api.request.call_count)

    def test_final_lifecycle_readback_requires_identity_revocation_and_disables_service(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-final-lifecycle",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        lifecycle_file = self.root / "lifecycle-personal-token.json"
        service_file = self.root / "service-token.json"
        fixture = {
            "lifecyclePatFile": str(lifecycle_file),
            "lifecyclePatId": "9007199254740993",
            "lifecyclePatName": "upgrade-lifecycle",
            "serviceAccountId": "9007199254740995",
        }
        manifest = {"tokenFiles": {"serviceToken": str(service_file)}}
        revoked = {
            "id": fixture["lifecyclePatId"],
            "name": fixture["lifecyclePatName"],
            "revokedAt": "2026-07-26T10:01:00Z",
            "lastUsedAt": "2026-07-26T10:00:00Z",
        }
        disabled_service = {
            "id": fixture["serviceAccountId"],
            "enabled": False,
        }
        api = MagicMock()
        api.request.side_effect = [[revoked], None, [disabled_service]]

        with patch.object(upgrade, "_AdminApi", return_value=api), patch.object(
            upgrade,
            "_raw_mcp_initialize_status",
            side_effect=[401, 200, 401],
        ) as probe:
            upgrade._final_lifecycle_readback(runtime, fixture, manifest)

        self.assertEqual(
            [
                (runtime, lifecycle_file),
                (runtime, service_file),
                (runtime, service_file),
            ],
            [call.args for call in probe.call_args_list],
        )
        requests = [call.args for call in api.request.call_args_list]
        self.assertFalse(any(
            args[0] == "DELETE" and "/personal-tokens/" in args[1]
            for args in requests
        ))
        self.assertTrue(any(
            args[0] == "DELETE"
            and args[1].endswith(
                f"/api/security/service-accounts/{fixture['serviceAccountId']}"
            )
            for args in requests
        ))

    def test_browser_identity_lifecycle_is_between_active_and_revoked_proofs(self) -> None:
        source = upgrade.SCRIPT_PATH.read_text(encoding="utf-8")
        active_probe = source.rindex("_pre_browser_lifecycle_probe(runtime, service_fixture)")
        browser_runtime = source.rindex("_run_playwright(runtime, runner")
        revoked_readback = source.rindex(
            "_final_lifecycle_readback(runtime, service_fixture, manifest_v2)"
        )
        self.assertLess(active_probe, browser_runtime)
        self.assertLess(browser_runtime, revoked_readback)

    def test_direct_script_import_can_enter_public_loopback_context(self) -> None:
        script = """
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
import rehearse_v1_to_v2_upgrade as upgrade

root = pathlib.Path(sys.argv[2])
runtime = upgrade.RuntimeContext(
    root,
    root / "runtime",
    upgrade.generate_resource_names("0123456789ab"),
    upgrade.Ports(18080, 18443, 18081),
    upgrade.EvidenceState(),
)
with upgrade._public_loopback_resolution(runtime):
    pass
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                script,
                str(upgrade.REPOSITORY_ROOT / "scripts"),
                str(self.root),
            ],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))

    def test_pkce_fixture_requests_every_read_scope_used_by_sdk_contract(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        issuer = (
            f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}"
        )
        parameters = upgrade._pkce_parameters(runtime, {
            "publicBaseUrl": issuer,
            "publicClientId": "release-pkce-0123456789ab",
            "redirectUri": issuer + "/login",
        })

        self.assertEqual(
            ("system:info", "project:list", "audit:list"),
            parameters["scopes"],
        )

    def test_browser_fixture_uses_localhost_for_production_secure_cookie(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-browser-origin",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.environment = {
            "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "acceptance-admin",
            "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": "private-password",
        }

        environment = upgrade._prepare_fixture_environment(
            runtime,
            {"v1Kid": "v1-key", "v2Kid": "v2-key"},
        )

        self.assertEqual(
            "http://localhost:18080",
            environment["WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL"],
        )
        self.assertEqual(
            "http://localhost:18080",
            upgrade._private_browser_base_url(runtime),
        )
        self.assertNotIn(
            "127.0.0.1",
            environment["WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL"],
        )

    def test_credential_tls_clients_reject_key_logging(self) -> None:
        with patch.dict(os.environ, {"SSLKEYLOGFILE": "/tmp/upgrade.keys"}, clear=False):
            with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "must be unset") as error:
                upgrade._new_oauth_token_opener()
        self.assertEqual("TLS_KEY_LOGGING", error.exception.code)

    def test_admin_fixture_transport_failure_is_classified_without_response_data(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        api = upgrade._AdminApi(runtime)

        class FailingOpener:
            def open(self, _request, **_kwargs):
                raise OSError("simulated connection reset")

        api.opener = FailingOpener()
        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "management API transport failed"
        ) as error:
            api.request("GET", "https://upgrade.invalid.test/api/auth/csrf")
        self.assertEqual("ADMIN_API_TRANSPORT", error.exception.code)

    def test_git_python_and_compose_environments_drop_ambient_behavior_controls(self) -> None:
        frozen = self.root / "frozen"
        (frozen / "scripts").mkdir(parents=True)
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.environment = {
            "WEB_STARTER_DB_USERNAME": "explicit",
            "WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL": (
                f"{upgrade.V1_ACCESS_TOKEN_TTL_SECONDS}s"
            ),
        }

        class CapturingRunner:
            kwargs: dict[str, object] = {}

            def run(self, _command, **kwargs):
                self.kwargs = kwargs
                return upgrade.CommandResult(0, b"", b"")

        with patch.dict(os.environ, {
            "GIT_DIR": "/poison/git",
            "GIT_INDEX_FILE": "/poison/index",
            "PYTHONPATH": "/poison/python",
            "WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED": "true",
            "WEB_STARTER_MCP_SESSION_IDLE_TTL": "1ms",
        }):
            git_env = upgrade.git_environment()
            python_env = upgrade.frozen_python_environment(frozen)
            compose_env = upgrade._compose_env(runtime, v2=True)
            v1_compose_env = upgrade._compose_env(runtime, v2=False)
            runner = CapturingRunner()
            upgrade._git_runner(runner)(("status", "--short"))  # type: ignore[arg-type]

        self.assertNotIn("GIT_DIR", git_env)
        self.assertNotIn("GIT_INDEX_FILE", git_env)
        self.assertEqual("1", git_env["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual(os.devnull, git_env["GIT_CONFIG_GLOBAL"])
        self.assertEqual(
            os.pathsep.join((str((frozen / "scripts").resolve()), str(frozen.resolve()))),
            python_env["PYTHONPATH"],
        )
        self.assertEqual("1", python_env["PYTHONNOUSERSITE"])
        self.assertNotIn("WEB_STARTER_MCP_SESSION_IDLE_TTL", compose_env)
        self.assertEqual("explicit", compose_env["WEB_STARTER_DB_USERNAME"])
        self.assertEqual(
            f"{upgrade.V1_ACCESS_TOKEN_TTL_SECONDS}s",
            v1_compose_env["WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL"],
        )
        self.assertEqual(
            f"{upgrade.V2_ACCESS_TOKEN_TTL_SECONDS}s",
            compose_env["WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL"],
        )
        self.assertTrue(runner.kwargs["replace_environment"])
        child_git_env = runner.kwargs["environment"]
        self.assertIsInstance(child_git_env, dict)
        self.assertNotIn("GIT_DIR", child_git_env)  # type: ignore[operator]
        self.assertNotIn("GIT_INDEX_FILE", child_git_env)  # type: ignore[operator]

    def test_flyway_history_is_exact_and_checksum_is_line_ending_independent(self) -> None:
        lf = self.root / "lf.sql"
        crlf = self.root / "crlf.sql"
        lf.write_bytes(b"\xef\xbb\xbfCREATE TABLE sample (id BIGINT);\n\n-- end\n")
        crlf.write_bytes(b"\xef\xbb\xbfCREATE TABLE sample (id BIGINT);\r\n\r\n-- end\r\n")
        self.assertEqual(upgrade.flyway_checksum(lf), upgrade.flyway_checksum(crlf))

        expected_rows: list[dict[str, object]] = []
        for index, relative in enumerate(upgrade.V2_MIGRATIONS, start=1):
            filename = Path(relative).name
            expected_rows.append({
                "installedRank": index,
                "version": index,
                "description": filename.split("__", 1)[1][:-4].replace("_", " "),
                "type": "SQL",
                "script": filename,
                "checksum": upgrade.flyway_checksum(upgrade.REPOSITORY_ROOT / relative),
                "success": True,
            })
        bound = upgrade.assert_flyway_history(
            expected_rows,
            {
                relative: upgrade.REPOSITORY_ROOT / relative
                for relative in upgrade.V2_MIGRATIONS
            },
            upgrade.V2_MIGRATIONS,
        )
        self.assertEqual(7, len(bound))
        self.assertTrue(all(len(str(row["scriptSha256"])) == 64 for row in bound))

        tampered = [dict(row) for row in expected_rows]
        tampered[4]["checksum"] = int(tampered[4]["checksum"]) + 1
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "exact migration"):
            upgrade.assert_flyway_history(
                tampered,
                {
                    relative: upgrade.REPOSITORY_ROOT / relative
                    for relative in upgrade.V2_MIGRATIONS
                },
                upgrade.V2_MIGRATIONS,
            )
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "exact migration"):
            upgrade.assert_flyway_history(
                expected_rows[:-1],
                {
                    relative: upgrade.REPOSITORY_ROOT / relative
                    for relative in upgrade.V2_MIGRATIONS
                },
                upgrade.V2_MIGRATIONS,
            )

    def test_fixed_v1_is_an_annotated_tag_at_the_exact_commit(self) -> None:
        identity = upgrade.validate_v1_identity(repository_git)
        self.assertEqual("tag", identity["tagObjectType"])
        self.assertEqual(upgrade.V1_COMMIT, identity["commit"])

    def test_fixed_v1_tag_has_no_runtime_fixture_or_recovery_adapter(self) -> None:
        files = upgrade.validate_v1_tag_adapter_boundary(repository_git)
        self.assertEqual(upgrade.V1_TAG_SCRIPT_FILES, files)
        self.assertNotIn("scripts/prepare_release_runtime_acceptance.py", files)
        self.assertNotIn("scripts/recovery_backup.py", files)

    def test_v1_tag_adapter_boundary_fails_on_a_false_attribution(self) -> None:
        def fake_git(_: tuple[str, ...]) -> bytes:
            return (
                "scripts/prepare_release_runtime_acceptance.py\n"
                "scripts/repository_policy.py\n"
                "scripts/test_repository_policy.py\n"
            ).encode()

        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "scripts"):
            upgrade.validate_v1_tag_adapter_boundary(fake_git)

    def test_frozen_v1_migrations_are_byte_equal_to_current_append_only_files(self) -> None:
        hashes = upgrade.validate_v1_migration_bytes(repository_git)
        self.assertEqual(set(upgrade.V1_MIGRATIONS), set(hashes))
        self.assertTrue(all(upgrade.SHA256.fullmatch(value) for value in hashes.values()))

    def test_resource_names_are_random_project_and_database_scoped(self) -> None:
        names = upgrade.generate_resource_names(RUN_ID)
        self.assertEqual("web-starter-ac40-" + RUN_ID, names.compose_project)
        self.assertEqual("ws_v1_" + RUN_ID, names.source_database)
        self.assertEqual("ws_v1_" + RUN_ID + "_restore_v2", names.target_database)
        self.assertNotEqual("web_starter", names.source_database)
        with self.assertRaises(upgrade.UpgradeRehearsalError):
            upgrade.generate_resource_names("production")

    def test_output_directory_must_be_external_empty_real_and_0700(self) -> None:
        candidate = upgrade.REPOSITORY_ROOT / ".upgrade-output-must-not-exist"
        self.assertFalse(candidate.exists())
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "outside"):
            upgrade.ensure_external_empty_private_directory(candidate)
        self.assertFalse(candidate.exists())

        open_directory = self.root / "open"
        open_directory.mkdir(mode=0o755)
        open_directory.chmod(0o755)
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "0700"):
            upgrade.ensure_external_empty_private_directory(open_directory)

        target = self.root / "target"
        target.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "symbolic"):
            upgrade.ensure_external_empty_private_directory(alias)

        accepted = upgrade.ensure_external_empty_private_directory(self.root / "accepted")
        self.assertEqual(0o700, stat.S_IMODE(accepted.stat().st_mode))

    def test_private_writer_is_0600_create_only(self) -> None:
        target = self.root / "secret.json"
        upgrade.write_private_json(target, {"token": "private-only"})
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        with self.assertRaises(upgrade.UpgradeRehearsalError):
            upgrade.write_private_json(target, {"token": "replacement"})

    def test_dependency_seed_is_strictly_bound_and_copied_to_private_runtime(self) -> None:
        seed_root, source_root = create_dependency_seed(self.root)
        seed = upgrade.validate_dependency_seed(
            seed_root,
            expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
            source_root=source_root,
        )
        self.assertEqual(
            set(upgrade.DEPENDENCY_SEED_COMPONENTS),
            set(seed.evidence["components"]),
        )
        self.assertEqual(
            upgrade.DEPENDENCY_SEED_EXECUTION_POLICY,
            seed.evidence["executionPolicy"],
        )
        runtime_root = self.root / "runtime-seed-copy"
        runtime_root.mkdir(mode=0o700)
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        copied = upgrade._copy_dependency_seed(seed, runtime)
        self.assertEqual(seed.evidence, runtime.dependency_seed_evidence)
        self.assertEqual(0o700, stat.S_IMODE(copied.stat().st_mode))
        self.assertEqual(
            seed.evidence["manifestSha256"],
            upgrade.sha256_file(copied / "manifest.json"),
        )

    def test_dependency_seed_rejects_links_modes_incomplete_and_project_artifacts(self) -> None:
        cases = ("link", "mode", "incomplete", "project")
        for case in cases:
            with self.subTest(case=case):
                case_root = self.root / case
                case_root.mkdir(mode=0o700)
                seed_root, source_root = create_dependency_seed(case_root)
                if case == "link":
                    link = seed_root / "pnpm-store" / "v3" / "files" / "unsafe-link"
                    link.symlink_to("../../../maven-repository/example.jar")
                elif case == "mode":
                    (seed_root / "maven-repository" / "example.jar").chmod(0o644)
                elif case == "incomplete":
                    marker = seed_root / "maven-repository" / "download.lastUpdated"
                    marker.write_bytes(b"partial")
                    marker.chmod(0o600)
                else:
                    artifact = (
                        seed_root / "maven-repository" / "dev" / "webstarter"
                        / "web-starter-core" / "2.0.0" / "web-starter-core-2.0.0.jar"
                    )
                    artifact.parent.mkdir(parents=True)
                    artifact.write_bytes(b"local build")
                    for directory in artifact.parents:
                        if directory == seed_root / "maven-repository":
                            break
                        directory.chmod(0o700)
                    artifact.chmod(0o600)
                with self.assertRaises(upgrade.UpgradeRehearsalError):
                    upgrade.validate_dependency_seed(
                        seed_root,
                        expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
                        source_root=source_root,
                    )

    def test_dependency_seed_requires_real_pnpm9_v3_files_below_store_dir(self) -> None:
        seed_root, source_root = create_dependency_seed(self.root)
        store = seed_root / upgrade.DEPENDENCY_SEED_COMPONENTS["pnpmStore"]
        legacy = store / "files"
        legacy.mkdir(mode=0o700)
        legacy_file = legacy / "fixture"
        legacy_file.write_bytes(b"legacy-layout")
        legacy_file.chmod(0o600)
        shutil.rmtree(store / "v3")
        rewrite_dependency_seed_manifest(seed_root, source_root)

        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "pnpm v3 store"
        ) as error:
            upgrade.validate_dependency_seed(
                seed_root,
                expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
                source_root=source_root,
            )
        self.assertEqual("DEPENDENCY_SEED_PNPM", error.exception.code)

    def test_playwright_seed_allows_only_safe_internal_relative_links_and_copies_them(self) -> None:
        seed_root, source_root = create_dependency_seed(self.root)
        browser_root = seed_root / upgrade.DEPENDENCY_SEED_COMPONENTS["playwrightBrowsers"]
        framework = browser_root / "chromium-1228" / "Framework.framework"
        version = framework / "Versions" / "149.0" / "Resources"
        version.mkdir(parents=True, mode=0o700)
        resource = version / "fixture.dat"
        resource.write_bytes(b"browser-framework-resource")
        resource.chmod(0o600)
        for directory in (framework, framework / "Versions", version.parent, version):
            directory.chmod(0o700)
        current = framework / "Versions" / "Current"
        current.symlink_to("149.0", target_is_directory=True)
        resources = framework / "Resources"
        resources.symlink_to("Versions/Current/Resources", target_is_directory=True)

        first_summary = upgrade._component_tree_summary(
            browser_root, component="playwrightBrowsers"
        )
        self.assertEqual(version.parent.resolve(), current.resolve())
        current.unlink()
        current.symlink_to("./149.0", target_is_directory=True)
        second_summary = upgrade._component_tree_summary(
            browser_root, component="playwrightBrowsers"
        )
        self.assertEqual(version.parent.resolve(), current.resolve())
        self.assertNotEqual(first_summary["treeSha256"], second_summary["treeSha256"])

        rewrite_dependency_seed_manifest(seed_root, source_root)
        seed = upgrade.validate_dependency_seed(
            seed_root,
            expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
            source_root=source_root,
        )
        runtime_root = self.root / "runtime-playwright-link-copy"
        runtime_root.mkdir(mode=0o700)
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        copied = upgrade._copy_dependency_seed(seed, runtime)
        copied_framework = copied / "playwright-browsers" / "chromium-1228" / "Framework.framework"
        self.assertEqual("./149.0", os.readlink(copied_framework / "Versions" / "Current"))
        self.assertEqual(
            "Versions/Current/Resources", os.readlink(copied_framework / "Resources")
        )
        self.assertEqual(
            seed.evidence["components"]["playwrightBrowsers"],
            upgrade._component_tree_summary(
                copied / "playwright-browsers", component="playwrightBrowsers"
            ),
        )

    def test_playwright_seed_rejects_absolute_escape_dangling_and_cyclic_links(self) -> None:
        for case in (
            "absolute", "escape", "escape-reentry", "dangling",
            "resolution-cycle", "directory-cycle",
        ):
            with self.subTest(case=case):
                case_root = self.root / case
                case_root.mkdir(mode=0o700)
                seed_root, source_root = create_dependency_seed(case_root)
                browser_root = seed_root / upgrade.DEPENDENCY_SEED_COMPONENTS["playwrightBrowsers"]
                if case == "absolute":
                    link = browser_root / "unsafe"
                    link.symlink_to((browser_root / "chromium-1228" / "chrome").resolve())
                elif case == "escape":
                    outside = case_root / "outside-browser-seed"
                    outside.write_bytes(b"outside")
                    outside.chmod(0o600)
                    link = browser_root / "unsafe"
                    link.symlink_to(os.path.relpath(outside, browser_root))
                elif case == "escape-reentry":
                    link = browser_root / "unsafe"
                    link.symlink_to("../playwright-browsers/chromium-1228/chrome")
                elif case == "dangling":
                    link = browser_root / "unsafe"
                    link.symlink_to("missing-browser-file")
                elif case == "resolution-cycle":
                    (browser_root / "first").symlink_to("second")
                    (browser_root / "second").symlink_to("first")
                else:
                    first = browser_root / "first"
                    second = browser_root / "second"
                    first.mkdir(mode=0o700)
                    second.mkdir(mode=0o700)
                    (first / "to-second").symlink_to("../second", target_is_directory=True)
                    (second / "to-first").symlink_to("../first", target_is_directory=True)

                with self.assertRaisesRegex(
                    upgrade.UpgradeRehearsalError, "link|cyclic|escapes"
                ) as error:
                    upgrade.validate_dependency_seed(
                        seed_root,
                        expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
                        source_root=source_root,
                    )
                self.assertEqual("DEPENDENCY_SEED_LINK", error.exception.code)

    def test_dependency_seed_requires_matching_canonical_aggregate_trust_anchor(self) -> None:
        seed_root, source_root = create_dependency_seed(self.root)
        expected = dependency_seed_trust_anchor(seed_root)
        accepted = upgrade.validate_dependency_seed(
            seed_root,
            expected_aggregate_sha256=expected,
            source_root=source_root,
        )
        self.assertEqual(expected, accepted.evidence["aggregateSha256"])

        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "expected aggregate"
        ) as error:
            upgrade.validate_dependency_seed(
                seed_root,
                expected_aggregate_sha256="0" * 64,
                source_root=source_root,
            )
        self.assertEqual("DEPENDENCY_SEED_TRUST_ANCHOR", error.exception.code)

        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "SHA-256"):
            upgrade.validate_dependency_seed(
                seed_root,
                expected_aggregate_sha256="missing",
                source_root=source_root,
            )

    def test_dependency_seed_rejects_manifest_and_candidate_source_drift(self) -> None:
        seed_root, source_root = create_dependency_seed(self.root)
        manifest = json.loads((seed_root / "manifest.json").read_text(encoding="utf-8"))
        manifest["components"]["pnpmStore"]["treeSha256"] = "f" * 64
        (seed_root / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        (seed_root / "manifest.json").chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "digest"):
            upgrade.validate_dependency_seed(
                seed_root,
                expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
                source_root=source_root,
            )

        reactor_poms = (
            "pom.xml",
            "web-starter-core/pom.xml",
            "web-starter-system/pom.xml",
            "web-starter-security/pom.xml",
            "web-starter-project/pom.xml",
            "web-starter-mcp/pom.xml",
        )
        for index, relative in enumerate(reactor_poms):
            with self.subTest(reactor_pom=relative):
                seed_root, source_root = create_dependency_seed(
                    self.root / f"source-drift-{index}"
                )
                source_path = source_root / relative
                source_path.write_text("changed reactor pom\n", encoding="utf-8")
                source_path.chmod(0o600)
                with self.assertRaisesRegex(
                    upgrade.UpgradeRehearsalError, "current candidate"
                ):
                    upgrade.validate_dependency_seed(
                        seed_root,
                        expected_aggregate_sha256=dependency_seed_trust_anchor(
                            seed_root
                        ),
                        source_root=source_root,
                    )

    def test_current_adapter_snapshot_uses_absolute_file_and_explicit_pythonpath(self) -> None:
        snapshot = self.root / "snapshot"
        scripts = snapshot / "scripts"
        scripts.mkdir(parents=True, mode=0o700)
        adapter = scripts / "prepare_release_runtime_acceptance.py"
        adapter.write_text("raise SystemExit(0)\n", encoding="utf-8")
        adapter.chmod(0o600)

        command = upgrade.frozen_python_command(
            snapshot,
            "scripts/prepare_release_runtime_acceptance.py",
            "--help",
        )
        environment = upgrade.frozen_python_environment(snapshot, {})
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertTrue(Path(command[2]).is_absolute())
        self.assertEqual("-B", command[1])
        self.assertNotIn("-m", command)
        self.assertEqual(
            [str(scripts.resolve()), str(snapshot.resolve())],
            environment["PYTHONPATH"].split(os.pathsep),
        )

    def test_adapter_allowlist_does_not_claim_the_files_are_from_v1(self) -> None:
        self.assertIn(
            "scripts/prepare_release_runtime_acceptance.py",
            upgrade.CURRENT_ADAPTER_FILES,
        )
        self.assertNotIn(
            "scripts/prepare_release_runtime_acceptance.py",
            upgrade.V1_TAG_SCRIPT_FILES,
        )

    def test_pkcs8_plan_is_portable_and_never_uses_pkey_check(self) -> None:
        commands = upgrade.pkcs8_command_plan(
            "/usr/bin/openssl",
            self.root / "private.pem",
            self.root / "private.der",
            self.root / "decoded.pem",
        )
        flattened = [item for command in commands for item in command]
        self.assertEqual("genpkey", commands[0][1])
        self.assertEqual("pkcs8", commands[1][1])
        self.assertIn("-topk8", commands[1])
        self.assertIn("DER", commands[1])
        self.assertEqual("pkcs8", commands[2][1])
        self.assertIn("-inform", commands[2])
        self.assertNotIn("pkey", flattened)
        self.assertNotIn("-check", flattened)

    def test_pkcs8_decode_preflight_requires_private_key_envelope_and_private_mode(self) -> None:
        valid = self.root / "decoded.pem"
        pkcs8_begin = "-----BEGIN " + "PRIVATE KEY-----"
        pkcs8_end = "-----END " + "PRIVATE KEY-----"
        valid.write_text(
            f"{pkcs8_begin}\nAA==\n{pkcs8_end}\n",
            encoding="ascii",
        )
        valid.chmod(0o600)
        upgrade.validate_decoded_pkcs8(valid)

        wrong = self.root / "wrong.pem"
        rsa_begin = "-----BEGIN RSA " + "PRIVATE KEY-----"
        rsa_end = "-----END RSA " + "PRIVATE KEY-----"
        wrong.write_text(
            f"{rsa_begin}\nAA==\n{rsa_end}\n",
            encoding="ascii",
        )
        wrong.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "PKCS#8"):
            upgrade.validate_decoded_pkcs8(wrong)

        valid.chmod(0o644)
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "private"):
            upgrade.validate_decoded_pkcs8(valid)

    def test_v1_kid_matches_sha256_base64url_contract(self) -> None:
        document = bytes(range(256)) + b"x" * 64
        expected = "k3dvoSl9-i5oOIrOp0UPQmGXd2uQUHOWG8eKZFPUpdk"
        self.assertEqual(expected, upgrade.compute_v1_kid(document))

    def test_retiring_v1_jwk_covers_the_v1_token_ttl_and_clock_skew(self) -> None:
        now = 1_800_000_000
        self.assertEqual(
            now
            + upgrade.V1_ACCESS_TOKEN_TTL_SECONDS
            + upgrade.RETIRING_KEY_CLOCK_SKEW_SECONDS,
            upgrade.retiring_key_retain_until_epoch_seconds(now),
        )
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "NumericDate"):
            upgrade.retiring_key_retain_until_epoch_seconds(0)

    def test_jwk_set_adapter_receives_and_binds_retiring_expiry(self) -> None:
        frozen = self.root / "frozen"
        adapter = frozen / "scripts" / "acceptance_jwk_set.py"
        adapter.parent.mkdir(parents=True)
        adapter.write_text("raise SystemExit(0)\n", encoding="utf-8")
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.runtime_root.mkdir(mode=0o700)
        expected_expiry = 1_800_008_100

        class CapturingRunner:
            command: list[str] = []

            def run(self, command, **_kwargs):
                self.command = list(command)
                output = Path(self.command[self.command.index("--output") + 1])
                output.write_text(
                    json.dumps({
                        "keys": [
                            {"kid": "v2-key", "d": "private"},
                            {"kid": "v1-key", "exp": expected_expiry},
                        ]
                    }),
                    encoding="utf-8",
                )
                return upgrade.CommandResult(0, b"", b"")

        runner = CapturingRunner()
        with patch.object(
            upgrade,
            "retiring_key_retain_until_epoch_seconds",
            return_value=expected_expiry,
        ):
            result = upgrade._create_jwk_set(
                runtime,
                runner,  # type: ignore[arg-type]
                frozen,
                {
                    "v1": {"pkcs1": self.root / "v1.der"},
                    "v2": {"pkcs1": self.root / "v2.der"},
                    "v1Kid": "v1-key",
                    "v2Kid": "v2-key",
                },
            )

        self.assertEqual(runtime.runtime_root / "oauth-jwk-set.json", result)
        option = runner.command.index("--retiring-retain-until-epoch-seconds")
        self.assertEqual(str(expected_expiry), runner.command[option + 1])

    def test_v2_runtime_keeps_v1_pepper_as_retiring_and_uses_nonlocal_hosts(self) -> None:
        names = upgrade.generate_resource_names(RUN_ID)
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime",
            names,
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.v2_commit = COMMIT
        runtime.runtime_root.mkdir(mode=0o700)
        v1_private = runtime.runtime_root / "v1.der"
        v1_public = runtime.runtime_root / "v1-public.der"
        v1_private.write_bytes(b"private-pkcs8")
        v1_public.write_bytes(b"public-x509")
        jwk = runtime.runtime_root / "keys.json"
        jwk.write_text('{"keys":[]}\n', encoding="utf-8")
        tls_key = runtime.runtime_root / "tls.key"
        tls_cert = runtime.runtime_root / "tls.crt"
        tls_key.write_text("key", encoding="ascii")
        tls_cert.write_text("cert", encoding="ascii")
        values = upgrade._runtime_environment(
            runtime,
            {
                "v1": {"pkcs8": v1_private, "public": v1_public},
                "v2Kid": "upgrade-active-test",
            },
            jwk,
            {"key": tls_key, "certificate": tls_cert},
        )
        self.assertEqual(
            values["WEB_STARTER_TOKEN_PEPPER"],
            values["WEB_STARTER_CREDENTIAL_PEPPER_RETIRING"],
        )
        self.assertEqual("v1", values["WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION"])
        self.assertEqual("upgrade-v2", values["WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION"])
        self.assertNotEqual(
            values["WEB_STARTER_CREDENTIAL_PEPPER"],
            values["WEB_STARTER_CREDENTIAL_PEPPER_RETIRING"],
        )
        allowed = values["WEB_STARTER_MCP_ALLOWED_HOSTS"]
        self.assertIn(names.public_hostname, allowed)
        self.assertIn(names.private_hostname, allowed)
        self.assertNotIn("127.0.0.1", allowed)
        self.assertEqual(
            base64.b64encode(b"private-pkcs8").decode("ascii"),
            values["WEB_STARTER_OAUTH_RSA_PRIVATE_KEY"],
        )
        self.assertEqual(
            f"{upgrade.V1_ACCESS_TOKEN_TTL_SECONDS}s",
            values["WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL"],
        )
        self.assertEqual(COMMIT, values["WEB_STARTER_GIT_COMMIT"])
        runtime.v2_commit = None
        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "frozen V2 commit is unavailable"
        ):
            upgrade._runtime_environment(
                runtime,
                {
                    "v1": {"pkcs8": v1_private, "public": v1_public},
                    "v2Kid": "upgrade-active-test",
                },
                jwk,
                {"key": tls_key, "certificate": tls_cert},
            )

    def test_ports_are_unique_unprivileged_and_detect_existing_listener(self) -> None:
        ports = upgrade.allocate_unique_loopback_ports()
        self.assertEqual(3, len(set(ports)))
        self.assertTrue(all(1024 <= value <= 65535 for value in ports))

        upgrade.assert_loopback_ports_unused(
            ports,
            connector=lambda *_args, **_kwargs: (_ for _ in ()).throw(ConnectionRefusedError()),
        )

        class Connection:
            def close(self) -> None:
                pass

        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "already in use"):
            upgrade.assert_loopback_ports_unused(
                (18080, 18443, 18081), connector=lambda *_args, **_kwargs: Connection()
            )

    def test_compose_port_preflight_requires_exact_loopback_set(self) -> None:
        ports = upgrade.Ports(18080, 18443, 18081)
        document = {
            "services": {
                "mysql": {},
                "redis": {},
                "app": {"ports": [{"host_ip": "127.0.0.1", "published": 18081, "target": 8081}]},
                "nginx": {"ports": [{"host_ip": "127.0.0.1", "published": 18080, "target": 8080}]},
                "mcp-public-nginx": {
                    "ports": [{"host_ip": "127.0.0.1", "published": 18443, "target": 8443}]
                },
            }
        }
        upgrade.assert_expected_published_ports(document, ports)
        document["services"]["mysql"]["ports"] = [
            {"host_ip": "127.0.0.1", "published": 13306, "target": 3306}
        ]
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "exact set"):
            upgrade.assert_expected_published_ports(document, ports)

    def test_image_references_reject_option_url_whitespace_and_traversal(self) -> None:
        self.assertEqual(
            "web-starter-app:candidate",
            upgrade.validate_image_reference("web-starter-app:candidate", "App"),
        )
        for value in (
            "--privileged", " app:tag", "https://registry/image", "repo/../image",
            "sha256:" + "a" * 64,
        ):
            with self.subTest(value=value), self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade.validate_image_reference(value, "App")

    def test_state_machine_is_ordered_exact_and_observations_are_immutable(self) -> None:
        state = upgrade.EvidenceState()
        self.assertEqual(set(upgrade.REQUIRED_CHECKS), set(state.checks))
        state.start_phase("source-freeze")
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "frozen order"):
            state.start_phase("runtime-preflight")
        state.mark("source.annotatedV1Tag", "PASS", "ANNOTATED_TAG_VERIFIED")
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "immutable"):
            state.mark("source.annotatedV1Tag", "FAIL", "SECOND_OBSERVATION")
        state.mark("credential.preUpgradeRefreshRotationAccepted", "NOT_COVERED", "V1_PKCE_REFRESH_NOT_CAPTURED")
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "immutable"):
            state.mark("credential.preUpgradeRefreshRotationAccepted", "PASS", "INVENTED_REFRESH_PASS")

    def test_refresh_token_not_covered_prevents_ac05_and_top_level_pass(self) -> None:
        state = upgrade.EvidenceState()
        for name in upgrade.REQUIRED_CHECKS:
            status = "NOT_COVERED" if name == "credential.preUpgradeRefreshRotationAccepted" else "PASS"
            detail = "V1_PKCE_REFRESH_NOT_CAPTURED" if status == "NOT_COVERED" else "REAL_OBSERVATION_PASS"
            state.mark(name, status, detail)
        self.assertEqual("NOT_COVERED", upgrade.overall_status(state.checks))
        self.assertEqual(upgrade.EXIT_INCOMPLETE, upgrade.process_exit_code("NOT_COVERED"))
        acceptance = upgrade.aggregate_acceptance(state.checks)
        self.assertEqual("NOT_COVERED", acceptance["V2-AC-05"]["status"])
        self.assertEqual("NOT_COVERED", acceptance["V2-AC-40"]["status"])

    def test_fail_and_environment_statuses_are_nonzero(self) -> None:
        for status, expected in (
            ("PASS", 0),
            ("FAIL", 1),
            ("NOT_COVERED", 6),
            ("ENV_REQUIRED", 6),
        ):
            with self.subTest(status=status):
                self.assertEqual(expected, upgrade.process_exit_code(status))

    def test_schema_exact_check_set_matches_code(self) -> None:
        schema = json.loads(upgrade.SCHEMA_PATH.read_text(encoding="utf-8"))
        required = schema["properties"]["checks"]["required"]
        properties = schema["properties"]["checks"]["properties"]
        self.assertEqual(set(upgrade.REQUIRED_CHECKS), set(required))
        self.assertEqual(set(upgrade.REQUIRED_CHECKS), set(properties))
        self.assertFalse(schema["properties"]["checks"]["additionalProperties"])

    def test_sanitized_incomplete_result_is_private_and_exits_six(self) -> None:
        output = self.root / "evidence"
        output.mkdir(mode=0o700)
        runtime_root = upgrade._private_temp_root(RUN_ID)
        runtime = upgrade.RuntimeContext(
            output,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.cleanup_summary = {
            "status": "PASS",
            "exactOwnershipVerified": True,
            "removed": {
                "containers": 0, "volumes": 0, "networks": 0,
                "imageTags": 0, "images": 0,
            },
            "residual": {
                "containers": False, "volumes": False, "networks": False,
                "imageTags": False, "images": False,
            },
            "failureCodes": [],
            "privateRuntimeRemoved": True,
        }
        self.assertTrue(upgrade._remove_private_runtime(runtime))
        exit_code = upgrade._write_result(runtime, {})
        self.assertEqual(6, exit_code)
        result = output / upgrade.RESULT_NAME
        checksum = output / upgrade.CHECKSUM_NAME
        self.assertEqual(0o600, stat.S_IMODE(result.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(checksum.stat().st_mode))
        document = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual("NOT_COVERED", document["status"])
        self.assertEqual(6, document["processExitCode"])
        self.assertFalse(document["evidencePolicy"]["containsSecrets"])
        self.assertFalse(document["privateCommandLogs"]["persisted"])

    def test_failed_runtime_removal_is_reported_as_persisted_and_nonzero(self) -> None:
        output = self.root / "failed-evidence"
        output.mkdir(mode=0o700)
        runtime_root = upgrade._private_temp_root(RUN_ID)
        state = upgrade.EvidenceState()
        state.mark("cleanup.exactOwnedResources", "FAIL", "PRIVATE_RUNTIME_REMOVAL_FAILED")
        runtime = upgrade.RuntimeContext(
            output,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            state,
        )
        runtime.cleanup_summary = {
            "status": "FAIL",
            "exactOwnershipVerified": False,
            "removed": {
                "containers": 0, "volumes": 0, "networks": 0,
                "imageTags": 0, "images": 0,
            },
            "residual": {
                "containers": False, "volumes": False, "networks": False,
                "imageTags": False, "images": False,
            },
            "failureCodes": ["PRIVATE_RUNTIME_REMOVAL_FAILED"],
            "privateRuntimeRemoved": False,
        }
        self.assertEqual(1, upgrade._write_result(runtime, {}))
        document = json.loads((output / upgrade.RESULT_NAME).read_text(encoding="utf-8"))
        self.assertTrue(document["privateCommandLogs"]["persisted"])
        self.assertTrue(document["evidencePolicy"]["privateRuntimePersisted"])
        shutil.rmtree(runtime_root)

    def test_service_account_fixture_explicitly_issues_a_v1_direct_token_privately(self) -> None:
        source = upgrade.SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('/api/security/service-accounts/{account[\'id\']}/tokens', source)
        self.assertIn('token_file = credential_root / "service-token.json"', source)
        self.assertIn('write_private_json(token_file, {"token": token["token"]})', source)
        self.assertIn('lifecycle_pat_file = credential_root / "lifecycle-pat.json"', source)
        self.assertIn('write_private_json(lifecycle_pat_file, {"token": lifecycle_pat["token"]})', source)
        self.assertIn('"credential.preUpgradeServiceAccessAccepted"', source)
        self.assertIn('"lifecycle.disabledServiceRejectedAndReadBack"', source)

    def test_public_evidence_secret_scan_rejects_token_password_cookie_and_private_key(self) -> None:
        safe = {"status": "NOT_COVERED", "sha256": "a" * 64}
        upgrade._secret_scan_public_document(safe)
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        jwt_shape = ".".join(("eyJ" + "a" * 11, "b" * 11, "c" * 11))
        for document in (
            {"password": "must-not-persist"},
            {"cookie": "WEB_STARTER_SESSION=secret"},
            {"value": private_key_marker},
            {"value": jwt_shape},
        ):
            with self.subTest(document=document), self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade._secret_scan_public_document(document)

    def test_private_command_runner_never_uses_shell_and_logs_are_0600(self) -> None:
        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        runner = upgrade.PrivateCommandRunner(logs)
        result = runner.run(
            [sys.executable, "-c", "print('private command output')"],
            label="unit-command",
        )
        self.assertEqual(0, result.returncode)
        files = list(logs.iterdir())
        self.assertEqual(1, len(files))
        self.assertEqual(0o600, stat.S_IMODE(files[0].stat().st_mode))
        self.assertIn(b"private command output", files[0].read_bytes())

    def test_private_command_failure_exposes_only_a_bounded_safe_label(self) -> None:
        logs = self.root / "failure-logs"
        logs.mkdir(mode=0o700)
        runner = upgrade.PrivateCommandRunner(logs)
        with self.assertRaises(upgrade.UpgradeRehearsalError) as raised:
            runner.run(
                [sys.executable, "-c", "raise SystemExit(7)"],
                label="sdk-7/McpSdkCrudRuntimeIT-" + "x" * 100,
            )

        expected_label = ("SDK_7_MCPSDKCRUDRUNTIMEIT_" + "X" * 100)[:64]
        self.assertEqual(
            "COMMAND_FAILED_" + expected_label,
            raised.exception.code,
        )
        self.assertLessEqual(len(raised.exception.code), 96)
        self.assertRegex(raised.exception.code, r"^[A-Z][A-Z0-9_]+$")

    def test_failed_sdk_report_detail_exposes_only_type_and_source_line(self) -> None:
        report_directory = self.root / "failed-sdk-report"
        report_directory.mkdir(mode=0o700)
        test_class = "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"
        report = report_directory / f"TEST-{test_class}.xml"
        report.write_text(
            f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="{test_class}" tests="1" failures="1" errors="0" skipped="0">
  <testcase name="provesEachWriteCommitsOnce" classname="{test_class}">
    <failure type="org.opentest4j.AssertionFailedError">expected:
      secret-bearer-value
      at {test_class}.provesEachWriteCommitsOnce(McpSdkCrudRuntimeIT.java:196)
    </failure>
  </testcase>
</testsuite>
""",
            encoding="utf-8",
        )
        report.chmod(0o600)

        detail = upgrade._failed_sdk_report_detail(report_directory, test_class)

        self.assertEqual(
            "FAILURE_ORG_OPENTEST4J_ASSERTIONFAILEDERROR_LINE_196",
            detail,
        )
        self.assertNotIn("secret", detail.lower())
        self.assertLessEqual(len(detail), 72)
        self.assertRegex(detail, r"^[A-Z][A-Z0-9_]+$")

    def test_failed_sdk_report_detail_rejects_forbidden_xml_without_parsing(self) -> None:
        report_directory = self.root / "failed-sdk-forbidden-report"
        report_directory.mkdir(mode=0o700)
        report = report_directory / "TEST-unsafe.xml"
        report.write_text(
            '<!DOCTYPE testsuite [<!ENTITY secret SYSTEM "file:///private/secret">]>'
            '<testsuite name="x">&secret;</testsuite>',
            encoding="utf-8",
        )
        report.chmod(0o600)

        self.assertEqual(
            "FORBIDDEN_REPORT_XML",
            upgrade._failed_sdk_report_detail(report_directory, "x"),
        )

    def test_mcp_crud_transaction_fault_installs_and_removes_exact_constraint(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-crud-fault",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        responses = [b"0\n", b"", b"1\n", b"", b"0\n"]
        with patch.object(
            upgrade, "_mysql_query", side_effect=responses
        ) as mysql_query:
            with upgrade._mcp_crud_transaction_fault(
                runtime, object(), f"upgrade-old-pat-crud-{RUN_ID}"
            ):
                pass

        self.assertEqual(5, mysql_query.call_count)
        statements = [
            invocation.args[2] for invocation in mysql_query.call_args_list
        ]
        self.assertIn("COUNT(*)", statements[0])
        self.assertIn("ADD CONSTRAINT chk_webstarter_ac40_tx_audit", statements[1])
        self.assertIn(
            f"trace_id='upgrade-old-pat-crud-{RUN_ID}-transaction-audit-failure'",
            statements[1],
        )
        self.assertIn("COUNT(*)", statements[2])
        self.assertIn("DROP CHECK chk_webstarter_ac40_tx_audit", statements[3])
        self.assertIn("COUNT(*)", statements[4])
        self.assertTrue(all(
            invocation.kwargs["database"] == runtime.names.target_database
            for invocation in mysql_query.call_args_list
        ))

    def test_mcp_crud_transaction_fault_removes_constraint_when_sdk_fails(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime-crud-fault-failure",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        responses = [b"0\n", b"", b"1\n", b"", b"0\n"]
        with patch.object(
            upgrade, "_mysql_query", side_effect=responses
        ) as mysql_query:
            with self.assertRaisesRegex(RuntimeError, "sdk failed"):
                with upgrade._mcp_crud_transaction_fault(
                    runtime, object(), f"upgrade-old-pat-crud-{RUN_ID}"
                ):
                    raise RuntimeError("sdk failed")

        self.assertEqual(5, mysql_query.call_count)
        self.assertIn(
            "DROP CHECK chk_webstarter_ac40_tx_audit",
            mysql_query.call_args_list[3].args[2],
        )

    def test_private_runtime_removal_requires_exact_sentinel(self) -> None:
        runtime_root = self.root / "owned-runtime"
        runtime_root.mkdir(mode=0o700)
        upgrade.write_private_json(
            runtime_root / ".web-starter-upgrade-owner.json",
            {"owner": upgrade.OWNER_VALUE, "runId": RUN_ID},
        )
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        playwright_temp = upgrade._playwright_temp_root(runtime)
        self.assertTrue(upgrade._remove_private_runtime(runtime))
        self.assertFalse(runtime_root.exists())
        self.assertFalse(playwright_temp.exists())

        tampered = self.root / "tampered-runtime"
        tampered.mkdir(mode=0o700)
        upgrade.write_private_json(
            tampered / ".web-starter-upgrade-owner.json",
            {"owner": upgrade.OWNER_VALUE, "runId": RUN_ID},
        )
        sentinel = tampered / ".web-starter-upgrade-owner.json"
        sentinel.write_text('{"owner":"other","runId":"0123456789ab"}\n', encoding="utf-8")
        sentinel.chmod(0o600)
        runtime.runtime_root = tampered
        self.assertFalse(upgrade._remove_private_runtime(runtime))
        shutil.rmtree(tampered)

    def test_cleanup_refuses_container_without_owner_run_role_and_project_match(self) -> None:
        runtime = upgrade.RuntimeContext(
            self.root,
            self.root / "runtime",
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.resource_cleanup_authorized = True

        class FakeRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def run(self, command, **_kwargs):
                value = list(command)
                self.commands.append(value)
                if value[:4] == ["docker", "container", "ls", "--all"]:
                    return upgrade.CommandResult(0, b"unsafe-container\n", b"")
                if value[:3] == ["docker", "container", "inspect"]:
                    document = [{
                        "Config": {"Labels": {
                            upgrade.LABEL_OWNER: upgrade.OWNER_VALUE,
                            upgrade.LABEL_RUN: RUN_ID,
                            upgrade.LABEL_ROLE: "app",
                            "com.docker.compose.service": "app",
                            "com.docker.compose.project": "a-different-project",
                        }}
                    }]
                    return upgrade.CommandResult(0, json.dumps(document).encode(), b"")
                return upgrade.CommandResult(0, b"", b"")

        runner = FakeRunner()
        summary = upgrade._cleanup_owned_resources(runtime, runner)  # type: ignore[arg-type]
        self.assertEqual("FAIL", summary["status"])
        self.assertIn("container-ownership", summary["failureCodes"])
        self.assertFalse(any(command[:3] == ["docker", "container", "rm"] for command in runner.commands))

    def test_script_contains_no_broad_docker_or_database_deletion(self) -> None:
        source = upgrade.SCRIPT_PATH.read_text(encoding="utf-8").lower()
        for forbidden in (
            "docker compose down",
            "docker system prune",
            "docker volume prune",
            "docker volume rm",
            "drop database",
            "shell=true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_crud_audit_fixture_precedes_browser_and_uses_the_shared_prefix_contract(self) -> None:
        source = upgrade.SCRIPT_PATH.read_text(encoding="utf-8")
        crud_runtime = source.rindex(
            '"dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"'
        )
        browser_runtime = source.rindex("_run_playwright(runtime, runner")
        self.assertLess(crud_runtime, browser_runtime)
        self.assertIn("WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX", source)
        self.assertNotIn("WEB_STARTER_UPGRADE_MCP_CRUD_TRACE_PREFIX", source)

    def test_only_crud_sdk_environment_receives_web_audit_login_credentials(self) -> None:
        runtime_root = self.root / "runtime-sdk-env"
        runtime_root.mkdir(mode=0o700)
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        seed_root = runtime_root / "dependency-seed"
        (seed_root / "maven-home").mkdir(parents=True, mode=0o700)
        (seed_root / "maven-repository").mkdir(mode=0o700)
        runtime.environment = {
            "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "acceptance-admin",
            "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": "private-password",
        }
        arguments = (
            runtime,
            {"truststore": self.root / "truststore", "hosts": self.root / "hosts"},
            {"ownerId": "1", "projectId": "2"},
            self.root / "token.json",
        )

        read_only = upgrade._sdk_environment(
            *arguments, public=False, trace_prefix="read-only"
        )
        crud = upgrade._sdk_environment(
            *arguments, public=False, trace_prefix="crud", web_audit=True
        )
        v1_compatible = upgrade._sdk_environment(
            *arguments,
            public=True,
            trace_prefix="v1-compatible",
            audit_trace_filter_supported=False,
        )
        service_oauth = upgrade._sdk_environment(
            *arguments,
            public=True,
            trace_prefix="service-oauth",
            expected_actor_type="SERVICE_ACCOUNT",
            expected_client_id_present=True,
        )

        self.assertNotIn("WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME", read_only)
        self.assertNotIn("WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD", read_only)
        self.assertNotIn("WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL", read_only)
        self.assertEqual(
            "acceptance-admin", crud["WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME"]
        )
        self.assertEqual(
            "private-password", crud["WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD"]
        )
        self.assertEqual(
            "http://127.0.0.1:18080",
            crud["WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL"],
        )
        self.assertEqual(
            "true",
            read_only["WEB_STARTER_MCP_AUDIT_TRACE_FILTER_SUPPORTED"],
        )
        self.assertEqual(
            "false",
            v1_compatible["WEB_STARTER_MCP_AUDIT_TRACE_FILTER_SUPPORTED"],
        )
        self.assertEqual(
            "USER",
            read_only["WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE"],
        )
        self.assertEqual(
            "SERVICE_ACCOUNT",
            service_oauth["WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE"],
        )
        self.assertEqual(
            "true",
            service_oauth["WEB_STARTER_MCP_EXPECTED_CLIENT_ID_PRESENT"],
        )
        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "expected actor type"
        ):
            upgrade._sdk_environment(
                *arguments,
                public=True,
                trace_prefix="invalid-actor",
                expected_actor_type="UNKNOWN",
            )

    def test_pre_upgrade_pkce_user_token_is_first_v2_external_credential(self) -> None:
        source = upgrade.SCRIPT_PATH.read_text(encoding="utf-8")
        refresh_rotation = source.rindex("_rotate_and_replay_v2_refresh(")
        old_client_credentials = source.rindex(
            'trace_prefix=f"upgrade-old-oauth-{run_id}"'
        )

        self.assertLess(refresh_rotation, old_client_credentials)
        self.assertIn("OLD_PKCE_TOKEN_FIRST_EXTERNAL_CALL", source)
        self.assertNotIn("OLD_TOKEN_FIRST_EXTERNAL_CALL", source)

    def test_sdk_and_browser_dependencies_are_private_offline_and_have_no_retry_download(self) -> None:
        seed_root, source_root = create_dependency_seed(self.root)
        seed = upgrade.validate_dependency_seed(
            seed_root,
            expected_aggregate_sha256=dependency_seed_trust_anchor(seed_root),
            source_root=source_root,
        )
        runtime_root = self.root / "runtime-offline"
        runtime_root.mkdir(mode=0o700)
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        upgrade._copy_dependency_seed(seed, runtime)
        maven_home, _, _ = upgrade._private_maven_paths(runtime)
        maven_repository = upgrade._private_maven_repository(runtime)
        browser_environment = upgrade._playwright_environment(runtime)
        self.assertTrue(upgrade._inside(maven_home, runtime_root))
        self.assertTrue(upgrade._inside(maven_repository, runtime_root))
        self.assertTrue(
            upgrade._inside(Path(browser_environment["COREPACK_HOME"]), runtime_root)
        )
        self.assertTrue(
            upgrade._inside(
                Path(browser_environment["PLAYWRIGHT_BROWSERS_PATH"]), runtime_root
            )
        )
        playwright_temp = Path(browser_environment["TMPDIR"])
        self.assertEqual(runtime.playwright_temp_root, playwright_temp)
        self.assertEqual(runtime_root.parent, playwright_temp.parent)
        self.assertFalse(upgrade._inside(playwright_temp, runtime_root))
        self.assertEqual(0o700, stat.S_IMODE(playwright_temp.stat().st_mode))
        self.assertEqual(
            {"owner": upgrade.OWNER_VALUE, "runId": RUN_ID},
            json.loads(
                (playwright_temp / ".web-starter-playwright-owner.json")
                .read_text(encoding="utf-8")
            ),
        )
        self.assertNotIn("NODE_COMPILE_CACHE", browser_environment)
        self.assertEqual("0", browser_environment["COREPACK_ENABLE_NETWORK"])
        self.assertEqual("true", browser_environment["NPM_CONFIG_OFFLINE"])
        self.assertEqual("1", browser_environment["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"])

    def test_personal_credential_http_failure_code_is_not_secret_shaped(self) -> None:
        upgrade._secret_scan_public_document({
            "detailCode": "PERSONAL_CREDENTIAL_PRE_HTTP_401",
        })

    def test_failed_playwright_detail_uses_structured_location_without_message(self) -> None:
        suites = []
        for file_name, titles in upgrade.PLAYWRIGHT_EXPECTED_TITLES.items():
            specs = []
            for index, title in enumerate(titles):
                failed = file_name == "frontend-quality-runtime.spec.ts" and index == 0
                result = {
                    "status": "failed" if failed else "passed",
                    "retry": 0,
                }
                if failed:
                    result["error"] = {
                        "message": "must-not-enter-public-evidence",
                        "location": {
                            "file": f"/private/source/e2e/{file_name}",
                            "line": 171,
                            "column": 9,
                        },
                    }
                specs.append({
                    "title": title,
                    "ok": not failed,
                    "tests": [{
                        "expectedStatus": "passed",
                        "status": "unexpected" if failed else "expected",
                        "results": [result],
                    }],
                })
            suites.append({"file": file_name, "specs": specs})

        detail = upgrade._failed_playwright_report_detail(json.dumps({
            "suites": suites,
            "errors": [],
        }).encode())

        self.assertEqual("FQ_SPEC_1_FAILED_LINE_171", detail)
        self.assertNotIn("must-not-enter", detail)

        source = upgrade.SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count('"--offline"'), 3)
        self.assertNotIn("run_with_one_retry", source)
        self.assertNotIn("playwright-private-chromium-install", source)
        self.assertNotIn('"install", "--no-shell", "chromium"', source)

    def test_help_is_available_without_contacting_docker(self) -> None:
        result = subprocess.run(
            [sys.executable, str(upgrade.SCRIPT_PATH), "--help"],
            cwd=upgrade.REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--preflight-only", result.stdout)
        self.assertIn("--mysql-image", result.stdout)
        self.assertIn("--redis-image", result.stdout)
        self.assertIn("--dependency-seed", result.stdout)
        self.assertIn("--expected-dependency-seed-sha256", result.stdout)
        self.assertNotIn("--v2-app-image", result.stdout)
        self.assertNotIn("--v2-nginx-image", result.stdout)
        self.assertNotIn("--run-id", result.stdout)

    def test_cli_fails_closed_when_dependency_seed_trust_anchor_is_missing(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(upgrade.SCRIPT_PATH),
                "--output-dir", str(self.root / "output"),
                "--mysql-image", "mysql@sha256:" + "1" * 64,
                "--redis-image", "redis@sha256:" + "2" * 64,
                "--dependency-seed", str(self.root / "dependency-seed"),
            ],
            cwd=upgrade.REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("--expected-dependency-seed-sha256", result.stderr)
        self.assertFalse((self.root / "output").exists())


if __name__ == "__main__":
    unittest.main()
