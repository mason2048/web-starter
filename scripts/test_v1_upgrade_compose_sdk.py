from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import scripts.rehearse_v1_to_v2_upgrade as upgrade
import scripts.validate_v1_upgrade_evidence as evidence_gate


RUN_ID = "abcdef012345"
SDK_CLASS = "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT"


class V1UpgradeComposeAndSdkProofTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-upgrade-p0-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_dependency_seed_source_contract_covers_exact_mcp_reactor_poms(self) -> None:
        reactor_poms = (
            "pom.xml",
            "web-starter-core/pom.xml",
            "web-starter-system/pom.xml",
            "web-starter-security/pom.xml",
            "web-starter-project/pom.xml",
            "web-starter-mcp/pom.xml",
        )
        self.assertEqual(
            reactor_poms,
            tuple(
                relative
                for relative in upgrade.DEPENDENCY_SEED_SOURCE_FILES
                if relative.endswith("pom.xml")
            ),
        )
        self.assertEqual(
            upgrade.DEPENDENCY_SEED_SOURCE_FILES,
            evidence_gate.DEPENDENCY_SEED_SOURCE_FILES,
        )
        self.assertTrue(
            set(upgrade.DEPENDENCY_SEED_SOURCE_FILES).issubset(
                upgrade.CURRENT_RUNTIME_SOURCE_FILES
            )
        )
        self.assertTrue(
            set(evidence_gate.DEPENDENCY_SEED_SOURCE_FILES).issubset(
                evidence_gate.RUNTIME_SOURCE_FILES
            )
        )

    def runtime(self) -> upgrade.RuntimeContext:
        runtime_root = self.root / "runtime"
        runtime_root.mkdir(mode=0o700, exist_ok=True)
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(18080, 18443, 18081),
            upgrade.EvidenceState(),
        )
        runtime.created_image_tags = {
            "mysql": "upgrade-mysql:candidate",
            "redis": "upgrade-redis:candidate",
            "v1-app": "upgrade-v1-app:candidate",
            "v1-nginx": "upgrade-v1-nginx:candidate",
            "v2-app": "upgrade-v2-app:candidate",
            "v2-nginx": "upgrade-v2-nginx:candidate",
        }
        runtime.resolved_images = {
            name: "sha256:" + character * 64
            for name, character in (
                ("mysql", "1"),
                ("redis", "2"),
                ("v1-app", "3"),
                ("v1-nginx", "4"),
                ("v2-app", "5"),
                ("v2-nginx", "6"),
            )
        }
        runtime.environment = {
            "WEB_STARTER_PUBLIC_TLS_CERT_FILE": str(self.root / "tls.crt"),
            "WEB_STARTER_PUBLIC_TLS_KEY_FILE": str(self.root / "tls.key"),
            "WEB_STARTER_CREDENTIAL_PEPPER": "active-pepper",
            "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION": "v2",
            "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING": "retiring-pepper",
            "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION": "v1",
            "WEB_STARTER_OAUTH_RSA_JWK_SET": '{"keys":[]}',
            "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": "v2-key",
            "WEB_STARTER_MANAGEMENT_USERNAME": "ops",
            "WEB_STARTER_MANAGEMENT_PASSWORD": "private-runtime-only",
        }
        seed_root = runtime_root / "dependency-seed"
        for relative in upgrade.DEPENDENCY_SEED_COMPONENTS.values():
            (seed_root / relative).mkdir(parents=True, mode=0o700)
        pnpm_entry = seed_root / "pnpm-store" / "v3" / "files" / "00" / "fixture"
        pnpm_entry.parent.mkdir(parents=True, mode=0o700)
        pnpm_entry.write_bytes(b"pnpm-store-entry")
        pnpm_entry.chmod(0o600)
        chromium = seed_root / "playwright-browsers" / "chromium-1228"
        chromium.mkdir(mode=0o700)
        (chromium / "INSTALLATION_COMPLETE").write_text("complete\n", encoding="utf-8")
        return runtime

    def snapshot_runtime_sources(self, runtime: upgrade.RuntimeContext) -> Path:
        runtime.v2_commit = "a" * 40

        def committed_worktree(arguments: tuple[str, ...]) -> bytes:
            self.assertEqual("show", arguments[0])
            _commit, relative = arguments[1].split(":", 1)
            return (upgrade.REPOSITORY_ROOT / relative).read_bytes()

        return upgrade._snapshot_current_runtime_sources(runtime, committed_worktree)

    def prepare_sdk_source(self, runtime: upgrade.RuntimeContext) -> Path:
        source = runtime.runtime_root / "v2-sdk-source"
        source.mkdir(mode=0o700)
        for relative in upgrade.CURRENT_RUNTIME_SOURCE_FILES:
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((upgrade.REPOSITORY_ROOT / relative).read_bytes())
        runtime.sdk_source_root = source
        runtime.sdk_source_hashes = {
            path.relative_to(source).as_posix(): upgrade.sha256_file(path)
            for path in sorted(source.rglob("*"))
            if path.is_file()
        }
        return source

    def test_real_v1_and_current_v2_ingress_sources_are_distinct(self) -> None:
        v1_root = self.root / "v1"
        v1_public = v1_root / "deploy/nginx/external-mcp.conf"
        v1_public.parent.mkdir(parents=True)
        payload = subprocess.run(
            [
                "git",
                "show",
                f"{upgrade.V1_COMMIT}:deploy/nginx/external-mcp.conf",
            ],
            cwd=upgrade.REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        v1_public.write_bytes(payload)
        current_root = self.root / "current"
        runtime = self.runtime()
        snapshot = self.snapshot_runtime_sources(runtime)
        self.assertEqual(snapshot, runtime.runtime_root / "frozen-current-source")
        upgrade.assert_version_specific_ingress_sources(v1_root, snapshot)
        for relative in ("deploy/nginx/nginx.conf", "deploy/nginx/nginx-public.conf"):
            source = (snapshot / relative).read_text(encoding="utf-8")
            self.assertNotIn("$http_referer", source)
            self.assertNotIn('"$request"', source)
        self.assertIn("listen 443 ssl;", payload.decode("utf-8"))
        self.assertIn(
            "listen 8443 ssl;",
            (snapshot / "deploy/nginx/external-mcp.conf").read_text(encoding="utf-8"),
        )
        self.assertFalse(current_root.exists())

    def test_v1_archive_extraction_is_python39_compatible_and_rejects_links(self) -> None:
        def archive(*, link: bool) -> bytes:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as document:
                pom = tarfile.TarInfo("pom.xml")
                payload = b"<project/>\n"
                pom.size = len(payload)
                document.addfile(pom, io.BytesIO(payload))
                if link:
                    unsafe = tarfile.TarInfo("unsafe-link")
                    unsafe.type = tarfile.SYMTYPE
                    unsafe.linkname = "/tmp/outside"
                    document.addfile(unsafe)
            return buffer.getvalue()

        class ArchiveRunner:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

            def run(self, _command, **_kwargs):
                return upgrade.CommandResult(0, self.payload, b"")

        runtime = self.runtime()
        extracted = upgrade._extract_v1_source(
            runtime, ArchiveRunner(archive(link=False))  # type: ignore[arg-type]
        )
        self.assertEqual(b"<project/>\n", (extracted / "pom.xml").read_bytes())

        unsafe_root = self.root / "unsafe-runtime"
        unsafe_root.mkdir(mode=0o700)
        unsafe_runtime = upgrade.RuntimeContext(
            self.root,
            unsafe_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(28080, 28443, 28081),
            upgrade.EvidenceState(),
        )
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "unsafe path"):
            upgrade._extract_v1_source(
                unsafe_runtime, ArchiveRunner(archive(link=True))  # type: ignore[arg-type]
            )

    def test_full_v2_archive_rejects_links_target_output_and_hash_drift(self) -> None:
        files = {
            "pom.xml": b"<project/>\n",
            "web-starter-mcp/pom.xml": b"<project/>\n",
            "mvnw": b"#!/bin/sh\n",
        }

        def archive(*, link: bool = False, target: bool = False) -> bytes:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as document:
                for name, payload in files.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    document.addfile(member, io.BytesIO(payload))
                if link:
                    member = tarfile.TarInfo("unsafe-link")
                    member.type = tarfile.SYMTYPE
                    member.linkname = "pom.xml"
                    document.addfile(member)
                if target:
                    payload = b"stale"
                    member = tarfile.TarInfo("web-starter-mcp/target/stale.class")
                    member.size = len(payload)
                    document.addfile(member, io.BytesIO(payload))
            return buffer.getvalue()

        class ArchiveRunner:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

            def run(self, _command, **_kwargs):
                return upgrade.CommandResult(0, self.payload, b"")

        def case_runtime(name: str, expected_hash: str | None = None) -> upgrade.RuntimeContext:
            runtime_root = self.root / name / "runtime"
            runtime_root.mkdir(parents=True, mode=0o700)
            runtime = upgrade.RuntimeContext(
                self.root / name,
                runtime_root,
                upgrade.generate_resource_names(RUN_ID),
                upgrade.Ports(18080, 18443, 18081),
                upgrade.EvidenceState(),
            )
            runtime.v2_commit = "a" * 40
            runtime.runtime_source_hashes = {
                "pom.xml": expected_hash or upgrade.sha256_bytes(files["pom.xml"]),
            }
            return runtime

        valid = case_runtime("v2-valid")
        source = upgrade._extract_v2_sdk_source(
            valid, ArchiveRunner(archive())  # type: ignore[arg-type]
        )
        self.assertEqual(files["pom.xml"], (source / "pom.xml").read_bytes())
        self.assertFalse(any(path.name == "target" for path in source.rglob("target")))

        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "unsafe path"):
            upgrade._extract_v2_sdk_source(
                case_runtime("v2-link"), ArchiveRunner(archive(link=True))  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "source tree is invalid"):
            upgrade._extract_v2_sdk_source(
                case_runtime("v2-target"), ArchiveRunner(archive(target=True))  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "does not match"):
            upgrade._extract_v2_sdk_source(
                case_runtime("v2-hash", "0" * 64),
                ArchiveRunner(archive()),  # type: ignore[arg-type]
            )

    def test_runtime_source_snapshot_has_exact_sdk_pom_compose_and_nginx_hashes(self) -> None:
        runtime = self.runtime()
        snapshot = self.snapshot_runtime_sources(runtime)
        self.assertEqual(
            set(upgrade.CURRENT_RUNTIME_SOURCE_FILES),
            set(runtime.runtime_source_hashes),
        )
        self.assertEqual(31, len(runtime.runtime_source_hashes))
        self.assertIn("Dockerfile", runtime.runtime_source_hashes)
        self.assertIn(".dockerignore", runtime.runtime_source_hashes)
        upgrade.assert_runtime_sources_unchanged(runtime)
        upgrade.assert_runtime_sources_unchanged(runtime, snapshot)

        changed = snapshot / "compose.production.yaml"
        changed.write_bytes(changed.read_bytes() + b"\n# drift\n")
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "changed"):
            upgrade.assert_runtime_sources_unchanged(runtime, snapshot)

    def test_overlays_use_frozen_v1_and_current_production_bases(self) -> None:
        runtime = self.runtime()
        v1_source = self.root / "v1-source"
        current_source = self.root / "current-source"
        (v1_source / "compose.yaml").parent.mkdir(parents=True)
        (v1_source / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
        (v1_source / "compose.public-mcp.yaml").write_text(
            "services: {}\n", encoding="utf-8"
        )
        current_source.mkdir()
        (current_source / "compose.production.yaml").write_text(
            "services: {}\n", encoding="utf-8"
        )

        v1_overlay, v2_overlay = upgrade._write_compose_overlays(
            runtime, v1_source, current_source, {}, {}
        )
        v1 = json.loads(v1_overlay.read_text(encoding="utf-8"))["services"]
        v2 = json.loads(v2_overlay.read_text(encoding="utf-8"))["services"]
        self.assertNotIn("ports", v1["app"])
        self.assertNotIn("ports", v1["nginx"])
        self.assertNotIn("ports", v1["mcp-public-nginx"])
        v1_log_root = runtime.runtime_root / "v1-public-nginx-redacted.conf"
        self.assertNotIn("$http_referer", v1_log_root.read_text(encoding="utf-8"))
        self.assertNotIn('"$request"', v1_log_root.read_text(encoding="utf-8"))
        self.assertEqual(8081, v2["app"]["ports"][0]["target"])
        self.assertNotIn("ports", v2["nginx"])
        self.assertNotIn("ports", v2["mcp-public-nginx"])
        self.assertEqual(
            (v1_source / "compose.yaml", v1_source / "compose.public-mcp.yaml", v1_overlay),
            runtime.compose_files_v1,
        )
        self.assertEqual(
            (current_source / "compose.production.yaml", v2_overlay),
            runtime.compose_files_v2,
        )
        self.assertNotIn(v1_source / "compose.yaml", runtime.compose_files_v2)

    def compose_document(
            self,
            runtime: upgrade.RuntimeContext,
            v1_source: Path,
            *,
            v2: bool) -> dict[str, object]:
        public_target = 8443 if v2 else 443
        public_command = (
            ["nginx", "-c", "/etc/nginx/nginx-public.conf", "-g", "daemon off;"]
            if v2 else None
        )
        public_mounts: list[dict[str, object]] = [
            {
                "type": "bind",
                "source": str(Path(runtime.environment["WEB_STARTER_PUBLIC_TLS_CERT_FILE"]).absolute()),
                "target": "/etc/nginx/tls/fullchain.pem",
                "read_only": True,
                **({"bind": {"create_host_path": False}} if v2 else {}),
            },
            {
                "type": "bind",
                "source": str(Path(runtime.environment["WEB_STARTER_PUBLIC_TLS_KEY_FILE"]).absolute()),
                "target": "/etc/nginx/tls/privkey.pem",
                "read_only": True,
                **({"bind": {"create_host_path": False}} if v2 else {}),
            },
        ]
        if not v2:
            public_mounts.append({
                "type": "bind",
                "source": str((v1_source / "deploy/nginx/external-mcp.conf").resolve()),
                "target": "/etc/nginx/conf.d/default.conf",
                "read_only": True,
            })
            public_mounts.append({
                "type": "bind",
                "source": str((runtime.runtime_root / "v1-public-nginx-redacted.conf").absolute()),
                "target": "/etc/nginx/nginx.conf",
                "read_only": True,
            })
        services: dict[str, object] = {
            "mysql": {
                "image": runtime.created_image_tags["mysql"],
                "volumes": [{
                    "type": "volume", "source": "mysql-data",
                    "target": "/var/lib/mysql", "volume": {},
                }],
            },
            "redis": {
                "image": runtime.created_image_tags["redis"],
                "volumes": [{
                    "type": "volume", "source": "redis-data",
                    "target": "/data", "volume": {},
                }],
            },
            "app": {
                "image": runtime.created_image_tags["v2-app" if v2 else "v1-app"],
                "command": None,
                **({"ports": [{
                    "host_ip": "127.0.0.1", "published": 18081, "target": 8081,
                    "protocol": "tcp", "mode": "ingress",
                }]} if v2 else {}),
            },
            "nginx": {
                "image": runtime.created_image_tags["v2-nginx" if v2 else "v1-nginx"],
                "command": None,
                "ports": [{
                    "host_ip": "127.0.0.1", "published": 18080, "target": 8080,
                    "protocol": "tcp", "mode": "ingress",
                }],
            },
            "mcp-public-nginx": {
                "image": runtime.created_image_tags["v2-nginx" if v2 else "v1-nginx"],
                "command": public_command,
                "ports": [{
                    "host_ip": "127.0.0.1", "published": 18443, "target": public_target,
                    "protocol": "tcp", "mode": "ingress",
                }],
                "volumes": public_mounts,
            },
        }
        return {
            "services": services,
            "volumes": {
                "mysql-data": {"name": runtime.names.compose_project + "_mysql-data"},
                "redis-data": {"name": runtime.names.compose_project + "_redis-data"},
            },
        }

    def test_compose_config_validation_is_exact_and_version_specific(self) -> None:
        runtime = self.runtime()
        v1_source = self.root / "v1-source"
        (v1_source / "deploy/nginx").mkdir(parents=True)
        (v1_source / "deploy/nginx/external-mcp.conf").write_text(
            "listen 443 ssl;\n", encoding="utf-8"
        )
        v1_document = self.compose_document(runtime, v1_source, v2=False)
        v2_document = self.compose_document(runtime, v1_source, v2=True)
        upgrade.assert_exact_compose_configuration(
            v1_document, runtime, v1_source, v2=False
        )
        upgrade.assert_exact_compose_configuration(
            v2_document, runtime, v1_source, v2=True
        )
        compose_240_document = copy.deepcopy(v2_document)
        for mount in compose_240_document["services"]["mcp-public-nginx"]["volumes"]:  # type: ignore[index]
            mount["bind"] = {}
        upgrade.assert_exact_compose_configuration(
            compose_240_document, runtime, v1_source, v2=True
        )

        mutations: list[tuple[str, dict[str, object], bool]] = []
        wrong_port = copy.deepcopy(v1_document)
        wrong_port["services"]["mcp-public-nginx"]["ports"][0]["target"] = 8443  # type: ignore[index]
        mutations.append(("port", wrong_port, False))
        missing_command = copy.deepcopy(v2_document)
        missing_command["services"]["mcp-public-nginx"]["command"] = None  # type: ignore[index]
        mutations.append(("command", missing_command, True))
        extra_mount = copy.deepcopy(v2_document)
        extra_mount["services"]["mcp-public-nginx"]["volumes"].append({  # type: ignore[index]
            "type": "bind", "source": "/tmp/foreign.conf",
            "target": "/etc/nginx/public.d/default.conf", "read_only": True,
        })
        mutations.append(("mount", extra_mount, True))
        unsafe_bind = copy.deepcopy(v2_document)
        unsafe_bind["services"]["mcp-public-nginx"]["volumes"][0]["bind"] = {  # type: ignore[index]
            "create_host_path": True,
        }
        mutations.append(("bind-create", unsafe_bind, True))
        wrong_image = copy.deepcopy(v2_document)
        wrong_image["services"]["app"]["image"] = "mutable:latest"  # type: ignore[index]
        mutations.append(("image", wrong_image, True))
        for label, document, is_v2 in mutations:
            with self.subTest(label=label), self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade.assert_exact_compose_configuration(
                    document, runtime, v1_source, v2=is_v2
                )

    def test_v2_tls_bind_source_policy_requires_exact_non_creating_mounts(self) -> None:
        source = self.root / "compose.production.yaml"
        valid = """services:
  mcp-public-nginx:
    image: example.invalid/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes:
      - type: bind
        source: ${WEB_STARTER_PUBLIC_TLS_CERT_FILE:?set WEB_STARTER_PUBLIC_TLS_CERT_FILE}
        target: /etc/nginx/tls/fullchain.pem
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: ${WEB_STARTER_PUBLIC_TLS_KEY_FILE:?set WEB_STARTER_PUBLIC_TLS_KEY_FILE}
        target: /etc/nginx/tls/privkey.pem
        read_only: true
        bind:
          create_host_path: false
    healthcheck:
      test: ["CMD", "true"]
"""
        source.write_text(valid, encoding="utf-8")
        upgrade.assert_v2_tls_bind_source_policy(source)

        for label, mutated in (
            ("missing", valid.replace("          create_host_path: false\n", "", 1)),
            ("true", valid.replace("create_host_path: false", "create_host_path: true", 1)),
            (
                "duplicate",
                valid.replace(
                    "  mcp-public-nginx:\n",
                    "  mcp-public-nginx:\n  mcp-public-nginx:\n",
                    1,
                ),
            ),
        ):
            with self.subTest(label=label):
                source.write_text(mutated, encoding="utf-8")
                with self.assertRaises(upgrade.UpgradeRehearsalError) as context:
                    upgrade.assert_v2_tls_bind_source_policy(source)
                self.assertEqual("COMPOSE_MOUNT_SOURCE_POLICY", context.exception.code)

    def test_sdk_run_is_strict_and_parses_only_its_private_surefire_xml(self) -> None:
        runtime = self.runtime()
        self.snapshot_runtime_sources(runtime)
        sdk_source = self.prepare_sdk_source(runtime)
        token = self.root / "token.json"
        token.write_text('{"token":"private-runtime-token-value"}\n', encoding="utf-8")
        truststore = self.root / "truststore.p12"
        hosts = self.root / "hosts"
        truststore.write_bytes(b"test")
        hosts.write_text("127.0.0.1 test\n", encoding="ascii")

        class FakeRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def run(self, command, **_kwargs):
                values = list(command)
                self.commands.append(values)
                report_argument = next(
                    (
                        value
                        for value in values
                        if value.startswith(
                            f"-D{upgrade.MCP_SUREFIRE_REPORTS_PROPERTY}="
                        )
                    ),
                    None,
                )
                if report_argument is not None:
                    report_directory = Path(report_argument.split("=", 1)[1])
                    report_directory.mkdir(parents=True, exist_ok=True)
                    (report_directory / f"TEST-{SDK_CLASS}.xml").write_text(
                        f'<testsuite name="{SDK_CLASS}" tests="1" failures="0" '
                        f'errors="0" skipped="0"><testcase classname="{SDK_CLASS}" '
                        'name="runtime"/></testsuite>\n',
                        encoding="utf-8",
                    )
                return upgrade.CommandResult(0, b"", b"")

        runner = FakeRunner()
        upgrade._run_sdk_test(
            runtime,
            runner,  # type: ignore[arg-type]
            {"truststore": truststore, "hosts": hosts},
            {"ownerId": "1", "projectId": "2"},
            token,
            SDK_CLASS,
            public=True,
            trace_prefix="upgrade-sdk-unit",
        )
        self.assertEqual(3, len(runner.commands))
        prepare, provider, strict = runner.commands
        self.assertEqual(str((sdk_source / "mvnw").resolve()), prepare[0])
        self.assertEqual(str((sdk_source / "mvnw").resolve()), provider[0])
        self.assertEqual(str((sdk_source / "mvnw").resolve()), strict[0])
        self.assertIn("-am", prepare)
        self.assertIn("-DskipTests", prepare)
        self.assertIn("--offline", prepare)
        self.assertIn("clean", prepare)
        self.assertIn(
            "-Dtest=dev.webstarter.mcp.acceptance.McpRuntimeToolExpectationsTest",
            provider,
        )
        self.assertIn("test", provider)
        self.assertIn("--offline", provider)
        self.assertNotIn("-DskipTests", provider)
        self.assertNotIn("-am", strict)
        self.assertIn("clean", strict)
        self.assertIn("--offline", strict)
        self.assertIn("-Dsurefire.failIfNoSpecifiedTests=true", strict)
        self.assertIn("-Dsurefire.rerunFailingTestsCount=0", strict)
        self.assertNotIn("-Dsurefire.failIfNoSpecifiedTests=false", strict)
        report_argument = next(
            value
            for value in strict
            if value.startswith(f"-D{upgrade.MCP_SUREFIRE_REPORTS_PROPERTY}=")
        )
        report_directory = Path(report_argument.split("=", 1)[1])
        self.assertTrue(report_directory.is_relative_to(runtime.runtime_root))
        self.assertFalse(report_directory.is_relative_to(sdk_source))
        self.assertFalse(report_directory.is_relative_to(upgrade.REPOSITORY_ROOT / "target"))
        self.assertTrue(any(value.startswith("-Dmaven.repo.local=") for value in prepare))
        self.assertTrue(any(value.startswith("-Dmaven.repo.local=") for value in strict))
        evidence = runtime.sanitized_observations["mcpSdkSurefire"]
        self.assertEqual(1, len(evidence))
        self.assertEqual(1, evidence[0]["tests"])
        self.assertEqual(
            runtime.runtime_source_hashes[upgrade.MCP_SDK_TEST_SOURCES[SDK_CLASS]],
            evidence[0]["testSourceSha256"],
        )
        self.assertEqual(runtime.runtime_source_hashes["pom.xml"], evidence[0]["rootPomSha256"])
        self.assertEqual(
            runtime.runtime_source_hashes["web-starter-mcp/pom.xml"],
            evidence[0]["modulePomSha256"],
        )

    def test_sdk_dependency_prepare_fails_closed_without_retry_and_stays_offline(self) -> None:
        runtime = self.runtime()
        self.snapshot_runtime_sources(runtime)
        self.prepare_sdk_source(runtime)

        class RetryRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []
                self.labels: list[str] = []

            def run(self, command, **kwargs):
                self.commands.append(list(command))
                self.labels.append(str(kwargs["label"]))
                raise upgrade.UpgradeRehearsalError(
                    "COMMAND_FAILED", "simulated incomplete offline seed"
                )

        runner = RetryRunner()
        with self.assertRaises(upgrade.UpgradeRehearsalError):
            upgrade._prepare_sdk_dependencies(runtime, runner)  # type: ignore[arg-type]

        self.assertFalse(runtime.sdk_dependencies_prepared)
        self.assertEqual(1, len(runner.commands))
        self.assertEqual(["sdk-prepare-reactor-dependencies"], runner.labels)
        self.assertIn("--offline", runner.commands[0])
        repositories = [
            next(value for value in command if value.startswith("-Dmaven.repo.local="))
            for command in runner.commands
        ]
        self.assertEqual(1, len(set(repositories)))

    def test_playwright_dependencies_use_the_pinned_corepack_pnpm(self) -> None:
        runtime = self.runtime()
        self.snapshot_runtime_sources(runtime)
        sdk_source = self.prepare_sdk_source(runtime)
        web = sdk_source / "web-starter-web"

        class PlaywrightRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []
                self.cwds: list[Path | None] = []

            def run(self, command, **kwargs):
                values = list(command)
                self.commands.append(values)
                self.cwds.append(kwargs.get("cwd"))
                if values == [*upgrade.PINNED_PNPM_COMMAND, "--version"]:
                    return upgrade.CommandResult(0, b"9.15.9\n", b"")
                if values[:3] == [*upgrade.PINNED_PNPM_COMMAND, "install"]:
                    cli = web / "node_modules" / ".bin" / "playwright"
                    cli.parent.mkdir(parents=True)
                    cli.write_text("#!/bin/sh\n", encoding="ascii")
                    package = web / "node_modules" / "@playwright" / "test" / "package.json"
                    package.parent.mkdir(parents=True)
                    package.write_text('{"version":"1.61.1"}\n', encoding="utf-8")
                    return upgrade.CommandResult(0, b"", b"")
                raise AssertionError(values)

        runner = PlaywrightRunner()
        observed_web, _environment = upgrade._prepare_playwright_dependencies(
            runtime, runner  # type: ignore[arg-type]
        )

        self.assertEqual(web, observed_web)
        self.assertTrue(runtime.playwright_dependencies_prepared)
        self.assertEqual([*upgrade.PINNED_PNPM_COMMAND, "--version"], runner.commands[0])
        self.assertEqual(
            [*upgrade.PINNED_PNPM_COMMAND, "install"], runner.commands[1][:3]
        )
        self.assertIn("--offline", runner.commands[1])
        store_option = runner.commands[1].index("--store-dir")
        store_root = Path(runner.commands[1][store_option + 1])
        self.assertEqual(runtime.runtime_root / "dependency-seed" / "pnpm-store", store_root)
        self.assertTrue((store_root / "v3" / "files").is_dir())
        self.assertFalse((store_root / "files").exists())
        self.assertEqual(2, len(runner.commands))
        self.assertEqual("0", _environment["COREPACK_ENABLE_NETWORK"])
        self.assertEqual("1", _environment["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"])
        self.assertEqual(web, runner.cwds[0])
        self.assertEqual(web, runner.cwds[1])

    def test_playwright_dependency_prepare_fails_closed_without_pnpm_v3_files(self) -> None:
        runtime = self.runtime()
        self.snapshot_runtime_sources(runtime)
        self.prepare_sdk_source(runtime)
        shutil_target = runtime.runtime_root / "dependency-seed" / "pnpm-store" / "v3"
        for path in sorted(shutil_target.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        shutil_target.rmdir()

        class VersionOnlyRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def run(self, command, **_kwargs):
                values = list(command)
                self.commands.append(values)
                if values == [*upgrade.PINNED_PNPM_COMMAND, "--version"]:
                    return upgrade.CommandResult(0, b"9.15.9\n", b"")
                raise AssertionError("install must not run with an invalid pnpm store")

        runner = VersionOnlyRunner()
        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "v3/files"
        ) as error:
            upgrade._prepare_playwright_dependencies(
                runtime, runner  # type: ignore[arg-type]
            )
        self.assertEqual("PLAYWRIGHT_PNPM_STORE", error.exception.code)
        self.assertEqual([[*upgrade.PINNED_PNPM_COMMAND, "--version"]], runner.commands)
        self.assertFalse(runtime.playwright_dependencies_prepared)

    def test_playwright_never_invokes_a_browser_download_or_retry(self) -> None:
        runtime = self.runtime()
        self.snapshot_runtime_sources(runtime)
        sdk_source = self.prepare_sdk_source(runtime)
        web = sdk_source / "web-starter-web"

        class RetryRunner:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], dict[str, object]]] = []

            def run(self, command, **kwargs):
                values = list(command)
                self.calls.append((values, dict(kwargs)))
                if values == [*upgrade.PINNED_PNPM_COMMAND, "--version"]:
                    return upgrade.CommandResult(0, b"9.15.9\n", b"")
                if values[:3] == [*upgrade.PINNED_PNPM_COMMAND, "install"]:
                    cli = web / "node_modules" / ".bin" / "playwright"
                    cli.parent.mkdir(parents=True)
                    cli.write_text("#!/bin/sh\n", encoding="ascii")
                    package = web / "node_modules" / "@playwright" / "test" / "package.json"
                    package.parent.mkdir(parents=True)
                    package.write_text('{"version":"1.61.1"}\n', encoding="utf-8")
                    return upgrade.CommandResult(0, b"", b"")
                raise AssertionError(values)

        runner = RetryRunner()
        upgrade._prepare_playwright_dependencies(runtime, runner)  # type: ignore[arg-type]

        self.assertEqual(2, len(runner.calls))
        self.assertFalse(any("chromium" in call[0] for call in runner.calls))
        self.assertEqual(
            ["playwright-pnpm-version", "playwright-frozen-install"],
            [str(call[1]["label"]) for call in runner.calls],
        )
        self.assertIn("--offline", runner.calls[1][0])
        self.assertEqual("0", runner.calls[1][1]["environment"]["COREPACK_ENABLE_NETWORK"])
        config = (web / "playwright.config.ts").read_text(encoding="utf-8")
        self.assertIn("channel: 'chromium'", config)
        self.assertTrue(runtime.playwright_dependencies_prepared)

    def test_playwright_json_requires_exact_twenty_tests_without_retry_or_only(self) -> None:
        suites = []
        for file_name, titles in upgrade.PLAYWRIGHT_EXPECTED_TITLES.items():
            suites.append({
                "file": file_name,
                "specs": [
                    {
                        "title": title,
                        "ok": True,
                        "tests": [{
                            "expectedStatus": "passed",
                            "status": "expected",
                            "results": [{"status": "passed", "retry": 0}],
                        }],
                    }
                    for title in titles
                ],
            })
        document = {
            "config": {
                "version": "1.61.1",
                "workers": 1,
                "forbidOnly": True,
                "fullyParallel": False,
                "reporter": [["json"]],
                "projects": [{"retries": 0, "repeatEach": 1}],
            },
            "suites": suites,
            "errors": [],
            "stats": {"expected": 20, "skipped": 0, "unexpected": 0, "flaky": 0},
        }
        report = upgrade._parse_playwright_json(json.dumps(document).encode("utf-8"))
        self.assertEqual(20, report["tests"])

        retried = copy.deepcopy(document)
        retried["suites"][0]["specs"][0]["tests"][0]["results"][0]["retry"] = 1
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "without retry"):
            upgrade._parse_playwright_json(json.dumps(retried).encode("utf-8"))

        only_allowed = copy.deepcopy(document)
        only_allowed["config"]["forbidOnly"] = False
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "configuration"):
            upgrade._parse_playwright_json(json.dumps(only_allowed).encode("utf-8"))

        failed = copy.deepcopy(document)
        failed["stats"]["expected"] = 19
        failed["stats"]["unexpected"] = 1
        failed_spec = failed["suites"][0]["specs"][0]
        failed_spec["ok"] = False
        failed_spec["tests"][0]["status"] = "unexpected"
        failed_spec["tests"][0]["results"][0].update({
            "status": "failed",
            "error": {"message": "private-password and bearer-token"},
        })
        detail = upgrade._failed_playwright_report_detail(
            json.dumps(failed).encode("utf-8")
        )
        self.assertEqual("FQ_SPEC_1_FAILED", detail)
        self.assertNotIn("password", detail.lower())
        self.assertNotIn("bearer", detail.lower())
        self.assertRegex(detail, r"^[A-Z][A-Z0-9_]+$")

        partial = copy.deepcopy(failed)
        partial["suites"][1]["specs"] = partial["suites"][1]["specs"][:1]
        partial_spec = partial["suites"][1]["specs"][0]
        partial_spec["ok"] = False
        partial_spec["tests"][0]["status"] = "unexpected"
        partial_spec["tests"][0]["results"][0].update({
            "status": "failed",
            "error": {"message": "private-cookie-value"},
        })
        partial["suites"][0]["specs"][0] = copy.deepcopy(
            document["suites"][0]["specs"][0]
        )
        self.assertEqual(
            "REL_SPEC_1_FAILED",
            upgrade._failed_playwright_report_detail(
                json.dumps(partial).encode("utf-8")
            ),
        )

        multiple = copy.deepcopy(document)
        multiple_cases = (
            (
                0, 0, "failed", "frontend-quality-runtime.spec.ts:190:7",
                "SAFE_SESSION_COOKIE_MISSING",
            ),
            (0, 1, "skipped", None, None),
            (
                1, 2, "failed", "release-runtime.spec.ts:704:11",
                "SAFE_HTTP_STATUS_403",
            ),
            (1, 3, "skipped", None, None),
        )
        for suite_index, spec_index, status, source, marker in multiple_cases:
            spec = multiple["suites"][suite_index]["specs"][spec_index]
            spec["ok"] = False
            spec["tests"][0]["status"] = (
                "skipped" if status == "skipped" else "unexpected"
            )
            result = spec["tests"][0]["results"][0]
            result["status"] = status
            if source is not None:
                result["error"] = {
                    "message": f"private-cookie-value {marker or ''}",
                    "stack": f"Error: redacted\n    at {source}",
                }
        self.assertEqual(
            "FQ_1_F_L190_SESSION_COOKIE_MISSING_REL_3_F_L704_HTTP_STATUS_403",
            upgrade._failed_playwright_report_detail(
                json.dumps(multiple).encode("utf-8")
            ),
        )

    def test_surefire_parser_rejects_empty_multiple_skipped_failed_or_wrong_suite(self) -> None:
        cases = {
            "empty": None,
            "skipped": (
                f'<testsuite name="{SDK_CLASS}" tests="1" failures="0" errors="0" skipped="1">'
                f'<testcase classname="{SDK_CLASS}" name="runtime"><skipped/></testcase></testsuite>'
            ),
            "failed": (
                f'<testsuite name="{SDK_CLASS}" tests="1" failures="1" errors="0" skipped="0">'
                f'<testcase classname="{SDK_CLASS}" name="runtime"><failure/></testcase></testsuite>'
            ),
            "wrong-suite": (
                '<testsuite name="other.Test" tests="1" failures="0" errors="0" skipped="0">'
                '<testcase classname="other.Test" name="runtime"/></testsuite>'
            ),
            "flaky": (
                f'<testsuite name="{SDK_CLASS}" tests="1" failures="0" errors="0" '
                f'skipped="0" flakes="1"><testcase classname="{SDK_CLASS}" name="runtime">'
                '<flakyFailure/></testcase></testsuite>'
            ),
        }
        for label, payload in cases.items():
            directory = self.root / label
            directory.mkdir()
            if payload is not None:
                (directory / "TEST-result.xml").write_text(payload, encoding="utf-8")
            with self.subTest(label=label), self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade._parse_single_surefire_report(directory, SDK_CLASS)

        multiple = self.root / "multiple"
        multiple.mkdir()
        for index in range(2):
            (multiple / f"TEST-{index}.xml").write_text("<testsuite/>", encoding="utf-8")
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "exactly one"):
            upgrade._parse_single_surefire_report(multiple, SDK_CLASS)

    def test_result_source_evidence_contains_the_exact_runtime_hash_map(self) -> None:
        runtime = self.runtime()
        self.snapshot_runtime_sources(runtime)
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
        exit_code = upgrade._write_result(runtime, {})
        self.assertEqual(upgrade.EXIT_INCOMPLETE, exit_code)
        result = json.loads((self.root / upgrade.RESULT_NAME).read_text(encoding="utf-8"))
        self.assertEqual(
            dict(sorted(runtime.runtime_source_hashes.items())),
            result["source"]["runtimeSourceSha256"],
        )


if __name__ == "__main__":
    unittest.main()
