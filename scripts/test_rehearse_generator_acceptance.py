from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import rehearse_generator_acceptance as generator


DIGEST = "sha256:" + "a" * 64
NGINX_DIGEST = "sha256:" + "b" * 64
APP_IMAGE_ID = "sha256:" + "c" * 64
NGINX_IMAGE_ID = "sha256:" + "d" * 64
MYSQL_IMAGE_ID = "sha256:" + "f" * 64
REDIS_IMAGE_ID = "sha256:" + "0" * 64
COMMIT = "e" * 40
VERSION = "2.0.0-SNAPSHOT"
OBSERVED_AT = "2026-07-20T00:00:00+00:00"
COMPOSE_PROJECT = "wsgen-123456789abc-project"


class GeneratorAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-generator-test-")
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.terms = self.root / "forbidden.txt"
        self.terms.write_text("external-only-term\n", encoding="utf-8")
        self.inputs = generator._safe_inputs(self.namespace())
        self.app = generator.BuiltImage(
            "app",
            "127.0.0.1:5000/journey/app",
            "127.0.0.1:5000/journey/app:stage",
            DIGEST,
            "127.0.0.1:5000/journey/app@" + DIGEST,
            APP_IMAGE_ID,
        )
        self.nginx = generator.BuiltImage(
            "nginx",
            "127.0.0.1:5000/journey/nginx",
            "127.0.0.1:5000/journey/nginx:stage",
            NGINX_DIGEST,
            "127.0.0.1:5000/journey/nginx@" + NGINX_DIGEST,
            NGINX_IMAGE_ID,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def namespace(self, **overrides) -> argparse.Namespace:
        values = {
            "repository": self.repository,
            "output": self.root / "evidence",
            "forbidden_terms": self.terms,
            "mysql_image": "registry.example/mysql@" + DIGEST,
            "redis_image": "registry.example/redis@" + DIGEST,
            "registry_image": "registry.example/registry@" + DIGEST,
            "project_name": "journey-admin",
            "product_name": "启程派生管理系统",
            "group_id": "dev.journey.admin",
            "database": "journey_admin",
            "environment_prefix": "JOURNEY_ADMIN_",
            "module_name": "asset",
            "module_label": "资产",
            "migration_version": "202607200001",
            "permission_id_base": "5100",
            "menu_id": "6100",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_inputs_require_external_absent_output_and_immutable_images(self) -> None:
        inputs = generator._safe_inputs(self.namespace())
        self.assertEqual(self.repository, inputs.repository)
        self.assertEqual(self.root / "evidence", inputs.output)

        with self.assertRaisesRegex(generator.GeneratorAcceptanceError, "immutable"):
            generator._safe_inputs(self.namespace(mysql_image="mysql:latest"))
        inside_terms = self.repository / "terms.txt"
        inside_terms.write_text("external-only-term\n", encoding="utf-8")
        with self.assertRaisesRegex(generator.GeneratorAcceptanceError, "outside"):
            generator._safe_inputs(self.namespace(forbidden_terms=inside_terms))

    def test_registry_wait_retries_a_transient_remote_disconnect(self) -> None:
        class ReadyResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        opener = mock.Mock()
        opener.open.side_effect = [
            generator.RemoteDisconnected("registry still starting"),
            ReadyResponse(),
        ]
        with (
            mock.patch.object(generator, "build_opener", return_value=opener),
            mock.patch.object(generator.time, "sleep") as sleep,
        ):
            generator._wait_registry("127.0.0.1:55000")

        self.assertEqual(2, opener.open.call_count)
        sleep.assert_called_once_with(0.5)

    def test_private_registry_uses_reserved_localhost_for_docker_image_references(self) -> None:
        with (
            mock.patch.object(generator, "_run") as run,
            mock.patch.object(generator, "_free_ports", return_value=[54321]),
            mock.patch.object(
                generator,
                "_captured",
                return_value="127.0.0.1:54321\n[::1]:54321",
            ),
            mock.patch.object(generator, "_wait_registry") as wait,
        ):
            address = generator._start_registry(
                self.inputs, "web-starter-generator-registry-a1b2c3d4e5f6",
                "a1b2c3d4e5f6",
            )

        self.assertEqual("localhost:54321", address)
        wait.assert_called_once_with("localhost:54321")
        create_command = run.call_args_list[0].args[0]
        self.assertEqual(
            ["127.0.0.1:54321:5000", "[::1]:54321:5000"],
            [
                create_command[index + 1]
                for index, value in enumerate(create_command)
                if value == "--publish"
            ],
        )

    def test_runtime_environment_uses_the_derived_prefix_and_exact_expectation(self) -> None:
        inputs = generator._safe_inputs(self.namespace())
        app = generator.BuiltImage(
            "app", "127.0.0.1:5000/journey/app", "app:tag", DIGEST,
            "127.0.0.1:5000/journey/app@" + DIGEST, DIGEST,
        )
        nginx = generator.BuiltImage(
            "nginx", "127.0.0.1:5000/journey/nginx", "nginx:tag", DIGEST,
            "127.0.0.1:5000/journey/nginx@" + DIGEST, DIGEST,
        )
        environment, project = generator.runtime_environment(
            inputs=inputs,
            stage="module",
            run_id="a1b2c3d4e5f6",
            version="2.0.0-SNAPSHOT",
            commit="b" * 40,
            app=app,
            nginx=nginx,
            artifact_root=self.root / "artifacts",
            runner_temp=self.root / "runner",
            expected_modules="asset",
            expected_mcp_modules="asset",
            ports=(18088, 18443, 18081),
        )

        self.assertEqual("asset", environment["JOURNEY_ADMIN_EXPECTED_GENERATED_MODULES"])
        self.assertEqual(
            "asset", environment["JOURNEY_ADMIN_EXPECTED_GENERATED_MCP_MODULES"]
        )
        self.assertEqual("b" * 40, environment["GITHUB_SHA"])
        self.assertEqual(
            "wsgen-a1b2c3d4e5f6-module", project
        )
        self.assertEqual(
            project, environment["JOURNEY_ADMIN_ACCEPTANCE_COMPOSE_PROJECT"]
        )

    def test_runtime_environment_bounds_long_compose_project_names_deterministically(self) -> None:
        inputs = generator._safe_inputs(self.namespace(project_name="p" + "x" * 49))
        app = self.app
        nginx = self.nginx
        arguments = dict(
            inputs=inputs,
            stage="module",
            run_id="a1b2c3d4e5f6",
            version=VERSION,
            commit=COMMIT,
            app=app,
            nginx=nginx,
            artifact_root=self.root / "long-artifacts",
            runner_temp=self.root / "long-runner",
            expected_modules="asset",
            expected_mcp_modules="asset",
            ports=(28088, 28443, 28081),
        )

        _environment, first = generator.runtime_environment(**arguments)
        _environment, second = generator.runtime_environment(**arguments)

        self.assertEqual(first, second)
        self.assertEqual("wsgen-a1b2c3d4e5f6-module", first)
        self.assertLessEqual(len(first), 63)
        self.assertRegex(first, r"^[a-z0-9][a-z0-9_-]*$")

    @staticmethod
    def metric_snapshot() -> dict[str, object]:
        names = {
            "journeyadmin.audit.operations",
            "journeyadmin.audit.persist.failures",
            "journeyadmin.login.attempts",
            "journeyadmin.mcp.calls",
            "journeyadmin.mcp.call.duration",
            "journeyadmin.mcp.rate_limited",
            "journeyadmin.mcp.sessions",
            "journeyadmin.protocol.requests",
            "journeyadmin.rate_limited",
            "hikaricp.connections.usage",
        }
        return {
            name: {"present": True, "measurements": {"COUNT": 1.0}, "tags": {}}
            for name in names
        }

    @staticmethod
    def protocol_endpoint_snapshot() -> dict[str, object]:
        return {
            endpoint: {
                "present": True,
                "measurements": {"COUNT": 1.0},
                "tags": {
                    "method": list(generator.PROTOCOL_METHODS),
                    "outcome": list(generator.PROTOCOL_OUTCOMES),
                },
            }
            for endpoint in generator.PROTOCOL_ENDPOINTS
        }

    def artifact_fixture(self, with_module: bool) -> Path:
        artifact_root = self.root / ("module" if with_module else "project")
        artifact_root.mkdir()
        expected_layers = {name: "PASS" for name in sorted(generator.VERIFY_LAYERS)}
        authorization = dict(generator.AUTHORIZATION_MATRIX)
        baseline = {
            "schemaVersion": 1,
            "status": "SNAPSHOT",
            "observedAt": OBSERVED_AT,
            "authorization": authorization,
            "metrics": self.metric_snapshot(),
            "protocolEndpoints": self.protocol_endpoint_snapshot(),
        }
        runtime_metrics = {
            "schemaVersion": 1,
            "status": "PASS",
            "observedAt": OBSERVED_AT,
            "authorization": authorization,
            "metrics": self.metric_snapshot(),
            "protocolEndpoints": self.protocol_endpoint_snapshot(),
            "baselineObservedAt": OBSERVED_AT,
            "checks": {name: True for name in generator.METRIC_CHECKS},
            "structuredLog": {
                "format": "ecs",
                "timestamp": "2026-07-20T00:00:00.123456789Z",
                "level": "INFO",
                "message": "protocol_request",
                "traceId": "release-runtime-trace",
                "endpoint": "mcp",
                "method": "POST",
                "outcome": "SUCCESS",
                "sourceLineSha256": "6" * 64,
            },
        }
        identity_images = {
            "app": {
                "reference": self.app.digest_reference,
                "imageId": self.app.image_id,
                "ociVersion": VERSION,
                "ociRevision": COMMIT,
            },
            "nginx": {
                "reference": self.nginx.digest_reference,
                "imageId": self.nginx.image_id,
                "ociVersion": VERSION,
                "ociRevision": COMMIT,
            },
            "mysql": {
                "reference": self.inputs.mysql_image,
                "imageId": MYSQL_IMAGE_ID,
                "ociVersion": None,
                "ociRevision": None,
            },
            "redis": {
                "reference": self.inputs.redis_image,
                "imageId": REDIS_IMAGE_ID,
                "ociVersion": None,
                "ociRevision": None,
            },
        }
        documents: dict[str, dict[str, object]] = {
            "runtime-production-compose-policy.json": {
                "schemaVersion": 1,
                "status": "PASS",
                "composeSha256": "f" * 64,
                "errors": [],
            },
            "runtime-version-identity.json": {
                "schemaVersion": 2,
                "status": "PASS",
                "observedAt": OBSERVED_AT,
                "release": {"version": VERSION, "gitCommit": COMMIT},
                "java": {"specificationVersion": "21", "runtimeVersion": "21.0.8+9"},
                "actuator": {
                    "applicationVersion": VERSION,
                    "buildVersion": VERSION,
                    "buildArtifact": "journey-admin-admin",
                    "buildGroup": "dev.journey.admin",
                },
                "images": identity_images,
            },
            "operational-metrics-baseline.json": baseline,
            "oauth-runtime.json": {
                "schemaVersion": 1,
                "status": "PASS",
                "checks": {name: "PASS" for name in generator.OAUTH_CHECKS},
            },
            "operational-metrics-runtime.json": runtime_metrics,
            "unified-verify-summary.json": {
                "schemaVersion": 1,
                "status": "PASS",
                "layers": expected_layers,
            },
            "runtime-compose-ps.json": {
                "schemaVersion": 1,
                "services": [
                    {"service": name, "state": "running", "health": "healthy"}
                    for name in sorted(generator.COMPOSE_SERVICES)
                ],
            },
        }
        for name, document in documents.items():
            (artifact_root / name).write_text(
                json.dumps(document) + "\n", encoding="utf-8"
            )
        unified_sha256 = generator.sha256_file(
            artifact_root / "unified-verify-summary.json"
        )
        release = {
            "schemaVersion": 1,
            "status": "PASS",
            "observedAt": OBSERVED_AT,
            "release": {"tag": "v" + VERSION, "version": VERSION, "gitCommit": COMMIT},
            "images": {
                "app": self.app.digest_reference,
                "nginx": self.nginx.digest_reference,
            },
            "identity": {
                "javaSpecificationVersion": "21",
                "applicationVersion": VERSION,
                "buildVersion": VERSION,
                "composeProject": COMPOSE_PROJECT,
                "mcpCrudTracePrefix": generator.MCP_CRUD_TRACE_PREFIX,
                "appImage": self.app.digest_reference,
                "nginxImage": self.nginx.digest_reference,
                "appOciVersion": VERSION,
                "appOciRevision": COMMIT,
                "nginxOciVersion": VERSION,
                "nginxOciRevision": COMMIT,
            },
            "checks": {name: "PASS" for name in generator.RUNTIME_CHECKS},
            "unifiedVerify": {
                "path": "unified-verify-summary.json",
                "sha256": unified_sha256,
                "status": "PASS",
                "layers": expected_layers,
            },
        }
        (artifact_root / "release-runtime-acceptance.json").write_text(
            json.dumps(release) + "\n", encoding="utf-8"
        )
        if with_module:
            generated = {
                "schemaVersion": 1,
                "status": "PASS",
                "modules": [{
                    "module": "asset",
                    "artifactId": "journey-admin-asset",
                    "migrationSha256": "1" * 64,
                    "planSha256": "2" * 64,
                    "browserTestSha256": "3" * 64,
                    "browserStatus": "PASS",
                    "mcpRuntimeTestSha256": "4" * 64,
                    "mcpStatus": "PASS",
                }],
            }
            (artifact_root / generator.GENERATED_ARTIFACT).write_text(
                json.dumps(generated) + "\n", encoding="utf-8"
            )
        return artifact_root

    def validate_artifacts(self, artifact_root: Path, expected_module: str | None):
        return generator.validate_stage_artifacts(
            artifact_root,
            inputs=self.inputs,
            version=VERSION,
            commit=COMMIT,
            compose_project=COMPOSE_PROJECT,
            app=self.app,
            nginx=self.nginx,
            expected_module=expected_module,
        )

    def test_artifact_validation_distinguishes_project_only_and_generated_module(self) -> None:
        project = self.artifact_fixture(False)
        module = self.artifact_fixture(True)

        self.assertEqual(
            set(generator.EXPECTED_ARTIFACTS),
            set(self.validate_artifacts(project, expected_module=None)),
        )
        self.assertEqual(
            set(generator.EXPECTED_ARTIFACTS) | {generator.GENERATED_ARTIFACT},
            set(self.validate_artifacts(module, expected_module="asset")),
        )

        (project / "unexpected.log").write_text("unsafe evidence surface\n")
        with self.assertRaisesRegex(generator.GeneratorAcceptanceError, "not exact"):
            self.validate_artifacts(project, expected_module=None)

    def test_artifact_validation_rejects_stage_identity_mismatch(self) -> None:
        artifact_root = self.artifact_fixture(False)
        identity_path = artifact_root / "runtime-version-identity.json"
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["release"]["gitCommit"] = "0" * 40
        identity_path.write_text(json.dumps(identity) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(generator.GeneratorAcceptanceError, "stage commit"):
            self.validate_artifacts(artifact_root, expected_module=None)

    def test_artifact_validation_rejects_release_runtime_stage_binding_mismatch(self) -> None:
        artifact_root = self.artifact_fixture(False)
        release_path = artifact_root / "release-runtime-acceptance.json"
        original = json.loads(release_path.read_text(encoding="utf-8"))
        for field, value in (
            ("composeProject", "wsgen-000000000000-project"),
            ("mcpCrudTracePrefix", "different-trace-prefix"),
        ):
            with self.subTest(field=field):
                release = json.loads(json.dumps(original))
                release["identity"][field] = value
                release_path.write_text(json.dumps(release) + "\n", encoding="utf-8")

                with self.assertRaisesRegex(
                    generator.GeneratorAcceptanceError,
                    "partial or stage-mismatched",
                ):
                    self.validate_artifacts(artifact_root, expected_module=None)

    def test_artifact_validation_rejects_operational_metric_contract_drift(self) -> None:
        artifact_root = self.artifact_fixture(False)
        runtime_path = artifact_root / "operational-metrics-runtime.json"
        original = json.loads(runtime_path.read_text(encoding="utf-8"))
        mutations = (
            lambda document: document["protocolEndpoints"]["mcp"]["tags"].update(
                {"method": ["POST"]}
            ),
            lambda document: document["structuredLog"].update({"traceId": "unsafe trace"}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                document = json.loads(json.dumps(original))
                mutation(document)
                runtime_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    generator.GeneratorAcceptanceError,
                    "protocol endpoint metric|structured log proof",
                ):
                    self.validate_artifacts(artifact_root, expected_module=None)

    def test_run_stage_binds_the_runtime_compose_project_to_artifact_validation(self) -> None:
        project = self.root / "derived-stage"
        project.mkdir()
        bundle = self.root / "bundle"
        bundle.mkdir()
        work_root = self.root / "work"
        work_root.mkdir()
        compose_project = "wsgen-123456789abc-project"
        built_images: list[generator.BuiltImage] = []
        compose_projects: list[str] = []

        with (
            mock.patch.object(generator, "_require_tracked_clean"),
            mock.patch.object(
                generator,
                "_build_images",
                return_value=(self.app, self.nginx, "9" * 64),
            ),
            mock.patch.object(generator, "_free_ports", return_value=[31001, 31002, 31003]),
            mock.patch.object(
                generator,
                "runtime_environment",
                return_value=({}, compose_project),
            ) as runtime,
            mock.patch.object(generator, "_run"),
            mock.patch.object(
                generator,
                "validate_stage_artifacts",
                return_value={"runtime-version-identity.json": "8" * 64},
            ) as validate,
        ):
            stage = generator._run_stage(
                project=project,
                inputs=self.inputs,
                stage_name="project",
                run_id="123456789abc",
                version=VERSION,
                commit=COMMIT,
                tree="7" * 40,
                registry="registry.localhost:55000",
                bundle=bundle,
                work_root=work_root,
                expected_modules="-",
                expected_mcp_modules="-",
                expected_module=None,
                built_images=built_images,
                compose_projects=compose_projects,
            )

        self.assertNotIn("compose_project", runtime.call_args.kwargs)
        self.assertEqual(compose_project, validate.call_args.kwargs["compose_project"])
        self.assertEqual(compose_project, stage.compose_project)
        self.assertEqual([compose_project], compose_projects)

    def test_artifact_validation_rejects_sensitive_material(self) -> None:
        artifact_root = self.artifact_fixture(False)
        oauth_path = artifact_root / "oauth-runtime.json"
        oauth = json.loads(oauth_path.read_text(encoding="utf-8"))
        oauth["password"] = "do-not-publish-this-secret"
        oauth_path.write_text(json.dumps(oauth) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(generator.GeneratorAcceptanceError, "sensitive material"):
            self.validate_artifacts(artifact_root, expected_module=None)

    def test_source_binds_final_pass_to_cleanup_and_two_runtime_stages(self) -> None:
        source = Path(generator.__file__).read_text(encoding="utf-8")
        self.assertIn('stage_name="project"', source)
        self.assertIn('expected_modules="-"', source)
        self.assertIn('stage_name="module"', source)
        self.assertIn("_force_compose_cleanup", source)
        self.assertIn("temporaryProjectTreeRemoved", source)
        self.assertIn("os.rename(bundle, inputs.output)", source)
        self.assertIn("_formal_candidate(inputs.repository)", source)
        self.assertIn(
            "executing generator producer differs from the committed candidate",
            source,
        )
        self.assertIn("_harden_evidence_tree(bundle)", source)
        self.assertIn("_write_checksum(bundle / CHECKSUM_FILE", source)
        self.assertLess(
            source.index("_cleanup_docker(run_id"),
            source.index("_write_private_json(evidence_path, document)"),
        )

    def test_build_context_is_exported_from_the_recorded_commit(self) -> None:
        project = self.root / "derived"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        executable = project / "mvnw"
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)
        commit, tree = generator._commit_project(project, "Test committed context")
        (project / "untracked-secret.txt").write_text("not archived\n", encoding="utf-8")

        context = self.root / "context"
        digest = generator._export_build_context(project, commit, tree, context)

        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual("FROM scratch\n", (context / "Dockerfile").read_text(encoding="utf-8"))
        self.assertTrue(os.access(context / "mvnw", os.X_OK))
        self.assertFalse((context / ".git").exists())
        self.assertFalse((context / "untracked-secret.txt").exists())

    def test_build_context_rejects_a_committed_symlink(self) -> None:
        project = self.root / "linked"
        project.mkdir()
        target = project / "target.txt"
        target.write_text("target\n", encoding="utf-8")
        (project / "link.txt").symlink_to(target.name)
        commit, tree = generator._commit_project(project, "Test linked context")

        with self.assertRaisesRegex(
            generator.GeneratorAcceptanceError,
            "link or special file",
        ):
            generator._export_build_context(project, commit, tree, self.root / "linked-context")

    def test_derived_git_commands_disable_external_hooks_templates_and_signing(self) -> None:
        source = Path(generator.__file__).read_text(encoding="utf-8")
        self.assertIn('environment["GIT_CONFIG_NOSYSTEM"] = "1"', source)
        self.assertIn('environment["GIT_CONFIG_GLOBAL"] = os.devnull', source)
        self.assertIn('"core.hooksPath=/dev/null"', source)
        self.assertIn('"commit.gpgSign=false"', source)
        self.assertIn('f"--template={template}"', source)
        self.assertIn('["git", "archive", "--format=tar"', source)
        self.assertIn('cwd=context', source)

    def test_cleanup_verification_includes_stopped_compose_containers(self) -> None:
        calls: list[tuple[list[str], str]] = []

        def docker_ids(arguments, noun):
            calls.append((list(arguments), noun))
            if noun == "container":
                return ["stopped-container-id"]
            return []

        with mock.patch.object(generator, "_docker_ids", side_effect=docker_ids):
            with self.assertRaisesRegex(
                generator.GeneratorAcceptanceError,
                "container:leftover",
            ):
                generator._verify_compose_cleanup(["isolated-project"])

        self.assertEqual(
            [
                (["--all", "--filter", "label=com.docker.compose.project=isolated-project"],
                 "container"),
                (["--filter", "label=com.docker.compose.project=isolated-project"],
                 "volume"),
                (["--filter", "label=com.docker.compose.project=isolated-project"],
                 "network"),
            ],
            calls,
        )

    def test_force_cleanup_continues_after_one_compose_resource_failure(self) -> None:
        removals: list[str] = []

        def docker_ids(_arguments, noun):
            return [noun + "-id"]

        def run(command, **_kwargs):
            noun = command[1]
            removals.append(noun)
            if noun == "container":
                raise generator.GeneratorAcceptanceError("injected container cleanup failure")

        with mock.patch.object(generator, "_docker_ids", side_effect=docker_ids), \
                mock.patch.object(generator, "_run", side_effect=run):
            with self.assertRaisesRegex(
                generator.GeneratorAcceptanceError,
                "isolated-project:container",
            ):
                generator._force_compose_cleanup(["isolated-project"])

        self.assertEqual(["container", "volume", "network"], removals)


if __name__ == "__main__":
    unittest.main()
