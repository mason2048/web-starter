from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import validate_generator_acceptance_evidence as gate


VERSION = "2.0.0"
OBSERVED_AT = "2026-07-20T00:00:00Z"
RUN_ID = "abcdef123456"


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed.stdout.strip()


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class GeneratorEvidenceValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="generator-evidence-validator-test-")
        self.root = Path(self.temporary.name).resolve()
        self.repository = self._candidate()
        self.terms = self.root / "forbidden-terms.txt"
        self.terms.write_text("external-test-only-term\n", encoding="utf-8")
        self.terms.chmod(0o600)
        self.bundle = self.root / "raw-evidence"
        self.document = self._document()
        self._write_bundle(self.document)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _candidate(self) -> Path:
        repository = self.root / "candidate"
        repository.mkdir()
        workspace = Path(gate.__file__).resolve().parents[1]
        for relative in gate.SOURCE_PATHS:
            target = repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == "pom.xml":
                source = (workspace / relative).read_text(encoding="utf-8")
                source = source.replace("2.0.0-SNAPSHOT", VERSION)
                target.write_text(source, encoding="utf-8")
            elif relative == "web-starter-web/package.json":
                source = json.loads((workspace / relative).read_text(encoding="utf-8"))
                source["version"] = VERSION
                target.write_text(json.dumps(source, ensure_ascii=False) + "\n", encoding="utf-8")
            else:
                target.write_bytes((workspace / relative).read_bytes())
            if relative == "bin/web-starter":
                target.chmod(0o755)
        admin_pom = repository / "web-starter-admin/pom.xml"
        admin_pom.parent.mkdir(parents=True, exist_ok=True)
        admin_pom.write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            "<artifactId>web-starter-admin</artifactId></project>\n",
            encoding="utf-8",
        )
        git(repository, "init", "--quiet")
        git(repository, "config", "user.name", "Generator Evidence Test")
        git(repository, "config", "user.email", "generator-evidence@example.invalid")
        git(repository, "add", "--all")
        git(repository, "commit", "--quiet", "-m", "candidate")
        git(repository, "tag", "-a", "v" + VERSION, "-m", "release candidate")
        return repository

    @staticmethod
    def _metric_snapshot() -> dict[str, object]:
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
    def _protocol_endpoint_snapshot() -> dict[str, object]:
        return {
            endpoint: {
                "present": True,
                "measurements": {"COUNT": 1.0},
                "tags": {
                    "method": list(gate.PROTOCOL_METHODS),
                    "outcome": list(gate.PROTOCOL_OUTCOMES),
                },
            }
            for endpoint in gate.PROTOCOL_ENDPOINTS
        }

    def _stage_documents(self, stage: str, commit: str, app_seed: str, nginx_seed: str) -> dict[str, dict[str, object]]:
        app_reference = f"registry.example.invalid/{stage}/app@sha256:{app_seed * 64}"
        nginx_reference = f"registry.example.invalid/{stage}/nginx@sha256:{nginx_seed * 64}"
        app_id = "sha256:" + app_seed * 64
        nginx_id = "sha256:" + nginx_seed * 64
        mysql_reference = "registry.example.invalid/mysql@sha256:" + "8" * 64
        redis_reference = "registry.example.invalid/redis@sha256:" + "9" * 64
        images = {
            "app": {"reference": app_reference, "imageId": app_id, "ociVersion": VERSION, "ociRevision": commit},
            "nginx": {"reference": nginx_reference, "imageId": nginx_id, "ociVersion": VERSION, "ociRevision": commit},
            "mysql": {"reference": mysql_reference, "imageId": "sha256:" + "8" * 64, "ociVersion": None, "ociRevision": None},
            "redis": {"reference": redis_reference, "imageId": "sha256:" + "9" * 64, "ociVersion": None, "ociRevision": None},
        }
        baseline = {
            "schemaVersion": 1,
            "status": "SNAPSHOT",
            "observedAt": OBSERVED_AT,
            "authorization": dict(gate.AUTHORIZATION_MATRIX),
            "metrics": self._metric_snapshot(),
            "protocolEndpoints": self._protocol_endpoint_snapshot(),
        }
        runtime = {
            **deepcopy(baseline),
            "status": "PASS",
            "baselineObservedAt": OBSERVED_AT,
            "checks": {name: True for name in gate.METRIC_CHECKS},
            "structuredLog": {
                "format": "ecs",
                "timestamp": OBSERVED_AT,
                "level": "INFO",
                "message": "protocol_request",
                "traceId": "generator-runtime-test",
                "endpoint": "mcp",
                "method": "POST",
                "outcome": "SUCCESS",
                "sourceLineSha256": "a" * 64,
            },
        }
        layers = {name: "PASS" for name in sorted(gate.VERIFY_LAYERS)}
        documents: dict[str, dict[str, object]] = {
            "runtime-production-compose-policy.json": {
                "schemaVersion": 1, "status": "PASS", "composeSha256": "a" * 64, "errors": [],
            },
            "runtime-version-identity.json": {
                "schemaVersion": 2,
                "status": "PASS",
                "observedAt": OBSERVED_AT,
                "release": {"version": VERSION, "gitCommit": commit},
                "java": {"specificationVersion": "21", "runtimeVersion": "21.0.8+9"},
                "actuator": {
                    "applicationVersion": VERSION,
                    "buildVersion": VERSION,
                    "buildArtifact": "journey-admin-admin",
                    "buildGroup": "dev.journey.admin",
                },
                "images": images,
            },
            "operational-metrics-baseline.json": baseline,
            "operational-metrics-runtime.json": runtime,
            "oauth-runtime.json": {
                "schemaVersion": 1, "status": "PASS",
                "checks": {name: "PASS" for name in gate.OAUTH_CHECKS},
            },
            "unified-verify-summary.json": {"schemaVersion": 1, "status": "PASS", "layers": layers},
            "runtime-compose-ps.json": {
                "schemaVersion": 1,
                "services": [
                    {"service": name, "state": "running", "health": "healthy"}
                    for name in sorted(gate.COMPOSE_SERVICES)
                ],
            },
        }
        unified_payload = (json.dumps(documents["unified-verify-summary.json"], sort_keys=True) + "\n").encode()
        documents["release-runtime-acceptance.json"] = {
            "schemaVersion": 1,
            "status": "PASS",
            "observedAt": OBSERVED_AT,
            "release": {"tag": "v" + VERSION, "version": VERSION, "gitCommit": commit},
            "images": {"app": app_reference, "nginx": nginx_reference},
            "identity": {
                "javaSpecificationVersion": "21",
                "applicationVersion": VERSION,
                "buildVersion": VERSION,
                "composeProject": f"wsgen-{RUN_ID}-{stage}",
                "mcpCrudTracePrefix": gate.MCP_CRUD_TRACE_PREFIX,
                "appImage": app_reference,
                "nginxImage": nginx_reference,
                "appOciVersion": VERSION,
                "appOciRevision": commit,
                "nginxOciVersion": VERSION,
                "nginxOciRevision": commit,
            },
            "checks": {name: "PASS" for name in gate.RUNTIME_CHECKS},
            "unifiedVerify": {
                "path": "unified-verify-summary.json",
                "sha256": sha256(unified_payload),
                "status": "PASS",
                "layers": layers,
            },
        }
        if stage == "module":
            documents[gate.GENERATED_ARTIFACT] = {
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
        return documents

    def _document(self) -> dict[str, object]:
        head = git(self.repository, "rev-parse", "HEAD^{commit}")
        tree = git(self.repository, "rev-parse", "HEAD^{tree}")
        tag_object = git(self.repository, "rev-parse", "refs/tags/v" + VERSION)
        source_blobs = {}
        for relative in gate.SOURCE_PATHS:
            payload = (self.repository / relative).read_bytes()
            source_blobs[relative] = {
                "gitBlob": git(self.repository, "rev-parse", f"HEAD:{relative}"),
                "sha256": sha256(payload),
            }
        project_commit = "6" * 40
        module_commit = "7" * 40
        stage_specs = (
            ("project", project_commit, "4" * 40, "1", "2", "-"),
            ("module", module_commit, "5" * 40, "3", "4", "asset"),
        )
        stages = []
        self.stage_documents: dict[str, dict[str, dict[str, object]]] = {}
        for stage, commit, stage_tree, app_seed, nginx_seed, expected_module in stage_specs:
            documents = self._stage_documents(stage, commit, app_seed, nginx_seed)
            self.stage_documents[stage] = documents
            artifacts = {
                name: sha256((json.dumps(value, sort_keys=True) + "\n").encode())
                for name, value in documents.items()
            }
            stages.append({
                "name": stage,
                "version": VERSION,
                "commit": commit,
                "tree": stage_tree,
                "buildContextSha256": ("a" if stage == "project" else "b") * 64,
                "composeProject": f"wsgen-{RUN_ID}-{stage}",
                "expectedModules": expected_module,
                "expectedMcpModules": expected_module,
                "images": {
                    role: {
                        "reference": documents["runtime-version-identity.json"]["images"][role]["reference"],
                        "imageId": documents["runtime-version-identity.json"]["images"][role]["imageId"],
                    }
                    for role in ("app", "nginx")
                },
                "artifacts": artifacts,
                "status": "PASS",
            })
        image_references = sorted(
            stage["images"][role]["reference"] for stage in stages for role in ("app", "nginx")
        )
        return {
            "schemaVersion": 2,
            "acceptanceIds": list(gate.ACCEPTANCE_IDS),
            "status": "PASS",
            "observedAt": OBSERVED_AT,
            "candidate": {
                "commit": head,
                "tree": tree,
                "tag": "v" + VERSION,
                "tagObject": tag_object,
                "mavenVersion": VERSION,
                "frontendVersion": VERSION,
                "cleanWorktree": True,
                "sourceBlobs": source_blobs,
            },
            "tooling": {
                "producerPath": gate.PRODUCER_PATH,
                "validatorPath": gate.VALIDATOR_PATH,
                "schemaPath": gate.SCHEMA_PATH,
                "sourceCount": len(gate.SOURCE_PATHS),
            },
            "derivedProject": {
                "name": "journey-admin",
                "productName": "启程派生管理系统",
                "groupId": "dev.journey.admin",
                "database": "journey_admin",
                "environmentPrefix": "JOURNEY_ADMIN_",
                "forbiddenTermsSha256": sha256(self.terms.read_bytes()),
            },
            "generatedModule": {
                "name": "asset",
                "label": "资产",
                "migrationVersion": "202607200001",
                "permissionIdBase": "5100",
                "menuId": "6100",
                "withMcp": True,
            },
            "stages": stages,
            "cleanup": {
                "composeProjectsRemoved": sorted(stage["composeProject"] for stage in stages),
                "registryContainerRemoved": f"web-starter-generator-registry-{RUN_ID}",
                "generatedImageReferencesRemoved": image_references,
                "temporaryProjectTreeRemoved": True,
                "status": "PASS",
            },
            "evidencePolicy": {
                "outsideRepository": True,
                "directoryMode": "0700",
                "fileMode": "0600",
                "onlyExpectedFiles": True,
                "rawSecretsPersisted": False,
            },
        }

    def _write_bundle(self, document: dict[str, object], raw_override: bytes | None = None) -> None:
        if self.bundle.exists():
            for path in sorted(self.bundle.rglob("*"), reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink()
                else:
                    path.rmdir()
            self.bundle.rmdir()
        self.bundle.mkdir(mode=0o700)
        stages_root = self.bundle / "stages"
        stages_root.mkdir(mode=0o700)
        for stage in ("project", "module"):
            root = stages_root / stage
            root.mkdir(mode=0o700)
            for name, value in self.stage_documents[stage].items():
                path = root / name
                path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
                path.chmod(0o600)
        payload = raw_override if raw_override is not None else (
            json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        evidence = self.bundle / gate.EVIDENCE_FILE
        evidence.write_bytes(payload)
        evidence.chmod(0o600)
        checksum = self.bundle / gate.CHECKSUM_FILE
        checksum.write_text(f"{sha256(payload)}  {gate.EVIDENCE_FILE}\n", encoding="ascii")
        checksum.chmod(0o600)

    @staticmethod
    def _replay(project_tree: str = "4" * 40, module_tree: str = "5" * 40, **overrides) -> gate.ReplayResult:
        plan = {
            "module": "asset",
            "artifactId": "journey-admin-asset",
            "withMcp": True,
            "migrationSha256": "1" * 64,
            "planSha256": "2" * 64,
            "browserTestSha256": "3" * 64,
            "mcpRuntimeTestSha256": "4" * 64,
        }
        plan.update(overrides)
        return gate.ReplayResult(
            project_tree, module_tree, plan,
            tuple(f"semanticCheck{index:02d}" for index in range(20)),
        )

    def _validate(self, replay=None, **kwargs):
        replay_function = replay or (lambda *_args: self._replay())
        with mock.patch.object(gate, "_validate_generator_isolation"):
            return gate.validate_bundle(
                self.bundle,
                repository_root=self.repository,
                forbidden_terms=self.terms,
                _replay=replay_function,
                **kwargs,
            )

    def test_complete_bundle_maps_all_eight_acceptances_and_writes_private_summary(self) -> None:
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        summary = self._validate(require_pass=True, summary_output=output)

        self.assertEqual(list(gate.ACCEPTANCE_IDS), summary["acceptanceIds"])
        self.assertEqual({name: "PASS" for name in gate.ACCEPTANCE_IDS}, summary["coverage"])
        summary_path = output / gate.SUMMARY_FILE
        self.assertEqual(0o600, summary_path.stat().st_mode & 0o777)
        self.assertNotIn("productName", json.loads(summary_path.read_text(encoding="utf-8"))["derivedProject"])
        self.assertIn(
            "executing generator validator differs from the committed candidate",
            Path(gate.__file__).read_text(encoding="utf-8"),
        )

    def test_duplicate_nonfinite_and_secret_shaped_json_are_rejected(self) -> None:
        original = json.dumps(self.document, ensure_ascii=False, sort_keys=True)
        duplicate = (original[:-1] + ',"status":"PASS"}\n').encode("utf-8")
        self._write_bundle(self.document, duplicate)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "repeats field"):
            self._validate()

        nonfinite = original.replace('"schemaVersion": 2', '"schemaVersion": NaN').encode() + b"\n"
        self._write_bundle(self.document, nonfinite)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "non-finite"):
            self._validate()

        secret = original.replace('"status": "PASS"', '"password": "do-not-persist", "status": "PASS"', 1).encode() + b"\n"
        self._write_bundle(self.document, secret)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "secret-shaped"):
            self._validate()

    def test_candidate_source_forgery_and_dirty_worktree_are_rejected(self) -> None:
        forged = deepcopy(self.document)
        forged["candidate"]["sourceBlobs"][gate.PRODUCER_PATH]["sha256"] = "f" * 64
        self._write_bundle(forged)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "source bytes differ"):
            self._validate()

        self._write_bundle(self.document)
        (self.repository / "untracked.txt").write_text("drift\n", encoding="utf-8")
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "dirty or differs"):
            self._validate()

    def test_lightweight_or_moved_release_tag_is_rejected(self) -> None:
        git(self.repository, "tag", "-d", "v" + VERSION)
        git(self.repository, "tag", "v" + VERSION)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "annotated release tag"):
            self._validate()

    def test_internally_rehashed_runtime_forgery_is_semantically_rejected(self) -> None:
        release_path = self.bundle / "stages/project/release-runtime-acceptance.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["checks"].pop("privateBrowserProjectCrud")
        release_path.write_text(json.dumps(release, sort_keys=True) + "\n", encoding="utf-8")
        release_path.chmod(0o600)
        forged = deepcopy(self.document)
        forged["stages"][0]["artifacts"]["release-runtime-acceptance.json"] = sha256(release_path.read_bytes())
        self._write_bundle(forged)
        # _write_bundle restores stage fixtures; reapply the internally consistent forged stage.
        release_path.write_text(json.dumps(release, sort_keys=True) + "\n", encoding="utf-8")
        release_path.chmod(0o600)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "behavioral check set"):
            self._validate()

    def test_protocol_endpoint_and_structured_log_contracts_are_fail_closed(self) -> None:
        protocol = deepcopy(self.document)
        self.stage_documents["project"]["operational-metrics-baseline.json"][
            "protocolEndpoints"
        ]["mcp"]["tags"]["method"] = ["POST"]
        protocol["stages"][0]["artifacts"]["operational-metrics-baseline.json"] = sha256(
            (
                json.dumps(
                    self.stage_documents["project"]["operational-metrics-baseline.json"],
                    sort_keys=True,
                )
                + "\n"
            ).encode()
        )
        self._write_bundle(protocol)
        with self.assertRaisesRegex(
            gate.GeneratorEvidenceError, "protocol endpoint metric mcp is not exact"
        ):
            self._validate()

        self.stage_documents["project"] = self._stage_documents(
            "project", "6" * 40, "1", "2"
        )
        self.stage_documents["project"]["operational-metrics-runtime.json"][
            "structuredLog"
        ]["format"] = "plain"
        structured = deepcopy(self.document)
        structured["stages"][0]["artifacts"]["operational-metrics-runtime.json"] = sha256(
            (
                json.dumps(
                    self.stage_documents["project"]["operational-metrics-runtime.json"],
                    sort_keys=True,
                )
                + "\n"
            ).encode()
        )
        self._write_bundle(structured)
        with self.assertRaisesRegex(
            gate.GeneratorEvidenceError, "structured log proof is not exact"
        ):
            self._validate()

    def test_replayed_tree_and_generated_semantics_must_match_runtime(self) -> None:
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "replayed generated trees"):
            self._validate(replay=lambda *_args: self._replay(project_tree="0" * 40))
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "differs from replayed semantics"):
            self._validate(replay=lambda *_args: self._replay(planSha256="0" * 64))

    def test_bundle_and_candidate_toctou_are_rejected(self) -> None:
        snapshot = gate._snapshot_bundle(self.bundle, self.repository)
        changed = replace(snapshot, root_modified_ns=snapshot.root_modified_ns + 1)
        with mock.patch.object(gate, "_snapshot_bundle", side_effect=[snapshot, changed]), \
                mock.patch.object(gate, "_validate_generator_isolation"):
            with self.assertRaisesRegex(gate.GeneratorEvidenceError, "changed during validation"):
                gate.validate_bundle(
                    self.bundle, repository_root=self.repository, forbidden_terms=self.terms,
                    _replay=lambda *_args: self._replay(),
                )

        def drift(*_args):
            (self.repository / "late-drift.txt").write_text("late\n", encoding="utf-8")
            return self._replay()

        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "dirty or differs"):
            self._validate(replay=drift)

    def test_private_mode_external_boundary_and_summary_policy_are_enforced(self) -> None:
        (self.bundle / gate.EVIDENCE_FILE).chmod(0o644)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "0600"):
            self._validate()

        self._write_bundle(self.document)
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "requires --require-pass"):
            self._validate(summary_output=self.root / "absent-summary")

    def test_generator_isolation_is_recomputed_from_candidate_sources(self) -> None:
        candidate = gate._verify_candidate(self.document["candidate"], self.repository)
        gate._validate_generator_isolation(self.repository, candidate)

    def test_forbidden_terms_input_is_hash_bound_and_external(self) -> None:
        self.terms.write_text("different-term\n", encoding="utf-8")
        with self.assertRaisesRegex(gate.GeneratorEvidenceError, "differs from producer input"):
            self._validate()


if __name__ == "__main__":
    unittest.main()
