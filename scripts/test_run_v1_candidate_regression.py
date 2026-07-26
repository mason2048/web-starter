from __future__ import annotations

from argparse import Namespace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_v1_candidate_regression as regression
import release_evidence_gate


def candidate() -> dict[str, object]:
    digest = "sha256:" + "a" * 64
    return {
        "schemaVersion": 1,
        "release": {
            "tag": "v1.2.3-rc.1",
            "version": "1.2.3-rc.1",
            "gitCommit": "b" * 40,
        },
        "images": {
            name: {"reference": f"registry.invalid/web-starter-{name}", "digest": digest}
            for name in ("app", "nginx", "mysql", "redis")
        },
    }


def source_identity() -> dict[str, object]:
    return {
        "gitCommit": "b" * 40,
        "gitTree": "d" * 40,
        "sourceArchiveSha256": "e" * 64,
        "releaseTag": "v1.2.3-rc.1",
        "releaseVersion": "1.2.3-rc.1",
        "indexNormal": True,
        "trackedDiffSha256": hashlib.sha256(b"").hexdigest(),
        "untrackedSourceSha256": hashlib.sha256(b"").hexdigest(),
        "untrackedSourceCount": 0,
        "clean": True,
    }


def supplemental_candidate(candidate_sha: str = "c" * 64) -> dict[str, str]:
    identity = source_identity()
    return {
        "manifestSha256": candidate_sha,
        "gitCommit": str(identity["gitCommit"]),
        "gitTree": str(identity["gitTree"]),
        "sourceArchiveSha256": str(identity["sourceArchiveSha256"]),
        "releaseTag": str(identity["releaseTag"]),
        "releaseVersion": str(identity["releaseVersion"]),
    }


def supplemental_artifact(
    *,
    producer: str = "browser-acceptance",
    check: str = "supplemental.browserStateAndViewportMatrix",
    candidate_sha: str = "c" * 64,
    observations: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "suite": "v1",
        "producer": producer,
        "check": check,
        "candidate": supplemental_candidate(candidate_sha),
        "observations": observations or {"viewportWidths": [390, 1440]},
    }


def write_supplemental_bundle(
    root: Path,
    artifact_document: dict[str, object],
    *,
    producer: str = "browser-acceptance",
    check: str = "supplemental.browserStateAndViewportMatrix",
    candidate_sha: str = "c" * 64,
) -> Path:
    bundle = root / "bundle"
    artifacts = bundle / "artifacts"
    bundle.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    artifact = artifacts / "sanitized.json"
    artifact.write_text(json.dumps(artifact_document), encoding="utf-8")
    artifact.chmod(0o600)
    observation = bundle / "observation.json"
    document = {
        "schemaVersion": 2,
        "suite": "v1",
        "candidate": supplemental_candidate(candidate_sha),
        "producer": producer,
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "artifacts": [{
            "id": "browser-summary",
            "path": "artifacts/sanitized.json",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }],
        "checks": [{
            "id": check,
            "artifactIds": ["browser-summary"],
        }],
    }
    observation.write_text(json.dumps(document), encoding="utf-8")
    observation.chmod(0o600)
    return observation


class V1CandidateRegressionTest(unittest.TestCase):
    def test_coverage_is_exactly_the_frozen_42_item_baseline(self) -> None:
        coverage = regression._load_coverage()
        self.assertEqual(42, len(coverage.items))
        self.assertEqual(
            [f"AC-{number:02d}" for number in range(1, 43)],
            [item.acceptance_id for item in coverage.items],
        )
        self.assertEqual(37, sum(item.level == "P0" for item in coverage.items))
        self.assertEqual(5, sum(item.level == "P1" for item in coverage.items))
        self.assertTrue(all(item.requirements for item in coverage.items))

    def test_runtime_check_contract_stays_in_sync_with_release_gate(self) -> None:
        self.assertEqual(release_evidence_gate.RUNTIME_CHECKS, regression.RUNTIME_CHECKS)
        runner = regression.RELEASE_RUNNER.read_text(encoding="utf-8")
        for check in regression.RUNTIME_CHECKS:
            self.assertIn(f'"{check}": "PASS"', runner)
        self.assertIn('"identity": {', runner)

    def test_supplemental_contract_has_no_self_reported_status_or_dynamic_bypass(self) -> None:
        observation_schema = json.loads(
            (
                regression.REPOSITORY_ROOT
                / "security/v1-regression-observation.schema.json"
            ).read_text(encoding="utf-8")
        )
        artifact_schema = json.loads(
            (
                regression.REPOSITORY_ROOT
                / "security/v1-regression-supplemental-artifact.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(2, observation_schema["properties"]["schemaVersion"]["const"])
        self.assertNotIn(
            "status",
            observation_schema["properties"]["checks"]["items"]["properties"],
        )
        self.assertNotIn("status", artifact_schema["properties"])
        registrations = regression.supplemental_validators.PRODUCER_VALIDATORS
        self.assertEqual(
            {regression.supplemental_validators.SOURCE_REVIEW_PRODUCER},
            set(registrations),
        )
        source_review = registrations[
            regression.supplemental_validators.SOURCE_REVIEW_PRODUCER
        ]
        self.assertEqual(
            regression.supplemental_validators.SOURCE_REVIEW_CHECKS,
            source_review.checks,
        )
        self.assertTrue(callable(source_review.validator))

    def test_source_identity_binds_head_tree_and_committed_archive_bytes(self) -> None:
        identity = regression._source_identity()
        expected_tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=regression.REPOSITORY_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        archive = subprocess.run(
            ["git", "archive", "--format=tar", str(identity["gitCommit"])],
            cwd=regression.REPOSITORY_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(expected_tree, identity["gitTree"])
        self.assertEqual(
            hashlib.sha256(archive).hexdigest(),
            identity["sourceArchiveSha256"],
        )

    def test_missing_and_environment_evidence_never_becomes_pass(self) -> None:
        coverage = regression._load_coverage()
        results, counts = regression._evaluate(coverage, {})
        self.assertEqual(42, counts["statuses"]["NOT_COVERED"])
        self.assertTrue(all(result["status"] == "NOT_COVERED" for result in results))

        ac41 = next(item for item in coverage.items if item.acceptance_id == "AC-41")
        checks = {requirement.check: "PASS" for requirement in ac41.requirements}
        checks[ac41.requirements[0].check] = "ENV_REQUIRED"
        results, _ = regression._evaluate(coverage, checks)
        self.assertEqual("ENV_REQUIRED", next(item for item in results if item["id"] == "AC-41")["status"])

        checks[ac41.requirements[0].check] = "FAIL"
        results, _ = regression._evaluate(coverage, checks)
        self.assertEqual("FAIL", next(item for item in results if item["id"] == "AC-41")["status"])

    def test_environment_block_is_incomplete_while_integrity_error_is_failure(self) -> None:
        counts = {
            "statuses": {"PASS": 1, "FAIL": 0, "NOT_COVERED": 40, "ENV_REQUIRED": 1}
        }
        self.assertEqual(
            "INCOMPLETE",
            regression._conclusion(counts, ["release-runtime-environment-required"]),
        )
        self.assertEqual(
            "FAIL", regression._conclusion(counts, ["candidate-source-changed-during-run"])
        )
        counts["statuses"] = {"PASS": 42, "FAIL": 0, "NOT_COVERED": 0, "ENV_REQUIRED": 0}
        self.assertEqual("PASS", regression._conclusion(counts, []))

    def test_plan_writes_private_incomplete_evidence_without_running_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            options = Namespace(
                mode="plan",
                output_dir=output,
                candidate=None,
                forbidden_terms_file=None,
                reference_repository=None,
                observation=[],
                runtime_timeout_seconds=60,
                fail_fast_timeout_seconds=60,
            )
            exit_code, actual_output = regression.run(options)
            self.assertEqual(regression.EXIT_INCOMPLETE, exit_code)
            ledger = json.loads((actual_output / "v1-regression-ledger.json").read_text())
            self.assertEqual("INCOMPLETE", ledger["conclusion"])
            self.assertEqual(42, ledger["counts"]["statuses"]["NOT_COVERED"])
            self.assertFalse((actual_output / "logs").exists())
            self.assertEqual(0o700, stat.S_IMODE(actual_output.stat().st_mode))
            for path in actual_output.iterdir():
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_output_must_be_external_empty_and_non_symlinked(self) -> None:
        with self.assertRaisesRegex(regression.RegressionError, "outside"):
            regression._prepare_output_directory(regression.REPOSITORY_ROOT / "target" / "v1")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "marker").write_text("marker", encoding="utf-8")
            with self.assertRaisesRegex(regression.RegressionError, "empty"):
                regression._prepare_output_directory(occupied)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(regression.RegressionError, "symbolic"):
                regression._prepare_output_directory(link)

    def test_candidate_contract_requires_exact_immutable_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "candidate.json"
            manifest.write_text(json.dumps(candidate()), encoding="utf-8")
            loaded, digest = regression._load_candidate(manifest)
            self.assertEqual("v1.2.3-rc.1", loaded["release"]["tag"])
            self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), digest)

            invalid = candidate()
            invalid["images"]["app"]["reference"] += "@latest"
            manifest.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(regression.RegressionError, "not immutable"):
                regression._load_candidate(manifest)

            snapshot = candidate()
            snapshot["release"]["version"] = "1.2.3-SNAPSHOT"
            snapshot["release"]["tag"] = "v1.2.3-SNAPSHOT"
            manifest.write_text(json.dumps(snapshot), encoding="utf-8")
            with self.assertRaisesRegex(regression.RegressionError, "identity is invalid"):
                regression._load_candidate(manifest)

    def test_runtime_json_cannot_hide_a_failure_behind_a_duplicate_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "summary.json"
            evidence.write_text('{"status":"FAIL","status":"PASS"}\n', encoding="utf-8")
            with self.assertRaisesRegex(regression.RegressionError, "repeats field: status"):
                regression._load_json(evidence, "runtime summary")

    def test_full_candidate_requires_clean_matching_source(self) -> None:
        manifest = candidate()
        with self.assertRaisesRegex(regression.RegressionError, "clean"):
            regression._verify_candidate_source(
                manifest, {"clean": False, "gitCommit": manifest["release"]["gitCommit"]}
            )
        with self.assertRaisesRegex(regression.RegressionError, "differs"):
            regression._verify_candidate_source(
                manifest, {"clean": True, "gitCommit": "d" * 40}
            )

    def test_status_only_supplemental_artifact_is_fail_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate_sha = "c" * 64
            observation = write_supplemental_bundle(
                Path(directory), {"status": "PASS"}, candidate_sha=candidate_sha
            )
            checks: dict[str, str] = {}
            sources: dict[str, dict[str, object]] = {}
            regression._load_observations(
                [observation], candidate_sha, source_identity(),
                {"supplemental.browserStateAndViewportMatrix"}, checks, sources,
            )
            self.assertEqual("FAIL", checks["supplemental.browserStateAndViewportMatrix"])
            results, _counts = regression._evaluate(regression._load_coverage(), checks)
            affected = next(
                result
                for result in results
                if any(
                    requirement["check"]
                    == "supplemental.browserStateAndViewportMatrix"
                    for requirement in result["requirements"]
                )
            )
            self.assertEqual("FAIL", affected["status"])
            self.assertNotIn("path", sources["supplemental.browserStateAndViewportMatrix"])

            document = json.loads(observation.read_text(encoding="utf-8"))
            document["artifacts"][0]["sha256"] = "d" * 64
            observation.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(regression.RegressionError, "checksum"):
                regression._load_observations(
                    [observation], candidate_sha, source_identity(),
                    {"supplemental.browserStateAndViewportMatrix"}, {}, {},
                )

    def test_unregistered_or_missing_supplemental_validator_stays_not_covered(self) -> None:
        check = "supplemental.browserStateAndViewportMatrix"
        with tempfile.TemporaryDirectory() as directory:
            observation = write_supplemental_bundle(
                Path(directory), supplemental_artifact()
            )
            for registry in (
                {},
                {
                    "browser-acceptance": regression.supplemental_validators.ProducerValidator(
                        frozenset({check}), None
                    )
                },
            ):
                checks: dict[str, str] = {}
                with self.subTest(registry=bool(registry)), patch.object(
                    regression.supplemental_validators,
                    "PRODUCER_VALIDATORS",
                    registry,
                ):
                    regression._load_observations(
                        [observation], "c" * 64, source_identity(), {check}, checks, {}
                    )
                self.assertEqual("NOT_COVERED", checks[check])

    def test_registered_validator_recomputes_status_from_status_free_observations(self) -> None:
        check = "supplemental.browserStateAndViewportMatrix"

        def validator(
            check_id: str,
            artifacts: list[dict[str, object]],
            candidate_binding: dict[str, str],
        ) -> str:
            self.assertEqual(check, check_id)
            self.assertEqual(supplemental_candidate(), candidate_binding)
            return (
                "PASS"
                if artifacts == [supplemental_artifact()]
                else "FAIL"
            )

        registration = regression.supplemental_validators.ProducerValidator(
            frozenset({check}), validator
        )
        with tempfile.TemporaryDirectory() as directory, patch.object(
            regression.supplemental_validators,
            "PRODUCER_VALIDATORS",
            {"browser-acceptance": registration},
        ):
            observation = write_supplemental_bundle(
                Path(directory), supplemental_artifact()
            )
            checks: dict[str, str] = {}
            regression._load_observations(
                [observation], "c" * 64, source_identity(), {check}, checks, {}
            )
            self.assertEqual("PASS", checks[check])

    def test_supplemental_bundle_permissions_and_file_set_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            observation = write_supplemental_bundle(
                Path(directory), supplemental_artifact()
            )
            observation.parent.chmod(0o755)
            with self.assertRaisesRegex(regression.RegressionError, "private"):
                regression._load_observations(
                    [observation], "c" * 64, source_identity(),
                    {"supplemental.browserStateAndViewportMatrix"}, {}, {},
                )
            observation.parent.chmod(0o700)
            artifact = observation.parent / "artifacts/sanitized.json"
            artifact.chmod(0o644)
            with self.assertRaisesRegex(regression.RegressionError, "unsafe"):
                regression._load_observations(
                    [observation], "c" * 64, source_identity(),
                    {"supplemental.browserStateAndViewportMatrix"}, {}, {},
                )
            artifact.chmod(0o600)
            extra = observation.parent / "unexpected.txt"
            extra.write_text("unexpected", encoding="utf-8")
            extra.chmod(0o600)
            with self.assertRaisesRegex(regression.RegressionError, "unexpected entries"):
                regression._load_observations(
                    [observation], "c" * 64, source_identity(),
                    {"supplemental.browserStateAndViewportMatrix"}, {}, {},
                )

    def test_private_snapshot_detects_replacement_after_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "observation.json"
            evidence.write_text('{"value":1}\n', encoding="utf-8")
            evidence.chmod(0o600)
            snapshot = regression._snapshot_file(
                evidence,
                "supplemental observation",
                expected_mode=0o600,
                maximum_bytes=1024,
            )
            evidence.write_text('{"value":2}\n', encoding="utf-8")
            with self.assertRaisesRegex(regression.RegressionError, "changed"):
                regression._verify_snapshot(
                    evidence, snapshot, "supplemental observation"
                )

    def test_internally_consistent_forged_candidate_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            observation = write_supplemental_bundle(
                Path(directory), supplemental_artifact()
            )
            document = json.loads(observation.read_text(encoding="utf-8"))
            forged_candidate = {
                "manifestSha256": "c" * 64,
                "gitCommit": "1" * 40,
                "gitTree": "2" * 40,
                "sourceArchiveSha256": "3" * 64,
                "releaseTag": "v1.2.3-rc.1",
                "releaseVersion": "1.2.3-rc.1",
            }
            artifact_path = observation.parent / "artifacts/sanitized.json"
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            document["candidate"] = forged_candidate
            artifact["candidate"] = forged_candidate
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            document["artifacts"][0]["sha256"] = hashlib.sha256(
                artifact_path.read_bytes()
            ).hexdigest()
            observation.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaisesRegex(regression.RegressionError, "wrong identity"):
                regression._load_observations(
                    [observation],
                    "c" * 64,
                    source_identity(),
                    {"supplemental.browserStateAndViewportMatrix"},
                    {},
                    {},
                )

    def test_reference_guard_detects_changes_to_existing_untracked_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "reference"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Regression", "-c",
                    "user.email=regression@example.invalid", "commit", "-qm", "initial",
                ],
                cwd=repository,
                check=True,
            )
            untracked = repository / "existing-untracked.txt"
            untracked.write_text("before\n", encoding="utf-8")
            before = regression._reference_identity(repository)
            untracked.write_text("after\n", encoding="utf-8")
            after = regression._reference_identity(repository)
            self.assertEqual(before["status"], after["status"])
            self.assertNotEqual(before["untracked"], after["untracked"])

    def test_runtime_adapter_accepts_only_fresh_exact_candidate_evidence(self) -> None:
        current_candidate = candidate()
        runtime_version = {"value": current_candidate["release"]["version"]}
        unified_browser = {"status": "PASS"}

        def fake_runner(_command, *, cwd, environment, timeout):
            del cwd, timeout
            output = Path(environment["WEB_STARTER_RELEASE_ARTIFACT_DIR"])
            unified_layers = {
                name: (unified_browser["status"] if name == "browser" else "PASS")
                for name in sorted(regression.VERIFY_LAYERS)
            }
            unified_summary = {
                "schemaVersion": 1,
                "status": "PASS" if unified_browser["status"] == "PASS" else "INCOMPLETE_OR_FAILED",
                "layers": unified_layers,
            }
            unified_path = output / "unified-verify-summary.json"
            unified_path.write_text(json.dumps(unified_summary), encoding="utf-8")
            document = {
                "schemaVersion": 1,
                "status": "PASS",
                "observedAt": datetime.now(timezone.utc).isoformat(),
                "release": current_candidate["release"],
                "images": {
                    "app": regression._effective_image(current_candidate, "app"),
                    "nginx": regression._effective_image(current_candidate, "nginx"),
                },
                "identity": {
                    "javaSpecificationVersion": "21",
                    "applicationVersion": runtime_version["value"],
                    "buildVersion": current_candidate["release"]["version"],
                    "composeProject": environment["WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT"],
                    "mcpCrudTracePrefix": "release-sdk",
                    "appImage": regression._effective_image(current_candidate, "app"),
                    "nginxImage": regression._effective_image(current_candidate, "nginx"),
                    "appOciVersion": current_candidate["release"]["version"],
                    "appOciRevision": current_candidate["release"]["gitCommit"],
                    "nginxOciVersion": current_candidate["release"]["version"],
                    "nginxOciRevision": current_candidate["release"]["gitCommit"],
                },
                "unifiedVerify": {
                    "path": unified_path.name,
                    "sha256": hashlib.sha256(unified_path.read_bytes()).hexdigest(),
                    "status": unified_summary["status"],
                    "layers": unified_layers,
                },
                "checks": {name: "PASS" for name in regression.RUNTIME_CHECKS},
            }
            (output / "release-runtime-acceptance.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            return 0

        with tempfile.TemporaryDirectory() as directory, patch.object(
            regression, "_run_quiet_process", side_effect=fake_runner
        ), patch.object(regression, "_isolated_release_suffix", return_value="abcdef123456"):
            checks: dict[str, str] = {}
            sources: dict[str, dict[str, object]] = {}
            errors: list[str] = []
            regression._run_release_runtime(
                Path(directory), current_candidate, checks, sources, errors, 60
            )
            self.assertEqual([], errors)
            self.assertEqual(len(regression.RUNTIME_CHECKS), len(checks))
            self.assertTrue(all(status == "PASS" for status in checks.values()))

        runtime_version["value"] = "0.0.0-mismatched"
        with tempfile.TemporaryDirectory() as directory, patch.object(
            regression, "_run_quiet_process", side_effect=fake_runner
        ), patch.object(regression, "_isolated_release_suffix", return_value="abcdef123456"):
            checks = {}
            errors = []
            regression._run_release_runtime(
                Path(directory), current_candidate, checks, {}, errors, 60
            )
            self.assertEqual({}, checks)
            self.assertEqual(["release-runtime-evidence-invalid"], errors)

        runtime_version["value"] = current_candidate["release"]["version"]
        unified_browser["status"] = "NOT_COVERED"
        with tempfile.TemporaryDirectory() as directory, patch.object(
            regression, "_run_quiet_process", side_effect=fake_runner
        ), patch.object(regression, "_isolated_release_suffix", return_value="abcdef123456"):
            checks = {}
            errors = []
            regression._run_release_runtime(
                Path(directory), current_candidate, checks, {}, errors, 60
            )
            self.assertEqual({}, checks)
            self.assertEqual(["release-runtime-evidence-invalid"], errors)

    def test_runtime_environment_gap_marks_every_runtime_check_environment_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            regression,
            "_isolated_release_suffix",
            side_effect=regression.RegressionError("unavailable"),
        ):
            checks: dict[str, str] = {}
            errors: list[str] = []
            regression._run_release_runtime(
                Path(directory), candidate(), checks, {}, errors, 60
            )
        self.assertEqual(
            {f"runtime.{check}" for check in regression.RUNTIME_CHECKS}, set(checks)
        )
        self.assertTrue(all(status == "ENV_REQUIRED" for status in checks.values()))
        self.assertEqual(["release-runtime-environment-required"], errors)

    def test_fail_fast_adapter_uses_schema_v2_independent_validator(self) -> None:
        current_candidate = candidate()
        expected_image = regression._effective_image(current_candidate, "app")

        def fake_runner(command, *, cwd, environment, timeout):
            del cwd, environment, timeout
            output = Path(command[command.index("--output-dir") + 1])
            output.mkdir(mode=0o700)
            report = output / "v2-ac29-production-fail-fast.json"
            report.write_text(
                json.dumps({
                    "schemaVersion": 2,
                    "acceptanceId": "V2-AC-29",
                    "status": "PASS",
                    "evidencePolicy": {
                        "rawLogsPersisted": False,
                        "fixtureMaterialPersisted": False,
                    },
                }),
                encoding="utf-8",
            )
            checksum = output / "v2-ac29-production-fail-fast.json.sha256"
            checksum.write_text(
                hashlib.sha256(report.read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )
            return 0

        with tempfile.TemporaryDirectory() as directory, patch.object(
            regression, "_run_quiet_process", side_effect=fake_runner
        ), patch.object(
            regression.production_fail_fast_rehearsal,
            "capture_candidate",
            return_value=object(),
        ), patch.object(
            regression.production_fail_fast_rehearsal,
            "inspect_local_app_image",
            return_value=SimpleNamespace(image_id="sha256:" + "f" * 64),
        ), patch.object(
            regression.production_fail_fast_validator,
            "validate_evidence",
            return_value={"status": "PASS"},
        ) as validate:
            checks: dict[str, str] = {}
            sources: dict[str, dict[str, object]] = {}
            errors: list[str] = []
            regression._run_fail_fast_rehearsal(
                Path(directory), current_candidate, checks, sources, errors, 60
            )

        self.assertEqual([], errors)
        self.assertEqual(
            "PASS", checks["rehearsal.productionSecurityFailFast"]
        )
        validate.assert_called_once_with(
            Path(directory)
            / "production-fail-fast"
            / "v2-ac29-production-fail-fast.json",
            expected_app_reference=expected_image,
            expected_app_image_id="sha256:" + "f" * 64,
            repository_root=regression.REPOSITORY_ROOT,
            require_pass=True,
        )

    def test_sensitive_gate_output_is_discarded_not_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            status, digest, error = regression._run_logged_gate(
                output,
                "sensitive-test",
                [os.environ.get("PYTHON", "python3"), "-c", "print('Authorization: Bearer abcdefghijklmnop')"],
                cwd=output,
            )
            self.assertEqual("FAIL", status)
            self.assertIsNone(digest)
            self.assertEqual("sensitive-test-sensitive-output-discarded", error)
            self.assertFalse((output / "logs/sensitive-test.log").exists())

    def test_structured_authorization_metrics_are_not_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            metrics = output / "metrics.json"
            metrics.write_text(
                json.dumps({
                    "authorization": {
                        "healthAnonymous": 200,
                        "metricsAnonymous": 401,
                    },
                    "checks": {"authorizationMatrix": True},
                }),
                encoding="utf-8",
            )
            errors: list[str] = []
            regression._discard_sensitive_evidence(output, errors)
            self.assertTrue(metrics.exists())
            self.assertEqual([], errors)

    def test_sensitive_runtime_artifact_is_deleted_before_ledger_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            unsafe = output / "runtime.json"
            unsafe.write_text(
                '{"access_' + 'token":"' + 'abcdefghijklmnop' + '"}\n', encoding="utf-8"
            )
            errors: list[str] = []
            regression._discard_sensitive_evidence(output, errors)
            self.assertFalse(unsafe.exists())
            self.assertEqual(["sensitive-evidence-discarded"], errors)

    def test_child_environment_does_not_inherit_application_credentials(self) -> None:
        with patch.dict(os.environ, {
            "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": "fixture-material",
            "WEB_STARTER_TOKEN_PEPPER": "fixture-material",
        }, clear=False):
            child = regression._safe_environment()
        self.assertNotIn("WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD", child)
        self.assertNotIn("WEB_STARTER_TOKEN_PEPPER", child)
        self.assertEqual("true", child["CI"])

    def test_random_release_project_preflight_retries_an_existing_identity(self) -> None:
        calls: list[list[str]] = []
        suffixes = iter(("111111111111", "222222222222"))

        def fake_run(command, **_kwargs):
            calls.append(command)
            occupied = "111111111111" in command[-1]
            return subprocess.CompletedProcess(command, 0, b"existing\n" if occupied else b"")

        with patch.object(regression.secrets, "token_hex", side_effect=lambda _size: next(suffixes)), patch.object(
            regression.subprocess, "run", side_effect=fake_run
        ):
            self.assertEqual("222222222222", regression._isolated_release_suffix())
        self.assertEqual(4, len(calls))

    def test_orchestrator_does_not_own_compose_cleanup_or_browser_implementation(self) -> None:
        source = Path(regression.__file__).read_text(encoding="utf-8")
        self.assertIn("run_release_runtime_acceptance.sh", source)
        self.assertNotIn("docker compose down", source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("Authorization: Bearer", source)


if __name__ == "__main__":
    unittest.main()
