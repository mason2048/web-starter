from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from scripts import create_release_runtime_test_reports_proof as producer
from scripts import validate_release_runtime_test_reports_proof as validator


WORKSPACE = Path(__file__).resolve().parents[1]
VERSION = "2.0.0"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed.stdout.strip()


class Fixture:
    def __init__(
        self,
        parent: Path,
        *,
        version: str = VERSION,
        annotated_tag: bool = True,
        source_replacements: dict[str, tuple[bytes, bytes]] | None = None,
    ) -> None:
        parent.mkdir(parents=True, exist_ok=True)
        self.parent = parent
        self.repository = parent / "candidate"
        self.repository.mkdir()
        self.version = version
        self.tag = f"v{version}"
        replacements = source_replacements or {}
        for relative in validator.SOURCE_PATHS:
            payload = WORKSPACE.joinpath(*relative.split("/")).read_bytes()
            if relative in {validator.ROOT_POM, validator.MCP_POM, validator.FRONTEND_PACKAGE}:
                payload = payload.replace(b"2.0.0-SNAPSHOT", version.encode())
            if relative in replacements:
                before, after = replacements[relative]
                if before not in payload:
                    raise AssertionError(f"fixture source marker missing: {relative}")
                payload = payload.replace(before, after, 1)
            target = self.repository.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Runtime Report Evidence Test")
        git(self.repository, "config", "user.email", "runtime-report@example.invalid")
        git(self.repository, "add", "--all")
        git(self.repository, "commit", "-q", "-m", "candidate")
        self.commit = git(self.repository, "rev-parse", "HEAD^{commit}")
        self.tree = git(self.repository, "rev-parse", "HEAD^{tree}")
        if annotated_tag:
            git(self.repository, "tag", "-a", self.tag, "-m", self.tag)
        else:
            git(self.repository, "tag", self.tag)

        self.evidence = parent / "raw"
        self.evidence.mkdir(mode=0o700)
        self.evidence.chmod(0o700)
        self.started = time.time_ns() - 5_000_000
        self.write_playwright(self.clean_playwright())
        for report_name, (test_class, method) in validator.SUREFIRE_TESTS.items():
            self.write_private(report_name, self.clean_surefire(test_class, method))

    def write_private(self, name: str, payload: bytes | str) -> None:
        encoded = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        target = self.evidence / name
        target.write_bytes(encoded)
        target.chmod(0o600)

    def clean_playwright(self) -> dict[str, object]:
        suites: list[dict[str, object]] = []
        test_directory = str((self.repository / "web-starter-web" / "e2e").resolve())
        for relative, titles in validator.PLAYWRIGHT_SPECS.items():
            reported = Path(relative).name
            suites.append({
                "title": Path(relative).name,
                "file": reported,
                "specs": [
                    {
                        "title": title,
                        "file": reported,
                        "ok": True,
                        "tags": [],
                        "tests": [{
                            "expectedStatus": "passed",
                            "status": "expected",
                            "projectName": "",
                            "projectId": "",
                            "annotations": [],
                            "results": [{
                                "status": "passed",
                                "retry": 0,
                                "errors": [],
                                "stdout": [],
                                "stderr": [],
                                "attachments": [],
                                "annotations": [],
                                "duration": 10,
                            }],
                        }],
                    }
                    for title in titles
                ],
                "suites": [],
            })
        start = datetime.fromtimestamp(
            self.started / 1_000_000_000, tz=timezone.utc
        ).isoformat().replace("+00:00", "Z")
        return {
            "config": {
                "rootDir": test_directory,
                "projects": [{
                    "id": "",
                    "name": "",
                    "testDir": test_directory,
                }],
            },
            "suites": suites,
            "errors": [],
            "stats": {
                "startTime": start,
                "duration": 1000,
                "expected": validator.PLAYWRIGHT_TEST_COUNT,
                "skipped": 0,
                "unexpected": 0,
                "flaky": 0,
            },
        }

    @staticmethod
    def clean_surefire(test_class: str, method: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="{test_class}" time="0.1" tests="1" '
            'failures="0" errors="0" skipped="0" flakes="0">\n'
            '  <properties><property name="runtime.fixture" value="private"/></properties>\n'
            f'  <testcase classname="{test_class}" name="{method}" time="0.1"/>\n'
            '</testsuite>\n'
        )

    def write_playwright(self, document: dict[str, object]) -> None:
        self.write_private(
            validator.PLAYWRIGHT_REPORT,
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        )

    def create(self) -> Path:
        return producer.create_proof(
            self.evidence,
            repository_root=self.repository,
            candidate_commit=self.commit,
            candidate_version=self.version,
            candidate_tag=self.tag,
            run_started_at_epoch_ns=self.started,
        )

    def kwargs(self, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "repository_root": self.repository,
            "expected_candidate_commit": self.commit,
            "expected_candidate_version": self.version,
            "expected_candidate_tag": self.tag,
            "expected_run_started_at_epoch_ns": self.started,
        }
        result.update(overrides)
        return result

    def validate(self, **overrides: object) -> dict[str, object]:
        return validator.validate_proof(self.evidence, **self.kwargs(**overrides))

    def proof_document(self) -> dict[str, object]:
        return json.loads((self.evidence / validator.PROOF_FILE).read_text(encoding="utf-8"))

    def write_proof_document(self, document: dict[str, object]) -> None:
        self.write_private(validator.PROOF_FILE, validator._canonical_json(document))

    def rebind_report(self, name: str) -> None:
        document = self.proof_document()
        target = self.evidence / name
        metadata = target.stat()
        reports = document["reports"]
        assert isinstance(reports, dict)
        reports[name] = {
            "sha256": digest(target.read_bytes()),
            "size": metadata.st_size,
            "modifiedAtEpochNs": metadata.st_mtime_ns,
        }
        self.write_proof_document(document)


class RuntimeTestReportEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-runtime-reports-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, name: str = "fixture", **kwargs: object) -> Fixture:
        return Fixture(self.root / name, **kwargs)

    def test_package_and_direct_cli_entrypoints_use_consistent_imports(self) -> None:
        self.assertIs(producer.validation, validator)
        commands = (
            [sys.executable, "-B", str(WORKSPACE / "scripts/create_release_runtime_test_reports_proof.py"), "--help"],
            [sys.executable, "-B", str(WORKSPACE / "scripts/validate_release_runtime_test_reports_proof.py"), "--help"],
            [sys.executable, "-B", "-m", "scripts.create_release_runtime_test_reports_proof", "--help"],
            [sys.executable, "-B", "-m", "scripts.validate_release_runtime_test_reports_proof", "--help"],
        )
        for command in commands:
            with self.subTest(command=command):
                completed = subprocess.run(
                    command,
                    cwd=WORKSPACE,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertIn("usage:", completed.stdout)

    def test_producer_and_independent_validator_accept_exact_reports(self) -> None:
        fixture = self.fixture()
        proof = fixture.create()
        summary = fixture.validate(require_pass=True)

        self.assertEqual(validator.PROOF_FILE, proof.name)
        self.assertEqual(0o600, stat.S_IMODE(proof.stat().st_mode))
        self.assertEqual("PASS", summary["status"])
        self.assertEqual(validator.EVIDENCE_TYPE, summary["evidenceType"])
        self.assertEqual(
            validator.PLAYWRIGHT_TEST_COUNT,
            summary["coverage"]["playwright"]["tests"],
        )
        self.assertEqual(2, len(summary["coverage"]["surefire"]))
        self.assertEqual(set(validator.SOURCE_PATHS), set(summary["sources"]))
        for relative in (
            "scripts/create_release_runtime_test_reports_proof.py",
            "scripts/validate_release_runtime_test_reports_proof.py",
        ):
            self.assertEqual(
                digest(fixture.repository.joinpath(*relative.split("/")).read_bytes()),
                summary["sources"][relative],
            )
        proof_text = proof.read_text(encoding="utf-8")
        self.assertNotIn('"status"', proof_text)
        self.assertEqual(
            validator._canonical_json(json.loads(proof_text)), proof.read_bytes()
        )

    def test_validator_writes_one_canonical_private_summary_without_raw_material(self) -> None:
        fixture = self.fixture()
        fixture.create()
        output = self.root / "public-summary"
        output.mkdir(mode=0o700)
        output.chmod(0o700)

        summary = fixture.validate(require_pass=True, summary_output=output)

        target = output / validator.SUMMARY_FILE
        self.assertEqual({validator.SUMMARY_FILE}, set(os.listdir(output)))
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        self.assertEqual(validator.canonical_summary_bytes(summary), target.read_bytes())
        text = target.read_text(encoding="utf-8")
        self.assertNotIn("runtime.fixture", text)
        self.assertNotIn("properties", text)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "empty"):
            fixture.validate(require_pass=True, summary_output=output)

    def test_summary_output_requires_explicit_pass_and_private_empty_directory(self) -> None:
        fixture = self.fixture()
        fixture.create()
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "requires"):
            fixture.validate(summary_output=output)

        output.chmod(0o755)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "0700"):
            fixture.validate(require_pass=True, summary_output=output)

        output.chmod(0o700)
        (output / "existing").write_text("occupied")
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "empty"):
            fixture.validate(require_pass=True, summary_output=output)

    def test_rejects_playwright_extra_missing_skipped_failed_and_retry_specs(self) -> None:
        mutations = ("extra", "missing", "skipped", "failed", "retry")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = self.fixture(f"playwright-{mutation}")
                document = fixture.clean_playwright()
                suites = document["suites"]
                assert isinstance(suites, list)
                first_specs = suites[0]["specs"]
                assert isinstance(first_specs, list)
                stats = document["stats"]
                assert isinstance(stats, dict)
                if mutation == "extra":
                    first_specs.append({
                        "title": "unexpected runtime test",
                        "file": "e2e/release-runtime.spec.ts",
                        "ok": True,
                        "tests": [{"expectedStatus": "passed", "status": "expected", "results": [{"status": "passed", "retry": 0}]}],
                    })
                    stats["expected"] = validator.PLAYWRIGHT_TEST_COUNT + 1
                elif mutation == "missing":
                    first_specs.pop()
                    stats["expected"] = validator.PLAYWRIGHT_TEST_COUNT - 1
                elif mutation == "skipped":
                    first_specs[0]["tests"][0]["expectedStatus"] = "skipped"
                    first_specs[0]["tests"][0]["status"] = "skipped"
                    stats["expected"] = validator.PLAYWRIGHT_TEST_COUNT - 1
                    stats["skipped"] = 1
                elif mutation == "failed":
                    first_specs[0]["ok"] = False
                    first_specs[0]["tests"][0]["status"] = "unexpected"
                    first_specs[0]["tests"][0]["results"][0]["status"] = "failed"
                    stats["expected"] = validator.PLAYWRIGHT_TEST_COUNT - 1
                    stats["unexpected"] = 1
                else:
                    first_specs[0]["tests"][0]["results"].append({"status": "passed", "retry": 1})
                fixture.write_playwright(document)
                with self.assertRaises(validator.RuntimeReportValidationError):
                    fixture.create()

    def test_rejects_playwright_wrong_source_top_error_and_duplicate_json_key(self) -> None:
        wrong = self.fixture("wrong-source")
        document = wrong.clean_playwright()
        document["suites"][0]["specs"][0]["file"] = "frontend-quality-runtime.spec.ts"
        wrong.write_playwright(document)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "different test source"):
            wrong.create()

        top_error = self.fixture("top-error")
        document = top_error.clean_playwright()
        document["errors"] = [{"message": "failure"}]
        top_error.write_playwright(document)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "top-level errors"):
            top_error.create()

        duplicate = self.fixture("duplicate-json")
        target = duplicate.evidence / validator.PLAYWRIGHT_REPORT
        payload = target.read_text(encoding="utf-8").replace(
            '"stats":', '"stats":{},"stats":', 1
        )
        duplicate.write_private(validator.PLAYWRIGHT_REPORT, payload)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "duplicate key"):
            duplicate.create()

    def test_playwright_sources_are_resolved_against_fixed_reported_test_dir(self) -> None:
        fixture = self.fixture("real-reporter-paths")
        fixture.create()
        self.assertEqual("PASS", fixture.validate(require_pass=True)["status"])

        escaped = self.fixture("wrong-test-dir")
        document = escaped.clean_playwright()
        config = document["config"]
        assert isinstance(config, dict)
        projects = config["projects"]
        assert isinstance(projects, list)
        projects[0]["testDir"] = str(escaped.repository / "web-starter-web")
        escaped.write_playwright(document)
        with self.assertRaisesRegex(
            validator.RuntimeReportValidationError, "fixed e2e root"
        ):
            escaped.create()

        wrong_root = self.fixture("wrong-root-dir")
        document = wrong_root.clean_playwright()
        config = document["config"]
        assert isinstance(config, dict)
        config["rootDir"] = str(wrong_root.repository / "web-starter-web")
        wrong_root.write_playwright(document)
        with self.assertRaisesRegex(
            validator.RuntimeReportValidationError, "fixed e2e root"
        ):
            wrong_root.create()

    def test_rejects_surefire_wrong_class_method_counts_skip_retry_and_declaration(self) -> None:
        report_name, (test_class, method) = next(iter(validator.SUREFIRE_TESTS.items()))
        cases = {
            "class": Fixture.clean_surefire("example.Wrong", method),
            "method": Fixture.clean_surefire(test_class, "wrongMethod"),
            "count": Fixture.clean_surefire(test_class, method).replace('tests="1"', 'tests="2"'),
            "skip": Fixture.clean_surefire(test_class, method).replace(
                'skipped="0"', 'skipped="1"'
            ).replace("</testsuite>", "<skipped/></testsuite>"),
            "retry": Fixture.clean_surefire(test_class, method).replace(
                "</testsuite>", "<rerunFailure/></testsuite>"
            ),
            "doctype": '<!DOCTYPE testsuite [<!ENTITY x "x">]><testsuite/>',
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                fixture = self.fixture(f"surefire-{label}")
                fixture.write_private(report_name, payload)
                with self.assertRaises(validator.RuntimeReportValidationError):
                    fixture.create()

    def test_rejects_stale_future_extra_missing_symlink_and_unsafe_modes(self) -> None:
        stale = self.fixture("stale")
        target = stale.evidence / validator.PLAYWRIGHT_REPORT
        os.utime(target, ns=(stale.started - 1, stale.started - 1))
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "stale"):
            stale.create()

        stale_surefire = self.fixture("stale-surefire")
        stale_report = stale_surefire.evidence / next(iter(validator.SUREFIRE_TESTS))
        os.utime(
            stale_report,
            ns=(stale_surefire.started - 1, stale_surefire.started - 1),
        )
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "stale"):
            stale_surefire.create()

        future = self.fixture("future")
        target = future.evidence / validator.PLAYWRIGHT_REPORT
        future_time = time.time_ns() + validator.MAX_CLOCK_SKEW_NS + 2_000_000_000
        os.utime(target, ns=(future_time, future_time))
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "future"):
            future.create()

        extra = self.fixture("extra-file")
        extra.write_private("extra-report.xml", "<testsuite/>")
        with self.assertRaisesRegex(producer.RuntimeReportProofError, "only"):
            extra.create()

        missing = self.fixture("missing-file")
        (missing.evidence / validator.PLAYWRIGHT_REPORT).unlink()
        with self.assertRaisesRegex(producer.RuntimeReportProofError, "only"):
            missing.create()

        mode = self.fixture("mode")
        (mode.evidence / validator.PLAYWRIGHT_REPORT).chmod(0o644)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "0600"):
            mode.create()

        linked = self.fixture("symlink")
        original = linked.evidence / "real.json"
        (linked.evidence / validator.PLAYWRIGHT_REPORT).rename(original)
        (linked.evidence / validator.PLAYWRIGHT_REPORT).symlink_to(original.name)
        with self.assertRaises((
            OSError,
            producer.RuntimeReportProofError,
            validator.RuntimeReportValidationError,
        )):
            linked.create()

    def test_rejects_playwright_annotations_errors_stdout_stderr_and_attachments(self) -> None:
        cases = {
            "annotation": ("annotations", [{"type": "skip", "description": "hidden"}]),
            "errors": ("errors", [{"message": "runtime detail"}]),
            "stdout": ("stdout", [{"text": "runtime output"}]),
            "stderr": ("stderr", [{"text": "runtime error output"}]),
            "attachments": ("attachments", [{"name": "trace", "path": "/private/trace.zip"}]),
        }
        for label, (field, value) in cases.items():
            with self.subTest(label=label):
                fixture = self.fixture(f"material-{label}")
                document = fixture.clean_playwright()
                test = document["suites"][0]["specs"][0]["tests"][0]
                if field == "annotations":
                    test[field] = value
                else:
                    test["results"][0][field] = value
                fixture.write_playwright(document)
                with self.assertRaises(validator.RuntimeReportValidationError):
                    fixture.create()

    def test_rejects_wrong_playwright_project_tags_result_annotations_and_steps(self) -> None:
        cases = ("config-project", "test-project", "tags", "result-annotations", "steps")
        for label in cases:
            with self.subTest(label=label):
                fixture = self.fixture(f"playwright-{label}")
                document = fixture.clean_playwright()
                spec = document["suites"][0]["specs"][0]
                test = spec["tests"][0]
                result = test["results"][0]
                if label == "config-project":
                    document["config"]["projects"][0]["name"] = "unexpected"
                elif label == "test-project":
                    test["projectName"] = "unexpected"
                elif label == "tags":
                    spec["tags"] = ["unexpected"]
                elif label == "result-annotations":
                    result["annotations"] = [{"type": "slow"}]
                else:
                    result["steps"] = [{"title": "hidden behavior"}]
                fixture.write_playwright(document)
                with self.assertRaises(validator.RuntimeReportValidationError):
                    fixture.create()

    def test_rejects_self_reported_pass_extra_and_duplicate_proof_keys(self) -> None:
        self_report = self.fixture("self-report")
        self_report.create()
        document = self_report.proof_document()
        document["status"] = "PASS"
        self_report.write_proof_document(document)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "self-reported"):
            self_report.validate()

        duplicate = self.fixture("duplicate-proof")
        duplicate.create()
        target = duplicate.evidence / validator.PROOF_FILE
        payload = target.read_text(encoding="utf-8").replace(
            '"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1', 1
        )
        duplicate.write_private(validator.PROOF_FILE, payload)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "duplicate key"):
            duplicate.validate()

    def test_rejects_forged_report_source_and_candidate_bindings(self) -> None:
        fixture = self.fixture()
        fixture.create()
        cases = (
            ("report", lambda document: document["reports"][validator.PLAYWRIGHT_REPORT].__setitem__("sha256", "0" * 64)),
            ("source", lambda document: document["sources"].__setitem__(validator.ROOT_POM, "0" * 64)),
            ("producer-source", lambda document: document["sources"].__setitem__(
                "scripts/create_release_runtime_test_reports_proof.py", "0" * 64
            )),
            ("validator-source", lambda document: document["sources"].__setitem__(
                "scripts/validate_release_runtime_test_reports_proof.py", "0" * 64
            )),
            ("tree", lambda document: document["candidate"].__setitem__("tree", "0" * 40)),
            ("start", lambda document: document.__setitem__("runStartedAtEpochNs", fixture.started - 1)),
        )
        original = fixture.proof_document()
        for label, mutation in cases:
            with self.subTest(label=label):
                document = json.loads(json.dumps(original))
                mutation(document)
                fixture.write_proof_document(document)
                with self.assertRaises(validator.RuntimeReportValidationError):
                    fixture.validate()
        fixture.write_proof_document(original)

    def test_rejects_expected_identity_mismatch_dirty_lightweight_and_snapshot_candidates(self) -> None:
        fixture = self.fixture("expected")
        fixture.create()
        cases = {
            "commit": {"expected_candidate_commit": "0" * 40},
            "version": {"expected_candidate_version": "2.0.1"},
            "tag": {"expected_candidate_tag": "v2.0.1"},
            "start": {"expected_run_started_at_epoch_ns": fixture.started - 1},
        }
        for label, override in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(validator.RuntimeReportValidationError):
                    fixture.validate(**override)

        dirty = self.fixture("dirty")
        (dirty.repository / "drift.txt").write_text("drift")
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "clean"):
            dirty.create()

        lightweight = self.fixture("lightweight", annotated_tag=False)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "annotated"):
            lightweight.create()

        snapshot = self.fixture("snapshot", version="2.0.0-SNAPSHOT")
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "non-SNAPSHOT"):
            snapshot.create()

    def test_rejects_fixed_test_source_inventory_drift(self) -> None:
        relative = "web-starter-web/e2e/release-runtime.spec.ts"
        fixture = self.fixture(
            "source-drift",
            source_replacements={
                relative: (
                    b"private Web UI performs Project CRUD, trace correlation and responsive rendering",
                    b"different runtime behavior",
                )
            },
        )
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "behavior hash drifted"):
            fixture.create()

    def test_rejects_unchanged_title_or_method_when_reviewed_behavior_body_drifts(self) -> None:
        cases = {
            "playwright-body": (
                "web-starter-web/e2e/release-runtime.spec.ts",
                b"expect(pageErrors).toEqual([])",
                b"expect(pageErrors).toBeDefined()",
            ),
            "java-body": (
                "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java",
                b'assertThat(initialized.protocolVersion()).isEqualTo("2025-11-25");',
                b"assertThat(initialized).isNotNull();",
            ),
        }
        for label, (relative, before, after) in cases.items():
            with self.subTest(label=label):
                fixture = self.fixture(
                    label,
                    source_replacements={relative: (before, after)},
                )
                with self.assertRaisesRegex(
                    validator.RuntimeReportValidationError, "behavior hash drifted"
                ):
                    fixture.create()

    def test_every_reviewed_behavior_hash_rejects_byte_drift(self) -> None:
        payloads = {
            relative: WORKSPACE.joinpath(*relative.split("/")).read_bytes()
            for relative in validator.REVIEWED_BEHAVIOR_SHA256
        }
        validator._validate_fixed_test_sources(payloads)
        for relative in validator.REVIEWED_BEHAVIOR_SHA256:
            with self.subTest(relative=relative):
                drifted = dict(payloads)
                drifted[relative] += b"\n"
                with self.assertRaisesRegex(
                    validator.RuntimeReportValidationError, "behavior hash drifted"
                ):
                    validator._validate_fixed_test_sources(drifted)

    def test_csrf_route_matrix_is_exact_and_rejects_route_or_security_drift(self) -> None:
        relatives = {
            validator.CSRF_ROUTE_MATRIX,
            validator.CSRF_SECURITY_CONFIGURATION,
            *validator.CSRF_CONTROLLER_SOURCES,
        }
        payloads = {
            relative: WORKSPACE.joinpath(*relative.split("/")).read_bytes()
            for relative in relatives
        }
        validator._validate_csrf_route_matrix(payloads)

        missing = dict(payloads)
        document = json.loads(missing[validator.CSRF_ROUTE_MATRIX])
        document["routes"].pop()
        missing[validator.CSRF_ROUTE_MATRIX] = json.dumps(document).encode()
        with self.assertRaisesRegex(
            validator.RuntimeReportValidationError,
            "exactly 36 routes",
        ):
            validator._validate_csrf_route_matrix(missing)

        extra_mapping = dict(payloads)
        controller = validator.CSRF_CONTROLLER_SOURCES[0]
        extra_mapping[controller] += b'\n@PostMapping("/unregistered-csrf-route")\n'
        with self.assertRaisesRegex(
            validator.RuntimeReportValidationError,
            "does not cover every write mapping",
        ):
            validator._validate_csrf_route_matrix(extra_mapping)

        disabled = dict(payloads)
        disabled[validator.CSRF_SECURITY_CONFIGURATION] = disabled[
            validator.CSRF_SECURITY_CONFIGURATION
        ].replace(
            b'.csrf(configurer -> configurer.csrfTokenRepository(csrf))',
            b'.csrf(configurer -> configurer.disable())',
            1,
        )
        with self.assertRaisesRegex(
            validator.RuntimeReportValidationError,
            "security configuration drifted",
        ):
            validator._validate_csrf_route_matrix(disabled)

    def test_rejects_executing_producer_or_validator_source_mismatch(self) -> None:
        cases = {
            "producer": (
                "scripts/create_release_runtime_test_reports_proof.py",
                b"Create the private candidate binding",
                b"Create an altered private candidate binding",
            ),
            "validator": (
                "scripts/validate_release_runtime_test_reports_proof.py",
                b"Validate candidate-bound browser",
                b"Validate altered candidate-bound browser",
            ),
        }
        for label, (relative, before, after) in cases.items():
            with self.subTest(label=label):
                fixture = self.fixture(
                    f"source-mismatch-{label}",
                    source_replacements={relative: (before, after)},
                )
                with self.assertRaisesRegex(
                    (producer.RuntimeReportProofError, validator.RuntimeReportValidationError),
                    "executing .* differs",
                ):
                    fixture.create()

    def test_rejects_report_replacement_and_candidate_drift_during_validation(self) -> None:
        replaced = self.fixture("replace")
        replaced.create()
        original = validator._validate_playwright

        def replace_after_validation(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            target = replaced.evidence / validator.PLAYWRIGHT_REPORT
            payload = target.read_bytes()
            target.unlink()
            target.write_bytes(payload)
            target.chmod(0o600)
            return result

        with mock.patch.object(validator, "_validate_playwright", side_effect=replace_after_validation):
            with self.assertRaisesRegex(validator.RuntimeReportValidationError, "changed"):
                replaced.validate()

        drift = self.fixture("candidate-drift")
        drift.create()

        def dirty_after_validation(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            (drift.repository / "late-drift.txt").write_text("drift")
            return result

        with mock.patch.object(validator, "_validate_playwright", side_effect=dirty_after_validation):
            with self.assertRaisesRegex(validator.RuntimeReportValidationError, "clean"):
                drift.validate()

    def test_sanitizes_git_environment_injection(self) -> None:
        fixture = self.fixture()
        fixture.create()
        ambient = self.root / "ambient.gitconfig"
        ambient.write_text("[core]\n\tfsmonitor = malicious\n")
        replacement = self.root / "replacement-pom.xml"
        replacement.write_text("<project><version>9.9.9</version></project>\n")
        original_blob = git(fixture.repository, "rev-parse", "HEAD:pom.xml")
        replacement_blob = git(fixture.repository, "hash-object", "-w", str(replacement))
        git(fixture.repository, "replace", original_blob, replacement_blob)
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": "/definitely/not/the/candidate",
                "GIT_OBJECT_DIRECTORY": "/definitely/not/objects",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/definitely/not/alternate",
                "GIT_CONFIG_GLOBAL": str(ambient),
                "GIT_CONFIG_SYSTEM": str(ambient),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": "malicious",
            },
            clear=False,
        ):
            summary = fixture.validate(require_pass=True)
        self.assertEqual("PASS", summary["status"])

    def test_validator_recomputes_semantics_after_report_and_proof_are_rebound(self) -> None:
        fixture = self.fixture()
        fixture.create()
        document = fixture.clean_playwright()
        first = document["suites"][0]["specs"][0]
        first["tests"][0]["results"][0]["retry"] = 1
        fixture.write_playwright(document)
        fixture.rebind_report(validator.PLAYWRIGHT_REPORT)
        with self.assertRaisesRegex(validator.RuntimeReportValidationError, "zero-retry"):
            fixture.validate()


if __name__ == "__main__":
    unittest.main()
