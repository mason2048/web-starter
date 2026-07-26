from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import create_mcp_tool_contract_runtime_proof as producer
import validate_mcp_tool_contract_runtime_proof as gate


VERSION = "2.0.0"
COMPOSE_PROJECT = "web-starter-release-33"
TRACE_PREFIX = "release-tool-contract"


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


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Fixture:
    def __init__(
        self,
        parent: Path,
        *,
        version: str = VERSION,
        frontend_version: str | None = None,
        annotated_tag: bool = True,
        sdk_dependency: bool = True,
        schema_bytes: bytes | None = None,
        validator_bytes: bytes | None = None,
    ) -> None:
        parent.mkdir(parents=True, exist_ok=True)
        self.parent = parent
        self.repository = parent / "candidate"
        self.repository.mkdir()
        self.version = version
        self.tag = f"v{version}"
        self.compose_project = COMPOSE_PROJECT
        self.trace_prefix = TRACE_PREFIX

        root_pom = (
            "<project><modelVersion>4.0.0</modelVersion>"
            "<groupId>dev.webstarter</groupId><artifactId>web-starter</artifactId>"
            f"<version>{version}</version>"
            "<properties><mcp-sdk.version>2.0.0</mcp-sdk.version></properties>"
            "<dependencyManagement><dependencies><dependency>"
            "<groupId>io.modelcontextprotocol.sdk</groupId><artifactId>mcp-bom</artifactId>"
            "<version>${mcp-sdk.version}</version><type>pom</type><scope>import</scope>"
            "</dependency></dependencies></dependencyManagement>"
            "</project>\n"
        ).encode()
        dependency = (
            "<dependency><groupId>io.modelcontextprotocol.sdk</groupId>"
            "<artifactId>mcp</artifactId></dependency>"
            if sdk_dependency else
            "<dependency><groupId>example.invalid</groupId><artifactId>fake</artifactId></dependency>"
        )
        module_pom = (
            "<project><modelVersion>4.0.0</modelVersion><parent>"
            "<groupId>dev.webstarter</groupId><artifactId>web-starter</artifactId>"
            f"<version>{version}</version></parent>"
            f"<artifactId>web-starter-mcp</artifactId><dependencies>{dependency}</dependencies>"
            "</project>\n"
        ).encode()
        schema = (
            schema_bytes
            if schema_bytes is not None
            else Path(gate.__file__).resolve().parent.parent.joinpath(
                gate.SUMMARY_SCHEMA
            ).read_bytes()
        )
        files: dict[str, bytes] = {
            gate.SOURCE_PATHS["runtimeTestSha256"]: b"// official SDK contract runtime test\n",
            gate.SOURCE_PATHS["expectationsSha256"]: b"// exact seven Tool expectations\n",
            gate.SOURCE_PATHS["catalogSha256"]: b"// output schema and annotations\n",
            gate.SOURCE_PATHS["invocationSha256"]: b"// stable error mapping\n",
            gate.SOURCE_PATHS["rootPomSha256"]: root_pom,
            gate.SOURCE_PATHS["modulePomSha256"]: module_pom,
            gate.SOURCE_PATHS["frontendPackageSha256"]: (
                json.dumps(
                    {"name": "web-starter-web", "version": frontend_version or version},
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            gate.SOURCE_PATHS["producerSha256"]: Path(producer.__file__).read_bytes(),
            gate.SOURCE_PATHS["validatorSha256"]: (
                validator_bytes
                if validator_bytes is not None
                else Path(gate.__file__).read_bytes()
            ),
            gate.SOURCE_PATHS["summarySchemaSha256"]: schema,
        }
        for relative, payload in files.items():
            target = self.repository.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Tool Contract Proof Test")
        git(self.repository, "config", "user.email", "tool-contract@example.invalid")
        git(self.repository, "add", "--all")
        git(self.repository, "commit", "-q", "-m", "candidate")
        self.commit = git(self.repository, "rev-parse", "HEAD^{commit}")
        self.tree = git(self.repository, "rev-parse", "HEAD^{tree}")
        if annotated_tag:
            git(self.repository, "tag", "-a", self.tag, "-m", self.tag)
        else:
            git(self.repository, "tag", self.tag)

        self.evidence_directory = parent / "proof"
        self.evidence_directory.mkdir(mode=0o700)
        self.evidence_directory.chmod(0o700)
        self.report = self.evidence_directory / gate.REPORT_FILE
        self.proof = self.evidence_directory / gate.PROOF_FILE
        self.xml = self.clean_xml()
        self.write_report(self.xml)
        self.started_at = max(1, self.report.stat().st_mtime_ns - 1)
        self.values: dict[str, str] = {
            "schemaVersion": "1",
            "testClass": gate.TEST_CLASS,
            "testMethod": gate.TEST_METHOD,
            "reportFile": gate.REPORT_FILE,
            "reportSha256": digest(self.report.read_bytes()),
            "candidateCommit": self.commit,
            "candidateTree": self.tree,
            "candidateVersion": version,
            "candidateTag": self.tag,
            "composeProject": self.compose_project,
            "tracePrefix": self.trace_prefix,
            "startedAtEpochNs": str(self.started_at),
        }
        for key, relative in gate.SOURCE_PATHS.items():
            self.values[key] = digest(files[relative])
        self.write_proof()

    @staticmethod
    def clean_xml() -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="{gate.TEST_CLASS}" time="0.1" tests="1" '
            'failures="0" errors="0" skipped="0" flakes="0">\n'
            f'  <testcase classname="{gate.TEST_CLASS}" name="{gate.TEST_METHOD}"/>\n'
            '</testsuite>\n'
        )

    def write_report(self, content: str | bytes, *, refresh_hash: bool = False) -> None:
        payload = content if isinstance(content, bytes) else content.encode("utf-8")
        self.report.write_bytes(payload)
        self.report.chmod(0o600)
        if refresh_hash and hasattr(self, "values"):
            self.values["reportSha256"] = digest(payload)
            self.write_proof()

    def write_proof(self, *, order: tuple[str, ...] = gate.PROOF_KEYS) -> None:
        payload = "".join(f"{key}={self.values[key]}\n" for key in order).encode()
        self.proof.write_bytes(payload)
        self.proof.chmod(0o600)

    def kwargs(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "repository_root": self.repository,
            "expected_candidate_commit": self.commit,
            "expected_candidate_version": self.version,
            "expected_candidate_tag": self.tag,
            "expected_compose_project": self.compose_project,
            "expected_trace_prefix": self.trace_prefix,
        }
        values.update(overrides)
        return values

    def validate(self, **overrides: object) -> dict[str, object]:
        return gate.validate_proof(self.proof, **self.kwargs(**overrides))


class McpToolContractRuntimeProofValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, name: str = "fixture", **kwargs: object) -> Fixture:
        return Fixture(self.root / name, **kwargs)

    def assert_rejected(self, fixture: Fixture, fragment: str, **overrides: object) -> None:
        with self.assertRaisesRegex(gate.ProofValidationError, fragment):
            fixture.validate(**overrides)

    def test_accepts_one_exact_candidate_bound_sdk_contract_result(self) -> None:
        fixture = self.fixture()

        summary = fixture.validate(require_pass=True)

        self.assertEqual("PASS", summary["status"])
        self.assertEqual(gate.ACCEPTANCE_ID, summary["acceptanceId"])
        self.assertEqual(fixture.commit, summary["candidate"]["commit"])
        self.assertEqual(list(gate.BASELINE_TOOLS), summary["protocol"]["baselineTools"])
        self.assertEqual("2.0.0", summary["protocol"]["sdkVersion"])
        self.assertEqual(
            ["project.create", "project.update", "project.remove"],
            summary["legacyCompatibility"]["successfulCalls"],
        )
        self.assertEqual(
            set(gate.SOURCE_PATHS.values()), set(summary["sources"])
        )

    def test_writes_only_one_canonical_private_public_summary_after_pass(self) -> None:
        fixture = self.fixture()
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        output.chmod(0o700)

        summary = gate.validate_proof(
            fixture.proof,
            **fixture.kwargs(require_pass=True, summary_output=output),
        )

        artifact = output / gate.SUMMARY_FILE
        self.assertEqual({gate.SUMMARY_FILE}, set(os.listdir(output)))
        self.assertEqual(0o600, stat.S_IMODE(artifact.stat().st_mode))
        self.assertEqual(gate.canonical_summary_bytes(summary), artifact.read_bytes())
        parsed = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertEqual(set(json.loads(
            fixture.repository.joinpath(gate.SUMMARY_SCHEMA).read_text()
        )["required"]), set(parsed))
        self.assertNotIn("token", artifact.read_text(encoding="utf-8").lower())

        with self.assertRaisesRegex(gate.ProofValidationError, "empty"):
            gate.validate_proof(
                fixture.proof,
                **fixture.kwargs(require_pass=True, summary_output=output),
            )

    def test_summary_requires_explicit_require_pass(self) -> None:
        fixture = self.fixture()
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        with self.assertRaisesRegex(gate.ProofValidationError, "requires --require-pass"):
            gate.validate_proof(
                fixture.proof,
                **fixture.kwargs(summary_output=output),
            )

    def test_rejects_wrong_expected_candidate_and_runtime_identity(self) -> None:
        fixture = self.fixture()
        cases = {
            "commit": {"expected_candidate_commit": "0" * 40},
            "version": {"expected_candidate_version": "2.0.1"},
            "tag": {"expected_candidate_tag": "v2.0.1"},
            "project": {"expected_compose_project": "other-stack"},
            "trace": {"expected_trace_prefix": "other-trace"},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                self.assert_rejected(fixture, "does not match|must equal", **overrides)

    def test_rejects_snapshot_lightweight_tag_dirty_or_hidden_index_candidate(self) -> None:
        snapshot = self.fixture("snapshot", version="2.0.0-SNAPSHOT")
        self.assert_rejected(snapshot, "SNAPSHOT")

        lightweight = self.fixture("lightweight", annotated_tag=False)
        self.assert_rejected(lightweight, "annotated")

        dirty = self.fixture("dirty")
        (dirty.repository / "untracked.txt").write_text("drift")
        self.assert_rejected(dirty, "clean")

        hidden = self.fixture("hidden")
        relative = gate.SOURCE_PATHS["runtimeTestSha256"]
        git(hidden.repository, "update-index", "--assume-unchanged", relative)
        self.assert_rejected(hidden, "index contains")

    def test_rejects_proof_schema_encoding_hash_and_source_tampering(self) -> None:
        duplicate = self.fixture("duplicate")
        duplicate.proof.write_bytes(
            duplicate.proof.read_bytes() + f"candidateCommit={duplicate.commit}\n".encode()
        )
        duplicate.proof.chmod(0o600)
        self.assert_rejected(duplicate, "duplicate key")

        reordered = self.fixture("reordered")
        reordered.write_proof(order=tuple(reversed(gate.PROOF_KEYS)))
        self.assert_rejected(reordered, "canonical exact schema")

        invalid = self.fixture("invalid")
        invalid.proof.write_bytes(b"\xff\xfe")
        invalid.proof.chmod(0o600)
        self.assert_rejected(invalid, "valid UTF-8")

        report_hash = self.fixture("report-hash")
        report_hash.values["reportSha256"] = "0" * 64
        report_hash.write_proof()
        self.assert_rejected(report_hash, "report hash")

        source_hash = self.fixture("source-hash")
        source_hash.values["catalogSha256"] = "0" * 64
        source_hash.write_proof()
        self.assert_rejected(source_hash, "source hash")

    def test_rejects_every_nonclean_surefire_counter_and_wrong_identity(self) -> None:
        changes = {
            "tests": ('tests="1"', 'tests="2"'),
            "failures": ('failures="0"', 'failures="1"'),
            "errors": ('errors="0"', 'errors="1"'),
            "skipped": ('skipped="0"', 'skipped="1"'),
            "flakes": ('flakes="0"', 'flakes="1"'),
            "class": (gate.TEST_CLASS, "dev.webstarter.mcp.acceptance.ForgedIT"),
            "method": (gate.TEST_METHOD, "forgedMethod"),
        }
        for name, (old, new) in changes.items():
            with self.subTest(name=name):
                fixture = self.fixture(name)
                fixture.write_report(fixture.xml.replace(old, new), refresh_hash=True)
                self.assert_rejected(fixture, "clean passing|different")

    def test_rejects_retry_flake_declaration_and_stale_report(self) -> None:
        retry = self.fixture("retry")
        retry.write_report(
            retry.xml.replace("/>\n</testsuite>", "><rerunFailure/></testcase>\n</testsuite>"),
            refresh_hash=True,
        )
        self.assert_rejected(retry, "retry, or flake")

        declaration = self.fixture("declaration")
        declaration.write_report(
            '<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
            + declaration.xml,
            refresh_hash=True,
        )
        self.assert_rejected(declaration, "DOCTYPE")

        stale = self.fixture("stale")
        stale.values["startedAtEpochNs"] = str(stale.report.stat().st_mtime_ns + 1)
        stale.write_proof()
        self.assert_rejected(stale, "stale")

        flaky_attribute = self.fixture("flaky-attribute")
        flaky_attribute.write_report(
            flaky_attribute.xml.replace('time="0.1"', 'time="0.1" retryCount="1"'),
            refresh_hash=True,
        )
        self.assert_rejected(flaky_attribute, "retry, or flake")

        nested = self.fixture("nested")
        nested.write_report(
            nested.xml.replace(
                f'  <testcase classname="{gate.TEST_CLASS}" name="{gate.TEST_METHOD}"/>',
                f'  <properties><testcase classname="{gate.TEST_CLASS}" '
                f'name="{gate.TEST_METHOD}"/></properties>',
            ),
            refresh_hash=True,
        )
        self.assert_rejected(nested, "different method")

    @unittest.skipUnless(os.name == "posix", "POSIX permission checks")
    def test_rejects_permissions_extra_files_and_symlink_evidence(self) -> None:
        proof_mode = self.fixture("proof-mode")
        proof_mode.proof.chmod(0o644)
        self.assert_rejected(proof_mode, "0600")

        directory_mode = self.fixture("directory-mode")
        directory_mode.evidence_directory.chmod(0o755)
        self.assert_rejected(directory_mode, "0700")

        extra = self.fixture("extra")
        (extra.evidence_directory / "extra.txt").write_text("unexpected")
        self.assert_rejected(extra, "only proof and report")

        symlink = self.fixture("symlink")
        actual = symlink.evidence_directory / "actual.properties"
        symlink.proof.rename(actual)
        symlink.proof.symlink_to(actual.name)
        self.assert_rejected(symlink, "non-symlink")

    def test_rejects_missing_official_sdk_dependency_version_drift_and_schema_drift(self) -> None:
        sdk = self.fixture("sdk", sdk_dependency=False)
        self.assert_rejected(sdk, "official MCP SDK")

        frontend = self.fixture("frontend", frontend_version="2.0.1")
        self.assert_rejected(frontend, "versions must match")

        schema_document = json.loads(
            Path(gate.__file__).resolve().parent.parent.joinpath(
                gate.SUMMARY_SCHEMA
            ).read_text()
        )
        schema_document["properties"]["status"] = {"const": "VALIDATED"}
        schema = self.fixture(
            "schema",
            schema_bytes=(json.dumps(schema_document, sort_keys=True) + "\n").encode(),
        )
        self.assert_rejected(schema, "schema identity drifted")

    def test_rejects_executing_validator_not_equal_to_candidate_blob(self) -> None:
        fixture = self.fixture("validator", validator_bytes=b"# forged validator\n")
        self.assert_rejected(fixture, "executing Tool contract validator differs")

    def test_rejects_secret_shaped_trace_prefix_before_summary(self) -> None:
        fixture = self.fixture()
        self.assert_rejected(
            fixture,
            "secret-shaped",
            expected_trace_prefix="bearer-trace",
        )

    def test_detects_report_toctou_before_final_summary(self) -> None:
        fixture = self.fixture()
        original = gate._validate_candidate
        calls = 0

        def mutate_on_second(*args: object, **kwargs: object) -> gate.CandidateBinding:
            nonlocal calls
            calls += 1
            if calls == 2:
                fixture.report.write_bytes(fixture.report.read_bytes() + b" ")
                fixture.report.chmod(0o600)
            return original(*args, **kwargs)

        with mock.patch.object(gate, "_validate_candidate", side_effect=mutate_on_second):
            with self.assertRaisesRegex(gate.ProofValidationError, "changed during validation"):
                fixture.validate()

    def test_failed_summary_write_removes_partial_artifact(self) -> None:
        fixture = self.fixture()
        summary = fixture.validate(require_pass=True)
        output = self.root / "partial-summary"
        output.mkdir(mode=0o700)
        output.chmod(0o700)

        with mock.patch.object(gate.os, "write", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                gate._write_summary(output, fixture.repository, summary)

        self.assertEqual([], os.listdir(output))

    def test_producer_creates_private_exact_proof_that_validator_accepts(self) -> None:
        fixture = self.fixture("producer")
        fixture.proof.unlink()
        fixture.started_at = max(1, fixture.report.stat().st_mtime_ns - 1)

        producer.create_proof(
            fixture.repository,
            fixture.report,
            fixture.proof,
            fixture.commit,
            fixture.version,
            fixture.tag,
            fixture.compose_project,
            fixture.trace_prefix,
            fixture.started_at,
        )

        self.assertEqual(0o600, stat.S_IMODE(fixture.proof.stat().st_mode))
        self.assertEqual(
            {gate.PROOF_FILE, gate.REPORT_FILE}, set(os.listdir(fixture.evidence_directory))
        )
        summary = fixture.validate(require_pass=True)
        self.assertEqual("PASS", summary["status"])

    def test_producer_rejects_dirty_candidate_and_nonpassing_report(self) -> None:
        dirty = self.fixture("producer-dirty")
        dirty.proof.unlink()
        (dirty.repository / "untracked.txt").write_text("drift")
        with self.assertRaisesRegex(producer.ProofError, "clean"):
            producer.create_proof(
                dirty.repository, dirty.report, dirty.proof, dirty.commit, dirty.version,
                dirty.tag, dirty.compose_project, dirty.trace_prefix, dirty.started_at,
            )

        failed = self.fixture("producer-failed")
        failed.proof.unlink()
        failed.write_report(failed.xml.replace('failures="0"', 'failures="1"'))
        with self.assertRaisesRegex(producer.ProofError, "clean passing"):
            producer.create_proof(
                failed.repository, failed.report, failed.proof, failed.commit, failed.version,
                failed.tag, failed.compose_project, failed.trace_prefix, failed.started_at,
            )


if __name__ == "__main__":
    unittest.main()
