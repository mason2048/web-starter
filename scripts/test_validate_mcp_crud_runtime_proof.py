from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import validate_mcp_crud_runtime_proof as gate


VERSION = "2.0.0"
COMPOSE_PROJECT = "web-starter-release-17"
TRACE_PREFIX = "release-sdk-crud"


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
        trace_prefix: str = TRACE_PREFIX,
        annotated_tag: bool = True,
        validator_bytes: bytes | None = None,
    ) -> None:
        parent.mkdir(parents=True, exist_ok=True)
        self.parent = parent
        self.repository = parent / "candidate"
        self.repository.mkdir()
        self.version = version
        self.tag = f"v{version}"
        self.compose_project = COMPOSE_PROJECT
        self.trace_prefix = trace_prefix

        files = {
            gate.TEST_SOURCE: b"// official SDK CRUD runtime acceptance source\n",
            gate.ROOT_POM: (
                "<project><modelVersion>4.0.0</modelVersion>"
                f"<groupId>dev.webstarter</groupId><artifactId>web-starter</artifactId>"
                f"<version>{version}</version></project>\n"
            ).encode(),
            gate.MODULE_POM: (
                "<project><modelVersion>4.0.0</modelVersion><parent>"
                "<groupId>dev.webstarter</groupId><artifactId>web-starter</artifactId>"
                f"<version>{version}</version></parent>"
                "<artifactId>web-starter-mcp</artifactId></project>\n"
            ).encode(),
            gate.FRONTEND_PACKAGE: (
                json.dumps(
                    {"name": "web-starter-web", "version": frontend_version or version},
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            gate.PRODUCER_SOURCE: Path(
                gate.__file__
            ).with_name("create_mcp_crud_runtime_proof.py").read_bytes(),
            gate.VALIDATOR_SOURCE: (
                validator_bytes if validator_bytes is not None else Path(gate.__file__).read_bytes()
            ),
            gate.RUNNER_SOURCE: b"#!/usr/bin/env bash\n# isolated AC-16 transaction runner\n",
            gate.PROJECT_SERVICE_SOURCE: b"// transactional project service\n",
            gate.MCP_INVOCATION_SOURCE: b"// shared MCP invocation transaction\n",
            gate.MCP_FAILURE_AUDIT_SOURCE: b"// requires-new failure audit\n",
            gate.MCP_TOOL_SUPPORT_SOURCE: b"// structured MCP error support\n",
            gate.AUDIT_RECORDER_SOURCE: b"// operation and MCP audit recorder\n",
            gate.SUMMARY_SCHEMA_SOURCE: b'{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n',
        }
        for relative, payload in files.items():
            target = self.repository.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Web Starter Proof Test")
        git(self.repository, "config", "user.email", "proof-test@example.invalid")
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
        self.transaction_receipt = self.evidence_directory / gate.TRANSACTION_RECEIPT_FILE
        self.proof = self.evidence_directory / gate.PROOF_FILE
        self.xml = self.clean_xml()
        self.write_report(self.xml)
        self.write_transaction_receipt(self.clean_transaction_receipt())
        self.values: dict[str, str] = {
            "schemaVersion": "2",
            "testClass": gate.TEST_CLASS,
            "testMethod": gate.TEST_METHOD,
            "sourcePath": gate.TEST_SOURCE,
            "sourceSha256": digest(files[gate.TEST_SOURCE]),
            "rootPomPath": gate.ROOT_POM,
            "rootPomSha256": digest(files[gate.ROOT_POM]),
            "modulePomPath": gate.MODULE_POM,
            "modulePomSha256": digest(files[gate.MODULE_POM]),
            "reportFile": gate.REPORT_FILE,
            "reportSha256": digest(self.report.read_bytes()),
            "transactionReceiptFile": gate.TRANSACTION_RECEIPT_FILE,
            "transactionReceiptSha256": digest(self.transaction_receipt.read_bytes()),
            "candidateCommit": self.commit,
            "candidateTree": self.tree,
            "candidateVersion": version,
            "candidateTag": self.tag,
            "composeProject": self.compose_project,
            "tracePrefix": trace_prefix,
            "startedAtEpochNs": "1",
        }
        self.write_proof()

    @staticmethod
    def clean_xml() -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="{gate.TEST_CLASS}" time="0.1" tests="1" '
            'failures="0" errors="0" skipped="0" flakes="0">\n'
            f'  <testcase classname="{gate.TEST_CLASS}" name="{gate.TEST_METHOD}"/>\n'
            "</testsuite>\n"
        )

    def clean_transaction_receipt(self) -> str:
        values = (
            ("schemaVersion", "1"),
            ("databaseName", "web_starter"),
            ("constraintName", gate.TRANSACTION_CONSTRAINT),
            ("failureTrace", f"{self.trace_prefix}-transaction-audit-failure"),
            ("failureProjectCode", gate.TRANSACTION_PROJECT_CODE),
            (
                "failureIdempotencyKeyHash",
                digest(gate.TRANSACTION_IDEMPOTENCY_KEY.encode("utf-8")),
            ),
            ("successTrace", f"{self.trace_prefix}-create-first"),
            ("constraintRowsDuringFault", "1"),
            ("constraintRowsAfterCleanup", "0"),
            ("failedProjectRows", "0"),
            ("failedOperationAuditRows", "0"),
            ("failedMcpAuditRows", "1"),
            ("failedMcpAuditExpectedRows", "1"),
            ("failedIdempotencyRows", "0"),
            ("successBusinessOperationMcpRows", "1"),
            ("transactionalTableRows", "4"),
        )
        return "".join(f"{key}={value}\n" for key, value in values)

    def write_report(self, content: str | bytes, *, refresh_hash: bool = False) -> None:
        payload = content if isinstance(content, bytes) else content.encode("utf-8")
        self.report.write_bytes(payload)
        self.report.chmod(0o600)
        if refresh_hash and hasattr(self, "values"):
            self.values["reportSha256"] = digest(payload)
            self.write_proof()

    def write_transaction_receipt(
        self, content: str | bytes, *, refresh_hash: bool = False
    ) -> None:
        payload = content if isinstance(content, bytes) else content.encode("utf-8")
        self.transaction_receipt.write_bytes(payload)
        self.transaction_receipt.chmod(0o600)
        if refresh_hash and hasattr(self, "values"):
            self.values["transactionReceiptSha256"] = digest(payload)
            self.write_proof()

    def write_proof(self) -> None:
        payload = "".join(f"{key}={value}\n" for key, value in self.values.items())
        self.proof.write_text(payload, encoding="utf-8")
        self.proof.chmod(0o600)

    def kwargs(self, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "repository_root": self.repository,
            "expected_candidate_commit": self.commit,
            "expected_candidate_version": self.version,
            "expected_candidate_tag": self.tag,
            "expected_compose_project": self.compose_project,
            "expected_trace_prefix": self.trace_prefix,
        }
        result.update(overrides)
        return result

    def validate(self, **overrides: object) -> dict[str, object]:
        return gate.validate_proof(self.proof, **self.kwargs(**overrides))


class McpCrudRuntimeProofValidatorTest(unittest.TestCase):
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

    def test_canonical_summary_schema_freezes_ac16_and_idempotency_checks(self) -> None:
        schema = json.loads(
            (Path(gate.__file__).resolve().parents[1] / gate.SUMMARY_SCHEMA_SOURCE).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
        )
        self.assertEqual(
            ["AC-16", "V2-AC-31", "V2-AC-32"],
            schema["properties"]["acceptanceIds"]["const"],
        )
        self.assertEqual(
            {
                "businessTransactionRollback",
                "failedMcpAuditPersists",
                "faultInjectionCleaned",
                "idempotencyReservationRollback",
                "officialSdkRuntime",
                "successBusinessAuditAtomicity",
                "transactionalStorage",
            },
            set(schema["properties"]["checks"]["required"]),
        )

    def test_accepts_exact_single_run_proof_and_binds_all_candidate_sources(self) -> None:
        fixture = self.fixture()

        summary = fixture.validate(require_pass=True)

        self.assertEqual("PASS", summary["status"])
        self.assertEqual(["AC-16", "V2-AC-31", "V2-AC-32"], summary["acceptanceIds"])
        self.assertEqual(fixture.commit, summary["candidate"]["commit"])
        self.assertEqual(gate.TEST_CLASS, summary["test"]["class"])
        self.assertEqual(gate.TEST_METHOD, summary["test"]["method"])
        self.assertEqual(set(gate.BOUND_SOURCE_PATHS), set(summary["sources"]))
        self.assertEqual(digest(fixture.proof.read_bytes()), summary["evidence"]["proofSha256"])
        self.assertEqual(digest(fixture.report.read_bytes()), summary["evidence"]["reportSha256"])
        self.assertEqual(
            digest(fixture.transaction_receipt.read_bytes()),
            summary["evidence"]["transactionReceiptSha256"],
        )
        self.assertEqual(
            {
                "businessTransactionRollback",
                "failedMcpAuditPersists",
                "faultInjectionCleaned",
                "idempotencyReservationRollback",
                "officialSdkRuntime",
                "successBusinessAuditAtomicity",
                "transactionalStorage",
            },
            set(summary["checks"]),
        )

    def test_rejects_hash_consistent_forged_ac16_transaction_observations(self) -> None:
        mutations = {
            "project-not-rolled-back": ("failedProjectRows=0", "failedProjectRows=1"),
            "operation-audit-remained": (
                "failedOperationAuditRows=0",
                "failedOperationAuditRows=1",
            ),
            "failure-audit-missing": ("failedMcpAuditRows=1", "failedMcpAuditRows=0"),
            "failure-audit-wrong": (
                "failedMcpAuditExpectedRows=1",
                "failedMcpAuditExpectedRows=0",
            ),
            "reservation-remained": (
                "failedIdempotencyRows=0",
                "failedIdempotencyRows=1",
            ),
            "success-not-atomic": (
                "successBusinessOperationMcpRows=1",
                "successBusinessOperationMcpRows=0",
            ),
            "constraint-not-cleaned": (
                "constraintRowsAfterCleanup=0",
                "constraintRowsAfterCleanup=1",
            ),
            "nontransactional-table": ("transactionalTableRows=4", "transactionalTableRows=3"),
        }
        for name, (before, after) in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture(name)
                fixture.write_transaction_receipt(
                    fixture.clean_transaction_receipt().replace(before, after),
                    refresh_hash=True,
                )
                self.assert_rejected(fixture, "does not prove the required value")

    def test_rejects_duplicate_extra_invalid_utf8_and_oversized_properties(self) -> None:
        duplicate = self.fixture("duplicate")
        duplicate.proof.write_bytes(
            duplicate.proof.read_bytes() + f"candidateCommit={duplicate.commit}\n".encode()
        )
        duplicate.proof.chmod(0o600)
        self.assert_rejected(duplicate, "duplicate key")

        extra = self.fixture("extra")
        extra.values["selfReportedStatus"] = "PASS"
        extra.write_proof()
        self.assert_rejected(extra, "exact schema")

        invalid = self.fixture("invalid-utf8")
        invalid.proof.write_bytes(b"\xff\xfe")
        invalid.proof.chmod(0o600)
        self.assert_rejected(invalid, "valid UTF-8")

        oversized = self.fixture("oversized")
        oversized.proof.write_bytes(b"x" * (gate.MAX_PROOF_BYTES + 1))
        oversized.proof.chmod(0o600)
        self.assert_rejected(oversized, "size")

    def test_rejects_hash_consistent_forged_report_and_proof(self) -> None:
        fixture = self.fixture()
        forged_class = "dev.webstarter.mcp.acceptance.ForgedRuntimeIT"
        forged = fixture.xml.replace(gate.TEST_CLASS, forged_class)
        fixture.write_report(forged, refresh_hash=True)

        self.assert_rejected(fixture, "different test suite")

    def test_rejects_wrong_class_method_and_every_nonclean_counter(self) -> None:
        changes = {
            "wrong-class": (gate.TEST_CLASS, "dev.webstarter.mcp.acceptance.OtherRuntimeIT"),
            "wrong-method": (gate.TEST_METHOD, "differentMethod"),
            "tests": ('tests="1"', 'tests="2"'),
            "failures": ('failures="0"', 'failures="1"'),
            "errors": ('errors="0"', 'errors="1"'),
            "skipped": ('skipped="0"', 'skipped="1"'),
            "flakes": ('flakes="0"', 'flakes="1"'),
        }
        for name, (old, new) in changes.items():
            with self.subTest(name=name):
                fixture = self.fixture(name)
                fixture.write_report(fixture.xml.replace(old, new), refresh_hash=True)
                self.assert_rejected(fixture, "different|clean passing")

    def test_rejects_retry_flaky_doctype_and_external_entity_evidence(self) -> None:
        retry = self.fixture("retry")
        retry.write_report(
            retry.xml.replace("</testcase>", "</testcase>")
            .replace("/>\n</testsuite>", "><rerunFailure/></testcase>\n</testsuite>"),
            refresh_hash=True,
        )
        self.assert_rejected(retry, "retry, or flake")

        flaky = self.fixture("flaky")
        flaky.write_report(
            flaky.xml.replace("/>\n</testsuite>", "><flakyFailure/></testcase>\n</testsuite>"),
            refresh_hash=True,
        )
        self.assert_rejected(flaky, "retry, or flake")

        retry_attribute = self.fixture("retry-attribute")
        retry_attribute.write_report(
            retry_attribute.xml.replace("<testcase ", '<testcase retryCount="1" '),
            refresh_hash=True,
        )
        self.assert_rejected(retry_attribute, "retry, or flake")

        nested_suite = self.fixture("nested-suite")
        nested_suite.write_report(
            nested_suite.xml.replace(
                "</testsuite>",
                '<testsuite name="hidden" tests="0" failures="0" errors="0" '
                'skipped="0" flakes="0"/></testsuite>',
            ),
            refresh_hash=True,
        )
        self.assert_rejected(nested_suite, "exactly one test suite")

        doctype = self.fixture("doctype")
        doctype.write_report(
            doctype.xml.replace(
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE testsuite>',
            ),
            refresh_hash=True,
        )
        self.assert_rejected(doctype, "DOCTYPE or entity")

        entity = self.fixture("entity")
        entity.write_report(
            entity.xml.replace(
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            ),
            refresh_hash=True,
        )
        self.assert_rejected(entity, "DOCTYPE or entity")

    def test_rejects_source_hash_drift_even_when_proof_is_rehashed(self) -> None:
        fixture = self.fixture()
        changed = b"// changed after candidate commit\n"
        source = fixture.repository / gate.TEST_SOURCE
        source.write_bytes(changed)
        fixture.values["sourceSha256"] = digest(changed)
        fixture.write_proof()

        self.assert_rejected(fixture, "worktree must be clean")

    def test_rejects_dirty_untracked_and_hidden_index_states(self) -> None:
        dirty = self.fixture("dirty")
        (dirty.repository / gate.ROOT_POM).write_text("<project/>\n")
        self.assert_rejected(dirty, "worktree must be clean")

        untracked = self.fixture("untracked")
        (untracked.repository / "untracked.txt").write_text("not candidate material\n")
        self.assert_rejected(untracked, "worktree must be clean")

        hidden = self.fixture("hidden")
        git(hidden.repository, "update-index", "--assume-unchanged", gate.TEST_SOURCE)
        self.assert_rejected(hidden, "Git index contains")

        skipped = self.fixture("skipped")
        git(skipped.repository, "update-index", "--skip-worktree", gate.TEST_SOURCE)
        self.assert_rejected(skipped, "Git index contains")

    def test_rejects_clean_head_and_tree_drift_after_proof_creation(self) -> None:
        fixture = self.fixture()
        tracked = fixture.repository / gate.TEST_SOURCE
        tracked.write_text("// a different clean candidate\n")
        git(fixture.repository, "add", gate.TEST_SOURCE)
        git(fixture.repository, "commit", "-q", "-m", "move candidate")

        self.assert_rejected(fixture, "Git HEAD does not equal")

    def test_rejects_candidate_identity_and_expected_runtime_mismatches(self) -> None:
        fixture = self.fixture()
        self.assert_rejected(
            fixture,
            "candidateCommit does not match",
            expected_candidate_commit="b" * 40,
        )
        self.assert_rejected(
            fixture,
            "candidateVersion does not match",
            expected_candidate_version="2.0.1",
            expected_candidate_tag="v2.0.1",
        )
        self.assert_rejected(
            fixture,
            "composeProject does not match",
            expected_compose_project="different-project",
        )
        self.assert_rejected(
            fixture,
            "tracePrefix does not match",
            expected_trace_prefix="different-trace",
        )

    def test_rejects_snapshot_frontend_drift_and_lightweight_tag(self) -> None:
        snapshot = self.fixture("snapshot", version="2.0.0-SNAPSHOT")
        self.assert_rejected(snapshot, "must not be a SNAPSHOT")

        frontend = self.fixture("frontend", frontend_version="2.0.1")
        self.assert_rejected(frontend, "versions must match")

        lightweight = self.fixture("lightweight", annotated_tag=False)
        self.assert_rejected(lightweight, "annotated Git tag")

    def test_rejects_uncommitted_or_nonexecuting_validator_source(self) -> None:
        fake_validator = self.fixture("fake-validator", validator_bytes=b"# forged validator\n")
        self.assert_rejected(fake_validator, "executing MCP CRUD validator differs")

        missing_producer = self.fixture("missing-producer")
        producer = missing_producer.repository / gate.PRODUCER_SOURCE
        producer.unlink()
        self.assert_rejected(missing_producer, "worktree must be clean")

    def test_rejects_nonprivate_symlink_and_additional_evidence_files(self) -> None:
        broad_file = self.fixture("broad-file")
        broad_file.report.chmod(0o644)
        self.assert_rejected(broad_file, "mode 0600")

        broad_receipt = self.fixture("broad-receipt")
        broad_receipt.transaction_receipt.chmod(0o644)
        self.assert_rejected(broad_receipt, "mode 0600")

        broad_directory = self.fixture("broad-directory")
        broad_directory.evidence_directory.chmod(0o755)
        self.assert_rejected(broad_directory, "mode 0700")

        symlink = self.fixture("symlink")
        real = symlink.parent / "real-proof.properties"
        real.write_bytes(symlink.proof.read_bytes())
        real.chmod(0o600)
        symlink.proof.unlink()
        symlink.proof.symlink_to(real)
        self.assert_rejected(symlink, "non-symlink")

        hardlink = self.fixture("hardlink")
        original = hardlink.parent / "hardlinked-proof.properties"
        hardlink.proof.replace(original)
        os.link(original, hardlink.proof)
        self.assert_rejected(hardlink, "regular mode 0600")

        extra = self.fixture("extra-file")
        attachment = extra.evidence_directory / "notes.txt"
        attachment.write_text("self-reported PASS\n")
        attachment.chmod(0o600)
        self.assert_rejected(extra, "only the proof, report, and AC-16 receipt")

    def test_rejects_proof_and_report_toctou_replacements(self) -> None:
        report = self.fixture("report-toctou")
        original = gate._validate_versions

        def mutate_report(binding: gate.CandidateBinding, version: str) -> None:
            original(binding, version)
            report.write_report(report.xml.replace('time="0.1"', 'time="0.2"'))

        with mock.patch.object(gate, "_validate_versions", side_effect=mutate_report):
            self.assert_rejected(report, "Surefire report changed")

        proof = self.fixture("proof-toctou")

        def mutate_proof(binding: gate.CandidateBinding, version: str) -> None:
            original(binding, version)
            proof.proof.write_bytes(proof.proof.read_bytes() + b"\n")
            proof.proof.chmod(0o600)

        with mock.patch.object(gate, "_validate_versions", side_effect=mutate_proof):
            self.assert_rejected(proof, "proof changed")

        receipt = self.fixture("receipt-toctou")

        def mutate_receipt(binding: gate.CandidateBinding, version: str) -> None:
            original(binding, version)
            receipt.write_transaction_receipt(
                receipt.clean_transaction_receipt().replace(
                    "failedProjectRows=0", "failedProjectRows=1"
                )
            )

        with mock.patch.object(gate, "_validate_versions", side_effect=mutate_receipt):
            self.assert_rejected(receipt, "transaction receipt changed")

    def test_writes_one_canonical_private_secret_free_summary_only_after_pass(self) -> None:
        fixture = self.fixture()
        output = self.root / "artifact"
        output.mkdir(mode=0o700)
        output.chmod(0o700)

        summary = fixture.validate(require_pass=True, summary_output=output)

        summary_path = output / gate.SUMMARY_FILE
        self.assertEqual(0o600, summary_path.stat().st_mode & 0o777)
        expected = (
            json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        self.assertEqual(expected, summary_path.read_bytes())
        self.assertNotRegex(summary_path.read_text(), gate.SECRET_PATTERN)

    def test_rejects_summary_overwrite_nonempty_directory_and_secret_shaped_value(self) -> None:
        fixture = self.fixture("overwrite")
        output = self.root / "artifact-overwrite"
        output.mkdir(mode=0o700)
        output.chmod(0o700)
        fixture.validate(require_pass=True, summary_output=output)
        with self.assertRaisesRegex(gate.ProofValidationError, "never overwritten"):
            fixture.validate(require_pass=True, summary_output=output)

        no_require = self.fixture("no-require")
        empty = self.root / "artifact-no-require"
        empty.mkdir(mode=0o700)
        empty.chmod(0o700)
        with self.assertRaisesRegex(gate.ProofValidationError, "requires --require-pass"):
            no_require.validate(summary_output=empty)
        self.assertEqual([], list(empty.iterdir()))

        secret = self.fixture("secret", trace_prefix="release-secret-token")
        secret_output = self.root / "artifact-secret"
        secret_output.mkdir(mode=0o700)
        secret_output.chmod(0o700)
        with self.assertRaisesRegex(gate.ProofValidationError, "secret-shaped"):
            secret.validate(require_pass=True, summary_output=secret_output)
        self.assertEqual([], list(secret_output.iterdir()))

        unsafe_target = self.root / "real-summary-directory"
        unsafe_target.mkdir(mode=0o700)
        unsafe_target.chmod(0o700)
        unsafe_link = self.root / "summary-directory-link"
        unsafe_link.symlink_to(unsafe_target, target_is_directory=True)
        with self.assertRaisesRegex(gate.ProofValidationError, "non-symlink"):
            fixture.validate(require_pass=True, summary_output=unsafe_link)

    def test_cli_requires_all_expected_bindings_and_emits_summary(self) -> None:
        fixture = self.fixture()
        output = self.root / "cli-artifact"
        output.mkdir(mode=0o700)
        output.chmod(0o700)
        exit_code = gate.main([
            "--repository-root",
            str(fixture.repository),
            "--proof",
            str(fixture.proof),
            "--expected-candidate-commit",
            fixture.commit,
            "--expected-candidate-version",
            fixture.version,
            "--expected-candidate-tag",
            fixture.tag,
            "--expected-compose-project",
            fixture.compose_project,
            "--expected-trace-prefix",
            fixture.trace_prefix,
            "--require-pass",
            "--summary-output",
            str(output),
        ])
        self.assertEqual(0, exit_code)
        self.assertTrue((output / gate.SUMMARY_FILE).is_file())


if __name__ == "__main__":
    unittest.main()
