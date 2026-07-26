from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import create_project_transport_parity_proof as producer
from scripts import validate_project_transport_parity_proof as validator


VERSION = "2.0.0"


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


def root_pom(version: str) -> bytes:
    return (
        '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<modelVersion>4.0.0</modelVersion><groupId>dev.webstarter</groupId>'
        f'<artifactId>web-starter</artifactId><version>{version}</version></project>\n'
    ).encode()


def module_pom(version: str, artifact: str, dependencies: tuple[str, ...] = ()) -> bytes:
    dependency_xml = "".join(
        "<dependency><groupId>dev.webstarter</groupId>"
        f"<artifactId>{dependency}</artifactId><version>${{project.version}}</version>"
        "</dependency>"
        for dependency in dependencies
    )
    return (
        '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<modelVersion>4.0.0</modelVersion><parent><groupId>dev.webstarter</groupId>'
        f'<artifactId>web-starter</artifactId><version>{version}</version></parent>'
        f'<artifactId>{artifact}</artifactId><dependencies>{dependency_xml}</dependencies>'
        '</project>\n'
    ).encode()


def admin_pom(version: str, report_property: str | None = None) -> bytes:
    report_property = report_property or "${project.build.directory}/surefire-reports"
    return (
        '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<modelVersion>4.0.0</modelVersion><parent><groupId>dev.webstarter</groupId>'
        f'<artifactId>web-starter</artifactId><version>{version}</version></parent>'
        '<artifactId>web-starter-admin</artifactId>'
        '<properties><web-starter.admin.surefire-reports-directory>'
        f'{report_property}'
        '</web-starter.admin.surefire-reports-directory></properties>'
        '<dependencies>'
        '<dependency><groupId>dev.webstarter</groupId><artifactId>web-starter-project</artifactId>'
        '<version>${project.version}</version></dependency>'
        '<dependency><groupId>dev.webstarter</groupId><artifactId>web-starter-mcp</artifactId>'
        '<version>${project.version}</version></dependency>'
        '</dependencies><build><plugins><plugin><groupId>org.apache.maven.plugins</groupId>'
        '<artifactId>maven-surefire-plugin</artifactId><configuration><reportsDirectory>'
        '${web-starter.admin.surefire-reports-directory}'
        '</reportsDirectory></configuration></plugin></plugins></build></project>\n'
    ).encode()


class Fixture:

    def __init__(
        self,
        parent: Path,
        *,
        version: str = VERSION,
        report_property: str | None = None,
        test_payload: bytes | None = None,
        validator_payload: bytes | None = None,
        schema_payload: bytes | None = None,
    ) -> None:
        self.workspace = Path(__file__).resolve().parents[1]
        self.repository = parent / "candidate"
        self.repository.mkdir(parents=True)
        self.version = version
        self.tag = f"v{version}"
        files: dict[str, bytes] = {}
        for relative in validator.SOURCE_PATHS.values():
            if relative == validator.SOURCE_PATHS["rootPomSha256"]:
                payload = root_pom(version)
            elif relative == validator.SOURCE_PATHS["projectPomSha256"]:
                payload = module_pom(version, "web-starter-project")
            elif relative == validator.SOURCE_PATHS["mcpPomSha256"]:
                payload = module_pom(
                    version,
                    "web-starter-mcp",
                    ("web-starter-project",),
                )
            elif relative == validator.SOURCE_PATHS["adminPomSha256"]:
                payload = admin_pom(version, report_property)
            elif relative == validator.SOURCE_PATHS["integrationTestSha256"] \
                    and test_payload is not None:
                payload = test_payload
            elif relative == validator.SOURCE_PATHS["validatorSha256"] \
                    and validator_payload is not None:
                payload = validator_payload
            elif relative == validator.SOURCE_PATHS["summarySchemaSha256"] \
                    and schema_payload is not None:
                payload = schema_payload
            else:
                payload = self.workspace.joinpath(*relative.split("/")).read_bytes()
            files[relative] = payload
            target = self.repository.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "AC-15 Evidence Test")
        git(self.repository, "config", "user.email", "ac15@example.invalid")
        git(self.repository, "add", "--all")
        git(self.repository, "commit", "-q", "-m", "candidate")
        self.commit = git(self.repository, "rev-parse", "HEAD^{commit}")
        self.tree = git(self.repository, "rev-parse", "HEAD^{tree}")
        git(self.repository, "tag", "-a", self.tag, "-m", self.tag)

        self.evidence = parent / "proof"
        self.evidence.mkdir(mode=0o700)
        self.evidence.chmod(0o700)
        self.report = self.evidence / validator.REPORT_FILE
        self.report.write_text(self.clean_xml(), encoding="utf-8")
        self.report.chmod(0o600)
        self.started_at = max(1, self.report.stat().st_mtime_ns - 1)
        self.proof = self.evidence / validator.PROOF_FILE
        producer.create_proof(
            self.repository,
            self.report,
            self.proof,
            self.commit,
            version,
            self.tag,
            self.started_at,
        )
        self.values = self.read_values()

    @staticmethod
    def clean_xml() -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="{validator.TEST_CLASS}" time="0.1" tests="1" '
            'failures="0" errors="0" skipped="0" flakes="0">\n'
            f'  <testcase classname="{validator.TEST_CLASS}" '
            f'name="{validator.TEST_METHOD}"/>\n'
            '</testsuite>\n'
        )

    def read_values(self) -> dict[str, str]:
        return dict(
            line.split("=", 1)
            for line in self.proof.read_text(encoding="utf-8").splitlines()
        )

    def write_proof(self, order: tuple[str, ...] = validator.PROOF_KEYS) -> None:
        self.proof.write_text(
            "".join(f"{key}={self.values[key]}\n" for key in order),
            encoding="utf-8",
        )
        self.proof.chmod(0o600)

    def write_report(self, content: str, *, refresh_hash: bool = True) -> None:
        self.report.write_text(content, encoding="utf-8")
        self.report.chmod(0o600)
        if refresh_hash:
            self.values["reportSha256"] = digest(self.report.read_bytes())
            self.write_proof()

    def kwargs(self, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "repository_root": self.repository,
            "expected_candidate_commit": self.commit,
            "expected_candidate_version": self.version,
            "expected_candidate_tag": self.tag,
        }
        result.update(overrides)
        return result

    def validate(self, **overrides: object) -> dict[str, object]:
        return validator.validate_proof(self.proof, **self.kwargs(**overrides))


class ProjectTransportParityEvidenceTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, name: str = "fixture", **kwargs: object) -> Fixture:
        return Fixture(self.root / name, **kwargs)

    def assert_rejected(self, fixture: Fixture, fragment: str, **overrides: object) -> None:
        with self.assertRaisesRegex(validator.ProofValidationError, fragment):
            fixture.validate(**overrides)

    def test_accepts_exact_candidate_bound_transport_parity_result(self) -> None:
        fixture = self.fixture()

        summary = fixture.validate(require_pass=True)

        self.assertEqual("PASS", summary["status"])
        self.assertEqual("AC-15", summary["acceptanceId"])
        self.assertEqual(fixture.commit, summary["candidate"]["commit"])
        self.assertEqual(list(validator.ADAPTER_CLASSES), summary["springContext"]["adapters"])
        self.assertTrue(summary["springContext"]["sharedBeanIdentity"])
        self.assertEqual(
            "dev.webstarter.project.service.impl.ProjectServiceImpl",
            summary["springContext"]["sharedServiceImplementation"],
        )
        self.assertEqual(1, summary["persistenceBoundary"]["projectMapperBeans"])
        self.assertEqual(1, summary["persistenceBoundary"]["projectServiceImplBeans"])
        self.assertEqual(0, summary["persistenceBoundary"]["adapterProjectMapperDependencies"])
        self.assertEqual(
            set(validator.SOURCE_PATHS.values()),
            set(summary["sources"]),
        )

    def test_writes_one_canonical_private_summary_only_with_require_pass(self) -> None:
        fixture = self.fixture()
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        output.chmod(0o700)

        with self.assertRaisesRegex(validator.ProofValidationError, "requires --require-pass"):
            fixture.validate(summary_output=output)

        summary = fixture.validate(require_pass=True, summary_output=output)
        artifact = output / validator.SUMMARY_FILE
        self.assertEqual({validator.SUMMARY_FILE}, set(os.listdir(output)))
        self.assertEqual(0o600, stat.S_IMODE(artifact.stat().st_mode))
        self.assertEqual(validator.canonical_summary_bytes(summary), artifact.read_bytes())
        self.assertEqual("AC-15", json.loads(artifact.read_text())["acceptanceId"])

    def test_rejects_wrong_expected_candidate_identity(self) -> None:
        fixture = self.fixture()
        cases = {
            "commit": {"expected_candidate_commit": "0" * 40},
            "version": {"expected_candidate_version": "2.0.1"},
            "tag": {"expected_candidate_tag": "v2.0.1"},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                self.assert_rejected(fixture, "does not match|must equal", **overrides)

    def test_rejects_dirty_lightweight_and_hidden_index_candidate(self) -> None:
        dirty = self.fixture("dirty")
        (dirty.repository / "untracked.txt").write_text("drift")
        self.assert_rejected(dirty, "clean")

        lightweight = self.fixture("lightweight")
        git(lightweight.repository, "tag", "-d", lightweight.tag)
        git(lightweight.repository, "tag", lightweight.tag)
        self.assert_rejected(lightweight, "annotated")

        hidden = self.fixture("hidden")
        git(
            hidden.repository,
            "update-index",
            "--assume-unchanged",
            validator.SOURCE_PATHS["integrationTestSha256"],
        )
        self.assert_rejected(hidden, "index contains")

    def test_producer_rejects_snapshot_and_fixed_test_source_drift(self) -> None:
        with self.assertRaisesRegex(producer.ProofError, "non-SNAPSHOT"):
            self.fixture("snapshot", version="2.0.0-SNAPSHOT")

        original = Path(__file__).resolve().parents[1].joinpath(
            *validator.SOURCE_PATHS["integrationTestSha256"].split("/")
        ).read_bytes()
        with self.assertRaisesRegex(producer.ProofError, "fixed integration test source"):
            self.fixture("test-drift", test_payload=original + b"\n")

    def test_rejects_proof_schema_hash_and_order_tampering(self) -> None:
        duplicate = self.fixture("duplicate")
        duplicate.proof.write_bytes(
            duplicate.proof.read_bytes() + f"candidateCommit={duplicate.commit}\n".encode()
        )
        duplicate.proof.chmod(0o600)
        self.assert_rejected(duplicate, "duplicate key")

        reordered = self.fixture("reordered")
        reordered.write_proof(tuple(reversed(validator.PROOF_KEYS)))
        self.assert_rejected(reordered, "canonical exact schema")

        report_hash = self.fixture("report-hash")
        report_hash.values["reportSha256"] = "0" * 64
        report_hash.write_proof()
        self.assert_rejected(report_hash, "report hash")

        source_hash = self.fixture("source-hash")
        source_hash.values["mcpToolCatalogSha256"] = "0" * 64
        source_hash.write_proof()
        self.assert_rejected(source_hash, "source hash mismatch")

    def test_rejects_every_nonclean_surefire_counter_class_and_method(self) -> None:
        changes = {
            "tests": ('tests="1"', 'tests="2"'),
            "failures": ('failures="0"', 'failures="1"'),
            "errors": ('errors="0"', 'errors="1"'),
            "skipped": ('skipped="0"', 'skipped="1"'),
            "flakes": ('flakes="0"', 'flakes="1"'),
            "class": (validator.TEST_CLASS, "dev.webstarter.admin.acceptance.ForgedIT"),
            "method": (validator.TEST_METHOD, "forgedMethod"),
        }
        for name, (old, new) in changes.items():
            with self.subTest(name=name):
                fixture = self.fixture(name)
                fixture.write_report(fixture.clean_xml().replace(old, new))
                self.assert_rejected(fixture, "exactly one clean passing test")

    def test_rejects_retry_declaration_stale_report_and_extra_file(self) -> None:
        retry = self.fixture("retry")
        retry.write_report(
            retry.clean_xml().replace(
                "/>\n</testsuite>",
                "><rerunFailure/></testcase>\n</testsuite>",
            )
        )
        self.assert_rejected(retry, "retry, or flake")

        declaration = self.fixture("declaration")
        declaration.write_report(
            '<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
            + declaration.clean_xml()
        )
        self.assert_rejected(declaration, "DOCTYPE")

        stale = self.fixture("stale")
        stale.values["startedAtEpochNs"] = str(stale.report.stat().st_mtime_ns + 1)
        stale.write_proof()
        self.assert_rejected(stale, "stale")

        extra = self.fixture("extra")
        (extra.evidence / "unexpected.txt").write_text("extra")
        (extra.evidence / "unexpected.txt").chmod(0o600)
        self.assert_rejected(extra, "only proof and report")

    def test_rejects_nonprivate_files_and_invalid_pom_semantics(self) -> None:
        wrong_mode = self.fixture("wrong-mode")
        wrong_mode.report.chmod(0o644)
        self.assert_rejected(wrong_mode, "mode 0600")

        bad_property = self.fixture(
            "bad-property",
            report_property="${project.build.directory}/untrusted-reports",
        )
        self.assert_rejected(bad_property, "report directory property drifted")

    def test_rejects_candidate_validator_and_schema_source_drift(self) -> None:
        fake_validator = self.fixture(
            "fake-validator",
            validator_payload=b"# different validator\n",
        )
        self.assert_rejected(fake_validator, "executing AC-15 validator differs")

        schema = json.loads(
            Path(__file__).resolve().parents[1].joinpath(validator.SUMMARY_SCHEMA)
            .read_text(encoding="utf-8")
        )
        schema["properties"]["acceptanceId"]["const"] = "AC-99"
        schema_payload = (json.dumps(schema, sort_keys=True) + "\n").encode()
        bad_schema = self.fixture("bad-schema", schema_payload=schema_payload)
        self.assert_rejected(bad_schema, "PASS identity drifted")

    def test_git_helpers_ignore_ambient_repository_object_and_config_injection(self) -> None:
        fixture = self.fixture("ambient-git")
        poison = {
            "GIT_DIR": str(self.root / "poison-git-dir"),
            "GIT_COMMON_DIR": str(self.root / "poison-common-dir"),
            "GIT_WORK_TREE": str(self.root / "poison-work-tree"),
            "GIT_INDEX_FILE": str(self.root / "poison-index"),
            "GIT_OBJECT_DIRECTORY": str(self.root / "poison-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.root / "poison-alternates"),
            "GIT_CONFIG_GLOBAL": str(self.root / "poison-global-config"),
            "GIT_CONFIG_SYSTEM": str(self.root / "poison-system-config"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
        }
        with patch.dict(os.environ, poison, clear=False):
            self.assertEqual(
                fixture.commit,
                producer._git_text(fixture.repository, "rev-parse", "HEAD^{commit}"),
            )
            self.assertEqual(
                fixture.commit,
                validator._git_text(fixture.repository, "rev-parse", "HEAD^{commit}"),
            )
            self.assertEqual("PASS", fixture.validate(require_pass=True)["status"])

            for environment in (
                producer._git_environment(),
                validator._git_environment(),
            ):
                self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
                self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
                self.assertEqual(os.devnull, environment["GIT_CONFIG_SYSTEM"])
                self.assertEqual("0", environment["GIT_CONFIG_COUNT"])
                self.assertEqual("1", environment["GIT_NO_REPLACE_OBJECTS"])
                self.assertNotIn("GIT_DIR", environment)
                self.assertNotIn("GIT_OBJECT_DIRECTORY", environment)
                self.assertNotIn("GIT_ALTERNATE_OBJECT_DIRECTORIES", environment)
                self.assertNotIn("GIT_CONFIG_KEY_0", environment)
                self.assertNotIn("GIT_CONFIG_VALUE_0", environment)

    def test_git_helpers_ignore_replace_object_injection(self) -> None:
        fixture = self.fixture("replace-object")
        controller = fixture.repository.joinpath(
            *validator.SOURCE_PATHS["projectControllerSha256"].split("/")
        )
        controller.write_bytes(controller.read_bytes() + b"\n// replacement object\n")
        git(fixture.repository, "add", "--all")
        git(fixture.repository, "commit", "-q", "-m", "replacement")
        replacement_commit = git(fixture.repository, "rev-parse", "HEAD^{commit}")
        git(fixture.repository, "reset", "--hard", fixture.commit)
        git(fixture.repository, "replace", fixture.commit, replacement_commit)

        ambient_tree = git(fixture.repository, "rev-parse", "HEAD^{tree}")
        self.assertNotEqual(fixture.tree, ambient_tree)
        self.assertEqual(
            fixture.tree,
            producer._git_text(fixture.repository, "rev-parse", "HEAD^{tree}"),
        )
        self.assertEqual(
            fixture.tree,
            validator._git_text(fixture.repository, "rev-parse", "HEAD^{tree}"),
        )
        self.assertEqual("PASS", fixture.validate(require_pass=True)["status"])


if __name__ == "__main__":
    unittest.main()
