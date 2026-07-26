from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import validate_production_fail_fast_evidence as gate


VERSION = "2.0.0"
IMAGE_ID = "sha256:" + "1" * 64
MANIFEST_DIGEST = "sha256:" + "2" * 64
IMAGE_REFERENCE = f"registry.example.invalid/web-starter-app@{MANIFEST_DIGEST}"
RUN_ID = "0123456789ab"


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


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def create_candidate(root: Path) -> Path:
    repository = root / "candidate"
    repository.mkdir()
    git(repository, "init")
    git(repository, "config", "user.name", "Web Starter AC29 Test")
    git(repository, "config", "user.email", "ac29-test@example.invalid")
    workspace = Path(gate.__file__).resolve().parents[1]
    for relative in gate.SOURCE_PATHS:
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == gate.ROOT_POM_PATH:
            path.write_text(
                "<?xml version=\"1.0\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                "<modelVersion>4.0.0</modelVersion><groupId>dev.webstarter</groupId>"
                f"<artifactId>web-starter</artifactId><version>{VERSION}</version></project>\n",
                encoding="utf-8",
            )
        elif relative == gate.ADMIN_POM_PATH:
            path.write_text(
                "<?xml version=\"1.0\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                "<modelVersion>4.0.0</modelVersion><parent><groupId>dev.webstarter</groupId>"
                f"<artifactId>web-starter</artifactId><version>{VERSION}</version></parent>"
                "<artifactId>web-starter-admin</artifactId></project>\n",
                encoding="utf-8",
            )
        elif relative == gate.FRONTEND_MANIFEST_PATH:
            path.write_text(
                json.dumps({"name": "web-starter-web", "version": VERSION}) + "\n",
                encoding="utf-8",
            )
        else:
            path.write_bytes((workspace / relative).read_bytes())
    git(repository, "add", "--all")
    git(repository, "commit", "-m", "AC29 candidate")
    git(repository, "tag", "-a", f"v{VERSION}", "-m", f"release v{VERSION}")
    return repository


def candidate_identity(repository: Path) -> tuple[str, str, str]:
    return (
        git(repository, "rev-parse", "HEAD^{commit}"),
        git(repository, "rev-parse", "HEAD^{tree}"),
        git(repository, "rev-parse", f"refs/tags/v{VERSION}"),
    )


def passing_document(repository: Path) -> dict[str, object]:
    head, tree, tag_object = candidate_identity(repository)
    sources = {
        relative: sha256((repository / relative).read_bytes())
        for relative in gate.SOURCE_PATHS
    }
    cases: list[dict[str, object]] = []
    zero_early = {key: 0 for key in gate.EARLY_MARKER_KEYS}
    for index, (case_id, changed_keys, rejection) in enumerate(gate.EXPECTED_CASES, start=1):
        command = gate._command(
            f"web-starter-ac29-{index:02d}-{RUN_ID}", RUN_ID, IMAGE_ID,
            gate.HARDENED_ENVIRONMENT_KEYS,
        )
        cases.append({
            "case": case_id,
            "changedKeys": sorted(changed_keys),
            "status": "PASS",
            "exitCode": 1,
            "timedOut": False,
            "logBytes": 200,
            "logSha256": f"{index:064x}",
            "commandSha256": gate._canonical_sha256(command),
            "expectedRejectionSha256": sha256((gate.UNSAFE_PREFIX + rejection).encode()),
            "exactRejectionCount": 1,
            "rejectionOffset": 20,
            "infrastructureMarkersBeforeRejection": dict(zero_early),
            "checks": {
                "nonZeroExit": True,
                "completedBeforeTimeout": True,
                "exactRejectionObservedOnce": True,
                "noInfrastructureBeforeRejection": True,
            },
            "failures": [],
        })
    java_command = gate._command(
        f"web-starter-ac29-java-{RUN_ID}", RUN_ID, IMAGE_ID, (),
        entrypoint="java", arguments=("-XshowSettings:properties", "-version"),
    )
    control_command = gate._command(
        f"web-starter-ac29-control-{RUN_ID}", RUN_ID, IMAGE_ID,
        gate.HARDENED_ENVIRONMENT_KEYS,
    )
    database_markers = {key: 0 for key in gate.DATABASE_MARKER_KEYS}
    database_markers["flyway"] = 1
    database_markers["communicationsLinkFailure"] = 1
    return {
        "schemaVersion": 2,
        "acceptanceId": "V2-AC-29",
        "status": "PASS",
        "generatedAt": "2026-07-20T12:00:00Z",
        "candidate": {
            "head": head,
            "tree": tree,
            "tag": f"v{VERSION}",
            "tagObject": tag_object,
            "mavenVersion": VERSION,
            "frontendVersion": VERSION,
            "cleanWorktree": True,
            "sourceSha256": sources,
        },
        "tool": {
            "path": gate.TOOL_PATH,
            "sha256": sources[gate.TOOL_PATH],
            "validatorPath": gate.VALIDATOR_PATH,
            "validatorSha256": sources[gate.VALIDATOR_PATH],
            "schemaPath": gate.SCHEMA_PATH,
            "schemaSha256": sources[gate.SCHEMA_PATH],
        },
        "image": {
            "requestedReference": IMAGE_REFERENCE,
            "id": IMAGE_ID,
            "manifestDigest": MANIFEST_DIGEST,
            "ociVersion": VERSION,
            "ociRevision": head,
            "operatingSystem": "linux",
            "architecture": "amd64",
            "javaHome": "/opt/java/openjdk",
        },
        "javaRuntime": {
            "status": "PASS",
            "imageId": IMAGE_ID,
            "exitCode": 0,
            "timedOut": False,
            "logBytes": 180,
            "logSha256": "a" * 64,
            "commandSha256": gate._canonical_sha256(java_command),
            "specificationVersion": "21",
            "runtimeVersion": "21.0.8+9-LTS",
            "vendor": "Eclipse Adoptium",
            "checks": {
                "exitZero": True,
                "completedBeforeTimeout": True,
                "specificationIs21": True,
                "runtimeVersionIs21": True,
                "identityValuesSanitized": True,
            },
            "failures": [],
        },
        "execution": {
            "runId": RUN_ID,
            "containerCount": 17,
            "dockerNetwork": "none",
            "readOnlyRootFilesystem": True,
            "publishedPorts": 0,
            "hostBindMounts": 0,
            "namedVolumeMounts": 0,
            "tmpfsMountsPerContainer": 1,
            "pullPolicy": "never",
            "dockerLogDriver": "none",
            "immutableImageIdUsed": True,
            "exactOwnershipLabels": True,
            "cleanup": {
                "expectedTargets": 17,
                "cleanupCalls": 17,
                "alreadyAbsentAfterAutoRemove": 17,
                "ownedContainersRemoved": 0,
                "ownershipLabelsVerifiedBeforeRemoval": 0,
                "unownedRemovalAttempts": 0,
                "residualContainers": 0,
                "complete": True,
            },
        },
        "rsa": {"generatedBits": 3072, "persisted": False},
        "dangerousCases": cases,
        "hardenedControl": {
            "case": "hardened-networkless-control",
            "status": "PASS",
            "exitCode": 1,
            "timedOut": False,
            "logBytes": 200,
            "logSha256": "b" * 64,
            "commandSha256": gate._canonical_sha256(control_command),
            "unsafeRejectionCount": 0,
            "databaseMarkers": database_markers,
            "checks": {
                "nonZeroExit": True,
                "completedBeforeTimeout": True,
                "securityValidationPassed": True,
                "databaseFailureObserved": True,
            },
            "failures": [],
        },
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
            "onlyReportAndChecksum": True,
            "rawLogsPersisted": False,
            "fixtureMaterialPersisted": False,
        },
    }


def write_evidence(directory: Path, document: dict[str, object] | None = None, raw: bytes | None = None) -> Path:
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / gate.RESULT_NAME
    content = raw if raw is not None else (
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    path.write_bytes(content)
    path.chmod(0o600)
    checksum = directory / gate.CHECKSUM_NAME
    checksum.write_text(f"{sha256(content)}  {gate.RESULT_NAME}\n", encoding="ascii")
    checksum.chmod(0o600)
    return path


class ProductionFailFastEvidenceValidatorTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-ac29-validator-")
        self.root = Path(self.temporary.name)
        self.repository = create_candidate(self.root)
        self.document = passing_document(self.repository)
        self.evidence = write_evidence(self.root / "evidence", self.document)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self, *, require_pass: bool = True) -> dict[str, object]:
        return gate.validate_evidence(
            self.evidence,
            expected_app_reference=IMAGE_REFERENCE,
            expected_app_image_id=IMAGE_ID,
            repository_root=self.repository,
            require_pass=require_pass,
        )

    def rewrite(self, document: dict[str, object]) -> None:
        self.evidence.unlink()
        (self.evidence.parent / gate.CHECKSUM_NAME).unlink()
        self.evidence = write_evidence(self.evidence.parent, document)

    def test_valid_pass_binds_candidate_image_sources_and_exact_semantics(self) -> None:
        result = self.validate()
        self.assertEqual("PASS", result["status"])
        self.assertEqual(15, result["caseCount"])
        self.assertEqual(len(gate.SOURCE_PATHS), result["sourceCount"])
        self.assertEqual(IMAGE_REFERENCE, result["imageReference"])

    def test_cli_requires_expected_reference_and_image_id(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = gate.main([
                "--evidence", str(self.evidence),
                "--repository-root", str(self.repository),
                "--expected-app-reference", IMAGE_REFERENCE,
                "--expected-app-image-id", IMAGE_ID,
                "--require-pass",
            ])
        self.assertEqual(0, code, stderr.getvalue())
        self.assertEqual("PASS", json.loads(stdout.getvalue())["status"])

    def test_bare_status_pass_self_report_is_rejected(self) -> None:
        self.evidence.unlink()
        (self.evidence.parent / gate.CHECKSUM_NAME).unlink()
        self.evidence = write_evidence(self.evidence.parent, {"status": "PASS"})
        with self.assertRaises(gate.EvidenceValidationError):
            self.validate()

    def test_hash_consistent_semantic_forgery_is_rejected(self) -> None:
        forged = deepcopy(self.document)
        forged["dangerousCases"][0]["checks"]["nonZeroExit"] = False
        self.rewrite(forged)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "independently derived"):
            self.validate()

    def test_candidate_head_tree_and_annotated_tag_are_not_self_asserted(self) -> None:
        for field in ("head", "tree", "tagObject"):
            forged = deepcopy(self.document)
            forged["candidate"][field] = "f" * 40
            self.rewrite(forged)
            with self.assertRaises(gate.EvidenceValidationError):
                self.validate()
            self.rewrite(self.document)
        git(self.repository, "tag", "-d", f"v{VERSION}")
        with self.assertRaises(gate.EvidenceValidationError):
            self.validate()

    def test_source_hash_forgery_is_rejected_even_with_matching_artifact_checksum(self) -> None:
        forged = deepcopy(self.document)
        forged["candidate"]["sourceSha256"][gate.VALIDATOR_JAVA_PATH] = "f" * 64
        self.rewrite(forged)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "source hash is forged"):
            self.validate()

    def test_oci_version_and_revision_must_match_candidate(self) -> None:
        for field, value in (("ociVersion", "2.0.1"), ("ociRevision", "f" * 40)):
            forged = deepcopy(self.document)
            forged["image"][field] = value
            self.rewrite(forged)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "OCI"):
                self.validate()
            self.rewrite(self.document)

    def test_caller_supplied_reference_and_image_id_cannot_be_substituted(self) -> None:
        with self.assertRaisesRegex(gate.EvidenceValidationError, "caller expectation"):
            gate.validate_evidence(
                self.evidence,
                expected_app_reference=(
                    "registry.example.invalid/web-starter-app@sha256:" + "3" * 64
                ),
                expected_app_image_id=IMAGE_ID,
                repository_root=self.repository,
            )
        with self.assertRaisesRegex(gate.EvidenceValidationError, "caller expectation"):
            gate.validate_evidence(
                self.evidence,
                expected_app_reference=IMAGE_REFERENCE,
                expected_app_image_id="sha256:" + "4" * 64,
                repository_root=self.repository,
            )

    def test_permissions_and_exact_two_file_policy_are_enforced(self) -> None:
        self.evidence.chmod(0o640)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "0600"):
            self.validate()
        self.evidence.chmod(0o600)
        self.evidence.parent.chmod(0o750)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "0700"):
            self.validate()
        self.evidence.parent.chmod(0o700)
        extra = self.evidence.parent / "raw.log"
        extra.write_text("not allowed", encoding="utf-8")
        extra.chmod(0o600)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "only report and checksum"):
            self.validate()

    def test_checksum_corruption_is_rejected(self) -> None:
        checksum = self.evidence.parent / gate.CHECKSUM_NAME
        checksum.write_text(f"{'f' * 64}  {gate.RESULT_NAME}\n", encoding="ascii")
        checksum.chmod(0o600)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "checksum"):
            self.validate()

    def test_duplicate_keys_nonfinite_and_secret_shaped_material_are_rejected(self) -> None:
        samples = (
            b'{"status":"PASS","status":"PASS"}\n',
            b'{"value":NaN}\n',
            b'{"password":"do-not-store-this"}\n',
        )
        for raw in samples:
            self.evidence.unlink()
            (self.evidence.parent / gate.CHECKSUM_NAME).unlink()
            self.evidence = write_evidence(self.evidence.parent, raw=raw)
            with self.assertRaises(gate.EvidenceValidationError):
                self.validate()

    def test_untracked_and_hidden_index_state_are_rejected(self) -> None:
        untracked = self.repository / "untracked.txt"
        untracked.write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(gate.EvidenceValidationError, "not clean"):
            self.validate()
        untracked.unlink()
        git(self.repository, "update-index", "--skip-worktree", gate.TOOL_PATH)
        with self.assertRaisesRegex(gate.EvidenceValidationError, "skip-worktree"):
            self.validate()

    def test_report_mutation_during_validation_is_rejected(self) -> None:
        original = gate._validate_report

        def mutate_after_semantics(*args, **kwargs):
            result = original(*args, **kwargs)
            self.evidence.write_bytes(self.evidence.read_bytes() + b" ")
            self.evidence.chmod(0o600)
            return result

        with patch.object(gate, "_validate_report", side_effect=mutate_after_semantics):
            with self.assertRaises(gate.EvidenceValidationError):
                self.validate()

    def test_candidate_source_mutation_during_validation_is_rejected(self) -> None:
        original = gate._validate_report

        def mutate_source_after_semantics(*args, **kwargs):
            result = original(*args, **kwargs)
            source = self.repository / gate.VALIDATOR_JAVA_PATH
            source.write_bytes(source.read_bytes() + b"\n")
            return result

        with patch.object(gate, "_validate_report", side_effect=mutate_source_after_semantics):
            with self.assertRaises(gate.EvidenceValidationError):
                self.validate()

    def test_require_pass_rejects_independently_valid_fail_observation(self) -> None:
        failed = deepcopy(self.document)
        first = failed["dangerousCases"][0]
        first["status"] = "FAIL"
        first["exitCode"] = 0
        first["checks"]["nonZeroExit"] = False
        first["failures"] = ["zeroExit"]
        failed["status"] = "FAIL"
        self.rewrite(failed)
        result = self.validate(require_pass=False)
        self.assertEqual("FAIL", result["status"])
        with self.assertRaises(gate.EvidenceNotPassingError):
            self.validate(require_pass=True)

    def test_schema_is_valid_json_and_tracks_the_exact_source_set(self) -> None:
        schema = json.loads((Path(gate.__file__).resolve().parents[1] / gate.SCHEMA_PATH).read_text())
        source_properties = schema["properties"]["candidate"]["properties"]["sourceSha256"]
        self.assertEqual(set(gate.SOURCE_PATHS), set(source_properties["required"]))
        self.assertEqual(set(gate.SOURCE_PATHS), set(source_properties["properties"]))
        self.assertFalse(source_properties["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
