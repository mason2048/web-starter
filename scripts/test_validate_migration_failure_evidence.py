from __future__ import annotations

import ast
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_validate_v1_upgrade_evidence as ac40_fixture
import validate_migration_failure_evidence as gate
import validate_v1_upgrade_evidence as ac40_validator


RUN_ID = "0123456789ab"
VERSION = "2.0.0"
APP_IMAGE_ID = "sha256:" + "1" * 64
MYSQL_IMAGE_ID = "sha256:" + "2" * 64
REDIS_IMAGE_ID = "sha256:" + "3" * 64
APP_DIGEST = "sha256:" + "4" * 64
APP_REFERENCE = f"registry.example.invalid/web-starter-app@{APP_DIGEST}"


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


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_clean_candidate(root: Path) -> Path:
    repository = root / "candidate"
    repository.mkdir()
    git(repository, "init")
    git(repository, "config", "user.name", "Web Starter Test")
    git(repository, "config", "user.email", "web-starter-test@example.invalid")
    paths = {
        ac40_validator.TOOL_PATH,
        ac40_validator.SCHEMA_PATH,
        *ac40_validator.CURRENT_ADAPTER_FILES,
        *ac40_validator.RUNTIME_SOURCE_FILES,
        *gate.SOURCE_PATHS,
        "pom.xml",
        "web-starter-web/package.json",
    }
    copied = {
        gate.TOOL_PATH,
        gate.SCHEMA_PATH,
        gate.AC40_VALIDATOR_PATH,
    }
    workspace = Path(gate.__file__).resolve().parents[1]
    for relative in sorted(paths):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in copied:
            path.write_bytes((workspace / relative).read_bytes())
        elif relative == ".mvn/wrapper/maven-wrapper.properties":
            path.write_text(
                "wrapperVersion=3.3.4\n"
                "distributionType=only-script\n"
                f"distributionUrl={ac40_fixture.MAVEN_DISTRIBUTION_URL}\n"
                f"distributionSha256Sum={ac40_fixture.SHA256}\n",
                encoding="utf-8",
            )
        elif relative == "pom.xml":
            path.write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>dev.webstarter</groupId><artifactId>web-starter</artifactId>"
                f"<version>{VERSION}</version></project>\n",
                encoding="utf-8",
            )
        elif relative == "web-starter-web/package.json":
            path.write_text(
                json.dumps({"name": "web-starter-web", "version": VERSION}) + "\n",
                encoding="utf-8",
            )
        else:
            path.write_bytes(f"candidate bytes for {relative}\n".encode("utf-8"))
    git(repository, "add", "--all")
    git(repository, "commit", "-m", "test candidate")
    return repository


def write_ac40(directory: Path, document: dict[str, object]) -> Path:
    directory.mkdir(mode=0o700)
    path = directory / "evidence.json"
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def write_ac07(directory: Path, document: dict[str, object]) -> Path:
    directory.mkdir(mode=0o700)
    path = directory / gate.RESULT_NAME
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(serialized, encoding="utf-8")
    path.chmod(0o600)
    checksum = directory / gate.CHECKSUM_NAME
    checksum.write_text(
        f"{sha256_file(path)}  {gate.RESULT_NAME}\n",
        encoding="ascii",
    )
    checksum.chmod(0o600)
    return path


def rewrite_ac07(path: Path, document: dict[str, object]) -> None:
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(serialized, encoding="utf-8")
    path.chmod(0o600)
    checksum = path.with_name(gate.CHECKSUM_NAME)
    checksum.write_text(
        f"{sha256_file(path)}  {gate.RESULT_NAME}\n",
        encoding="ascii",
    )
    checksum.chmod(0o600)


def migration_hash(run_id: str) -> str:
    content = (
        "-- V2-AC-07 isolated intentional failure; never ship this file.\n"
        f"SELECT id FROM ac07_missing_{run_id};\n"
    ).encode("ascii")
    return hashlib.sha256(content).hexdigest()


def ac07_document(repository: Path, ac40_path: Path) -> dict[str, object]:
    head = git(repository, "rev-parse", "HEAD^{commit}")
    tree = git(repository, "rev-parse", "HEAD^{tree}")
    sources = {
        relative: sha256_file(repository / relative)
        for relative in gate.SOURCE_PATHS
    }
    return {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-07",
        "status": "PASS",
        "statusDetail": "COMPLETE",
        "processExitCode": 0,
        "generatedAt": "2026-07-20T00:20:00Z",
        "candidate": {
            "head": head,
            "tree": tree,
            "version": VERSION,
            "cleanWorktree": True,
            "sourceSha256": sources,
        },
        "tool": {
            "path": gate.TOOL_PATH,
            "sha256": sources[gate.TOOL_PATH],
            "evidenceSchemaPath": gate.SCHEMA_PATH,
            "evidenceSchemaSha256": sources[gate.SCHEMA_PATH],
        },
        "failureProtection": {
            "status": "PASS",
            "checks": {name: True for name in gate.FAILURE_CHECKS},
        },
        "recovery": {
            "status": "PASS",
            "statusDetail": "AC40_INDEPENDENT_VALIDATION_PASS",
            "promotionAllowed": True,
            "evidenceSha256": sha256_file(ac40_path),
            "validator": {
                "path": gate.AC40_VALIDATOR_PATH,
                "sha256": sources[gate.AC40_VALIDATOR_PATH],
                "checkCount": 36,
                "acceptanceCount": 5,
                "phaseCount": 10,
            },
        },
        "images": {
            "app": {
                "id": APP_IMAGE_ID,
                "requestedReferenceSha256": hashlib.sha256(
                    APP_REFERENCE.encode("ascii")
                ).hexdigest(),
                "requestedDigest": APP_DIGEST,
                "ociVersion": VERSION,
                "ociRevision": head,
            },
            "mysql": {
                "id": MYSQL_IMAGE_ID,
                "requestedReferenceSha256": hashlib.sha256(b"mysql:8.4").hexdigest(),
            },
            "redis": {
                "id": REDIS_IMAGE_ID,
                "requestedReferenceSha256": hashlib.sha256(b"redis:7.4-alpine").hexdigest(),
            },
        },
        "resources": {
            "prefix": "web-starter-ac07-",
            "runId": RUN_ID,
            "network": f"web-starter-ac07-{RUN_ID}",
            "containers": {
                role: f"web-starter-ac07-{role}-{RUN_ID}"
                for role in gate.IMAGE_ROLES
            },
            "isolation": {
                "internalNetwork": True,
                "publishedHostPorts": 0,
                "dockerVolumeMounts": 0,
                "hostBindMounts": 1,
                "migrationBindReadOnly": True,
                "appRootFilesystemReadOnly": True,
                "immutableImageIds": True,
                "exactOwnershipLabels": True,
            },
            "cleanup": {
                "exactLabelsVerifiedBeforeRemoval": True,
                "removed": {name: True for name in gate.RESOURCE_BOOLEAN_FIELDS},
                "residual": {name: False for name in gate.RESOURCE_BOOLEAN_FIELDS},
                "complete": True,
            },
        },
        "infrastructure": {
            "mysqlReady": True,
            "redisReady": True,
            "probeAttempts": {"mysql": 1, "redis": 1},
            "hostPorts": 0,
            "sharedVolumes": 0,
        },
        "migration": {
            "version": "999999",
            "file": "V999999__ac07_intentional_failure.sql",
            "contentSha256": migration_hash(RUN_ID),
            "temporaryReadOnlyMount": True,
            "persistedAfterRun": False,
            "successfulBaseRows": 7,
            "successfulFailureVersionRows": 0,
            "unsuccessfulFailureVersionRows": 1,
            "totalFailureVersionRows": 1,
            "latestSuccessfulVersion": 7,
        },
        "application": {
            "exitCode": 1,
            "timedOut": False,
            "readinessAttempts": 1,
            "readinessSuccesses": 0,
            "logMarkers": {
                "applicationStarted": 0,
                "intentionalMigrationFailure": 1,
                "unsafeProductionConfiguration": 0,
            },
        },
        "logs": {
            "rawPersisted": False,
            "fixtureMaterialPersisted": False,
            "fixtureLeakDetected": False,
            "app": {"bytes": 120, "sha256": "a" * 64},
            "mysql": {"bytes": 80, "sha256": "b" * 64},
            "redis": {"bytes": 20, "sha256": "c" * 64},
        },
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
        },
    }


@contextmanager
def valid_bundle():
    with tempfile.TemporaryDirectory(prefix="web-starter-ac07-validator-") as temporary:
        root = Path(temporary)
        repository = create_clean_candidate(root)
        ac40_document = ac40_fixture.fixture(completed_non_cleanup_phases=9)
        ac40_fixture.bind_to_candidate(ac40_document, repository)
        ac40_fixture.create_dependency_seed(root, repository, ac40_document)
        ac40_path = write_ac40(root / "ac40", ac40_document)
        document = ac07_document(repository, ac40_path)
        ac07_path = write_ac07(root / "ac07", document)
        yield repository, ac40_path, ac07_path, document


class ValidateMigrationFailureEvidenceTest(unittest.TestCase):
    @staticmethod
    def ac40_seed_inputs(ac40_path: Path) -> tuple[Path, str]:
        document = json.loads(ac40_path.read_text(encoding="utf-8"))
        return (
            ac40_path.parent.parent / "dependency-seed",
            document["source"]["dependencySeed"]["aggregateSha256"],
        )

    def validate_pass(
        self,
        path: Path,
        repository: Path,
        ac40_path: Path,
    ) -> dict[str, object]:
        dependency_seed, expected_seed_sha256 = self.ac40_seed_inputs(ac40_path)
        return gate.validate_document_path(
            path,
            repository_root=repository,
            ac40_evidence_path=ac40_path,
            ac40_dependency_seed=dependency_seed,
            expected_ac40_dependency_seed_sha256=expected_seed_sha256,
            expected_app_image_id=APP_IMAGE_ID,
            expected_mysql_image_id=MYSQL_IMAGE_ID,
            expected_redis_image_id=REDIS_IMAGE_ID,
            expected_app_digest=APP_DIGEST,
            expected_app_reference=APP_REFERENCE,
            require_pass=True,
        )

    def test_pass_binds_private_evidence_candidate_images_and_actual_ac40(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, _document):
            summary = self.validate_pass(path, repository, ac40_path)
            self.assertEqual("PASS", summary["status"])
            self.assertEqual(9, summary["checkCount"])
            output = io.StringIO()
            errors = io.StringIO()
            dependency_seed, expected_seed_sha256 = self.ac40_seed_inputs(ac40_path)
            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = gate.main([
                    "--document", str(path),
                    "--repository-root", str(repository),
                    "--ac40-evidence", str(ac40_path),
                    "--ac40-dependency-seed", str(dependency_seed),
                    "--expected-ac40-dependency-seed-sha256", expected_seed_sha256,
                    "--expected-app-image-id", APP_IMAGE_ID,
                    "--expected-mysql-image-id", MYSQL_IMAGE_ID,
                    "--expected-redis-image-id", REDIS_IMAGE_ID,
                    "--expected-app-reference", APP_REFERENCE,
                    "--require-pass",
                ])
            self.assertEqual(0, exit_code, errors.getvalue())
            self.assertIn("status=PASS", output.getvalue())

    def test_bound_ac40_requires_seed_and_external_trust_anchor(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, _document):
            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "dependency seed and external SHA-256 trust anchor",
            ):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    ac40_evidence_path=ac40_path,
                    expected_app_image_id=APP_IMAGE_ID,
                    expected_mysql_image_id=MYSQL_IMAGE_ID,
                    expected_redis_image_id=REDIS_IMAGE_ID,
                    expected_app_digest=APP_DIGEST,
                    expected_app_reference=APP_REFERENCE,
                    require_pass=True,
                )

    def test_rejects_internally_consistent_forged_source_hashes(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, document):
            forged = "f" * 64
            document["candidate"]["sourceSha256"] = {  # type: ignore[index]
                relative: forged for relative in gate.SOURCE_PATHS
            }
            document["tool"]["sha256"] = forged  # type: ignore[index]
            document["tool"]["evidenceSchemaSha256"] = forged  # type: ignore[index]
            document["recovery"]["validator"]["sha256"] = forged  # type: ignore[index]
            rewrite_ac07(path, document)
            self.assertEqual("PASS", gate.validate_document(document)["status"])
            with self.assertRaisesRegex(gate.EvidenceValidationError, "candidate bytes"):
                self.validate_pass(path, repository, ac40_path)

    def test_rejects_document_or_checksum_tampering(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, _document):
            path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "checksum sibling"):
                self.validate_pass(path, repository, ac40_path)

        with valid_bundle() as (repository, ac40_path, path, _document):
            path.with_name(gate.CHECKSUM_NAME).write_text("0" * 64 + "  wrong.json\n")
            path.with_name(gate.CHECKSUM_NAME).chmod(0o600)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "checksum sibling"):
                self.validate_pass(path, repository, ac40_path)

    def test_rejects_replaced_or_missing_ac40_evidence(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, _document):
            ac40_path.write_text(ac40_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            ac40_path.chmod(0o600)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "recovery.evidenceSha256"):
                self.validate_pass(path, repository, ac40_path)

        with valid_bundle() as (repository, ac40_path, path, document):
            uncovered = ac40_fixture.fixture()
            ac40_path.write_text(json.dumps(uncovered, sort_keys=True) + "\n", encoding="utf-8")
            ac40_path.chmod(0o600)
            document["recovery"]["evidenceSha256"] = sha256_file(ac40_path)  # type: ignore[index]
            rewrite_ac07(path, document)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "recovery summary"):
                self.validate_pass(path, repository, ac40_path)

        with valid_bundle() as (repository, _ac40_path, path, _document):
            with self.assertRaisesRegex(gate.EvidenceValidationError, "actual AC-40 evidence path"):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    expected_app_image_id=APP_IMAGE_ID,
                    expected_mysql_image_id=MYSQL_IMAGE_ID,
                    expected_redis_image_id=REDIS_IMAGE_ID,
                    expected_app_digest=APP_DIGEST,
                    require_pass=True,
                )

    def test_rejects_candidate_identity_and_dirty_worktree(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, document):
            forged_head = "d" * 40
            document["candidate"]["head"] = forged_head  # type: ignore[index]
            document["images"]["app"]["ociRevision"] = forged_head  # type: ignore[index]
            rewrite_ac07(path, document)
            self.assertEqual("PASS", gate.validate_document(document)["status"])
            with self.assertRaisesRegex(gate.EvidenceValidationError, "HEAD/tree"):
                self.validate_pass(path, repository, ac40_path)

        with valid_bundle() as (repository, ac40_path, path, _document):
            (repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(gate.EvidenceValidationError, "not clean"):
                self.validate_pass(path, repository, ac40_path)

    def test_rejects_oci_and_expected_image_id_mismatches(self) -> None:
        with valid_bundle() as (_repository, _ac40_path, _path, document):
            document["images"]["app"]["ociVersion"] = "2.0.1"  # type: ignore[index]
            with self.assertRaisesRegex(gate.EvidenceValidationError, "OCI version"):
                gate.validate_document(document)

        with valid_bundle() as (repository, ac40_path, path, _document):
            with self.assertRaisesRegex(gate.EvidenceValidationError, "expected image ID"):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    ac40_evidence_path=ac40_path,
                    expected_app_image_id="sha256:" + "9" * 64,
                )

        with valid_bundle() as (_repository, _ac40_path, _path, document):
            with self.assertRaisesRegex(gate.EvidenceValidationError, "manifest digest"):
                gate.validate_document(
                    document,
                    expected_app_digest="sha256:" + "8" * 64,
                )
            with self.assertRaisesRegex(gate.EvidenceValidationError, "Reference|reference"):
                gate.validate_document(
                    document,
                    expected_app_reference=(
                        f"mirror.example.invalid/web-starter-app@{APP_DIGEST}"
                    ),
                )

    def test_require_pass_requires_all_independent_release_image_inputs(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, _document):
            with self.assertRaisesRegex(gate.EvidenceValidationError, "release inputs"):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    ac40_evidence_path=ac40_path,
                    require_pass=True,
                )

    def test_rejects_consistent_looking_semantic_forgeries(self) -> None:
        mutations = (
            ("check", lambda document: document["failureProtection"]["checks"].update(  # type: ignore[index]
                {"intentionalMigrationFailureObserved": False}
            )),
            ("status", lambda document: document.update({"processExitCode": 1})),
            ("cleanup", lambda document: document["resources"]["cleanup"]["residual"].update(  # type: ignore[index]
                {"app": True}
            )),
            ("isolation", lambda document: document["resources"]["isolation"].update(  # type: ignore[index]
                {"publishedHostPorts": 1}
            )),
            ("boolean-as-integer", lambda document: document["infrastructure"].update(  # type: ignore[index]
                {"hostPorts": False}
            )),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), valid_bundle() as (
                _repository, _ac40_path, _path, original,
            ):
                document = deepcopy(original)
                mutate(document)
                with self.assertRaises(gate.EvidenceValidationError):
                    gate.validate_document(document)

    def test_rejects_unknown_or_missing_fields_and_extra_evidence_siblings(self) -> None:
        with valid_bundle() as (_repository, _ac40_path, _path, document):
            document["invented"] = True
            with self.assertRaisesRegex(gate.EvidenceValidationError, "unknown=invented"):
                gate.validate_document(document)

        with valid_bundle() as (_repository, _ac40_path, _path, document):
            del document["application"]["logMarkers"]  # type: ignore[index]
            with self.assertRaisesRegex(gate.EvidenceValidationError, "missing=logMarkers"):
                gate.validate_document(document)

        with valid_bundle() as (repository, ac40_path, path, _document):
            extra = path.parent / "unbound.txt"
            extra.write_text("not part of evidence\n", encoding="utf-8")
            extra.chmod(0o600)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "contain only"):
                self.validate_pass(path, repository, ac40_path)

    def test_rejects_unsafe_modes_and_secret_shaped_material(self) -> None:
        with valid_bundle() as (repository, ac40_path, path, _document):
            path.chmod(0o644)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "mode 0600"):
                self.validate_pass(path, repository, ac40_path)

        with valid_bundle() as (repository, ac40_path, path, _document):
            path.parent.chmod(0o755)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "mode 0700"):
                self.validate_pass(path, repository, ac40_path)

        with valid_bundle() as (_repository, _ac40_path, _path, document):
            document["recovery"] = {
                "status": "NOT_COVERED",
                "statusDetail": "AC40_EVIDENCE_NOT_SUPPLIED",
                "promotionAllowed": False,
                "reason": "password=not-a-real-secret",
            }
            document.update({
                "status": "NOT_COVERED",
                "statusDetail": "PENDING_AC40",
                "processExitCode": 6,
            })
            with self.assertRaisesRegex(gate.EvidenceValidationError, "secret-shaped"):
                gate.validate_document(document)

    def test_valid_non_pass_is_accepted_unless_require_pass_is_set(self) -> None:
        with valid_bundle() as (repository, _ac40_path, path, document):
            document["recovery"] = {
                "status": "NOT_COVERED",
                "statusDetail": "AC40_EVIDENCE_NOT_SUPPLIED",
                "promotionAllowed": False,
                "reason": "No AC-40 result was supplied",
            }
            document.update({
                "status": "NOT_COVERED",
                "statusDetail": "PENDING_AC40",
                "processExitCode": 6,
            })
            rewrite_ac07(path, document)

            summary = gate.validate_document_path(path, repository_root=repository)
            self.assertEqual("NOT_COVERED", summary["status"])
            with self.assertRaises(gate.EvidenceNotPassingError):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    expected_app_image_id=APP_IMAGE_ID,
                    expected_mysql_image_id=MYSQL_IMAGE_ID,
                    expected_redis_image_id=REDIS_IMAGE_ID,
                    expected_app_digest=APP_DIGEST,
                    require_pass=True,
                )

            output = io.StringIO()
            errors = io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                permissive = gate.main([
                    "--document", str(path),
                    "--repository-root", str(repository),
                ])
                strict = gate.main([
                    "--document", str(path),
                    "--repository-root", str(repository),
                    "--expected-app-image-id", APP_IMAGE_ID,
                    "--expected-mysql-image-id", MYSQL_IMAGE_ID,
                    "--expected-redis-image-id", REDIS_IMAGE_ID,
                    "--expected-app-digest", APP_DIGEST,
                    "--require-pass",
                ])
            self.assertEqual(0, permissive)
            self.assertEqual(6, strict)

    def test_implementation_is_stdlib_only_and_does_not_import_the_producer(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertNotIn("import rehearse_migration_failure", source)
        self.assertNotIn("jsonschema", source)
        self.assertEqual(
            {
                "__future__", "argparse", "datetime", "hashlib", "json", "os",
                "pathlib", "re", "stat", "subprocess", "sys", "typing",
                "validate_v1_upgrade_evidence", "xml",
            },
            imported,
        )


if __name__ == "__main__":
    unittest.main()
