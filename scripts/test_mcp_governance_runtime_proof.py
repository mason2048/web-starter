from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Mapping
from unittest import mock

from scripts import create_mcp_governance_runtime_proof as producer
from scripts import validate_mcp_governance_runtime_proof as validator


WORKSPACE_ROOT = Path(validator.__file__).resolve().parent.parent


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Fixture:
    VERSION = "2.0.0"
    TAG = "v2.0.0"
    PROJECT = "web-starter-proof"
    TRACE = "governance-proof"
    APP_IMAGE_ID = "sha256:" + "b" * 64
    APP_REFERENCE = "example.invalid/web-starter@sha256:" + "c" * 64
    NGINX_IMAGE_ID = "sha256:" + "d" * 64
    NGINX_REFERENCE = "example.invalid/web-starter-nginx@sha256:" + "a" * 64
    REDIS_IMAGE_ID = "sha256:" + "e" * 64
    REDIS_REFERENCE = "redis@sha256:" + "f" * 64

    def __init__(
        self,
        root: Path,
        *,
        produce: bool = True,
        annotated_tag: bool = True,
        validator_bytes: bytes | None = None,
        schema_bytes: bytes | None = None,
        source_overrides: Mapping[str, bytes] | None = None,
    ) -> None:
        self.root = root
        self.repository = root / "repo"
        self.raw = root / "raw"
        self.repository.mkdir(parents=True)
        self.raw.mkdir(mode=0o700)
        self.raw.chmod(0o700)
        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Acceptance Test")
        git(self.repository, "config", "user.email", "acceptance@example.invalid")

        actual_validator = Path(validator.__file__).read_bytes()
        actual_schema = WORKSPACE_ROOT.joinpath(validator.SUMMARY_SCHEMA).read_bytes()
        real_source_paths = {
            *validator.REVIEWED_BEHAVIOR_SHA256,
            validator.SOURCE_PATHS["producerSha256"],
            validator.SOURCE_PATHS["restartOrchestratorSha256"],
        }
        overrides = dict(source_overrides or {})
        for relative in validator.SOURCE_PATHS.values():
            path = self.repository.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "pom.xml":
                payload = (
                    "<project><version>2.0.0</version><properties>"
                    "<mcp-sdk.version>2.0.0</mcp-sdk.version>"
                    "</properties></project>\n"
                ).encode()
            elif relative == "web-starter-mcp/pom.xml":
                payload = (
                    "<project><dependencies><dependency>"
                    "<groupId>io.modelcontextprotocol.sdk</groupId>"
                    "<artifactId>mcp</artifactId>"
                    "</dependency></dependencies></project>\n"
                ).encode()
            elif relative == "web-starter-web/package.json":
                payload = b'{"name":"web-starter-web","version":"2.0.0"}\n'
            elif relative == validator.SOURCE_PATHS["validatorSha256"]:
                payload = actual_validator if validator_bytes is None else validator_bytes
            elif relative == validator.SUMMARY_SCHEMA:
                payload = actual_schema if schema_bytes is None else schema_bytes
            elif relative in overrides:
                payload = overrides[relative]
            elif relative in real_source_paths:
                payload = WORKSPACE_ROOT.joinpath(*relative.split("/")).read_bytes()
            else:
                payload = f"fixture source for {relative}\n".encode()
            path.write_bytes(payload)

        git(self.repository, "add", ".")
        git(self.repository, "commit", "-q", "-m", "candidate")
        if annotated_tag:
            git(self.repository, "tag", "-a", self.TAG, "-m", "candidate tag")
        else:
            git(self.repository, "tag", self.TAG)
        self.commit = git(self.repository, "rev-parse", "HEAD^{commit}")
        self.tree = git(self.repository, "rev-parse", "HEAD^{tree}")

        now = time.time_ns()
        self.main_started = now - 5_000_000_000
        self.created_ms = (now - 3_000_000_000) // 1_000_000
        self.restart_started = now - 2_000_000_000
        self.main_report = self.raw / validator.MAIN_REPORT
        self.shutdown_report = self.raw / validator.SHUTDOWN_REPORT
        self.state = self.raw / validator.STATE_FILE
        self.receipt = self.raw / validator.RESTART_RECEIPT
        self.proof = self.raw / validator.PROOF_FILE
        self.main_report.write_text(self.xml(validator.MAIN_TEST_CLASS, validator.MAIN_TEST_METHOD))
        self.state.write_text(self.state_text())
        for path in (self.main_report, self.state):
            path.chmod(0o600)
        state_ns = self.created_ms * 1_000_000
        os.utime(self.state, ns=(state_ns, state_ns))
        self.receipt.write_bytes(self.receipt_bytes())
        self.receipt.chmod(0o600)
        receipt_ns = self.restart_started + 800_000_000
        os.utime(self.receipt, ns=(receipt_ns, receipt_ns))
        self.shutdown_report.write_text(
            self.xml(validator.SHUTDOWN_TEST_CLASS, validator.SHUTDOWN_TEST_METHOD))
        self.shutdown_report.chmod(0o600)
        if produce:
            self.produce()

    @staticmethod
    def xml(test_class: str, method: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="{test_class}" tests="1" failures="0" '
            'errors="0" skipped="0" flakes="0">\n'
            f'  <testcase classname="{test_class}" name="{method}"/>\n'
            '</testsuite>\n'
        )

    def state_text(self, **changes: object) -> str:
        values: dict[str, object] = {
            "schemaVersion": 1,
            "sessionId": "session-acceptance-1234",
            "createdAtEpochMillis": self.created_ms,
            "tracePrefix": self.TRACE,
            "expectedIdleTtlSeconds": 50,
            "expectedAbsoluteTtlSeconds": 60,
        }
        values.update(changes)
        return "".join(f"{key}={value}\n" for key, value in values.items())

    def receipt_document(self) -> dict[str, object]:
        stop_requested = self.restart_started + 100_000_000
        stop_completed = self.restart_started + 300_000_000
        start_requested = self.restart_started + 400_000_000
        healthy = self.restart_started + 700_000_000
        app_container = "a" * 64
        app_image = self.APP_IMAGE_ID
        app_reference = self.APP_REFERENCE

        def timestamp(epoch_ns: int) -> str:
            seconds, nanoseconds = divmod(epoch_ns, 1_000_000_000)
            prefix = datetime.fromtimestamp(seconds, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
            return f"{prefix}.{nanoseconds:09d}Z"

        return {
            "schemaVersion": 1,
            "status": "PASS",
            "producerSha256": digest(
                self.repository.joinpath(
                    *validator.SOURCE_PATHS["restartOrchestratorSha256"].split("/")
                ).read_bytes()
            ),
            "candidate": {"version": self.VERSION, "gitCommit": self.commit},
            "runtime": {"composeProject": self.PROJECT, "tracePrefix": self.TRACE},
            "gracefulRestart": {
                "signal": "SIGTERM",
                "configuredStopSignal": "DOCKER_DEFAULT_SIGTERM",
                "timeoutSeconds": 40,
                "stopCommandExitCode": 0,
                "old": {
                    "containerId": app_container,
                    "imageId": app_image,
                    "imageReference": app_reference,
                    "pid": 101,
                    "startedAt": timestamp(self.main_started - 2_000_000_000),
                    "restartCount": 0,
                },
                "stopped": {
                    "containerId": app_container,
                    "exitCode": 0,
                    "oomKilled": False,
                    "dead": False,
                    "finishedAt": timestamp(stop_completed),
                },
                "new": {
                    "containerId": app_container,
                    "imageId": app_image,
                    "imageReference": app_reference,
                    "pid": 202,
                    "startedAt": timestamp(start_requested + 100_000_000),
                    "restartCount": 0,
                },
                "health": "healthy",
            },
            "redisContinuity": {
                "containerId": "d" * 64,
                "imageId": self.REDIS_IMAGE_ID,
                "imageReference": self.REDIS_REFERENCE,
                "pid": 303,
                "startedAt": timestamp(self.main_started - 3_000_000_000),
                "restartCount": 0,
                "dataVolumeNameSha256": "1" * 64,
                "markerSurvived": True,
                "markerTtlSecondsAfterRestart": 170,
            },
            "ingressContinuity": {
                "services": {
                    "nginx": {
                        "containerId": "2" * 64,
                        "imageId": self.NGINX_IMAGE_ID,
                        "imageReference": self.NGINX_REFERENCE,
                        "pid": 404,
                        "startedAt": timestamp(self.main_started - 4_000_000_000),
                        "restartCount": 0,
                    },
                    "mcp-public-nginx": {
                        "containerId": "3" * 64,
                        "imageId": self.NGINX_IMAGE_ID,
                        "imageReference": self.NGINX_REFERENCE,
                        "pid": 505,
                        "startedAt": timestamp(self.main_started - 4_000_000_000),
                        "restartCount": 0,
                    },
                },
                "healthyAfterRestart": True,
                "unchangedAcrossAppRestart": True,
            },
            "shutdownProbeState": {
                "file": validator.STATE_FILE,
                "sha256": digest(self.state.read_bytes()),
                "createdAtEpochMillis": self.created_ms,
                "modifiedAtEpochNs": self.state.stat().st_mtime_ns,
            },
            "timing": {
                "stopRequestedAtEpochNs": stop_requested,
                "stopCompletedAtEpochNs": stop_completed,
                "startRequestedAtEpochNs": start_requested,
                "healthyAtEpochNs": healthy,
            },
        }

    def receipt_bytes(self, document: dict[str, object] | None = None) -> bytes:
        value = self.receipt_document() if document is None else document
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()

    def produce(self) -> None:
        producer.create_proof(
            self.repository,
            self.raw,
            self.proof,
            self.commit,
            self.VERSION,
            self.TAG,
            self.PROJECT,
            self.TRACE,
            self.main_started,
            self.restart_started,
        )

    def kwargs(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "repository_root": self.repository,
            "expected_candidate_commit": self.commit,
            "expected_candidate_version": self.VERSION,
            "expected_candidate_tag": self.TAG,
            "expected_compose_project": self.PROJECT,
            "expected_trace_prefix": self.TRACE,
            "expected_app_reference": self.APP_REFERENCE,
            "expected_app_image_id": self.APP_IMAGE_ID,
            "expected_nginx_reference": self.NGINX_REFERENCE,
            "expected_nginx_image_id": self.NGINX_IMAGE_ID,
            "expected_redis_reference": self.REDIS_REFERENCE,
            "expected_redis_image_id": self.REDIS_IMAGE_ID,
        }
        values.update(overrides)
        return values

    def validate(self, **overrides: object) -> dict[str, object]:
        return validator.validate_proof(self.proof, **self.kwargs(**overrides))

    def proof_values(self) -> dict[str, str]:
        return dict(line.split("=", 1) for line in self.proof.read_text().splitlines())

    def write_proof(self, values: dict[str, str], order: tuple[str, ...] = validator.PROOF_KEYS) -> None:
        self.proof.write_text("".join(f"{key}={values[key]}\n" for key in order))
        self.proof.chmod(0o600)

    def rewrite_report(self, path: Path, payload: str) -> None:
        path.write_text(payload)
        path.chmod(0o600)
        values = self.proof_values()
        key = "mainReportSha256" if path == self.main_report else "shutdownReportSha256"
        values[key] = digest(path.read_bytes())
        self.write_proof(values)

    def rewrite_state(self, payload: str, modified_ns: int | None = None) -> None:
        self.state.write_text(payload)
        self.state.chmod(0o600)
        if modified_ns is not None:
            os.utime(self.state, ns=(modified_ns, modified_ns))
        values = self.proof_values()
        values["stateSha256"] = digest(self.state.read_bytes())
        self.write_proof(values)

    def rewrite_receipt(self, document: dict[str, object]) -> None:
        self.receipt.write_bytes(self.receipt_bytes(document))
        self.receipt.chmod(0o600)
        os.utime(
            self.receipt,
            ns=(self.restart_started + 800_000_000, self.restart_started + 800_000_000),
        )
        values = self.proof_values()
        values["restartReceiptSha256"] = digest(self.receipt.read_bytes())
        self.write_proof(values)


class McpGovernanceRuntimeProofTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, name: str = "fixture", **kwargs: object) -> Fixture:
        return Fixture(self.root / name, **kwargs)

    def rejected(self, fixture: Fixture, pattern: str, **overrides: object) -> None:
        with self.assertRaisesRegex(validator.ProofValidationError, pattern):
            fixture.validate(**overrides)

    def test_producer_and_validator_parse_rfc3339nano_independently(self) -> None:
        earlier = "2026-07-20T03:19:00.518599094Z"
        later = "2026-07-20T03:19:00.518599095Z"
        invalid = (
            "0001-01-01T00:00:00Z",
            "2026-07-20T03:19:00.1234567890Z",
            "2026-07-20T03:19:00.123456789+00:00",
            "2026-02-30T03:19:00Z",
        )
        for module, error in (
            (producer, producer.ProofError),
            (validator, validator.ProofValidationError),
        ):
            with self.subTest(module=module.__name__):
                self.assertEqual(
                    1,
                    module._timestamp(later, "Docker startedAt")
                    - module._timestamp(earlier, "Docker startedAt"),
                )
                for value in invalid:
                    with self.subTest(value=value), self.assertRaises(error):
                        module._timestamp(value, "Docker startedAt")

    def test_accepts_exact_two_stage_candidate_bound_observation(self) -> None:
        fixture = self.fixture()

        summary = fixture.validate(require_pass=True)

        self.assertEqual("PASS", summary["status"])
        self.assertEqual(list(validator.ACCEPTANCE_IDS), summary["acceptanceIds"])
        self.assertEqual(50, summary["sessionLifecycle"]["idleTtlSeconds"])
        self.assertEqual(5, summary["rateLimiting"]["maxPerSubject"])
        self.assertEqual(5, summary["rateLimiting"]["maxPerClient"])
        self.assertEqual(1, summary["rateLimiting"]["riskLimits"]["destructive"])
        self.assertTrue(summary["shutdown"]["ingressContinuity"])
        self.assertEqual(fixture.NGINX_IMAGE_ID, summary["shutdown"]["nginxImageId"])
        self.assertEqual(
            digest(fixture.NGINX_REFERENCE.encode()),
            summary["shutdown"]["nginxImageReferenceSha256"],
        )
        self.assertTrue(summary["shutdown"]["probeBeforeIdleExpiry"])
        self.assertEqual(
            digest(fixture.receipt.read_bytes()),
            summary["shutdown"]["restartReceiptSha256"],
        )
        self.assertEqual(
            fixture.receipt_document()["producerSha256"],
            summary["shutdown"]["restartProducerSha256"],
        )
        self.assertEqual(set(validator.SOURCE_PATHS.values()), set(summary["sources"]))
        self.assertNotIn("session-acceptance", validator.canonical_summary_bytes(summary).decode())

    def test_writes_one_private_canonical_summary_only_with_explicit_pass(self) -> None:
        fixture = self.fixture()
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        output.chmod(0o700)

        with self.assertRaisesRegex(validator.ProofValidationError, "requires --require-pass"):
            fixture.validate(summary_output=output)
        self.assertEqual([], os.listdir(output))

        summary = fixture.validate(require_pass=True, summary_output=output)
        artifact = output / validator.SUMMARY_FILE
        self.assertEqual({validator.SUMMARY_FILE}, set(os.listdir(output)))
        self.assertEqual(validator.canonical_summary_bytes(summary), artifact.read_bytes())
        if os.name == "posix":
            self.assertEqual(0o600, stat.S_IMODE(artifact.stat().st_mode))

    def test_rejects_report_failure_skip_retry_wrong_method_and_staleness(self) -> None:
        cases = {
            "failure": ('failures="0"', 'failures="1"'),
            "skip": ('skipped="0"', 'skipped="1"'),
            "flake": ('flakes="0"', 'flakes="1"'),
            "method": (validator.MAIN_TEST_METHOD, "forgedPass"),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name=name):
                fixture = self.fixture(name)
                fixture.rewrite_report(
                    fixture.main_report,
                    fixture.main_report.read_text().replace(old, new),
                )
                self.rejected(fixture, "clean passing|different test")

        retry = self.fixture("retry")
        retry.rewrite_report(
            retry.shutdown_report,
            retry.shutdown_report.read_text().replace(
                f'  <testcase classname="{validator.SHUTDOWN_TEST_CLASS}" '
                f'name="{validator.SHUTDOWN_TEST_METHOD}"/>',
                f'  <testcase classname="{validator.SHUTDOWN_TEST_CLASS}" '
                f'name="{validator.SHUTDOWN_TEST_METHOD}"><rerunFailure/></testcase>'),
        )
        self.rejected(retry, "retry, or flake")

        stale = self.fixture("stale")
        values = stale.proof_values()
        values["restartStartedAtEpochNs"] = str(stale.shutdown_report.stat().st_mtime_ns + 1)
        stale.write_proof(values)
        self.rejected(stale, "stale")

    def test_rejects_noncanonical_or_out_of_window_shutdown_state(self) -> None:
        ttl = self.fixture("ttl")
        ttl.rewrite_state(
            ttl.state_text(expectedIdleTtlSeconds=51),
            ttl.created_ms * 1_000_000,
        )
        self.rejected(ttl, "fixed canonical")

        late = self.fixture("late")
        created_ms = (late.restart_started + 1_000_000_000) // 1_000_000
        late.created_ms = created_ms
        late.rewrite_state(late.state_text(), created_ms * 1_000_000)
        self.rejected(late, "outside the pre-restart")

    def test_restart_receipt_is_required_and_causally_bound(self) -> None:
        missing = self.fixture("receipt-missing")
        missing.receipt.unlink()
        self.rejected(missing, "unexpected file set")

        cases = {
            "candidate": ("candidate", "gitCommit", "0" * 40, "candidate or runtime"),
            "stop": ("gracefulRestart", "signal", "SIGKILL", "graceful-stop"),
            "redis": ("redisContinuity", "markerSurvived", False, "Redis continuity"),
            "ingress": (
                "ingressContinuity", "unchangedAcrossAppRestart", False,
                "Nginx ingress",
            ),
            "state": ("shutdownProbeState", "sha256", "0" * 64, "state binding"),
            "producer": ("envelope", "producerSha256", "0" * 64, "producer differs"),
            "timing": (
                "timing",
                "healthyAtEpochNs",
                1,
                "causally ordered",
            ),
        }
        for name, (section, key, value, pattern) in cases.items():
            with self.subTest(name=name):
                fixture = self.fixture(f"receipt-{name}")
                document = fixture.receipt_document()
                if section == "envelope":
                    document[key] = value
                else:
                    nested = document[section]
                    self.assertIsInstance(nested, dict)
                    nested[key] = value  # type: ignore[index]
                fixture.rewrite_receipt(document)
                self.rejected(fixture, pattern)

        docker_time = self.fixture("receipt-docker-time")
        document = docker_time.receipt_document()
        restart = document["gracefulRestart"]
        redis = document["redisContinuity"]
        ingress = document["ingressContinuity"]
        self.assertIsInstance(restart, dict)
        self.assertIsInstance(redis, dict)
        self.assertIsInstance(ingress, dict)
        restart["old"]["startedAt"] = "2030-01-01T00:00:00Z"  # type: ignore[index]
        restart["stopped"]["finishedAt"] = "2030-01-01T00:01:00Z"  # type: ignore[index]
        restart["new"]["startedAt"] = "2030-01-01T00:02:00Z"  # type: ignore[index]
        redis["startedAt"] = "2030-01-01T00:00:00Z"  # type: ignore[index]
        ingress["services"]["nginx"]["startedAt"] = "2030-01-01T00:00:00Z"  # type: ignore[index]
        docker_time.rewrite_receipt(document)
        self.rejected(docker_time, "cross-bound")

        producer_fixture = self.fixture("receipt-producer-validation", produce=False)
        document = producer_fixture.receipt_document()
        restart = document["gracefulRestart"]
        self.assertIsInstance(restart, dict)
        restart["signal"] = "SIGKILL"  # type: ignore[index]
        producer_fixture.receipt.write_bytes(producer_fixture.receipt_bytes(document))
        producer_fixture.receipt.chmod(0o600)
        os.utime(
            producer_fixture.receipt,
            ns=(
                producer_fixture.restart_started + 800_000_000,
                producer_fixture.restart_started + 800_000_000,
            ),
        )
        with self.assertRaisesRegex(producer.ProofError, "graceful-stop"):
            producer_fixture.produce()

    def test_restart_receipt_images_are_bound_to_release_runtime_identity(self) -> None:
        cases = {
            "app-reference": (
                "expected_app_reference",
                "example.invalid/other@sha256:" + "1" * 64,
                "app image identity",
            ),
            "app-image-id": (
                "expected_app_image_id",
                "sha256:" + "2" * 64,
                "app image identity",
            ),
            "nginx-reference": (
                "expected_nginx_reference",
                "example.invalid/nginx@sha256:" + "5" * 64,
                "Nginx ingress identity",
            ),
            "nginx-image-id": (
                "expected_nginx_image_id",
                "sha256:" + "6" * 64,
                "Nginx ingress identity",
            ),
            "redis-reference": (
                "expected_redis_reference",
                "example.invalid/redis@sha256:" + "3" * 64,
                "Redis image identity",
            ),
            "redis-image-id": (
                "expected_redis_image_id",
                "sha256:" + "4" * 64,
                "Redis image identity",
            ),
        }
        for name, (argument, value, pattern) in cases.items():
            with self.subTest(name=name):
                fixture = self.fixture(f"runtime-image-{name}")
                self.rejected(fixture, pattern, **{argument: value})

    def test_validator_cli_requires_all_release_runtime_image_bindings(self) -> None:
        fixture = self.fixture("validator-cli-images")
        common = [
            "--proof", str(fixture.proof),
            "--repository-root", str(fixture.repository),
            "--expected-candidate-commit", fixture.commit,
            "--expected-candidate-version", fixture.VERSION,
            "--expected-candidate-tag", fixture.TAG,
            "--expected-compose-project", fixture.PROJECT,
            "--expected-trace-prefix", fixture.TRACE,
        ]
        with mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            validator._parser().parse_args(common)
        parsed = validator._parser().parse_args(
            common
            + [
                "--expected-app-reference", fixture.APP_REFERENCE,
                "--expected-app-image-id", fixture.APP_IMAGE_ID,
                "--expected-nginx-reference", fixture.NGINX_REFERENCE,
                "--expected-nginx-image-id", fixture.NGINX_IMAGE_ID,
                "--expected-redis-reference", fixture.REDIS_REFERENCE,
                "--expected-redis-image-id", fixture.REDIS_IMAGE_ID,
            ]
        )
        self.assertEqual(fixture.APP_REFERENCE, parsed.expected_app_reference)
        self.assertEqual(fixture.NGINX_IMAGE_ID, parsed.expected_nginx_image_id)
        self.assertEqual(fixture.REDIS_IMAGE_ID, parsed.expected_redis_image_id)

    def test_rejects_proof_reorder_duplicate_hash_and_expected_identity_drift(self) -> None:
        reordered = self.fixture("reordered")
        reordered.write_proof(reordered.proof_values(), tuple(reversed(validator.PROOF_KEYS)))
        self.rejected(reordered, "canonical exact schema")

        duplicate = self.fixture("duplicate")
        duplicate.proof.write_text(
            duplicate.proof.read_text() + f"candidateCommit={duplicate.commit}\n")
        duplicate.proof.chmod(0o600)
        self.rejected(duplicate, "duplicate key|canonical exact schema")

        bad_hash = self.fixture("hash")
        values = bad_hash.proof_values()
        values["mainReportSha256"] = "0" * 64
        bad_hash.write_proof(values)
        self.rejected(bad_hash, "hash does not match")

        identity = self.fixture("identity")
        self.rejected(identity, "expected candidate", expected_compose_project="other")

    def test_rejects_dirty_hidden_lightweight_replace_graft_and_object_alternates(self) -> None:
        dirty = self.fixture("dirty")
        (dirty.repository / "untracked.txt").write_text("drift")
        self.rejected(dirty, "clean")

        hidden = self.fixture("hidden")
        git(hidden.repository, "update-index", "--assume-unchanged", "pom.xml")
        self.rejected(hidden, "index contains")

        lightweight = self.fixture("lightweight")
        git(lightweight.repository, "tag", "-d", lightweight.TAG)
        git(lightweight.repository, "tag", lightweight.TAG)
        self.rejected(lightweight, "annotated")

        replaced = self.fixture("replace")
        replacement = git(
            replaced.repository,
            "commit-tree",
            replaced.tree,
            "-m",
            "replacement",
        )
        git(replaced.repository, "replace", replaced.commit, replacement)
        self.rejected(replaced, "replacement refs")

        graft = self.fixture("graft")
        git_directory = Path(git(graft.repository, "rev-parse", "--absolute-git-dir"))
        (git_directory / "info" / "grafts").write_text(f"{graft.commit}\n")
        self.rejected(graft, "grafts")

        alternate = self.fixture("alternate")
        git_directory = Path(git(alternate.repository, "rev-parse", "--absolute-git-dir"))
        (git_directory / "objects" / "info" / "alternates").write_text(
            str(git_directory / "objects") + "\n")
        self.rejected(alternate, "object alternates")

    def test_git_environment_injection_is_neutralized_for_producer_and_validator(self) -> None:
        fixture = self.fixture("poison", produce=False)
        fake_index = self.root / "fake-index"
        fake_objects = self.root / "fake-objects"
        fake_objects.mkdir()
        poison = {
            "GIT_DIR": str(self.root / "fake-git-dir"),
            "GIT_COMMON_DIR": str(self.root / "fake-common-dir"),
            "GIT_WORK_TREE": str(self.root / "fake-worktree"),
            "GIT_INDEX_FILE": str(fake_index),
            "GIT_OBJECT_DIRECTORY": str(fake_objects),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(fake_objects),
            "GIT_REPLACE_REF_BASE": "refs/attacker",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.worktree",
            "GIT_CONFIG_VALUE_0": str(self.root / "fake-worktree"),
            "GIT_CONFIG_GLOBAL": str(self.root / "attacker.gitconfig"),
            "GIT_CONFIG_SYSTEM": str(self.root / "attacker-system.gitconfig"),
        }
        with mock.patch.dict(os.environ, poison, clear=False):
            fixture.produce()
            summary = fixture.validate(require_pass=True)
        self.assertEqual(fixture.commit, summary["candidate"]["commit"])

    def test_git_execution_has_live_byte_and_timeout_bounds(self) -> None:
        output = self.root / "git-output"
        output.write_text(
            f"#!{sys.executable}\nimport os\nos.write(1, b'x' * 65536)\n")
        output.chmod(0o700)
        sleeper = self.root / "git-sleeper"
        sleeper.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(5)\n")
        sleeper.chmod(0o700)
        for module, error in (
            (producer, producer.ProofError),
            (validator, validator.ProofValidationError),
        ):
            with self.subTest(module=module.__name__, bound="bytes"):
                with mock.patch.object(module, "_trusted_git", return_value=str(output)):
                    with self.assertRaisesRegex(error, "unexpectedly large"):
                        module._git(self.root, "ignored", limit=1024, timeout_seconds=2)
            with self.subTest(module=module.__name__, bound="timeout"):
                with mock.patch.object(module, "_trusted_git", return_value=str(sleeper)):
                    with self.assertRaisesRegex(error, "timed out"):
                        module._git(self.root, "ignored", timeout_seconds=0.05)

    def test_final_recheck_rejects_late_candidate_and_raw_mutation(self) -> None:
        producer_fixture = self.fixture("late-producer", produce=False)
        original_sources = producer._candidate_sources
        source_calls = 0

        def produce_then_dirty(repository: Path, commit: str) -> tuple[str, dict[str, bytes]]:
            nonlocal source_calls
            result = original_sources(repository, commit)
            source_calls += 1
            if source_calls == 1:
                (repository / "late-untracked.txt").write_text("late drift\n")
            return result

        with mock.patch.object(producer, "_candidate_sources", side_effect=produce_then_dirty):
            with self.assertRaisesRegex(producer.ProofError, "clean"):
                producer_fixture.produce()
        self.assertGreaterEqual(source_calls, 1)

        validator_fixture = self.fixture("late-validator")
        original_candidate = validator._candidate
        candidate_calls = 0

        def validate_then_dirty(*arguments: object, **kwargs: object) -> object:
            nonlocal candidate_calls
            result = original_candidate(*arguments, **kwargs)
            candidate_calls += 1
            if candidate_calls == 1:
                (validator_fixture.repository / "late-untracked.txt").write_text("late drift\n")
            return result

        with mock.patch.object(validator, "_candidate", side_effect=validate_then_dirty):
            self.rejected(validator_fixture, "clean")
        self.assertGreaterEqual(candidate_calls, 1)

        raw_fixture = self.fixture("late-raw")
        original_receipt = validator._restart_receipt

        def validate_then_mutate_raw(*arguments: object, **kwargs: object) -> None:
            original_receipt(*arguments, **kwargs)
            raw_fixture.main_report.write_bytes(raw_fixture.main_report.read_bytes() + b" ")
            raw_fixture.main_report.chmod(0o600)

        with mock.patch.object(
            validator, "_restart_receipt", side_effect=validate_then_mutate_raw
        ):
            self.rejected(raw_fixture, "changed during validation")

    @unittest.skipUnless(os.name == "posix", "POSIX evidence permissions")
    def test_rejects_permissions_symlink_and_extra_raw_files(self) -> None:
        mode = self.fixture("mode")
        mode.proof.chmod(0o644)
        self.rejected(mode, "0600")

        extra = self.fixture("extra")
        (extra.raw / "forged.json").write_text("{}")
        self.rejected(extra, "unexpected file set")

        symlink = self.fixture("symlink")
        actual = symlink.raw / "actual.xml"
        symlink.main_report.rename(actual)
        symlink.main_report.symlink_to(actual.name)
        self.rejected(symlink, "unexpected file set|cannot open|regular file")

        hardlink = self.fixture("hardlink")
        linked = self.root / "linked-main.xml"
        hardlink.main_report.rename(linked)
        os.link(linked, hardlink.main_report)
        self.rejected(hardlink, "link count")

    def test_rejects_candidate_source_schema_and_executing_validator_drift(self) -> None:
        source = self.fixture("source")
        path = source.repository / validator.SOURCE_PATHS["rateLimiterSha256"]
        path.write_text("uncommitted weakening\n")
        self.rejected(source, "clean|workspace source differs")

        schema_document = json.loads(
            Path(validator.__file__).resolve().parent.parent.joinpath(
                validator.SUMMARY_SCHEMA).read_text())
        schema_document["additionalProperties"] = True
        schema = self.fixture(
            "schema", schema_bytes=(json.dumps(schema_document) + "\n").encode())
        self.rejected(schema, "strict expected envelope")

        executing = self.fixture("executing", validator_bytes=b"# forged validator\n")
        self.rejected(executing, "executing MCP governance validator differs")

    def test_fixed_human_reviewed_behavior_hashes_reject_test_body_drift(self) -> None:
        self.assertEqual(
            producer.REVIEWED_BEHAVIOR_SHA256,
            validator.REVIEWED_BEHAVIOR_SHA256,
        )
        replacements = {
            validator.SOURCE_PATHS["mainTestSha256"]: (
                b".isEqualTo(429);", b".isNotEqualTo(429);"
            ),
            validator.SOURCE_PATHS["shutdownTestSha256"]: (
                b".isEqualTo(404);", b".isNotEqualTo(404);"
            ),
            validator.SOURCE_PATHS["runtimeSupportSha256"]: (
                b"RATE_WINDOW_SECONDS = 15", b"RATE_WINDOW_SECONDS = 16"
            ),
        }
        for index, (relative, (old, new)) in enumerate(replacements.items()):
            actual = WORKSPACE_ROOT.joinpath(*relative.split("/")).read_bytes()
            self.assertEqual(
                validator.REVIEWED_BEHAVIOR_SHA256[relative], digest(actual), relative)
            self.assertIn(old, actual)
            weakened = actual.replace(old, new, 1)
            fixture = self.fixture(
                f"behavior-{index}",
                produce=False,
                source_overrides={relative: weakened},
            )
            with self.assertRaisesRegex(producer.ProofError, "human-reviewed"):
                fixture.produce()
            with mock.patch.dict(
                producer.REVIEWED_BEHAVIOR_SHA256,
                {relative: digest(weakened)},
            ):
                fixture.produce()
            self.rejected(fixture, "human-reviewed")

    @unittest.skipUnless(os.name == "posix", "POSIX staging contract")
    def test_stages_only_one_private_surefire_xml_with_exclusive_copy(self) -> None:
        raw = self.root / "stage-raw"
        raw.mkdir(mode=0o700)
        raw.chmod(0o700)
        for name in (validator.MAIN_REPORT, validator.SHUTDOWN_REPORT):
            stage = self.root / ("stage-" + name.split(".")[-2])
            stage.mkdir(mode=0o700)
            stage.chmod(0o700)
            report = stage / name
            report.write_text("<testsuite/>\n")
            report.chmod(0o600)
            producer.stage_surefire_report(stage, name, raw)
            self.assertEqual(report.read_bytes(), (raw / name).read_bytes())
            self.assertEqual(0o600, stat.S_IMODE((raw / name).stat().st_mode))
            with self.assertRaisesRegex(producer.ProofError, "not ready"):
                producer.stage_surefire_report(stage, name, raw)

        extra = self.root / "stage-extra"
        extra.mkdir(mode=0o700)
        extra.chmod(0o700)
        report = extra / validator.MAIN_REPORT
        report.write_text("<testsuite/>\n")
        report.chmod(0o600)
        (extra / "unexpected.txt").write_text("not a report")
        empty_raw = self.root / "empty-raw"
        empty_raw.mkdir(mode=0o700)
        empty_raw.chmod(0o700)
        with self.assertRaisesRegex(producer.ProofError, "exactly"):
            producer.stage_surefire_report(extra, validator.MAIN_REPORT, empty_raw)

    def test_documented_surefire_contract_uses_isolated_stages_and_no_text_report(self) -> None:
        document = WORKSPACE_ROOT.joinpath("docs/mcp-governance-runtime-evidence.md").read_text()
        self.assertGreaterEqual(document.count("-Dsurefire.useFile=false"), 2)
        self.assertIn("WEB_STARTER_GOVERNANCE_MAIN_REPORT_DIR", document)
        self.assertIn("WEB_STARTER_GOVERNANCE_SHUTDOWN_REPORT_DIR", document)
        self.assertGreaterEqual(document.count("stage_surefire_report"), 2)
        self.assertIn("orchestrate_mcp_governance_restart.py", document)

    def test_producer_rejects_snapshot_lightweight_extra_and_existing_output(self) -> None:
        lightweight = self.fixture("producer-lightweight", produce=False, annotated_tag=False)
        with self.assertRaisesRegex(producer.ProofError, "annotated"):
            lightweight.produce()

        extra = self.fixture("producer-extra", produce=False)
        (extra.raw / "extra").write_text("forged")
        with self.assertRaisesRegex(producer.ProofError, "exactly"):
            extra.produce()

        existing = self.fixture("producer-existing")
        with self.assertRaisesRegex(producer.ProofError, "exactly|already exists"):
            existing.produce()

        hardlink = self.fixture("producer-hardlink", produce=False)
        linked = self.root / "producer-linked-main.xml"
        hardlink.main_report.rename(linked)
        os.link(linked, hardlink.main_report)
        with self.assertRaisesRegex(producer.ProofError, "link count"):
            hardlink.produce()


if __name__ == "__main__":
    unittest.main()
