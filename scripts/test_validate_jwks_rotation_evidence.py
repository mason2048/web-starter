from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import validate_jwks_rotation_evidence as validator


WORKSPACE = Path(__file__).resolve().parents[1]
VERSION = "2.0.0"
PROJECT = "web-starter-ac26-unit-1"
MANIFEST_DIGEST = "sha256:" + "a" * 64
APP_REFERENCE = "registry.invalid/web-starter@" + MANIFEST_DIGEST
APP_IMAGE_ID = "sha256:" + "b" * 64
NGINX_DIGEST = "sha256:" + "c" * 64
NGINX_REFERENCE = "registry.invalid/web-starter-nginx@" + NGINX_DIGEST
NGINX_IMAGE_ID = "sha256:" + "d" * 64
PUBLIC_ORIGIN = "https://mcp.ac26.webstarter.test:18443"
PRIVATE_ORIGIN = "http://127.0.0.1:18088"
TRACE_PREFIX = "ac26-unit-0001"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode().strip()


def success_mcp(
    trace: str, seed: str, started_at: int, completed_at: int
) -> dict[str, object]:
    return {
        "initializeHttpStatus": 200,
        "initializedHttpStatus": 202,
        "toolCallHttpStatus": 200,
        "deleteHttpStatus": 204,
        "protocolVersion": "2025-11-25",
        "serverName": "web-starter-mcp",
        "toolName": "system.info",
        "toolResultSuccess": True,
        "startedAtEpochSeconds": started_at,
        "completedAtEpochSeconds": completed_at,
        "traceId": trace,
        "traceHeaderMatched": True,
        "sessionIdSha256": digest((seed + "-session").encode()),
        "initializeResponseSha256": digest((seed + "-initialize").encode()),
        "toolResponseSha256": digest((seed + "-tool").encode()),
    }


def audit(source_trace: str, audit_trace: str, seed: str) -> dict[str, object]:
    return {
        "httpStatus": 200,
        "sourceTraceId": source_trace,
        "auditTraceId": audit_trace,
        "rowMatched": True,
        "toolNameMatched": True,
        "successOutcomeMatched": True,
        "responseSha256": seed * 64,
        "attempt": 1,
    }


def jwks(
    kids: list[str], fingerprints: dict[str, str], seed: str, observed_at: int
) -> dict[str, object]:
    return {
        "httpStatus": 200,
        "responseContentTypeJson": True,
        "observedAtEpochSeconds": observed_at,
        "keyCount": len(kids),
        "kids": sorted(kids),
        "publicFingerprintSha256": {key: fingerprints[key] for key in sorted(fingerprints)},
        "privateParametersAbsent": True,
        "metadataIssuerMatched": True,
        "metadataJwksUriMatched": True,
        "responseSha256": seed * 64,
    }


class Fixture:
    def __init__(self, root: Path, terminal_mode: str = "expiry") -> None:
        self.root = root
        self.repository = root / "candidate"
        self.repository.mkdir(parents=True)
        for relative in validator.SOURCE_PATHS:
            source = WORKSPACE.joinpath(*relative.split("/"))
            target = self.repository.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = source.read_bytes()
            if relative in {
                validator.ROOT_POM_PATH,
                validator.SECURITY_POM_PATH,
                validator.MCP_POM_PATH,
                validator.FRONTEND_MANIFEST_PATH,
            }:
                payload = payload.replace(b"2.0.0-SNAPSHOT", VERSION.encode())
            target.write_bytes(payload)
        run_git(self.repository, "init", "-q")
        run_git(self.repository, "config", "user.name", "AC26 Unit")
        run_git(self.repository, "config", "user.email", "ac26@example.invalid")
        run_git(self.repository, "add", ".")
        run_git(self.repository, "commit", "-q", "-m", "candidate")
        self.commit = run_git(self.repository, "rev-parse", "HEAD")
        run_git(self.repository, "tag", "-a", f"v{VERSION}", "-m", "release")
        self.tree = run_git(self.repository, "rev-parse", "HEAD^{tree}")
        self.tag_object = run_git(self.repository, "rev-parse", f"refs/tags/v{VERSION}^{{tag}}")

        self.runtime_identity = root / "runtime-identity.json"
        runtime = {
            "schemaVersion": 2,
            "status": "PASS",
            "observedAt": "2033-05-18T03:33:00Z",
            "release": {"version": VERSION, "gitCommit": self.commit},
            "images": {
                "app": {
                    "reference": APP_REFERENCE,
                    "imageId": APP_IMAGE_ID,
                    "ociVersion": VERSION,
                    "ociRevision": self.commit,
                },
                "nginx": {
                    "reference": NGINX_REFERENCE,
                    "imageId": NGINX_IMAGE_ID,
                    "ociVersion": VERSION,
                    "ociRevision": self.commit,
                },
                "mysql": {
                    "reference": "registry.invalid/mysql@sha256:" + "e" * 64,
                    "imageId": "sha256:" + "f" * 64,
                    "ociVersion": None,
                    "ociRevision": None,
                },
                "redis": {
                    "reference": "registry.invalid/redis@sha256:" + "0" * 64,
                    "imageId": "sha256:" + "9" * 64,
                    "ociVersion": None,
                    "ociRevision": None,
                },
            },
        }
        self.runtime_identity.write_text(json.dumps(runtime, sort_keys=True) + "\n")
        self.runtime_identity.chmod(0o600)

        self.evidence_directory = root / "evidence"
        self.evidence_directory.mkdir(mode=0o700)
        self.report = self.evidence_directory / validator.RESULT_NAME
        self.checksum = self.evidence_directory / validator.CHECKSUM_NAME
        self.document = self.sample(terminal_mode)
        self.write()

    def source_hashes(self) -> dict[str, str]:
        return {
            relative: digest(self.repository.joinpath(*relative.split("/")).read_bytes())
            for relative in validator.SOURCE_PATHS
        }

    def sample(self, terminal_mode: str) -> dict[str, object]:
        baseline_at = 2_000_000_010
        baseline_jwks_at = baseline_at - 2
        rotated_jwks_at = baseline_at + 1
        rotated_at = baseline_at + 3
        new_completed_at = baseline_at + 5
        retain_until = baseline_at + 60
        terminal_jwks_at = (
            retain_until + 1 if terminal_mode == "expiry" else baseline_at + 20
        )
        terminal_at = terminal_jwks_at + 2
        final_completed_at = terminal_at + 2
        old_kid = "old-2025"
        new_kid = "new-2026"
        old_fingerprint = "1" * 64
        new_fingerprint = "2" * 64
        hashes = self.source_hashes()
        def transition(
            phase: str,
            previous_app: str,
            current_app: str,
            previous_ingress: tuple[str, str],
            current_ingress: tuple[str, str],
        ) -> dict[str, object]:
            return {
                "phase": phase,
                "previousContainerId": previous_app * 64,
                "currentContainerId": current_app * 64,
                "previousIngressContainerIds": {
                    "nginx": previous_ingress[0] * 64,
                    "mcp-public-nginx": previous_ingress[1] * 64,
                },
                "currentIngressContainerIds": {
                    "nginx": current_ingress[0] * 64,
                    "mcp-public-nginx": current_ingress[1] * 64,
                },
                "imageId": APP_IMAGE_ID,
                "nginxImageId": NGINX_IMAGE_ID,
                "nginxReference": NGINX_REFERENCE,
                "projectLabelMatched": True,
                "serviceLabelMatched": True,
                "fixedServices": ["app", "mcp-public-nginx", "nginx"],
                "allContainersHealthy": True,
                "portBindingsMatched": True,
                "noBuild": True,
                "noPull": True,
                "noDependencies": True,
            }

        transitions = [
            transition("baseline", "a", "b", ("1", "2"), ("3", "4")),
            transition("rotated", "b", "c", ("3", "4"), ("5", "6")),
        ]
        if terminal_mode == "revocation":
            terminal_transition = transition(
                "terminal", "c", "d", ("5", "6"), ("7", "8")
            )
            transitions.append(terminal_transition)
        old_window_trace = f"{TRACE_PREFIX}-old-window"
        new_trace = f"{TRACE_PREFIX}-new-active"
        final_trace = f"{TRACE_PREFIX}-new-final"
        return {
            "schemaVersion": 2,
            "acceptanceId": "V2-AC-26",
            "status": "PASS",
            "generatedAt": datetime.fromtimestamp(
                final_completed_at + 1, tz=timezone.utc
            ).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "candidate": {
                "head": self.commit,
                "tree": self.tree,
                "tag": f"v{VERSION}",
                "tagObject": self.tag_object,
                "mavenVersion": VERSION,
                "frontendVersion": VERSION,
                "cleanWorktree": True,
                "sourceSha256": hashes,
            },
            "tool": {
                "path": validator.TOOL_PATH,
                "sha256": hashes[validator.TOOL_PATH],
                "validatorPath": validator.VALIDATOR_PATH,
                "validatorSha256": hashes[validator.VALIDATOR_PATH],
                "schemaPath": validator.SCHEMA_PATH,
                "schemaSha256": hashes[validator.SCHEMA_PATH],
            },
            "runtime": {
                "composeProject": PROJECT,
                "publicOriginSha256": digest(PUBLIC_ORIGIN.encode()),
                "privateOriginSha256": digest(PRIVATE_ORIGIN.encode()),
                "privatePort": 18088,
                "publicPort": 18443,
                "tracePrefix": TRACE_PREFIX,
                "runtimeIdentitySha256": digest(self.runtime_identity.read_bytes()),
                "app": {
                    "requestedReference": APP_REFERENCE,
                    "id": APP_IMAGE_ID,
                    "manifestDigest": MANIFEST_DIGEST,
                    "ociVersion": VERSION,
                    "ociRevision": self.commit,
                },
                "nginx": {
                    "requestedReference": NGINX_REFERENCE,
                    "id": NGINX_IMAGE_ID,
                    "manifestDigest": NGINX_DIGEST,
                    "ociVersion": VERSION,
                    "ociRevision": self.commit,
                },
                "containerTransitions": transitions,
            },
            "keyRing": {
                "oldKid": old_kid,
                "newKid": new_kid,
                "oldPublicFingerprintSha256": old_fingerprint,
                "newPublicFingerprintSha256": new_fingerprint,
                "retainUntilEpochSeconds": retain_until,
                "terminalMode": terminal_mode,
                "initialPrivateKeyCount": 1,
                "rotatedPrivateKeyCount": 1,
                "retiringPrivateMaterialPresent": False,
                "terminalRevocationConfigured": terminal_mode == "revocation",
            },
            "observations": {
                "baseline": {
                    "observedAtEpochSeconds": baseline_at,
                    "jwks": jwks(
                        [old_kid], {old_kid: old_fingerprint}, "5", baseline_jwks_at
                    ),
                    "oldOauthGrant": {
                        "httpStatus": 200,
                        "responseContentTypeJson": True,
                        "kid": old_kid,
                        "algorithm": "RS256",
                        "issuedAtEpochSeconds": baseline_at - 1,
                        "expiresAtEpochSeconds": terminal_at + 30,
                        "protectedHeaderSha256": "6" * 64,
                        "claimsSha256": "7" * 64,
                        "responseSha256": "8" * 64,
                        "issuerMatched": True,
                        "audienceMatched": True,
                        "requiredScopesMatched": True,
                    },
                    "oldMcp": success_mcp(
                        f"{TRACE_PREFIX}-old-base", "9", baseline_at - 1, baseline_at
                    ),
                },
                "rotated": {
                    "observedAtEpochSeconds": rotated_at,
                    "jwks": jwks(
                        [old_kid, new_kid],
                        {old_kid: old_fingerprint, new_kid: new_fingerprint},
                        "a",
                        rotated_jwks_at,
                    ),
                    "newOauthGrant": {
                        "httpStatus": 200,
                        "responseContentTypeJson": True,
                        "kid": new_kid,
                        "algorithm": "RS256",
                        "issuedAtEpochSeconds": rotated_jwks_at,
                        "expiresAtEpochSeconds": final_completed_at + 600,
                        "protectedHeaderSha256": "b" * 64,
                        "claimsSha256": "c" * 64,
                        "responseSha256": "d" * 64,
                        "issuerMatched": True,
                        "audienceMatched": True,
                        "requiredScopesMatched": True,
                    },
                    "oldWithinWindowMcp": success_mcp(
                        old_window_trace, "1", rotated_at - 1, rotated_at
                    ),
                    "newActiveMcp": success_mcp(
                        new_trace, "4", rotated_at + 1, new_completed_at
                    ),
                    "oldTraceAudit": audit(
                        old_window_trace, f"{TRACE_PREFIX}-audit-old", "7"
                    ),
                    "newTraceAudit": audit(
                        new_trace, f"{TRACE_PREFIX}-audit-new", "8"
                    ),
                },
                "terminal": {
                    "observedAtEpochSeconds": terminal_at,
                    "jwks": jwks(
                        [new_kid], {new_kid: new_fingerprint}, "9", terminal_jwks_at
                    ),
                    "oldCredentialRejected": {
                        "httpStatus": 401,
                        "startedAtEpochSeconds": terminal_at - 1,
                        "completedAtEpochSeconds": terminal_at,
                        "traceId": f"{TRACE_PREFIX}-old-reject",
                        "traceHeaderMatched": True,
                        "wwwAuthenticateBearer": True,
                        "noSessionIssued": True,
                        "responseSha256": "a" * 64,
                    },
                    "newActiveMcp": success_mcp(
                        final_trace, "d", terminal_at + 1, final_completed_at
                    ),
                    "newTraceAudit": audit(
                        final_trace, f"{TRACE_PREFIX}-audit-final", "0"
                    ),
                },
            },
            "supplementalConfigurationGuards": {
                "status": "SOURCE_BOUND_ONLY",
                "unknownKidRuntime": "NOT_COVERED",
                "invalidActiveRuntime": "NOT_COVERED",
                "unitTestSourcePath": validator.KEY_RING_TEST_PATH,
                "unitTestSourceSha256": hashes[validator.KEY_RING_TEST_PATH],
            },
            "evidencePolicy": {
                "outsideRepository": True,
                "directoryMode": "0700",
                "fileMode": "0600",
                "onlyReportAndChecksum": True,
                "rawHttpBodiesPersisted": False,
                "credentialsPersisted": False,
                "privateKeyMaterialPersisted": False,
                "arbitraryHookAccepted": False,
                "dockerResourcesRemoved": False,
            },
        }

    def write(self) -> None:
        payload = (json.dumps(self.document, indent=2, sort_keys=True) + "\n").encode()
        self.report.write_bytes(payload)
        self.report.chmod(0o600)
        self.checksum.write_text(f"{digest(payload)}  {validator.RESULT_NAME}\n")
        self.checksum.chmod(0o600)

    def kwargs(self, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "expected_candidate_commit": self.commit,
            "expected_candidate_version": VERSION,
            "expected_candidate_tag": f"v{VERSION}",
            "expected_compose_project": PROJECT,
            "expected_app_reference": APP_REFERENCE,
            "expected_app_image_id": APP_IMAGE_ID,
            "expected_nginx_reference": NGINX_REFERENCE,
            "expected_nginx_image_id": NGINX_IMAGE_ID,
            "expected_public_origin": PUBLIC_ORIGIN,
            "expected_private_origin": PRIVATE_ORIGIN,
            "expected_trace_prefix": TRACE_PREFIX,
            "expected_terminal_mode": self.document["keyRing"]["terminalMode"],
            "require_pass": True,
        }
        result.update(overrides)
        return result

    def validate(self, **overrides: object) -> dict[str, object]:
        return validator.validate_evidence(
            self.report,
            self.repository,
            self.runtime_identity,
            **self.kwargs(**overrides),
        )


class JwksRotationEvidenceValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, name: str = "fixture", terminal_mode: str = "expiry") -> Fixture:
        return Fixture(self.root / name, terminal_mode)

    def rejected(self, fixture: Fixture, fragment: str, **kwargs: object) -> None:
        with self.assertRaisesRegex(validator.EvidenceValidationError, fragment):
            fixture.validate(**kwargs)

    def test_accepts_expiry_runtime_and_emits_explicit_not_covered_supplemental(self) -> None:
        fixture = self.fixture()

        summary = fixture.validate()

        self.assertEqual("PASS", summary["status"])
        self.assertEqual("expiry", summary["rotation"]["terminalMode"])
        self.assertEqual("PASS", summary["checks"]["oldCredentialWithinWindowMcp"])
        self.assertEqual("PASS", summary["checks"]["oldCredentialTerminalRejection"])
        self.assertEqual("NOT_COVERED", summary["checks"]["unknownKidRuntime"])
        self.assertEqual("NOT_COVERED", summary["checks"]["invalidActiveRuntime"])

    def test_accepts_pre_boundary_revocation_only_with_terminal_recreation(self) -> None:
        fixture = self.fixture("revocation", "revocation")

        summary = fixture.validate()

        self.assertEqual("revocation", summary["rotation"]["terminalMode"])
        self.assertEqual(3, len(fixture.document["runtime"]["containerTransitions"]))

    def test_rejects_self_reported_pass_without_real_http_and_mcp_observations(self) -> None:
        fixture = self.fixture()
        fixture.document["observations"]["rotated"]["oldWithinWindowMcp"]["toolCallHttpStatus"] = 0
        fixture.write()
        self.rejected(fixture, "complete real MCP")

        fixture = self.fixture("oauth")
        fixture.document["observations"]["baseline"]["oldOauthGrant"]["httpStatus"] = 0
        fixture.write()
        self.rejected(fixture, "successful RS256 issuance")

        fixture = self.fixture("rejection")
        fixture.document["observations"]["terminal"]["oldCredentialRejected"]["httpStatus"] = 200
        fixture.write()
        self.rejected(fixture, "HTTP 401")

    def test_rejects_wrong_window_timing_and_token_expiry_confounder(self) -> None:
        before = self.fixture("before")
        retain = before.document["keyRing"]["retainUntilEpochSeconds"]
        before.document["observations"]["terminal"]["observedAtEpochSeconds"] = retain - 1
        before.document["observations"]["terminal"]["jwks"]["observedAtEpochSeconds"] = retain - 1
        before.document["observations"]["terminal"]["oldCredentialRejected"]["startedAtEpochSeconds"] = retain - 1
        before.document["observations"]["terminal"]["oldCredentialRejected"]["completedAtEpochSeconds"] = retain - 1
        before.write()
        self.rejected(before, "before the exclusive boundary")

        expired = self.fixture("expired")
        rejected_at = expired.document["observations"]["terminal"]["oldCredentialRejected"]["completedAtEpochSeconds"]
        expired.document["observations"]["baseline"]["oldOauthGrant"]["expiresAtEpochSeconds"] = rejected_at
        expired.write()
        self.rejected(expired, "does not isolate key retirement")

        late_revocation = self.fixture("late-revocation", "revocation")
        retain = late_revocation.document["keyRing"]["retainUntilEpochSeconds"]
        late_revocation.document["observations"]["terminal"]["observedAtEpochSeconds"] = retain
        late_revocation.document["observations"]["terminal"]["jwks"]["observedAtEpochSeconds"] = retain
        late_revocation.document["observations"]["terminal"]["oldCredentialRejected"]["startedAtEpochSeconds"] = retain
        late_revocation.document["observations"]["terminal"]["oldCredentialRejected"]["completedAtEpochSeconds"] = retain
        late_revocation.document["observations"]["terminal"]["newActiveMcp"]["startedAtEpochSeconds"] = retain
        late_revocation.document["observations"]["terminal"]["newActiveMcp"]["completedAtEpochSeconds"] = retain + 1
        late_revocation.document["observations"]["baseline"]["oldOauthGrant"]["expiresAtEpochSeconds"] = retain + 30
        late_revocation.write()
        self.rejected(late_revocation, "did not complete before")

    def test_rejects_jwks_private_flag_kid_fingerprint_and_active_credential_drift(self) -> None:
        private = self.fixture("private")
        private.document["observations"]["rotated"]["jwks"]["privateParametersAbsent"] = False
        private.write()
        self.rejected(private, "must be true")

        kids = self.fixture("kids")
        kids.document["observations"]["rotated"]["jwks"]["kids"] = ["new-2026"]
        kids.write()
        self.rejected(kids, "exact expected kids")

        active = self.fixture("active")
        active.document["observations"]["rotated"]["newOauthGrant"]["kid"] = "old-2025"
        active.write()
        self.rejected(active, "active kid")

    def test_rejects_runtime_identity_image_project_and_transition_chain_drift(self) -> None:
        identity = self.fixture("identity")
        runtime = json.loads(identity.runtime_identity.read_text())
        runtime["images"]["app"]["imageId"] = "sha256:" + "f" * 64
        identity.runtime_identity.write_text(json.dumps(runtime) + "\n")
        identity.runtime_identity.chmod(0o600)
        self.rejected(identity, "caller expectations")

        project = self.fixture("project")
        self.rejected(
            project,
            "Compose project differs",
            expected_compose_project="web-starter-ac26-other-1",
        )

        transition = self.fixture("transition")
        transition.document["runtime"]["containerTransitions"][1]["previousContainerId"] = "f" * 64
        transition.write()
        self.rejected(transition, "not continuous")

        ingress = self.fixture("ingress")
        ingress.document["runtime"]["containerTransitions"][0]["portBindingsMatched"] = False
        ingress.write()
        self.rejected(ingress, "must be true")

    def test_caller_fixes_nginx_origin_trace_prefix_and_terminal_mode(self) -> None:
        fixture = self.fixture("caller-bindings")
        self.rejected(
            fixture,
            "terminal mode differs",
            expected_terminal_mode="revocation",
        )
        self.rejected(
            fixture,
            "trace prefix differs",
            expected_trace_prefix="ac26-other-0001",
        )
        self.rejected(
            fixture,
            "origin, port",
            expected_public_origin="https://mcp.ac26.webstarter.test:19443",
        )
        self.rejected(
            fixture,
            "Nginx differs",
            expected_nginx_image_id="sha256:" + "8" * 64,
        )

    def test_rejects_dirty_candidate_source_forgery_secrets_and_checksum_or_mode_drift(self) -> None:
        dirty = self.fixture("dirty")
        (dirty.repository / "untracked.txt").write_text("dirty")
        self.rejected(dirty, "clean")

        forged = self.fixture("forged")
        forged.document["candidate"]["sourceSha256"][validator.KEY_RING_PATH] = "f" * 64
        forged.write()
        self.rejected(forged, "source hashes")

        secret = self.fixture("secret")
        payload = secret.report.read_bytes() + b'\n"access_token":"eyJsecret.secret.secret"\n'
        secret.report.write_bytes(payload)
        secret.report.chmod(0o600)
        secret.checksum.write_text(f"{digest(payload)}  {validator.RESULT_NAME}\n")
        secret.checksum.chmod(0o600)
        self.rejected(secret, "credential or private")

        checksum = self.fixture("checksum")
        checksum.checksum.write_text("0" * 64 + f"  {validator.RESULT_NAME}\n")
        checksum.checksum.chmod(0o600)
        self.rejected(checksum, "checksum")

        mode = self.fixture("mode")
        mode.report.chmod(0o644)
        self.rejected(mode, "size or mode")

    def test_rechecks_candidate_after_semantic_validation(self) -> None:
        fixture = self.fixture("candidate-toctou")
        original_snapshot = validator.snapshot_evidence
        snapshot_calls = 0

        def mutate_before_final_snapshot(report: Path) -> validator.EvidenceSnapshot:
            nonlocal snapshot_calls
            snapshot_calls += 1
            if snapshot_calls == 2:
                (fixture.repository / "late-untracked.txt").write_text("late mutation")
            return original_snapshot(report)

        with patch.object(validator, "snapshot_evidence", side_effect=mutate_before_final_snapshot):
            self.rejected(fixture, "clean")
        self.assertEqual(2, snapshot_calls)

    def test_rejects_overstated_supplemental_and_writes_canonical_summary_once(self) -> None:
        overstated = self.fixture("overstated")
        overstated.document["supplementalConfigurationGuards"]["unknownKidRuntime"] = "PASS"
        overstated.write()
        self.rejected(overstated, "overstate runtime coverage")

        fixture = self.fixture("summary")
        summary = fixture.validate()
        summary_dir = self.root / "summary-output"
        summary_dir.mkdir(mode=0o700)
        summary_path = summary_dir / validator.SUMMARY_NAME
        validator.write_canonical_summary(summary_path, summary)
        payload = summary_path.read_bytes()
        self.assertEqual(
            json.dumps(summary, sort_keys=True, separators=(",", ":")).encode() + b"\n",
            payload,
        )
        self.assertEqual(0o600, summary_path.stat().st_mode & 0o777)
        with self.assertRaisesRegex(validator.EvidenceValidationError, "must not already exist"):
            validator.write_canonical_summary(summary_path, summary)

    def test_schema_and_validator_are_stdlib_and_source_sets_remain_in_lockstep(self) -> None:
        schema = json.loads((WORKSPACE / validator.SCHEMA_PATH).read_text())
        required_sources = set(
            schema["properties"]["candidate"]["properties"]["sourceSha256"]["required"]
        )
        self.assertEqual(set(validator.SOURCE_PATHS), required_sources)
        properties = schema["properties"]
        definitions = schema["$defs"]
        observations = properties["observations"]["properties"]
        pairs = (
            (schema, validator.TOP_FIELDS),
            (properties["candidate"], validator.CANDIDATE_FIELDS),
            (properties["tool"], validator.TOOL_FIELDS),
            (properties["runtime"], validator.RUNTIME_FIELDS),
            (definitions["releaseImage"], validator.APP_FIELDS),
            (definitions["transition"], validator.TRANSITION_FIELDS),
            (properties["keyRing"], validator.KEY_RING_FIELDS),
            (properties["observations"], validator.OBSERVATION_FIELDS),
            (observations["baseline"], validator.BASELINE_FIELDS),
            (observations["rotated"], validator.ROTATED_FIELDS),
            (observations["terminal"], validator.TERMINAL_FIELDS),
            (definitions["jwks"], validator.JWKS_FIELDS),
            (definitions["oauthGrant"], validator.CREDENTIAL_FIELDS),
            (definitions["mcpCall"], validator.MCP_FIELDS),
            (definitions["audit"], validator.AUDIT_FIELDS),
            (definitions["rejection"], validator.REJECTION_FIELDS),
            (properties["supplementalConfigurationGuards"], validator.SUPPLEMENTAL_FIELDS),
            (properties["evidencePolicy"], validator.POLICY_FIELDS),
        )
        for schema_object, expected_fields in pairs:
            self.assertEqual(set(expected_fields), set(schema_object["required"]))
            self.assertEqual(set(expected_fields), set(schema_object["properties"]))
        source = (WORKSPACE / validator.VALIDATOR_PATH).read_text(encoding="utf-8")
        self.assertNotIn("jsonschema", source)
        self.assertNotIn("import requests", source)
        self.assertNotIn('["docker", "compose"', source.lower())
        self.assertNotIn('["docker", "inspect"', source.lower())


if __name__ == "__main__":
    unittest.main()
