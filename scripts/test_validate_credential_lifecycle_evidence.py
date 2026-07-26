from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import validate_credential_lifecycle_evidence as gate


VERSION = "2.0.0"
PROJECT = "web-starter-release-credential"
APP_IMAGE = "web-starter-app@sha256:" + "a" * 64
NGINX_IMAGE = "web-starter-nginx@sha256:" + "b" * 64


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed.stdout.strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    def __init__(self, root: Path, annotated: bool = True) -> None:
        self.root = root
        self.repository = root / "candidate"
        self.repository.mkdir(parents=True)
        source_root = Path(gate.__file__).resolve().parent.parent
        for relative in gate.SOURCE_PATHS:
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source_root / relative).read_bytes())
        (self.repository / "pom.xml").write_text(
            f"<project><version>{VERSION}</version></project>\n", encoding="utf-8"
        )
        frontend = self.repository / "web-starter-web/package.json"
        frontend.parent.mkdir(parents=True, exist_ok=True)
        frontend.write_text(json.dumps({"name": "web-starter-web", "version": VERSION}) + "\n")
        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Credential Evidence Test")
        git(self.repository, "config", "user.email", "credential-evidence@example.invalid")
        git(self.repository, "add", "--all")
        git(self.repository, "commit", "-q", "-m", "candidate")
        self.commit = git(self.repository, "rev-parse", "HEAD")
        self.tag = "v" + VERSION
        if annotated:
            git(self.repository, "tag", "-a", self.tag, "-m", self.tag)
        else:
            git(self.repository, "tag", self.tag)

        self.private = root / "private"
        self.private.mkdir(mode=0o700)
        self.private.chmod(0o700)
        self.runtime = self.private / "runtime.json"
        self.oauth = self.private / "oauth.json"
        self.report = self.private / gate.REPORT_NAME
        self._write_private(self.runtime, {
            "status": "PASS",
            "images": {"app": {"reference": APP_IMAGE}, "nginx": {"reference": NGINX_IMAGE}},
        })
        self._write_private(self.oauth, {
            "status": "PASS",
            "checks": {
                "oauthMetadataConsistency": "PASS",
                "dynamicClientRegistrationDisabled": "PASS", "wwwAuthenticate": "PASS",
                "clientCredentials": "PASS", "clientCredentialsShortLived": "PASS",
                "oauthPublicMcp": "PASS",
                "patPrivateMcp": "PASS", "patPublicRejected": "PASS",
                "invalidOriginRejected": "PASS",
            },
        })
        self.document = self.clean_report()
        self.write_report()

    @staticmethod
    def _write_private(path: Path, document: dict[str, object]) -> None:
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def clean_report(self) -> dict[str, object]:
        cases = []
        for number, action in enumerate(gate.ACTIONS, start=1):
            cases.append({
                "action": action,
                "traceId": f"release-lifecycle-{action}-{number}",
                "oauthGrantType": "authorization_code",
                "pkceMethod": "S256",
                "oauthAccessExpiresInSeconds": 600,
                "oauthBeforeHttpStatus": 200,
                "sessionNextHttpStatus": 401,
                "oauthAccessNextHttpStatus": 401,
                "oauthRefreshNextHttpStatus": 400,
                "oauthRefreshError": "invalid_grant",
                "patNextHttpStatus": 401,
                "operationAuditObserved": True,
                "fixtureCleanupTraceId": (
                    f"release-lifecycle-{action}-{number}"
                    if action == "subject-remove"
                    else f"release-lifecycle-{action}-{number}-cleanup"
                ),
                "fixtureReadAfterCleanupHttpStatus": 404,
                "fixtureCleanupAuditObserved": True,
            })
        return {
            "schemaVersion": 1,
            "acceptanceIds": gate.ACCEPTANCE_IDS,
            "status": "PASS",
            "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "candidate": {
                "releaseTag": self.tag, "releaseVersion": VERSION, "gitCommit": self.commit,
                "appImageReference": APP_IMAGE, "nginxImageReference": NGINX_IMAGE,
            },
            "runtime": {
                "composeProject": PROJECT,
                "privateOrigin": "http://127.0.0.1:18088",
                "privateMcpOrigin": "http://mcp-private.release.webstarter.test:18088",
                "publicOrigin": "https://mcp.release.webstarter.test:18443",
                "runtimeIdentitySha256": digest(self.runtime),
                "oauthRuntimeReportSha256": digest(self.oauth),
            },
            "cascadeInvalidation": {"cases": cases},
            "pepperRotation": {
                "beforeVersion": "release-v1", "afterVersion": "release-v2",
                "authenticationHttpStatus": 200, "activeHashMatched": True,
                "lastUsedRecorded": True, "databasePlaintextAbsent": True,
                "runtimeLogPlaintextAbsent": True,
            },
            "clientSecretRotation": {
                "overlapSeconds": 2, "oldDuringHttpStatus": 200, "newDuringHttpStatus": 200,
                "oldAfterHttpStatus": 401, "oldAfterError": "invalid_client",
                "newAfterHttpStatus": 200, "preRegisteredClientObserved": True,
                "operationAuditObserved": True,
            },
            "clientCredentialsLifecycle": {
                "shortLivedTokenObserved": True,
                "roleRevocationHttpStatus": 401,
                "roleRestorationHttpStatus": 200,
                "revocationAuditObserved": True,
                "restorationAuditObserved": True,
            },
            "serviceAccountLifecycle": {
                "createdEnabledWithRole": True,
                "roleRemovalErrorCode": "FORBIDDEN",
                "roleRestorationHttpStatus": 200,
                "explicitRevocationHttpStatus": 401,
                "peerAfterSingleRevocationHttpStatus": 200,
                "disabledTokenHttpStatuses": [401, 401],
                "allExistingTokenRowsRevoked": True,
                "reenabledOldTokenHttpStatuses": [401, 401],
                "replacementTokenHttpStatus": 200,
                "operationAuditsObserved": True,
            },
            "personalTokenLifecycle": {
                "boundUserObserved": True,
                "oneTimePlaintextObserved": True,
                "databaseHashAndHintObserved": True,
                "scopeDeniedCode": "FORBIDDEN",
                "beforeExpiryHttpStatus": 200,
                "afterExpiryHttpStatus": 401,
                "revokedHttpStatus": 401,
                "ipRestrictedHttpStatus": 401,
                "lastUsedRecorded": True,
                "lifecycleFieldsObserved": True,
            },
            "securityRegression": {
                "rbacAllowedScopeDeniedCode": "FORBIDDEN",
                "scopeAllowedRbacDeniedCode": "FORBIDDEN",
                "disabledSubjectRejected": True, "revokedCredentialHttpStatus": 401,
                "privatePatHttpStatus": 200, "publicPatHttpStatus": 401,
                "privateServiceTokenHttpStatus": 200, "publicServiceTokenHttpStatus": 401,
                "invalidHostHttpStatus": 400, "invalidOriginRejected": True,
                "scopeDeniedAuditObserved": True, "rbacDeniedAuditObserved": True,
                "correlatedAuditsObserved": True,
            },
            "secretHandling": {
                "rawCredentialsPersisted": False, "databaseDumpScanned": True,
                "runtimeLogsScanned": True, "errorResponsesScanned": True,
                "runtimeSensitiveHeadersAbsent": True, "sensitiveValueCount": 24,
            },
            "sources": {relative: digest(self.repository / relative) for relative in gate.SOURCE_PATHS},
        }

    def write_report(self) -> None:
        self._write_private(self.report, self.document)

    def validate(self, output: Path | None = None) -> dict[str, object]:
        return gate.validate(
            self.report, self.repository, self.runtime, self.oauth, PROJECT, output
        )


class CredentialLifecycleEvidenceValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_accepts_exact_candidate_bound_runtime_observations(self) -> None:
        fixture = Fixture(self.root)

        summary = fixture.validate()

        self.assertEqual("PASS", summary["status"])
        self.assertEqual(gate.ACCEPTANCE_IDS, summary["acceptanceIds"])
        self.assertEqual(fixture.commit, summary["candidate"]["gitCommit"])
        self.assertEqual("PASS", summary["checks"]["fixtureCleanup"])
        self.assertEqual(set(gate.SOURCE_PATHS), set(summary["evidence"]["sourceSha256"]))

    def test_writes_one_mode_0600_canonical_summary(self) -> None:
        fixture = Fixture(self.root)
        output = self.root / "summary"
        output.mkdir(mode=0o700)
        output.chmod(0o700)
        target = output / gate.SUMMARY_NAME

        summary = fixture.validate(target)

        self.assertEqual({gate.SUMMARY_NAME}, set(os.listdir(output)))
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        self.assertEqual(summary, json.loads(target.read_text(encoding="utf-8")))

    def test_accepts_any_explicit_http_4xx_for_invalid_host(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["securityRegression"]["invalidHostHttpStatus"] = 421
        fixture.write_report()

        summary = fixture.validate()

        self.assertEqual("PASS", summary["checks"]["unifiedSecurityRegression"])

    def test_rejects_server_error_for_invalid_host(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["securityRegression"]["invalidHostHttpStatus"] = 500
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "security-negative"):
            fixture.validate()

    def test_rejects_service_token_on_wrong_ingress_boundary(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["securityRegression"]["publicServiceTokenHttpStatus"] = 200
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "security-negative"):
            fixture.validate()

    def test_rejects_one_cascade_path_that_does_not_invalidate_refresh_token(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["cascadeInvalidation"]["cases"][0]["oauthRefreshError"] = "server_error"
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "next-request invalidation"):
            fixture.validate()

    def test_rejects_one_cascade_fixture_that_was_not_removed(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["cascadeInvalidation"]["cases"][0][
            "fixtureReadAfterCleanupHttpStatus"
        ] = 200
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "next-request invalidation"):
            fixture.validate()

    def test_rejects_authorization_code_without_short_lived_pkce_s256_token(self) -> None:
        fixture = Fixture(self.root)
        case = fixture.document["cascadeInvalidation"]["cases"][0]
        case["pkceMethod"] = "plain"
        case["oauthAccessExpiresInSeconds"] = 7200
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "next-request invalidation"):
            fixture.validate()

    def test_rejects_old_client_secret_after_window_still_working(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["clientSecretRotation"]["oldAfterHttpStatus"] = 200
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "overlap observations"):
            fixture.validate()

    def test_rejects_client_rotation_without_pre_registered_client_observation(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["clientSecretRotation"]["preRegisteredClientObserved"] = False
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "overlap observations"):
            fixture.validate()

    def test_rejects_client_credentials_that_survive_role_revocation(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["clientCredentialsLifecycle"]["roleRevocationHttpStatus"] = 200
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "lifecycle observations"):
            fixture.validate()

    def test_rejects_service_account_disable_that_leaves_a_token_usable(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["serviceAccountLifecycle"]["disabledTokenHttpStatuses"] = [401, 200]
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "service account lifecycle"):
            fixture.validate()

    def test_rejects_personal_token_that_survives_expiry(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["personalTokenLifecycle"]["afterExpiryHttpStatus"] = 200
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "personal token lifecycle"):
            fixture.validate()

    def test_rejects_plaintext_token_shaped_material_in_report(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["unexpected"] = "wst_pat_" + "A" * 40
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "unexpected or missing"):
            fixture.validate()

    def test_rejects_missing_error_response_or_sensitive_header_scan(self) -> None:
        fixture = Fixture(self.root)
        fixture.document["secretHandling"]["errorResponsesScanned"] = False
        fixture.write_report()

        with self.assertRaisesRegex(gate.EvidenceError, "secret persistence"):
            fixture.validate()

        fixture.document["secretHandling"]["errorResponsesScanned"] = True
        fixture.document["secretHandling"]["runtimeSensitiveHeadersAbsent"] = False
        fixture.write_report()
        with self.assertRaisesRegex(gate.EvidenceError, "secret persistence"):
            fixture.validate()

    def test_rejects_source_tampering_even_if_report_hash_is_unchanged(self) -> None:
        fixture = Fixture(self.root)
        source = fixture.repository / gate.SOURCE_PATHS[-1]
        source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")

        with self.assertRaisesRegex(gate.EvidenceError, "clean"):
            fixture.validate()

    def test_rejects_lightweight_release_tag(self) -> None:
        fixture = Fixture(self.root, annotated=False)

        with self.assertRaisesRegex(gate.EvidenceError, "annotated tag"):
            fixture.validate()


if __name__ == "__main__":
    unittest.main()
