from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import validate_tooling_lifecycle_evidence as evidence


COMMIT = "c" * 40
PROJECT = "web-starter-tooling-17-1"
REFERENCES = {
    "app": "registry.invalid/app@sha256:" + "a" * 64,
    "nginx": "registry.invalid/nginx@sha256:" + "b" * 64,
    "mysql": "registry.invalid/mysql@sha256:" + "d" * 64,
    "redis": "registry.invalid/redis@sha256:" + "e" * 64,
}
IMAGE_IDS = {
    "app": "sha256:" + "1" * 64,
    "nginx": "sha256:" + "2" * 64,
    "mysql": "sha256:" + "3" * 64,
    "redis": "sha256:" + "4" * 64,
}
CANDIDATE = {
    "gitCommit": COMMIT,
    "gitTree": "5" * 40,
    "tagObject": "6" * 40,
    "releaseVersion": "2.0.0",
    "releaseTag": "v2.0.0",
}


def empty_snapshot() -> dict:
    return {"containers": {}, "volumes": [], "networks": []}


def up_snapshot() -> dict:
    return {
        "containers": {
            service: {"status": "running", "health": "healthy", "imageId": IMAGE_IDS[service]}
            for service in sorted(evidence.SERVICES)
        },
        "volumes": sorted((f"{PROJECT}_mysql-data", f"{PROJECT}_redis-data")),
        "networks": sorted((f"{PROJECT}_app", f"{PROJECT}_data")),
    }


def preserved_snapshot() -> dict:
    return {
        "containers": {},
        "volumes": sorted((f"{PROJECT}_mysql-data", f"{PROJECT}_redis-data")),
        "networks": [],
    }


def business_record() -> dict:
    digest = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()
    fixture_id = evidence.BUSINESS_FIXTURE_BASE_ID + (
        int(digest[:16], 16) % evidence.BUSINESS_FIXTURE_ID_RANGE
    )
    fixture_code = "TOOLING_" + digest[:16].upper()
    fields = (
        str(fixture_id), evidence.BUSINESS_FIXTURE_NAME, fixture_code, str(fixture_id),
        evidence.BUSINESS_FIXTURE_OWNER, "ACTIVE", evidence.BUSINESS_FIXTURE_DESCRIPTION, "0",
        evidence.BUSINESS_FIXTURE_TIMESTAMP, evidence.BUSINESS_FIXTURE_TIMESTAMP, "0",
    )
    return {
        "fixtureId": fixture_id,
        "fixtureCode": fixture_code,
        "rowCount": 1,
        "rowSha256": hashlib.sha256("\x1f".join(fields).encode("utf-8")).hexdigest(),
    }


def bootstrap_credential() -> dict:
    return {
        "firstLogin": {"status": 200, "sessionCookie": True},
        "passwordHashBeforeRestart": "9" * 64,
        "environmentPasswordRemovedBeforeRestart": True,
        "secondLogin": {"status": 200, "sessionCookie": True},
        "passwordHashAfterRestart": "9" * 64,
        "firstRuntimeLogs": {
            "byteCount": 1024,
            "sha256": "a" * 64,
            "secretMatches": 0,
        },
        "secondRuntimeLogs": {
            "byteCount": 2048,
            "sha256": "b" * 64,
            "secretMatches": 0,
        },
    }


def report() -> dict:
    return {
        "schemaVersion": 1,
        "evidenceType": "toolingLifecycleRuntime",
        "status": "PASS",
        "acceptanceIds": ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"],
        "observedAt": "2026-07-20T00:00:00+00:00",
        "candidate": dict(CANDIDATE),
        "runtime": {
            "composeProject": PROJECT,
            "images": dict(REFERENCES),
            "ports": {"mysql": 31001, "redis": 31002, "app": 31003, "nginx": 31004},
        },
        "doctor": {
            "checks": {
                name: {"status": "PASS", "detail": "verified", "action": "none"}
                for name in sorted(evidence.EXPECTED_DOCTOR_CHECKS)
            },
            "outputSha256": "7" * 64,
        },
        "lifecycle": {
            "initial": empty_snapshot(),
            "firstUp": up_snapshot(),
            "businessPersistence": {
                "beforeRestart": business_record(),
                "afterRestart": business_record(),
            },
            "bootstrapCredential": bootstrap_credential(),
            "defaultDown": preserved_snapshot(),
            "rejections": {
                "confirmationWithoutVolumes": 2,
                "wrongProjectConfirmation": 2,
                "missingNonInteractiveConfirmation": 3,
            },
            "afterRejections": preserved_snapshot(),
            "secondUp": up_snapshot(),
            "confirmedVolumeDelete": empty_snapshot(),
        },
    }


class ToolingLifecycleEvidenceTest(unittest.TestCase):

    def validate(self, document: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / evidence.REPORT_NAME
            raw.write_text(json.dumps(document), encoding="utf-8")
            raw.chmod(0o600)
            identity = root / "runtime-version-identity.json"
            identity.write_text(json.dumps({
                "schemaVersion": 2,
                "status": "PASS",
                "release": {"gitCommit": COMMIT, "version": "2.0.0"},
                "images": {
                    service: {"reference": REFERENCES[service], "imageId": IMAGE_IDS[service]}
                    for service in sorted(evidence.SERVICES)
                },
            }), encoding="utf-8")
            identity.chmod(0o600)
            with mock.patch.object(
                evidence,
                "_candidate",
                return_value=(dict(CANDIDATE), {path: "8" * 64 for path in evidence.SOURCE_PATHS}),
            ):
                return evidence.validate(raw, root, identity, PROJECT, None)

    def test_exact_doctor_preservation_restart_and_confirmed_cleanup_pass(self) -> None:
        summary = self.validate(report())
        self.assertEqual(
            ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"],
            summary["acceptanceIds"],
        )
        self.assertEqual(
            "PASS", summary["checks"]["bootstrapPasswordRemovedBeforeRestart"],
        )
        self.assertEqual(
            "9" * 64,
            summary["runtime"]["bootstrapCredential"]["passwordHashSha256"],
        )
        self.assertEqual("PASS", summary["checks"]["defaultDownPreservedVolumes"])
        self.assertEqual(
            "PASS", summary["checks"]["businessDataPersistedAcrossRestart"],
        )
        self.assertEqual(business_record(), summary["runtime"]["businessPersistence"])
        self.assertEqual("PASS", summary["checks"]["confirmedDeletionRemovedAllResources"])

    def test_canonical_schema_requires_business_persistence_and_all_bound_sources(self) -> None:
        repository = Path(__file__).resolve().parent.parent
        schema = json.loads(
            (repository / evidence.SCHEMA_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"],
            schema["properties"]["acceptanceIds"]["const"],
        )
        self.assertIn(
            "businessPersistence", schema["properties"]["runtime"]["required"],
        )
        self.assertIn(
            "businessDataPersistedAcrossRestart",
            schema["properties"]["checks"]["required"],
        )
        self.assertIn(
            "bootstrapCredential", schema["properties"]["runtime"]["required"],
        )
        self.assertIn(
            "existingAdminPasswordUnchanged",
            schema["properties"]["checks"]["required"],
        )
        self.assertEqual(
            set(evidence.SOURCE_PATHS),
            set(
                schema["properties"]["evidence"]["properties"]["sourceSha256"][
                    "required"
                ]
            ),
        )

    def test_missing_doctor_domain_or_non_pass_is_rejected(self) -> None:
        missing = report()
        del missing["doctor"]["checks"]["docker-engine"]
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "doctor inventory"):
            self.validate(missing)

        failed = report()
        failed["doctor"]["checks"]["java"]["status"] = "FAIL"
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "actionable PASS"):
            self.validate(failed)

    def test_volume_loss_or_confirmation_bypass_is_rejected(self) -> None:
        lost = report()
        lost["lifecycle"]["defaultDown"]["volumes"] = []
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "preserve"):
            self.validate(lost)

        bypass = report()
        bypass["lifecycle"]["rejections"]["wrongProjectConfirmation"] = 0
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "rejection contract"):
            self.validate(bypass)

    def test_restart_image_drift_or_final_resource_leak_is_rejected(self) -> None:
        drift = report()
        drift["lifecycle"]["secondUp"]["containers"]["app"]["imageId"] = "sha256:" + "9" * 64
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "different image"):
            self.validate(drift)

        leaked = report()
        leaked["lifecycle"]["confirmedVolumeDelete"] = preserved_snapshot()
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "not empty"):
            self.validate(leaked)

    def test_business_row_loss_or_content_drift_is_rejected(self) -> None:
        lost = report()
        lost["lifecycle"]["businessPersistence"]["afterRestart"]["rowCount"] = 0
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "deterministic business row"):
            self.validate(lost)

        changed = report()
        changed["lifecycle"]["businessPersistence"]["afterRestart"]["rowSha256"] = "9" * 64
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "deterministic business row"):
            self.validate(changed)

        wrong_fixture = report()
        wrong_fixture["lifecycle"]["businessPersistence"]["beforeRestart"][
            "fixtureCode"
        ] = "TOOLING_0000000000000000"
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "deterministic business row"):
            self.validate(wrong_fixture)

    def test_bootstrap_password_removal_login_hash_and_log_scan_are_required(self) -> None:
        changed = report()
        changed["lifecycle"]["bootstrapCredential"]["passwordHashAfterRestart"] = "8" * 64
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "persisted administrator hash"):
            self.validate(changed)

        leaked = report()
        leaked["lifecycle"]["bootstrapCredential"]["secondRuntimeLogs"]["secretMatches"] = 1
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "runtime log scan"):
            self.validate(leaked)

        no_session = report()
        no_session["lifecycle"]["bootstrapCredential"]["secondLogin"]["sessionCookie"] = False
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "login evidence"):
            self.validate(no_session)

    def test_runtime_identity_drift_and_credential_shaped_raw_are_rejected(self) -> None:
        drift = report()
        drift["runtime"]["images"]["app"] = "registry.invalid/other@sha256:" + "a" * 64
        with self.assertRaisesRegex(evidence.ToolingEvidenceError, "runtime identity"):
            self.validate(drift)

        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / evidence.REPORT_NAME
            raw.write_bytes(
                b'{"authorization":"Bea' + b'rer secret-value-12345678"}'
            )
            raw.chmod(0o600)
            with self.assertRaisesRegex(evidence.ToolingEvidenceError, "credential-shaped"):
                evidence._load_private(raw, "tooling lifecycle report")


if __name__ == "__main__":
    unittest.main()
