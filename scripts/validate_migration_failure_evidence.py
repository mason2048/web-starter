#!/usr/bin/env python3
"""Independently validate V2-AC-07 migration-failure evidence.

This verifier shares no validation helpers with the producer.  It uses only
the Python standard library, recomputes the public evidence semantics, binds a
PASS result to one clean Git candidate, and invokes the independent AC-40
validator against the actual recovery evidence file.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping
import xml.etree.ElementTree as ElementTree

import validate_v1_upgrade_evidence as ac40_validator


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESULT_NAME = "v2-ac07-migration-failure.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"
TOOL_PATH = "scripts/rehearse_migration_failure.py"
SCHEMA_PATH = "security/v2-ac07-migration-failure.schema.json"
AC40_VALIDATOR_PATH = "scripts/validate_v1_upgrade_evidence.py"
SOURCE_PATHS = (TOOL_PATH, SCHEMA_PATH, AC40_VALIDATOR_PATH)

ALLOWED_STATUSES = frozenset({"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"})
STATUS_EXIT_CODES = {"PASS": 0, "FAIL": 1, "NOT_COVERED": 6, "ENV_REQUIRED": 6}
FAILURE_CHECKS = (
    "appExitedNonZero",
    "appCompletedBeforeTimeout",
    "readinessNeverSucceeded",
    "applicationStartedMarkerAbsent",
    "intentionalMigrationFailureObserved",
    "productionPolicyAcceptedFixture",
    "baseMigrationsSucceeded",
    "failedVersionNotRecordedSuccessful",
    "failureVersionHistoryConsistent",
)

TOP_LEVEL_FIELDS = frozenset({
    "schemaVersion", "acceptanceId", "status", "statusDetail", "processExitCode",
    "generatedAt", "candidate", "tool", "failureProtection", "recovery", "images",
    "resources", "infrastructure", "migration", "application", "logs", "evidencePolicy",
})
CANDIDATE_FIELDS = frozenset({"head", "tree", "version", "cleanWorktree", "sourceSha256"})
TOOL_FIELDS = frozenset({"path", "sha256", "evidenceSchemaPath", "evidenceSchemaSha256"})
FAILURE_FIELDS = frozenset({"status", "checks"})
IMAGE_ROLES = ("app", "mysql", "redis")
APP_IMAGE_FIELDS = frozenset({
    "id", "requestedReferenceSha256", "requestedDigest", "ociVersion", "ociRevision",
})
INFRASTRUCTURE_IMAGE_FIELDS = frozenset({"id", "requestedReferenceSha256"})
RESOURCE_FIELDS = frozenset({"prefix", "runId", "network", "containers", "isolation", "cleanup"})
CONTAINER_FIELDS = frozenset(IMAGE_ROLES)
ISOLATION_FIELDS = frozenset({
    "internalNetwork", "publishedHostPorts", "dockerVolumeMounts", "hostBindMounts",
    "migrationBindReadOnly", "appRootFilesystemReadOnly", "immutableImageIds",
    "exactOwnershipLabels",
})
CLEANUP_FIELDS = frozenset({"exactLabelsVerifiedBeforeRemoval", "removed", "residual", "complete"})
RESOURCE_BOOLEAN_FIELDS = frozenset({"app", "redis", "mysql", "network"})
INFRASTRUCTURE_FIELDS = frozenset({
    "mysqlReady", "redisReady", "probeAttempts", "hostPorts", "sharedVolumes",
})
PROBE_FIELDS = frozenset({"mysql", "redis"})
MIGRATION_FIELDS = frozenset({
    "version", "file", "contentSha256", "temporaryReadOnlyMount", "persistedAfterRun",
    "successfulBaseRows", "successfulFailureVersionRows", "unsuccessfulFailureVersionRows",
    "totalFailureVersionRows", "latestSuccessfulVersion",
})
APPLICATION_FIELDS = frozenset({
    "exitCode", "timedOut", "readinessAttempts", "readinessSuccesses", "logMarkers",
})
MARKER_FIELDS = frozenset({
    "applicationStarted", "intentionalMigrationFailure", "unsafeProductionConfiguration",
})
LOG_FIELDS = frozenset({
    "rawPersisted", "fixtureMaterialPersisted", "fixtureLeakDetected", "app", "mysql", "redis",
})
LOG_DIGEST_FIELDS = frozenset({"bytes", "sha256"})
POLICY_FIELDS = frozenset({"outsideRepository", "directoryMode", "fileMode"})
AC40_VALIDATOR_FIELDS = frozenset({
    "path", "sha256", "checkCount", "acceptanceCount", "phaseCount",
})

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_BOUND_REFERENCE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,181}@(?P<digest>sha256:[0-9a-f]{64})$"
)
GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        r"[\"']?(?:password|access_token|refresh_token|client_secret|authorization|cookie)"
        r"[\"']?\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:pat|svc)_[0-9A-Za-z_-]{16,}\b", re.IGNORECASE),
)


class EvidenceValidationError(ValueError):
    """The public AC-07 evidence is malformed, inconsistent, or unbound."""


class EvidenceNotPassingError(EvidenceValidationError):
    """A valid evidence document did not satisfy an explicit PASS gate."""

    def __init__(self, status: str) -> None:
        super().__init__(f"evidence status is {status}; PASS is required")
        self.status = status


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    frozen = set(expected)
    if actual == frozen:
        return
    details: list[str] = []
    missing = sorted(frozen - actual)
    unknown = sorted(actual - frozen)
    if missing:
        details.append("missing=" + ",".join(missing))
    if unknown:
        details.append("unknown=" + ",".join(unknown))
    raise EvidenceValidationError(f"{label} fields are not exact ({'; '.join(details)})")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{label} must be a string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceValidationError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceValidationError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise EvidenceValidationError(f"{label} must be >= {minimum}")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} must be a lowercase SHA-256")
    return text


def _image_id(value: Any, label: str) -> str:
    text = _string(value, label)
    if IMAGE_ID_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} must be a lowercase sha256 image ID")
    return text


def _git_object(value: Any, label: str) -> str:
    text = _string(value, label)
    if GIT_OBJECT_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} must be a 40-character lowercase Git object ID")
    return text


def _status(value: Any, label: str) -> str:
    text = _string(value, label)
    if text not in ALLOWED_STATUSES:
        raise EvidenceValidationError(f"{label} has an unsupported status")
    return text


def _timestamp(value: Any, label: str) -> datetime:
    text = _string(value, label)
    if not text or len(text) > 64:
        raise EvidenceValidationError(f"{label} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exception:
        raise EvidenceValidationError(f"{label} must be an RFC 3339 timestamp") from exception
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceValidationError(f"{label} must include a timezone")
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceValidationError(f"JSON object repeats field: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EvidenceValidationError(f"JSON contains a non-finite number: {value}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exception:
        raise EvidenceValidationError("evidence-bound file cannot be read") from exception
    return digest.hexdigest()


def load_document(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError("evidence document must be a regular non-symlink file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise EvidenceValidationError("evidence document exceeds the 2 MiB safety limit")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceValidationError("evidence document is missing or invalid JSON") from exception
    return _object(value, "evidence document")


def _validate_candidate(value: Any, *, require_complete: bool) -> dict[str, Any]:
    candidate = _object(value, "candidate")
    _exact_keys(candidate, CANDIDATE_FIELDS, "candidate")
    _git_object(candidate["head"], "candidate.head")
    _git_object(candidate["tree"], "candidate.tree")
    version = _string(candidate["version"], "candidate.version")
    if VERSION_PATTERN.fullmatch(version) is None or "snapshot" in version.lower():
        raise EvidenceValidationError("candidate.version must be a non-SNAPSHOT release version")
    clean = _boolean(candidate["cleanWorktree"], "candidate.cleanWorktree")
    if require_complete and not clean:
        raise EvidenceValidationError("candidate.cleanWorktree must be true for PASS")
    sources = _object(candidate["sourceSha256"], "candidate.sourceSha256")
    _exact_keys(sources, SOURCE_PATHS, "candidate.sourceSha256")
    for relative in SOURCE_PATHS:
        _sha256(sources[relative], f"candidate.sourceSha256[{relative}]")
    return candidate


def _validate_tool(value: Any, candidate: Mapping[str, Any]) -> None:
    tool = _object(value, "tool")
    _exact_keys(tool, TOOL_FIELDS, "tool")
    if tool["path"] != TOOL_PATH or tool["evidenceSchemaPath"] != SCHEMA_PATH:
        raise EvidenceValidationError("tool paths do not match the frozen AC-07 contract")
    tool_sha = _sha256(tool["sha256"], "tool.sha256")
    schema_sha = _sha256(tool["evidenceSchemaSha256"], "tool.evidenceSchemaSha256")
    sources = _object(candidate["sourceSha256"], "candidate.sourceSha256")
    if tool_sha != sources[TOOL_PATH] or schema_sha != sources[SCHEMA_PATH]:
        raise EvidenceValidationError("tool hashes do not match candidate source bindings")


def _validate_recovery(value: Any, candidate: Mapping[str, Any]) -> dict[str, Any]:
    recovery = _object(value, "recovery")
    status = _status(recovery.get("status"), "recovery.status")
    supplied = "evidenceSha256" in recovery or "validator" in recovery
    if supplied:
        _exact_keys(
            recovery,
            {"status", "statusDetail", "promotionAllowed", "evidenceSha256", "validator"},
            "recovery",
        )
        _sha256(recovery["evidenceSha256"], "recovery.evidenceSha256")
        validator = _object(recovery["validator"], "recovery.validator")
        _exact_keys(validator, AC40_VALIDATOR_FIELDS, "recovery.validator")
        if validator["path"] != AC40_VALIDATOR_PATH:
            raise EvidenceValidationError("recovery validator path is not the independent AC-40 validator")
        validator_sha = _sha256(validator["sha256"], "recovery.validator.sha256")
        sources = _object(candidate["sourceSha256"], "candidate.sourceSha256")
        if validator_sha != sources[AC40_VALIDATOR_PATH]:
            raise EvidenceValidationError("recovery validator hash does not match the candidate")
        for name in ("checkCount", "acceptanceCount", "phaseCount"):
            _integer(validator[name], f"recovery.validator.{name}", minimum=1)
        if recovery["statusDetail"] != f"AC40_INDEPENDENT_VALIDATION_{status}":
            raise EvidenceValidationError("recovery.statusDetail does not match its AC-40 status")
    else:
        _exact_keys(recovery, {"status", "statusDetail", "promotionAllowed", "reason"}, "recovery")
        if (
            status != "NOT_COVERED"
            or recovery["statusDetail"] != "AC40_EVIDENCE_NOT_SUPPLIED"
            or not isinstance(recovery["reason"], str)
            or not recovery["reason"]
        ):
            raise EvidenceValidationError("recovery without evidence must be explicit NOT_COVERED")
    promotion = _boolean(recovery["promotionAllowed"], "recovery.promotionAllowed")
    if promotion != (status == "PASS"):
        raise EvidenceValidationError("recovery.promotionAllowed does not match recovery.status")
    return recovery


def _validate_images(
    value: Any,
    candidate: Mapping[str, Any],
    expected_ids: Mapping[str, str | None],
    expected_app_digest: str | None,
    expected_app_reference: str | None,
) -> None:
    images = _object(value, "images")
    _exact_keys(images, IMAGE_ROLES, "images")
    for role in IMAGE_ROLES:
        image = _object(images[role], f"images.{role}")
        expected_fields = APP_IMAGE_FIELDS if role == "app" else INFRASTRUCTURE_IMAGE_FIELDS
        _exact_keys(image, expected_fields, f"images.{role}")
        image_id = _image_id(image["id"], f"images.{role}.id")
        _sha256(image["requestedReferenceSha256"], f"images.{role}.requestedReferenceSha256")
        expected = expected_ids.get(role)
        if expected is not None:
            _image_id(expected, f"expected {role} image ID")
            if image_id != expected:
                raise EvidenceValidationError(f"images.{role}.id does not match the expected image ID")
        if role == "app":
            requested_digest = _image_id(
                image["requestedDigest"], "images.app.requestedDigest"
            )
            if expected_app_digest is not None:
                expected_digest = _image_id(
                    expected_app_digest, "expected App manifest digest"
                )
                if requested_digest != expected_digest:
                    raise EvidenceValidationError(
                        "images.app.requestedDigest does not match the expected App manifest digest"
                    )
            if expected_app_reference is not None:
                expected_reference = _string(
                    expected_app_reference, "expected App digest reference"
                )
                match = DIGEST_BOUND_REFERENCE_PATTERN.fullmatch(expected_reference)
                if match is None:
                    raise EvidenceValidationError(
                        "expected App reference must be repository@sha256 digest-bound"
                    )
                if match.group("digest") != requested_digest:
                    raise EvidenceValidationError(
                        "images.app.requestedDigest does not match the expected App reference"
                    )
                reference_sha256 = hashlib.sha256(expected_reference.encode("utf-8")).hexdigest()
                if image["requestedReferenceSha256"] != reference_sha256:
                    raise EvidenceValidationError(
                        "images.app.requestedReferenceSha256 does not match the expected App reference"
                    )
            if image["ociVersion"] != candidate["version"]:
                raise EvidenceValidationError("App OCI version does not match candidate.version")
            if image["ociRevision"] != candidate["head"]:
                raise EvidenceValidationError("App OCI revision does not match candidate.head")


def _validate_resources(value: Any) -> str:
    resources = _object(value, "resources")
    _exact_keys(resources, RESOURCE_FIELDS, "resources")
    if resources["prefix"] != "web-starter-ac07-":
        raise EvidenceValidationError("resources.prefix is not frozen")
    run_id = _string(resources["runId"], "resources.runId")
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise EvidenceValidationError("resources.runId is malformed")
    if resources["network"] != f"web-starter-ac07-{run_id}":
        raise EvidenceValidationError("resources.network does not match resources.runId")
    containers = _object(resources["containers"], "resources.containers")
    _exact_keys(containers, CONTAINER_FIELDS, "resources.containers")
    for role in IMAGE_ROLES:
        if containers[role] != f"web-starter-ac07-{role}-{run_id}":
            raise EvidenceValidationError(f"resources.containers.{role} is not run-scoped")

    isolation = _object(resources["isolation"], "resources.isolation")
    _exact_keys(isolation, ISOLATION_FIELDS, "resources.isolation")
    expected_isolation = {
        "internalNetwork": True,
        "publishedHostPorts": 0,
        "dockerVolumeMounts": 0,
        "hostBindMounts": 1,
        "migrationBindReadOnly": True,
        "appRootFilesystemReadOnly": True,
        "immutableImageIds": True,
        "exactOwnershipLabels": True,
    }
    for name in (
        "internalNetwork", "migrationBindReadOnly", "appRootFilesystemReadOnly",
        "immutableImageIds", "exactOwnershipLabels",
    ):
        _boolean(isolation[name], f"resources.isolation.{name}")
    for name in ("publishedHostPorts", "dockerVolumeMounts", "hostBindMounts"):
        _integer(isolation[name], f"resources.isolation.{name}", minimum=0)
    if isolation != expected_isolation:
        raise EvidenceValidationError("resources.isolation does not prove the frozen private topology")

    cleanup = _object(resources["cleanup"], "resources.cleanup")
    _exact_keys(cleanup, CLEANUP_FIELDS, "resources.cleanup")
    if cleanup["exactLabelsVerifiedBeforeRemoval"] is not True or cleanup["complete"] is not True:
        raise EvidenceValidationError("resources.cleanup lacks exact ownership or completion")
    for name, expected in (("removed", True), ("residual", False)):
        values = _object(cleanup[name], f"resources.cleanup.{name}")
        _exact_keys(values, RESOURCE_BOOLEAN_FIELDS, f"resources.cleanup.{name}")
        for role in RESOURCE_BOOLEAN_FIELDS:
            if _boolean(values[role], f"resources.cleanup.{name}.{role}") is not expected:
                raise EvidenceValidationError(f"resources.cleanup.{name} is not complete")
    return run_id


def _validate_infrastructure(value: Any) -> None:
    infrastructure = _object(value, "infrastructure")
    _exact_keys(infrastructure, INFRASTRUCTURE_FIELDS, "infrastructure")
    _boolean(infrastructure["mysqlReady"], "infrastructure.mysqlReady")
    _boolean(infrastructure["redisReady"], "infrastructure.redisReady")
    _integer(infrastructure["hostPorts"], "infrastructure.hostPorts", minimum=0)
    _integer(infrastructure["sharedVolumes"], "infrastructure.sharedVolumes", minimum=0)
    if (
        infrastructure["mysqlReady"] is not True
        or infrastructure["redisReady"] is not True
        or infrastructure["hostPorts"] != 0
        or infrastructure["sharedVolumes"] != 0
    ):
        raise EvidenceValidationError("infrastructure does not prove ready isolated dependencies")
    attempts = _object(infrastructure["probeAttempts"], "infrastructure.probeAttempts")
    _exact_keys(attempts, PROBE_FIELDS, "infrastructure.probeAttempts")
    for role in PROBE_FIELDS:
        _integer(attempts[role], f"infrastructure.probeAttempts.{role}", minimum=1)


def _validate_migration(value: Any, run_id: str) -> dict[str, Any]:
    migration = _object(value, "migration")
    _exact_keys(migration, MIGRATION_FIELDS, "migration")
    if migration["version"] != "999999" or migration["file"] != "V999999__ac07_intentional_failure.sql":
        raise EvidenceValidationError("migration fixture identity is not frozen")
    expected_content = (
        "-- V2-AC-07 isolated intentional failure; never ship this file.\n"
        f"SELECT id FROM ac07_missing_{run_id};\n"
    ).encode("ascii")
    if migration["contentSha256"] != hashlib.sha256(expected_content).hexdigest():
        raise EvidenceValidationError("migration.contentSha256 does not match the run-scoped fixture")
    if migration["temporaryReadOnlyMount"] is not True or migration["persistedAfterRun"] is not False:
        raise EvidenceValidationError("migration fixture was not temporary and read-only")
    for name in (
        "successfulBaseRows", "successfulFailureVersionRows", "unsuccessfulFailureVersionRows",
        "totalFailureVersionRows", "latestSuccessfulVersion",
    ):
        _integer(migration[name], f"migration.{name}", minimum=0)
    return migration


def _validate_application(value: Any) -> dict[str, Any]:
    application = _object(value, "application")
    _exact_keys(application, APPLICATION_FIELDS, "application")
    _integer(application["exitCode"], "application.exitCode")
    _boolean(application["timedOut"], "application.timedOut")
    _integer(application["readinessAttempts"], "application.readinessAttempts", minimum=0)
    _integer(application["readinessSuccesses"], "application.readinessSuccesses", minimum=0)
    markers = _object(application["logMarkers"], "application.logMarkers")
    _exact_keys(markers, MARKER_FIELDS, "application.logMarkers")
    for name in MARKER_FIELDS:
        _integer(markers[name], f"application.logMarkers.{name}", minimum=0)
    return application


def _recomputed_failure_checks(
    application: Mapping[str, Any], migration: Mapping[str, Any]
) -> dict[str, bool]:
    markers = _object(application["logMarkers"], "application.logMarkers")
    return {
        "appExitedNonZero": application["exitCode"] != 0,
        "appCompletedBeforeTimeout": application["timedOut"] is False,
        "readinessNeverSucceeded": application["readinessSuccesses"] == 0,
        "applicationStartedMarkerAbsent": markers["applicationStarted"] == 0,
        "intentionalMigrationFailureObserved": markers["intentionalMigrationFailure"] > 0,
        "productionPolicyAcceptedFixture": markers["unsafeProductionConfiguration"] == 0,
        "baseMigrationsSucceeded": migration["successfulBaseRows"] > 0,
        "failedVersionNotRecordedSuccessful": migration["successfulFailureVersionRows"] == 0,
        "failureVersionHistoryConsistent": (
            migration["totalFailureVersionRows"]
            == migration["unsuccessfulFailureVersionRows"]
        ),
    }


def _validate_logs_and_policy(logs_value: Any, policy_value: Any) -> None:
    logs = _object(logs_value, "logs")
    _exact_keys(logs, LOG_FIELDS, "logs")
    if (
        logs["rawPersisted"] is not False
        or logs["fixtureMaterialPersisted"] is not False
        or logs["fixtureLeakDetected"] is not False
    ):
        raise EvidenceValidationError("logs violate the redacted public evidence policy")
    for role in IMAGE_ROLES:
        digest = _object(logs[role], f"logs.{role}")
        _exact_keys(digest, LOG_DIGEST_FIELDS, f"logs.{role}")
        _integer(digest["bytes"], f"logs.{role}.bytes", minimum=0)
        _sha256(digest["sha256"], f"logs.{role}.sha256")
    policy = _object(policy_value, "evidencePolicy")
    _exact_keys(policy, POLICY_FIELDS, "evidencePolicy")
    if policy != {"outsideRepository": True, "directoryMode": "0700", "fileMode": "0600"}:
        raise EvidenceValidationError("evidencePolicy does not match the private evidence contract")


def _outcome(failure_passed: bool, recovery_status: str) -> tuple[str, str]:
    if not failure_passed:
        return "FAIL", "FAILURE_PROTECTION_FAILED"
    if recovery_status == "PASS":
        return "PASS", "COMPLETE"
    if recovery_status == "FAIL":
        return "FAIL", "RECOVERY_FAILED"
    if recovery_status == "ENV_REQUIRED":
        return "ENV_REQUIRED", "RECOVERY_ENV_REQUIRED"
    return "NOT_COVERED", "PENDING_AC40"


def _secret_scan(document: Mapping[str, Any]) -> None:
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if any(pattern.search(encoded) for pattern in SECRET_PATTERNS):
        raise EvidenceValidationError("public AC-07 evidence contains secret-shaped material")


def validate_document(
    document: Any,
    *,
    expected_app_image_id: str | None = None,
    expected_mysql_image_id: str | None = None,
    expected_redis_image_id: str | None = None,
    expected_app_digest: str | None = None,
    expected_app_reference: str | None = None,
) -> dict[str, Any]:
    root = _object(document, "evidence document")
    _exact_keys(root, TOP_LEVEL_FIELDS, "evidence document")
    if root["schemaVersion"] != 1 or isinstance(root["schemaVersion"], bool):
        raise EvidenceValidationError("schemaVersion must equal integer 1")
    if root["acceptanceId"] != "V2-AC-07":
        raise EvidenceValidationError("acceptanceId must equal V2-AC-07")
    declared_status = _status(root["status"], "status")
    _timestamp(root["generatedAt"], "generatedAt")
    candidate = _validate_candidate(root["candidate"], require_complete=declared_status == "PASS")
    _validate_tool(root["tool"], candidate)
    recovery = _validate_recovery(root["recovery"], candidate)
    _validate_images(
        root["images"],
        candidate,
        {
            "app": expected_app_image_id,
            "mysql": expected_mysql_image_id,
            "redis": expected_redis_image_id,
        },
        expected_app_digest,
        expected_app_reference,
    )
    run_id = _validate_resources(root["resources"])
    _validate_infrastructure(root["infrastructure"])
    migration = _validate_migration(root["migration"], run_id)
    application = _validate_application(root["application"])
    _validate_logs_and_policy(root["logs"], root["evidencePolicy"])

    failure = _object(root["failureProtection"], "failureProtection")
    _exact_keys(failure, FAILURE_FIELDS, "failureProtection")
    if failure["status"] not in {"PASS", "FAIL"}:
        raise EvidenceValidationError("failureProtection.status must be PASS or FAIL")
    checks = _object(failure["checks"], "failureProtection.checks")
    _exact_keys(checks, FAILURE_CHECKS, "failureProtection.checks")
    recomputed_checks = _recomputed_failure_checks(application, migration)
    for name in FAILURE_CHECKS:
        _boolean(checks[name], f"failureProtection.checks.{name}")
    if checks != recomputed_checks:
        raise EvidenceValidationError("failureProtection checks do not match sanitized observations")
    failure_status = "PASS" if all(recomputed_checks.values()) else "FAIL"
    if failure["status"] != failure_status:
        raise EvidenceValidationError("failureProtection.status does not match recomputed checks")

    recovery_status = _status(recovery["status"], "recovery.status")
    recomputed_status, recomputed_detail = _outcome(failure_status == "PASS", recovery_status)
    if declared_status != recomputed_status or root["statusDetail"] != recomputed_detail:
        raise EvidenceValidationError("top-level status/detail do not match recomputed evidence")
    expected_exit = STATUS_EXIT_CODES[recomputed_status]
    if (
        isinstance(root["processExitCode"], bool)
        or not isinstance(root["processExitCode"], int)
        or root["processExitCode"] != expected_exit
    ):
        raise EvidenceValidationError("processExitCode does not match recomputed status")
    _secret_scan(root)
    return {
        "status": recomputed_status,
        "processExitCode": expected_exit,
        "checkCount": len(FAILURE_CHECKS),
        "recoveryEvidenceRequired": "evidenceSha256" in recovery,
    }


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _git(repository: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        completed = subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(repository), *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
    except OSError as exception:
        raise EvidenceValidationError("Git is required to bind PASS evidence") from exception
    if completed.returncode != 0:
        raise EvidenceValidationError("Git candidate query failed")
    return completed.stdout


def _resolve_repository(repository_root: Path) -> Path:
    expanded = repository_root.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise EvidenceValidationError("repository root must be a real directory")
    repository = expanded.resolve()
    try:
        top = Path(_git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve(
            strict=True
        )
    except (OSError, UnicodeDecodeError) as exception:
        raise EvidenceValidationError("Git returned an invalid repository root") from exception
    if top != repository:
        raise EvidenceValidationError("repository root must be the exact Git worktree top level")
    return repository


def _git_object_id(repository: Path, expression: str, label: str) -> str:
    try:
        value = _git(repository, "rev-parse", "--verify", expression).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError(f"{label} is not an ASCII Git object ID") from exception
    if GIT_OBJECT_PATTERN.fullmatch(value) is None:
        raise EvidenceValidationError(f"{label} is malformed")
    return value


def _require_clean_candidate(repository: Path) -> None:
    records = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if not records:
        raise EvidenceValidationError("Git candidate has no tracked files")
    if any(not record.startswith(b"H ") for record in records):
        raise EvidenceValidationError("Git candidate index contains hidden file state")
    if _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise EvidenceValidationError("Git candidate is not clean")


def _candidate_blob(repository: Path, head: str, relative: str) -> bytes:
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceValidationError(f"candidate source path is unsafe: {relative}")
    workspace = repository.joinpath(*path.parts)
    try:
        workspace_stat = workspace.lstat()
        resolved = workspace.resolve(strict=True)
    except OSError as exception:
        raise EvidenceValidationError(f"candidate source is missing: {relative}") from exception
    if not stat.S_ISREG(workspace_stat.st_mode) or workspace.is_symlink() or not _inside(resolved, repository):
        raise EvidenceValidationError(f"candidate source is not a regular file: {relative}")
    entries = [entry for entry in _git(repository, "ls-tree", "-z", head, "--", relative).split(b"\0") if entry]
    if len(entries) != 1:
        raise EvidenceValidationError(f"candidate commit does not contain: {relative}")
    metadata, separator, encoded_path = entries[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or encoded_path.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise EvidenceValidationError(f"candidate source is not a regular Git blob: {relative}")
    committed = _git(repository, "show", f"{head}:{relative}")
    try:
        current = workspace.read_bytes()
    except OSError as exception:
        raise EvidenceValidationError(f"candidate source cannot be read: {relative}") from exception
    if current != committed:
        raise EvidenceValidationError(f"candidate workspace bytes differ from commit: {relative}")
    return committed


def _committed_version(repository: Path, head: str) -> str:
    pom = _candidate_blob(repository, head, "pom.xml")
    package = _candidate_blob(repository, head, "web-starter-web/package.json")
    try:
        root = ElementTree.fromstring(pom)
        namespace = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
        version_element = root.find(f"{namespace}version")
        maven = version_element.text.strip() if version_element is not None and version_element.text else ""
        frontend = json.loads(package, object_pairs_hook=_unique_object)["version"]
    except (ElementTree.ParseError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exception:
        raise EvidenceValidationError("candidate version manifests are invalid") from exception
    if (
        not isinstance(frontend, str)
        or frontend != maven
        or VERSION_PATTERN.fullmatch(maven) is None
        or "snapshot" in maven.lower()
    ):
        raise EvidenceValidationError("candidate Maven/frontend version is not one non-SNAPSHOT release")
    return maven


def _validate_candidate_binding(candidate: Mapping[str, Any], repository_root: Path) -> None:
    repository = _resolve_repository(repository_root)
    head = _git_object_id(repository, "HEAD^{commit}", "candidate HEAD")
    tree = _git_object_id(repository, "HEAD^{tree}", "candidate tree")
    if candidate["head"] != head or candidate["tree"] != tree:
        raise EvidenceValidationError("evidence candidate does not match current Git HEAD/tree")
    if candidate["cleanWorktree"] is not True:
        raise EvidenceValidationError("PASS candidate must declare a clean worktree")
    _require_clean_candidate(repository)
    if candidate["version"] != _committed_version(repository, head):
        raise EvidenceValidationError("candidate.version does not match committed release manifests")
    sources = _object(candidate["sourceSha256"], "candidate.sourceSha256")
    for relative in SOURCE_PATHS:
        actual = hashlib.sha256(_candidate_blob(repository, head, relative)).hexdigest()
        if sources[relative] != actual:
            raise EvidenceValidationError(
                f"candidate.sourceSha256[{relative}] does not match current candidate bytes"
            )
    loaded_ac40 = Path(ac40_validator.__file__).resolve()
    expected_loaded = Path(__file__).resolve().with_name(AC40_VALIDATOR_PATH.rsplit("/", 1)[1])
    if loaded_ac40 != expected_loaded or _sha256_file(loaded_ac40) != sources[AC40_VALIDATOR_PATH]:
        raise EvidenceValidationError("executed AC-40 validator does not match candidate bytes")
    if (
        _git_object_id(repository, "HEAD^{commit}", "candidate HEAD") != head
        or _git_object_id(repository, "HEAD^{tree}", "candidate tree") != tree
    ):
        raise EvidenceValidationError("Git candidate identity changed during validation")
    _require_clean_candidate(repository)


def _validate_ac40_binding(
    recovery: Mapping[str, Any],
    ac40_evidence_path: Path | None,
    ac40_dependency_seed: Path | None,
    expected_ac40_dependency_seed_sha256: str | None,
    repository_root: Path,
) -> None:
    bound = "evidenceSha256" in recovery
    if not bound:
        if any(
            value is not None
            for value in (
                ac40_evidence_path,
                ac40_dependency_seed,
                expected_ac40_dependency_seed_sha256,
            )
        ):
            raise EvidenceValidationError(
                "unbound AC-40 evidence or dependency-seed input was supplied"
            )
        return
    if ac40_evidence_path is None:
        raise EvidenceValidationError("bound recovery evidence requires the actual AC-40 evidence path")
    if ac40_dependency_seed is None or expected_ac40_dependency_seed_sha256 is None:
        raise EvidenceValidationError(
            "bound recovery evidence requires the AC-40 dependency seed and external SHA-256 trust anchor"
        )
    expanded = ac40_evidence_path.expanduser().absolute()
    digest_before = _sha256_file(expanded)
    if digest_before != recovery["evidenceSha256"]:
        raise EvidenceValidationError("actual AC-40 evidence does not match recovery.evidenceSha256")
    try:
        summary = ac40_validator.validate_document_path(
            expanded,
            repository_root=repository_root,
            dependency_seed=ac40_dependency_seed,
            expected_dependency_seed_sha256=expected_ac40_dependency_seed_sha256,
            require_pass=False,
        )
    except ac40_validator.EvidenceValidationError as exception:
        raise EvidenceValidationError("actual AC-40 evidence failed independent validation") from exception
    digest_after = _sha256_file(expanded)
    if digest_after != digest_before:
        raise EvidenceValidationError("AC-40 evidence changed during independent validation")
    validator = _object(recovery["validator"], "recovery.validator")
    expected = {
        "status": recovery["status"],
        "checkCount": validator["checkCount"],
        "acceptanceCount": validator["acceptanceCount"],
        "phaseCount": validator["phaseCount"],
    }
    actual = {name: summary.get(name) for name in expected}
    if actual != expected:
        raise EvidenceValidationError("recovery summary does not match independent AC-40 validation")


def _validate_private_evidence_files(path: Path, repository_root: Path) -> tuple[dict[str, Any], str]:
    expanded = path.expanduser().absolute()
    if expanded.name != RESULT_NAME:
        raise EvidenceValidationError(f"evidence document must be named {RESULT_NAME}")
    document = load_document(expanded)
    resolved = expanded.resolve()
    repository = repository_root.expanduser().absolute().resolve()
    if _inside(resolved, repository) or _inside(repository, resolved.parent):
        raise EvidenceValidationError("evidence directory must be outside and must not contain the repository")
    if stat.S_IMODE(expanded.stat().st_mode) != 0o600:
        raise EvidenceValidationError("evidence document must have mode 0600")
    parent = expanded.parent
    if parent.is_symlink() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise EvidenceValidationError("evidence directory must be a real directory with mode 0700")
    checksum = parent / CHECKSUM_NAME
    if checksum.is_symlink() or not checksum.is_file() or stat.S_IMODE(checksum.stat().st_mode) != 0o600:
        raise EvidenceValidationError("evidence checksum sibling must be a regular mode 0600 file")
    if {entry.name for entry in parent.iterdir()} != {RESULT_NAME, CHECKSUM_NAME}:
        raise EvidenceValidationError("evidence directory must contain only the document and checksum sibling")
    digest = _sha256_file(expanded)
    try:
        expected_checksum = f"{digest}  {RESULT_NAME}\n"
        actual_checksum = checksum.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exception:
        raise EvidenceValidationError("evidence checksum sibling cannot be read") from exception
    if actual_checksum != expected_checksum:
        raise EvidenceValidationError("evidence checksum sibling does not match the document")
    return document, digest


def validate_document_path(
    path: Path,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    ac40_evidence_path: Path | None = None,
    ac40_dependency_seed: Path | None = None,
    expected_ac40_dependency_seed_sha256: str | None = None,
    expected_app_image_id: str | None = None,
    expected_mysql_image_id: str | None = None,
    expected_redis_image_id: str | None = None,
    expected_app_digest: str | None = None,
    expected_app_reference: str | None = None,
    require_pass: bool = False,
) -> dict[str, Any]:
    if require_pass:
        missing: list[str] = []
        for name, value in (
            ("expected App image ID", expected_app_image_id),
            ("expected MySQL image ID", expected_mysql_image_id),
            ("expected Redis image ID", expected_redis_image_id),
        ):
            if value is None:
                missing.append(name)
        if expected_app_digest is None and expected_app_reference is None:
            missing.append("expected App digest or digest-bound reference")
        if missing:
            raise EvidenceValidationError(
                "--require-pass needs independent release inputs: " + ", ".join(missing)
            )
    document, digest_before = _validate_private_evidence_files(path, repository_root)
    summary = validate_document(
        document,
        expected_app_image_id=expected_app_image_id,
        expected_mysql_image_id=expected_mysql_image_id,
        expected_redis_image_id=expected_redis_image_id,
        expected_app_digest=expected_app_digest,
        expected_app_reference=expected_app_reference,
    )
    recovery = _object(document["recovery"], "recovery")
    if summary["status"] == "PASS":
        _validate_candidate_binding(_object(document["candidate"], "candidate"), repository_root)
    _validate_ac40_binding(
        recovery,
        ac40_evidence_path,
        ac40_dependency_seed,
        expected_ac40_dependency_seed_sha256,
        repository_root,
    )
    if _sha256_file(path.expanduser().absolute()) != digest_before:
        raise EvidenceValidationError("AC-07 evidence changed during validation")
    if require_pass and summary["status"] != "PASS":
        raise EvidenceNotPassingError(summary["status"])
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Independently validate V2-AC-07 evidence without Docker or third-party packages"
    )
    result.add_argument("--document", required=True, type=Path)
    result.add_argument(
        "--repository-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="Git worktree whose clean HEAD/tree and committed bytes must match PASS evidence",
    )
    result.add_argument(
        "--ac40-evidence",
        type=Path,
        help="actual external V2-AC-40 evidence file bound by recovery.evidenceSha256",
    )
    result.add_argument(
        "--ac40-dependency-seed",
        type=Path,
        help=(
            "original private AC-40 dependency seed; required when recovery binds "
            "actual AC-40 evidence"
        ),
    )
    result.add_argument(
        "--expected-ac40-dependency-seed-sha256",
        help=(
            "external lowercase SHA-256 trust anchor for the independently rescanned "
            "AC-40 dependency seed"
        ),
    )
    result.add_argument("--expected-app-image-id")
    result.add_argument("--expected-mysql-image-id")
    result.add_argument("--expected-redis-image-id")
    result.add_argument("--expected-app-digest")
    result.add_argument(
        "--expected-app-reference",
        help="expected repository@sha256 App reference; binds both its hash and manifest digest",
    )
    result.add_argument(
        "--require-pass",
        action="store_true",
        help="return non-zero when a valid document is FAIL, NOT_COVERED, or ENV_REQUIRED",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_document_path(
            args.document,
            repository_root=args.repository_root,
            ac40_evidence_path=args.ac40_evidence,
            ac40_dependency_seed=args.ac40_dependency_seed,
            expected_ac40_dependency_seed_sha256=(
                args.expected_ac40_dependency_seed_sha256
            ),
            expected_app_image_id=args.expected_app_image_id,
            expected_mysql_image_id=args.expected_mysql_image_id,
            expected_redis_image_id=args.expected_redis_image_id,
            expected_app_digest=args.expected_app_digest,
            expected_app_reference=args.expected_app_reference,
            require_pass=args.require_pass,
        )
    except EvidenceNotPassingError as error:
        print(f"FAIL validate-migration-failure-evidence: {error}", file=sys.stderr)
        return STATUS_EXIT_CODES[error.status]
    except EvidenceValidationError as error:
        print(f"FAIL validate-migration-failure-evidence: {error}", file=sys.stderr)
        return 1
    print(
        "PASS validate-migration-failure-evidence: "
        f"status={summary['status']} checks={summary['checkCount']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
