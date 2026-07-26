#!/usr/bin/env python3
"""Independently validate V1 to V2 upgrade rehearsal evidence.

The producer and this gate deliberately do not share Python constants or
helpers.  A producer defect must not automatically become the verifier's
definition of success.  This module uses only the Python standard library and
does not contact Docker, a database, or the network.  A PASS additionally
requires the original private dependency-seed directory plus an externally
supplied SHA-256 trust anchor; the gate rescans that directory instead of
trusting the producer's public summary.

In addition to structural validation, the gate independently recomputes every
acceptance and top-level status, binds the two runtime container sets to the
resolved or built image IDs, and requires the refresh-token rotation/replay
proof when ``credential.preUpgradeRefreshRotationAccepted`` is reported as PASS.  File-level
validation additionally binds every top-level PASS to the current clean Git
HEAD/tree and the committed bytes of the declared V2 source snapshots.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_STATUSES = frozenset({"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"})
STATUS_EXIT_CODES = {
    "PASS": 0,
    "FAIL": 1,
    "NOT_COVERED": 6,
    "ENV_REQUIRED": 6,
}

TOP_LEVEL_FIELDS = frozenset({
    "schemaVersion",
    "acceptanceId",
    "status",
    "processExitCode",
    "generatedAt",
    "source",
    "run",
    "phases",
    "checks",
    "acceptance",
    "observations",
    "privateCommandLogs",
    "cleanup",
    "evidencePolicy",
})
SOURCE_FIELDS = frozenset({
    "v1Tag",
    "v1Commit",
    "toolPath",
    "toolSha256",
    "schemaPath",
    "schemaSha256",
    "v2Commit",
    "v2Tree",
    "cleanWorktree",
    "currentAdapterSnapshotSha256",
    "runtimeSourceSha256",
    "inputImageReferences",
    "resolvedImageIds",
    "builtV1ImageIds",
    "builtV2ImageIds",
    "dependencySeed",
})
RUN_FIELDS = frozenset({
    "runId",
    "composeProject",
    "sourceDatabase",
    "targetDatabase",
    "publishedPortCount",
    "loopbackOnly",
    "containerImageIds",
})
PHASE_FIELDS = frozenset({"name", "status", "startedAt", "finishedAt", "detailCode"})
CHECK_FIELDS = frozenset({"status", "detailCode"})
ACCEPTANCE_FIELDS = frozenset({"status"})
PRIVATE_LOG_FIELDS = frozenset({"persisted", "count", "aggregateSha256"})
CLEANUP_FIELDS = frozenset({
    "status",
    "exactOwnershipVerified",
    "removed",
    "residual",
    "failureCodes",
    "privateRuntimeRemoved",
})
REMOVED_FIELDS = frozenset({"containers", "volumes", "networks", "imageTags", "images"})
RESIDUAL_FIELDS = frozenset({"containers", "volumes", "networks", "imageTags", "images"})
EVIDENCE_POLICY_FIELDS = frozenset({
    "outsideRepository",
    "directoryMode",
    "fileMode",
    "containsSecrets",
    "privateRuntimePersisted",
})

V1_TAG = "v1.0.0"
V1_COMMIT = "5ebdb238650d182c17e1493adf47aaa3324f19cb"
TOOL_PATH = "scripts/rehearse_v1_to_v2_upgrade.py"
SCHEMA_PATH = "security/v2-v1-upgrade-rehearsal.schema.json"

CURRENT_ADAPTER_FILES = (
    "scripts/__init__.py",
    "scripts/acceptance_network.py",
    "scripts/generated_module_plan.py",
    "scripts/prepare_release_runtime_acceptance.py",
    "scripts/recovery_common.py",
    "scripts/recovery_backup.py",
    "scripts/recovery_restore.py",
    "scripts/verify_oauth_runtime.py",
    "scripts/acceptance_jwk_set.py",
    "scripts/v1_upgrade_refresh.py",
    "scripts/validate_v1_upgrade_evidence.py",
)

INPUT_IMAGE_ROLES = ("mysql", "redis")
V2_IMAGE_ROLES = ("v2-app", "v2-nginx")
RESOLVED_IMAGE_ROLES = (*V2_IMAGE_ROLES, *INPUT_IMAGE_ROLES)
V1_IMAGE_ROLES = ("v1-app", "v1-nginx")
RUNTIME_GENERATIONS = ("v1", "v2")
SERVICE_IMAGE_ROLES = ("mysql", "redis", "app", "nginx", "mcp-public-nginx")

RUNTIME_SOURCE_FILES = (
    ".dockerignore",
    "Dockerfile",
    "compose.production.yaml",
    "deploy/nginx/Dockerfile",
    "deploy/nginx/nginx.conf",
    "deploy/nginx/nginx-public.conf",
    "deploy/nginx/default.conf",
    "deploy/nginx/external-mcp.conf",
    "deploy/nginx/forwarded-maps.conf",
    "deploy/nginx/proxy-headers.conf",
    "pom.xml",
    "web-starter-core/pom.xml",
    "web-starter-system/pom.xml",
    "web-starter-security/pom.xml",
    "web-starter-project/pom.xml",
    "web-starter-mcp/pom.xml",
    ".mvn/wrapper/maven-wrapper.properties",
    "mvnw",
    "web-starter-admin/src/main/resources/db/migration/V4__add_identity_security_epoch.sql",
    "web-starter-admin/src/main/resources/db/migration/V5__add_mcp_idempotency.sql",
    "web-starter-admin/src/main/resources/db/migration/V6__add_mcp_idempotency_audit.sql",
    "web-starter-admin/src/main/resources/db/migration/V7__add_credential_rotation.sql",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
    "McpSdkProjectListRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkCrudRuntimeIT.java",
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
    "web-starter-web/playwright.config.ts",
    "web-starter-web/e2e/frontend-quality-runtime.spec.ts",
    "web-starter-web/e2e/release-runtime.spec.ts",
    "web-starter-web/e2e/v1-management-runtime.spec.ts",
)

DEPENDENCY_SEED_SOURCE_FILES = (
    "pom.xml",
    "web-starter-core/pom.xml",
    "web-starter-system/pom.xml",
    "web-starter-security/pom.xml",
    "web-starter-project/pom.xml",
    "web-starter-mcp/pom.xml",
    ".mvn/wrapper/maven-wrapper.properties",
    "mvnw",
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
    "web-starter-web/playwright.config.ts",
)
DEPENDENCY_SEED_COMPONENTS = (
    "mavenHome",
    "mavenRepository",
    "corepackHome",
    "pnpmStore",
    "playwrightBrowsers",
)
DEPENDENCY_SEED_COMPONENT_PATHS = {
    "mavenHome": "maven-home",
    "mavenRepository": "maven-repository",
    "corepackHome": "corepack-home",
    "pnpmStore": "pnpm-store",
    "playwrightBrowsers": "playwright-browsers",
}
DEPENDENCY_SEED_FIELDS = frozenset({
    "kind", "schemaVersion", "platform", "architecture", "versions",
    "sourceSha256", "components", "manifestSha256", "aggregateSha256",
    "copiedToPrivateRuntime", "executionPolicy",
})
DEPENDENCY_SEED_COMPONENT_FIELDS = frozenset({"treeSha256", "fileCount", "byteCount"})
DEPENDENCY_SEED_VERSIONS = {
    "maven": "3.9.15",
    "pnpm": "9.15.9",
    "playwright": "1.61.1",
    "chromiumRevision": "1228",
}
DEPENDENCY_SEED_EXECUTION_POLICY = {
    "privateCopyOnly": True,
    "mavenOffline": True,
    "pnpmOffline": True,
    "corepackNetworkDisabled": True,
    "browserDownloadsDisabled": True,
    "dependencyRetries": 0,
}
DEPENDENCY_SEED_MANIFEST_FIELDS = frozenset({
    "schemaVersion", "kind", "platform", "architecture", "versions",
    "sourceSha256", "components",
})
DEPENDENCY_SEED_MANIFEST_COMPONENT_FIELDS = frozenset({
    "path", "treeSha256", "fileCount", "byteCount",
})
INCOMPLETE_DEPENDENCY_SEED_SUFFIXES = frozenset({
    ".lastupdated", ".part", ".partial", ".tmp", ".lock", ".download", ".aria2",
})

V1_MIGRATION_FILES = (
    "web-starter-admin/src/main/resources/db/migration/V1__create_core_schema.sql",
    "web-starter-admin/src/main/resources/db/migration/V2__seed_reference_data.sql",
    "web-starter-admin/src/main/resources/db/migration/"
    "V3__add_oauth_refresh_token_families.sql",
)
V2_ONLY_MIGRATION_FILES = (
    "web-starter-admin/src/main/resources/db/migration/V4__add_identity_security_epoch.sql",
    "web-starter-admin/src/main/resources/db/migration/V5__add_mcp_idempotency.sql",
    "web-starter-admin/src/main/resources/db/migration/V6__add_mcp_idempotency_audit.sql",
    "web-starter-admin/src/main/resources/db/migration/V7__add_credential_rotation.sql",
)
V2_MIGRATION_FILES = V1_MIGRATION_FILES + V2_ONLY_MIGRATION_FILES
FLYWAY_HISTORY_FIELDS = frozenset({
    "installedRank", "version", "description", "type", "script",
    "checksum", "success", "scriptSha256",
})

REQUIRED_CHECKS = (
    "source.annotatedV1Tag",
    "source.fixedV1Commit",
    "source.v1TagAdapterBoundary",
    "source.v1MigrationBytes",
    "preflight.requiredCommands",
    "preflight.frozenScriptImports",
    "preflight.composeConfiguration",
    "preflight.publishedPorts",
    "preflight.composeProjectIsolation",
    "preflight.databaseIsolation",
    "keys.v1Pkcs8Der",
    "keys.v1KidCaptured",
    "backup.consistentPackage",
    "restore.newDatabaseVerified",
    "migration.flywayOneThroughSeven",
    "migration.v1RowsPreserved",
    "migration.v1ProjectionPreserved",
    "oauth.preUpgradeUserAuthorizationAccepted",
    "oauth.oldKidPublicOnly",
    "oauth.newKidActiveSigning",
    "oauth.preUpgradeClientCredentialAccepted",
    "oauth.freshClientCredentials",
    "credential.oldPatRead",
    "credential.oldPatCrud",
    "credential.preUpgradeServiceAccessAccepted",
    "credential.preUpgradeRefreshRotationAccepted",
    "compatibility.restProjectCrud",
    "compatibility.mcpReadAndDiscovery",
    "authorization.permissionDenied",
    "browser.playwright",
    "mcp.crudIdempotencyAudit",
    "audit.traceSearch",
    "lifecycle.revokedPatRejectedAndReadBack",
    "lifecycle.disabledServiceRejectedAndReadBack",
    "integrity.finalSource",
    "cleanup.exactOwnedResources",
)

ACCEPTANCE_IDS = (
    "V2-AC-04",
    "V2-AC-05",
    "V2-AC-06",
    "V2-AC-39",
    "V2-AC-40",
)

ACCEPTANCE_GROUPS = {
    "V2-AC-04": (
        "backup.consistentPackage",
        "restore.newDatabaseVerified",
        "migration.flywayOneThroughSeven",
        "migration.v1RowsPreserved",
        "migration.v1ProjectionPreserved",
        "integrity.finalSource",
    ),
    "V2-AC-05": (
        "oauth.preUpgradeUserAuthorizationAccepted",
        "oauth.oldKidPublicOnly",
        "oauth.newKidActiveSigning",
        "oauth.preUpgradeClientCredentialAccepted",
        "oauth.freshClientCredentials",
        "credential.oldPatRead",
        "credential.oldPatCrud",
        "credential.preUpgradeServiceAccessAccepted",
        "credential.preUpgradeRefreshRotationAccepted",
        "lifecycle.revokedPatRejectedAndReadBack",
        "lifecycle.disabledServiceRejectedAndReadBack",
        "integrity.finalSource",
    ),
    "V2-AC-06": (
        "compatibility.restProjectCrud",
        "compatibility.mcpReadAndDiscovery",
        "authorization.permissionDenied",
        "integrity.finalSource",
    ),
    "V2-AC-39": ("audit.traceSearch", "integrity.finalSource"),
    "V2-AC-40": REQUIRED_CHECKS,
}

PHASE_ORDER = (
    "source-freeze",
    "cryptographic-preflight",
    "runtime-preflight",
    "v1-fixtures",
    "backup-restore",
    "v2-migration",
    "credential-compatibility",
    "runtime-acceptance",
    "lifecycle-readback",
    "cleanup",
)

PHASE_PASS_DETAILS = {
    "source-freeze": "SOURCE_AND_TOOLS_FROZEN",
    "cryptographic-preflight": "PORTABLE_KEY_PREFLIGHT_PASS",
    "runtime-preflight": "FORMAL_PREFLIGHT_PASS",
    "v1-fixtures": "V1_FIXTURES_AND_PROJECTION_CAPTURED",
    "backup-restore": "BACKUP_AND_RESTORE_PASS",
    "v2-migration": "MIGRATION_AND_DATA_PRESERVATION_PASS",
    "credential-compatibility": "OLD_AND_NEW_CREDENTIALS_PASS",
    "runtime-acceptance": "BROWSER_REST_MCP_ACCEPTANCE_PASS",
    "lifecycle-readback": "FINAL_LIFECYCLE_READBACK_PASS",
    "cleanup": "EXACT_OWNED_CLEANUP_PASS",
}

CHECK_PASS_DETAILS = {
    "source.annotatedV1Tag": "ANNOTATED_TAG_VERIFIED",
    "source.fixedV1Commit": "FIXED_COMMIT_VERIFIED",
    "source.v1TagAdapterBoundary": "V1_TAG_HAS_NO_RUNTIME_ADAPTERS",
    "source.v1MigrationBytes": "V1_MIGRATIONS_BYTE_EQUAL",
    "preflight.requiredCommands": "COMMANDS_AVAILABLE",
    "preflight.frozenScriptImports": "EXPLICIT_PATH_IMPORTS_PASS",
    "preflight.composeConfiguration": "V1_V2_CONFIG_EXACT_SET",
    "preflight.publishedPorts": "PORTS_UNUSED_AND_UNIQUE",
    "preflight.composeProjectIsolation": "PROJECT_AND_RUN_LABEL_SETS_EMPTY",
    "preflight.databaseIsolation": "RANDOM_NEW_DATABASE_NAMES",
    "keys.v1Pkcs8Der": "PKCS8_GENERATE_DECODE_ROUNDTRIP",
    "keys.v1KidCaptured": "V1_KID_FROM_ISSUED_JWT",
    "backup.consistentPackage": "NO_WRITER_BACKUP_VERIFIED",
    "restore.newDatabaseVerified": "NEW_DATABASE_RESTORE_VERIFIED",
    "migration.flywayOneThroughSeven": "FLYWAY_EXACT_1_TO_7",
    "migration.v1RowsPreserved": "V1_ROW_DIGESTS_PRESERVED",
    "migration.v1ProjectionPreserved": "V1_ALL_COLUMNS_EXACT_OR_AUDIT_APPEND_ONLY",
    "oauth.preUpgradeUserAuthorizationAccepted": "OLD_PKCE_TOKEN_FIRST_EXTERNAL_CALL",
    "oauth.oldKidPublicOnly": "MULTI_KEY_AND_OLD_CLIENT_PASS",
    "oauth.newKidActiveSigning": "MULTI_KEY_AND_OLD_CLIENT_PASS",
    "oauth.preUpgradeClientCredentialAccepted": "MULTI_KEY_AND_OLD_CLIENT_PASS",
    "oauth.freshClientCredentials": "MULTI_KEY_AND_OLD_CLIENT_PASS",
    "credential.oldPatRead": "V1_PAT_READ_AND_FORBIDDEN_PASS",
    "credential.oldPatCrud": "V1_PAT_CRUD_PASS",
    "credential.preUpgradeServiceAccessAccepted": "V1_SERVICE_TOKEN_PASS",
    "credential.preUpgradeRefreshRotationAccepted": "V1_REFRESH_ROTATION_REUSE_PASS",
    "compatibility.restProjectCrud": "PLAYWRIGHT_REAL_BROWSER_PASS",
    "compatibility.mcpReadAndDiscovery": "OLD_OAUTH_MCP_DISCOVERY_PASS",
    "authorization.permissionDenied": "PLAYWRIGHT_REAL_BROWSER_PASS",
    "browser.playwright": "PLAYWRIGHT_REAL_BROWSER_PASS",
    "mcp.crudIdempotencyAudit": "MCP_CRUD_REPLAY_CONFLICT_AUDIT_PASS",
    "audit.traceSearch": "AUDIT_FILTER_CORRELATION_REDACTION_PASS",
    "lifecycle.revokedPatRejectedAndReadBack": "REVOKED_PAT_DATABASE_READBACK_PASS",
    "lifecycle.disabledServiceRejectedAndReadBack": "DISABLED_SERVICE_401_AND_READBACK_PASS",
    "integrity.finalSource": "FINAL_SOURCE_IDENTITY_VERIFIED",
    "cleanup.exactOwnedResources": "EXACT_OWNED_CLEANUP_PASS",
}

PHASE_REQUIRED_CHECKS: Mapping[str, tuple[str, ...]] = {
    "source-freeze": (
        "source.annotatedV1Tag",
        "source.fixedV1Commit",
        "source.v1TagAdapterBoundary",
        "source.v1MigrationBytes",
    ),
    "cryptographic-preflight": (
        "preflight.requiredCommands",
        "preflight.frozenScriptImports",
        "keys.v1Pkcs8Der",
    ),
    "runtime-preflight": (
        "preflight.composeConfiguration",
        "preflight.publishedPorts",
        "preflight.composeProjectIsolation",
        "preflight.databaseIsolation",
    ),
    "v1-fixtures": ("keys.v1KidCaptured",),
    "backup-restore": ("backup.consistentPackage", "restore.newDatabaseVerified"),
    "v2-migration": (
        "migration.flywayOneThroughSeven",
        "migration.v1RowsPreserved",
        "migration.v1ProjectionPreserved",
    ),
    "credential-compatibility": (
        "oauth.preUpgradeUserAuthorizationAccepted",
        "oauth.oldKidPublicOnly",
        "oauth.newKidActiveSigning",
        "oauth.preUpgradeClientCredentialAccepted",
        "oauth.freshClientCredentials",
        "credential.oldPatRead",
        "credential.preUpgradeServiceAccessAccepted",
        "credential.preUpgradeRefreshRotationAccepted",
        "compatibility.mcpReadAndDiscovery",
    ),
    "runtime-acceptance": (
        "credential.oldPatCrud",
        "compatibility.restProjectCrud",
        "authorization.permissionDenied",
        "browser.playwright",
        "mcp.crudIdempotencyAudit",
        "audit.traceSearch",
    ),
    "lifecycle-readback": (
        "lifecycle.revokedPatRejectedAndReadBack",
        "lifecycle.disabledServiceRejectedAndReadBack",
        "integrity.finalSource",
    ),
    "cleanup": ("cleanup.exactOwnedResources",),
}

OBSERVATION_BASE_FIELDS = frozenset({
    "v1MigrationSha256",
    "v1TableCount",
    "v2TableCount",
    "v1ProjectionCount",
    "flywayVersions",
    "flywayHistory",
    "credentialTypesCapturedBeforeUpgrade",
})
OBSERVATION_OPTIONAL_FIELDS = frozenset({"mcpSdkSurefire", "playwright"})
SDK_OBSERVATION_FIELDS = frozenset({
    "testClass",
    "tests",
    "failures",
    "errors",
    "skipped",
    "reportSha256",
    "testSourceSha256",
    "rootPomSha256",
    "modulePomSha256",
})
PLAYWRIGHT_OBSERVATION_FIELDS = frozenset({
    "tests", "failures", "skipped", "flaky", "reportSha256",
    "packageJsonSha256", "lockfileSha256", "configSha256", "testSourceSha256",
})
PLAYWRIGHT_TEST_SOURCES = (
    "web-starter-web/e2e/frontend-quality-runtime.spec.ts",
    "web-starter-web/e2e/release-runtime.spec.ts",
    "web-starter-web/e2e/v1-management-runtime.spec.ts",
)
SDK_CLASS_SOURCE = {
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java"
    ),
    "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/"
        "McpSdkProjectListRuntimeIT.java"
    ),
    "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT": (
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkCrudRuntimeIT.java"
    ),
}
SDK_CLASS_ORDER = (
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT",
)

SDK_MINIMUM_REPORTS_BY_CHECK = (
    ("keys.v1KidCaptured", 1),
    ("oauth.preUpgradeUserAuthorizationAccepted", 3),
    ("credential.preUpgradeRefreshRotationAccepted", 3),
    ("compatibility.mcpReadAndDiscovery", 4),
    ("credential.oldPatRead", 5),
    ("credential.preUpgradeServiceAccessAccepted", 6),
    ("credential.oldPatCrud", 7),
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
DETAIL_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
FAILURE_CODE_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{2,95}$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        r"[\"']?(?:password|access_token|refresh_token|client_secret|code_verifier|cookie)"
        r"[\"']?\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:pat|svc)_[0-9A-Za-z_-]{16,}\b", re.IGNORECASE),
)


class EvidenceValidationError(ValueError):
    """The public evidence does not match the independent frozen contract."""


class EvidenceNotPassingError(EvidenceValidationError):
    """A valid evidence document did not satisfy an explicit PASS gate."""

    def __init__(self, status: str) -> None:
        super().__init__(f"evidence status is {status}; PASS is required")
        self.status = status


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    required = set(expected)
    if actual == required:
        return
    details: list[str] = []
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing:
        details.append("missing=" + ",".join(missing))
    if unknown:
        details.append("unknown=" + ",".join(unknown))
    raise EvidenceValidationError(f"{label} fields are not exact ({'; '.join(details)})")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceValidationError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{label} must be a string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceValidationError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceValidationError(f"{label} must be an integer >= {minimum}")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} must be a lowercase SHA-256")
    return text


def _git_object(value: Any, label: str) -> str:
    text = _string(value, label)
    if GIT_OBJECT_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} must be a 40-character lowercase Git object ID")
    return text


def _image_id(value: Any, label: str) -> str:
    text = _string(value, label)
    if IMAGE_ID_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} must be a lowercase sha256 image ID")
    return text


def _image_reference(value: Any, label: str) -> str:
    text = _string(value, label)
    if IMAGE_REFERENCE_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} is not a canonical image reference")
    if text.lower().startswith("sha256:"):
        raise EvidenceValidationError(f"{label} must not be a naked sha256 image ID alias")
    return text


def _nullable_sha256(value: Any, label: str, *, require_value: bool) -> str | None:
    if value is None:
        if require_value:
            raise EvidenceValidationError(f"{label} must be present for PASS")
        return None
    return _sha256(value, label)


def _nullable_git_object(value: Any, label: str, *, require_value: bool) -> str | None:
    if value is None:
        if require_value:
            raise EvidenceValidationError(f"{label} must be present for PASS")
        return None
    return _git_object(value, label)


def _known_subset_keys(
    value: Mapping[str, Any],
    expected: Iterable[str],
    label: str,
    *,
    require_complete: bool,
) -> None:
    allowed = set(expected)
    actual = set(value)
    unknown = sorted(actual - allowed)
    if unknown:
        raise EvidenceValidationError(f"{label} contains unknown keys: {','.join(unknown)}")
    if require_complete and actual != allowed:
        missing = sorted(allowed - actual)
        raise EvidenceValidationError(
            f"{label} must be exact for PASS (missing={','.join(missing)})"
        )


def _validate_hash_map(
    value: Any,
    expected: Sequence[str],
    label: str,
    *,
    require_complete: bool,
) -> dict[str, Any]:
    result = _object(value, label)
    _known_subset_keys(result, expected, label, require_complete=require_complete)
    for name, digest in result.items():
        _sha256(digest, f"{label}[{name}]")
    return result


def _validate_image_map(
    value: Any,
    expected: Sequence[str],
    label: str,
    *,
    require_complete: bool,
) -> dict[str, Any]:
    result = _object(value, label)
    _known_subset_keys(result, expected, label, require_complete=require_complete)
    for name, image_id in result.items():
        _image_id(image_id, f"{label}[{name}]")
    return result


def _status(value: Any, label: str) -> str:
    text = _string(value, label)
    if text not in ALLOWED_STATUSES:
        raise EvidenceValidationError(f"{label} has an unsupported status")
    return text


def _detail_code(value: Any, label: str) -> str:
    text = _string(value, label)
    if DETAIL_CODE_PATTERN.fullmatch(text) is None:
        raise EvidenceValidationError(f"{label} has an invalid detail code")
    return text


def _timestamp(value: Any, label: str, *, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    text = _string(value, label)
    if len(text) > 64:
        raise EvidenceValidationError(f"{label} is too long")
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


def load_document(path: Path) -> dict[str, Any]:
    """Load a JSON object while rejecting duplicate keys and unsafe input."""
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError("evidence document must be a regular non-symlink file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise EvidenceValidationError("evidence document exceeds the 2 MiB safety limit")
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceValidationError("evidence document is missing or invalid JSON") from exception
    return _object(value, "evidence document")


def _aggregate_status(statuses: Sequence[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if "ENV_REQUIRED" in statuses:
        return "ENV_REQUIRED"
    if statuses and all(value == "PASS" for value in statuses):
        return "PASS"
    return "NOT_COVERED"


def _validate_dependency_seed(
    value: Any,
    runtime_source_hashes: Mapping[str, Any],
    *,
    require_complete: bool,
) -> dict[str, Any]:
    seed = _object(value, "source.dependencySeed")
    if not seed:
        if require_complete:
            raise EvidenceValidationError(
                "source.dependencySeed must be complete for PASS"
            )
        return seed
    _exact_keys(seed, DEPENDENCY_SEED_FIELDS, "source.dependencySeed")
    if seed["schemaVersion"] != 1 or isinstance(seed["schemaVersion"], bool):
        raise EvidenceValidationError("source.dependencySeed.schemaVersion must equal 1")
    if seed["kind"] != "web-starter-ac40-dependency-seed":
        raise EvidenceValidationError("source.dependencySeed.kind is not frozen")
    platform_name = _string(seed["platform"], "source.dependencySeed.platform")
    architecture = _string(seed["architecture"], "source.dependencySeed.architecture")
    if platform_name not in {"darwin", "linux", "win32"} or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{1,31}", architecture
    ) is None:
        raise EvidenceValidationError("source.dependencySeed platform identity is unsupported")
    if seed["versions"] != DEPENDENCY_SEED_VERSIONS:
        raise EvidenceValidationError("source.dependencySeed versions are not the frozen exact set")

    source_hashes = _object(
        seed["sourceSha256"], "source.dependencySeed.sourceSha256"
    )
    _exact_keys(
        source_hashes,
        DEPENDENCY_SEED_SOURCE_FILES,
        "source.dependencySeed.sourceSha256",
    )
    for relative in DEPENDENCY_SEED_SOURCE_FILES:
        digest = _sha256(
            source_hashes[relative],
            f"source.dependencySeed.sourceSha256[{relative}]",
        )
        runtime_digest = runtime_source_hashes.get(relative)
        if (require_complete and runtime_digest is None) or (
            runtime_digest is not None and runtime_digest != digest
        ):
            raise EvidenceValidationError(
                "source.dependencySeed source binding does not match runtimeSourceSha256"
            )

    components = _object(seed["components"], "source.dependencySeed.components")
    _exact_keys(components, DEPENDENCY_SEED_COMPONENTS, "source.dependencySeed.components")
    for name in DEPENDENCY_SEED_COMPONENTS:
        component = _object(
            components[name], f"source.dependencySeed.components[{name}]"
        )
        _exact_keys(
            component,
            DEPENDENCY_SEED_COMPONENT_FIELDS,
            f"source.dependencySeed.components[{name}]",
        )
        _sha256(
            component["treeSha256"],
            f"source.dependencySeed.components[{name}].treeSha256",
        )
        _integer(
            component["fileCount"],
            f"source.dependencySeed.components[{name}].fileCount",
            minimum=1,
        )
        _integer(
            component["byteCount"],
            f"source.dependencySeed.components[{name}].byteCount",
            minimum=1,
        )
    _sha256(seed["manifestSha256"], "source.dependencySeed.manifestSha256")
    aggregate_sha256 = _sha256(
        seed["aggregateSha256"], "source.dependencySeed.aggregateSha256"
    )
    if _boolean(
        seed["copiedToPrivateRuntime"],
        "source.dependencySeed.copiedToPrivateRuntime",
    ) is not True:
        raise EvidenceValidationError(
            "source.dependencySeed must prove a verified private runtime copy"
        )
    policy = _object(seed["executionPolicy"], "source.dependencySeed.executionPolicy")
    if policy != DEPENDENCY_SEED_EXECUTION_POLICY:
        raise EvidenceValidationError(
            "source.dependencySeed execution policy is not exact offline-only policy"
        )
    aggregate_payload = {
        "kind": seed["kind"],
        "schemaVersion": seed["schemaVersion"],
        "platform": platform_name,
        "architecture": architecture,
        "versions": seed["versions"],
        "sourceSha256": source_hashes,
        "components": components,
    }
    expected_aggregate = hashlib.sha256(json.dumps(
        aggregate_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    if aggregate_sha256 != expected_aggregate:
        raise EvidenceValidationError(
            "source.dependencySeed aggregateSha256 does not match its public fields"
        )
    return seed


def _validate_source(value: Any, *, require_complete: bool) -> dict[str, Any]:
    source = _object(value, "source")
    _exact_keys(source, SOURCE_FIELDS, "source")
    constants = {
        "v1Tag": V1_TAG,
        "v1Commit": V1_COMMIT,
        "toolPath": TOOL_PATH,
        "schemaPath": SCHEMA_PATH,
    }
    for name, expected in constants.items():
        if source[name] != expected:
            raise EvidenceValidationError(f"source.{name} does not match the frozen value")
    _nullable_sha256(
        source["toolSha256"], "source.toolSha256", require_value=require_complete
    )
    _nullable_sha256(
        source["schemaSha256"], "source.schemaSha256", require_value=require_complete
    )
    _nullable_git_object(
        source["v2Commit"], "source.v2Commit", require_value=require_complete
    )
    _nullable_git_object(
        source["v2Tree"], "source.v2Tree", require_value=require_complete
    )
    clean_worktree = _boolean(source["cleanWorktree"], "source.cleanWorktree")
    if require_complete and not clean_worktree:
        raise EvidenceValidationError("source.cleanWorktree must be true for PASS")

    _validate_hash_map(
        source["currentAdapterSnapshotSha256"],
        CURRENT_ADAPTER_FILES,
        "source.currentAdapterSnapshotSha256",
        require_complete=require_complete,
    )
    _validate_hash_map(
        source["runtimeSourceSha256"],
        RUNTIME_SOURCE_FILES,
        "source.runtimeSourceSha256",
        require_complete=require_complete,
    )
    _validate_dependency_seed(
        source["dependencySeed"],
        _object(source["runtimeSourceSha256"], "source.runtimeSourceSha256"),
        require_complete=require_complete,
    )

    input_references = _object(source["inputImageReferences"], "source.inputImageReferences")
    _known_subset_keys(
        input_references,
        INPUT_IMAGE_ROLES,
        "source.inputImageReferences",
        require_complete=require_complete,
    )
    for name, reference in input_references.items():
        _image_reference(reference, f"source.inputImageReferences[{name}]")

    resolved = _validate_image_map(
        source["resolvedImageIds"],
        RESOLVED_IMAGE_ROLES,
        "source.resolvedImageIds",
        require_complete=require_complete,
    )
    built_v1 = _validate_image_map(
        source["builtV1ImageIds"],
        V1_IMAGE_ROLES,
        "source.builtV1ImageIds",
        require_complete=require_complete,
    )
    built_v2 = _validate_image_map(
        source["builtV2ImageIds"],
        V2_IMAGE_ROLES,
        "source.builtV2ImageIds",
        require_complete=require_complete,
    )
    missing_references = sorted((set(resolved) & set(INPUT_IMAGE_ROLES)) - set(input_references))
    if missing_references:
        raise EvidenceValidationError(
            "source.resolvedImageIds lacks matching input image references: "
            + ",".join(missing_references)
        )
    for role, image_id in built_v2.items():
        if resolved.get(role) != image_id:
            raise EvidenceValidationError(
                f"source.resolvedImageIds[{role}] is not cross-bound to source.builtV2ImageIds"
            )
    return source


def _validate_run(
    value: Any,
    source: Mapping[str, Any],
    *,
    require_complete: bool,
) -> dict[str, Any]:
    run = _object(value, "run")
    _exact_keys(run, RUN_FIELDS, "run")
    run_id = _string(run["runId"], "run.runId")
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise EvidenceValidationError("run.runId must be twelve lowercase hexadecimal characters")
    expected = {
        "composeProject": f"web-starter-ac40-{run_id}",
        "sourceDatabase": f"ws_v1_{run_id}",
        "targetDatabase": f"ws_v1_{run_id}_restore_v2",
    }
    for name, expected_value in expected.items():
        if run[name] != expected_value:
            raise EvidenceValidationError(f"run.{name} is not derived from run.runId")
    if _integer(run["publishedPortCount"], "run.publishedPortCount") != 3:
        raise EvidenceValidationError("run.publishedPortCount must equal 3")
    if _boolean(run["loopbackOnly"], "run.loopbackOnly") is not True:
        raise EvidenceValidationError("run.loopbackOnly must be true")

    container_images = _object(run["containerImageIds"], "run.containerImageIds")
    _known_subset_keys(
        container_images,
        RUNTIME_GENERATIONS,
        "run.containerImageIds",
        require_complete=require_complete,
    )
    validated_generations: dict[str, dict[str, Any]] = {}
    for generation, raw_images in container_images.items():
        validated_generations[generation] = _validate_image_map(
            raw_images,
            SERVICE_IMAGE_ROLES,
            f"run.containerImageIds[{generation}]",
            require_complete=require_complete,
        )

    resolved = _object(source["resolvedImageIds"], "source.resolvedImageIds")
    built_v1 = _object(source["builtV1ImageIds"], "source.builtV1ImageIds")
    built_v2 = _object(source["builtV2ImageIds"], "source.builtV2ImageIds")
    bindings = {
        "v1": {
            "mysql": (resolved, "mysql"),
            "redis": (resolved, "redis"),
            "app": (built_v1, "v1-app"),
            "nginx": (built_v1, "v1-nginx"),
            "mcp-public-nginx": (built_v1, "v1-nginx"),
        },
        "v2": {
            "mysql": (resolved, "mysql"),
            "redis": (resolved, "redis"),
            "app": (built_v2, "v2-app"),
            "nginx": (built_v2, "v2-nginx"),
            "mcp-public-nginx": (built_v2, "v2-nginx"),
        },
    }
    for generation, images in validated_generations.items():
        for service, actual_id in images.items():
            provenance, role = bindings[generation][service]
            expected_id = provenance.get(role)
            if expected_id is None:
                raise EvidenceValidationError(
                    f"run.containerImageIds[{generation}][{service}] has no source image provenance"
                )
            if actual_id != expected_id:
                raise EvidenceValidationError(
                    f"run.containerImageIds[{generation}][{service}] is not cross-bound "
                    "to its source image ID"
                )
    return run


def _validate_progress_bindings(
    source: Mapping[str, Any],
    run: Mapping[str, Any],
    phases: Mapping[str, Mapping[str, Any]],
) -> None:
    """Require complete evidence for each phase already reported as PASS."""
    if phases["source-freeze"]["status"] == "PASS":
        _nullable_sha256(source["toolSha256"], "source.toolSha256", require_value=True)
        _nullable_sha256(source["schemaSha256"], "source.schemaSha256", require_value=True)
        _nullable_git_object(source["v2Commit"], "source.v2Commit", require_value=True)
        _nullable_git_object(source["v2Tree"], "source.v2Tree", require_value=True)
        if not _boolean(source["cleanWorktree"], "source.cleanWorktree"):
            raise EvidenceValidationError(
                "a PASS source-freeze phase requires source.cleanWorktree=true"
            )
        _known_subset_keys(
            _object(source["currentAdapterSnapshotSha256"], "source.currentAdapterSnapshotSha256"),
            CURRENT_ADAPTER_FILES,
            "source.currentAdapterSnapshotSha256",
            require_complete=True,
        )
        _known_subset_keys(
            _object(source["runtimeSourceSha256"], "source.runtimeSourceSha256"),
            RUNTIME_SOURCE_FILES,
            "source.runtimeSourceSha256",
            require_complete=True,
        )

    if phases["runtime-preflight"]["status"] == "PASS":
        for field, roles in (
            ("inputImageReferences", INPUT_IMAGE_ROLES),
            ("resolvedImageIds", RESOLVED_IMAGE_ROLES),
            ("builtV1ImageIds", V1_IMAGE_ROLES),
            ("builtV2ImageIds", V2_IMAGE_ROLES),
        ):
            _known_subset_keys(
                _object(source[field], f"source.{field}"),
                roles,
                f"source.{field}",
                require_complete=True,
            )

    container_images = _object(run["containerImageIds"], "run.containerImageIds")
    for phase_name, generation in (("v1-fixtures", "v1"), ("v2-migration", "v2")):
        if phases[phase_name]["status"] != "PASS":
            continue
        generation_images = container_images.get(generation)
        if generation_images is None:
            raise EvidenceValidationError(
                f"a PASS {phase_name} phase requires run.containerImageIds[{generation}]"
            )
        _known_subset_keys(
            _object(generation_images, f"run.containerImageIds[{generation}]"),
            SERVICE_IMAGE_ROLES,
            f"run.containerImageIds[{generation}]",
            require_complete=True,
        )


def _validate_phases(value: Any, generated_at: datetime) -> dict[str, dict[str, Any]]:
    phases = _array(value, "phases")
    if len(phases) != len(PHASE_ORDER):
        raise EvidenceValidationError("phases must contain exactly ten entries")

    result: dict[str, dict[str, Any]] = {}
    stopped = False
    previous_finished: datetime | None = None
    for index, expected_name in enumerate(PHASE_ORDER):
        phase = _object(phases[index], f"phases[{index}]")
        _exact_keys(phase, PHASE_FIELDS, f"phases[{index}]")
        if phase["name"] != expected_name:
            raise EvidenceValidationError("phases are not in the frozen exact order")
        status_value = _status(phase["status"], f"phases[{index}].status")
        detail = _detail_code(phase["detailCode"], f"phases[{index}].detailCode")
        started = _timestamp(phase["startedAt"], f"phases[{index}].startedAt", nullable=True)
        finished = _timestamp(phase["finishedAt"], f"phases[{index}].finishedAt", nullable=True)

        if expected_name == "cleanup":
            if started is None or finished is None or status_value not in {"PASS", "FAIL"}:
                raise EvidenceValidationError("cleanup phase must execute and finish with PASS or FAIL")
            expected_detail = (
                "EXACT_OWNED_CLEANUP_PASS" if status_value == "PASS"
                else "EXACT_OWNED_CLEANUP_FAILED"
            )
            if detail != expected_detail:
                raise EvidenceValidationError("cleanup phase detail does not match its status")
        elif status_value == "PASS":
            if stopped or started is None or finished is None:
                raise EvidenceValidationError("a PASS phase must be an executed prefix phase")
            if detail != PHASE_PASS_DETAILS[expected_name]:
                raise EvidenceValidationError(f"{expected_name} uses a forged PASS detail code")
        elif status_value in {"FAIL", "ENV_REQUIRED"}:
            if stopped or started is None or finished is None:
                raise EvidenceValidationError("a failed phase must be the final executed prefix phase")
            if detail in {PHASE_PASS_DETAILS[expected_name], "RUNNING", "NOT_STARTED", "STOPPED_BEFORE_PHASE"}:
                raise EvidenceValidationError("a failed phase uses a non-failure detail code")
            stopped = True
        else:
            if not stopped:
                stopped = True
            if started is not None or finished is not None or detail != "STOPPED_BEFORE_PHASE":
                raise EvidenceValidationError(
                    "an unexecuted phase must be NOT_COVERED / STOPPED_BEFORE_PHASE with null times"
                )

        if (started is None) != (finished is None):
            raise EvidenceValidationError("phase start and finish timestamps must both be present or null")
        if started is not None and finished is not None:
            if started > finished:
                raise EvidenceValidationError("phase finishes before it starts")
            if previous_finished is not None and started < previous_finished:
                raise EvidenceValidationError("executed phase timestamps move backwards")
            if finished > generated_at:
                raise EvidenceValidationError("phase finishes after evidence generation")
            previous_finished = finished
        result[expected_name] = phase
    return result


def _validate_checks(value: Any) -> dict[str, dict[str, Any]]:
    checks = _object(value, "checks")
    _exact_keys(checks, REQUIRED_CHECKS, "checks")
    result: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_CHECKS:
        check = _object(checks[name], f"checks[{name}]")
        _exact_keys(check, CHECK_FIELDS, f"checks[{name}]")
        status_value = _status(check["status"], f"checks[{name}].status")
        detail = _detail_code(check["detailCode"], f"checks[{name}].detailCode")
        if status_value == "PASS":
            expected_detail = CHECK_PASS_DETAILS.get(name)
            if expected_detail is None or detail != expected_detail:
                raise EvidenceValidationError(f"checks[{name}] uses a forged PASS detail code")
        if name == "credential.preUpgradeRefreshRotationAccepted" and detail == "V1_PKCE_REFRESH_NOT_CAPTURED":
            if status_value != "NOT_COVERED":
                raise EvidenceValidationError(
                    "an uncaptured V1 refresh token must remain NOT_COVERED"
                )
        result[name] = check
    return result


def _is_unobserved(check: Mapping[str, Any]) -> bool:
    return check["status"] == "NOT_COVERED" and check["detailCode"] == "NOT_OBSERVED"


def _validate_check_execution(
    phases: Mapping[str, Mapping[str, Any]],
    checks: Mapping[str, Mapping[str, Any]],
) -> None:
    assigned = [name for names in PHASE_REQUIRED_CHECKS.values() for name in names]
    if len(assigned) != len(set(assigned)) or set(assigned) != set(REQUIRED_CHECKS):
        raise EvidenceValidationError("independent phase/check ownership contract is incomplete")

    for phase_name, check_names in PHASE_REQUIRED_CHECKS.items():
        phase_status = phases[phase_name]["status"]
        phase_checks = [checks[name] for name in check_names]
        statuses = [str(check["status"]) for check in phase_checks]
        if phase_status == "PASS":
            if any(status != "PASS" for status in statuses):
                raise EvidenceValidationError(
                    f"PASS phase {phase_name} has a non-PASS required check"
                )
        elif phase_status == "NOT_COVERED":
            if any(not _is_unobserved(check) for check in phase_checks):
                raise EvidenceValidationError(
                    f"unexecuted phase {phase_name} contains observed checks"
                )
        else:
            for status in statuses:
                if status in {"FAIL", "ENV_REQUIRED"} and status != phase_status:
                    raise EvidenceValidationError(
                        f"failed phase {phase_name} contradicts a required check status"
                    )


def _validate_acceptance(
    value: Any,
    checks: Mapping[str, Mapping[str, Any]],
    phases: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    acceptance = _object(value, "acceptance")
    _exact_keys(acceptance, ACCEPTANCE_IDS, "acceptance")
    recomputed: dict[str, str] = {}
    for acceptance_id in ACCEPTANCE_IDS:
        entry = _object(acceptance[acceptance_id], f"acceptance[{acceptance_id}]")
        _exact_keys(entry, ACCEPTANCE_FIELDS, f"acceptance[{acceptance_id}]")
        declared = _status(entry["status"], f"acceptance[{acceptance_id}].status")
        statuses = [
            _status(checks[name]["status"], f"checks[{name}].status")
            for name in ACCEPTANCE_GROUPS[acceptance_id]
        ]
        owned = set(ACCEPTANCE_GROUPS[acceptance_id])
        phase_names = (
            PHASE_ORDER
            if acceptance_id == "V2-AC-40"
            else tuple(
                phase_name
                for phase_name, required in PHASE_REQUIRED_CHECKS.items()
                if owned.intersection(required)
            )
        )
        statuses.extend(
            _status(phases[name]["status"], f"phases[{name}].status")
            for name in phase_names
        )
        expected = _aggregate_status(statuses)
        if declared != expected:
            raise EvidenceValidationError(
                f"acceptance[{acceptance_id}] does not equal the recomputed check/phase aggregate"
            )
        recomputed[acceptance_id] = expected
    return recomputed


def _validate_sdk_observations(
    value: Any,
    runtime_sources: Mapping[str, Any],
) -> list[dict[str, Any]]:
    reports = _array(value, "observations.mcpSdkSurefire")
    if len(reports) > len(SDK_CLASS_ORDER):
        raise EvidenceValidationError("observations.mcpSdkSurefire contains too many reports")
    result: list[dict[str, Any]] = []
    for index, raw_report in enumerate(reports):
        report = _object(raw_report, f"observations.mcpSdkSurefire[{index}]")
        _exact_keys(report, SDK_OBSERVATION_FIELDS, f"observations.mcpSdkSurefire[{index}]")
        test_class = _string(report["testClass"], f"observations.mcpSdkSurefire[{index}].testClass")
        if test_class != SDK_CLASS_ORDER[index]:
            raise EvidenceValidationError("MCP SDK reports are not the exact producer execution prefix")
        tests = _integer(report["tests"], f"observations.mcpSdkSurefire[{index}].tests")
        if tests != 1:
            raise EvidenceValidationError("an MCP SDK report must prove exactly one test")
        for name in ("failures", "errors", "skipped"):
            if _integer(report[name], f"observations.mcpSdkSurefire[{index}].{name}") != 0:
                raise EvidenceValidationError("a persisted MCP SDK success report must have no failures or skips")
        _sha256(report["reportSha256"], f"observations.mcpSdkSurefire[{index}].reportSha256")
        _sha256(
            report["testSourceSha256"],
            f"observations.mcpSdkSurefire[{index}].testSourceSha256",
        )
        _sha256(
            report["rootPomSha256"],
            f"observations.mcpSdkSurefire[{index}].rootPomSha256",
        )
        _sha256(
            report["modulePomSha256"],
            f"observations.mcpSdkSurefire[{index}].modulePomSha256",
        )
        source_path = SDK_CLASS_SOURCE[test_class]
        frozen_source_hash = runtime_sources.get(source_path)
        if frozen_source_hash is None or report["testSourceSha256"] != frozen_source_hash:
            raise EvidenceValidationError("MCP SDK report is not bound to its frozen test source")
        if report["rootPomSha256"] != runtime_sources.get("pom.xml"):
            raise EvidenceValidationError("MCP SDK report is not bound to the frozen root POM")
        if report["modulePomSha256"] != runtime_sources.get("web-starter-mcp/pom.xml"):
            raise EvidenceValidationError("MCP SDK report is not bound to the frozen module POM")
        result.append(report)
    return result


def _validate_playwright_observation(
    value: Any,
    runtime_sources: Mapping[str, Any],
) -> None:
    report = _object(value, "observations.playwright")
    _exact_keys(report, PLAYWRIGHT_OBSERVATION_FIELDS, "observations.playwright")
    for name, expected in (
        ("tests", 20), ("failures", 0), ("skipped", 0), ("flaky", 0),
    ):
        if _integer(report[name], f"observations.playwright.{name}") != expected:
            raise EvidenceValidationError(
                "Playwright observation does not prove twenty clean passes"
            )
    _sha256(report["reportSha256"], "observations.playwright.reportSha256")
    bindings = {
        "packageJsonSha256": "web-starter-web/package.json",
        "lockfileSha256": "web-starter-web/pnpm-lock.yaml",
        "configSha256": "web-starter-web/playwright.config.ts",
    }
    for field, relative in bindings.items():
        digest = _sha256(report[field], f"observations.playwright.{field}")
        if digest != runtime_sources[relative]:
            raise EvidenceValidationError("Playwright observation is not bound to runtime sources")
    test_sources = _object(
        report["testSourceSha256"], "observations.playwright.testSourceSha256"
    )
    _exact_keys(
        test_sources, PLAYWRIGHT_TEST_SOURCES,
        "observations.playwright.testSourceSha256",
    )
    for relative in PLAYWRIGHT_TEST_SOURCES:
        digest = _sha256(
            test_sources[relative],
            f"observations.playwright.testSourceSha256[{relative}]",
        )
        if digest != runtime_sources[relative]:
            raise EvidenceValidationError("Playwright test source hash is not cross-bound")


def _validate_observations(
    value: Any,
    phases: Mapping[str, Mapping[str, Any]],
    checks: Mapping[str, Mapping[str, Any]],
    source: Mapping[str, Any],
) -> None:
    observations = _object(value, "observations")
    migration_passed = phases["v2-migration"]["status"] == "PASS"
    allowed = (
        OBSERVATION_BASE_FIELDS | OBSERVATION_OPTIONAL_FIELDS
        if migration_passed
        else OBSERVATION_OPTIONAL_FIELDS
    )
    unknown = set(observations) - allowed
    missing = OBSERVATION_BASE_FIELDS - set(observations) if migration_passed else set()
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            details.append("unknown=" + ",".join(sorted(unknown)))
        raise EvidenceValidationError(
            "observations fields are not the current producer contract (" + "; ".join(details) + ")"
        )

    if migration_passed:
        migration_hashes = _object(
            observations["v1MigrationSha256"], "observations.v1MigrationSha256"
        )
        _exact_keys(migration_hashes, V1_MIGRATION_FILES, "observations.v1MigrationSha256")
        for name in V1_MIGRATION_FILES:
            _sha256(migration_hashes[name], f"observations.v1MigrationSha256[{name}]")

        v1_tables = _integer(
            observations["v1TableCount"], "observations.v1TableCount", minimum=1
        )
        v2_tables = _integer(
            observations["v2TableCount"], "observations.v2TableCount", minimum=1
        )
        _integer(
            observations["v1ProjectionCount"],
            "observations.v1ProjectionCount",
            minimum=1,
        )
        if v2_tables < v1_tables:
            raise EvidenceValidationError(
                "observations.v2TableCount cannot be less than v1TableCount"
            )
        if observations["flywayVersions"] != [1, 2, 3, 4, 5, 6, 7]:
            raise EvidenceValidationError(
                "observations.flywayVersions must equal exact versions 1 through 7"
            )
        flyway_history = _array(
            observations["flywayHistory"], "observations.flywayHistory"
        )
        if len(flyway_history) != len(V2_MIGRATION_FILES):
            raise EvidenceValidationError(
                "observations.flywayHistory must contain exactly seven rows"
            )
        runtime_sources = _object(
            source["runtimeSourceSha256"], "source.runtimeSourceSha256"
        )
        for index, relative in enumerate(V2_MIGRATION_FILES, start=1):
            row = _object(
                flyway_history[index - 1],
                f"observations.flywayHistory[{index - 1}]",
            )
            _exact_keys(
                row, FLYWAY_HISTORY_FIELDS,
                f"observations.flywayHistory[{index - 1}]",
            )
            filename = Path(relative).name
            expected_description = filename.split("__", 1)[1][:-4].replace("_", " ")
            expected_digest = (
                migration_hashes[relative]
                if relative in V1_MIGRATION_FILES
                else runtime_sources[relative]
            )
            if (
                _integer(row["installedRank"], "flyway installedRank") != index
                or _integer(row["version"], "flyway version") != index
                or row["description"] != expected_description
                or row["type"] != "SQL"
                or row["script"] != filename
                or not isinstance(row["success"], bool)
                or row["success"] is not True
                or _sha256(row["scriptSha256"], "flyway scriptSha256") != expected_digest
            ):
                raise EvidenceValidationError(
                    "observations.flywayHistory is not cross-bound to the exact migration set"
                )
            checksum = _integer(
                row["checksum"], "flyway checksum", minimum=-(2**31)
            )
            if checksum > 2**31 - 1:
                raise EvidenceValidationError("Flyway checksum is outside signed INT range")
        if observations["credentialTypesCapturedBeforeUpgrade"] != [
            "OAUTH_ACCESS_TOKEN",
            "OAUTH_CLIENT_SECRET",
            "OAUTH_REFRESH_TOKEN",
            "PERSONAL_ACCESS_TOKEN",
            "SERVICE_ACCOUNT_TOKEN",
        ]:
            raise EvidenceValidationError(
                "observations.credentialTypesCapturedBeforeUpgrade is not the frozen exact list"
            )

    reports = _validate_sdk_observations(
        observations.get("mcpSdkSurefire", []),
        _object(source["runtimeSourceSha256"], "source.runtimeSourceSha256"),
    )
    minimum_report_count = max(
        (
            count
            for check_name, count in SDK_MINIMUM_REPORTS_BY_CHECK
            if checks[check_name]["status"] == "PASS"
        ),
        default=0,
    )
    if len(reports) < minimum_report_count:
        raise EvidenceValidationError(
            "MCP SDK report prefix is shorter than its passed check milestones require"
        )
    if (
        all(checks[name]["status"] == "PASS" for name in REQUIRED_CHECKS)
        and all(phases[name]["status"] == "PASS" for name in PHASE_ORDER)
        and len(reports) != len(SDK_CLASS_ORDER)
    ):
        raise EvidenceValidationError("PASS evidence requires the exact seven MCP SDK reports")

    playwright = observations.get("playwright")
    if playwright is not None:
        _validate_playwright_observation(
            playwright,
            _object(source["runtimeSourceSha256"], "source.runtimeSourceSha256"),
        )
    if checks["browser.playwright"]["status"] == "PASS" and playwright is None:
        raise EvidenceValidationError(
            "browser.playwright PASS requires an exact Playwright report observation"
        )


def _validate_cleanup_and_private_policy(
    cleanup_value: Any,
    logs_value: Any,
    policy_value: Any,
    phases: Mapping[str, Mapping[str, Any]],
    checks: Mapping[str, Mapping[str, Any]],
) -> None:
    cleanup = _object(cleanup_value, "cleanup")
    _exact_keys(cleanup, CLEANUP_FIELDS, "cleanup")
    cleanup_status = _string(cleanup["status"], "cleanup.status")
    if cleanup_status not in {"PASS", "FAIL"}:
        raise EvidenceValidationError("cleanup.status must be PASS or FAIL")
    exact_ownership = _boolean(cleanup["exactOwnershipVerified"], "cleanup.exactOwnershipVerified")

    removed = _object(cleanup["removed"], "cleanup.removed")
    _exact_keys(removed, REMOVED_FIELDS, "cleanup.removed")
    for name in REMOVED_FIELDS:
        _integer(removed[name], f"cleanup.removed.{name}")

    residual = _object(cleanup["residual"], "cleanup.residual")
    _exact_keys(residual, RESIDUAL_FIELDS, "cleanup.residual")
    residual_values = {
        name: _boolean(residual[name], f"cleanup.residual.{name}")
        for name in RESIDUAL_FIELDS
    }

    failure_codes = _array(cleanup["failureCodes"], "cleanup.failureCodes")
    for index, value in enumerate(failure_codes):
        code = _string(value, f"cleanup.failureCodes[{index}]")
        if FAILURE_CODE_PATTERN.fullmatch(code) is None:
            raise EvidenceValidationError("cleanup.failureCodes contains an invalid code")
    if failure_codes != sorted(set(failure_codes)):
        raise EvidenceValidationError("cleanup.failureCodes must be sorted and unique")
    private_removed = _boolean(cleanup["privateRuntimeRemoved"], "cleanup.privateRuntimeRemoved")

    logs = _object(logs_value, "privateCommandLogs")
    _exact_keys(logs, PRIVATE_LOG_FIELDS, "privateCommandLogs")
    logs_persisted = _boolean(logs["persisted"], "privateCommandLogs.persisted")
    _integer(logs["count"], "privateCommandLogs.count")
    _sha256(logs["aggregateSha256"], "privateCommandLogs.aggregateSha256")

    policy = _object(policy_value, "evidencePolicy")
    _exact_keys(policy, EVIDENCE_POLICY_FIELDS, "evidencePolicy")
    expected_constants = {
        "outsideRepository": True,
        "directoryMode": "0700",
        "fileMode": "0600",
        "containsSecrets": False,
    }
    for name, expected in expected_constants.items():
        if policy[name] != expected:
            raise EvidenceValidationError(f"evidencePolicy.{name} violates the public evidence policy")
    policy_persisted = _boolean(
        policy["privateRuntimePersisted"],
        "evidencePolicy.privateRuntimePersisted",
    )
    expected_persisted = not private_removed
    if logs_persisted != expected_persisted or policy_persisted != expected_persisted:
        raise EvidenceValidationError("private runtime persistence fields do not agree")

    check = checks["cleanup.exactOwnedResources"]
    phase = phases["cleanup"]
    if cleanup_status == "PASS":
        if (
            not exact_ownership
            or any(residual_values.values())
            or failure_codes
            or not private_removed
            or check != {"status": "PASS", "detailCode": "EXACT_OWNED_CLEANUP_PASS"}
            or phase["status"] != "PASS"
        ):
            raise EvidenceValidationError("cleanup PASS is not supported by exact clean ownership evidence")
    else:
        if check["status"] != "FAIL" or check["detailCode"] not in {
            "EXACT_OWNED_CLEANUP_FAILED",
            "PRIVATE_RUNTIME_REMOVAL_FAILED",
        }:
            raise EvidenceValidationError("cleanup FAIL is not reflected by the cleanup check")
        if phase["status"] != "FAIL":
            raise EvidenceValidationError("cleanup FAIL is not reflected by the cleanup phase")


def _secret_scan(document: Mapping[str, Any]) -> None:
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if any(pattern.search(encoded) for pattern in SECRET_PATTERNS):
        raise EvidenceValidationError("public evidence contains secret-shaped material")


def validate_document(document: Any) -> dict[str, Any]:
    """Validate document-local semantics; use validate_document_path for Git binding."""
    root = _object(document, "evidence document")
    _exact_keys(root, TOP_LEVEL_FIELDS, "evidence document")
    if root["schemaVersion"] != 1 or isinstance(root["schemaVersion"], bool):
        raise EvidenceValidationError("schemaVersion must equal integer 1")
    if root["acceptanceId"] != "V2-AC-40":
        raise EvidenceValidationError("acceptanceId must equal V2-AC-40")
    declared_status = _status(root["status"], "status")
    require_complete = declared_status == "PASS"
    generated_at = _timestamp(root["generatedAt"], "generatedAt")
    assert generated_at is not None

    source = _validate_source(root["source"], require_complete=require_complete)
    run = _validate_run(root["run"], source, require_complete=require_complete)
    phases = _validate_phases(root["phases"], generated_at)
    _validate_progress_bindings(source, run, phases)
    checks = _validate_checks(root["checks"])
    _validate_check_execution(phases, checks)
    acceptance = _validate_acceptance(root["acceptance"], checks, phases)
    _validate_observations(root["observations"], phases, checks, source)
    _validate_cleanup_and_private_policy(
        root["cleanup"],
        root["privateCommandLogs"],
        root["evidencePolicy"],
        phases,
        checks,
    )

    check_statuses = [
        _status(checks[name]["status"], f"checks[{name}].status")
        for name in REQUIRED_CHECKS
    ]
    phase_statuses = [
        _status(phases[name]["status"], f"phases[{name}].status")
        for name in PHASE_ORDER
    ]
    recomputed_status = _aggregate_status([*check_statuses, *phase_statuses])
    if declared_status != recomputed_status:
        raise EvidenceValidationError(
            "top-level status does not equal the recomputed check and phase aggregate"
        )
    expected_exit = STATUS_EXIT_CODES[recomputed_status]
    if (
        isinstance(root["processExitCode"], bool)
        or not isinstance(root["processExitCode"], int)
        or root["processExitCode"] != expected_exit
    ):
        raise EvidenceValidationError("processExitCode does not match the recomputed status")
    if acceptance["V2-AC-40"] != recomputed_status:
        raise EvidenceValidationError("V2-AC-40 does not match the top-level aggregate")

    _secret_scan(root)
    return {
        "status": recomputed_status,
        "processExitCode": expected_exit,
        "checkCount": len(REQUIRED_CHECKS),
        "acceptanceCount": len(ACCEPTANCE_IDS),
        "phaseCount": len(PHASE_ORDER),
    }


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _git(repository: Path, *arguments: str) -> bytes:
    """Run one read-only Git query without optional index locks or replace refs."""
    environment = os.environ.copy()
    environment.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    try:
        completed = subprocess.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                "-C", str(repository),
                *arguments,
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
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        if detail:
            detail = detail.splitlines()[-1][:300]
            raise EvidenceValidationError(
                f"Git candidate query failed ({arguments[0]}): {detail}"
            )
        raise EvidenceValidationError(f"Git candidate query failed ({arguments[0]})")
    return completed.stdout


def _resolve_git_repository(repository_root: Path) -> Path:
    expanded = repository_root.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise EvidenceValidationError(
            "repository root must be a real directory, not a symlink"
        )
    repository = expanded.resolve()
    raw_top_level = _git(repository, "rev-parse", "--show-toplevel")
    try:
        top_level = Path(raw_top_level.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exception:
        raise EvidenceValidationError("Git returned an invalid repository root") from exception
    if top_level != repository:
        raise EvidenceValidationError(
            "repository root must identify the exact Git worktree top level"
        )
    return repository


def _git_object_id(repository: Path, expression: str, label: str) -> str:
    try:
        object_id = _git(
            repository, "rev-parse", "--verify", expression
        ).decode("ascii").strip()
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError(f"{label} is not an ASCII Git object ID") from exception
    if GIT_OBJECT_PATTERN.fullmatch(object_id) is None:
        raise EvidenceValidationError(f"{label} is not a 40-character Git object ID")
    return object_id


def _require_clean_candidate(repository: Path) -> None:
    index_records = _git(repository, "ls-files", "-v", "-z").split(b"\0")
    tracked_records = [record for record in index_records if record]
    if not tracked_records:
        raise EvidenceValidationError("Git candidate has no tracked files")
    if any(not record.startswith(b"H ") for record in tracked_records):
        raise EvidenceValidationError(
            "Git candidate index contains skip-worktree, assume-unchanged, or non-normal entries"
        )
    if _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise EvidenceValidationError(
            "Git candidate is not clean (tracked or untracked changes are present)"
        )


def _candidate_blob(repository: Path, commit: str, relative: str) -> bytes:
    relative_path = Path(relative)
    if relative_path.is_absolute() or not relative_path.parts or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise EvidenceValidationError(f"candidate source path is unsafe: {relative}")

    workspace_path = repository.joinpath(*relative_path.parts)
    try:
        workspace_stat = workspace_path.lstat()
        resolved_workspace_path = workspace_path.resolve(strict=True)
    except OSError as exception:
        raise EvidenceValidationError(
            f"candidate source file is missing: {relative}"
        ) from exception
    if (
        not stat.S_ISREG(workspace_stat.st_mode)
        or workspace_path.is_symlink()
        or not _inside(resolved_workspace_path, repository)
    ):
        raise EvidenceValidationError(
            f"candidate source file must be a regular in-repository file: {relative}"
        )

    tree_entry = _git(
        repository,
        "ls-tree",
        "-z",
        commit,
        "--",
        relative,
    )
    entries = [entry for entry in tree_entry.split(b"\0") if entry]
    if len(entries) != 1:
        raise EvidenceValidationError(
            f"candidate commit does not contain exactly one source file: {relative}"
        )
    metadata, separator, encoded_path = entries[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or encoded_path.decode("utf-8", errors="surrogateescape") != relative
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise EvidenceValidationError(
            f"candidate commit source is not a regular blob: {relative}"
        )

    committed = _git(repository, "show", f"{commit}:{relative}")
    try:
        workspace = workspace_path.read_bytes()
    except OSError as exception:
        raise EvidenceValidationError(
            f"candidate source file cannot be read: {relative}"
        ) from exception
    if workspace != committed:
        raise EvidenceValidationError(
            f"candidate workspace bytes differ from committed bytes: {relative}"
        )
    return committed


def _safe_dependency_seed_name(name: str) -> bool:
    return bool(name) and all(
        ord(character) >= 32 and ord(character) != 127 for character in name
    )


def _incomplete_dependency_seed_name(name: str) -> bool:
    lowered = name.lower()
    return any(
        lowered.endswith(suffix) for suffix in INCOMPLETE_DEPENDENCY_SEED_SUFFIXES
    )


def _same_seed_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_nlink,
        left.st_size,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_nlink,
        right.st_size,
    )


def _open_seed_file(path: Path, expected: os.stat_result, label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exception:
        raise EvidenceValidationError(f"{label} cannot be opened safely") from exception
    observed = os.fstat(descriptor)
    if not stat.S_ISREG(observed.st_mode) or not _same_seed_file(expected, observed):
        os.close(descriptor)
        raise EvidenceValidationError(f"{label} changed before it was read")
    return descriptor


def _seed_file_sha256(path: Path, expected: os.stat_result, label: str) -> str:
    descriptor = _open_seed_file(path, expected, label)
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if not _same_seed_file(expected, os.fstat(descriptor)):
            raise EvidenceValidationError(f"{label} changed while it was read")
    except OSError as exception:
        raise EvidenceValidationError(f"{label} cannot be read safely") from exception
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _seed_file_bytes(
    path: Path,
    expected: os.stat_result,
    label: str,
    *,
    maximum_bytes: int,
) -> bytes:
    if expected.st_size > maximum_bytes:
        raise EvidenceValidationError(f"{label} exceeds its size limit")
    descriptor = _open_seed_file(path, expected, label)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise EvidenceValidationError(f"{label} exceeds its size limit")
        if not _same_seed_file(expected, os.fstat(descriptor)):
            raise EvidenceValidationError(f"{label} changed while it was read")
    except OSError as exception:
        raise EvidenceValidationError(f"{label} cannot be read safely") from exception
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _dependency_seed_component_summary(root: Path, *, component: str) -> dict[str, Any]:
    """Independently hash one caller-owned, private dependency component tree.

    Package-manager and Maven components remain link-free.  The Playwright
    browser component may contain only validated, relative, in-tree links.
    """
    if not hasattr(os, "getuid"):
        raise EvidenceValidationError(
            "dependency seed owner validation is unavailable on this platform"
        )
    caller_uid = os.getuid()
    try:
        root_metadata = root.lstat()
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed component cannot be inspected"
        ) from exception
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != caller_uid
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise EvidenceValidationError(
            "dependency seed component directories must be caller-owned mode 0700"
        )

    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed component cannot be resolved"
        ) from exception
    records: list[tuple[str, str, int, int, str]] = []
    directory_edges: dict[Path, set[Path]] = {}
    file_count = 0
    byte_count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            resolved_directory = directory.resolve(strict=True)
        except (OSError, RuntimeError) as exception:
            raise EvidenceValidationError(
                "dependency seed directory cannot be resolved"
            ) from exception
        directory_edges.setdefault(resolved_directory, set())
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        except OSError as exception:
            raise EvidenceValidationError(
                "dependency seed component cannot be enumerated"
            ) from exception
        child_directories: list[Path] = []
        for entry in entries:
            if (
                not _safe_dependency_seed_name(entry.name)
                or _incomplete_dependency_seed_name(entry.name)
            ):
                raise EvidenceValidationError(
                    "dependency seed contains an unsafe or incomplete marker"
                )
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exception:
                raise EvidenceValidationError(
                    "dependency seed entry cannot be inspected"
                ) from exception
            mode = stat.S_IMODE(metadata.st_mode)
            if metadata.st_uid != caller_uid:
                raise EvidenceValidationError(
                    "dependency seed entries must be owned by the caller"
                )
            if stat.S_ISLNK(metadata.st_mode):
                if component != "playwrightBrowsers":
                    raise EvidenceValidationError(
                        "only the Playwright browser seed may contain symbolic links"
                    )
                try:
                    raw_target = os.readlink(path)
                except OSError as exception:
                    raise EvidenceValidationError(
                        "Playwright dependency seed link cannot be read"
                    ) from exception
                if (
                    not _safe_dependency_seed_name(raw_target)
                    or Path(raw_target).is_absolute()
                ):
                    raise EvidenceValidationError(
                        "Playwright dependency seed links must use safe relative targets"
                    )
                lexical_depth = len(path.parent.relative_to(root).parts)
                for part in Path(raw_target).parts:
                    if part in {"", "."}:
                        continue
                    if part == "..":
                        if lexical_depth == 0:
                            raise EvidenceValidationError(
                                "Playwright dependency seed link escapes its component"
                            )
                        lexical_depth -= 1
                    else:
                        lexical_depth += 1
                try:
                    resolved_target = path.resolve(strict=True)
                except (OSError, RuntimeError) as exception:
                    raise EvidenceValidationError(
                        "Playwright dependency seed link is dangling or cyclic"
                    ) from exception
                if not _inside(resolved_target, resolved_root):
                    raise EvidenceValidationError(
                        "Playwright dependency seed link escapes its component"
                    )
                try:
                    target_bytes = raw_target.encode("utf-8")
                except UnicodeEncodeError as exception:
                    raise EvidenceValidationError(
                        "Playwright dependency seed link target is not valid UTF-8"
                    ) from exception
                records.append((
                    "L",
                    relative,
                    mode,
                    len(target_bytes),
                    hashlib.sha256(target_bytes).hexdigest(),
                ))
                if resolved_target.is_dir():
                    directory_edges[resolved_directory].add(resolved_target)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if mode != 0o700:
                    raise EvidenceValidationError(
                        "dependency seed directories must have mode 0700"
                    )
                records.append(("D", relative, mode, 0, ""))
                try:
                    resolved_child = path.resolve(strict=True)
                except (OSError, RuntimeError) as exception:
                    raise EvidenceValidationError(
                        "dependency seed directory cannot be resolved"
                    ) from exception
                directory_edges[resolved_directory].add(resolved_child)
                directory_edges.setdefault(resolved_child, set())
                child_directories.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise EvidenceValidationError(
                    "dependency seed contains a special file"
                )
            if metadata.st_nlink != 1:
                raise EvidenceValidationError(
                    "dependency seed must not contain hard links"
                )
            if mode & 0o7077 or not mode & stat.S_IRUSR:
                raise EvidenceValidationError(
                    "dependency seed files must be owner-readable without group, other, or special bits"
                )
            if component == "mavenRepository":
                parts = Path(relative).parts
                if parts[:2] == ("dev", "webstarter") or entry.name.startswith(
                    "web-starter-"
                ):
                    raise EvidenceValidationError(
                        "dependency seed must not contain locally built project artifacts"
                    )
            if file_count >= 500_000 or byte_count + metadata.st_size > 8 * 1024**3:
                raise EvidenceValidationError(
                    "dependency seed exceeds the bounded cache size"
                )
            payload_sha256 = _seed_file_sha256(
                path,
                metadata,
                f"dependency seed component file {component}/{relative}",
            )
            records.append(("F", relative, mode, metadata.st_size, payload_sha256))
            file_count += 1
            byte_count += metadata.st_size
        stack.extend(reversed(child_directories))

    directory_state: dict[Path, int] = {}
    traversal: list[tuple[Path, bool]] = [(resolved_root, False)]
    while traversal:
        directory, finishing = traversal.pop()
        state = directory_state.get(directory, 0)
        if finishing:
            directory_state[directory] = 2
            continue
        if state == 1:
            raise EvidenceValidationError(
                "Playwright dependency seed contains a cyclic directory link"
            )
        if state == 2:
            continue
        directory_state[directory] = 1
        traversal.append((directory, True))
        for target in sorted(
            directory_edges.get(directory, set()),
            key=lambda item: os.fsencode(str(item)),
            reverse=True,
        ):
            if directory_state.get(target, 0) == 1:
                raise EvidenceValidationError(
                    "Playwright dependency seed contains a cyclic directory link"
                )
            if directory_state.get(target, 0) != 2:
                traversal.append((target, False))

    if file_count == 0:
        raise EvidenceValidationError("dependency seed components must not be empty")
    digest = hashlib.sha256()
    for kind, relative, mode, size, payload_sha256 in sorted(
        records, key=lambda item: item[1]
    ):
        encoded = relative.encode("utf-8")
        digest.update(kind.encode("ascii"))
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(size.to_bytes(8, "big"))
        digest.update(payload_sha256.encode("ascii"))
    return {
        "treeSha256": digest.hexdigest(),
        "fileCount": file_count,
        "byteCount": byte_count,
    }


def _java_string_hash(value: str) -> str:
    result = 0
    for character in value:
        result = (result * 31 + ord(character)) & 0xFFFFFFFF
    return format(result, "x")


def _validate_dependency_seed_semantics(
    root: Path,
    repository: Path,
    head: str,
) -> None:
    try:
        wrapper_properties = _candidate_blob(
            repository,
            head,
            ".mvn/wrapper/maven-wrapper.properties",
        ).decode("utf-8")
    except UnicodeDecodeError as exception:
        raise EvidenceValidationError(
            "candidate Maven Wrapper properties are not UTF-8"
        ) from exception
    properties: dict[str, str] = {}
    for line in wrapper_properties.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key.strip()] = value.strip()
    distribution_url = properties.get("distributionUrl", "")
    distribution_sha256 = properties.get("distributionSha256Sum", "")
    if (
        not distribution_url.endswith(
            "/apache-maven/3.9.15/apache-maven-3.9.15-bin.zip"
        )
        or SHA256_PATTERN.fullmatch(distribution_sha256) is None
    ):
        raise EvidenceValidationError(
            "dependency seed is not bound to the frozen Maven 3.9.15 wrapper"
        )
    wrapper_binary = (
        root
        / DEPENDENCY_SEED_COMPONENT_PATHS["mavenHome"]
        / "wrapper"
        / "dists"
        / "apache-maven-3.9.15"
        / _java_string_hash(distribution_url)
        / "bin"
        / "mvn"
    )
    try:
        wrapper_metadata = wrapper_binary.lstat()
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed lacks the exact executable Maven Wrapper home"
        ) from exception
    if (
        wrapper_binary.is_symlink()
        or not stat.S_ISREG(wrapper_metadata.st_mode)
        or not wrapper_metadata.st_mode & stat.S_IXUSR
        or (
            root
            / DEPENDENCY_SEED_COMPONENT_PATHS["mavenHome"]
            / "repository"
        ).exists()
    ):
        raise EvidenceValidationError(
            "dependency seed lacks the exact executable Maven Wrapper home"
        )

    maven_repository = root / DEPENDENCY_SEED_COMPONENT_PATHS["mavenRepository"]
    if not any(maven_repository.rglob("*.pom")) or not any(
        maven_repository.rglob("*.jar")
    ):
        raise EvidenceValidationError(
            "dependency seed Maven repository is incomplete"
        )

    pnpm_package = (
        root
        / DEPENDENCY_SEED_COMPONENT_PATHS["corepackHome"]
        / "v1"
        / "pnpm"
        / DEPENDENCY_SEED_VERSIONS["pnpm"]
        / "package.json"
    )
    try:
        pnpm_document = json.loads(pnpm_package.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceValidationError(
            "dependency seed pnpm package is unavailable"
        ) from exception
    if not isinstance(pnpm_document, dict) or pnpm_document.get("version") != "9.15.9":
        raise EvidenceValidationError(
            "dependency seed does not contain pnpm 9.15.9"
        )

    pnpm_files = (
        root / DEPENDENCY_SEED_COMPONENT_PATHS["pnpmStore"] / "v3" / "files"
    )
    try:
        pnpm_store_present = (
            not pnpm_files.is_symlink()
            and pnpm_files.is_dir()
            and any(pnpm_files.iterdir())
        )
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed pnpm v3 store cannot be inspected"
        ) from exception
    if not pnpm_store_present:
        raise EvidenceValidationError(
            "dependency seed pnpm v3 store is incomplete"
        )

    chromium = (
        root
        / DEPENDENCY_SEED_COMPONENT_PATHS["playwrightBrowsers"]
        / f"chromium-{DEPENDENCY_SEED_VERSIONS['chromiumRevision']}"
    )
    try:
        chromium_present = (chromium / "INSTALLATION_COMPLETE").is_file() and any(
            path.is_file()
            and not path.is_symlink()
            and path.stat().st_mode & stat.S_IXUSR
            and path.name in {"chrome", "Google Chrome for Testing"}
            for path in chromium.rglob("*")
        )
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed Chromium revision cannot be inspected"
        ) from exception
    if not chromium_present:
        raise EvidenceValidationError(
            "dependency seed lacks the complete executable Chromium revision 1228"
        )


def _validate_dependency_seed_binding(
    source: Mapping[str, Any],
    dependency_seed: Path,
    expected_sha256: str,
    repository: Path,
    head: str,
    tree: str,
) -> None:
    """Rescan the physical seed and bind it to an external canonical SHA-256."""
    expected_anchor = _sha256(
        expected_sha256,
        "expected dependency seed SHA-256 trust anchor",
    )
    expanded = dependency_seed.expanduser().absolute()
    try:
        root_metadata = expanded.lstat()
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed must be a real directory"
        ) from exception
    if expanded.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceValidationError("dependency seed must be a real directory")
    root = expanded.resolve()
    if root == repository or _inside(root, repository) or _inside(repository, root):
        raise EvidenceValidationError(
            "dependency seed must stay outside the candidate repository"
        )
    if (
        not hasattr(os, "getuid")
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise EvidenceValidationError(
            "dependency seed root must be caller-owned mode 0700"
        )

    expected_top_level = {"manifest.json", *DEPENDENCY_SEED_COMPONENT_PATHS.values()}
    try:
        top_level_before = {entry.name for entry in os.scandir(root)}
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed top-level cannot be enumerated"
        ) from exception
    if top_level_before != expected_top_level:
        raise EvidenceValidationError(
            "dependency seed top-level layout is not exact"
        )

    manifest_path = root / "manifest.json"
    try:
        manifest_metadata = manifest_path.lstat()
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed manifest is unavailable"
        ) from exception
    if (
        manifest_path.is_symlink()
        or not stat.S_ISREG(manifest_metadata.st_mode)
        or manifest_metadata.st_uid != os.getuid()
        or manifest_metadata.st_nlink != 1
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
    ):
        raise EvidenceValidationError(
            "dependency seed manifest must be a caller-owned private regular file"
        )
    manifest_bytes = _seed_file_bytes(
        manifest_path,
        manifest_metadata,
        "dependency seed manifest",
        maximum_bytes=64 * 1024,
    )
    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise EvidenceValidationError(
            "dependency seed manifest is invalid JSON"
        ) from exception
    manifest_object = _object(manifest, "dependency seed manifest")
    _exact_keys(
        manifest_object,
        DEPENDENCY_SEED_MANIFEST_FIELDS,
        "dependency seed manifest",
    )

    runtime_platform = sys.platform
    runtime_architecture = platform.machine().lower()
    if (
        manifest_object["schemaVersion"] != 1
        or isinstance(manifest_object["schemaVersion"], bool)
        or manifest_object["kind"] != "web-starter-ac40-dependency-seed"
        or manifest_object["platform"] != runtime_platform
        or manifest_object["architecture"] != runtime_architecture
        or manifest_object["versions"] != DEPENDENCY_SEED_VERSIONS
    ):
        raise EvidenceValidationError(
            "dependency seed identity does not match the validator runtime"
        )

    candidate_source_hashes = {
        relative: hashlib.sha256(
            _candidate_blob(repository, head, relative)
        ).hexdigest()
        for relative in DEPENDENCY_SEED_SOURCE_FILES
    }
    manifest_source_hashes = _object(
        manifest_object["sourceSha256"],
        "dependency seed manifest sourceSha256",
    )
    _exact_keys(
        manifest_source_hashes,
        DEPENDENCY_SEED_SOURCE_FILES,
        "dependency seed manifest sourceSha256",
    )
    for relative in DEPENDENCY_SEED_SOURCE_FILES:
        _sha256(
            manifest_source_hashes[relative],
            f"dependency seed manifest sourceSha256[{relative}]",
        )
    if manifest_source_hashes != candidate_source_hashes:
        raise EvidenceValidationError(
            "dependency seed manifest is not bound to current candidate bytes"
        )

    declared_components = _object(
        manifest_object["components"],
        "dependency seed manifest components",
    )
    _exact_keys(
        declared_components,
        DEPENDENCY_SEED_COMPONENTS,
        "dependency seed manifest components",
    )
    observed_components: dict[str, dict[str, Any]] = {}
    for component in DEPENDENCY_SEED_COMPONENTS:
        declared_component = _object(
            declared_components[component],
            f"dependency seed manifest components[{component}]",
        )
        _exact_keys(
            declared_component,
            DEPENDENCY_SEED_MANIFEST_COMPONENT_FIELDS,
            f"dependency seed manifest components[{component}]",
        )
        expected_path = DEPENDENCY_SEED_COMPONENT_PATHS[component]
        if declared_component["path"] != expected_path:
            raise EvidenceValidationError(
                "dependency seed component path does not match the frozen layout"
            )
        observed = _dependency_seed_component_summary(
            root / expected_path,
            component=component,
        )
        if declared_component != {"path": expected_path, **observed}:
            raise EvidenceValidationError(
                "dependency seed manifest component summary does not match the physical tree"
            )
        observed_components[component] = observed

    _validate_dependency_seed_semantics(root, repository, head)

    declared_seed = _object(source["dependencySeed"], "source.dependencySeed")
    actual_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(
        declared_seed["manifestSha256"], actual_manifest_sha256
    ):
        raise EvidenceValidationError(
            "source.dependencySeed.manifestSha256 does not match the physical manifest"
        )
    expected_public_identity = {
        "kind": manifest_object["kind"],
        "schemaVersion": manifest_object["schemaVersion"],
        "platform": runtime_platform,
        "architecture": runtime_architecture,
        "versions": manifest_object["versions"],
        "sourceSha256": candidate_source_hashes,
        "components": observed_components,
    }
    for field in (
        "kind", "schemaVersion", "platform", "architecture", "versions",
        "sourceSha256", "components",
    ):
        if declared_seed[field] != expected_public_identity[field]:
            raise EvidenceValidationError(
                f"source.dependencySeed.{field} does not match the independent physical rescan"
            )
    actual_anchor = hashlib.sha256(json.dumps(
        expected_public_identity,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual_anchor, expected_anchor):
        raise EvidenceValidationError(
            "dependency seed independent aggregate does not match the external SHA-256 trust anchor"
        )
    if not hmac.compare_digest(declared_seed["aggregateSha256"], actual_anchor):
        raise EvidenceValidationError(
            "source.dependencySeed.aggregateSha256 does not match the independent physical rescan"
        )

    # A mutable directory is accepted only after an identical second scan.
    try:
        manifest_metadata_after = manifest_path.lstat()
        manifest_bytes_after = _seed_file_bytes(
            manifest_path,
            manifest_metadata_after,
            "dependency seed manifest",
            maximum_bytes=64 * 1024,
        )
        observed_after = {
            component: _dependency_seed_component_summary(
                root / DEPENDENCY_SEED_COMPONENT_PATHS[component],
                component=component,
            )
            for component in DEPENDENCY_SEED_COMPONENTS
        }
        top_level_after = {entry.name for entry in os.scandir(root)}
        root_metadata_after = root.lstat()
    except OSError as exception:
        raise EvidenceValidationError(
            "dependency seed changed during independent validation"
        ) from exception
    if (
        not _same_seed_file(manifest_metadata, manifest_metadata_after)
        or manifest_bytes_after != manifest_bytes
        or observed_after != observed_components
        or top_level_after != expected_top_level
        or (
            root_metadata.st_dev,
            root_metadata.st_ino,
            root_metadata.st_mode,
            root_metadata.st_uid,
        )
        != (
            root_metadata_after.st_dev,
            root_metadata_after.st_ino,
            root_metadata_after.st_mode,
            root_metadata_after.st_uid,
        )
    ):
        raise EvidenceValidationError(
            "dependency seed changed during independent validation"
        )
    if (
        _git_object_id(repository, "HEAD^{commit}", "candidate HEAD") != head
        or _git_object_id(repository, "HEAD^{tree}", "candidate tree") != tree
    ):
        raise EvidenceValidationError(
            "Git candidate identity changed during dependency seed validation"
        )
    _require_clean_candidate(repository)


def _validate_candidate_binding(
    source: Mapping[str, Any], repository_root: Path
) -> tuple[Path, str, str]:
    """Bind a PASS claim to one clean HEAD/tree and its exact committed bytes."""
    repository = _resolve_git_repository(repository_root)
    head = _git_object_id(repository, "HEAD^{commit}", "candidate HEAD")
    tree = _git_object_id(repository, "HEAD^{tree}", "candidate tree")
    if source["v2Commit"] != head:
        raise EvidenceValidationError(
            "source.v2Commit does not match the current Git candidate HEAD"
        )
    if source["v2Tree"] != tree:
        raise EvidenceValidationError(
            "source.v2Tree does not match the current Git candidate tree"
        )
    _require_clean_candidate(repository)

    declared_hashes: dict[str, tuple[str, str]] = {
        TOOL_PATH: (source["toolSha256"], "source.toolSha256"),
        SCHEMA_PATH: (source["schemaSha256"], "source.schemaSha256"),
    }
    for relative, digest in source["currentAdapterSnapshotSha256"].items():
        declared_hashes[relative] = (
            digest,
            f"source.currentAdapterSnapshotSha256[{relative}]",
        )
    for relative, digest in source["runtimeSourceSha256"].items():
        existing = declared_hashes.get(relative)
        if existing is not None and existing[0] != digest:
            raise EvidenceValidationError(
                f"candidate source has conflicting declared hashes: {relative}"
            )
        declared_hashes[relative] = (
            digest,
            f"source.runtimeSourceSha256[{relative}]",
        )

    for relative, (declared, label) in declared_hashes.items():
        actual = hashlib.sha256(_candidate_blob(repository, head, relative)).hexdigest()
        if declared != actual:
            raise EvidenceValidationError(
                f"{label} does not match the current Git candidate bytes"
            )

    if (
        _git_object_id(repository, "HEAD^{commit}", "candidate HEAD") != head
        or _git_object_id(repository, "HEAD^{tree}", "candidate tree") != tree
    ):
        raise EvidenceValidationError("Git candidate identity changed during validation")
    _require_clean_candidate(repository)
    return repository, head, tree


def validate_document_path(
    path: Path,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    dependency_seed: Path | None = None,
    expected_dependency_seed_sha256: str | None = None,
    require_pass: bool = False,
) -> dict[str, Any]:
    """Bind PASS evidence to a clean candidate and independently rescanned seed."""
    expanded = path.expanduser().absolute()
    document = load_document(expanded)
    resolved = expanded.resolve()
    repository = repository_root.expanduser().absolute().resolve()
    if _inside(resolved, repository) or _inside(repository, resolved.parent):
        raise EvidenceValidationError("evidence document must be outside and must not contain the repository")
    if stat.S_IMODE(expanded.stat().st_mode) != 0o600:
        raise EvidenceValidationError("evidence document must have mode 0600")
    if expanded.parent.is_symlink() or stat.S_IMODE(expanded.parent.stat().st_mode) != 0o700:
        raise EvidenceValidationError("evidence directory must be a real directory with mode 0700")
    if expected_dependency_seed_sha256 is not None:
        _sha256(
            expected_dependency_seed_sha256,
            "expected dependency seed SHA-256 trust anchor",
        )
    summary = validate_document(document)
    if summary["status"] == "PASS":
        if dependency_seed is None or expected_dependency_seed_sha256 is None:
            raise EvidenceValidationError(
                "PASS validation requires dependency seed and external SHA-256 trust anchor"
            )
        source = _object(document["source"], "source")
        candidate, head, tree = _validate_candidate_binding(source, repository_root)
        _validate_dependency_seed_binding(
            source,
            dependency_seed,
            expected_dependency_seed_sha256,
            candidate,
            head,
            tree,
        )
    if require_pass and summary["status"] != "PASS":
        raise EvidenceNotPassingError(summary["status"])
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Independently validate a V1 to V2 upgrade rehearsal result without Docker "
            "or third-party dependencies."
        )
    )
    result.add_argument("--document", required=True, type=Path)
    result.add_argument(
        "--repository-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="Git worktree whose clean HEAD and bytes must match PASS evidence",
    )
    result.add_argument(
        "--dependency-seed",
        required=True,
        type=Path,
        help=(
            "original caller-owned mode-0700 dependency seed that PASS evidence "
            "must match under an independent physical rescan"
        ),
    )
    result.add_argument(
        "--expected-dependency-seed-sha256",
        required=True,
        help=(
            "external lowercase SHA-256 trust anchor for the canonical dependency "
            "seed identity and independently observed component trees"
        ),
    )
    result.add_argument(
        "--require-pass",
        action="store_true",
        help="return a non-zero status when valid evidence is NOT_COVERED, ENV_REQUIRED, or FAIL",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_document_path(
            args.document,
            repository_root=args.repository_root,
            dependency_seed=args.dependency_seed,
            expected_dependency_seed_sha256=args.expected_dependency_seed_sha256,
            require_pass=args.require_pass,
        )
    except EvidenceNotPassingError as error:
        print(f"FAIL validate-v1-upgrade-evidence: {error}", file=sys.stderr)
        return STATUS_EXIT_CODES[error.status]
    except EvidenceValidationError as error:
        print(f"FAIL validate-v1-upgrade-evidence: {error}", file=sys.stderr)
        return 1
    print(
        "PASS validate-v1-upgrade-evidence: "
        f"status={summary['status']} checks={summary['checkCount']} "
        f"acceptance={summary['acceptanceCount']} phases={summary['phaseCount']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
