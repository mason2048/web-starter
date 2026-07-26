#!/usr/bin/env python3
"""Run the isolated, fail-closed V1 to V2 upgrade and recovery rehearsal.

This is the only supported orchestration entry point for the rehearsal.  It
freezes the annotated V1 source, creates a randomly named Compose project and
databases, exercises the repository recovery tools, and records sanitized
status evidence.  Secret-bearing runtime files never enter the evidence
directory and are removed in ``finally`` after exact ownership checks.

The implementation intentionally does not accept arbitrary hook commands.  A
failed or unimplemented observation remains NOT_COVERED and can never be
promoted to PASS by an operator-authored JSON file.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
import xml.etree.ElementTree as ElementTree
import zlib

try:
    from scripts.v1_upgrade_refresh import (
        OAuthTokenSet,
        PkceRefreshError,
        authorization_code_pkce_once,
        expect_refresh_invalid_grant_once,
        install_no_redirect_handler,
        refresh_token_once,
    )
except ModuleNotFoundError as exception:
    if exception.name != "scripts":
        raise
    from v1_upgrade_refresh import (  # type: ignore[no-redef]
        OAuthTokenSet,
        PkceRefreshError,
        authorization_code_pkce_once,
        expect_refresh_invalid_grant_once,
        install_no_redirect_handler,
        refresh_token_once,
    )

try:
    from scripts.acceptance_network import (
        RejectRedirectHandler,
        isolated_loopback_resolution,
        reject_tls_key_logging,
    )
except ModuleNotFoundError as exception:
    if exception.name != "scripts":
        raise
    from acceptance_network import (  # type: ignore[no-redef]
        RejectRedirectHandler,
        isolated_loopback_resolution,
        reject_tls_key_logging,
    )


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "rehearse_v1_to_v2_upgrade.py"
SCHEMA_PATH = REPOSITORY_ROOT / "security" / "v2-v1-upgrade-rehearsal.schema.json"
RESULT_NAME = "v2-v1-upgrade-rehearsal.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"

V1_TAG = "v1.0.0"
V1_COMMIT = "5ebdb238650d182c17e1493adf47aaa3324f19cb"
V1_ACCESS_TOKEN_TTL_SECONDS = 2 * 60 * 60
V2_ACCESS_TOKEN_TTL_SECONDS = 10 * 60
V2_MINIMUM_REMAINING_TTL_SECONDS = V2_ACCESS_TOKEN_TTL_SECONDS - 60
RETIRING_KEY_CLOCK_SKEW_SECONDS = 15 * 60
V1_MIGRATIONS = (
    "web-starter-admin/src/main/resources/db/migration/V1__create_core_schema.sql",
    "web-starter-admin/src/main/resources/db/migration/V2__seed_reference_data.sql",
    "web-starter-admin/src/main/resources/db/migration/V3__add_oauth_refresh_token_families.sql",
)
V2_MIGRATIONS = V1_MIGRATIONS + (
    "web-starter-admin/src/main/resources/db/migration/V4__add_identity_security_epoch.sql",
    "web-starter-admin/src/main/resources/db/migration/V5__add_mcp_idempotency.sql",
    "web-starter-admin/src/main/resources/db/migration/V6__add_mcp_idempotency_audit.sql",
    "web-starter-admin/src/main/resources/db/migration/V7__add_credential_rotation.sql",
)
V2_ONLY_MIGRATIONS = V2_MIGRATIONS[len(V1_MIGRATIONS):]
# These adapters come from the V2 candidate worktree, not from the V1 tag.
# They are copied byte-for-byte into the private runtime so one rehearsal
# cannot silently switch implementation half way through.  The V1 tag itself
# contains only the repository-policy scripts listed below.
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
MCP_SDK_TEST_SOURCES = {
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
MCP_SUREFIRE_REPORTS_PROPERTY = "web-starter.mcp.surefire-reports-directory"
MCP_CRUD_FAULT_CONSTRAINT = "chk_webstarter_ac40_tx_audit"
MCP_CRUD_FAILURE_SUFFIX = "-transaction-audit-failure"
PINNED_PNPM_COMMAND = ("corepack", "pnpm@9.15.9")
DEPENDENCY_SEED_KIND = "web-starter-ac40-dependency-seed"
DEPENDENCY_SEED_SCHEMA_VERSION = 1
DEPENDENCY_SEED_COMPONENTS = {
    "mavenHome": "maven-home",
    "mavenRepository": "maven-repository",
    "corepackHome": "corepack-home",
    "pnpmStore": "pnpm-store",
    "playwrightBrowsers": "playwright-browsers",
}
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
INCOMPLETE_SEED_NAMES = frozenset({
    ".lastUpdated", ".part", ".partial", ".tmp", ".lock", ".download", ".aria2",
})
PLAYWRIGHT_TEST_SOURCES = (
    "web-starter-web/e2e/frontend-quality-runtime.spec.ts",
    "web-starter-web/e2e/release-runtime.spec.ts",
    "web-starter-web/e2e/v1-management-runtime.spec.ts",
)
PLAYWRIGHT_EXPECTED_TITLES = {
    "frontend-quality-runtime.spec.ts": (
        "real login endpoint applies generic progressive protection without blocking another account",
        "query, pagination, loading, empty and validation states remain usable in a real browser",
        "401, 403, 404, 409, 429 and 500 states have stable browser behavior and trace IDs",
        "desktop, tablet and 390px layouts pass keyboard and basic accessibility checks",
    ),
    "release-runtime.spec.ts": (
        "private Web UI performs Project CRUD, trace correlation and responsive rendering",
        "all frozen management pages expose usable primary browser controls",
        "management write domains persist complete operation audit records",
        "public OAuth authorization-code flow requires PKCE and yields a usable MCP token",
        "personal security manages real browser sessions and prevents self-elevation",
        "credential management filters lifecycle states without redisplaying secrets",
        "audit search filters login operation and MCP records with correlated redacted traces",
    ),
    "v1-management-runtime.spec.ts": (
        "AC-06 user management completes the full browser lifecycle with operation audits",
        "AC-07 role CRUD assigns permissions and menus, rejects stale versions and revokes the next request",
        "AC-08 administrator continuity rejects self lockout, last-admin loss and built-in role weakening",
        "AC-09 withdrawing a role menu removes navigation and routes the existing user to 403",
        "AC-10 missing create permission hides the button and the manual API call still returns 403",
        "AC-11 permission dictionary enforces unique codes, controllable status and protected assignments",
        "AC-12 non-sensitive configuration is maintained in the browser while secret-like keys are rejected",
        "AC-13 project list supports paging cap keyword status filters and browser details",
        "AC-14 project writes enforce uniqueness validation optimistic conflict and logical deletion",
    ),
}
PLAYWRIGHT_DIAGNOSTIC_ALIASES = {
    "frontend-quality-runtime.spec.ts": "FQ",
    "release-runtime.spec.ts": "REL",
    "v1-management-runtime.spec.ts": "V1M",
}
CURRENT_RUNTIME_SOURCE_FILES = (
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
    *V2_ONLY_MIGRATIONS,
    *MCP_SDK_TEST_SOURCES.values(),
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
    "web-starter-web/playwright.config.ts",
    *PLAYWRIGHT_TEST_SOURCES,
)
V1_TAG_SCRIPT_FILES = (
    "scripts/repository_policy.py",
    "scripts/test_repository_policy.py",
)

ALLOWED_STATUSES = frozenset({"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"})
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 6
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
COMPOSE_PROJECT = re.compile(r"^web-starter-ac40-[0-9a-f]{12}$")
DATABASE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
OAUTH_AUTHORIZATION_ID = re.compile(r"^[A-Za-z0-9._~-]{1,100}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

INPUT_IMAGE_ROLES = ("mysql", "redis")
CANDIDATE_IMAGE_ROLES = ("v2-app", "v2-nginx")
RESOLVED_IMAGE_ROLES = (*CANDIDATE_IMAGE_ROLES, *INPUT_IMAGE_ROLES)
BUILT_IMAGE_ROLES = ("v1-app", "v1-nginx", *CANDIDATE_IMAGE_ROLES)
SERVICE_IMAGE_ROLES = ("mysql", "redis", "app", "nginx", "mcp-public-nginx")

LABEL_OWNER = "dev.webstarter.upgrade"
LABEL_RUN = "dev.webstarter.upgrade.run"
LABEL_ROLE = "dev.webstarter.upgrade.role"
OWNER_VALUE = "v1-to-v2"

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

PHASE_REQUIRED_CHECKS: Mapping[str, tuple[str, ...]] = {
    "source-freeze": tuple(name for name in REQUIRED_CHECKS if name.startswith("source.")),
    "cryptographic-preflight": (
        "preflight.requiredCommands", "preflight.frozenScriptImports", "keys.v1Pkcs8Der",
    ),
    "runtime-preflight": (
        "preflight.composeConfiguration", "preflight.publishedPorts",
        "preflight.composeProjectIsolation", "preflight.databaseIsolation",
    ),
    "v1-fixtures": ("keys.v1KidCaptured",),
    "backup-restore": ("backup.consistentPackage", "restore.newDatabaseVerified"),
    "v2-migration": (
        "migration.flywayOneThroughSeven", "migration.v1RowsPreserved",
        "migration.v1ProjectionPreserved",
    ),
    "credential-compatibility": (
        "oauth.preUpgradeUserAuthorizationAccepted", "oauth.oldKidPublicOnly",
        "oauth.newKidActiveSigning", "oauth.preUpgradeClientCredentialAccepted", "oauth.freshClientCredentials",
        "credential.oldPatRead", "credential.preUpgradeServiceAccessAccepted",
        "credential.preUpgradeRefreshRotationAccepted", "compatibility.mcpReadAndDiscovery",
    ),
    "runtime-acceptance": (
        "credential.oldPatCrud", "compatibility.restProjectCrud",
        "authorization.permissionDenied", "browser.playwright",
        "mcp.crudIdempotencyAudit", "audit.traceSearch",
    ),
    "lifecycle-readback": (
        "lifecycle.revokedPatRejectedAndReadBack",
        "lifecycle.disabledServiceRejectedAndReadBack",
        "integrity.finalSource",
    ),
    "cleanup": ("cleanup.exactOwnedResources",),
}

# Audit tables append during runtime validation.  Every V1 row must still be
# present byte-for-byte, while new audit rows are allowed.
AUDIT_TABLES = frozenset({"sys_login_log", "sys_operation_log", "sys_mcp_call_log"})


class UpgradeRehearsalError(RuntimeError):
    """A safe, non-secret-bearing orchestration failure."""

    def __init__(self, code: str, message: str, *, environment: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.environment = environment


def _reject_tls_key_log() -> None:
    try:
        reject_tls_key_logging()
    except ValueError as error:
        raise UpgradeRehearsalError("TLS_KEY_LOGGING", str(error)) from error


@dataclass(frozen=True)
class ResourceNames:
    run_id: str
    compose_project: str
    source_database: str
    target_database: str
    public_hostname: str
    private_hostname: str


@dataclass(frozen=True)
class Ports:
    private_http: int
    public_https: int
    management: int

    def values(self) -> tuple[int, ...]:
        return self.private_http, self.public_https, self.management


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass
class PhaseObservation:
    name: str
    status: str = "NOT_COVERED"
    started_at: str | None = None
    finished_at: str | None = None
    detail_code: str = "NOT_STARTED"


@dataclass
class EvidenceState:
    checks: dict[str, dict[str, Any]] = field(default_factory=lambda: {
        name: {"status": "NOT_COVERED", "detailCode": "NOT_OBSERVED"}
        for name in REQUIRED_CHECKS
    })
    phases: dict[str, PhaseObservation] = field(default_factory=lambda: {
        name: PhaseObservation(name) for name in PHASE_ORDER
    })
    current_phase_index: int = -1

    def start_phase(self, name: str) -> None:
        if name not in self.phases:
            raise UpgradeRehearsalError("STATE_UNKNOWN_PHASE", "unknown rehearsal phase")
        expected = self.current_phase_index + 1
        actual = PHASE_ORDER.index(name)
        if actual != expected:
            raise UpgradeRehearsalError(
                "STATE_PHASE_ORDER", "rehearsal phases must execute in the frozen order"
            )
        self.current_phase_index = actual
        observation = self.phases[name]
        observation.started_at = utc_now()
        observation.detail_code = "RUNNING"

    def finish_phase(self, name: str, status: str, detail_code: str) -> None:
        validate_status(status)
        observation = self.phases[name]
        if observation.started_at is None or observation.finished_at is not None:
            raise UpgradeRehearsalError("STATE_PHASE_FINISH", "phase was not active")
        if status == "PASS" and any(
            self.checks[check]["status"] != "PASS"
            for check in PHASE_REQUIRED_CHECKS.get(name, ())
        ):
            raise UpgradeRehearsalError(
                "STATE_PHASE_CHECKS", "a phase cannot pass before all of its checks pass"
            )
        observation.status = status
        observation.detail_code = validate_detail_code(detail_code)
        observation.finished_at = utc_now()

    def mark(self, name: str, status: str, detail_code: str) -> None:
        if name not in self.checks:
            raise UpgradeRehearsalError("STATE_UNKNOWN_CHECK", "unknown rehearsal check")
        validate_status(status)
        current = self.checks[name]
        if current["detailCode"] != "NOT_OBSERVED":
            raise UpgradeRehearsalError("STATE_CHECK_REWRITE", "check status is immutable once observed")
        self.checks[name] = {
            "status": status,
            "detailCode": validate_detail_code(detail_code),
        }

    def fail_current_phase(self, detail_code: str, *, environment: bool) -> None:
        if self.current_phase_index < 0:
            return
        phase = self.phases[PHASE_ORDER[self.current_phase_index]]
        if phase.finished_at is None:
            self.finish_phase(
                phase.name,
                "ENV_REQUIRED" if environment else "FAIL",
                detail_code,
            )


@dataclass
class RuntimeContext:
    output_directory: Path
    runtime_root: Path
    names: ResourceNames
    ports: Ports
    state: EvidenceState
    environment: dict[str, str] = field(default_factory=dict)
    intended_image_tags: dict[str, str] = field(default_factory=dict)
    created_image_tags: dict[str, str] = field(default_factory=dict)
    created_image_ids: dict[str, str] = field(default_factory=dict)
    resolved_images: dict[str, str] = field(default_factory=dict)
    input_image_references: dict[str, str] = field(default_factory=dict)
    started_container_images: dict[str, dict[str, str]] = field(default_factory=dict)
    helper_hashes: dict[str, str] = field(default_factory=dict)
    runtime_source_hashes: dict[str, str] = field(default_factory=dict)
    v2_commit: str | None = None
    v2_tree: str | None = None
    clean_worktree: bool = False
    frozen_tool_sha256: str | None = None
    frozen_schema_sha256: str | None = None
    evidence_validator: Callable[[Mapping[str, Any]], None] | None = None
    resource_cleanup_authorized: bool = False
    resource_mutation_started: bool = False
    compose_files_v1: tuple[Path, ...] = ()
    compose_files_v2: tuple[Path, ...] = ()
    sdk_source_root: Path | None = None
    sdk_source_hashes: dict[str, str] = field(default_factory=dict)
    sdk_dependencies_prepared: bool = False
    sdk_invocation_count: int = 0
    playwright_dependencies_prepared: bool = False
    playwright_temp_root: Path | None = None
    cleanup_summary: dict[str, Any] = field(default_factory=dict)
    sanitized_observations: dict[str, Any] = field(default_factory=dict)
    dependency_seed_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DependencySeed:
    root: Path
    manifest_bytes: bytes
    evidence: dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitized_host_environment() -> dict[str, str]:
    """Keep only host plumbing, never ambient acceptance behavior toggles."""
    exact = {
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG",
        "JAVA_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy",
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH", "DOCKER_CONFIG",
    }
    return {
        name: value
        for name, value in os.environ.items()
        if name in exact or name.startswith("LC_")
    }


def git_environment() -> dict[str, str]:
    """Use the intended repository without ambient Git redirection/config."""
    environment = sanitized_host_environment()
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    })
    return environment


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_MANIFEST", "dependency seed manifest repeats a field"
            )
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise UpgradeRehearsalError(
        "DEPENDENCY_SEED_MANIFEST", "dependency seed manifest contains a non-finite number"
    )


def _safe_seed_name(name: str) -> bool:
    return bool(name) and not any(ord(character) < 32 or ord(character) == 127 for character in name)


def _seed_incomplete_name(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(marker.lower()) for marker in INCOMPLETE_SEED_NAMES)


def _component_tree_summary(
        root: Path,
        *,
        component: str,
        enforce_owner: bool = True) -> dict[str, Any]:
    """Hash one private dependency-cache tree deterministically.

    The package-manager and Maven caches remain completely link-free.  A
    Playwright browser bundle may contain the relative, in-tree links used by
    a macOS framework.  Those links are validated without following them
    during enumeration and their original target text is bound into the tree
    digest.
    """
    if root.is_symlink() or not root.is_dir():
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_LAYOUT", "dependency seed component must be a real directory"
        )
    root_stat = root.stat()
    if stat.S_IMODE(root_stat.st_mode) != 0o700 or (
        enforce_owner and root_stat.st_uid != os.getuid()
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MODE", "dependency seed directories must be owned and mode 0700"
        )

    resolved_root = root.resolve(strict=True)
    records: list[tuple[str, str, int, int, str]] = []
    directory_edges: dict[Path, set[Path]] = {}
    file_count = 0
    byte_count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        resolved_directory = directory.resolve(strict=True)
        directory_edges.setdefault(resolved_directory, set())
        try:
            entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as exception:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_READ", "dependency seed component cannot be enumerated"
            ) from exception
        directories: list[Path] = []
        for entry in entries:
            if not _safe_seed_name(entry.name) or _seed_incomplete_name(entry.name):
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_INCOMPLETE",
                    "dependency seed contains an unsafe or incomplete marker",
                )
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exception:
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_READ", "dependency seed entry cannot be inspected"
                ) from exception
            mode = stat.S_IMODE(metadata.st_mode)
            if enforce_owner and metadata.st_uid != os.getuid():
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_OWNER", "dependency seed entries must be owned by the caller"
                )
            if stat.S_ISLNK(metadata.st_mode):
                if component != "playwrightBrowsers":
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_LINK",
                        "only the Playwright browser seed may contain symbolic links",
                    )
                try:
                    raw_target = os.readlink(path)
                except OSError as exception:
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_LINK", "dependency seed link cannot be read"
                    ) from exception
                if not _safe_seed_name(raw_target) or Path(raw_target).is_absolute():
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_LINK",
                        "Playwright dependency seed links must use safe relative targets",
                    )
                lexical_depth = len(path.parent.relative_to(root).parts)
                for part in Path(raw_target).parts:
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if lexical_depth == 0:
                            raise UpgradeRehearsalError(
                                "DEPENDENCY_SEED_LINK",
                                "Playwright dependency seed link escapes its component",
                            )
                        lexical_depth -= 1
                    else:
                        lexical_depth += 1
                try:
                    resolved_target = path.resolve(strict=True)
                except (OSError, RuntimeError) as exception:
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_LINK",
                        "Playwright dependency seed link is dangling or cyclic",
                    ) from exception
                if not _inside(resolved_target, resolved_root):
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_LINK",
                        "Playwright dependency seed link escapes its component",
                    )
                try:
                    target_bytes = raw_target.encode("utf-8")
                except UnicodeEncodeError as exception:
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_LINK",
                        "Playwright dependency seed link target is not valid UTF-8",
                    ) from exception
                records.append((
                    "L", relative, mode, len(target_bytes), sha256_bytes(target_bytes)
                ))
                if resolved_target.is_dir():
                    directory_edges[resolved_directory].add(resolved_target)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if mode != 0o700:
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_MODE", "dependency seed directories must have mode 0700"
                    )
                records.append(("D", relative, mode, 0, ""))
                resolved_child = path.resolve(strict=True)
                directory_edges[resolved_directory].add(resolved_child)
                directory_edges.setdefault(resolved_child, set())
                directories.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_FILE_TYPE", "dependency seed contains a special file"
                )
            if metadata.st_nlink != 1:
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_LINK", "dependency seed must not contain hard links"
                )
            if mode & 0o7077 or not mode & stat.S_IRUSR:
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_MODE",
                    "dependency seed files must be owner-readable without group, other, or special bits",
                )
            if component == "mavenRepository":
                parts = Path(relative).parts
                if parts[:2] == ("dev", "webstarter") or entry.name.startswith("web-starter-"):
                    raise UpgradeRehearsalError(
                        "DEPENDENCY_SEED_PROJECT_ARTIFACT",
                        "dependency seed must not contain locally built project artifacts",
                    )
            if file_count >= 500_000 or byte_count + metadata.st_size > 8 * 1024**3:
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_SIZE", "dependency seed exceeds the bounded cache size"
                )
            digest = sha256_file(path)
            records.append(("F", relative, mode, metadata.st_size, digest))
            file_count += 1
            byte_count += metadata.st_size
        stack.extend(reversed(directories))

    # Real directory edges plus directory-link edges form the traversal graph.
    # A link back to an ancestor or a pair of mutually linked directories is
    # unsafe even when resolving either individual link would terminate.
    directory_state: dict[Path, int] = {}
    traversal: list[tuple[Path, bool]] = [(resolved_root, False)]
    while traversal:
        directory, finishing = traversal.pop()
        state = directory_state.get(directory, 0)
        if finishing:
            directory_state[directory] = 2
            continue
        if state == 1:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_LINK",
                "Playwright dependency seed contains a cyclic directory link",
            )
        if state == 2:
            continue
        directory_state[directory] = 1
        traversal.append((directory, True))
        for target in sorted(
            directory_edges.get(directory, set()), key=lambda item: os.fsencode(str(item)),
            reverse=True,
        ):
            if directory_state.get(target, 0) == 1:
                raise UpgradeRehearsalError(
                    "DEPENDENCY_SEED_LINK",
                    "Playwright dependency seed contains a cyclic directory link",
                )
            if directory_state.get(target, 0) != 2:
                traversal.append((target, False))

    if file_count == 0:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_EMPTY", "dependency seed components must not be empty"
        )
    digest = hashlib.sha256()
    for kind, relative, mode, size, payload_sha256 in sorted(records, key=lambda item: item[1]):
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


def _manifest_source_hashes(source_root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in DEPENDENCY_SEED_SOURCE_FILES:
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_SOURCE", "dependency seed source binding is unavailable"
            )
        hashes[relative] = sha256_file(path)
    return hashes


def _validate_seed_semantics(
        root: Path,
        components: Mapping[str, Mapping[str, Any]],
        source_root: Path) -> None:
    wrapper_properties = source_root / ".mvn" / "wrapper" / "maven-wrapper.properties"
    properties: dict[str, str] = {}
    for line in wrapper_properties.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key.strip()] = value.strip()
    distribution_url = properties.get("distributionUrl", "")
    distribution_sha256 = properties.get("distributionSha256Sum", "")
    expected_url_suffix = "/apache-maven/3.9.15/apache-maven-3.9.15-bin.zip"
    if (
        not distribution_url.endswith(expected_url_suffix)
        or not SHA256.fullmatch(distribution_sha256)
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MAVEN", "Maven Wrapper is not the frozen 3.9.15 distribution"
        )
    wrapper_home = (
        root
        / DEPENDENCY_SEED_COMPONENTS["mavenHome"]
        / "wrapper"
        / "dists"
        / "apache-maven-3.9.15"
        / _java_string_hash(distribution_url)
    )
    wrapper_binary = wrapper_home / "bin" / "mvn"
    if (
        wrapper_binary.is_symlink()
        or not wrapper_binary.is_file()
        or not wrapper_binary.stat().st_mode & stat.S_IXUSR
        or (root / DEPENDENCY_SEED_COMPONENTS["mavenHome"] / "repository").exists()
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MAVEN", "dependency seed lacks the exact executable Maven Wrapper home"
        )
    maven_repository = root / DEPENDENCY_SEED_COMPONENTS["mavenRepository"]
    if not any(maven_repository.rglob("*.pom")) or not any(maven_repository.rglob("*.jar")):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MAVEN", "dependency seed Maven repository is incomplete"
        )

    pnpm_package = (
        root / DEPENDENCY_SEED_COMPONENTS["corepackHome"]
        / "v1" / "pnpm" / DEPENDENCY_SEED_VERSIONS["pnpm"] / "package.json"
    )
    try:
        pnpm_document = json.loads(pnpm_package.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_PNPM", "dependency seed pnpm package is unavailable"
        ) from exception
    if not isinstance(pnpm_document, dict) or pnpm_document.get("version") != "9.15.9":
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_PNPM", "dependency seed does not contain pnpm 9.15.9"
        )
    # pnpm 9 receives the component root via --store-dir and resolves content
    # below <store-dir>/v3/files.  Accepting a legacy <store-dir>/files shape
    # would pass preflight and then fail only after the runtime has started.
    pnpm_files = root / DEPENDENCY_SEED_COMPONENTS["pnpmStore"] / "v3" / "files"
    if pnpm_files.is_symlink() or not pnpm_files.is_dir() or not any(pnpm_files.iterdir()):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_PNPM", "dependency seed pnpm v3 store is incomplete"
        )

    chromium = (
        root / DEPENDENCY_SEED_COMPONENTS["playwrightBrowsers"]
        / f"chromium-{DEPENDENCY_SEED_VERSIONS['chromiumRevision']}"
    )
    if not (chromium / "INSTALLATION_COMPLETE").is_file() or not any(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_mode & stat.S_IXUSR
        and path.name in {"chrome", "Google Chrome for Testing"}
        for path in chromium.rglob("*")
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_PLAYWRIGHT",
            "dependency seed lacks the complete executable Chromium revision 1228",
        )
    if set(components) != set(DEPENDENCY_SEED_COMPONENTS):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_COMPONENTS", "dependency seed component set is not exact"
        )


def validate_dependency_seed(
        path: Path,
        *,
        expected_aggregate_sha256: str,
        source_root: Path = REPOSITORY_ROOT) -> DependencySeed:
    if not isinstance(expected_aggregate_sha256, str) or not SHA256.fullmatch(
        expected_aggregate_sha256
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_TRUST_ANCHOR",
            "expected dependency seed aggregate SHA-256 is invalid",
        )
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or not expanded.is_dir():
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_PATH", "dependency seed must be a real directory"
        )
    root = expanded.resolve()
    repository = source_root.resolve()
    if root == repository or _inside(root, repository) or _inside(repository, root):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_SCOPE", "dependency seed must stay outside the repository"
        )
    root_stat = root.stat()
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MODE", "dependency seed root must be caller-owned mode 0700"
        )
    expected_top_level = {"manifest.json", *DEPENDENCY_SEED_COMPONENTS.values()}
    if {entry.name for entry in os.scandir(root)} != expected_top_level:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_LAYOUT", "dependency seed top-level layout is not exact"
        )
    manifest_path = root / "manifest.json"
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.stat().st_uid != os.getuid()
        or stat.S_IMODE(manifest_path.stat().st_mode) != 0o600
        or manifest_path.stat().st_size > 64 * 1024
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MANIFEST", "dependency seed manifest must be a private regular file"
        )
    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_nonfinite_json,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MANIFEST", "dependency seed manifest is invalid JSON"
        ) from exception
    if not isinstance(manifest, dict) or set(manifest) != {
        "schemaVersion", "kind", "platform", "architecture", "versions",
        "sourceSha256", "components",
    }:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_MANIFEST", "dependency seed manifest fields are not exact"
        )
    expected_platform = sys.platform
    expected_architecture = platform.machine().lower()
    if (
        manifest["schemaVersion"] != DEPENDENCY_SEED_SCHEMA_VERSION
        or isinstance(manifest["schemaVersion"], bool)
        or manifest["kind"] != DEPENDENCY_SEED_KIND
        or manifest["platform"] != expected_platform
        or manifest["architecture"] != expected_architecture
        or manifest["versions"] != DEPENDENCY_SEED_VERSIONS
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_IDENTITY", "dependency seed identity does not match this runtime"
        )
    source_hashes = _manifest_source_hashes(source_root)
    if manifest["sourceSha256"] != source_hashes:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_SOURCE", "dependency seed is not bound to the current candidate sources"
        )
    declared_components = manifest["components"]
    if not isinstance(declared_components, dict) or set(declared_components) != set(
        DEPENDENCY_SEED_COMPONENTS
    ):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_COMPONENTS", "dependency seed component manifest is not exact"
        )
    summaries: dict[str, dict[str, Any]] = {}
    for component, relative in DEPENDENCY_SEED_COMPONENTS.items():
        declared = declared_components[component]
        if not isinstance(declared, dict) or set(declared) != {
            "path", "treeSha256", "fileCount", "byteCount",
        } or declared.get("path") != relative:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_COMPONENTS", "dependency seed component fields are not exact"
            )
        observed = _component_tree_summary(root / relative, component=component)
        if declared != {"path": relative, **observed}:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_DIGEST", "dependency seed component digest does not match"
            )
        summaries[component] = observed
    _validate_seed_semantics(root, summaries, source_root)
    aggregate_payload = {
        "kind": DEPENDENCY_SEED_KIND,
        "schemaVersion": DEPENDENCY_SEED_SCHEMA_VERSION,
        "platform": expected_platform,
        "architecture": expected_architecture,
        "versions": DEPENDENCY_SEED_VERSIONS,
        "sourceSha256": source_hashes,
        "components": summaries,
    }
    aggregate_sha256 = sha256_bytes(json.dumps(
        aggregate_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"))
    if not hmac.compare_digest(aggregate_sha256, expected_aggregate_sha256):
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_TRUST_ANCHOR",
            "dependency seed does not match the expected aggregate SHA-256",
        )
    evidence = {
        **aggregate_payload,
        "manifestSha256": sha256_bytes(manifest_bytes),
        "aggregateSha256": aggregate_sha256,
        "copiedToPrivateRuntime": True,
        "executionPolicy": dict(DEPENDENCY_SEED_EXECUTION_POLICY),
    }
    return DependencySeed(root=root, manifest_bytes=manifest_bytes, evidence=evidence)


def _copy_dependency_seed(seed: DependencySeed, runtime: RuntimeContext) -> Path:
    destination = runtime.runtime_root / "dependency-seed"
    if destination.exists() or destination.is_symlink():
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_COPY", "private dependency seed destination already exists"
        )
    destination.mkdir(mode=0o700)
    write_private(destination / "manifest.json", seed.manifest_bytes)
    for component, relative in DEPENDENCY_SEED_COMPONENTS.items():
        source = seed.root / relative
        target = destination / relative
        try:
            shutil.copytree(source, target, symlinks=True, copy_function=shutil.copy2)
        except OSError as exception:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_COPY", "dependency seed could not be copied privately"
            ) from exception
        observed = _component_tree_summary(target, component=component)
        if observed != seed.evidence["components"][component]:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_COPY", "private dependency seed copy failed digest verification"
            )
        source_after_copy = _component_tree_summary(source, component=component)
        if source_after_copy != seed.evidence["components"][component]:
            raise UpgradeRehearsalError(
                "DEPENDENCY_SEED_COPY", "dependency seed changed while it was copied"
            )
    if sha256_file(destination / "manifest.json") != seed.evidence["manifestSha256"]:
        raise UpgradeRehearsalError(
            "DEPENDENCY_SEED_COPY", "private dependency seed manifest copy changed"
        )
    runtime.dependency_seed_evidence = seed.evidence
    return destination


def validate_status(status: str) -> str:
    if status not in ALLOWED_STATUSES:
        raise UpgradeRehearsalError("STATE_STATUS", "unsupported acceptance status")
    return status


def validate_detail_code(value: str) -> str:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", value):
        raise UpgradeRehearsalError("STATE_DETAIL", "invalid detail code")
    return value


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def ensure_external_empty_private_directory(path: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink():
        raise UpgradeRehearsalError("OUTPUT_SYMLINK", "output directory must not be a symbolic link")
    repository = REPOSITORY_ROOT.resolve()
    resolved = expanded.resolve()
    if resolved == repository or _inside(resolved, repository) or _inside(repository, resolved):
        raise UpgradeRehearsalError(
            "OUTPUT_SCOPE", "output directory must stay outside and must not contain the repository"
        )
    if expanded.exists():
        if not expanded.is_dir() or any(expanded.iterdir()):
            raise UpgradeRehearsalError("OUTPUT_NOT_EMPTY", "output directory must be empty")
        if stat.S_IMODE(expanded.stat().st_mode) & 0o077:
            raise UpgradeRehearsalError("OUTPUT_MODE", "output directory must have mode 0700")
    else:
        expanded.mkdir(parents=True, mode=0o700)
    expanded.chmod(0o700)
    return resolved


def write_private(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink() or path.parent.is_symlink():
        raise UpgradeRehearsalError("PRIVATE_WRITE_COLLISION", "private output path already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def write_private_json(path: Path, value: Any) -> None:
    write_private(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def generate_resource_names(run_id: str) -> ResourceNames:
    if not RUN_ID.fullmatch(run_id):
        raise UpgradeRehearsalError("RUN_ID", "run identifier must be twelve lowercase hex characters")
    project = f"web-starter-ac40-{run_id}"
    source = f"ws_v1_{run_id}"
    target = f"{source}_restore_v2"
    if not COMPOSE_PROJECT.fullmatch(project) or not DATABASE.fullmatch(source) or not DATABASE.fullmatch(target):
        raise UpgradeRehearsalError("RESOURCE_NAME", "generated rehearsal resource name is invalid")
    return ResourceNames(
        run_id=run_id,
        compose_project=project,
        source_database=source,
        target_database=target,
        public_hostname=f"mcp-{run_id}.upgrade.webstarter.test",
        private_hostname=f"private-{run_id}.upgrade.webstarter.test",
    )


def allocate_unique_loopback_ports(
        count: int = 3,
        socket_factory: Callable[..., socket.socket] = socket.socket) -> tuple[int, ...]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            candidate = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            candidate.bind(("127.0.0.1", 0))
            candidate.listen(1)
            sockets.append(candidate)
        values = tuple(int(item.getsockname()[1]) for item in sockets)
        if len(values) != len(set(values)) or any(value < 1024 or value > 65535 for value in values):
            raise UpgradeRehearsalError("PORT_ALLOCATION", "could not allocate unique unprivileged ports")
        return values
    finally:
        for candidate in sockets:
            candidate.close()


def assert_loopback_ports_unused(
        ports: Iterable[int],
        connector: Callable[[tuple[str, int]], Any] = socket.create_connection) -> None:
    values = tuple(ports)
    if len(values) != len(set(values)):
        raise UpgradeRehearsalError("PORT_DUPLICATE", "published ports must be unique")
    for port in values:
        if isinstance(port, bool) or not isinstance(port, int) or port < 1024 or port > 65535:
            raise UpgradeRehearsalError("PORT_RANGE", "published port is outside the allowed range")
        try:
            connection = connector(("127.0.0.1", port), timeout=0.2)
        except (ConnectionRefusedError, TimeoutError, OSError):
            continue
        try:
            connection.close()
        finally:
            raise UpgradeRehearsalError("PORT_IN_USE", "a selected loopback port is already in use")


def validate_image_reference(value: str, label: str) -> str:
    if (
        value != value.strip()
        or not IMAGE_REFERENCE.fullmatch(value)
        or value.startswith("-")
        or ".." in value
        or "://" in value
        or IMAGE_ID.fullmatch(value)
    ):
        raise UpgradeRehearsalError("IMAGE_REFERENCE", f"{label} image reference is unsafe")
    return value


def frozen_python_environment(frozen_root: Path, base: Mapping[str, str] | None = None) -> dict[str, str]:
    root = frozen_root.resolve()
    scripts = root / "scripts"
    if root.is_symlink() or scripts.is_symlink() or not scripts.is_dir():
        raise UpgradeRehearsalError("FROZEN_PYTHONPATH", "frozen tools directory is invalid")
    environment = dict(sanitized_host_environment() if base is None else base)
    environment["PYTHONPATH"] = os.pathsep.join((str(scripts), str(root)))
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def frozen_python_command(frozen_root: Path, relative_script: str, *arguments: str) -> list[str]:
    if relative_script not in CURRENT_ADAPTER_FILES or not relative_script.endswith(".py"):
        raise UpgradeRehearsalError("FROZEN_SCRIPT", "script is not in the frozen helper allowlist")
    script = (frozen_root / relative_script).resolve()
    expected_parent = (frozen_root / "scripts").resolve()
    if script.parent != expected_parent or not script.is_file() or script.is_symlink():
        raise UpgradeRehearsalError("FROZEN_SCRIPT", "frozen script path is invalid")
    return [str(Path(sys.executable).resolve()), "-B", str(script), *arguments]


def validate_v1_identity(
        git: Callable[[Sequence[str]], bytes]) -> dict[str, str]:
    object_type = git(("cat-file", "-t", V1_TAG)).decode("ascii").strip()
    commit = git(("rev-parse", f"{V1_TAG}^{{}}")).decode("ascii").strip()
    if object_type != "tag":
        raise UpgradeRehearsalError("V1_TAG_NOT_ANNOTATED", "V1 tag is not an annotated tag")
    if commit != V1_COMMIT:
        raise UpgradeRehearsalError("V1_COMMIT_MISMATCH", "V1 tag does not resolve to the frozen commit")
    return {"tagObjectType": object_type, "commit": commit}


def validate_v1_migration_bytes(git: Callable[[Sequence[str]], bytes]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in V1_MIGRATIONS:
        frozen = git(("show", f"{V1_COMMIT}:{relative}"))
        current_path = REPOSITORY_ROOT / relative
        if current_path.is_symlink() or not current_path.is_file() or current_path.read_bytes() != frozen:
            raise UpgradeRehearsalError(
                "V1_MIGRATION_CHANGED", "a frozen V1 Flyway migration differs from the V1 tag"
            )
        hashes[relative] = sha256_bytes(frozen)
    return hashes


def validate_v1_tag_adapter_boundary(git: Callable[[Sequence[str]], bytes]) -> tuple[str, ...]:
    """Prove the fixed V1 tag does not contain the V2 runtime adapters.

    This regression exists because the eighth manual rehearsal invoked the
    current fixture adapter as ``python -m scripts...`` while the V1 source was
    also on the import path.  The adapter must instead be a current-candidate
    snapshot executed by absolute file path with its own explicit PYTHONPATH.
    """
    raw = git(("ls-tree", "-r", "--name-only", V1_COMMIT, "scripts"))
    files = tuple(sorted(line for line in raw.decode("utf-8").splitlines() if line))
    if files != V1_TAG_SCRIPT_FILES:
        raise UpgradeRehearsalError(
            "V1_SCRIPT_BOUNDARY", "V1 tag scripts do not match the frozen compatibility boundary"
        )
    if any(relative in files for relative in CURRENT_ADAPTER_FILES):
        raise UpgradeRehearsalError(
            "V1_ADAPTER_CLAIM", "a current runtime adapter was incorrectly attributed to the V1 tag"
        )
    return files


def compose_published_ports(document: Mapping[str, Any]) -> dict[str, tuple[tuple[str, int, int], ...]]:
    services = document.get("services")
    if not isinstance(services, dict):
        raise UpgradeRehearsalError("COMPOSE_CONFIG", "Compose config does not contain services")
    result: dict[str, tuple[tuple[str, int, int], ...]] = {}
    for service, payload in services.items():
        if not isinstance(payload, dict):
            raise UpgradeRehearsalError("COMPOSE_CONFIG", "Compose service config is invalid")
        parsed: list[tuple[str, int, int]] = []
        for item in payload.get("ports") or []:
            if not isinstance(item, dict):
                raise UpgradeRehearsalError("COMPOSE_PORT", "Compose published port is invalid")
            host_ip = str(item.get("host_ip") or item.get("hostIp") or "0.0.0.0")
            try:
                published = int(item["published"])
                target = int(item["target"])
            except (KeyError, TypeError, ValueError) as exception:
                raise UpgradeRehearsalError("COMPOSE_PORT", "Compose port fields are invalid") from exception
            parsed.append((host_ip, published, target))
        if parsed:
            result[str(service)] = tuple(sorted(parsed))
    return result


def assert_expected_published_ports(
        document: Mapping[str, Any], ports: Ports, *, v2: bool = True) -> None:
    actual = compose_published_ports(document)
    expected = (
        {
            "app": (("127.0.0.1", ports.management, 8081),),
            "mcp-public-nginx": (("127.0.0.1", ports.public_https, 8443),),
            "nginx": (("127.0.0.1", ports.private_http, 8080),),
        }
        if v2
        else {
            "mcp-public-nginx": (("127.0.0.1", ports.public_https, 443),),
            "nginx": (("127.0.0.1", ports.private_http, 8080),),
        }
    )
    if actual != expected:
        raise UpgradeRehearsalError(
            "COMPOSE_PORT_SET", "Compose published ports do not equal the isolated exact set"
        )


def pkcs8_command_plan(openssl: str, pem: Path, der: Path, decoded: Path) -> tuple[tuple[str, ...], ...]:
    """Return the portable V1 key generation/decode plan.

    ``openssl pkey -check`` is deliberately absent: LibreSSL treats ``-check``
    as a cipher name.  Decoding with the PKCS#8 subcommand and checking the PEM
    envelope is the portable preflight used by this harness.
    """
    return (
        (openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(pem)),
        (openssl, "pkcs8", "-topk8", "-nocrypt", "-in", str(pem), "-outform", "DER", "-out", str(der)),
        (openssl, "pkcs8", "-inform", "DER", "-nocrypt", "-in", str(der), "-out", str(decoded)),
    )


def validate_decoded_pkcs8(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise UpgradeRehearsalError("PKCS8_MODE", "decoded PKCS#8 key must be a private regular file")
    first = path.read_bytes().splitlines()[:1]
    pkcs8_begin = b"-----BEGIN " + b"PRIVATE KEY-----"
    if first != [pkcs8_begin]:
        raise UpgradeRehearsalError("PKCS8_DECODE", "PKCS#8 decode did not produce a PRIVATE KEY envelope")


def compute_v1_kid(public_x509_der: bytes) -> str:
    if len(public_x509_der) < 256:
        raise UpgradeRehearsalError("PUBLIC_KEY_DER", "V1 public key DER is unexpectedly short")
    return base64.urlsafe_b64encode(hashlib.sha256(public_x509_der).digest()).rstrip(b"=").decode("ascii")


def retiring_key_retain_until_epoch_seconds(now_epoch_seconds: int | None = None) -> int:
    """Keep the V1 verification key beyond every access token issued by V1."""
    if now_epoch_seconds is None:
        now_epoch_seconds = int(datetime.now(timezone.utc).timestamp())
    if isinstance(now_epoch_seconds, bool) or now_epoch_seconds <= 0:
        raise UpgradeRehearsalError(
            "RETIRING_KEY_CLOCK", "retiring-key retention requires a positive NumericDate"
        )
    return (
        now_epoch_seconds
        + V1_ACCESS_TOKEN_TTL_SECONDS
        + RETIRING_KEY_CLOCK_SKEW_SECONDS
    )


def _aggregate_status_values(statuses: Sequence[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if "ENV_REQUIRED" in statuses:
        return "ENV_REQUIRED"
    if statuses and all(status == "PASS" for status in statuses):
        return "PASS"
    return "NOT_COVERED"


def overall_status(
        checks: Mapping[str, Mapping[str, Any]],
        phases: Mapping[str, PhaseObservation] | None = None) -> str:
    if set(checks) != set(REQUIRED_CHECKS):
        raise UpgradeRehearsalError("EVIDENCE_CHECK_SET", "evidence does not contain the exact check set")
    statuses = [validate_status(str(checks[name].get("status"))) for name in REQUIRED_CHECKS]
    if phases is not None:
        if tuple(phases) != PHASE_ORDER:
            raise UpgradeRehearsalError("EVIDENCE_PHASE_SET", "evidence does not contain the exact phase order")
        statuses.extend(validate_status(phases[name].status) for name in PHASE_ORDER)
    return _aggregate_status_values(statuses)


def process_exit_code(status: str) -> int:
    return 0 if status == "PASS" else EXIT_FAIL if status == "FAIL" else EXIT_INCOMPLETE


def aggregate_acceptance(
        checks: Mapping[str, Mapping[str, Any]],
        phases: Mapping[str, PhaseObservation] | None = None) -> dict[str, dict[str, str]]:
    groups = {
        "V2-AC-04": tuple(name for name in REQUIRED_CHECKS if name.startswith(("backup.", "restore.", "migration."))) + ("integrity.finalSource",),
        "V2-AC-05": tuple(name for name in REQUIRED_CHECKS if name.startswith(("oauth.", "credential.", "lifecycle."))) + ("integrity.finalSource",),
        "V2-AC-06": tuple(name for name in REQUIRED_CHECKS if name.startswith(("compatibility.", "authorization."))) + ("integrity.finalSource",),
        "V2-AC-39": ("audit.traceSearch", "integrity.finalSource"),
        "V2-AC-40": REQUIRED_CHECKS,
    }
    result: dict[str, dict[str, str]] = {}
    for acceptance_id, names in groups.items():
        subset = {name: checks[name] for name in names}
        statuses = [str(value["status"]) for value in subset.values()]
        if phases is not None:
            owned = set(names)
            phase_names = (
                PHASE_ORDER
                if acceptance_id == "V2-AC-40"
                else tuple(
                    phase_name
                    for phase_name, required in PHASE_REQUIRED_CHECKS.items()
                    if owned.intersection(required)
                )
            )
            statuses.extend(phases[name].status for name in phase_names)
        status = _aggregate_status_values(statuses)
        result[acceptance_id] = {"status": status}
    return result


class PrivateCommandRunner:
    """Run commands without a shell and keep raw stdout/stderr private."""

    def __init__(self, log_directory: Path) -> None:
        self.log_directory = log_directory
        self.counter = 0
        self.log_digests: dict[str, dict[str, Any]] = {}

    def run(
            self,
            command: Sequence[str],
            *,
            label: str,
            cwd: Path | None = None,
            environment: Mapping[str, str] | None = None,
            replace_environment: bool = False,
            input_bytes: bytes | None = None,
            timeout: float = 600,
            check: bool = True) -> CommandResult:
        if not command or any(not isinstance(item, str) or "\0" in item for item in command):
            raise UpgradeRehearsalError("COMMAND_SHAPE", "command contains an invalid argument")
        self.counter += 1
        safe_label = re.sub(r"[^a-z0-9-]", "-", label.lower()).strip("-") or "command"
        log_path = self.log_directory / f"{self.counter:03d}-{safe_label}.log"
        child_environment = {} if replace_environment else dict(os.environ)
        if environment:
            child_environment.update(environment)
        try:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                env=child_environment,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exception:
            raise UpgradeRehearsalError(
                "COMMAND_MISSING", "a required executable is not installed", environment=True
            ) from exception
        except subprocess.TimeoutExpired as exception:
            raise UpgradeRehearsalError("COMMAND_TIMEOUT", "a bounded rehearsal command timed out") from exception
        payload = b"stdout:\n" + completed.stdout + b"\nstderr:\n" + completed.stderr
        write_private(log_path, payload)
        self.log_digests[f"{self.counter:03d}-{safe_label}"] = {
            "sha256": sha256_bytes(payload),
            "bytes": len(payload),
            "exitCode": completed.returncode,
        }
        if check and completed.returncode != 0:
            diagnostic_label = re.sub(
                r"[^A-Z0-9]+", "_", safe_label.upper()
            ).strip("_")[:64].rstrip("_")
            raise UpgradeRehearsalError(
                f"COMMAND_FAILED_{diagnostic_label or 'COMMAND'}",
                "a private rehearsal command failed",
            )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _git_runner(runner: PrivateCommandRunner) -> Callable[[Sequence[str]], bytes]:
    def git(arguments: Sequence[str]) -> bytes:
        label = "git-" + "-".join(arguments[:2]).replace("^{}`,", "")
        return runner.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                *arguments,
            ],
            label=label,
            cwd=REPOSITORY_ROOT,
            environment=git_environment(),
            replace_environment=True,
            timeout=60,
        ).stdout
    return git


def validate_v2_source_identity(
        git: Callable[[Sequence[str]], bytes],
        runtime: RuntimeContext | None = None) -> dict[str, Any]:
    """Bind a formal run to one clean, committed V2 tree descended from V1."""
    commit = git(("rev-parse", "--verify", "HEAD^{commit}")).decode("ascii").strip()
    tree = git(("rev-parse", "--verify", "HEAD^{tree}")).decode("ascii").strip()
    if not GIT_OBJECT.fullmatch(commit) or not GIT_OBJECT.fullmatch(tree):
        raise UpgradeRehearsalError("V2_GIT_OBJECT", "V2 commit or tree identity is invalid")
    if runtime is not None:
        runtime.v2_commit = commit
        runtime.v2_tree = tree
        runtime.clean_worktree = False
    git(("merge-base", "--is-ancestor", V1_COMMIT, commit))

    tracked = git(("ls-files", "-v", "-z"))
    entries = tuple(entry for entry in tracked.split(b"\0") if entry)
    if not entries or any(not entry.startswith(b"H ") for entry in entries):
        raise UpgradeRehearsalError(
            "V2_GIT_INDEX_FLAGS",
            "tracked files must not use assume-unchanged or skip-worktree flags",
        )
    if git(("status", "--porcelain=v1", "-z", "--untracked-files=all")):
        raise UpgradeRehearsalError(
            "V2_WORKTREE_DIRTY", "formal V2 upgrade evidence requires a clean worktree"
        )
    if runtime is not None:
        runtime.clean_worktree = True
    return {"commit": commit, "tree": tree, "cleanWorktree": True}


def assert_v2_source_identity_unchanged(
        runtime: RuntimeContext,
        git: Callable[[Sequence[str]], bytes]) -> None:
    observed = validate_v2_source_identity(git)
    if (
        observed["commit"] != runtime.v2_commit
        or observed["tree"] != runtime.v2_tree
        or not runtime.clean_worktree
    ):
        raise UpgradeRehearsalError(
            "V2_SOURCE_DRIFT", "V2 source identity changed during the rehearsal"
        )
    assert_runtime_sources_unchanged(runtime)


def _committed_candidate_bytes(
        runtime: RuntimeContext,
        git: Callable[[Sequence[str]], bytes],
        relative: str) -> bytes:
    if runtime.v2_commit is None or not GIT_OBJECT.fullmatch(runtime.v2_commit):
        raise UpgradeRehearsalError("V2_SOURCE_IDENTITY", "V2 commit was not frozen")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise UpgradeRehearsalError("V2_SOURCE_PATH", "candidate source path is unsafe")
    committed = git(("show", f"{runtime.v2_commit}:{relative}"))
    source = REPOSITORY_ROOT / candidate
    if source.is_symlink() or not source.is_file() or source.read_bytes() != committed:
        raise UpgradeRehearsalError(
            "V2_SOURCE_DRIFT", "candidate source does not match the frozen V2 commit"
        )
    return committed


def _private_temp_root(run_id: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix=f"web-starter-upgrade-{run_id}-"))
    root.chmod(0o700)
    sentinel = root / ".web-starter-upgrade-owner.json"
    write_private_json(sentinel, {"owner": OWNER_VALUE, "runId": run_id})
    return root


def _snapshot_current_adapters(
        runtime: RuntimeContext, git: Callable[[Sequence[str]], bytes]) -> Path:
    frozen = runtime.runtime_root / "frozen-tools"
    frozen.mkdir(mode=0o700)
    for relative in CURRENT_ADAPTER_FILES:
        destination = frozen / relative
        committed = _committed_candidate_bytes(runtime, git, relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(destination, committed)
        runtime.helper_hashes[relative] = sha256_file(destination)
    return frozen


def _snapshot_current_runtime_sources(
        runtime: RuntimeContext, git: Callable[[Sequence[str]], bytes]) -> Path:
    """Freeze every current-candidate file that defines the V2 ingress or SDK proof.

    The V2 Compose file is executed from this private snapshot. Maven and the
    candidate image builds use the complete frozen commit archive; the SDK
    sources, build definitions, and effective POMs are additionally checked
    against these hashes around every relevant invocation.
    """
    frozen = runtime.runtime_root / "frozen-current-source"
    frozen.mkdir(mode=0o700)
    hashes: dict[str, str] = {}
    for relative in CURRENT_RUNTIME_SOURCE_FILES:
        destination = frozen / relative
        committed = _committed_candidate_bytes(runtime, git, relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(destination, committed)
        hashes[relative] = sha256_file(destination)
    if tuple(hashes) != CURRENT_RUNTIME_SOURCE_FILES:
        raise UpgradeRehearsalError(
            "RUNTIME_SOURCE_SET", "the current runtime source snapshot is incomplete"
        )
    runtime.runtime_source_hashes = hashes
    return frozen


def _freeze_contract_and_load_validator(
        runtime: RuntimeContext,
        git: Callable[[Sequence[str]], bytes],
        frozen_adapters: Path) -> None:
    contract = runtime.runtime_root / "frozen-contract"
    contract.mkdir(mode=0o700)
    for relative, attribute in (
        ("scripts/rehearse_v1_to_v2_upgrade.py", "frozen_tool_sha256"),
        ("security/v2-v1-upgrade-rehearsal.schema.json", "frozen_schema_sha256"),
    ):
        payload = _committed_candidate_bytes(runtime, git, relative)
        destination = contract / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(destination, payload)
        setattr(runtime, attribute, sha256_file(destination))

    validator_path = frozen_adapters / "scripts" / "validate_v1_upgrade_evidence.py"
    spec = importlib.util.spec_from_file_location(
        "web_starter_frozen_v1_upgrade_validator", validator_path
    )
    if spec is None or spec.loader is None:
        raise UpgradeRehearsalError("EVIDENCE_VALIDATOR_LOAD", "validator module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        validator = getattr(module, "validate_document")
    except Exception as exception:
        raise UpgradeRehearsalError(
            "EVIDENCE_VALIDATOR_LOAD", "validator module cannot be initialized"
        ) from exception
    if not callable(validator):
        raise UpgradeRehearsalError("EVIDENCE_VALIDATOR_API", "validator API is unavailable")
    runtime.evidence_validator = validator


def assert_runtime_sources_unchanged(
        runtime: RuntimeContext, source_root: Path = REPOSITORY_ROOT) -> None:
    """Fail closed if Maven would execute different test/POM bytes than evidence binds."""
    if tuple(runtime.runtime_source_hashes) != CURRENT_RUNTIME_SOURCE_FILES:
        raise UpgradeRehearsalError(
            "RUNTIME_SOURCE_SET", "runtime source evidence does not contain the exact file set"
        )
    root = source_root.resolve()
    for relative, expected in runtime.runtime_source_hashes.items():
        source = root / relative
        if (
            source.is_symlink()
            or not source.is_file()
            or not SHA256.fullmatch(expected)
            or sha256_file(source) != expected
        ):
            raise UpgradeRehearsalError(
                "RUNTIME_SOURCE_DRIFT", "a runtime source changed after it was frozen"
            )


def _extract_v1_source(runtime: RuntimeContext, runner: PrivateCommandRunner) -> Path:
    source = runtime.runtime_root / "v1-source"
    source.mkdir(mode=0o700)
    archive = runtime.runtime_root / "v1-source.tar"
    result = runner.run(
        ["git", "archive", "--format=tar", V1_COMMIT],
        label="archive-v1-source",
        cwd=REPOSITORY_ROOT,
        environment=git_environment(),
        replace_environment=True,
    )
    write_private(archive, result.stdout)
    with tarfile.open(archive, mode="r:") as document:
        for member in document.getmembers():
            destination = (source / member.name).resolve()
            if (
                not _inside(destination, source.resolve())
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise UpgradeRehearsalError("V1_ARCHIVE_PATH", "V1 archive contains an unsafe path")
        # Python 3.9 on the supported macOS development host predates the
        # ``filter=`` API.  The exhaustive regular-file/directory and resolved
        # path checks above provide the equivalent fail-closed boundary.
        document.extractall(source)
    archive.unlink()
    if (source / ".git").exists() or not (source / "pom.xml").is_file():
        raise UpgradeRehearsalError("V1_ARCHIVE_CONTENT", "frozen V1 source tree is invalid")
    return source


def _extract_v2_sdk_source(runtime: RuntimeContext, runner: PrivateCommandRunner) -> Path:
    """Extract the frozen V2 commit for Maven SDK tests.

    A clean Git worktree does not constrain ignored ``target`` directories.  SDK
    tests therefore execute only from this private archive, which cannot contain
    pre-existing build output and is bound byte-for-byte to the frozen commit.
    """
    if runtime.v2_commit is None or not GIT_OBJECT.fullmatch(runtime.v2_commit):
        raise UpgradeRehearsalError("V2_SOURCE_IDENTITY", "V2 commit was not frozen")
    source = runtime.runtime_root / "v2-sdk-source"
    source.mkdir(mode=0o700)
    archive = runtime.runtime_root / "v2-sdk-source.tar"
    result = runner.run(
        ["git", "archive", "--format=tar", runtime.v2_commit],
        label="archive-v2-sdk-source",
        cwd=REPOSITORY_ROOT,
        environment=git_environment(),
        replace_environment=True,
    )
    write_private(archive, result.stdout)
    with tarfile.open(archive, mode="r:") as document:
        members = document.getmembers()
        for member in members:
            destination = (source / member.name).resolve()
            if (
                not _inside(destination, source.resolve())
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise UpgradeRehearsalError(
                    "V2_SDK_ARCHIVE_PATH", "V2 SDK archive contains an unsafe path"
                )
        document.extractall(source)
    archive.unlink()
    if (
        (source / ".git").exists()
        or not (source / "pom.xml").is_file()
        or not (source / "web-starter-mcp" / "pom.xml").is_file()
        or not (source / "mvnw").is_file()
        or any(path.name == "target" for path in source.rglob("target"))
    ):
        raise UpgradeRehearsalError(
            "V2_SDK_ARCHIVE_CONTENT", "frozen V2 SDK source tree is invalid"
        )
    hashes: dict[str, str] = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise UpgradeRehearsalError(
                "V2_SDK_ARCHIVE_CONTENT", "frozen V2 SDK source contains a symbolic link"
            )
        if path.is_file():
            relative = path.relative_to(source).as_posix()
            hashes[relative] = sha256_file(path)
    if not hashes or any(
        hashes.get(relative) != expected
        for relative, expected in runtime.runtime_source_hashes.items()
    ):
        raise UpgradeRehearsalError(
            "V2_SDK_ARCHIVE_BINDING", "V2 SDK source does not match the frozen runtime sources"
        )
    runtime.sdk_source_root = source
    runtime.sdk_source_hashes = hashes
    return source


def assert_sdk_source_unchanged(runtime: RuntimeContext) -> Path:
    source = runtime.sdk_source_root
    if (
        source is None
        or source.is_symlink()
        or not source.is_dir()
        or not runtime.sdk_source_hashes
    ):
        raise UpgradeRehearsalError("SDK_SOURCE_MISSING", "frozen SDK source is unavailable")
    observed: dict[str, str] = {}
    for path in sorted(source.rglob("*")):
        relative_path = path.relative_to(source)
        if "target" in relative_path.parts or "node_modules" in relative_path.parts:
            continue
        if path.is_symlink():
            raise UpgradeRehearsalError(
                "SDK_SOURCE_DRIFT", "frozen SDK source changed during the rehearsal"
            )
        if path.is_file():
            observed[relative_path.as_posix()] = sha256_file(path)
    if observed != runtime.sdk_source_hashes or any(
        not SHA256.fullmatch(expected) for expected in observed.values()
    ):
        raise UpgradeRehearsalError(
            "SDK_SOURCE_DRIFT", "frozen SDK source changed during the rehearsal"
        )
    return source


def _required_commands() -> tuple[str, ...]:
    return (
        "docker", "git", "openssl", "keytool", "node", "corepack",
        str(Path(sys.executable).resolve()),
    )


def _check_required_commands() -> None:
    missing = [value for value in _required_commands() if shutil.which(value) is None]
    if missing:
        raise UpgradeRehearsalError(
            "REQUIRED_COMMAND_MISSING", "one or more required commands are unavailable", environment=True
        )


def _inspect_image_metadata(
        reference: str,
        runner: PrivateCommandRunner,
        label: str) -> tuple[str, dict[str, str]]:
    validate_image_reference(reference, label)
    result = runner.run(
        ["docker", "image", "inspect", reference], label=f"inspect-{label}-image", timeout=60
    )
    try:
        documents = json.loads(result.stdout)
        image_id = documents[0]["Id"]
        raw_labels = documents[0].get("Config", {}).get("Labels") or {}
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exception:
        raise UpgradeRehearsalError("IMAGE_INSPECT", "Docker returned malformed image metadata") from exception
    if (
        len(documents) != 1
        or not isinstance(image_id, str)
        or not IMAGE_ID.fullmatch(image_id)
        or not isinstance(raw_labels, dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in raw_labels.items())
    ):
        raise UpgradeRehearsalError("IMAGE_ID", "image did not resolve to one immutable ID")
    return image_id, dict(raw_labels)


def _inspect_image(reference: str, runner: PrivateCommandRunner, label: str) -> str:
    return _inspect_image_metadata(reference, runner, label)[0]


def _validate_candidate_image_revision(
        role: str, labels: Mapping[str, str], expected_commit: str | None) -> None:
    if role not in {"v2-app", "v2-nginx"}:
        return
    if expected_commit is None or labels.get("org.opencontainers.image.revision") != expected_commit:
        raise UpgradeRehearsalError(
            "IMAGE_REVISION", "V2 image revision label does not match the frozen commit"
        )


def _tag_image_alias(
        image_id: str, alias: str, runtime: RuntimeContext, runner: PrivateCommandRunner, role: str) -> None:
    probe, _ = _probe_image_alias(alias, runner, f"probe-{role}-alias")
    if probe == "PRESENT":
        raise UpgradeRehearsalError("IMAGE_ALIAS_COLLISION", "generated image alias already exists")
    if probe != "ABSENT":
        raise UpgradeRehearsalError("IMAGE_ALIAS_PROBE", "generated image alias absence was not proven")
    runtime.intended_image_tags[role] = alias
    runtime.resolved_images[role] = image_id
    runtime.resource_mutation_started = True
    runner.run(["docker", "image", "tag", image_id, alias], label=f"tag-{role}-alias")
    runtime.created_image_tags[role] = alias


def _build_v1_images(
        runtime: RuntimeContext, runner: PrivateCommandRunner, v1_source: Path) -> None:
    for role, dockerfile in (("v1-app", "Dockerfile"), ("v1-nginx", "deploy/nginx/Dockerfile")):
        tag = f"web-starter-upgrade-{runtime.names.run_id}-{role}:candidate"
        probe, _ = _probe_image_alias(tag, runner, f"probe-{role}-tag")
        if probe == "PRESENT":
            raise UpgradeRehearsalError("IMAGE_TAG_COLLISION", "generated V1 image tag already exists")
        if probe != "ABSENT":
            raise UpgradeRehearsalError("IMAGE_TAG_PROBE", "generated V1 image tag absence was not proven")
        runtime.intended_image_tags[role] = tag
        runtime.resource_mutation_started = True
        runner.run(
            [
                "docker", "build", "--pull=false",
                "--label", f"{LABEL_OWNER}={OWNER_VALUE}",
                "--label", f"{LABEL_RUN}={runtime.names.run_id}",
                "--label", f"{LABEL_ROLE}={role}",
                "--file", str(v1_source / dockerfile),
                "--tag", tag,
                str(v1_source),
            ],
            label=f"build-{role}",
            timeout=1800,
        )
        image_id = _inspect_image(tag, runner, role)
        runtime.created_image_tags[role] = tag
        runtime.created_image_ids[role] = image_id
        runtime.resolved_images[role] = image_id


def _build_v2_images(runtime: RuntimeContext, runner: PrivateCommandRunner) -> None:
    """Build the candidate images from the exact frozen V2 commit archive."""
    source = assert_sdk_source_unchanged(runtime)
    if runtime.v2_commit is None or not GIT_OBJECT.fullmatch(runtime.v2_commit):
        raise UpgradeRehearsalError("V2_SOURCE_IDENTITY", "V2 commit was not frozen")
    for role, dockerfile in (("v2-app", "Dockerfile"), ("v2-nginx", "deploy/nginx/Dockerfile")):
        tag = f"web-starter-upgrade-{runtime.names.run_id}-{role}:candidate"
        probe, _ = _probe_image_alias(tag, runner, f"probe-{role}-tag")
        if probe == "PRESENT":
            raise UpgradeRehearsalError("IMAGE_TAG_COLLISION", "generated V2 image tag already exists")
        if probe != "ABSENT":
            raise UpgradeRehearsalError("IMAGE_TAG_PROBE", "generated V2 image tag absence was not proven")
        runtime.intended_image_tags[role] = tag
        runtime.resource_mutation_started = True
        runner.run(
            [
                "docker", "build", "--pull=false",
                "--label", f"{LABEL_OWNER}={OWNER_VALUE}",
                "--label", f"{LABEL_RUN}={runtime.names.run_id}",
                "--label", f"{LABEL_ROLE}={role}",
                "--label", f"org.opencontainers.image.revision={runtime.v2_commit}",
                "--file", str(source / dockerfile),
                "--tag", tag,
                str(source),
            ],
            label=f"build-{role}-from-frozen-commit",
            environment={**sanitized_host_environment(), "DOCKER_BUILDKIT": "1"},
            replace_environment=True,
            timeout=2400,
        )
        image_id, labels = _inspect_image_metadata(tag, runner, role)
        if (
            labels.get(LABEL_OWNER) != OWNER_VALUE
            or labels.get(LABEL_RUN) != runtime.names.run_id
            or labels.get(LABEL_ROLE) != role
        ):
            raise UpgradeRehearsalError(
                "IMAGE_BUILD_LABELS", "built V2 image ownership labels are invalid"
            )
        _validate_candidate_image_revision(role, labels, runtime.v2_commit)
        runtime.created_image_tags[role] = tag
        runtime.created_image_ids[role] = image_id
        runtime.resolved_images[role] = image_id
    assert_sdk_source_unchanged(runtime)


def _generate_rsa_material(
        runtime: RuntimeContext, runner: PrivateCommandRunner) -> dict[str, Any]:
    key_root = runtime.runtime_root / "keys"
    key_root.mkdir(mode=0o700)
    openssl = str(Path(shutil.which("openssl") or "openssl").resolve())
    result: dict[str, Any] = {}
    for role in ("v1", "v2"):
        pem = key_root / f"{role}-private.pem"
        pkcs8 = key_root / f"{role}-private-pkcs8.der"
        decoded = key_root / f"{role}-decoded.pem"
        for index, command in enumerate(pkcs8_command_plan(openssl, pem, pkcs8, decoded), start=1):
            runner.run(command, label=f"{role}-pkcs8-step-{index}", timeout=120)
        for path in (pem, pkcs8, decoded):
            path.chmod(0o600)
        validate_decoded_pkcs8(decoded)
        public_der = key_root / f"{role}-public-x509.der"
        runner.run(
            [openssl, "pkey", "-in", str(decoded), "-pubout", "-outform", "DER", "-out", str(public_der)],
            label=f"{role}-public-der",
        )
        public_der.chmod(0o600)
        pkcs1 = key_root / f"{role}-private-pkcs1.der"
        first = runner.run(
            [openssl, "rsa", "-in", str(decoded), "-traditional", "-outform", "DER", "-out", str(pkcs1)],
            label=f"{role}-pkcs1-traditional",
            check=False,
        )
        if first.returncode != 0:
            runner.run(
                [openssl, "rsa", "-in", str(decoded), "-outform", "DER", "-out", str(pkcs1)],
                label=f"{role}-pkcs1-libressl",
            )
        pkcs1.chmod(0o600)
        result[role] = {
            "pem": pem,
            "pkcs8": pkcs8,
            "decoded": decoded,
            "public": public_der,
            "pkcs1": pkcs1,
            "privatePkcs8Sha256": sha256_file(pkcs8),
            "publicX509Sha256": sha256_file(public_der),
        }
    v1_public = Path(result["v1"]["public"]).read_bytes()
    result["v1Kid"] = compute_v1_kid(v1_public)
    result["v2Kid"] = f"upgrade-active-{runtime.names.run_id}"
    return result


def _generate_tls_material(
        runtime: RuntimeContext, runner: PrivateCommandRunner) -> dict[str, Path]:
    tls = runtime.runtime_root / "tls"
    tls.mkdir(mode=0o700)
    private = tls / "tls.key"
    certificate = tls / "tls.crt"
    runner.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", "1",
            "-subj", f"/CN={runtime.names.public_hostname}",
            "-addext", f"subjectAltName=DNS:{runtime.names.public_hostname}",
            "-keyout", str(private), "-out", str(certificate),
        ],
        label="generate-tls-certificate",
        timeout=120,
    )
    private.chmod(0o600)
    certificate.chmod(0o600)
    hosts = tls / "hosts"
    write_private(
        hosts,
        f"127.0.0.1 {runtime.names.public_hostname} {runtime.names.private_hostname}\n".encode("ascii"),
    )
    truststore = tls / "truststore.p12"
    runner.run(
        [
            "keytool", "-importcert", "-noprompt", "-alias", "web-starter-upgrade",
            "-file", str(certificate), "-keystore", str(truststore),
            "-storetype", "PKCS12", "-storepass", "changeit",
        ],
        label="generate-java-truststore",
    )
    truststore.chmod(0o600)
    return {"key": private, "certificate": certificate, "hosts": hosts, "truststore": truststore}


def _random_secret() -> str:
    return secrets.token_urlsafe(48)


def _write_environment_file(path: Path, values: Mapping[str, str]) -> None:
    lines: list[str] = []
    for name, value in values.items():
        if not re.fullmatch(r"WEB_STARTER_[A-Z0-9_]+", name):
            raise UpgradeRehearsalError("ENV_NAME", "generated environment name is invalid")
        if any(character in value for character in "\r\n\0"):
            raise UpgradeRehearsalError("ENV_VALUE", "generated environment value is multiline")
        lines.append(f"{name}={value}\n")
    write_private(path, "".join(lines).encode("utf-8"))


def _compose_labels(runtime: RuntimeContext, role: str) -> dict[str, str]:
    return {LABEL_OWNER: OWNER_VALUE, LABEL_RUN: runtime.names.run_id, LABEL_ROLE: role}


def _write_compose_overlays(
        runtime: RuntimeContext,
        v1_source: Path,
        current_source: Path,
        keys: Mapping[str, Any],
        tls: Mapping[str, Path]) -> tuple[Path, Path]:
    jdbc_v1 = (
        f"jdbc:mysql://mysql:3306/{runtime.names.source_database}?useUnicode=true&characterEncoding=utf8&"
        "preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true&"
        "allowPublicKeyRetrieval=true&useSSL=false"
    )
    jdbc_v2 = jdbc_v1.replace(runtime.names.source_database, runtime.names.target_database)
    shared_data_services: dict[str, Any] = {
        "mysql": {
            "image": runtime.created_image_tags["mysql"],
            "environment": {"MYSQL_DATABASE": runtime.names.source_database},
            "labels": _compose_labels(runtime, "mysql"),
        },
        "redis": {"image": runtime.created_image_tags["redis"], "labels": _compose_labels(runtime, "redis")},
    }
    ownership = {
        "volumes": {
            "mysql-data": {"labels": _compose_labels(runtime, "mysql-data")},
            "redis-data": {"labels": _compose_labels(runtime, "redis-data")},
        },
        "networks": {
            "app": {"labels": _compose_labels(runtime, "app-network")},
            "data": {"internal": True, "labels": _compose_labels(runtime, "data-network")},
        },
    }
    v1_redacted_nginx = runtime.runtime_root / "v1-public-nginx-redacted.conf"
    write_private(
        v1_redacted_nginx,
        b"""worker_processes auto;
pid /var/run/nginx.pid;
error_log /dev/stderr notice;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '$remote_addr - $remote_user [$time_local] '
                    '\"$request_method $uri $server_protocol\" '
                    '$status $body_bytes_sent '
                    '\"$http_user_agent\" \"$http_x_forwarded_for\"';
    access_log /dev/stdout main;
    sendfile on;
    keepalive_timeout 65;
    include /etc/nginx/conf.d/*.conf;
}
""",
    )
    v1_services = json.loads(json.dumps(shared_data_services))
    v1_services["app"] = {
        "image": runtime.created_image_tags["v1-app"],
        "environment": {"WEB_STARTER_DB_URL": jdbc_v1},
        "labels": _compose_labels(runtime, "app"),
    }
    v1_services["nginx"] = {
        "image": runtime.created_image_tags["v1-nginx"],
        "labels": _compose_labels(runtime, "nginx"),
    }
    v1_services["mcp-public-nginx"] = {
        "image": runtime.created_image_tags["v1-nginx"],
        "labels": _compose_labels(runtime, "mcp-public-nginx"),
        "volumes": [{
            "type": "bind",
            "source": str(v1_redacted_nginx),
            "target": "/etc/nginx/nginx.conf",
            "read_only": True,
        }],
    }
    v1_overlay = runtime.runtime_root / "compose-v1-upgrade.json"
    write_private_json(v1_overlay, {"services": v1_services, **ownership})

    v2_services = json.loads(json.dumps(shared_data_services))
    v2_services["app"] = {
        "image": runtime.created_image_tags["v2-app"],
        "environment": {
            "WEB_STARTER_DB_URL": jdbc_v2,
            "WEB_STARTER_RUNTIME_MODE": "production",
            "WEB_STARTER_CREDENTIAL_PEPPER": runtime.environment["WEB_STARTER_CREDENTIAL_PEPPER"],
            "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION": runtime.environment[
                "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION"
            ],
            "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING": runtime.environment[
                "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING"
            ],
            "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION": runtime.environment[
                "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION"
            ],
            "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": "",
            "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": "",
            "WEB_STARTER_OAUTH_RSA_JWK_SET": runtime.environment["WEB_STARTER_OAUTH_RSA_JWK_SET"],
            "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": runtime.environment[
                "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID"
            ],
            "WEB_STARTER_MANAGEMENT_PORT": "8081",
            "WEB_STARTER_MANAGEMENT_BIND_ADDRESS": "0.0.0.0",
            "WEB_STARTER_MANAGEMENT_USERNAME": runtime.environment[
                "WEB_STARTER_MANAGEMENT_USERNAME"
            ],
            "WEB_STARTER_MANAGEMENT_PASSWORD": runtime.environment[
                "WEB_STARTER_MANAGEMENT_PASSWORD"
            ],
            "WEB_STARTER_LOG_FORMAT": "ecs",
        },
        "ports": [{
            "target": 8081, "published": runtime.ports.management,
            "host_ip": "127.0.0.1", "protocol": "tcp",
        }],
        "labels": _compose_labels(runtime, "app"),
        "healthcheck": {
            "test": ["CMD", "curl", "-fsS", "http://127.0.0.1:8081/actuator/health/readiness"],
            "interval": "10s", "timeout": "5s", "retries": 30, "start_period": "30s",
        },
    }
    v2_services["nginx"] = {
        "image": runtime.created_image_tags["v2-nginx"],
        "labels": _compose_labels(runtime, "nginx"),
    }
    v2_services["mcp-public-nginx"] = {
        "image": runtime.created_image_tags["v2-nginx"],
        "labels": _compose_labels(runtime, "mcp-public-nginx"),
    }
    v2_overlay = runtime.runtime_root / "compose-v2-upgrade.json"
    write_private_json(v2_overlay, {"services": v2_services, **ownership})

    v1_base = v1_source / "compose.yaml"
    v1_public = v1_source / "compose.public-mcp.yaml"
    v2_production = current_source / "compose.production.yaml"
    if any(
        path.is_symlink() or not path.is_file()
        for path in (v1_base, v1_public, v2_production)
    ):
        raise UpgradeRehearsalError(
            "COMPOSE_SOURCE", "a frozen version-specific Compose source is invalid"
        )
    runtime.compose_files_v1 = (v1_base, v1_public, v1_overlay)
    runtime.compose_files_v2 = (v2_production, v2_overlay)
    return v1_overlay, v2_overlay


def _compose_command(runtime: RuntimeContext, files: Sequence[Path], *arguments: str) -> list[str]:
    command = ["docker", "compose", "--env-file", str(runtime.runtime_root / "runtime.env")]
    for path in files:
        command.extend(("--file", str(path.resolve())))
    command.extend(("--project-name", runtime.names.compose_project, *arguments))
    return command


def _assert_project_unused(runtime: RuntimeContext, runner: PrivateCommandRunner) -> None:
    project_filter = f"label=com.docker.compose.project={runtime.names.compose_project}"
    run_filter = f"label={LABEL_RUN}={runtime.names.run_id}"
    scans = (
        ("project-container", ["docker", "container", "ls", "--all", "--quiet", "--filter", project_filter]),
        ("project-volume", ["docker", "volume", "ls", "--quiet", "--filter", project_filter]),
        ("project-network", ["docker", "network", "ls", "--quiet", "--filter", project_filter]),
        ("run-container", ["docker", "container", "ls", "--all", "--quiet", "--filter", run_filter]),
        ("run-volume", ["docker", "volume", "ls", "--quiet", "--filter", run_filter]),
        ("run-network", ["docker", "network", "ls", "--quiet", "--filter", run_filter]),
        ("run-image", ["docker", "image", "ls", "--quiet", "--filter", run_filter]),
    )
    for noun, command in scans:
        result = runner.run(command, label=f"preflight-unused-{noun}", timeout=30)
        if result.stdout.strip():
            raise UpgradeRehearsalError(
                "PROJECT_COLLISION", "generated project or run identity already owns Docker resources"
            )
    runtime.resource_cleanup_authorized = True


def _validate_frozen_helpers(frozen: Path, runner: PrivateCommandRunner) -> None:
    environment = frozen_python_environment(frozen)
    for relative in (
        "scripts/prepare_release_runtime_acceptance.py",
        "scripts/recovery_backup.py",
        "scripts/recovery_restore.py",
        "scripts/verify_oauth_runtime.py",
        "scripts/acceptance_jwk_set.py",
    ):
        runner.run(
            frozen_python_command(frozen, relative, "--help"),
            label="frozen-help-" + Path(relative).stem,
            environment=environment,
            replace_environment=True,
            timeout=30,
        )


def _create_jwk_set(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        frozen: Path,
        keys: Mapping[str, Any]) -> Path:
    target = runtime.runtime_root / "oauth-jwk-set.json"
    retiring_retain_until = retiring_key_retain_until_epoch_seconds()
    runner.run(
        frozen_python_command(
            frozen,
            "scripts/acceptance_jwk_set.py",
            "--active-private-der", str(keys["v2"]["pkcs1"]),
            "--retiring-private-der", str(keys["v1"]["pkcs1"]),
            "--active-kid", str(keys["v2Kid"]),
            "--retiring-kid", str(keys["v1Kid"]),
            "--retiring-retain-until-epoch-seconds", str(retiring_retain_until),
            "--output", str(target),
        ),
        label="build-oauth-jwk-set",
        environment=frozen_python_environment(frozen),
        replace_environment=True,
    )
    document = json.loads(target.read_text(encoding="utf-8"))
    entries = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(entries, list) or len(entries) != 2:
        raise UpgradeRehearsalError("JWK_SET", "generated OAuth JWK set does not contain exactly two keys")
    by_kid = {entry.get("kid"): entry for entry in entries if isinstance(entry, dict)}
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    if set(by_kid) != {keys["v1Kid"], keys["v2Kid"]}:
        raise UpgradeRehearsalError("JWK_KID", "generated OAuth JWK set has unexpected kid values")
    if private_fields.intersection(by_kid[keys["v1Kid"]]):
        raise UpgradeRehearsalError("JWK_OLD_PRIVATE", "retiring V1 JWK contains private material")
    if by_kid[keys["v1Kid"]].get("exp") != retiring_retain_until:
        raise UpgradeRehearsalError(
            "JWK_OLD_EXP", "retiring V1 JWK does not carry the bounded retention time"
        )
    if not private_fields.intersection(by_kid[keys["v2Kid"]]):
        raise UpgradeRehearsalError("JWK_ACTIVE_PUBLIC", "active V2 JWK lacks private signing material")
    return target


def _runtime_environment(
        runtime: RuntimeContext,
        keys: Mapping[str, Any],
        jwk_set: Path,
        tls: Mapping[str, Path]) -> dict[str, str]:
    if runtime.v2_commit is None or not GIT_OBJECT.fullmatch(runtime.v2_commit):
        raise UpgradeRehearsalError(
            "V2_COMMIT", "the frozen V2 commit is unavailable for runtime identity"
        )
    public_url = f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}"
    token_pepper = _random_secret()
    values = {
        "WEB_STARTER_DB_USERNAME": "web_starter",
        "WEB_STARTER_DB_PASSWORD": _random_secret(),
        "WEB_STARTER_DB_ROOT_PASSWORD": _random_secret(),
        "WEB_STARTER_REDIS_PASSWORD": _random_secret(),
        "WEB_STARTER_GIT_COMMIT": runtime.v2_commit,
        "WEB_STARTER_TOKEN_PEPPER": token_pepper,
        "WEB_STARTER_CREDENTIAL_PEPPER": _random_secret(),
        "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION": "upgrade-v2",
        "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING": token_pepper,
        "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION": "v1",
        "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "upgrade_admin",
        "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": _random_secret() + "!9a",
        "WEB_STARTER_BOOTSTRAP_ADMIN_DISPLAY_NAME": "升级演练管理员",
        "WEB_STARTER_MANAGEMENT_USERNAME": "upgrade_ops",
        "WEB_STARTER_MANAGEMENT_PASSWORD": _random_secret(),
        "WEB_STARTER_OAUTH_ISSUER": public_url,
        "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": public_url + "/mcp",
        "WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL": f"{V1_ACCESS_TOKEN_TTL_SECONDS}s",
        "WEB_STARTER_OAUTH_REFRESH_TOKEN_TTL": "8h",
        "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "false",
        "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": base64.b64encode(Path(keys["v1"]["pkcs8"]).read_bytes()).decode("ascii"),
        "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": base64.b64encode(Path(keys["v1"]["public"]).read_bytes()).decode("ascii"),
        "WEB_STARTER_OAUTH_RSA_JWK_SET": jwk_set.read_text(encoding="utf-8").strip(),
        "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": str(keys["v2Kid"]),
        "WEB_STARTER_INTERNAL_TOKENS_ENABLED": "true",
        "WEB_STARTER_COOKIE_SECURE": "true",
        "WEB_STARTER_MCP_ALLOWED_HOSTS": (
            f"{runtime.names.public_hostname}:{runtime.ports.public_https},"
            f"{runtime.names.private_hostname}:{runtime.ports.private_http}"
        ),
        "WEB_STARTER_MCP_ALLOWED_ORIGINS": public_url,
        "WEB_STARTER_HTTP_BIND_ADDRESS": "127.0.0.1",
        "WEB_STARTER_HTTP_PORT": str(runtime.ports.private_http),
        "WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS": "127.0.0.1",
        "WEB_STARTER_PUBLIC_MCP_PORT": str(runtime.ports.public_https),
        "WEB_STARTER_PUBLIC_TLS_CERT_FILE": str(tls["certificate"]),
        "WEB_STARTER_PUBLIC_TLS_KEY_FILE": str(tls["key"]),
        "WEB_STARTER_LOG_LEVEL": "INFO",
    }
    return values


def _production_image_environment(runtime: RuntimeContext) -> dict[str, str]:
    """Return required base interpolation values after every image is frozen."""
    try:
        values = {
            "WEB_STARTER_MYSQL_IMAGE": runtime.created_image_tags["mysql"],
            "WEB_STARTER_REDIS_IMAGE": runtime.created_image_tags["redis"],
            "WEB_STARTER_APP_IMAGE": runtime.created_image_tags["v2-app"],
            "WEB_STARTER_APP_DIGEST": runtime.resolved_images["v2-app"],
            "WEB_STARTER_NGINX_IMAGE": runtime.created_image_tags["v2-nginx"],
            "WEB_STARTER_NGINX_DIGEST": runtime.resolved_images["v2-nginx"],
        }
    except KeyError as exception:
        raise UpgradeRehearsalError(
            "PRODUCTION_IMAGE_ENV", "production image aliases are incomplete"
        ) from exception
    for label in (
        "WEB_STARTER_MYSQL_IMAGE",
        "WEB_STARTER_REDIS_IMAGE",
        "WEB_STARTER_APP_IMAGE",
        "WEB_STARTER_NGINX_IMAGE",
    ):
        validate_image_reference(values[label], label)
    for label in ("WEB_STARTER_APP_DIGEST", "WEB_STARTER_NGINX_DIGEST"):
        if not IMAGE_ID.fullmatch(values[label]):
            raise UpgradeRehearsalError(
                "PRODUCTION_IMAGE_DIGEST",
                f"{label} is not an immutable SHA256 image ID",
            )
    return values


def _compose_env(runtime: RuntimeContext, *, v2: bool) -> dict[str, str]:
    # Compose interpolation must never inherit ambient WEB_STARTER_* behavior
    # switches.  Keep only host/Docker plumbing and the run's explicit values;
    # every other setting therefore comes from the frozen Compose defaults.
    values = sanitized_host_environment()
    values.update(runtime.environment)
    # V1 understands only the single-key variables; V2 must consume only the
    # key ring so the retired private key is no longer distributed.
    if v2:
        values["WEB_STARTER_OAUTH_RSA_PRIVATE_KEY"] = ""
        values["WEB_STARTER_OAUTH_RSA_PUBLIC_KEY"] = ""
        # V1 tokens deliberately live long enough to survive the complete
        # backup/restore rehearsal. Preserve those already-issued JWTs through
        # the retiring key, but require every token newly issued by V2 to use
        # the production short-lived baseline.
        values["WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL"] = (
            f"{V2_ACCESS_TOKEN_TTL_SECONDS}s"
        )
    else:
        values["WEB_STARTER_OAUTH_RSA_JWK_SET"] = ""
        values["WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID"] = ""
    return values


def _parse_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exception:
        raise UpgradeRehearsalError("JSON_OUTPUT", f"{label} did not return JSON") from exception
    if not isinstance(value, dict):
        raise UpgradeRehearsalError("JSON_OUTPUT", f"{label} did not return a JSON object")
    return value


def _compose_service_map(document: Mapping[str, Any]) -> Mapping[str, Any]:
    services = document.get("services")
    expected = {"mysql", "redis", "app", "nginx", "mcp-public-nginx"}
    if not isinstance(services, dict) or set(services) != expected:
        raise UpgradeRehearsalError(
            "COMPOSE_SERVICE_SET", "Compose config does not contain the exact service set"
        )
    if any(not isinstance(services[name], dict) for name in expected):
        raise UpgradeRehearsalError("COMPOSE_SERVICE", "Compose service config is invalid")
    return services


def _compose_command_value(service: Mapping[str, Any]) -> tuple[str, ...] | None:
    command = service.get("command")
    if command is None:
        return None
    if not isinstance(command, list) or not all(isinstance(value, str) for value in command):
        raise UpgradeRehearsalError("COMPOSE_COMMAND", "Compose command has an invalid shape")
    return tuple(command)


def _compose_mount_values(
        service: Mapping[str, Any]) -> tuple[tuple[str, str, str, bool, bool | None], ...]:
    result: list[tuple[str, str, str, bool, bool | None]] = []
    volumes = service.get("volumes") or []
    if not isinstance(volumes, list):
        raise UpgradeRehearsalError("COMPOSE_MOUNT", "Compose mounts have an invalid shape")
    for mount in volumes:
        if not isinstance(mount, dict):
            raise UpgradeRehearsalError("COMPOSE_MOUNT", "Compose mount is invalid")
        mount_type = mount.get("type")
        source = mount.get("source")
        target = mount.get("target")
        if not all(isinstance(value, str) and value for value in (mount_type, source, target)):
            raise UpgradeRehearsalError("COMPOSE_MOUNT", "Compose mount fields are invalid")
        bind = mount.get("bind")
        if bind is not None and not isinstance(bind, dict):
            raise UpgradeRehearsalError("COMPOSE_MOUNT", "Compose bind options are invalid")
        create_host_path = bind.get("create_host_path") if isinstance(bind, dict) else None
        if create_host_path is not None and not isinstance(create_host_path, bool):
            raise UpgradeRehearsalError("COMPOSE_MOUNT", "Compose bind creation option is invalid")
        # Compose 2.40 normalizes an explicit ``create_host_path: false`` to an
        # empty ``bind`` object, while newer Compose releases retain the false
        # value. The frozen production source is checked separately below, so
        # both canonical outputs can be compared without weakening the policy.
        # An unsafe true value remains distinguishable and rejected.
        if create_host_path is False:
            create_host_path = None
        result.append((
            mount_type,
            source,
            target,
            bool(mount.get("read_only", False)),
            create_host_path,
        ))
    return tuple(sorted(result))


def assert_v2_tls_bind_source_policy(path: Path) -> None:
    """Require the exact two non-creating TLS bind mounts in frozen V2 YAML."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exception:
        raise UpgradeRehearsalError(
            "COMPOSE_MOUNT_SOURCE_POLICY", "V2 Compose source cannot be read safely"
        ) from exception
    service_markers = [
        index for index, line in enumerate(lines) if line == "  mcp-public-nginx:"
    ]
    if len(service_markers) != 1:
        raise UpgradeRehearsalError(
            "COMPOSE_MOUNT_SOURCE_POLICY", "V2 public ingress service is not unique"
        )
    service_start = service_markers[0]
    service_end = next(
        (
            index
            for index in range(service_start + 1, len(lines))
            if lines[index] and not lines[index].startswith("    ")
        ),
        len(lines),
    )
    volume_markers = [
        index
        for index in range(service_start + 1, service_end)
        if lines[index] == "    volumes:"
    ]
    if len(volume_markers) != 1:
        raise UpgradeRehearsalError(
            "COMPOSE_MOUNT_SOURCE_POLICY", "V2 public TLS volume block is not unique"
        )
    volume_start = volume_markers[0]
    volume_end = next(
        (
            index
            for index in range(volume_start + 1, service_end)
            if lines[index] and not lines[index].startswith("      ")
        ),
        service_end,
    )
    observed = tuple(
        line.strip()
        for line in lines[volume_start + 1:volume_end]
        if line.strip() and not line.lstrip().startswith("#")
    )
    expected = (
        "- type: bind",
        "source: ${WEB_STARTER_PUBLIC_TLS_CERT_FILE:?set WEB_STARTER_PUBLIC_TLS_CERT_FILE}",
        "target: /etc/nginx/tls/fullchain.pem",
        "read_only: true",
        "bind:",
        "create_host_path: false",
        "- type: bind",
        "source: ${WEB_STARTER_PUBLIC_TLS_KEY_FILE:?set WEB_STARTER_PUBLIC_TLS_KEY_FILE}",
        "target: /etc/nginx/tls/privkey.pem",
        "read_only: true",
        "bind:",
        "create_host_path: false",
    )
    if observed != expected:
        raise UpgradeRehearsalError(
            "COMPOSE_MOUNT_SOURCE_POLICY",
            "V2 public TLS binds must explicitly disable host-path creation",
        )


def assert_version_specific_ingress_sources(v1_source: Path, current_source: Path) -> None:
    """Bind the Compose topology to each version's checked-in Nginx layout."""
    v1_public = (v1_source / "deploy/nginx/external-mcp.conf").read_text(encoding="utf-8")
    v2_public = (current_source / "deploy/nginx/external-mcp.conf").read_text(encoding="utf-8")
    v2_root = (current_source / "deploy/nginx/nginx-public.conf").read_text(encoding="utf-8")
    v2_private_root = (current_source / "deploy/nginx/nginx.conf").read_text(encoding="utf-8")
    v2_dockerfile = (current_source / "deploy/nginx/Dockerfile").read_text(encoding="utf-8")
    if "listen 443 ssl;" not in v1_public or "listen 8443 ssl;" in v1_public:
        raise UpgradeRehearsalError(
            "V1_INGRESS_SOURCE", "frozen V1 public Nginx is not the expected 443 topology"
        )
    if "listen 8443 ssl;" not in v2_public or "listen 443 ssl;" in v2_public:
        raise UpgradeRehearsalError(
            "V2_INGRESS_SOURCE", "current V2 public Nginx is not the expected 8443 topology"
        )
    if "include /etc/nginx/public.d/*.conf;" not in v2_root:
        raise UpgradeRehearsalError(
            "V2_INGRESS_ROOT", "current V2 public Nginx root does not load public.d"
        )
    if any(
        '"$request"' in source
        or "$http_referer" in source
        or '"$request_method $uri $server_protocol"' not in source
        for source in (v2_root, v2_private_root)
    ):
        raise UpgradeRehearsalError(
            "V2_INGRESS_LOGGING",
            "V2 Nginx access logs must omit raw query strings and Referer headers",
        )
    required_copies = (
        "COPY deploy/nginx/nginx-public.conf /etc/nginx/nginx-public.conf",
        "COPY deploy/nginx/external-mcp.conf /etc/nginx/public.d/default.conf",
    )
    if any(value not in v2_dockerfile for value in required_copies):
        raise UpgradeRehearsalError(
            "V2_INGRESS_IMAGE", "current V2 Nginx image does not package the public topology"
        )


def assert_exact_compose_configuration(
        document: Mapping[str, Any],
        runtime: RuntimeContext,
        v1_source: Path,
        *,
        v2: bool) -> None:
    """Validate the exact isolated port, image, command, and mount topology."""
    services = _compose_service_map(document)
    assert_expected_published_ports(document, runtime.ports, v2=v2)

    for service in services.values():
        ports = service.get("ports") or []
        if not isinstance(ports, list) or any(
            not isinstance(item, dict)
            or item.get("protocol") != "tcp"
            or item.get("mode") != "ingress"
            for item in ports
        ):
            raise UpgradeRehearsalError(
                "COMPOSE_PORT_MODE", "Compose published ports are not exact TCP ingress ports"
            )

    expected_images = {
        "mysql": runtime.created_image_tags["mysql"],
        "redis": runtime.created_image_tags["redis"],
        "app": runtime.created_image_tags["v2-app" if v2 else "v1-app"],
        "nginx": runtime.created_image_tags["v2-nginx" if v2 else "v1-nginx"],
        "mcp-public-nginx": runtime.created_image_tags["v2-nginx" if v2 else "v1-nginx"],
    }
    if any(services[name].get("image") != image for name, image in expected_images.items()):
        raise UpgradeRehearsalError(
            "COMPOSE_IMAGE", "Compose config does not use the frozen image aliases"
        )

    expected_commands = {
        "app": None,
        "nginx": None,
        "mcp-public-nginx": (
            ("nginx", "-c", "/etc/nginx/nginx-public.conf", "-g", "daemon off;")
            if v2 else None
        ),
    }
    if any(
        _compose_command_value(services[name]) != command
        for name, command in expected_commands.items()
    ):
        raise UpgradeRehearsalError(
            "COMPOSE_COMMAND", "Compose ingress command does not match the version topology"
        )

    volumes = document.get("volumes")
    if not isinstance(volumes, dict) or set(volumes) != {"mysql-data", "redis-data"}:
        raise UpgradeRehearsalError(
            "COMPOSE_VOLUME_SET", "Compose config does not contain the exact data volume set"
        )
    try:
        mysql_volume = volumes["mysql-data"]["name"]
        redis_volume = volumes["redis-data"]["name"]
    except (KeyError, TypeError) as exception:
        raise UpgradeRehearsalError(
            "COMPOSE_VOLUME_NAME", "Compose data volume names are invalid"
        ) from exception
    if not all(isinstance(value, str) and value for value in (mysql_volume, redis_volume)):
        raise UpgradeRehearsalError("COMPOSE_VOLUME_NAME", "Compose data volume name is invalid")
    if (
        mysql_volume != f"{runtime.names.compose_project}_mysql-data"
        or redis_volume != f"{runtime.names.compose_project}_redis-data"
    ):
        raise UpgradeRehearsalError(
            "COMPOSE_VOLUME_NAME", "Compose data volumes are not isolated to the rehearsal project"
        )

    # Compose preserves an already absolute bind source instead of resolving
    # host aliases such as macOS /var -> /private/var.  Match that exact value.
    certificate = str(Path(runtime.environment["WEB_STARTER_PUBLIC_TLS_CERT_FILE"]).absolute())
    private_key = str(Path(runtime.environment["WEB_STARTER_PUBLIC_TLS_KEY_FILE"]).absolute())
    public_mounts = [
        ("bind", certificate, "/etc/nginx/tls/fullchain.pem", True, None),
        ("bind", private_key, "/etc/nginx/tls/privkey.pem", True, None),
    ]
    if not v2:
        public_mounts.append((
            "bind",
            str((v1_source / "deploy/nginx/external-mcp.conf").resolve()),
            "/etc/nginx/conf.d/default.conf",
            True,
            None,
        ))
        public_mounts.append((
            "bind",
            str((runtime.runtime_root / "v1-public-nginx-redacted.conf").absolute()),
            "/etc/nginx/nginx.conf",
            True,
            None,
        ))
    expected_mounts = {
        "mysql": (("volume", "mysql-data", "/var/lib/mysql", False, None),),
        "redis": (("volume", "redis-data", "/data", False, None),),
        "app": (),
        "nginx": (),
        "mcp-public-nginx": tuple(sorted(public_mounts)),
    }
    if any(
        _compose_mount_values(services[name]) != mounts
        for name, mounts in expected_mounts.items()
    ):
        raise UpgradeRehearsalError(
            "COMPOSE_MOUNT_SET", "Compose mounts do not match the version-specific exact set"
        )


def _run_compose_preflight(runtime: RuntimeContext, runner: PrivateCommandRunner, *, v2: bool) -> None:
    files = runtime.compose_files_v2 if v2 else runtime.compose_files_v1
    if v2:
        assert_v2_tls_bind_source_policy(files[0])
    environment = _compose_env(runtime, v2=v2)
    result = runner.run(
        _compose_command(runtime, files, "config", "--format", "json"),
        label="compose-config-v2" if v2 else "compose-config-v1",
        environment=environment,
        replace_environment=True,
        timeout=60,
    )
    config = _parse_json_bytes(result.stdout, "Compose config")
    v1_source = runtime.compose_files_v1[0].parent
    assert_exact_compose_configuration(config, runtime, v1_source, v2=v2)


def _verify_started_container_images(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        *,
        v2: bool) -> None:
    """Prove every started service uses the exact image ID bound in evidence."""
    files = runtime.compose_files_v2 if v2 else runtime.compose_files_v1
    environment = _compose_env(runtime, v2=v2)
    version = "v2" if v2 else "v1"
    application_role = "v2-app" if v2 else "v1-app"
    nginx_role = "v2-nginx" if v2 else "v1-nginx"
    expected_roles = {
        "mysql": "mysql",
        "redis": "redis",
        "app": application_role,
        "nginx": nginx_role,
        "mcp-public-nginx": nginx_role,
    }
    observed: dict[str, str] = {}
    for service in SERVICE_IMAGE_ROLES:
        result = runner.run(
            _compose_command(runtime, files, "ps", "--all", "--quiet", service),
            label=f"inspect-{version}-{service}-container-id",
            environment=environment,
            replace_environment=True,
            timeout=30,
        )
        identifiers = tuple(
            line.strip() for line in result.stdout.decode("ascii", errors="strict").splitlines()
            if line.strip()
        )
        if len(identifiers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", identifiers[0]):
            raise UpgradeRehearsalError(
                "CONTAINER_CARDINALITY", "Compose did not resolve exactly one container per service"
            )
        inspected = runner.run(
            ["docker", "container", "inspect", identifiers[0]],
            label=f"inspect-{version}-{service}-container",
            timeout=30,
        )
        try:
            documents = json.loads(inspected.stdout)
            payload = documents[0]
            image_id = payload["Image"]
            labels = payload["Config"]["Labels"] or {}
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exception:
            raise UpgradeRehearsalError(
                "CONTAINER_INSPECT", "Docker returned malformed container metadata"
            ) from exception
        expected_image = runtime.resolved_images.get(expected_roles[service])
        if (
            len(documents) != 1
            or image_id != expected_image
            or not IMAGE_ID.fullmatch(str(image_id))
            or labels.get(LABEL_OWNER) != OWNER_VALUE
            or labels.get(LABEL_RUN) != runtime.names.run_id
            or labels.get(LABEL_ROLE) != service
            or labels.get("com.docker.compose.project") != runtime.names.compose_project
            or labels.get("com.docker.compose.service") != service
        ):
            raise UpgradeRehearsalError(
                "CONTAINER_IMAGE_BINDING",
                "started container does not match the frozen service image and ownership",
            )
        observed[service] = str(image_id)
    runtime.started_container_images[version] = observed


def _wait_for_http_status(
        url: str,
        expected: int,
        *,
        attempts: int = 90,
        insecure: bool = False,
        aliases: Mapping[str, str] | None = None) -> None:
    previous_hosts = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS")
    previous_address = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS")
    if aliases:
        os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = ",".join(aliases)
        os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = next(iter(aliases.values()))
    try:
        context = ssl._create_unverified_context() if insecure else None  # noqa: SLF001
        with isolated_loopback_resolution():
            for _ in range(attempts):
                try:
                    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
                    request = Request(url, headers={"Accept": "application/json"})
                    with opener.open(request, timeout=5) as response:
                        if response.status == expected:
                            return
                except HTTPError as error:
                    error.read()
                    if error.code == expected:
                        return
                except OSError:
                    pass
                import time
                time.sleep(1)
    finally:
        if previous_hosts is None:
            os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS", None)
        else:
            os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = previous_hosts
        if previous_address is None:
            os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS", None)
        else:
            os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = previous_address
    raise UpgradeRehearsalError("HTTP_READINESS", "runtime did not reach the expected HTTP status")


@contextmanager
def _public_loopback_resolution(runtime: RuntimeContext) -> Iterable[None]:
    previous_hosts = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS")
    previous_address = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS")
    os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = runtime.names.public_hostname
    os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = "127.0.0.1"
    try:
        with isolated_loopback_resolution():
            yield
    finally:
        if previous_hosts is None:
            os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS", None)
        else:
            os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = previous_hosts
        if previous_address is None:
            os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS", None)
        else:
            os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = previous_address


def _new_oauth_token_opener() -> Any:
    """Create a proxy-disabled TLS opener with no browser cookie processor."""
    _reject_tls_key_log()
    return build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=ssl._create_unverified_context()),  # noqa: SLF001
    )


def _private_browser_base_url(runtime: RuntimeContext) -> str:
    # Chromium accepts Secure cookies on the localhost development exception,
    # while a numeric HTTP loopback URL does not provide the same cookie
    # behavior.  Real production management access still requires trusted
    # HTTPS as documented; this helper is only for the isolated local drill.
    return f"http://localhost:{runtime.ports.private_http}"


def _prepare_fixture_environment(runtime: RuntimeContext, keys: Mapping[str, Any]) -> dict[str, str]:
    public_url = f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}"
    private_url = _private_browser_base_url(runtime)
    values = _compose_env(runtime, v2=False)
    values.update({
        "WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL": private_url,
        "WEB_STARTER_ACCEPTANCE_PRIVATE_MCP_BASE_URL": private_url,
        "WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL": public_url,
        "WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME": runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME"],
        "WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD": runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD"],
        "WEB_STARTER_ACCEPTANCE_INSECURE_TLS": "true",
        "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": (
            runtime.names.public_hostname + "," + runtime.names.private_hostname
        ),
        "WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS": "127.0.0.1",
        "WEB_STARTER_ACCEPTANCE_OAUTH_ACTIVE_KID": str(keys["v1Kid"]),
        "WEB_STARTER_ACCEPTANCE_OAUTH_RETIRING_KID": str(keys["v2Kid"]),
        "WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX": (
            f"upgrade-old-pat-crud-{runtime.names.run_id}"
        ),
    })
    return values


class _AdminApi:
    """Small private fixture client; it never persists cookies or request bodies."""

    def __init__(self, runtime: RuntimeContext) -> None:
        self.runtime = runtime
        self.public = f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}"
        self.private = f"http://127.0.0.1:{runtime.ports.private_http}"
        self.cookies = CookieJar()
        _reject_tls_key_log()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPCookieProcessor(self.cookies),
            HTTPSHandler(context=ssl._create_unverified_context()),  # noqa: SLF001
        )
        install_no_redirect_handler(self.opener)
        self.csrf_name = "X-XSRF-TOKEN"
        self.csrf_value = ""
        self.cookie_header = ""

    def request(self, method: str, url: str, payload: Any | None = None, *, private: bool = False) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if private and self.cookie_header:
            headers["Cookie"] = self.cookie_header
        if method in {"POST", "PUT", "DELETE"} and self.csrf_value:
            headers[self.csrf_name] = self.csrf_value
        request = Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read()
        except HTTPError as error:
            error.read()
            raise UpgradeRehearsalError("ADMIN_API_HTTP", "fixture management API returned a non-success status") from error
        except OSError as error:
            raise UpgradeRehearsalError(
                "ADMIN_API_TRANSPORT", "fixture management API transport failed"
            ) from error
        try:
            document = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exception:
            raise UpgradeRehearsalError("ADMIN_API_JSON", "fixture management API returned invalid JSON") from exception
        if not isinstance(document, dict) or document.get("code") not in (0, 200):
            raise UpgradeRehearsalError("ADMIN_API_ENVELOPE", "fixture management API returned a failed envelope")
        return document.get("data")

    def login(self) -> None:
        previous_hosts = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS")
        previous_address = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS")
        os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = self.runtime.names.public_hostname
        os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = "127.0.0.1"
        try:
            with isolated_loopback_resolution():
                csrf = self.request("GET", self.public + "/api/auth/csrf")
                if not isinstance(csrf, dict) or not isinstance(csrf.get("token"), str):
                    raise UpgradeRehearsalError("ADMIN_CSRF", "fixture CSRF response is invalid")
                self.csrf_name = str(csrf.get("headerName") or "X-XSRF-TOKEN")
                self.csrf_value = csrf["token"]
                self.request("POST", self.public + "/api/auth/login", {
                    "username": self.runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME"],
                    "password": self.runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD"],
                })
        finally:
            if previous_hosts is None:
                os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS", None)
            else:
                os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = previous_hosts
            if previous_address is None:
                os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS", None)
            else:
                os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = previous_address
        self.cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in self.cookies)
        if "WEB_STARTER_SESSION=" not in self.cookie_header:
            raise UpgradeRehearsalError("ADMIN_SESSION", "fixture login did not establish a session")


def _extend_v1_service_fixture(
        runtime: RuntimeContext,
        credential_root: Path,
        api: _AdminApi | None = None) -> dict[str, str]:
    api = _AdminApi(runtime) if api is None else api
    if not api.cookie_header:
        api.login()
    suffix = runtime.names.run_id
    account = api.request("POST", api.private + "/api/security/service-accounts", {
        "code": f"upgrade_agent_{suffix}",
        "displayName": "Upgrade rehearsal agent",
        "description": "Disposable V1 direct-token compatibility subject",
        "roleIds": [1],
    }, private=True)
    if not isinstance(account, dict) or not str(account.get("id", "")).isdigit():
        raise UpgradeRehearsalError("SERVICE_FIXTURE", "service account fixture response is invalid")
    token = api.request("POST", api.private + f"/api/security/service-accounts/{account['id']}/tokens", {
        "name": f"upgrade-service-{suffix}",
        "scopes": ["system:info", "project:list", "audit:list"],
        "allowedIpCidrs": [],
        "expiresAt": None,
    }, private=True)
    if not isinstance(token, dict) or not isinstance(token.get("token"), str) or not str(token.get("id", "")).isdigit():
        raise UpgradeRehearsalError("SERVICE_TOKEN_FIXTURE", "service token fixture response is invalid")
    token_file = credential_root / "service-token.json"
    write_private_json(token_file, {"token": token["token"]})
    lifecycle_pat_name = f"upgrade-revocation-{suffix}"
    lifecycle_pat = api.request("POST", api.private + "/api/security/personal-tokens", {
        "name": lifecycle_pat_name,
        "scopes": ["system:info", "project:list"],
        "allowedIpCidrs": [],
        "expiresAt": None,
    }, private=True)
    if (
        not isinstance(lifecycle_pat, dict)
        or not isinstance(lifecycle_pat.get("token"), str)
        or not str(lifecycle_pat.get("id", "")).isdigit()
    ):
        raise UpgradeRehearsalError("LIFECYCLE_PAT_FIXTURE", "lifecycle PAT fixture response is invalid")
    lifecycle_pat_file = credential_root / "lifecycle-pat.json"
    write_private_json(lifecycle_pat_file, {"token": lifecycle_pat["token"]})
    manifest_path = credential_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("tokenFiles"), dict):
        raise UpgradeRehearsalError("FIXTURE_MANIFEST", "V1 fixture manifest is invalid")
    manifest["upgradeCredentialFixtures"] = {
        "serviceAccountId": str(account["id"]),
        "serviceTokenId": str(token["id"]),
        "lifecyclePatId": str(lifecycle_pat["id"]),
        "lifecyclePatName": lifecycle_pat_name,
    }
    manifest["tokenFiles"]["serviceToken"] = str(token_file)
    manifest["tokenFiles"]["lifecyclePat"] = str(lifecycle_pat_file)
    replacement = credential_root / "manifest.next.json"
    write_private_json(replacement, manifest)
    replacement.replace(manifest_path)
    manifest_path.chmod(0o600)
    return {
        "serviceAccountId": str(account["id"]),
        "serviceTokenId": str(token["id"]),
        "serviceTokenFile": str(token_file),
        "lifecyclePatId": str(lifecycle_pat["id"]),
        "lifecyclePatName": lifecycle_pat_name,
        "lifecyclePatFile": str(lifecycle_pat_file),
    }


def _pkce_parameters(
        runtime: RuntimeContext, manifest: Mapping[str, Any]) -> dict[str, Any]:
    issuer = f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}"
    client_id = manifest.get("publicClientId")
    redirect_uri = manifest.get("redirectUri")
    if (
        manifest.get("publicBaseUrl") != issuer
        or not isinstance(client_id, str)
        or not isinstance(redirect_uri, str)
        or redirect_uri != issuer + "/login"
    ):
        raise UpgradeRehearsalError("PKCE_MANIFEST", "PKCE fixture manifest is invalid")
    return {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/oauth2/authorize",
        "token_endpoint": issuer + "/oauth2/token",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scopes": ("system:info", "project:list", "audit:list"),
        "audience": issuer + "/mcp",
    }


def _write_pkce_token_set(
        path: Path,
        parameters: Mapping[str, Any],
        tokens: OAuthTokenSet) -> None:
    write_private_json(path, {
        "client_id": parameters["client_id"],
        "redirect_uri": parameters["redirect_uri"],
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
    })


def _capture_v1_pkce_tokens(
        runtime: RuntimeContext,
        api: _AdminApi,
        manifest: Mapping[str, Any],
        credential_root: Path,
        expected_kid: str) -> tuple[OAuthTokenSet, Path, dict[str, Any]]:
    parameters = _pkce_parameters(runtime, manifest)
    try:
        with _public_loopback_resolution(runtime):
            tokens = authorization_code_pkce_once(
                api.opener,
                token_opener=_new_oauth_token_opener(),
                authorization_endpoint=parameters["authorization_endpoint"],
                token_endpoint=parameters["token_endpoint"],
                client_id=parameters["client_id"],
                redirect_uri=parameters["redirect_uri"],
                scopes=parameters["scopes"],
                expected_kid=expected_kid,
                expected_issuer=parameters["issuer"],
                expected_audience=parameters["audience"],
                minimum_ttl_seconds=1800,
            )
    except PkceRefreshError as exception:
        raise UpgradeRehearsalError(
            "PKCE_" + exception.code, "V1 PKCE authorization-code capture failed"
        ) from exception
    token_file = credential_root / "v1-pkce-refresh.json"
    _write_pkce_token_set(token_file, parameters, tokens)
    return tokens, token_file, parameters


def _rotate_and_replay_v2_refresh(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        opener: Any,
        parameters: Mapping[str, Any],
        old_tokens: OAuthTokenSet,
        old_token_file: Path,
        authorization_id: str,
        expected_kid: str,
        tls: Mapping[str, Path],
        manifest: Mapping[str, Any]) -> Path:
    # A0 must still work through the V2 public ingress before its one-time R0
    # refresh is consumed.
    _run_sdk_test(
        runtime,
        runner,
        tls,
        manifest,
        old_token_file,
        "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
        public=True,
        trace_prefix=f"upgrade-old-pkce-v2-{runtime.names.run_id}",
    )
    try:
        with _public_loopback_resolution(runtime):
            rotated = refresh_token_once(
                opener,
                token_endpoint=parameters["token_endpoint"],
                client_id=parameters["client_id"],
                refresh_token=old_tokens.refresh_token,
                expected_kid=expected_kid,
                expected_issuer=parameters["issuer"],
                expected_audience=parameters["audience"],
                expected_scopes=parameters["scopes"],
                minimum_ttl_seconds=V2_MINIMUM_REMAINING_TTL_SECONDS,
            )
    except PkceRefreshError as exception:
        raise UpgradeRehearsalError(
            "REFRESH_" + exception.code, "V2 refresh-token rotation failed"
        ) from exception
    if rotated.expires_in != V2_ACCESS_TOKEN_TTL_SECONDS:
        raise UpgradeRehearsalError(
            "REFRESH_TOKEN_TTL",
            "V2 refresh-token rotation did not issue the exact short-lived access-token TTL",
        )
    rotated_file = old_token_file.parent / "v2-pkce-rotated.json"
    _write_pkce_token_set(rotated_file, parameters, rotated)
    _validate_refresh_storage_after_rotation(
        runtime,
        runner,
        authorization_id,
        old_tokens.refresh_token,
        rotated.refresh_token,
    )
    if _raw_mcp_initialize_status(runtime, old_token_file, public=True) != 401:
        raise UpgradeRehearsalError(
            "REFRESH_OLD_ACCESS", "old access token remained usable after refresh rotation"
        )
    _run_sdk_test(
        runtime,
        runner,
        tls,
        manifest,
        rotated_file,
        "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
        public=True,
        trace_prefix=f"upgrade-rotated-pkce-v2-{runtime.names.run_id}",
    )
    try:
        with _public_loopback_resolution(runtime):
            expect_refresh_invalid_grant_once(
                opener,
                token_endpoint=parameters["token_endpoint"],
                client_id=parameters["client_id"],
                refresh_token=old_tokens.refresh_token,
                expected_issuer=parameters["issuer"],
            )
            expect_refresh_invalid_grant_once(
                opener,
                token_endpoint=parameters["token_endpoint"],
                client_id=parameters["client_id"],
                refresh_token=rotated.refresh_token,
                expected_issuer=parameters["issuer"],
            )
    except PkceRefreshError as exception:
        raise UpgradeRehearsalError(
            "REFRESH_REPLAY_" + exception.code,
            "refresh-token replay revocation validation failed",
        ) from exception
    if (
        _raw_mcp_initialize_status(runtime, old_token_file, public=True) != 401
        or _raw_mcp_initialize_status(runtime, rotated_file, public=True) != 401
    ):
        raise UpgradeRehearsalError(
            "REFRESH_ACCESS_REVOCATION", "refresh-token reuse did not revoke access tokens"
        )
    _validate_refresh_storage_after_reuse(runtime, runner, authorization_id)
    return rotated_file


def _mysql_query(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        sql: str,
        *,
        database: str,
        label: str) -> bytes:
    if not DATABASE.fullmatch(database):
        raise UpgradeRehearsalError("DATABASE_IDENTIFIER", "database identifier is unsafe")
    command = _compose_command(
        runtime,
        runtime.compose_files_v1,
        "exec", "-T", "mysql", "sh", "-ec",
        'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$1" --batch --raw --binary-as-hex --skip-column-names',
        "web-starter-upgrade-mysql", database,
    )
    return runner.run(
        command,
        label=label,
        environment=_compose_env(runtime, v2=False),
        replace_environment=True,
        input_bytes=sql.encode("utf-8"),
        timeout=120,
    ).stdout


def _mcp_crud_fault_constraint_count(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        *,
        label: str) -> int:
    payload = _mysql_query(
        runtime,
        runner,
        (
            "SELECT COUNT(*) FROM information_schema.table_constraints "
            "WHERE constraint_schema=DATABASE() "
            "AND table_name='sys_operation_log' "
            f"AND constraint_name='{MCP_CRUD_FAULT_CONSTRAINT}' "
            "AND constraint_type='CHECK' AND enforced='YES';\n"
        ),
        database=runtime.names.target_database,
        label=label,
    )
    value = _single_tsv_row(
        payload, columns=1, code="MCP_CRUD_FAULT_COUNT"
    )[0]
    if value not in {"0", "1"}:
        raise UpgradeRehearsalError(
            "MCP_CRUD_FAULT_COUNT",
            "the isolated CRUD fault constraint count is invalid",
        )
    return int(value)


@contextmanager
def _mcp_crud_transaction_fault(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        trace_prefix: str) -> Iterable[None]:
    """Install the isolated DB fault required to prove business/audit atomicity."""
    failure_trace = trace_prefix + MCP_CRUD_FAILURE_SUFFIX
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,64}", failure_trace):
        raise UpgradeRehearsalError(
            "MCP_CRUD_FAULT_TRACE",
            "the CRUD transaction-failure trace is invalid",
        )
    if _mcp_crud_fault_constraint_count(
        runtime, runner, label="mcp-crud-fault-count-before"
    ) != 0:
        raise UpgradeRehearsalError(
            "MCP_CRUD_FAULT_PREEXISTS",
            "the isolated CRUD fault constraint already exists",
        )

    installed = False
    try:
        _mysql_query(
            runtime,
            runner,
            (
                "ALTER TABLE sys_operation_log "
                f"ADD CONSTRAINT {MCP_CRUD_FAULT_CONSTRAINT} "
                "CHECK (NOT ("
                f"trace_id='{failure_trace}' "
                "AND module='project' "
                "AND action='CREATE' "
                "AND result='SUCCESS'"
                ")) ENFORCED;\n"
            ),
            database=runtime.names.target_database,
            label="mcp-crud-fault-install",
        )
        installed = True
        if _mcp_crud_fault_constraint_count(
            runtime, runner, label="mcp-crud-fault-count-during"
        ) != 1:
            raise UpgradeRehearsalError(
                "MCP_CRUD_FAULT_INSTALL",
                "the isolated CRUD fault constraint was not installed exactly once",
            )
        yield
    finally:
        if installed:
            _mysql_query(
                runtime,
                runner,
                (
                    "ALTER TABLE sys_operation_log "
                    f"DROP CHECK {MCP_CRUD_FAULT_CONSTRAINT};\n"
                ),
                database=runtime.names.target_database,
                label="mcp-crud-fault-remove",
            )
            if _mcp_crud_fault_constraint_count(
                runtime, runner, label="mcp-crud-fault-count-after"
            ) != 0:
                raise UpgradeRehearsalError(
                    "MCP_CRUD_FAULT_CLEANUP",
                    "the isolated CRUD fault constraint remains after the test",
                )


def _single_tsv_row(payload: bytes, *, columns: int, code: str) -> tuple[str, ...]:
    try:
        rows = tuple(
            tuple(line.split("\t"))
            for line in payload.decode("ascii", errors="strict").splitlines()
            if line
        )
    except UnicodeDecodeError as exception:
        raise UpgradeRehearsalError(code, "database proof returned invalid encoding") from exception
    if len(rows) != 1 or len(rows[0]) != columns:
        raise UpgradeRehearsalError(code, "database proof returned an unexpected row shape")
    return rows[0]


def _token_hmac(runtime: RuntimeContext, token: str) -> str:
    pepper = runtime.environment.get("WEB_STARTER_TOKEN_PEPPER")
    if not isinstance(pepper, str) or len(pepper) < 32 or not isinstance(token, str) or not token:
        raise UpgradeRehearsalError("REFRESH_HASH_INPUT", "refresh-token hash inputs are invalid")
    return hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _authorization_literal(authorization_id: str) -> str:
    if not OAUTH_AUTHORIZATION_ID.fullmatch(authorization_id):
        raise UpgradeRehearsalError(
            "OAUTH_AUTHORIZATION_ID", "OAuth authorization identifier is invalid"
        )
    return "'" + authorization_id + "'"


def _validate_refresh_storage_before_upgrade(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        refresh_token: str) -> str:
    expected_hash = _token_hmac(runtime, refresh_token)
    row = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT id, CAST(refresh_token_value AS CHAR CHARACTER SET ascii), "
            "TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(6), refresh_token_expires_at) "
            "FROM oauth2_authorization WHERE authorization_grant_type='authorization_code' "
            "ORDER BY id;\n",
            database=runtime.names.source_database,
            label="v1-refresh-authorization-storage",
        ),
        columns=3,
        code="V1_REFRESH_AUTHORIZATION",
    )
    authorization_id, stored_value, remaining = row
    if (
        not OAUTH_AUTHORIZATION_ID.fullmatch(authorization_id)
        or stored_value != "hmac$" + expected_hash
        or not remaining.isdigit()
        or int(remaining) < 1800
    ):
        raise UpgradeRehearsalError(
            "V1_REFRESH_AUTHORIZATION", "V1 refresh authorization storage proof failed"
        )
    literal = _authorization_literal(authorization_id)
    family = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT authorization_id, current_token_hash, generation, "
            "IF(revoked_at IS NULL,1,0), "
            "TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(6), current_expires_at) "
            f"FROM sec_oauth_refresh_family WHERE authorization_id={literal};\n",
            database=runtime.names.source_database,
            label="v1-refresh-family-storage",
        ),
        columns=5,
        code="V1_REFRESH_FAMILY",
    )
    if (
        family[0] != authorization_id
        or family[1] != expected_hash
        or family[2] != "0"
        or family[3] != "1"
        or not family[4].isdigit()
        or int(family[4]) < 1800
    ):
        raise UpgradeRehearsalError("V1_REFRESH_FAMILY", "V1 refresh family proof failed")
    history = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT token_hash, generation, IF(consumed_at IS NULL,0,1), "
            "IF(revoked_at IS NULL,1,0), "
            "TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(6), expires_at) "
            f"FROM sec_oauth_refresh_history WHERE authorization_id={literal};\n",
            database=runtime.names.source_database,
            label="v1-refresh-history-storage",
        ),
        columns=5,
        code="V1_REFRESH_HISTORY",
    )
    if (
        history[0] != expected_hash
        or history[1:4] != ("0", "0", "1")
        or not history[4].isdigit()
        or int(history[4]) < 1800
    ):
        raise UpgradeRehearsalError("V1_REFRESH_HISTORY", "V1 refresh history proof failed")
    return authorization_id


def _validate_refresh_storage_after_rotation(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        authorization_id: str,
        old_refresh_token: str,
        new_refresh_token: str) -> None:
    literal = _authorization_literal(authorization_id)
    old_hash = _token_hmac(runtime, old_refresh_token)
    new_hash = _token_hmac(runtime, new_refresh_token)
    authorization = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT CAST(refresh_token_value AS CHAR CHARACTER SET ascii), "
            "TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(6), refresh_token_expires_at) "
            f"FROM oauth2_authorization WHERE id={literal};\n",
            database=runtime.names.target_database,
            label="v2-refresh-authorization-rotated",
        ),
        columns=2,
        code="V2_REFRESH_AUTHORIZATION",
    )
    if (
        authorization[0] != "hmac$" + new_hash
        or not authorization[1].isdigit()
        or int(authorization[1]) < 1800
    ):
        raise UpgradeRehearsalError(
            "V2_REFRESH_AUTHORIZATION", "rotated refresh authorization proof failed"
        )
    family = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT current_token_hash, generation, IF(revoked_at IS NULL,1,0) "
            f"FROM sec_oauth_refresh_family WHERE authorization_id={literal};\n",
            database=runtime.names.target_database,
            label="v2-refresh-family-rotated",
        ),
        columns=3,
        code="V2_REFRESH_FAMILY",
    )
    if family != (new_hash, "1", "1"):
        raise UpgradeRehearsalError("V2_REFRESH_FAMILY", "rotated refresh family proof failed")
    history_payload = _mysql_query(
        runtime,
        runner,
        "SELECT generation, token_hash, IF(consumed_at IS NULL,0,1), "
        "IF(revoked_at IS NULL,1,0) FROM sec_oauth_refresh_history "
        f"WHERE authorization_id={literal} ORDER BY generation;\n",
        database=runtime.names.target_database,
        label="v2-refresh-history-rotated",
    )
    rows = tuple(
        tuple(line.split("\t"))
        for line in history_payload.decode("ascii", errors="strict").splitlines() if line
    )
    if rows != (("0", old_hash, "1", "1"), ("1", new_hash, "0", "1")):
        raise UpgradeRehearsalError("V2_REFRESH_HISTORY", "rotated refresh history proof failed")
    registry = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT COUNT(*), COALESCE(SUM(revoked_at IS NULL),0) "
            f"FROM sec_oauth_token_registry WHERE authorization_id={literal};\n",
            database=runtime.names.target_database,
            label="v2-refresh-access-registry-rotated",
        ),
        columns=2,
        code="V2_REFRESH_ACCESS_REGISTRY",
    )
    if registry != ("2", "1"):
        raise UpgradeRehearsalError(
            "V2_REFRESH_ACCESS_REGISTRY", "latest-only access registry proof failed"
        )


def _validate_refresh_storage_after_reuse(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        authorization_id: str) -> None:
    literal = _authorization_literal(authorization_id)
    authorization = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            f"SELECT COUNT(*) FROM oauth2_authorization WHERE id={literal};\n",
            database=runtime.names.target_database,
            label="v2-refresh-authorization-removed",
        ),
        columns=1,
        code="V2_REFRESH_AUTHORIZATION_REMOVAL",
    )
    family = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT generation, IF(revoked_at IS NULL,0,1), COALESCE(revoke_reason,'') "
            f"FROM sec_oauth_refresh_family WHERE authorization_id={literal};\n",
            database=runtime.names.target_database,
            label="v2-refresh-family-revoked",
        ),
        columns=3,
        code="V2_REFRESH_FAMILY_REVOCATION",
    )
    history = _mysql_query(
        runtime,
        runner,
        "SELECT generation, IF(revoked_at IS NULL,0,1), COALESCE(revoke_reason,'') "
        "FROM sec_oauth_refresh_history "
        f"WHERE authorization_id={literal} ORDER BY generation;\n",
        database=runtime.names.target_database,
        label="v2-refresh-history-revoked",
    )
    history_rows = tuple(
        tuple(line.split("\t"))
        for line in history.decode("ascii", errors="strict").splitlines() if line
    )
    registry = _single_tsv_row(
        _mysql_query(
            runtime,
            runner,
            "SELECT COUNT(*), COALESCE(SUM(revoked_at IS NULL),0) "
            f"FROM sec_oauth_token_registry WHERE authorization_id={literal};\n",
            database=runtime.names.target_database,
            label="v2-refresh-access-registry-revoked",
        ),
        columns=2,
        code="V2_REFRESH_ACCESS_REGISTRY_REVOCATION",
    )
    if (
        authorization != ("0",)
        or family != ("1", "1", "REFRESH_TOKEN_REUSE")
        or history_rows != (
            ("0", "1", "REFRESH_TOKEN_REUSE"),
            ("1", "1", "REFRESH_TOKEN_REUSE"),
        )
        or registry != ("2", "0")
    ):
        raise UpgradeRehearsalError(
            "V2_REFRESH_REUSE_REVOCATION", "refresh-token reuse revocation proof failed"
        )


def _table_inventory(runtime: RuntimeContext, runner: PrivateCommandRunner, database: str) -> tuple[str, ...]:
    output = _mysql_query(
        runtime, runner,
        "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() "
        "AND table_type='BASE TABLE' AND table_name<>'flyway_schema_history' ORDER BY table_name;\n",
        database=database,
        label=f"tables-{database}",
    ).decode("utf-8").splitlines()
    if not output or any(not SAFE_IDENTIFIER.fullmatch(item) for item in output) or len(output) != len(set(output)):
        raise UpgradeRehearsalError("TABLE_INVENTORY", "database table inventory is invalid")
    return tuple(output)


def _row_counts(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        database: str,
        tables: Sequence[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for table in tables:
        if not SAFE_IDENTIFIER.fullmatch(table):
            raise UpgradeRehearsalError("TABLE_IDENTIFIER", "table identifier is unsafe")
        raw = _mysql_query(
            runtime, runner, f"SELECT COUNT(*) FROM `{table}`;\n",
            database=database, label=f"count-{database}-{table}",
        ).decode("ascii").strip()
        try:
            value = int(raw)
        except ValueError as exception:
            raise UpgradeRehearsalError("ROW_COUNT", "database row count is invalid") from exception
        if value < 0:
            raise UpgradeRehearsalError("ROW_COUNT", "database row count is invalid")
        result[table] = value
    return result


def _projection_profile(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        database: str,
        tables: Sequence[str]) -> dict[str, dict[str, tuple[str, ...]]]:
    if (
        any(not isinstance(table, str) or not SAFE_IDENTIFIER.fullmatch(table) for table in tables)
        or len(tables) != len(set(tables))
    ):
        raise UpgradeRehearsalError("PROJECTION_IDENTIFIER", "database projection identifier is unsafe")
    result: dict[str, dict[str, tuple[str, ...]]] = {}
    for table in tables:
        columns = _mysql_query(
            runtime, runner,
            "SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() "
            f"AND table_name='{table}' ORDER BY ordinal_position;\n",
            database=database, label=f"columns-{database}-{table}",
        ).decode("utf-8").splitlines()
        primary = _mysql_query(
            runtime, runner,
            "SELECT column_name FROM information_schema.key_column_usage WHERE table_schema=DATABASE() "
            f"AND table_name='{table}' AND constraint_name='PRIMARY' ORDER BY ordinal_position;\n",
            database=database, label=f"primary-{database}-{table}",
        ).decode("utf-8").splitlines()
        if (
            not columns
            or any(not SAFE_IDENTIFIER.fullmatch(value) for value in (*columns, *primary))
            or len(columns) != len(set(columns))
            or len(primary) != len(set(primary))
            or not set(primary).issubset(columns)
        ):
            raise UpgradeRehearsalError("PROJECTION_PROFILE", "database projection profile is invalid")
        result[table] = {"columns": tuple(columns), "order": tuple(primary or columns)}
    return result


def _validated_projection_specification(
        table: object,
        specification: Mapping[str, Sequence[str]]) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if not isinstance(table, str) or not SAFE_IDENTIFIER.fullmatch(table):
        raise UpgradeRehearsalError("PROJECTION_IDENTIFIER", "database projection identifier is unsafe")
    try:
        raw_columns = specification["columns"]
        raw_order = specification["order"]
    except (KeyError, TypeError) as exception:
        raise UpgradeRehearsalError(
            "PROJECTION_PROFILE", "database projection profile is invalid"
        ) from exception
    if isinstance(raw_columns, (str, bytes)) or isinstance(raw_order, (str, bytes)):
        raise UpgradeRehearsalError("PROJECTION_PROFILE", "database projection profile is invalid")
    columns = tuple(raw_columns)
    order = tuple(raw_order)
    if (
        not columns
        or not order
        or any(not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value) for value in (*columns, *order))
        or len(columns) != len(set(columns))
        or len(order) != len(set(order))
        or not set(order).issubset(columns)
    ):
        raise UpgradeRehearsalError("PROJECTION_IDENTIFIER", "database projection identifier is unsafe")
    return table, columns, order


def _framed_column_expression(column: str) -> str:
    """Build a prefix-free binary SQL frame for one already validated column.

    NULL is a single zero marker.  A non-NULL value is a one marker, an
    unsigned eight-byte big-endian byte length, and the exact binary value.
    This keeps NULL, empty bytes, embedded delimiters, and adjacent column
    boundaries distinct without returning the row content to the harness.
    """
    if not isinstance(column, str) or not SAFE_IDENTIFIER.fullmatch(column):
        raise UpgradeRehearsalError("PROJECTION_IDENTIFIER", "database projection identifier is unsafe")
    quoted = f"`{column}`"
    binary_value = f"CAST({quoted} AS BINARY)"
    return (
        f"CASE WHEN {quoted} IS NULL THEN UNHEX('00') ELSE CONCAT("
        f"UNHEX('01'),UNHEX(LPAD(HEX(OCTET_LENGTH({binary_value})),16,'0')),{binary_value}) END"
    )


def _projection_hashes(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        database: str,
        profile: Mapping[str, Mapping[str, Sequence[str]]]) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for table, specification in profile.items():
        table, columns, _order = _validated_projection_specification(table, specification)
        frames = ",".join(_framed_column_expression(value) for value in columns)
        query = (
            f"SELECT LOWER(SHA2(CONCAT({frames}),256)) AS `row_sha256` "
            f"FROM `{table}` ORDER BY `row_sha256`;\n"
        )
        lines = _mysql_query(
            runtime, runner, query, database=database, label=f"projection-{database}-{table}"
        ).decode("ascii").splitlines()
        if any(not SHA256.fullmatch(value) for value in lines):
            raise UpgradeRehearsalError("PROJECTION_HASH", "database row digest output is invalid")
        result[table] = tuple(sorted(lines))
    return result


def _digest_multiplicities(values: Sequence[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise UpgradeRehearsalError("PROJECTION_HASH", "database row digest output is invalid")
        result[value] = result.get(value, 0) + 1
    return result


def _assert_v1_projection_preserved(
        before: Mapping[str, Sequence[str]],
        after: Mapping[str, Sequence[str]],
        before_counts: Mapping[str, int],
        after_counts: Mapping[str, int]) -> None:
    expected_tables = set(before)
    if (
        expected_tables != set(after)
        or expected_tables != set(before_counts)
        or expected_tables != set(after_counts)
        or any(not isinstance(table, str) or not SAFE_IDENTIFIER.fullmatch(table) for table in expected_tables)
    ):
        raise UpgradeRehearsalError("V1_PROJECTION", "V1 row projection set changed during migration")
    for table in sorted(expected_tables):
        before_rows = tuple(before[table])
        after_rows = tuple(after[table])
        if (
            isinstance(before_counts[table], bool)
            or not isinstance(before_counts[table], int)
            or isinstance(after_counts[table], bool)
            or not isinstance(after_counts[table], int)
            or before_counts[table] < 0
            or after_counts[table] < 0
            or len(before_rows) != before_counts[table]
            or len(after_rows) != after_counts[table]
        ):
            raise UpgradeRehearsalError("V1_PROJECTION", "V1 row projection cardinality is invalid")
        before_multiplicities = _digest_multiplicities(before_rows)
        after_multiplicities = _digest_multiplicities(after_rows)
        if table in AUDIT_TABLES:
            if any(
                after_multiplicities.get(digest, 0) < occurrences
                for digest, occurrences in before_multiplicities.items()
            ):
                raise UpgradeRehearsalError(
                    "V1_AUDIT_PROJECTION", "a V1 audit row changed or disappeared during migration"
                )
        elif before_multiplicities != after_multiplicities:
            raise UpgradeRehearsalError(
                "V1_PROJECTION", "a V1 row changed or disappeared during migration"
            )


def flyway_checksum(path: Path) -> int:
    """Reproduce Flyway's UTF-8, line-ending-independent CRC32 checksum."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exception:
        raise UpgradeRehearsalError(
            "FLYWAY_SOURCE", "a frozen Flyway migration is unreadable"
        ) from exception
    checksum = 0
    for line in text.splitlines():
        if line.startswith("\ufeff"):
            line = line[1:]
        checksum = zlib.crc32(line.encode("utf-8"), checksum)
    return checksum if checksum < 2**31 else checksum - 2**32


def _flyway_history(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        database: str) -> tuple[dict[str, Any], ...]:
    payload = _mysql_query(
        runtime,
        runner,
        (
            "SELECT installed_rank, version, description, type, script, "
            "IFNULL(checksum, ''), success FROM flyway_schema_history ORDER BY installed_rank;\n"
        ),
        database=database,
        label=f"flyway-{database}",
    )
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exception:
        raise UpgradeRehearsalError(
            "FLYWAY_HISTORY", "Flyway history is not valid UTF-8"
        ) from exception
    history: list[dict[str, Any]] = []
    for line in lines:
        columns = line.split("\t")
        if len(columns) != 7:
            raise UpgradeRehearsalError(
                "FLYWAY_HISTORY", "Flyway history has an unexpected row shape"
            )
        try:
            installed_rank = int(columns[0])
            version = int(columns[1])
            checksum = int(columns[5])
        except ValueError as exception:
            raise UpgradeRehearsalError(
                "FLYWAY_HISTORY", "Flyway history contains a nonnumeric field"
            ) from exception
        if columns[6] != "1":
            raise UpgradeRehearsalError(
                "FLYWAY_HISTORY", "Flyway history contains an unsuccessful migration"
            )
        history.append({
            "installedRank": installed_rank,
            "version": version,
            "description": columns[2],
            "type": columns[3],
            "script": columns[4],
            "checksum": checksum,
            "success": True,
        })
    return tuple(history)


def assert_flyway_history(
        history: Sequence[Mapping[str, Any]],
        source_files: Mapping[str, Path],
        migrations: Sequence[str]) -> list[dict[str, Any]]:
    if set(source_files) != set(migrations):
        raise UpgradeRehearsalError(
            "FLYWAY_SOURCE", "the frozen Flyway source map is incomplete"
        )
    expected: list[dict[str, Any]] = []
    for installed_rank, relative in enumerate(migrations, start=1):
        source = source_files[relative]
        filename = Path(relative).name
        matched = re.fullmatch(r"V([1-9][0-9]*)__([A-Za-z0-9_]+)\.sql", filename)
        if source.is_symlink() or not source.is_file() or matched is None:
            raise UpgradeRehearsalError(
                "FLYWAY_SOURCE", "the frozen Flyway migration set is invalid"
            )
        expected.append({
            "installedRank": installed_rank,
            "version": int(matched.group(1)),
            "description": matched.group(2).replace("_", " "),
            "type": "SQL",
            "script": filename,
            "checksum": flyway_checksum(source),
            "success": True,
            "scriptSha256": sha256_file(source),
        })
    observed = [dict(row) for row in history]
    comparable = [{key: value for key, value in row.items() if key != "scriptSha256"}
                  for row in expected]
    if observed != comparable:
        raise UpgradeRehearsalError(
            "FLYWAY_HISTORY", "Flyway history does not match the frozen exact migration inventory"
        )
    return expected


def _sdk_environment(
        runtime: RuntimeContext,
        tls: Mapping[str, Path],
        manifest: Mapping[str, Any],
        token_file: Path,
        *,
        public: bool,
        trace_prefix: str,
        web_audit: bool = False,
        audit_trace_filter_supported: bool = True,
        expected_actor_type: str = "USER",
        expected_client_id_present: bool = True) -> dict[str, str]:
    if expected_actor_type not in {"USER", "SERVICE_ACCOUNT"}:
        raise UpgradeRehearsalError(
            "SDK_EXPECTED_ACTOR", "SDK expected actor type is invalid"
        )
    java_options = (
        f"-Djavax.net.ssl.trustStore={tls['truststore']} "
        "-Djavax.net.ssl.trustStorePassword=changeit "
        f"-Djdk.net.hosts.file={tls['hosts']} "
        f"-Dhttp.nonProxyHosts={runtime.names.public_hostname}|{runtime.names.private_hostname}|localhost|127.*"
    )
    maven_home, user_home, _ = _private_maven_paths(runtime)
    environment = sanitized_host_environment()
    environment.update({
        "JAVA_TOOL_OPTIONS": java_options,
        "HOME": str(user_home),
        "MAVEN_USER_HOME": str(maven_home),
        "WEB_STARTER_MCP_BASE_URL": (
            f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}"
            if public else f"http://{runtime.names.private_hostname}:{runtime.ports.private_http}"
        ),
        "WEB_STARTER_MCP_TOKEN_RESPONSE_FILE": str(token_file),
        "WEB_STARTER_MCP_OWNER_ID": str(manifest["ownerId"]),
        "WEB_STARTER_MCP_PROJECT_ID": str(manifest["projectId"]),
        "WEB_STARTER_MCP_TRACE_PREFIX": trace_prefix,
        "WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE": expected_actor_type,
        "WEB_STARTER_MCP_EXPECTED_CLIENT_ID_PRESENT": (
            "true" if expected_client_id_present else "false"
        ),
        "WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED": "false",
        "WEB_STARTER_MCP_AUDIT_TRACE_FILTER_SUPPORTED": (
            "true" if audit_trace_filter_supported else "false"
        ),
    })
    if web_audit:
        # McpSdkCrudRuntimeIT uses PAT only for /mcp, then creates a
        # short-lived Web session to prove the corresponding business
        # operation audit rows. Do not broaden PAT authentication to /api or
        # expose these credentials to the read-only SDK invocations.
        environment.update({
            "WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME": (
                runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME"]
            ),
            "WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD": (
                runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD"]
            ),
            "WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL": (
                f"http://127.0.0.1:{runtime.ports.private_http}"
            ),
        })
    return environment


def _private_maven_paths(runtime: RuntimeContext) -> tuple[Path, Path, Path]:
    seed_root = runtime.runtime_root / "dependency-seed"
    maven_home = seed_root / DEPENDENCY_SEED_COMPONENTS["mavenHome"]
    user_home = runtime.runtime_root / "sdk-user-home"
    repository = seed_root / DEPENDENCY_SEED_COMPONENTS["mavenRepository"]
    if not user_home.exists():
        user_home.mkdir(mode=0o700)
    for path in (maven_home, user_home, repository):
        if path.is_symlink() or not path.is_dir():
            raise UpgradeRehearsalError("SDK_MAVEN_HOME", "private Maven home is unsafe")
    settings = runtime.runtime_root / "sdk-settings.xml"
    if not settings.exists():
        write_private(settings, b"<settings/>\n")
    if settings.is_symlink() or not settings.is_file() or stat.S_IMODE(settings.stat().st_mode) != 0o600:
        raise UpgradeRehearsalError("SDK_MAVEN_SETTINGS", "private Maven settings are unsafe")
    return maven_home, user_home, settings


def _private_maven_repository(runtime: RuntimeContext) -> Path:
    repository = (
        runtime.runtime_root / "dependency-seed"
        / DEPENDENCY_SEED_COMPONENTS["mavenRepository"]
    )
    if repository.is_symlink() or not repository.is_dir():
        raise UpgradeRehearsalError(
            "SDK_MAVEN_REPOSITORY", "private Maven repository copy is unavailable"
        )
    return repository


def _parse_single_surefire_report(report_directory: Path, test_class: str) -> dict[str, Any]:
    if report_directory.is_symlink() or not report_directory.is_dir():
        raise UpgradeRehearsalError(
            "SDK_REPORT_DIRECTORY", "this SDK invocation did not create its private report directory"
        )
    reports = tuple(sorted(report_directory.rglob("*.xml")))
    if len(reports) != 1:
        raise UpgradeRehearsalError(
            "SDK_REPORT_COUNT", "this SDK invocation did not produce exactly one Surefire XML"
        )
    report = reports[0]
    if report.is_symlink() or not report.is_file() or not _inside(
        report.resolve(), report_directory.resolve()
    ):
        raise UpgradeRehearsalError("SDK_REPORT_PATH", "the Surefire XML path is unsafe")
    payload = report.read_bytes()
    if not payload or len(payload) > 4 * 1024 * 1024:
        raise UpgradeRehearsalError("SDK_REPORT_SIZE", "the Surefire XML size is invalid")
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise UpgradeRehearsalError("SDK_REPORT_XML", "the Surefire XML contains a forbidden DTD")
    try:
        suite = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise UpgradeRehearsalError("SDK_REPORT_XML", "the Surefire XML is malformed") from exception
    if suite.tag != "testsuite" or suite.get("name") != test_class:
        raise UpgradeRehearsalError(
            "SDK_REPORT_SUITE", "the Surefire XML does not identify the requested SDK test"
        )

    counts: dict[str, int] = {}
    for name in ("tests", "failures", "errors", "skipped"):
        raw = suite.get(name)
        if raw is None or not re.fullmatch(r"[0-9]+", raw):
            raise UpgradeRehearsalError(
                "SDK_REPORT_COUNTER", "the Surefire XML has an invalid test counter"
            )
        counts[name] = int(raw)
    if counts != {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}:
        raise UpgradeRehearsalError(
            "SDK_REPORT_RESULT", "the SDK test did not run exactly once and pass"
        )
    flakes = suite.get("flakes")
    if (
        flakes is not None
        and (not re.fullmatch(r"[0-9]+", flakes) or int(flakes) != 0)
    ) or any(
        suite.find(f".//{name}") is not None
        for name in ("flakyFailure", "flakyError")
    ):
        raise UpgradeRehearsalError(
            "SDK_REPORT_FLAKY", "the SDK test report contains a retried flaky failure"
        )
    testcases = suite.findall("testcase")
    if (
        len(testcases) != 1
        or testcases[0].get("classname") != test_class
        or any(testcases[0].find(name) is not None for name in ("failure", "error", "skipped"))
    ):
        raise UpgradeRehearsalError(
            "SDK_REPORT_TESTCASE", "the Surefire XML testcase does not prove one passing execution"
        )
    return {**counts, "reportSha256": sha256_bytes(payload)}


def _failed_sdk_report_detail(report_directory: Path, test_class: str) -> str:
    """Return a bounded diagnostic derived only from a failed test's type and source line."""
    if report_directory.is_symlink() or not report_directory.is_dir():
        return "NO_REPORT_DIRECTORY"
    reports = tuple(sorted(report_directory.rglob("*.xml")))
    if len(reports) != 1:
        return "NO_REPORT" if not reports else "MULTIPLE_REPORTS"
    report = reports[0]
    try:
        if report.is_symlink() or not report.is_file() or not _inside(
            report.resolve(), report_directory.resolve()
        ):
            return "UNSAFE_REPORT"
        payload = report.read_bytes()
    except OSError:
        return "UNREADABLE_REPORT"
    if not payload or len(payload) > 4 * 1024 * 1024:
        return "INVALID_REPORT_SIZE"
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        return "FORBIDDEN_REPORT_XML"
    try:
        suite = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return "MALFORMED_REPORT_XML"
    if suite.tag != "testsuite" or suite.get("name") != test_class:
        return "UNEXPECTED_REPORT_SUITE"

    testcase = suite.find("testcase")
    if (
        testcase is None
        or testcase.get("classname") != test_class
        or len(suite.findall("testcase")) != 1
    ):
        return "UNEXPECTED_REPORT_TESTCASE"
    failure = testcase.find("failure")
    failure_kind = "FAILURE"
    if failure is None:
        failure = testcase.find("error")
        failure_kind = "ERROR"
    if failure is None:
        return "FAILED_WITHOUT_REPORT_DETAIL"

    failure_type = re.sub(
        r"[^A-Z0-9]+",
        "_",
        failure.get("type", "UNKNOWN").upper(),
    ).strip("_")[:40].rstrip("_") or "UNKNOWN"
    simple_name = test_class.rsplit(".", 1)[-1]
    source_line = re.search(
        rf"{re.escape(simple_name)}\.java:([1-9][0-9]{{0,5}})",
        failure.text or "",
    )
    line_detail = f"_LINE_{source_line.group(1)}" if source_line is not None else ""
    return f"{failure_kind}_{failure_type}{line_detail}"[:72].rstrip("_")


def _prepare_sdk_dependencies(
        runtime: RuntimeContext, runner: PrivateCommandRunner) -> None:
    if runtime.sdk_dependencies_prepared:
        return
    source = assert_sdk_source_unchanged(runtime)
    assert_runtime_sources_unchanged(runtime)
    maven_home, user_home, settings = _private_maven_paths(runtime)
    base = [
        str((source / "mvnw").resolve()),
        "--batch-mode",
        "--no-transfer-progress",
        "--offline",
        "--settings", str(settings),
        f"-Dmaven.repo.local={_private_maven_repository(runtime)}",
    ]
    environment = {
        **sanitized_host_environment(),
        "HOME": str(user_home),
        "MAVEN_USER_HOME": str(maven_home),
    }

    runner.run([
        *base,
        "-pl",
        "web-starter-mcp",
        "-am",
        "-DskipTests",
        "-DskipITs",
        "clean",
        "install",
    ], label="sdk-prepare-reactor-dependencies", cwd=source, environment=environment,
        replace_environment=True, timeout=900)
    # -DskipTests intentionally avoids resolving Surefire's dynamically
    # selected JUnit Platform provider.  Resolve and execute one fixed,
    # credential-free unit test before SDK invocations switch to the
    # loopback-only hosts file and can no longer reach Maven Central.
    runner.run([
        *base,
        "-pl",
        "web-starter-mcp",
        "-Dtest=dev.webstarter.mcp.acceptance.McpRuntimeToolExpectationsTest",
        "-Dsurefire.failIfNoSpecifiedTests=true",
        "-Dsurefire.rerunFailingTestsCount=0",
        "-DfailIfNoTests=true",
        "test",
    ], label="sdk-prepare-surefire-provider", cwd=source, environment=environment,
        replace_environment=True, timeout=900)
    assert_sdk_source_unchanged(runtime)
    assert_runtime_sources_unchanged(runtime)
    runtime.sdk_dependencies_prepared = True


def _run_sdk_test(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        tls: Mapping[str, Path],
        manifest: Mapping[str, Any],
        token_file: Path,
        test_class: str,
        *,
        public: bool,
        trace_prefix: str,
        audit_trace_filter_supported: bool = True,
        expected_actor_type: str = "USER",
        expected_client_id_present: bool = True) -> None:
    source_relative = MCP_SDK_TEST_SOURCES.get(test_class)
    if source_relative is None:
        raise UpgradeRehearsalError("SDK_TEST_CLASS", "SDK test class is not in the frozen allowlist")
    _prepare_sdk_dependencies(runtime, runner)
    source = assert_sdk_source_unchanged(runtime)
    assert_runtime_sources_unchanged(runtime)
    runtime.sdk_invocation_count += 1
    simple_name = test_class.rsplit(".", 1)[-1]
    report_directory = (
        runtime.runtime_root
        / "surefire"
        / f"{runtime.sdk_invocation_count:02d}-{simple_name}"
    )
    if report_directory.exists() or report_directory.is_symlink():
        raise UpgradeRehearsalError(
            "SDK_REPORT_COLLISION", "the private Surefire report directory already exists"
        )
    report_directory.mkdir(parents=True, mode=0o700)
    _, _, settings = _private_maven_paths(runtime)
    sdk_result = runner.run(
        [
            str((source / "mvnw").resolve()), "--batch-mode", "--no-transfer-progress",
            "--offline",
            "--settings", str(settings),
            f"-Dmaven.repo.local={_private_maven_repository(runtime)}",
            "-pl", "web-starter-mcp", f"-Dtest={test_class}",
            "-Dsurefire.failIfNoSpecifiedTests=true",
            "-Dsurefire.rerunFailingTestsCount=0",
            "-DfailIfNoTests=true",
            f"-D{MCP_SUREFIRE_REPORTS_PROPERTY}={report_directory}",
            "clean",
            "test",
        ],
        label="sdk-" + simple_name,
        cwd=source,
        environment=_sdk_environment(
            runtime, tls, manifest, token_file, public=public, trace_prefix=trace_prefix,
            web_audit=(test_class == "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"),
            audit_trace_filter_supported=audit_trace_filter_supported,
            expected_actor_type=expected_actor_type,
            expected_client_id_present=expected_client_id_present,
        ),
        replace_environment=True,
        timeout=900,
        check=False,
    )
    if sdk_result.returncode != 0:
        detail = _failed_sdk_report_detail(report_directory, test_class)
        raise UpgradeRehearsalError(
            f"SDK_TEST_FAILED_{detail}",
            "an SDK acceptance test failed; only a bounded failure type and source line are exposed",
        )
    assert_sdk_source_unchanged(runtime)
    assert_runtime_sources_unchanged(runtime)
    report = _parse_single_surefire_report(report_directory, test_class)
    runtime.sanitized_observations.setdefault("mcpSdkSurefire", []).append({
        "testClass": test_class,
        "tests": report["tests"],
        "failures": report["failures"],
        "errors": report["errors"],
        "skipped": report["skipped"],
        "reportSha256": report["reportSha256"],
        "testSourceSha256": runtime.runtime_source_hashes[source_relative],
        "rootPomSha256": runtime.runtime_source_hashes["pom.xml"],
        "modulePomSha256": runtime.runtime_source_hashes["web-starter-mcp/pom.xml"],
    })


def _swap_manifest_for_v2(
        runtime: RuntimeContext,
        credential_root: Path,
        keys: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    source = json.loads((credential_root / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(source, dict) or not isinstance(source.get("oauthSigningKeys"), dict):
        raise UpgradeRehearsalError("FIXTURE_MANIFEST", "fixture manifest is invalid")
    source["oauthSigningKeys"] = {"activeKid": keys["v2Kid"], "retiringKid": keys["v1Kid"]}
    source["privateMcpBaseUrl"] = (
        f"http://{runtime.names.private_hostname}:{runtime.ports.private_http}"
    )
    target = credential_root / "manifest-v2.json"
    write_private_json(target, source)
    return target, source


def _playwright_temp_root(runtime: RuntimeContext) -> Path:
    existing = runtime.playwright_temp_root
    sentinel_name = ".web-starter-playwright-owner.json"
    expected_owner = {"owner": OWNER_VALUE, "runId": runtime.names.run_id}
    if existing is not None:
        try:
            owner = json.loads((existing / sentinel_name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            owner = None
        if existing.is_symlink() or not existing.is_dir() or owner != expected_owner:
            raise UpgradeRehearsalError(
                "PLAYWRIGHT_PRIVATE_PATH",
                "private Playwright temporary root lost its ownership boundary",
            )
        return existing
    root = runtime.runtime_root.parent / f"p-{runtime.names.run_id}"
    if root.exists() or root.is_symlink() or _inside(root.resolve(), REPOSITORY_ROOT.resolve()):
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_PRIVATE_PATH",
            "private Playwright temporary root collided with an existing path",
        )
    root.mkdir(mode=0o700)
    write_private_json(root / sentinel_name, expected_owner)
    runtime.playwright_temp_root = root
    return root


def _playwright_environment(runtime: RuntimeContext) -> dict[str, str]:
    roots = {
        "HOME": runtime.runtime_root / "playwright-user-home",
        "PNPM_HOME": runtime.runtime_root / "pnpm-home",
        "XDG_CONFIG_HOME": runtime.runtime_root / "xdg-config",
        "XDG_CACHE_HOME": runtime.runtime_root / "xdg-cache",
        # Chromium and Playwright need a short temp path for Unix sockets.
        # This sibling is private, owner-marked and removed with runtime_root.
        "TMPDIR": _playwright_temp_root(runtime),
    }
    for path in roots.values():
        if not path.exists():
            path.mkdir(mode=0o700)
        if path.is_symlink() or not path.is_dir():
            raise UpgradeRehearsalError(
                "PLAYWRIGHT_PRIVATE_PATH", "private Playwright dependency path is unsafe"
            )
    environment = sanitized_host_environment()
    environment.update({name: str(path) for name, path in roots.items()})
    seed_root = runtime.runtime_root / "dependency-seed"
    seeded_roots = {
        "COREPACK_HOME": seed_root / DEPENDENCY_SEED_COMPONENTS["corepackHome"],
        "PLAYWRIGHT_BROWSERS_PATH": (
            seed_root / DEPENDENCY_SEED_COMPONENTS["playwrightBrowsers"]
        ),
    }
    for name, path in seeded_roots.items():
        if path.is_symlink() or not path.is_dir():
            raise UpgradeRehearsalError(
                "PLAYWRIGHT_PRIVATE_PATH", "private Playwright dependency copy is unavailable"
            )
        environment[name] = str(path)
    user_config = runtime.runtime_root / "playwright-user.npmrc"
    global_config = runtime.runtime_root / "playwright-global.npmrc"
    for config in (user_config, global_config):
        if not config.exists():
            write_private(config, b"\n")
        if config.is_symlink() or not config.is_file() or stat.S_IMODE(config.stat().st_mode) != 0o600:
            raise UpgradeRehearsalError(
                "PLAYWRIGHT_NPM_CONFIG", "private package-manager config is unsafe"
            )
    environment.update({
        "NPM_CONFIG_USERCONFIG": str(user_config),
        "NPM_CONFIG_GLOBALCONFIG": str(global_config),
        "npm_config_userconfig": str(user_config),
        "npm_config_globalconfig": str(global_config),
        "COREPACK_ENABLE_NETWORK": "0",
        "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
        "NPM_CONFIG_OFFLINE": "true",
        "npm_config_offline": "true",
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    })
    return environment


def _private_pnpm_store(runtime: RuntimeContext) -> Path:
    store = (
        runtime.runtime_root / "dependency-seed"
        / DEPENDENCY_SEED_COMPONENTS["pnpmStore"]
    )
    content = store / "v3" / "files"
    if (
        store.is_symlink()
        or not store.is_dir()
        or (store / "v3").is_symlink()
        or not (store / "v3").is_dir()
        or content.is_symlink()
        or not content.is_dir()
        or not any(content.iterdir())
    ):
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_PNPM_STORE",
            "private pnpm 9 store must contain a real non-empty v3/files directory",
        )
    return store


def _prepare_playwright_dependencies(
        runtime: RuntimeContext, runner: PrivateCommandRunner) -> tuple[Path, dict[str, str]]:
    source = assert_sdk_source_unchanged(runtime)
    web = source / "web-starter-web"
    environment = _playwright_environment(runtime)
    if runtime.playwright_dependencies_prepared:
        return web, environment
    version = runner.run(
        [*PINNED_PNPM_COMMAND, "--version"],
        label="playwright-pnpm-version",
        cwd=web,
        environment=environment,
        replace_environment=True,
        timeout=30,
    ).stdout.strip()
    if version != b"9.15.9":
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_PNPM_VERSION", "formal Playwright requires pnpm 9.15.9"
        )
    runner.run(
        [
            *PINNED_PNPM_COMMAND,
            "install", "--frozen-lockfile", "--ignore-scripts", "--offline",
            "--store-dir", str(_private_pnpm_store(runtime)),
        ],
        label="playwright-frozen-install",
        cwd=web,
        environment=environment,
        replace_environment=True,
        timeout=1200,
    )
    cli = web / "node_modules" / ".bin" / "playwright"
    package = web / "node_modules" / "@playwright" / "test" / "package.json"
    try:
        package_document = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exception:
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_INSTALL", "installed Playwright package metadata is invalid"
        ) from exception
    if (
        not cli.exists()
        or not cli.is_file()
        or not _inside(cli.resolve(), (web / "node_modules").resolve())
        or package_document.get("version") != "1.61.1"
    ):
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_INSTALL", "installed Playwright is not the frozen 1.61.1 package"
        )
    chromium = (
        Path(environment["PLAYWRIGHT_BROWSERS_PATH"])
        / f"chromium-{DEPENDENCY_SEED_VERSIONS['chromiumRevision']}"
    )
    if not (chromium / "INSTALLATION_COMPLETE").is_file():
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_BROWSER_SEED", "private Chromium seed is incomplete"
        )
    assert_sdk_source_unchanged(runtime)
    runtime.playwright_dependencies_prepared = True
    return web, environment


def _parse_playwright_json(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_REPORT_JSON", "Playwright did not emit one JSON report"
        ) from exception
    if not isinstance(document, dict) or document.get("errors") != []:
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_REPORT", "Playwright report contains top-level errors"
        )
    config = document.get("config")
    projects = config.get("projects") if isinstance(config, dict) else None
    if (
        not isinstance(config, dict)
        or config.get("version") != "1.61.1"
        or config.get("workers") != 1
        or config.get("forbidOnly") is not True
        or config.get("fullyParallel") is not False
        or config.get("reporter") != [["json"]]
        or not isinstance(projects, list)
        or len(projects) != 1
        or projects[0].get("retries") != 0
        or projects[0].get("repeatEach") != 1
    ):
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_REPORT_CONFIG", "Playwright report configuration is not exact"
        )
    stats = document.get("stats")
    expected_count = sum(len(titles) for titles in PLAYWRIGHT_EXPECTED_TITLES.values())
    if not isinstance(stats, dict) or any(
        stats.get(name) != expected
        for name, expected in (
            ("expected", expected_count), ("skipped", 0),
            ("unexpected", 0), ("flaky", 0),
        )
    ):
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_REPORT_STATS", "Playwright report does not prove twenty clean passes"
        )
    suites = document.get("suites")
    if not isinstance(suites, list) or len(suites) != len(PLAYWRIGHT_EXPECTED_TITLES):
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_REPORT_SUITES", "Playwright report suite set is not exact"
        )
    observed: dict[str, tuple[str, ...]] = {}
    for suite in suites:
        if not isinstance(suite, dict) or not isinstance(suite.get("file"), str):
            raise UpgradeRehearsalError("PLAYWRIGHT_REPORT_SUITES", "Playwright suite is invalid")
        file_name = suite["file"]
        specs = suite.get("specs")
        if not isinstance(specs, list):
            raise UpgradeRehearsalError("PLAYWRIGHT_REPORT_SUITES", "Playwright specs are invalid")
        titles: list[str] = []
        for spec in specs:
            tests = spec.get("tests") if isinstance(spec, dict) else None
            if (
                not isinstance(spec, dict)
                or spec.get("ok") is not True
                or not isinstance(spec.get("title"), str)
                or not isinstance(tests, list)
                or len(tests) != 1
            ):
                raise UpgradeRehearsalError("PLAYWRIGHT_REPORT_SPEC", "Playwright spec is not exact")
            test = tests[0]
            results = test.get("results") if isinstance(test, dict) else None
            if (
                not isinstance(test, dict)
                or test.get("expectedStatus") != "passed"
                or test.get("status") != "expected"
                or not isinstance(results, list)
                or len(results) != 1
                or not isinstance(results[0], dict)
                or results[0].get("status") != "passed"
                or results[0].get("retry") != 0
            ):
                raise UpgradeRehearsalError(
                    "PLAYWRIGHT_REPORT_RESULT", "Playwright test did not pass once without retry"
                )
            titles.append(spec["title"])
        observed[file_name] = tuple(titles)
    if observed != PLAYWRIGHT_EXPECTED_TITLES:
        raise UpgradeRehearsalError(
            "PLAYWRIGHT_REPORT_IDENTITY", "Playwright test identities are not the frozen suite"
        )
    return {
        "tests": expected_count,
        "failures": 0,
        "skipped": 0,
        "flaky": 0,
        "reportSha256": sha256_bytes(payload),
    }


def _failed_playwright_report_detail(payload: bytes) -> str:
    """Classify a failed fixed Playwright suite without exposing failure messages."""
    if not payload or len(payload) > 16 * 1024 * 1024:
        return "MISSING_OR_OVERSIZED_REPORT"
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "MALFORMED_JSON_REPORT"
    if not isinstance(document, dict):
        return "INVALID_REPORT_ROOT"
    suites = document.get("suites")
    if not isinstance(suites, list):
        return "MISSING_SUITES"

    failures: list[tuple[str, int, str, str | None, str | None]] = []
    incomplete_suites: list[str] = []
    seen: set[str] = set()
    for suite in suites:
        if not isinstance(suite, dict):
            return "INVALID_SUITE"
        file_name = suite.get("file")
        if (
            not isinstance(file_name, str)
            or file_name not in PLAYWRIGHT_EXPECTED_TITLES
            or file_name in seen
        ):
            return "UNEXPECTED_SUITE"
        seen.add(file_name)
        alias = PLAYWRIGHT_DIAGNOSTIC_ALIASES[file_name]
        specs = suite.get("specs")
        expected_titles = PLAYWRIGHT_EXPECTED_TITLES[file_name]
        if not isinstance(specs, list):
            return f"{alias}_SPEC_SHAPE"
        if len(specs) > len(expected_titles):
            return f"{alias}_SPEC_COUNT_{len(specs)}"
        if len(specs) != len(expected_titles):
            incomplete_suites.append(f"{alias}_SPEC_COUNT_{len(specs)}")
        for index, (spec, expected_title) in enumerate(
            zip(specs, expected_titles), start=1
        ):
            if not isinstance(spec, dict) or spec.get("title") != expected_title:
                return f"{alias}_SPEC_{index}_IDENTITY"
            tests = spec.get("tests")
            if not isinstance(tests, list) or len(tests) != 1 or not isinstance(tests[0], dict):
                return f"{alias}_SPEC_{index}_TEST_SHAPE"
            test = tests[0]
            results = test.get("results")
            passed_once = (
                spec.get("ok") is True
                and test.get("expectedStatus") == "passed"
                and test.get("status") == "expected"
                and isinstance(results, list)
                and len(results) == 1
                and isinstance(results[0], dict)
                and results[0].get("status") == "passed"
                and results[0].get("retry") == 0
            )
            if passed_once:
                continue
            raw_status = (
                results[-1].get("status")
                if isinstance(results, list)
                and results
                and isinstance(results[-1], dict)
                else test.get("status")
            )
            status = re.sub(
                r"[^A-Z0-9]+", "_", str(raw_status or "UNKNOWN").upper()
            ).strip("_")[:24].rstrip("_") or "UNKNOWN"
            source_line: str | None = None
            safe_marker: str | None = None
            if (
                isinstance(results, list)
                and results
                and isinstance(results[-1], dict)
            ):
                location_candidates: list[Any] = []
                error_text: list[str] = []
                error = results[-1].get("error")
                if isinstance(error, dict):
                    location_candidates.append(error.get("location"))
                    error_text.extend(
                        value for name in ("stack", "message", "snippet")
                        if isinstance((value := error.get(name)), str)
                    )
                errors = results[-1].get("errors")
                if isinstance(errors, list):
                    for item in errors:
                        if isinstance(item, dict):
                            location_candidates.append(item.get("location"))
                            error_text.extend(
                                value for name in ("stack", "message", "snippet")
                                if isinstance((value := item.get(name)), str)
                            )
                for location in location_candidates:
                    if (
                        isinstance(location, dict)
                        and isinstance(location.get("file"), str)
                        and Path(location["file"]).name == file_name
                        and isinstance(location.get("line"), int)
                        and not isinstance(location["line"], bool)
                        and 0 < location["line"] <= 999_999
                    ):
                        source_line = str(location["line"])
                        break
                combined_error = "\n".join(error_text)
                if source_line is None:
                    match = re.search(
                        rf"{re.escape(file_name)}:([1-9][0-9]{{0,5}}):[1-9][0-9]{{0,4}}",
                        combined_error,
                    )
                    if match is not None:
                        source_line = match.group(1)
                marker = re.search(
                    r"\bSAFE_(?:HTTP_STATUS_[1-5][0-9]{2}|"
                    r"SESSION_COOKIE_(?:MISSING|NOT_HTTP_ONLY))\b",
                    combined_error,
                )
                if marker is not None:
                    safe_marker = marker.group(0)[len("SAFE_"):]
            failures.append((alias, index, status, source_line, safe_marker))

    if seen != set(PLAYWRIGHT_EXPECTED_TITLES):
        return "MISSING_EXPECTED_SUITE"
    if len(failures) == 1:
        alias, index, status, source_line, safe_marker = failures[0]
        line_detail = f"_LINE_{source_line}" if source_line is not None else ""
        marker_detail = f"_{safe_marker}" if safe_marker is not None else ""
        return f"{alias}_SPEC_{index}_{status}{line_detail}{marker_detail}"
    if failures:
        root_failures = [
            failure for failure in failures
            if failure[2] not in {"SKIPPED", "INTERRUPTED"}
        ]
        if root_failures:
            status_alias = {
                "FAILED": "F",
                "TIMEDOUT": "T",
            }
            roots = [
                (
                    f"{alias}_{index}_{status_alias.get(status, status[:1])}"
                    + (f"_L{source_line}" if source_line is not None else "")
                    + (f"_{safe_marker}" if safe_marker is not None else "")
                )
                for alias, index, status, source_line, safe_marker in root_failures
            ]
            return "_".join(roots)[:72].rstrip("_")
        grouped: list[str] = []
        for alias in PLAYWRIGHT_DIAGNOSTIC_ALIASES.values():
            indices = [
                str(index) for current, index, _, _, _ in failures
                if current == alias
            ]
            if indices:
                grouped.append(alias + "_" + "_".join(indices))
        statuses = {status for _, _, status, _, _ in failures}
        status = next(iter(statuses)) if len(statuses) == 1 else "MIXED"
        return ("_".join(grouped) + "_" + status)[:72].rstrip("_")
    if len(incomplete_suites) == 1:
        return incomplete_suites[0]
    if incomplete_suites:
        return f"MULTIPLE_INCOMPLETE_SUITES_{len(incomplete_suites)}"
    if document.get("errors"):
        return "TOP_LEVEL_ERRORS"
    return "NONZERO_WITHOUT_FAILED_SPEC"


def _run_playwright(
        runtime: RuntimeContext,
        runner: PrivateCommandRunner,
        manifest_path: Path) -> None:
    web, environment = _prepare_playwright_dependencies(runtime, runner)
    output = runtime.runtime_root / "playwright-output"
    output.mkdir(mode=0o700)
    environment.update({
        "WEB_STARTER_ACCEPTANCE_MANIFEST": str(manifest_path),
        "WEB_STARTER_BROWSER_BASE_URL": _private_browser_base_url(runtime),
        "WEB_STARTER_OAUTH_ACCEPTANCE_BASE_URL": f"https://{runtime.names.public_hostname}:{runtime.ports.public_https}",
        "WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME": runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME"],
        "WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD": runtime.environment["WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD"],
        "WEB_STARTER_ACCEPTANCE_INSECURE_TLS": "true",
        "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": runtime.names.public_hostname,
        "WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS": "127.0.0.1",
        "WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX": (
            f"upgrade-old-pat-crud-{runtime.names.run_id}"
        ),
        "WEB_STARTER_PLAYWRIGHT_OUTPUT_DIR": str(output),
    })
    cli = (web / "node_modules" / ".bin" / "playwright").resolve()
    result = runner.run(
        [
            str(cli), "test",
            "e2e/release-runtime.spec.ts",
            "e2e/frontend-quality-runtime.spec.ts",
            "e2e/v1-management-runtime.spec.ts",
            "--reporter=json", "--retries=0", "--workers=1",
            "--repeat-each=1", "--forbid-only",
        ],
        label="playwright-upgrade-runtime",
        cwd=web,
        environment=environment,
        replace_environment=True,
        timeout=1200,
        check=False,
    )
    if result.returncode != 0:
        detail = _failed_playwright_report_detail(result.stdout)
        raise UpgradeRehearsalError(
            f"PLAYWRIGHT_TEST_FAILED_{detail}",
            "a fixed browser acceptance test failed; messages and attachments remain private",
        )
    report = _parse_playwright_json(result.stdout)
    runtime.sanitized_observations["playwright"] = {
        **report,
        "packageJsonSha256": runtime.runtime_source_hashes["web-starter-web/package.json"],
        "lockfileSha256": runtime.runtime_source_hashes["web-starter-web/pnpm-lock.yaml"],
        "configSha256": runtime.runtime_source_hashes["web-starter-web/playwright.config.ts"],
        "testSourceSha256": {
            relative: runtime.runtime_source_hashes[relative]
            for relative in PLAYWRIGHT_TEST_SOURCES
        },
    }
    assert_sdk_source_unchanged(runtime)


def _raw_mcp_initialize_status(
        runtime: RuntimeContext, token_file: Path, *, public: bool = False) -> int:
    document = json.loads(token_file.read_text(encoding="utf-8"))
    token = document.get("token") or document.get("access_token")
    if not isinstance(token, str) or len(token) < 20:
        raise UpgradeRehearsalError("TOKEN_FILE", "private token response file is invalid")
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "upgrade-lifecycle-readback", "version": "1.0.0"}},
    }, separators=(",", ":")).encode("utf-8")
    hostname = runtime.names.public_hostname if public else runtime.names.private_hostname
    port = runtime.ports.public_https if public else runtime.ports.private_http
    scheme = "https" if public else "http"
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "X-Trace-Id": f"upgrade-lifecycle-{runtime.names.run_id}",
    }
    if public:
        headers["Origin"] = f"https://{hostname}:{port}"
    endpoint = f"{scheme}://{hostname}:{port}/mcp"
    request = Request(
        endpoint,
        data=payload,
        headers=headers,
        method="POST",
    )
    previous_hosts = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS")
    previous_address = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS")
    os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = hostname
    os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = "127.0.0.1"
    try:
        handlers: list[Any] = [ProxyHandler({}), RejectRedirectHandler()]
        if public:
            _reject_tls_key_log()
            handlers.append(HTTPSHandler(context=ssl._create_unverified_context()))  # noqa: SLF001
        opener = build_opener(*handlers)
        with isolated_loopback_resolution():
            try:
                with opener.open(request, timeout=20) as response:
                    response.read()
                    status = response.status
                    response_headers = response.headers
            except HTTPError as error:
                error.read()
                return error.code
            if status != 200:
                return status
            session_id = response_headers.get("Mcp-Session-Id", "")
            if not re.fullmatch(r"[A-Za-z0-9._-]{8,256}", session_id):
                raise UpgradeRehearsalError(
                    "MCP_SESSION_HEADER",
                    "successful lifecycle initialization did not return a valid MCP Session ID",
                )
            close_headers = {
                **headers,
                "Mcp-Session-Id": session_id,
                "X-Trace-Id": f"upgrade-lifecycle-{runtime.names.run_id}-close",
            }
            close_request = Request(
                endpoint,
                headers=close_headers,
                method="DELETE",
            )
            try:
                with opener.open(close_request, timeout=20) as response:
                    close_payload = response.read()
                    close_status = response.status
            except HTTPError as error:
                error.read()
                close_status = error.code
                close_payload = b""
            if close_status not in {200, 202, 204} or close_payload.strip():
                raise UpgradeRehearsalError(
                    f"MCP_SESSION_CLOSE_HTTP_{close_status}",
                    "lifecycle MCP probe did not release its temporary Session",
                )
            return status
    finally:
        if previous_hosts is None:
            os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS", None)
        else:
            os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS"] = previous_hosts
        if previous_address is None:
            os.environ.pop("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS", None)
        else:
            os.environ["WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS"] = previous_address


def _final_lifecycle_readback(
        runtime: RuntimeContext,
        credential_root: Path,
        service_fixture: Mapping[str, str],
    manifest: Mapping[str, Any]) -> None:
    api = _AdminApi(runtime)
    api.login()
    token_files = manifest.get("tokenFiles", {})
    lifecycle_pat_file = Path(service_fixture["lifecyclePatFile"])
    service_token_file = Path(str(token_files["serviceToken"]))
    pats_before = api.request("GET", api.private + "/api/security/personal-tokens", private=True)
    lifecycle_pat_before = next((
        item
        for item in pats_before
        if isinstance(item, dict)
        and str(item.get("id")) == service_fixture["lifecyclePatId"]
        and item.get("name") == service_fixture["lifecyclePatName"]
    ), None) if isinstance(pats_before, list) else None
    if not isinstance(lifecycle_pat_before, dict):
        raise UpgradeRehearsalError(
            "PERSONAL_CREDENTIAL_PRE_READBACK_MISSING",
            "lifecycle personal credential was not present before revocation",
        )
    if lifecycle_pat_before.get("revokedAt") is not None:
        raise UpgradeRehearsalError(
            "PERSONAL_CREDENTIAL_PRE_READBACK_REVOKED",
            "lifecycle personal credential was already revoked before the final proof",
        )
    pat_pre_status = _raw_mcp_initialize_status(runtime, lifecycle_pat_file)
    if pat_pre_status != 200:
        raise UpgradeRehearsalError(
            f"PERSONAL_CREDENTIAL_PRE_HTTP_{pat_pre_status}",
            "lifecycle PAT was not usable immediately before revocation",
        )
    service_pre_status = _raw_mcp_initialize_status(runtime, service_token_file)
    if service_pre_status != 200:
        raise UpgradeRehearsalError(
            f"SERVICE_PRE_DISABLE_HTTP_{service_pre_status}",
            "service token was not usable immediately before disable",
        )
    api.request(
        "DELETE",
        api.private + f"/api/security/personal-tokens/{service_fixture['lifecyclePatId']}",
        private=True,
    )
    api.request(
        "DELETE",
        api.private + f"/api/security/service-accounts/{service_fixture['serviceAccountId']}",
        private=True,
    )
    accounts = api.request("GET", api.private + "/api/security/service-accounts", private=True)
    if not isinstance(accounts, list) or not any(
        isinstance(item, dict)
        and str(item.get("id")) == service_fixture["serviceAccountId"]
        and item.get("enabled") is False
        for item in accounts
    ):
        raise UpgradeRehearsalError("SERVICE_DISABLED_READBACK", "disabled service account was not read back")
    pats = api.request("GET", api.private + "/api/security/personal-tokens", private=True)
    if not isinstance(pats, list) or not any(
        isinstance(item, dict)
        and item.get("name") == service_fixture["lifecyclePatName"]
        and item.get("revokedAt")
        for item in pats
    ):
        raise UpgradeRehearsalError("PAT_REVOKED_READBACK", "revoked PAT was not read back")
    pat_status = _raw_mcp_initialize_status(runtime, lifecycle_pat_file)
    if pat_status != 401:
        raise UpgradeRehearsalError("PAT_REVOKED_REJECT", "revoked PAT was not rejected")
    service_status = _raw_mcp_initialize_status(runtime, service_token_file)
    if service_status != 401:
        raise UpgradeRehearsalError("SERVICE_DISABLED_REJECT", "disabled service token was not rejected")


def _secret_scan_public_document(document: Mapping[str, Any]) -> None:
    encoded = json.dumps(document, ensure_ascii=False)
    patterns = (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b",
        r"(?i)[\"']?(?:password|access_token|refresh_token|client_secret|code_verifier|cookie)"
        r"[\"']?\s*[:=]",
        r"(?i)\b(?:pat|svc)_[0-9A-Za-z_-]{16,}\b",
    )
    if any(re.search(pattern, encoded) for pattern in patterns):
        raise UpgradeRehearsalError("PUBLIC_EVIDENCE_SECRET", "sanitized evidence contains secret-shaped material")


def _probe_image_alias(
        tag: str,
        runner: PrivateCommandRunner,
        label: str) -> tuple[str, dict[str, Any] | None]:
    """Return PRESENT, ABSENT, or ERROR without treating daemon errors as absence."""
    inspected = runner.run(
        ["docker", "image", "inspect", tag],
        label=f"{label}-inspect",
        check=False,
        timeout=30,
    )
    if inspected.returncode == 0:
        try:
            documents = json.loads(inspected.stdout)
        except json.JSONDecodeError:
            return "ERROR", None
        if len(documents) != 1 or not isinstance(documents[0], dict):
            return "ERROR", None
        return "PRESENT", documents[0]

    listed = runner.run(
        [
            "docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
            "--filter", f"reference={tag}",
        ],
        label=f"{label}-absence-proof",
        check=False,
        timeout=30,
    )
    if listed.returncode != 0:
        return "ERROR", None
    try:
        decoded = listed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "ERROR", None
    references = {line.strip() for line in decoded.splitlines() if line.strip()}
    return ("ERROR", None) if tag in references else ("ABSENT", None)


def _cleanup_owned_resources(runtime: RuntimeContext, runner: PrivateCommandRunner) -> dict[str, Any]:
    removed = {
        "containers": 0, "volumes": 0, "networks": 0,
        "imageTags": 0, "images": 0,
    }
    if not runtime.resource_cleanup_authorized:
        if not runtime.resource_mutation_started:
            return {
                "status": "PASS",
                "exactOwnershipVerified": True,
                "removed": removed,
                "residual": {
                    "containers": False, "volumes": False, "networks": False,
                    "imageTags": False, "images": False,
                },
                "failureCodes": [],
            }
        return {
            "status": "FAIL",
            "exactOwnershipVerified": False,
            "removed": removed,
            "residual": {
                "containers": False, "volumes": False, "networks": False,
                "imageTags": False, "images": False,
            },
            "failureCodes": ["RESOURCE_CLEANUP_NOT_AUTHORIZED"],
        }
    failures: list[str] = []
    ownership_filter = f"label={LABEL_RUN}={runtime.names.run_id}"
    project_filter = f"label=com.docker.compose.project={runtime.names.compose_project}"

    def listed(command: list[str], label: str) -> list[str]:
        result = runner.run(command, label=label, check=False, timeout=60)
        if result.returncode != 0:
            failures.append(label)
            return []
        return [line.strip() for line in result.stdout.decode("ascii", errors="ignore").splitlines() if line.strip()]

    def candidates(noun: str, base: list[str]) -> list[str]:
        values: set[str] = set()
        for scope, filter_value in (("run", ownership_filter), ("project", project_filter)):
            values.update(listed(
                [*base, "--filter", filter_value],
                f"cleanup-list-{scope}-{noun}s",
            ))
        return sorted(values)

    containers = candidates("container", ["docker", "container", "ls", "--all", "--quiet"])
    for identifier in containers:
        inspected = runner.run(
            ["docker", "container", "inspect", identifier],
            label="cleanup-inspect-container", check=False, timeout=30,
        )
        try:
            payload = json.loads(inspected.stdout)[0]
            labels = payload["Config"]["Labels"] or {}
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            failures.append("container-inspection")
            continue
        if (
            labels.get(LABEL_OWNER) != OWNER_VALUE
            or labels.get(LABEL_RUN) != runtime.names.run_id
            or labels.get("com.docker.compose.project") != runtime.names.compose_project
            or labels.get(LABEL_ROLE) != labels.get("com.docker.compose.service")
        ):
            failures.append("container-ownership")
            continue
        result = runner.run(
            ["docker", "container", "rm", "--force", identifier],
            label="cleanup-remove-container", check=False, timeout=60,
        )
        if result.returncode == 0:
            removed["containers"] += 1
        else:
            failures.append("container-removal")

    for noun, list_command, inspect_command, remove_command in (
        ("volume", ["docker", "volume", "ls", "--quiet"],
         ["docker", "volume", "inspect"], ["docker", "volume", "rm"]),
        ("network", ["docker", "network", "ls", "--quiet"],
         ["docker", "network", "inspect"], ["docker", "network", "rm"]),
    ):
        for name in candidates(noun, list_command):
            inspected = runner.run(
                [*inspect_command, name], label=f"cleanup-inspect-{noun}", check=False, timeout=30
            )
            try:
                payload = json.loads(inspected.stdout)[0]
                labels = payload.get("Labels") or {}
            except (json.JSONDecodeError, IndexError, TypeError):
                failures.append(f"{noun}-inspection")
                continue
            expected_roles = (
                {"mysql-data", "redis-data"}
                if noun == "volume"
                else {"app-network", "data-network"}
            )
            if (
                labels.get(LABEL_OWNER) != OWNER_VALUE
                or labels.get(LABEL_RUN) != runtime.names.run_id
                or labels.get("com.docker.compose.project") != runtime.names.compose_project
                or labels.get(LABEL_ROLE) not in expected_roles
            ):
                failures.append(f"{noun}-ownership")
                continue
            result = runner.run(
                [*remove_command, name], label=f"cleanup-remove-{noun}", check=False, timeout=60
            )
            if result.returncode == 0:
                removed[noun + "s"] += 1
            else:
                failures.append(f"{noun}-removal")

    intended_tags = dict(runtime.created_image_tags)
    intended_tags.update(runtime.intended_image_tags)
    for role, tag in tuple(intended_tags.items()):
        probe, payload = _probe_image_alias(tag, runner, f"cleanup-image-{role}")
        if probe == "ABSENT":
            continue
        if probe != "PRESENT" or payload is None:
            failures.append("image-inspection")
            continue
        try:
            actual_id = payload["Id"]
            labels = payload.get("Config", {}).get("Labels") or {}
        except (KeyError, TypeError):
            failures.append("image-inspection")
            continue
        expected_id = runtime.resolved_images.get(role)
        if not tag.startswith(f"web-starter-upgrade-{runtime.names.run_id}-"):
            failures.append("image-alias-ownership")
            continue
        if role not in BUILT_IMAGE_ROLES and role not in INPUT_IMAGE_ROLES:
            failures.append("image-alias-ownership")
            continue
        if role in INPUT_IMAGE_ROLES and (expected_id is None or actual_id != expected_id):
            failures.append("image-alias-ownership")
            continue
        if role in BUILT_IMAGE_ROLES and expected_id is not None and actual_id != expected_id:
            failures.append("image-alias-ownership")
            continue
        original_reference = runtime.input_image_references.get(role)
        if original_reference is not None:
            try:
                original_id = _inspect_image(
                    original_reference, runner, f"cleanup-original-{role}-before"
                )
            except UpgradeRehearsalError:
                failures.append("original-image-reference-before")
                continue
            if original_id != expected_id:
                failures.append("original-image-reference-before")
                continue
        if role in BUILT_IMAGE_ROLES:
            if (
                labels.get(LABEL_OWNER) != OWNER_VALUE
                or labels.get(LABEL_RUN) != runtime.names.run_id
                or labels.get(LABEL_ROLE) != role
                or (expected_id is not None and actual_id != expected_id)
            ):
                failures.append("built-image-labels")
                continue
        result = runner.run(
            ["docker", "image", "rm", tag], label=f"cleanup-remove-image-{role}", check=False, timeout=60
        )
        if result.returncode == 0:
            removed["imageTags"] += 1
            removed_probe, _ = _probe_image_alias(
                tag, runner, f"cleanup-confirm-image-alias-removed-{role}"
            )
            if removed_probe == "PRESENT":
                failures.append("image-tag-residual")
            elif removed_probe == "ERROR":
                failures.append("image-tag-removal-unverified")
            if original_reference is not None:
                try:
                    surviving_id = _inspect_image(
                        original_reference, runner, f"cleanup-original-{role}-after"
                    )
                except UpgradeRehearsalError:
                    failures.append("original-image-reference-after")
                    continue
                if surviving_id != expected_id:
                    failures.append("original-image-reference-after")
        else:
            failures.append("image-tag-removal")

    residual_image_tags = False
    for role, tag in tuple(intended_tags.items()):
        probe, _ = _probe_image_alias(tag, runner, f"cleanup-residual-image-{role}")
        if probe == "PRESENT":
            residual_image_tags = True
        elif probe == "ERROR":
            residual_image_tags = True
            failures.append("residual-image-inspection")

    intended_values = set(intended_tags.values())
    run_image_ids = listed(
        [
            "docker", "image", "ls", "--all", "--quiet", "--no-trunc",
            "--filter", ownership_filter,
        ],
        "cleanup-list-run-images",
    )
    for image_id in sorted(set(run_image_ids)):
        inspected = runner.run(
            ["docker", "image", "inspect", image_id],
            label="cleanup-inspect-run-image",
            check=False,
            timeout=30,
        )
        if inspected.returncode != 0:
            failures.append("run-image-inspection")
            continue
        try:
            payload = json.loads(inspected.stdout)[0]
            actual_id = payload["Id"]
            labels = payload.get("Config", {}).get("Labels") or {}
            repo_tags = payload.get("RepoTags") or []
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            failures.append("run-image-inspection")
            continue
        if (
            actual_id != image_id
            or labels.get(LABEL_OWNER) != OWNER_VALUE
            or labels.get(LABEL_RUN) != runtime.names.run_id
            or labels.get(LABEL_ROLE) not in set(BUILT_IMAGE_ROLES)
            or not isinstance(repo_tags, list)
            or any(not isinstance(tag, str) or tag not in intended_values for tag in repo_tags)
        ):
            failures.append("run-image-ownership")
            continue
        removed_image = runner.run(
            ["docker", "image", "rm", image_id],
            label="cleanup-remove-run-image",
            check=False,
            timeout=60,
        )
        if removed_image.returncode == 0:
            removed["images"] += 1
        else:
            failures.append("run-image-removal")

    residual_run_images = listed(
        [
            "docker", "image", "ls", "--all", "--quiet", "--no-trunc",
            "--filter", ownership_filter,
        ],
        "cleanup-residual-run-images",
    )
    residual = {
        "containers": bool(candidates(
            "residual-container", ["docker", "container", "ls", "--all", "--quiet"]
        )),
        "volumes": bool(candidates(
            "residual-volume", ["docker", "volume", "ls", "--quiet"]
        )),
        "networks": bool(candidates(
            "residual-network", ["docker", "network", "ls", "--quiet"]
        )),
        "imageTags": residual_image_tags,
        "images": bool(residual_run_images),
    }
    status = "PASS" if not failures and not any(residual.values()) else "FAIL"
    return {
        "status": status,
        "exactOwnershipVerified": not failures,
        "removed": removed,
        "residual": residual,
        "failureCodes": sorted(set(failures)),
    }


def _remove_owned_private_tree(
        root: Path,
        sentinel_name: str,
        expected_owner: Mapping[str, str]) -> bool:
    if root.is_symlink() or not root.is_dir() or _inside(root.resolve(), REPOSITORY_ROOT.resolve()):
        return False
    sentinel = root / sentinel_name
    try:
        owner = json.loads(sentinel.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if owner != dict(expected_owner):
        return False
    try:
        shutil.rmtree(root)
    except OSError:
        return False
    return not root.exists()


def _remove_private_runtime(runtime: RuntimeContext) -> bool:
    expected_owner = {"owner": OWNER_VALUE, "runId": runtime.names.run_id}
    playwright_removed = (
        runtime.playwright_temp_root is None
        or _remove_owned_private_tree(
            runtime.playwright_temp_root,
            ".web-starter-playwright-owner.json",
            expected_owner,
        )
    )
    runtime_removed = _remove_owned_private_tree(
        runtime.runtime_root,
        ".web-starter-upgrade-owner.json",
        expected_owner,
    )
    return playwright_removed and runtime_removed


def _write_result(runtime: RuntimeContext, runner_logs: Mapping[str, Any]) -> int:
    status = overall_status(runtime.state.checks, runtime.state.phases)
    exit_code = process_exit_code(status)
    private_runtime_persisted = not bool(runtime.cleanup_summary.get("privateRuntimeRemoved"))
    document = {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-40",
        "status": status,
        "processExitCode": exit_code,
        "generatedAt": utc_now(),
        "source": {
            "v1Tag": V1_TAG,
            "v1Commit": V1_COMMIT,
            "toolPath": "scripts/rehearse_v1_to_v2_upgrade.py",
            "toolSha256": runtime.frozen_tool_sha256,
            "schemaPath": "security/v2-v1-upgrade-rehearsal.schema.json",
            "schemaSha256": runtime.frozen_schema_sha256,
            "v2Commit": runtime.v2_commit,
            "v2Tree": runtime.v2_tree,
            "cleanWorktree": runtime.clean_worktree,
            "currentAdapterSnapshotSha256": dict(sorted(runtime.helper_hashes.items())),
            "runtimeSourceSha256": dict(sorted(runtime.runtime_source_hashes.items())),
            "inputImageReferences": {
                role: runtime.input_image_references[role]
                for role in INPUT_IMAGE_ROLES if role in runtime.input_image_references
            },
            "resolvedImageIds": {
                role: runtime.resolved_images[role]
                for role in RESOLVED_IMAGE_ROLES if role in runtime.resolved_images
            },
            "builtV1ImageIds": {
                role: runtime.created_image_ids[role]
                for role in ("v1-app", "v1-nginx") if role in runtime.created_image_ids
            },
            "builtV2ImageIds": {
                role: runtime.created_image_ids[role]
                for role in CANDIDATE_IMAGE_ROLES if role in runtime.created_image_ids
            },
            "dependencySeed": runtime.dependency_seed_evidence,
        },
        "run": {
            "runId": runtime.names.run_id,
            "composeProject": runtime.names.compose_project,
            "sourceDatabase": runtime.names.source_database,
            "targetDatabase": runtime.names.target_database,
            "publishedPortCount": 3,
            "loopbackOnly": True,
            "containerImageIds": {
                version: dict(sorted(images.items()))
                for version, images in sorted(runtime.started_container_images.items())
            },
        },
        "phases": [
            {
                "name": phase.name,
                "status": phase.status,
                "startedAt": phase.started_at,
                "finishedAt": phase.finished_at,
                "detailCode": phase.detail_code,
            }
            for phase in runtime.state.phases.values()
        ],
        "checks": runtime.state.checks,
        "acceptance": aggregate_acceptance(runtime.state.checks, runtime.state.phases),
        "observations": runtime.sanitized_observations,
        "privateCommandLogs": {
            "persisted": private_runtime_persisted,
            "count": len(runner_logs),
            "aggregateSha256": sha256_bytes(json.dumps(runner_logs, sort_keys=True).encode("utf-8")),
        },
        "cleanup": runtime.cleanup_summary,
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
            "containsSecrets": False,
            "privateRuntimePersisted": private_runtime_persisted,
        },
    }
    _secret_scan_public_document(document)
    if runtime.evidence_validator is None:
        if status == "PASS":
            raise UpgradeRehearsalError(
                "EVIDENCE_VALIDATOR_MISSING", "PASS evidence requires the frozen independent validator"
            )
    else:
        try:
            runtime.evidence_validator(document)
        except Exception as exception:
            raise UpgradeRehearsalError(
                "EVIDENCE_SEMANTIC_INVALID", "independent evidence validation failed"
            ) from exception
    result = runtime.output_directory / RESULT_NAME
    write_private_json(result, document)
    write_private(
        runtime.output_directory / CHECKSUM_NAME,
        f"{sha256_file(result)}  {RESULT_NAME}\n".encode("ascii"),
    )
    return exit_code


def _mark_many(state: EvidenceState, names: Iterable[str], status: str, detail: str) -> None:
    for name in names:
        state.mark(name, status, detail)


def execute_rehearsal(args: argparse.Namespace) -> int:
    dependency_seed = validate_dependency_seed(
        args.dependency_seed,
        expected_aggregate_sha256=args.expected_dependency_seed_sha256,
    )
    output = ensure_external_empty_private_directory(args.output_dir)
    run_id = secrets.token_hex(6)
    names = generate_resource_names(run_id)
    allocated = allocate_unique_loopback_ports()
    ports = Ports(*allocated)
    runtime_root = _private_temp_root(run_id)
    state = EvidenceState()
    runtime = RuntimeContext(output, runtime_root, names, ports, state)
    logs = runtime_root / "logs"
    logs.mkdir(mode=0o700)
    runner = PrivateCommandRunner(logs)
    frozen: Path | None = None
    current_source: Path | None = None
    v1_source: Path | None = None
    keys: dict[str, Any] = {}
    tls: dict[str, Path] = {}
    credential_root = runtime_root / "credentials"
    service_fixture: dict[str, str] = {}
    v1_manifest: dict[str, Any] = {}
    v1_profile: dict[str, Any] = {}
    pkce_api: _AdminApi | None = None
    pkce_tokens: OAuthTokenSet | None = None
    pkce_token_file: Path | None = None
    pkce_parameters: dict[str, Any] = {}
    pkce_authorization_id: str | None = None

    try:
        state.start_phase("source-freeze")
        _copy_dependency_seed(dependency_seed, runtime)
        _check_required_commands()
        git = _git_runner(runner)
        validate_v1_identity(git)
        state.mark("source.annotatedV1Tag", "PASS", "ANNOTATED_TAG_VERIFIED")
        state.mark("source.fixedV1Commit", "PASS", "FIXED_COMMIT_VERIFIED")
        validate_v1_tag_adapter_boundary(git)
        state.mark("source.v1TagAdapterBoundary", "PASS", "V1_TAG_HAS_NO_RUNTIME_ADAPTERS")
        migration_hashes = validate_v1_migration_bytes(git)
        state.mark("source.v1MigrationBytes", "PASS", "V1_MIGRATIONS_BYTE_EQUAL")
        validate_v2_source_identity(git, runtime)
        v1_source = _extract_v1_source(runtime, runner)
        frozen = _snapshot_current_adapters(runtime, git)
        current_source = _snapshot_current_runtime_sources(runtime, git)
        _extract_v2_sdk_source(runtime, runner)
        _freeze_contract_and_load_validator(runtime, git, frozen)
        assert_runtime_sources_unchanged(runtime)
        assert_sdk_source_unchanged(runtime)
        assert_version_specific_ingress_sources(v1_source, current_source)
        state.finish_phase("source-freeze", "PASS", "SOURCE_AND_TOOLS_FROZEN")

        state.start_phase("cryptographic-preflight")
        keys = _generate_rsa_material(runtime, runner)
        tls = _generate_tls_material(runtime, runner)
        _validate_frozen_helpers(frozen, runner)
        state.mark("preflight.requiredCommands", "PASS", "COMMANDS_AVAILABLE")
        state.mark("preflight.frozenScriptImports", "PASS", "EXPLICIT_PATH_IMPORTS_PASS")
        state.mark("keys.v1Pkcs8Der", "PASS", "PKCS8_GENERATE_DECODE_ROUNDTRIP")
        jwk_set = _create_jwk_set(runtime, runner, frozen, keys)
        state.finish_phase("cryptographic-preflight", "PASS", "PORTABLE_KEY_PREFLIGHT_PASS")

        state.start_phase("runtime-preflight")
        _assert_project_unused(runtime, runner)
        state.mark("preflight.composeProjectIsolation", "PASS", "PROJECT_AND_RUN_LABEL_SETS_EMPTY")
        assert_loopback_ports_unused(ports.values())
        state.mark("preflight.publishedPorts", "PASS", "PORTS_UNUSED_AND_UNIQUE")
        if names.source_database == "web_starter" or names.target_database == names.source_database:
            raise UpgradeRehearsalError("DATABASE_ISOLATION", "rehearsal databases are not isolated")
        state.mark("preflight.databaseIsolation", "PASS", "RANDOM_NEW_DATABASE_NAMES")
        for label, reference in (
            ("mysql", args.mysql_image),
            ("redis", args.redis_image),
        ):
            image_id, labels = _inspect_image_metadata(reference, runner, label)
            runtime.input_image_references[label] = reference
            alias = f"web-starter-upgrade-{run_id}-{label}:candidate"
            _tag_image_alias(image_id, alias, runtime, runner, label)
        _build_v2_images(runtime, runner)
        _build_v1_images(runtime, runner, v1_source)
        runtime.environment = _runtime_environment(runtime, keys, jwk_set, tls)
        runtime.environment.update(_production_image_environment(runtime))
        _write_environment_file(runtime_root / "runtime.env", runtime.environment)
        _write_compose_overlays(runtime, v1_source, current_source, keys, tls)
        _run_compose_preflight(runtime, runner, v2=False)
        _run_compose_preflight(runtime, runner, v2=True)
        state.mark("preflight.composeConfiguration", "PASS", "V1_V2_CONFIG_EXACT_SET")
        state.finish_phase("runtime-preflight", "PASS", "FORMAL_PREFLIGHT_PASS")

        if args.preflight_only:
            # This is intentionally incomplete.  A successful preflight is not
            # an upgrade result and therefore exits 6 after owned cleanup.
            raise UpgradeRehearsalError(
                "PREFLIGHT_ONLY_COMPLETE", "preflight-only mode does not execute acceptance"
            )

        state.start_phase("v1-fixtures")
        assert_loopback_ports_unused(ports.values())
        runner.run(
            _compose_command(runtime, runtime.compose_files_v1, "up", "--detach", "--wait", "--wait-timeout", "300", "--no-build", "--pull", "never"),
            label="start-v1-stack",
            environment=_compose_env(runtime, v2=False),
            replace_environment=True,
            timeout=420,
        )
        _verify_started_container_images(runtime, runner, v2=False)
        _wait_for_http_status(
            f"http://127.0.0.1:{ports.private_http}/actuator/health/readiness", 200,
        )
        _wait_for_http_status(
            (
                f"https://{runtime.names.public_hostname}:{ports.public_https}"
                "/.well-known/oauth-authorization-server"
            ),
            200,
            insecure=True,
            aliases={runtime.names.public_hostname: "127.0.0.1"},
        )
        fixture_environment = frozen_python_environment(frozen, _prepare_fixture_environment(runtime, keys))
        runner.run(
            frozen_python_command(
                frozen,
                "scripts/prepare_release_runtime_acceptance.py",
                "--repository-root", str(REPOSITORY_ROOT),
                "--output-directory", str(credential_root),
            ),
            label="prepare-v1-fixtures-explicit-path",
            environment=fixture_environment,
            replace_environment=True,
            timeout=180,
        )
        pkce_api = _AdminApi(runtime)
        pkce_api.login()
        service_fixture = _extend_v1_service_fixture(runtime, credential_root, pkce_api)
        v1_manifest = json.loads((credential_root / "manifest.json").read_text(encoding="utf-8"))
        pkce_tokens, pkce_token_file, pkce_parameters = _capture_v1_pkce_tokens(
            runtime,
            pkce_api,
            v1_manifest,
            credential_root,
            str(keys["v1Kid"]),
        )
        pkce_authorization_id = _validate_refresh_storage_before_upgrade(
            runtime, runner, pkce_tokens.refresh_token
        )
        _run_sdk_test(
            runtime,
            runner,
            tls,
            v1_manifest,
            pkce_token_file,
            "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
            public=True,
            trace_prefix=f"upgrade-pkce-v1-{run_id}",
            audit_trace_filter_supported=False,
        )
        state.mark("keys.v1KidCaptured", "PASS", "V1_KID_FROM_ISSUED_JWT")
        tables = _table_inventory(runtime, runner, names.source_database)
        counts = _row_counts(runtime, runner, names.source_database, tables)
        profile = _projection_profile(runtime, runner, names.source_database, tables)
        projections = _projection_hashes(runtime, runner, names.source_database, profile)
        v1_profile = {"tables": tables, "counts": counts, "profile": profile, "projections": projections}
        assert_flyway_history(
            _flyway_history(runtime, runner, names.source_database),
            {relative: v1_source / relative for relative in V1_MIGRATIONS},
            V1_MIGRATIONS,
        )
        state.finish_phase("v1-fixtures", "PASS", "V1_FIXTURES_AND_PROJECTION_CAPTURED")

        state.start_phase("backup-restore")
        runner.run(
            _compose_command(runtime, runtime.compose_files_v1, "stop", "app", "nginx", "mcp-public-nginx"),
            label="stop-v1-writers",
            environment=_compose_env(runtime, v2=False),
            replace_environment=True,
            timeout=180,
        )
        backup_parent = runtime_root / "backup"
        backup_parent.mkdir(mode=0o700)
        backup_arguments: list[str] = [
            "--compose-project", names.compose_project,
            "--expected-database", names.source_database,
            "--release-version", "1.0.0",
            "--output-dir", str(backup_parent),
            "--confirm-no-external-writers",
        ]
        for compose_file in runtime.compose_files_v1:
            backup_arguments.extend(("--compose-file", str(compose_file)))
        backup_result = runner.run(
            frozen_python_command(frozen, "scripts/recovery_backup.py", *backup_arguments),
            label="create-v1-backup",
            environment=frozen_python_environment(frozen, _compose_env(runtime, v2=False)),
            replace_environment=True,
            timeout=600,
        )
        backup_document = _parse_json_bytes(backup_result.stdout, "backup tool")
        package = Path(str(backup_document.get("package", ""))).resolve()
        if package.parent != backup_parent.resolve() or package.is_symlink() or not package.is_dir():
            raise UpgradeRehearsalError("BACKUP_PACKAGE", "backup tool returned an unsafe package path")
        state.mark("backup.consistentPackage", "PASS", "NO_WRITER_BACKUP_VERIFIED")
        restore_report = runtime_root / "restore-report.json"
        restore_override = runtime_root / "restore-override.yaml"
        restore_arguments: list[str] = [
            "--package", str(package),
            "--compose-project", names.compose_project,
            "--confirm-project", names.compose_project,
            "--target-database", names.target_database,
            "--report-file", str(restore_report),
            "--runtime-override-file", str(restore_override),
        ]
        for compose_file in runtime.compose_files_v1:
            restore_arguments.extend(("--compose-file", str(compose_file)))
        runner.run(
            frozen_python_command(frozen, "scripts/recovery_restore.py", *restore_arguments),
            label="restore-v1-backup",
            environment=frozen_python_environment(frozen, _compose_env(runtime, v2=False)),
            replace_environment=True,
            timeout=600,
        )
        restore_document = json.loads(restore_report.read_text(encoding="utf-8"))
        if (
            restore_document.get("status") != "RESTORED_DATABASE_VERIFIED"
            or restore_document.get("sourceDatabase") != names.source_database
            or restore_document.get("targetDatabase") != names.target_database
            or restore_document.get("flywayHistory") != "MATCH"
        ):
            raise UpgradeRehearsalError("RESTORE_REPORT", "restore report did not prove the new database")
        state.mark("restore.newDatabaseVerified", "PASS", "NEW_DATABASE_RESTORE_VERIFIED")
        state.finish_phase("backup-restore", "PASS", "BACKUP_AND_RESTORE_PASS")

        state.start_phase("v2-migration")
        runner.run(
            _compose_command(runtime, runtime.compose_files_v2, "up", "--detach", "--wait", "--wait-timeout", "300", "--no-build", "--pull", "never"),
            label="start-v2-upgrade-stack",
            environment=_compose_env(runtime, v2=True),
            replace_environment=True,
            timeout=420,
        )
        _verify_started_container_images(runtime, runner, v2=True)
        flyway_history = assert_flyway_history(
            _flyway_history(runtime, runner, names.target_database),
            {
                **{relative: v1_source / relative for relative in V1_MIGRATIONS},
                **{relative: current_source / relative for relative in V2_ONLY_MIGRATIONS},
            },
            V2_MIGRATIONS,
        )
        state.mark("migration.flywayOneThroughSeven", "PASS", "FLYWAY_EXACT_1_TO_7")
        v2_tables = _table_inventory(runtime, runner, names.target_database)
        v2_counts = _row_counts(runtime, runner, names.target_database, v1_profile["tables"])
        v2_projections = _projection_hashes(
            runtime, runner, names.target_database, v1_profile["profile"]
        )
        _assert_v1_projection_preserved(
            v1_profile["projections"],
            v2_projections,
            v1_profile["counts"],
            v2_counts,
        )
        state.mark("migration.v1RowsPreserved", "PASS", "V1_ROW_DIGESTS_PRESERVED")
        state.mark(
            "migration.v1ProjectionPreserved",
            "PASS",
            "V1_ALL_COLUMNS_EXACT_OR_AUDIT_APPEND_ONLY",
        )
        runtime.sanitized_observations.update({
            "v1MigrationSha256": migration_hashes,
            "v1TableCount": len(v1_profile["tables"]),
            "v2TableCount": len(v2_tables),
            "v1ProjectionCount": len(v1_profile["projections"]),
            "flywayVersions": [1, 2, 3, 4, 5, 6, 7],
            "flywayHistory": flyway_history,
            "credentialTypesCapturedBeforeUpgrade": [
                "OAUTH_ACCESS_TOKEN", "OAUTH_CLIENT_SECRET", "OAUTH_REFRESH_TOKEN",
                "PERSONAL_ACCESS_TOKEN", "SERVICE_ACCOUNT_TOKEN",
            ],
        })
        state.finish_phase("v2-migration", "PASS", "MIGRATION_AND_DATA_PRESERVATION_PASS")

        state.start_phase("credential-compatibility")
        token_files = v1_manifest["tokenFiles"]
        manifest_v2_path, manifest_v2 = _swap_manifest_for_v2(runtime, credential_root, keys)
        if (
            pkce_api is None
            or pkce_tokens is None
            or pkce_token_file is None
            or pkce_authorization_id is None
            or not pkce_parameters
        ):
            raise UpgradeRehearsalError("PKCE_CONTEXT", "V1 PKCE context is incomplete")
        # The pre-upgrade PKCE user access token must remain the first V2
        # external credential call. Do not put client credentials, JWKS
        # verification, or browser setup before this refresh-rotation proof.
        _rotate_and_replay_v2_refresh(
            runtime,
            runner,
            _new_oauth_token_opener(),
            pkce_parameters,
            pkce_tokens,
            pkce_token_file,
            pkce_authorization_id,
            str(keys["v2Kid"]),
            tls,
            manifest_v2,
        )
        state.mark(
            "oauth.preUpgradeUserAuthorizationAccepted",
            "PASS",
            "OLD_PKCE_TOKEN_FIRST_EXTERNAL_CALL",
        )
        state.mark(
            "credential.preUpgradeRefreshRotationAccepted", "PASS", "V1_REFRESH_ROTATION_REUSE_PASS"
        )
        _run_sdk_test(
            runtime, runner, tls, manifest_v2, Path(token_files["oauthToken"]),
            "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
            public=True,
            trace_prefix=f"upgrade-old-oauth-{run_id}",
            expected_actor_type="SERVICE_ACCOUNT",
            expected_client_id_present=True,
        )
        state.mark(
            "compatibility.mcpReadAndDiscovery",
            "PASS",
            "OLD_OAUTH_MCP_DISCOVERY_PASS",
        )
        oauth_report = runtime_root / "oauth-upgrade-runtime.json"
        oauth_environment = frozen_python_environment(frozen, _prepare_fixture_environment(runtime, keys))
        runner.run(
            frozen_python_command(
                frozen,
                "scripts/verify_oauth_runtime.py",
                "--manifest", str(manifest_v2_path),
                "--output", str(oauth_report),
            ),
            label="verify-v2-oauth-with-v1-client",
            environment=oauth_environment,
            replace_environment=True,
            timeout=180,
        )
        oauth_document = json.loads(oauth_report.read_text(encoding="utf-8"))
        if oauth_document.get("status") != "PASS":
            raise UpgradeRehearsalError("OAUTH_REPORT", "OAuth upgrade verifier did not pass")
        _mark_many(state, (
            "oauth.oldKidPublicOnly", "oauth.newKidActiveSigning",
            "oauth.preUpgradeClientCredentialAccepted", "oauth.freshClientCredentials",
        ), "PASS", "MULTI_KEY_AND_OLD_CLIENT_PASS")
        _run_sdk_test(
            runtime, runner, tls, manifest_v2, Path(token_files["patRead"]),
            "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
            public=False,
            trace_prefix=f"upgrade-old-pat-read-{run_id}",
        )
        state.mark("credential.oldPatRead", "PASS", "V1_PAT_READ_AND_FORBIDDEN_PASS")
        _run_sdk_test(
            runtime, runner, tls, manifest_v2, Path(token_files["serviceToken"]),
            "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
            public=False,
            trace_prefix=f"upgrade-old-service-{run_id}",
        )
        state.mark("credential.preUpgradeServiceAccessAccepted", "PASS", "V1_SERVICE_TOKEN_PASS")
        state.finish_phase("credential-compatibility", "PASS", "OLD_AND_NEW_CREDENTIALS_PASS")

        state.start_phase("runtime-acceptance")
        crud_trace_prefix = f"upgrade-old-pat-crud-{run_id}"
        with _mcp_crud_transaction_fault(runtime, runner, crud_trace_prefix):
            _run_sdk_test(
                runtime, runner, tls, manifest_v2, Path(token_files["patCrud"]),
                "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT",
                public=False,
                trace_prefix=crud_trace_prefix,
            )
        state.mark("credential.oldPatCrud", "PASS", "V1_PAT_CRUD_PASS")
        state.mark("mcp.crudIdempotencyAudit", "PASS", "MCP_CRUD_REPLAY_CONFLICT_AUDIT_PASS")
        _run_playwright(runtime, runner, manifest_v2_path)
        _mark_many(state, (
            "compatibility.restProjectCrud", "authorization.permissionDenied",
            "browser.playwright",
        ), "PASS", "PLAYWRIGHT_REAL_BROWSER_PASS")
        state.mark(
            "audit.traceSearch", "PASS", "AUDIT_FILTER_CORRELATION_REDACTION_PASS"
        )
        state.finish_phase("runtime-acceptance", "PASS", "BROWSER_REST_MCP_ACCEPTANCE_PASS")

        state.start_phase("lifecycle-readback")
        _final_lifecycle_readback(runtime, credential_root, service_fixture, manifest_v2)
        assert_v2_source_identity_unchanged(runtime, git)
        state.mark("integrity.finalSource", "PASS", "FINAL_SOURCE_IDENTITY_VERIFIED")
        state.mark(
            "lifecycle.revokedPatRejectedAndReadBack", "PASS", "REVOKED_PAT_DATABASE_READBACK_PASS"
        )
        state.mark(
            "lifecycle.disabledServiceRejectedAndReadBack", "PASS", "DISABLED_SERVICE_401_AND_READBACK_PASS"
        )
        state.finish_phase("lifecycle-readback", "PASS", "FINAL_LIFECYCLE_READBACK_PASS")

    except UpgradeRehearsalError as exception:
        if exception.code != "PREFLIGHT_ONLY_COMPLETE":
            state.fail_current_phase(exception.code, environment=exception.environment)
    except Exception:  # fail closed without persisting exception text
        state.fail_current_phase("UNEXPECTED_FAILURE", environment=False)
    finally:
        # Cleanup is always the final state-machine phase.  If execution stopped
        # earlier, skipped phases remain NOT_COVERED and are closed explicitly.
        for name in PHASE_ORDER:
            phase = state.phases[name]
            if phase.started_at is None and name != "cleanup":
                phase.status = "NOT_COVERED"
                phase.detail_code = "STOPPED_BEFORE_PHASE"
        cleanup_phase = state.phases["cleanup"]
        if cleanup_phase.started_at is None:
            # Advance the state machine cursor only for the special always-run
            # cleanup path; no skipped phase is reported as executed.
            cleanup_phase.started_at = utc_now()
        try:
            runtime.cleanup_summary = _cleanup_owned_resources(runtime, runner)
        except Exception:
            runtime.cleanup_summary = {
                "status": "FAIL", "exactOwnershipVerified": False,
                "removed": {
                    "containers": 0, "volumes": 0, "networks": 0,
                    "imageTags": 0, "images": 0,
                },
                "residual": {
                    "containers": False, "volumes": False, "networks": False,
                    "imageTags": False, "images": False,
                },
                "failureCodes": ["CLEANUP_EXCEPTION"],
            }
        if runtime.cleanup_summary.get("status") == "PASS":
            try:
                state.mark("cleanup.exactOwnedResources", "PASS", "EXACT_OWNED_CLEANUP_PASS")
            except UpgradeRehearsalError:
                pass
            cleanup_phase.status = "PASS"
            cleanup_phase.detail_code = "EXACT_OWNED_CLEANUP_PASS"
        else:
            if state.checks["cleanup.exactOwnedResources"]["status"] == "NOT_COVERED":
                state.mark("cleanup.exactOwnedResources", "FAIL", "EXACT_OWNED_CLEANUP_FAILED")
            cleanup_phase.status = "FAIL"
            cleanup_phase.detail_code = "EXACT_OWNED_CLEANUP_FAILED"
        cleanup_phase.finished_at = utc_now()

        log_digests = dict(runner.log_digests)
        runtime_removed = _remove_private_runtime(runtime)
        runtime.cleanup_summary["privateRuntimeRemoved"] = runtime_removed
        if not runtime_removed:
            if state.checks["cleanup.exactOwnedResources"]["status"] == "PASS":
                state.checks["cleanup.exactOwnedResources"] = {
                    "status": "FAIL", "detailCode": "PRIVATE_RUNTIME_REMOVAL_FAILED"
                }
            cleanup_phase.status = "FAIL"
            cleanup_phase.detail_code = "EXACT_OWNED_CLEANUP_FAILED"
            failure_codes = runtime.cleanup_summary.setdefault("failureCodes", [])
            if isinstance(failure_codes, list):
                failure_codes.append("PRIVATE_RUNTIME_REMOVAL_FAILED")
                runtime.cleanup_summary["failureCodes"] = sorted(set(failure_codes))
            runtime.cleanup_summary["status"] = "FAIL"
        return _write_result(runtime, log_digests)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Run the isolated V1 tag to V2 upgrade/restore rehearsal. The command exits 0 only "
            "when every frozen check passes and exact cleanup succeeds."
        )
    )
    result.add_argument("--output-dir", required=True, type=Path)
    result.add_argument("--mysql-image", required=True)
    result.add_argument("--redis-image", required=True)
    result.add_argument(
        "--dependency-seed",
        required=True,
        type=Path,
        help=(
            "private 0700 dependency seed bound to the candidate; Maven, pnpm, and "
            "Playwright acceptance use only its verified private copy in offline mode"
        ),
    )
    result.add_argument(
        "--expected-dependency-seed-sha256",
        required=True,
        help=(
            "trusted canonical aggregate SHA-256 for the dependency seed; the producer "
            "recomputes and compares it before creating any runtime resources"
        ),
    )
    result.add_argument(
        "--preflight-only", action="store_true",
        help="run all command/key/image/config/isolation preflights, then clean up and exit 6",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        for label, value in (
            ("MySQL", args.mysql_image), ("Redis", args.redis_image),
        ):
            validate_image_reference(value, label)
        return execute_rehearsal(args)
    except UpgradeRehearsalError as error:
        print(f"ERROR {error.code}: {error}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
