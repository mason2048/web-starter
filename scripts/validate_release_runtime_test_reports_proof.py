#!/usr/bin/env python3
"""Validate candidate-bound browser and official MCP SDK runtime test reports.

The raw bundle is deliberately private.  This validator reads every file through
an ``O_NOFOLLOW`` directory descriptor, re-evaluates the report semantics, binds
the result to one clean annotated release candidate, and is the only component
allowed to emit the public ``releaseRuntimeTestReports`` PASS summary.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
from typing import Any, Mapping
import xml.etree.ElementTree as ET


EVIDENCE_TYPE = "releaseRuntimeTestReports"
PLAYWRIGHT_REPORT = "playwright-release-runtime.json"
PROOF_FILE = "release-runtime-test-reports-proof.json"
SUMMARY_FILE = "release-runtime-test-reports-summary.json"
SUMMARY_SCHEMA = "security/release-runtime-test-reports-summary.schema.json"
CSRF_ROUTE_MATRIX = "security/web-csrf-route-matrix.json"
CSRF_SECURITY_CONFIGURATION = (
    "web-starter-security/src/main/java/dev/webstarter/security/config/"
    "WebStarterSecurityConfiguration.java"
)
CSRF_CONTROLLER_SOURCES = (
    "web-starter-system/src/main/java/dev/webstarter/system/web/UserController.java",
    "web-starter-system/src/main/java/dev/webstarter/system/web/RoleController.java",
    "web-starter-system/src/main/java/dev/webstarter/system/web/PermissionController.java",
    "web-starter-system/src/main/java/dev/webstarter/system/web/MenuController.java",
    "web-starter-system/src/main/java/dev/webstarter/system/web/ConfigController.java",
    "web-starter-project/src/main/java/dev/webstarter/project/web/ProjectController.java",
    "web-starter-security/src/main/java/dev/webstarter/security/web/AuthController.java",
    "web-starter-security/src/main/java/dev/webstarter/security/web/AccountSecurityController.java",
    "web-starter-security/src/main/java/dev/webstarter/security/web/OAuthClientController.java",
    "web-starter-security/src/main/java/dev/webstarter/security/web/PersonalTokenController.java",
    "web-starter-security/src/main/java/dev/webstarter/security/web/ServiceAccountController.java",
)

PLAYWRIGHT_SPECS: Mapping[str, tuple[str, ...]] = {
    "web-starter-web/e2e/release-runtime.spec.ts": (
        "private Web UI performs Project CRUD, trace correlation and responsive rendering",
        "all frozen management pages expose usable primary browser controls",
        "management write domains persist complete operation audit records",
        "public OAuth authorization-code flow requires PKCE and yields a usable MCP token",
        "personal security manages real browser sessions and prevents self-elevation",
        "credential management filters lifecycle states without redisplaying secrets",
        "audit search filters login operation and MCP records with correlated redacted traces",
    ),
    "web-starter-web/e2e/frontend-quality-runtime.spec.ts": (
        "real login endpoint applies generic progressive protection without blocking another account",
        "query, pagination, loading, empty and validation states remain usable in a real browser",
        "401, 403, 404, 409, 429 and 500 states have stable browser behavior and trace IDs",
        "desktop, tablet and 390px layouts pass keyboard and basic accessibility checks",
    ),
    "web-starter-web/e2e/v1-management-runtime.spec.ts": (
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
PLAYWRIGHT_TEST_COUNT = sum(len(titles) for titles in PLAYWRIGHT_SPECS.values())

SUREFIRE_TESTS: Mapping[str, tuple[str, str]] = {
    "TEST-dev.webstarter.mcp.acceptance.McpSdkRuntimeIT.xml": (
        "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
        "initializesDiscoversReadsAndCallsThroughTheOfficialSdk",
    ),
    "TEST-dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT.xml": (
        "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
        "projectListWorksWhileProjectCreateIsDenied",
    ),
}

RAW_REPORT_FILES = frozenset({PLAYWRIGHT_REPORT, *SUREFIRE_TESTS})
RAW_BUNDLE_FILES = frozenset({*RAW_REPORT_FILES, PROOF_FILE})

SOURCE_PATHS = (
    "pom.xml",
    "web-starter-mcp/pom.xml",
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
    "web-starter-web/playwright.config.ts",
    *PLAYWRIGHT_SPECS.keys(),
    "web-starter-web/contracts/private-api.openapi.json",
    "web-starter-web/src/api/generated/privateApiContract.ts",
    "web-starter-web/scripts/check-private-api-contract.mjs",
    "web-starter-web/scripts/check-private-api-contract.spec.js",
    "web-starter-web/bundle-budget.json",
    "web-starter-web/scripts/check-bundle-budget.mjs",
    "web-starter-web/scripts/check-bundle-budget.spec.js",
    "web-starter-web/src/api/projects.ts",
    "web-starter-web/src/crud/useStandardCrudPage.ts",
    "web-starter-web/src/crud/useStandardCrudPage.spec.ts",
    "web-starter-web/src/views/ProjectsView.vue",
    "web-starter-web/src/navigation/manifest.ts",
    "web-starter-web/src/navigation/manifest.spec.ts",
    "web-starter-web/src/router/index.ts",
    "web-starter-web/src/components/SidebarNav.vue",
    "web-starter-web/src/components/BreadcrumbNav.vue",
    "web-starter-web/src/components/CommandSearch.vue",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/DeveloperCommands.java",
    CSRF_ROUTE_MATRIX,
    CSRF_SECURITY_CONFIGURATION,
    *CSRF_CONTROLLER_SOURCES,
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkProjectListRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpRuntimeToolExpectations.java",
    "scripts/create_release_runtime_test_reports_proof.py",
    "scripts/validate_release_runtime_test_reports_proof.py",
    SUMMARY_SCHEMA,
)

ROOT_POM = "pom.xml"
MCP_POM = "web-starter-mcp/pom.xml"
FRONTEND_PACKAGE = "web-starter-web/package.json"
VALIDATOR_SOURCE = "scripts/validate_release_runtime_test_reports_proof.py"

# These hashes are an explicit human-review boundary, not candidate-supplied
# claims. A behavioral test or its fixed runtime configuration may change only
# together with a reviewed update to this validator and its negative tests.
REVIEWED_BEHAVIOR_SHA256: Mapping[str, str] = {
    "web-starter-web/e2e/release-runtime.spec.ts":
        "8c47870a26a938c192b35abf41cfd7ec767e976065fb8f50b904270e54e85b9a",
    "web-starter-web/e2e/frontend-quality-runtime.spec.ts":
        "61279940b72fb07e8549d21c4575c12539c525deeb3360b7fdc8849db3a92bb7",
    "web-starter-web/e2e/v1-management-runtime.spec.ts":
        "0721ce398f6c84a0731e527d1ac8c09414a6cdf3853a5c2717275461f3b659c5",
    "web-starter-web/playwright.config.ts":
        "6cf4fdd23e340de7ef221377474d41517d13e2c8d4468b95812e630aae63021b",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java":
        "c705bb7c6123ab9c56a0ad0f69e8a960081a67f9fcfe09171ed65258d7e63f1c",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkProjectListRuntimeIT.java":
        "1ce34785f2118f0a8931d2b08b639549a72bb6876cd7559f54cb4959f0492952",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpRuntimeToolExpectations.java":
        "0ecf834a8faa6f28871ddcd051c84ab21e65609545da154223d6793cf98919ed",
    CSRF_ROUTE_MATRIX:
        "1e32e00c2e52583331d16ff6dbdc50014f86f31845d34295d4e1467994bd07e4",
    CSRF_SECURITY_CONFIGURATION:
        "57e3f3481f1aa81219d2e000505f4ac3f37fead02a257fa3e001101c5c9649e4",
    "web-starter-web/contracts/private-api.openapi.json":
        "81e01a64bf3513c27488b8e9cc5548fbebfe3c0ed626d517c8e563f0e00fe8e3",
    "web-starter-web/src/api/generated/privateApiContract.ts":
        "abf870dc53503442f32db26ffc5c0569429d1f3f3a54bbe75e02b562ca96a946",
    "web-starter-web/scripts/check-private-api-contract.mjs":
        "e9c298601391d293994ca757ddd99c3642bd19609dc68231236ff4768b7ed29d",
    "web-starter-web/scripts/check-private-api-contract.spec.js":
        "2474db057c095775e4e7d9bcbaac4f8b78b9c40b4e1bbde645874b8949bfa8bc",
    "web-starter-web/bundle-budget.json":
        "810edea83238932302b31a2db42cfc084a3536960d421836de557b4e5b8d31ca",
    "web-starter-web/scripts/check-bundle-budget.mjs":
        "1a3cd077c14ea1b0507f96739b4d446c2d30320bffc575413790a327cc041a63",
    "web-starter-web/scripts/check-bundle-budget.spec.js":
        "f51ba20a9e4fa2c427529b2bdfc9b36c5072d10d78d58d77d02c5431209da844",
    "web-starter-web/src/api/projects.ts":
        "da790cdf6e99a4c7c9bfcd07cfa5af62d636ce7fd1ad09caeef39e6e7ce2af0a",
    "web-starter-web/src/crud/useStandardCrudPage.ts":
        "ff31f83c1780a10091f21af4f512c71f3f626666090ce89a56da555f54e19e49",
    "web-starter-web/src/crud/useStandardCrudPage.spec.ts":
        "6652279f9c9a64c353018a6a123350ab1480dd088fdf0686a5e7809ff2e1f3c7",
    "web-starter-web/src/views/ProjectsView.vue":
        "94316834400e120d513dcc42f1ad61d54790166bf6b173fcc8a1fb5f1e3845eb",
    "web-starter-web/src/navigation/manifest.ts":
        "98fe9ced97b2fcfbe4f1c7c1cfb04738db359e8a21c8847ee2d978d7839015cc",
    "web-starter-web/src/navigation/manifest.spec.ts":
        "ae3285d304d19085431d6efdbfc5fd7112a8e00a61e03fd896c78d3144a81c33",
    "web-starter-web/src/router/index.ts":
        "8984603ca20cda52902f58aacada413c75b789657210cf1d1975b65a31bf9c7e",
    "web-starter-web/src/components/SidebarNav.vue":
        "c2ee809c2c33514eca5c9d2ca6e21d95240ce466e387a68f22a41702381f992d",
    "web-starter-web/src/components/BreadcrumbNav.vue":
        "c85cc8efa3a1cc01c1014d3b336dc2002f7449b1451a29cdb0e9931167c484ae",
    "web-starter-web/src/components/CommandSearch.vue":
        "1160c467a1f3dbacc2da886493543dfbb61e8a60a0cd1d76fd1a1ffa905105cf",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/DeveloperCommands.java":
        "883940770ef13b1bd9ed3a08a136ecfe0d338bd65b0f722143adb4b2dcc690dc",
}

OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
TEST_DECLARATION = re.compile(r"(?m)^test\(\s*(['\"])(.*?)\1\s*,")
MAX_PROOF_BYTES = 128 * 1024
MAX_PLAYWRIGHT_BYTES = 8 * 1024 * 1024
MAX_SUREFIRE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_GIT_BYTES = 16 * 1024 * 1024
MAX_CLOCK_SKEW_NS = 5_000_000_000

FORBIDDEN_XML_ELEMENTS = {
    "failure",
    "error",
    "skipped",
    "flakyfailure",
    "flakyerror",
    "rerunfailure",
    "rerunerror",
}
SENSITIVE_FIELD = re.compile(
    r"(?i)^(?:authorization|cookie|password|passwd|privateKey|clientSecret|"
    r"accessToken|refreshToken|tokenValue|requestBody|responseBody)$"
)
SENSITIVE_VALUE = re.compile(
    r"(?i)(?:^Bearer\s+|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$)"
)


class RuntimeReportValidationError(RuntimeError):
    """Raised when the raw reports cannot support a canonical PASS."""


@dataclass(frozen=True)
class FileSnapshot:
    payload: bytes
    sha256: str
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    mode: int
    owner: int
    links: int


@dataclass(frozen=True)
class CandidateBinding:
    commit: str
    tree: str
    tag_object: str
    version: str
    source_sha256: Mapping[str, str]
    source_payloads: Mapping[str, bytes]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeReportValidationError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise RuntimeReportValidationError(f"JSON contains non-finite number: {value}")


def _parse_json(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise RuntimeReportValidationError(f"{label} is not UTF-8 JSON") from exception
    if text.startswith("\ufeff") or "\0" in text:
        raise RuntimeReportValidationError(f"{label} has a forbidden encoding marker")
    try:
        return json.loads(
            text,
            object_pairs_hook=_json_pairs,
            parse_constant=_reject_nonfinite,
        )
    except RuntimeReportValidationError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exception:
        raise RuntimeReportValidationError(f"{label} is not valid JSON") from exception


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _git(repository: Path, *arguments: str, limit: int = MAX_GIT_BYTES) -> bytes:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                str(repository),
                *arguments,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exception:
        raise RuntimeReportValidationError("Git is required for candidate binding") from exception
    if completed.returncode != 0:
        raise RuntimeReportValidationError("Git could not verify the release candidate")
    if len(completed.stdout) > limit or len(completed.stderr) > limit:
        raise RuntimeReportValidationError("Git candidate output is unexpectedly large")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise RuntimeReportValidationError("Git identity is not valid UTF-8") from exception
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise RuntimeReportValidationError("Git identity is malformed")
    return value


def _resolve_repository(configured: Path) -> Path:
    requested = configured.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise RuntimeReportValidationError("repository root must be a non-symlink directory")
    try:
        repository = requested.resolve(strict=True)
        top = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exception:
        raise RuntimeReportValidationError("repository root cannot be resolved") from exception
    if top != repository:
        raise RuntimeReportValidationError("repository root must be the exact Git top-level")
    return repository


def _require_clean_candidate(repository: Path) -> None:
    records = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if not records or any(len(record) < 3 or not record.startswith(b"H ") for record in records):
        raise RuntimeReportValidationError(
            "Git index contains hidden, skip-worktree, or non-cached entries"
        )
    if _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise RuntimeReportValidationError("release candidate worktree must be clean")


def _candidate_blob(repository: Path, commit: str, relative: str) -> bytes:
    entry = _git(repository, "ls-tree", "-z", commit, "--", relative)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise RuntimeReportValidationError(f"candidate must contain exactly one {relative}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or OBJECT_ID.fullmatch(fields[2].decode("ascii", errors="ignore")) is None
        or encoded_path != relative.encode("utf-8")
    ):
        raise RuntimeReportValidationError(f"candidate {relative} is not one regular Git blob")
    return _git(repository, "cat-file", "blob", f"{commit}:{relative}", limit=MAX_SOURCE_BYTES)


def _workspace_source(repository: Path, relative: str) -> bytes:
    target = repository.joinpath(*relative.split("/"))
    if target.is_symlink() or not target.is_file():
        raise RuntimeReportValidationError(f"candidate source is not a regular file: {relative}")
    resolved = target.resolve(strict=True)
    if not _inside(resolved, repository):
        raise RuntimeReportValidationError(f"candidate source escaped repository: {relative}")
    payload = resolved.read_bytes()
    if not payload or len(payload) > MAX_SOURCE_BYTES:
        raise RuntimeReportValidationError(f"candidate source size is invalid: {relative}")
    return payload


def _xml(payload: bytes, label: str) -> ET.Element:
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", payload, flags=re.IGNORECASE):
        raise RuntimeReportValidationError(f"{label} contains a forbidden XML declaration")
    try:
        return ET.fromstring(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ET.ParseError) as exception:
        raise RuntimeReportValidationError(f"{label} is not valid XML") from exception


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def _direct_text(root: ET.Element, name: str, label: str) -> str:
    matches = [child for child in list(root) if _local_name(child.tag) == name]
    if len(matches) != 1 or matches[0].text is None or not matches[0].text.strip():
        raise RuntimeReportValidationError(f"{label} must contain exactly one {name}")
    return matches[0].text.strip()


def _validate_versions(payloads: Mapping[str, bytes], expected_version: str) -> None:
    root = _xml(payloads[ROOT_POM], ROOT_POM)
    module = _xml(payloads[MCP_POM], MCP_POM)
    if _local_name(root.tag) != "project" or _local_name(module.tag) != "project":
        raise RuntimeReportValidationError("Maven sources must have project roots")
    root_version = _direct_text(root, "version", ROOT_POM)
    parents = [child for child in list(module) if _local_name(child.tag) == "parent"]
    if len(parents) != 1:
        raise RuntimeReportValidationError("MCP pom must have exactly one parent")
    module_version = _direct_text(parents[0], "version", "MCP parent")
    frontend = _parse_json(payloads[FRONTEND_PACKAGE], FRONTEND_PACKAGE)
    if not isinstance(frontend, dict) or not isinstance(frontend.get("version"), str):
        raise RuntimeReportValidationError("frontend package must contain one string version")
    versions = (root_version, module_version, frontend["version"], expected_version)
    if len(set(versions)) != 1 or any("SNAPSHOT" in value.upper() for value in versions):
        raise RuntimeReportValidationError(
            "root, MCP parent, frontend, and candidate versions must match and be non-SNAPSHOT"
        )


def _validate_fixed_test_sources(payloads: Mapping[str, bytes]) -> None:
    for relative, expected_sha256 in REVIEWED_BEHAVIOR_SHA256.items():
        if relative not in payloads or _sha256(payloads[relative]) != expected_sha256:
            raise RuntimeReportValidationError(
                f"reviewed runtime test behavior hash drifted: {relative}"
            )
    for relative, expected_titles in PLAYWRIGHT_SPECS.items():
        try:
            source = payloads[relative].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exception:
            raise RuntimeReportValidationError(f"{relative} is not UTF-8") from exception
        actual_titles = tuple(match.group(2) for match in TEST_DECLARATION.finditer(source))
        if actual_titles != expected_titles:
            raise RuntimeReportValidationError(f"fixed Playwright test inventory drifted: {relative}")
        if re.search(r"\btest\s*\.\s*(?:only|skip|fixme|fail)\s*\(", source):
            raise RuntimeReportValidationError(f"fixed Playwright source disables or alters tests: {relative}")

    java_sources = {
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java": (
            "McpSdkRuntimeIT",
            "initializesDiscoversReadsAndCallsThroughTheOfficialSdk",
        ),
        "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkProjectListRuntimeIT.java": (
            "McpSdkProjectListRuntimeIT",
            "projectListWorksWhileProjectCreateIsDenied",
        ),
    }
    for relative, (class_name, method) in java_sources.items():
        try:
            source = payloads[relative].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exception:
            raise RuntimeReportValidationError(f"{relative} is not UTF-8") from exception
        methods = re.findall(r"@Test\s+(?:public\s+|protected\s+|private\s+)?void\s+(\w+)\s*\(", source)
        if methods != [method] or re.search(rf"\bclass\s+{re.escape(class_name)}\b", source) is None:
            raise RuntimeReportValidationError(f"fixed Surefire test inventory drifted: {relative}")


def _csrf_probe_matches_template(template: str, probe: str) -> bool:
    template_segments = template.split("/")
    probe_segments = probe.split("/")
    if len(template_segments) != len(probe_segments):
        return False
    for expected, actual in zip(template_segments, probe_segments):
        if re.fullmatch(r"\{[A-Za-z][A-Za-z0-9]*\}", expected):
            if not actual or "{" in actual or "}" in actual:
                return False
        elif expected != actual:
            return False
    return True


def _validate_csrf_route_matrix(payloads: Mapping[str, bytes]) -> None:
    document = _parse_json(payloads[CSRF_ROUTE_MATRIX], CSRF_ROUTE_MATRIX)
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "routes"}:
        raise RuntimeReportValidationError("Web CSRF route matrix shape is invalid")
    if document.get("schemaVersion") != 1:
        raise RuntimeReportValidationError("Web CSRF route matrix version is invalid")
    routes = document.get("routes")
    if not isinstance(routes, list) or len(routes) != 36:
        raise RuntimeReportValidationError("Web CSRF route matrix must contain exactly 36 routes")

    actual: set[tuple[str, str]] = set()
    anonymous = 0
    for route in routes:
        if not isinstance(route, dict) or set(route) != {
            "method", "template", "probePath", "authentication", "bodyKind"
        }:
            raise RuntimeReportValidationError("Web CSRF route entry shape is invalid")
        method = route.get("method")
        template = route.get("template")
        probe = route.get("probePath")
        authentication = route.get("authentication")
        body_kind = route.get("bodyKind")
        if method not in {"POST", "PUT", "DELETE"}:
            raise RuntimeReportValidationError("Web CSRF route method is invalid")
        if (
            not isinstance(template, str)
            or not template.startswith("/api/")
            or not isinstance(probe, str)
            or not probe.startswith("/api/")
            or not _csrf_probe_matches_template(template, probe)
        ):
            raise RuntimeReportValidationError("Web CSRF route template/probe is invalid")
        if authentication not in {"ANONYMOUS", "ADMIN"}:
            raise RuntimeReportValidationError("Web CSRF route authentication is invalid")
        if body_kind not in {"NONE", "EMPTY_JSON", "LOGIN"}:
            raise RuntimeReportValidationError("Web CSRF route body kind is invalid")
        if authentication == "ANONYMOUS":
            anonymous += 1
            if (method, template, body_kind) != ("POST", "/api/auth/login", "LOGIN"):
                raise RuntimeReportValidationError("anonymous Web CSRF route is not the login route")
        elif body_kind == "LOGIN":
            raise RuntimeReportValidationError("authenticated Web CSRF route cannot use login body")
        if method == "DELETE" and body_kind != "NONE":
            raise RuntimeReportValidationError("DELETE Web CSRF probe must not carry a body")
        key = (method, template)
        if key in actual:
            raise RuntimeReportValidationError("Web CSRF route matrix contains a duplicate")
        actual.add(key)
    if anonymous != 1:
        raise RuntimeReportValidationError("Web CSRF route matrix must contain one anonymous login")

    discovered: set[tuple[str, str]] = set()
    mapping_pattern = re.compile(
        r'@(Post|Put|Delete)Mapping(?:\(\s*"([^"]*)"\s*\))?'
    )
    for relative in CSRF_CONTROLLER_SOURCES:
        try:
            source = payloads[relative].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exception:
            raise RuntimeReportValidationError(f"CSRF controller is not UTF-8: {relative}") from exception
        bases = re.findall(r'@RequestMapping\(\s*"([^"]+)"\s*\)', source)
        if len(bases) != 1 or not bases[0].startswith("/api/"):
            raise RuntimeReportValidationError(f"CSRF controller base mapping drifted: {relative}")
        base = bases[0].rstrip("/")
        mappings = mapping_pattern.findall(source)
        if not mappings:
            raise RuntimeReportValidationError(f"CSRF controller has no write mappings: {relative}")
        for annotation, suffix in mappings:
            method = {"Post": "POST", "Put": "PUT", "Delete": "DELETE"}[annotation]
            path = base if not suffix else base + "/" + suffix.lstrip("/")
            discovered.add((method, path))

    try:
        security_source = payloads[CSRF_SECURITY_CONFIGURATION].decode(
            "utf-8", errors="strict"
        )
    except UnicodeDecodeError as exception:
        raise RuntimeReportValidationError("Web security configuration is not UTF-8") from exception
    required_security_tokens = (
        'CookieCsrfTokenRepository.withHttpOnlyFalse()',
        'csrf.setCookieName("XSRF-TOKEN")',
        'csrf.setHeaderName("X-XSRF-TOKEN")',
        '.csrf(configurer -> configurer.csrfTokenRepository(csrf))',
        '.logoutUrl("/api/auth/logout")',
    )
    if any(token not in security_source for token in required_security_tokens):
        raise RuntimeReportValidationError("Web CSRF security configuration drifted")
    discovered.add(("POST", "/api/auth/logout"))
    if actual != discovered:
        raise RuntimeReportValidationError("Web CSRF route matrix does not cover every write mapping")


def _typescript_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _render_private_api_types(document: Mapping[str, Any], source: bytes) -> str:
    imports = document.get("x-web-starter-type-imports")
    paths = document.get("paths")
    if document.get("openapi") != "3.1.0" or not isinstance(imports, dict) or not isinstance(paths, dict):
        raise RuntimeReportValidationError("private API contract is not a typed OpenAPI 3.1 document")
    operations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for contract_path, path_item in paths.items():
        if not isinstance(contract_path, str) or not isinstance(path_item, dict):
            raise RuntimeReportValidationError("private API contract path inventory is malformed")
        for method in ("get", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise RuntimeReportValidationError("private API operation is malformed")
            operation_id = operation.get("operationId")
            request_type = operation.get("x-web-starter-request-type")
            response_type = operation.get("x-web-starter-response-type")
            if (
                not isinstance(operation_id, str) or operation_id in seen
                or not isinstance(request_type, str) or not isinstance(response_type, str)
            ):
                raise RuntimeReportValidationError("private API typed operation identity is incomplete")
            seen.add(operation_id)
            operations.append({
                "operationId": operation_id,
                "method": method.upper(),
                "path": contract_path,
                "csrf": operation.get("x-web-starter-csrf") is True,
                "requestType": request_type,
                "responseType": response_type,
            })
    expected_ids = {
        "project.list", "project.create", "project.owners", "project.get",
        "project.update", "project.remove",
    }
    if seen != expected_ids:
        raise RuntimeReportValidationError("private Project API operation inventory drifted")
    operations.sort(key=lambda item: item["operationId"])
    lines = [
        "/* This file is generated by scripts/check-private-api-contract.mjs. */",
        f"/* source-sha256: {_sha256(source)} */",
    ]
    for module_name in sorted(imports):
        names = imports[module_name]
        if not isinstance(module_name, str) or not isinstance(names, list) \
                or any(not isinstance(name, str) for name in names):
            raise RuntimeReportValidationError("private API type import inventory is malformed")
        lines.append(
            f"import type {{ {', '.join(sorted(names))} }} from {_typescript_quote(module_name)}"
        )
    lines.extend(("", "export interface PrivateApiOperationTypes {"))
    for operation in operations:
        lines.append(
            f"  {_typescript_quote(operation['operationId'])}: "
            f"{{ request: {operation['requestType']}; response: {operation['responseType']} }}"
        )
    lines.extend(("}", "", "export const PRIVATE_API_OPERATIONS = {"))
    for operation in operations:
        csrf = "true" if operation["csrf"] else "false"
        lines.append(
            f"  {_typescript_quote(operation['operationId'])}: "
            f"{{ method: {_typescript_quote(operation['method'])}, "
            f"path: {_typescript_quote(operation['path'])}, csrf: {csrf} }},"
        )
    lines.extend((
        "} as const", "",
        "export type PrivateApiOperationId = keyof PrivateApiOperationTypes",
        "export type PrivateApiRequest<K extends PrivateApiOperationId> = PrivateApiOperationTypes[K][\"request\"]",
        "export type PrivateApiResponse<K extends PrivateApiOperationId> = PrivateApiOperationTypes[K][\"response\"]",
        "",
    ))
    return "\n".join(lines)


def _utf8(payloads: Mapping[str, bytes], relative: str) -> str:
    try:
        return payloads[relative].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise RuntimeReportValidationError(f"frontend foundation source is not UTF-8: {relative}") from exception


def _validate_frontend_foundation_sources(payloads: Mapping[str, bytes]) -> None:
    package = _parse_json(payloads[FRONTEND_PACKAGE], FRONTEND_PACKAGE)
    scripts = package.get("scripts") if isinstance(package, dict) else None
    expected_scripts = {
        "build": "pnpm run contract:check && pnpm run typecheck && vite build && pnpm run bundle:check && pnpm run production:mount-check",
        "bundle:check": "node scripts/check-bundle-budget.mjs",
        "contract:check": "node scripts/check-private-api-contract.mjs",
        "production:mount-check": "node scripts/check-production-mount.mjs",
        "test": "vitest run",
    }
    if not isinstance(scripts, dict) or any(scripts.get(name) != value for name, value in expected_scripts.items()):
        raise RuntimeReportValidationError("frontend quality command chain drifted")

    contract_path = "web-starter-web/contracts/private-api.openapi.json"
    generated_path = "web-starter-web/src/api/generated/privateApiContract.ts"
    contract = _parse_json(payloads[contract_path], contract_path)
    if not isinstance(contract, dict):
        raise RuntimeReportValidationError("private API contract must be an object")
    if _utf8(payloads, generated_path) != _render_private_api_types(contract, payloads[contract_path]):
        raise RuntimeReportValidationError("generated TypeScript differs from the private API contract")

    budget_path = "web-starter-web/bundle-budget.json"
    budget = _parse_json(payloads[budget_path], budget_path)
    if budget != {
        "maxEntryJavaScriptBytes": 850000,
        "maxJavaScriptChunkBytes": 350000,
        "maxStylesheetBytes": 400000,
        "maxOtherAssetBytes": 500000,
        "maxTotalProductionBytes": 1800000,
    }:
        raise RuntimeReportValidationError("frontend bundle budget drifted or is incomplete")

    required_fragments = {
        "web-starter-web/src/api/projects.ts": (
            "PRIVATE_API_OPERATIONS", "PrivateApiRequest", "PrivateApiResponse",
        ),
        "web-starter-web/src/views/ProjectsView.vue": (
            "useStandardCrudPage", "const crudPage = useStandardCrudPage<Project>",
        ),
        "web-starter-web/src/navigation/manifest.ts": (
            "export const APP_NAVIGATION", "export const sidebarNavigation",
            "export const commandNavigation", "export function applicationRoutes",
            "export function findNavigationItem",
        ),
        "web-starter-web/src/router/index.ts": ("applicationRoutes",),
        "web-starter-web/src/components/SidebarNav.vue": ("sidebarNavigation",),
        "web-starter-web/src/components/BreadcrumbNav.vue": ("findNavigationItem",),
        "web-starter-web/src/components/CommandSearch.vue": ("commandNavigation",),
        "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/DeveloperCommands.java": (
            'step("lint", List.of("pnpm", "lint")',
            'step("typecheck", List.of("pnpm", "typecheck")',
            'step("unit-test", List.of("pnpm", "test")',
            'step("production-build", List.of("pnpm", "build")',
        ),
    }
    for relative, fragments in required_fragments.items():
        source = _utf8(payloads, relative)
        if any(fragment not in source for fragment in fragments):
            raise RuntimeReportValidationError(f"frontend foundation projection drifted: {relative}")


def _validate_summary_schema(payload: bytes) -> None:
    schema = _parse_json(payload, SUMMARY_SCHEMA)
    if not isinstance(schema, dict):
        raise RuntimeReportValidationError("summary schema must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise RuntimeReportValidationError("summary schema draft drifted")
    properties = schema.get("properties")
    required = schema.get("required")
    expected = {"schemaVersion", "evidenceType", "status", "candidate", "run", "coverage", "reports", "sources"}
    if not isinstance(properties, dict) or set(properties) != expected or set(required or []) != expected:
        raise RuntimeReportValidationError("summary schema top-level contract drifted")
    if properties.get("evidenceType", {}).get("const") != EVIDENCE_TYPE:
        raise RuntimeReportValidationError("summary schema evidence type drifted")
    if properties.get("status", {}).get("const") != "PASS":
        raise RuntimeReportValidationError("summary schema status contract drifted")


def _validate_candidate(
    repository: Path,
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
) -> CandidateBinding:
    if OBJECT_ID.fullmatch(expected_commit) is None:
        raise RuntimeReportValidationError("candidate commit has an invalid format")
    if VERSION.fullmatch(expected_version) is None or "SNAPSHOT" in expected_version.upper():
        raise RuntimeReportValidationError("candidate version must be explicit and non-SNAPSHOT")
    if expected_tag != f"v{expected_version}":
        raise RuntimeReportValidationError("candidate tag must equal v plus candidate version")

    commit = _git_text(repository, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git_text(repository, "rev-parse", "--verify", "HEAD^{tree}")
    if commit != expected_commit or OBJECT_ID.fullmatch(tree) is None:
        raise RuntimeReportValidationError("Git HEAD does not equal the expected candidate")
    if _git_text(repository, "cat-file", "-t", f"refs/tags/{expected_tag}") != "tag":
        raise RuntimeReportValidationError("candidate tag must be annotated")
    if _git_text(repository, "rev-parse", "--verify", f"refs/tags/{expected_tag}^{{commit}}") != commit:
        raise RuntimeReportValidationError("candidate tag does not resolve to candidate commit")
    tag_object = _git_text(repository, "rev-parse", "--verify", f"refs/tags/{expected_tag}^{{tag}}")
    if OBJECT_ID.fullmatch(tag_object) is None:
        raise RuntimeReportValidationError("candidate tag object identity is invalid")
    _require_clean_candidate(repository)

    payloads: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        workspace = _workspace_source(repository, relative)
        committed = _candidate_blob(repository, commit, relative)
        if committed != workspace:
            raise RuntimeReportValidationError(f"workspace source differs from candidate: {relative}")
        payloads[relative] = committed
        hashes[relative] = _sha256(committed)

    try:
        executing = Path(__file__).resolve(strict=True).read_bytes()
    except OSError as exception:
        raise RuntimeReportValidationError("executing validator source cannot be read") from exception
    if executing != payloads[VALIDATOR_SOURCE]:
        raise RuntimeReportValidationError("executing validator differs from candidate validator")
    _validate_versions(payloads, expected_version)
    _validate_fixed_test_sources(payloads)
    _validate_csrf_route_matrix(payloads)
    _validate_frontend_foundation_sources(payloads)
    _validate_summary_schema(payloads[SUMMARY_SCHEMA])
    return CandidateBinding(
        commit=commit,
        tree=tree,
        tag_object=tag_object,
        version=expected_version,
        source_sha256=dict(sorted(hashes.items())),
        source_payloads=payloads,
    )


def _directory_flags() -> int:
    if os.name == "posix" and not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeReportValidationError("O_NOFOLLOW is required for private evidence")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags(write: bool = False, create: bool = False) -> int:
    flags = os.O_WRONLY if write else os.O_RDONLY
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_private_directory(path: Path, repository: Path, label: str) -> tuple[Path, int, os.stat_result]:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise RuntimeReportValidationError(f"{label} must be a non-symlink directory")
    resolved = requested.resolve(strict=True)
    if _inside(resolved, repository) or _inside(repository, resolved):
        raise RuntimeReportValidationError(f"{label} must be outside and not contain repository")
    before = os.lstat(resolved)
    descriptor = os.open(resolved, _directory_flags())
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_uid != os.geteuid()
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        raise RuntimeReportValidationError(f"{label} must be owned mode-0700 real directory")
    return resolved, descriptor, opened


def _directory_names(descriptor: int) -> set[str]:
    names = os.listdir(descriptor)
    if any(
        not isinstance(name, str) or not name or "/" in name or "\0" in name or name in {".", ".."}
        for name in names
    ):
        raise RuntimeReportValidationError("private evidence directory has an invalid entry")
    if len(names) != len(set(names)):
        raise RuntimeReportValidationError("private evidence directory has duplicate entries")
    return set(names)


def _snapshot_file(descriptor: int, name: str, maximum: int, label: str) -> FileSnapshot:
    child = os.open(name, _file_flags(), dir_fd=descriptor)
    try:
        before_path = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        before = os.fstat(child)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeReportValidationError(
                f"{label} must be one owned non-symlink regular file with mode 0600"
            )
        if before.st_size <= 0 or before.st_size > maximum:
            raise RuntimeReportValidationError(f"{label} size is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(child, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(child)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            stat.S_IMODE(before.st_mode),
            before.st_uid,
            before.st_nlink,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            stat.S_IMODE(after.st_mode),
            after.st_uid,
            after.st_nlink,
        )
        if len(payload) != before.st_size or len(payload) > maximum or identity_before != identity_after:
            raise RuntimeReportValidationError(f"{label} changed while being read")
        return FileSnapshot(
            payload=payload,
            sha256=_sha256(payload),
            device=before.st_dev,
            inode=before.st_ino,
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
            mode=stat.S_IMODE(before.st_mode),
            owner=before.st_uid,
            links=before.st_nlink,
        )
    finally:
        os.close(child)


def _snapshot_bundle(descriptor: int) -> dict[str, FileSnapshot]:
    if _directory_names(descriptor) != RAW_BUNDLE_FILES:
        raise RuntimeReportValidationError("raw directory must contain only the three reports and proof")
    maximums = {
        PROOF_FILE: MAX_PROOF_BYTES,
        PLAYWRIGHT_REPORT: MAX_PLAYWRIGHT_BYTES,
        **{name: MAX_SUREFIRE_BYTES for name in SUREFIRE_TESTS},
    }
    return {
        name: _snapshot_file(descriptor, name, maximums[name], f"raw {name}")
        for name in sorted(RAW_BUNDLE_FILES)
    }


def _validate_directory_unchanged(path: Path, descriptor: int, opened: os.stat_result) -> None:
    current = os.lstat(path)
    held = os.fstat(descriptor)
    if (
        (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        or (held.st_dev, held.st_ino) != (opened.st_dev, opened.st_ino)
        or stat.S_IMODE(current.st_mode) != 0o700
        or current.st_uid != os.geteuid()
    ):
        raise RuntimeReportValidationError("raw directory changed during validation")


def _parse_proof(payload: bytes) -> Mapping[str, Any]:
    document = _parse_json(payload, "runtime report proof")
    if not isinstance(document, dict):
        raise RuntimeReportValidationError("runtime report proof must be an object")
    expected = {"schemaVersion", "candidate", "runStartedAtEpochNs", "reports", "sources"}
    if set(document) != expected:
        raise RuntimeReportValidationError(
            "runtime report proof has extra, missing, or self-reported fields"
        )
    if document.get("schemaVersion") != 1:
        raise RuntimeReportValidationError("runtime report proof schema version is invalid")
    candidate = document.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {
        "commit", "tree", "tag", "tagObject", "version"
    }:
        raise RuntimeReportValidationError("runtime report proof candidate shape is invalid")
    reports = document.get("reports")
    if not isinstance(reports, dict) or set(reports) != RAW_REPORT_FILES:
        raise RuntimeReportValidationError("runtime report proof report inventory is not exact")
    for name, metadata in reports.items():
        if not isinstance(metadata, dict) or set(metadata) != {"sha256", "size", "modifiedAtEpochNs"}:
            raise RuntimeReportValidationError(f"runtime report metadata is invalid: {name}")
        if SHA256.fullmatch(str(metadata.get("sha256", ""))) is None:
            raise RuntimeReportValidationError(f"runtime report hash is invalid: {name}")
        for key in ("size", "modifiedAtEpochNs"):
            value = metadata.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise RuntimeReportValidationError(f"runtime report metadata {key} is invalid: {name}")
    sources = document.get("sources")
    if not isinstance(sources, dict) or set(sources) != set(SOURCE_PATHS):
        raise RuntimeReportValidationError("runtime report proof source inventory is not exact")
    if any(not isinstance(value, str) or SHA256.fullmatch(value) is None for value in sources.values()):
        raise RuntimeReportValidationError("runtime report proof source hash is invalid")
    started = document.get("runStartedAtEpochNs")
    if not isinstance(started, int) or isinstance(started, bool) or started <= 0:
        raise RuntimeReportValidationError("runtime report proof start time is invalid")
    return document


def _validate_proof_binding(
    proof: Mapping[str, Any],
    reports: Mapping[str, FileSnapshot],
    candidate: CandidateBinding,
    expected_tag: str,
    expected_started_ns: int,
) -> None:
    if proof["runStartedAtEpochNs"] != expected_started_ns:
        raise RuntimeReportValidationError("proof start time does not match independent input")
    expected_candidate = {
        "commit": candidate.commit,
        "tree": candidate.tree,
        "tag": expected_tag,
        "tagObject": candidate.tag_object,
        "version": candidate.version,
    }
    if proof["candidate"] != expected_candidate:
        raise RuntimeReportValidationError("proof candidate does not match independently verified candidate")
    for name in RAW_REPORT_FILES:
        snapshot = reports[name]
        expected = {
            "sha256": snapshot.sha256,
            "size": snapshot.size,
            "modifiedAtEpochNs": snapshot.modified_ns,
        }
        if proof["reports"][name] != expected:
            raise RuntimeReportValidationError(f"proof report binding differs from raw bytes: {name}")
    if proof["sources"] != candidate.source_sha256:
        raise RuntimeReportValidationError("proof source hashes differ from candidate blobs")


def _validate_report_freshness(snapshot: FileSnapshot, started_ns: int, label: str) -> None:
    now = time.time_ns()
    if started_ns <= 0 or started_ns > now:
        raise RuntimeReportValidationError("runtime test start time is invalid")
    if snapshot.modified_ns < started_ns or snapshot.modified_ns > now + MAX_CLOCK_SKEW_NS:
        raise RuntimeReportValidationError(f"{label} is stale or future-dated")


def _reported_test_directory(repository: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise RuntimeReportValidationError(f"Playwright {label} is invalid")
    expected = (repository / "web-starter-web" / "e2e").resolve(strict=True)
    candidate = Path(value)
    if not candidate.is_absolute():
        raise RuntimeReportValidationError(f"Playwright {label} must be absolute")
    try:
        actual = candidate.resolve(strict=True)
    except OSError as exception:
        raise RuntimeReportValidationError(f"Playwright {label} cannot be resolved") from exception
    if actual != expected:
        raise RuntimeReportValidationError(f"Playwright {label} differs from the fixed e2e root")
    return expected


def _reported_source(
    repository: Path,
    test_directory: Path,
    value: Any,
    expected_relative: str,
) -> None:
    if not isinstance(value, str) or not value or "\0" in value:
        raise RuntimeReportValidationError("Playwright spec source path is invalid")
    candidate = Path(value)
    expected = repository.joinpath(*expected_relative.split("/")).resolve(strict=True)
    if candidate.is_absolute():
        try:
            actual = candidate.resolve(strict=True)
        except OSError as exception:
            raise RuntimeReportValidationError("Playwright absolute source cannot be resolved") from exception
    else:
        posix = PurePosixPath(value.replace("\\", "/"))
        if posix.is_absolute() or ".." in posix.parts or "." in posix.parts or not posix.parts:
            raise RuntimeReportValidationError("Playwright relative source path is unsafe")
        try:
            actual = test_directory.joinpath(*posix.parts).resolve(strict=True)
        except OSError as exception:
            raise RuntimeReportValidationError("Playwright relative source cannot be resolved") from exception
    if actual != expected:
        raise RuntimeReportValidationError("Playwright report identifies a different test source")


def _walk_specs(suites: Any) -> list[Mapping[str, Any]]:
    if not isinstance(suites, list):
        raise RuntimeReportValidationError("Playwright suites must be a list")
    result: list[Mapping[str, Any]] = []
    for suite in suites:
        if not isinstance(suite, dict):
            raise RuntimeReportValidationError("Playwright suite must be an object")
        specs = suite.get("specs", [])
        nested = suite.get("suites", [])
        if not isinstance(specs, list) or not isinstance(nested, list):
            raise RuntimeReportValidationError("Playwright suite inventory is invalid")
        for spec in specs:
            if not isinstance(spec, dict):
                raise RuntimeReportValidationError("Playwright spec must be an object")
            result.append(spec)
        result.extend(_walk_specs(nested))
    return result


def _iso_epoch_ns(value: Any) -> int:
    if not isinstance(value, str) or not value:
        raise RuntimeReportValidationError("Playwright startTime is invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exception:
        raise RuntimeReportValidationError("Playwright startTime is invalid") from exception
    if parsed.tzinfo is None:
        raise RuntimeReportValidationError("Playwright startTime must include a timezone")
    return int(parsed.astimezone(timezone.utc).timestamp() * 1_000_000_000)


def _validate_playwright(
    snapshot: FileSnapshot,
    repository: Path,
    started_ns: int,
) -> list[dict[str, str]]:
    _validate_report_freshness(snapshot, started_ns, "Playwright report")
    document = _parse_json(snapshot.payload, "Playwright report")
    if not isinstance(document, dict):
        raise RuntimeReportValidationError("Playwright report must be an object")
    config = document.get("config")
    projects = config.get("projects") if isinstance(config, dict) else None
    if (
        not isinstance(projects, list)
        or len(projects) != 1
        or not isinstance(projects[0], dict)
        or projects[0].get("name") != ""
        or projects[0].get("id") != ""
    ):
        raise RuntimeReportValidationError(
            "Playwright report must contain only the fixed default project"
        )
    test_directory = _reported_test_directory(
        repository, projects[0].get("testDir"), "project testDir"
    )
    root_directory = _reported_test_directory(
        repository, config.get("rootDir"), "config rootDir"
    )
    if root_directory != test_directory:
        raise RuntimeReportValidationError("Playwright rootDir and testDir differ")
    if document.get("errors") != []:
        raise RuntimeReportValidationError("Playwright report contains top-level errors")
    stats = document.get("stats")
    if not isinstance(stats, dict):
        raise RuntimeReportValidationError("Playwright report stats are missing")
    expected_stats = {
        "expected": PLAYWRIGHT_TEST_COUNT,
        "skipped": 0,
        "unexpected": 0,
        "flaky": 0,
    }
    for key, expected in expected_stats.items():
        value = stats.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value != expected:
            raise RuntimeReportValidationError(f"Playwright stats {key} is not {expected}")
    duration = stats.get("duration")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool) \
            or not math.isfinite(duration) or duration < 0:
        raise RuntimeReportValidationError("Playwright duration is invalid")
    report_started = _iso_epoch_ns(stats.get("startTime"))
    if report_started < started_ns - 2_000_000_000 \
            or report_started > time.time_ns() + MAX_CLOCK_SKEW_NS:
        raise RuntimeReportValidationError("Playwright report startTime is stale or future-dated")

    specs = _walk_specs(document.get("suites"))
    if len(specs) != PLAYWRIGHT_TEST_COUNT:
        raise RuntimeReportValidationError(
            f"Playwright report must contain exactly {PLAYWRIGHT_TEST_COUNT} specs"
        )
    expected_inventory = {
        (relative, title)
        for relative, titles in PLAYWRIGHT_SPECS.items()
        for title in titles
    }
    observed: list[dict[str, str]] = []
    observed_inventory: set[tuple[str, str]] = set()
    for spec in specs:
        title = spec.get("title")
        file_value = spec.get("file")
        if not isinstance(title, str):
            raise RuntimeReportValidationError("Playwright spec title is invalid")
        matches = [
            relative for relative, titles in PLAYWRIGHT_SPECS.items() if title in titles
        ]
        if len(matches) != 1:
            raise RuntimeReportValidationError("Playwright report contains an unexpected spec")
        relative = matches[0]
        _reported_source(repository, test_directory, file_value, relative)
        identity = (relative, title)
        if identity in observed_inventory:
            raise RuntimeReportValidationError("Playwright report contains a duplicate spec")
        observed_inventory.add(identity)
        if spec.get("ok") is not True:
            raise RuntimeReportValidationError("Playwright spec did not pass")
        if spec.get("tags") != []:
            raise RuntimeReportValidationError("Playwright spec contains tags")
        if spec.get("annotations", []) != []:
            raise RuntimeReportValidationError("Playwright spec contains annotations")
        tests = spec.get("tests")
        if not isinstance(tests, list) or len(tests) != 1 or not isinstance(tests[0], dict):
            raise RuntimeReportValidationError("Playwright spec must have exactly one project test")
        test = tests[0]
        if test.get("expectedStatus") != "passed" or test.get("status") != "expected":
            raise RuntimeReportValidationError("Playwright test is skipped, unexpected, or flaky")
        if test.get("projectName") != "" or test.get("projectId") != "":
            raise RuntimeReportValidationError("Playwright test belongs to an unexpected project")
        if test.get("annotations") != []:
            raise RuntimeReportValidationError("Playwright test contains annotations")
        results = test.get("results")
        if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict):
            raise RuntimeReportValidationError("Playwright test must have exactly one zero-retry result")
        result = results[0]
        if result.get("status") != "passed" or result.get("retry") != 0:
            raise RuntimeReportValidationError("Playwright result is not a zero-retry pass")
        if result.get("errors") != [] or result.get("error") is not None:
            raise RuntimeReportValidationError("Playwright passing result contains errors")
        if result.get("stdout") != [] or result.get("stderr") != []:
            raise RuntimeReportValidationError(
                "Playwright result contains stdout or stderr material"
            )
        if result.get("attachments", []) != []:
            raise RuntimeReportValidationError("Playwright result contains diagnostic attachments")
        if result.get("annotations") != [] or result.get("steps") not in (None, []):
            raise RuntimeReportValidationError(
                "Playwright result contains annotations or serialized steps"
            )
        observed.append({"file": relative, "title": title})
    if observed_inventory != expected_inventory:
        raise RuntimeReportValidationError("Playwright report does not exactly cover fixed specs")
    return sorted(observed, key=lambda item: (item["file"], item["title"]))


def _validate_surefire(
    name: str,
    snapshot: FileSnapshot,
    started_ns: int,
) -> dict[str, Any]:
    _validate_report_freshness(snapshot, started_ns, name)
    expected_class, expected_method = SUREFIRE_TESTS[name]
    suite = _xml(snapshot.payload, name)
    if _local_name(suite.tag) != "testsuite" or suite.attrib.get("name") != expected_class:
        raise RuntimeReportValidationError(f"{name} identifies a different suite")
    suites = [item for item in suite.iter() if _local_name(item.tag) == "testsuite"]
    cases = [item for item in suite.iter() if _local_name(item.tag) == "testcase"]
    direct_cases = [item for item in list(suite) if _local_name(item.tag) == "testcase"]
    required_counts = {"tests": "1", "failures": "0", "errors": "0", "skipped": "0"}
    if suites != [suite] or any(suite.attrib.get(key) != value for key, value in required_counts.items()):
        raise RuntimeReportValidationError(f"{name} is not exactly one passing test")
    if suite.attrib.get("flakes", "0") != "0":
        raise RuntimeReportValidationError(f"{name} contains a flaky result")
    if (
        len(cases) != 1
        or len(direct_cases) != 1
        or cases[0] is not direct_cases[0]
        or cases[0].attrib.get("classname") != expected_class
        or cases[0].attrib.get("name") != expected_method
    ):
        raise RuntimeReportValidationError(f"{name} identifies a different test method")
    for element in suite.iter():
        local = _local_name(element.tag).lower()
        if local in FORBIDDEN_XML_ELEMENTS or "retry" in local or "rerun" in local or "flak" in local:
            raise RuntimeReportValidationError(f"{name} contains fail, skip, retry, or flake evidence")
        for attribute in element.attrib:
            field = _local_name(attribute).lower()
            if "retry" in field or "rerun" in field or ("flak" in field and field != "flakes"):
                raise RuntimeReportValidationError(f"{name} contains retry or flake metadata")
    return {
        "reportFile": name,
        "testClass": expected_class,
        "testMethod": expected_method,
        "tests": 1,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "retries": 0,
    }


def _summary_safe(value: Any, path: str = "summary") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_FIELD.fullmatch(key):
                raise RuntimeReportValidationError(f"summary contains sensitive field at {path}.{key}")
            _summary_safe(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _summary_safe(child, f"{path}[{index}]")
    elif isinstance(value, str) and SENSITIVE_VALUE.search(value):
        raise RuntimeReportValidationError(f"summary contains sensitive-shaped value at {path}")


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    _summary_safe(summary)
    return _canonical_json(summary)


def _write_summary(
    output_directory: Path,
    repository: Path,
    summary: Mapping[str, Any],
) -> Path:
    directory, descriptor, opened = _open_private_directory(
        output_directory, repository, "summary output directory"
    )
    created = False
    try:
        if _directory_names(descriptor):
            raise RuntimeReportValidationError("summary output directory must be empty")
        payload = canonical_summary_bytes(summary)
        child = os.open(SUMMARY_FILE, _file_flags(write=True, create=True), 0o600, dir_fd=descriptor)
        created = True
        try:
            os.fchmod(child, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(child, remaining)
                if written <= 0:
                    raise RuntimeReportValidationError("summary output write made no progress")
                remaining = remaining[written:]
            os.fsync(child)
            metadata = os.fstat(child)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise RuntimeReportValidationError("summary output is not private")
        finally:
            os.close(child)
        current = os.lstat(directory)
        if (
            (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or _directory_names(descriptor) != {SUMMARY_FILE}
        ):
            raise RuntimeReportValidationError("summary output changed during creation")
        written = _snapshot_file(descriptor, SUMMARY_FILE, MAX_PROOF_BYTES, "canonical summary")
        if written.payload != payload:
            raise RuntimeReportValidationError("canonical summary readback differs")
        return directory / SUMMARY_FILE
    except Exception:
        if created:
            try:
                os.unlink(SUMMARY_FILE, dir_fd=descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(descriptor)


def validate_proof(
    evidence_directory: Path,
    *,
    repository_root: Path,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    expected_run_started_at_epoch_ns: int,
    require_pass: bool = False,
    summary_output: Path | None = None,
) -> dict[str, Any]:
    """Independently recompute report semantics and optionally write a PASS summary."""
    if summary_output is not None and not require_pass:
        raise RuntimeReportValidationError("--summary-output requires --require-pass")
    if (
        not isinstance(expected_run_started_at_epoch_ns, int)
        or isinstance(expected_run_started_at_epoch_ns, bool)
        or expected_run_started_at_epoch_ns <= 0
        or expected_run_started_at_epoch_ns > time.time_ns()
    ):
        raise RuntimeReportValidationError("expected runtime start time is invalid")
    repository = _resolve_repository(repository_root)
    candidate = _validate_candidate(
        repository,
        expected_candidate_commit,
        expected_candidate_version,
        expected_candidate_tag,
    )
    directory, descriptor, opened = _open_private_directory(
        evidence_directory, repository, "raw evidence directory"
    )
    try:
        before = _snapshot_bundle(descriptor)
        proof = _parse_proof(before[PROOF_FILE].payload)
        reports = {name: before[name] for name in RAW_REPORT_FILES}
        _validate_proof_binding(
            proof,
            reports,
            candidate,
            expected_candidate_tag,
            expected_run_started_at_epoch_ns,
        )
        playwright_specs = _validate_playwright(
            reports[PLAYWRIGHT_REPORT], repository, expected_run_started_at_epoch_ns
        )
        surefire = [
            _validate_surefire(name, reports[name], expected_run_started_at_epoch_ns)
            for name in sorted(SUREFIRE_TESTS)
        ]

        _validate_directory_unchanged(directory, descriptor, opened)
        after = _snapshot_bundle(descriptor)
        if before != after:
            raise RuntimeReportValidationError("raw evidence changed during validation")
        final_candidate = _validate_candidate(
            repository,
            expected_candidate_commit,
            expected_candidate_version,
            expected_candidate_tag,
        )
        if final_candidate != candidate:
            raise RuntimeReportValidationError("candidate changed during validation")
        final = _snapshot_bundle(descriptor)
        if before != final:
            raise RuntimeReportValidationError("raw evidence changed during candidate recheck")
    finally:
        os.close(descriptor)

    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "evidenceType": EVIDENCE_TYPE,
        "status": "PASS",
        "candidate": {
            "commit": candidate.commit,
            "tree": candidate.tree,
            "version": candidate.version,
            "tag": expected_candidate_tag,
            "tagObject": candidate.tag_object,
        },
        "run": {"startedAtEpochNs": expected_run_started_at_epoch_ns},
        "coverage": {
            "playwright": {
                "reportFile": PLAYWRIGHT_REPORT,
                "tests": PLAYWRIGHT_TEST_COUNT,
                "passed": PLAYWRIGHT_TEST_COUNT,
                "skipped": 0,
                "retries": 0,
                "projectName": "default",
                "specs": playwright_specs,
            },
            "surefire": surefire,
        },
        "reports": {
            name: reports[name].sha256 for name in sorted(RAW_REPORT_FILES)
        },
        "sources": dict(candidate.source_sha256),
    }
    canonical_summary_bytes(summary)
    if summary_output is not None:
        _write_summary(summary_output, repository, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-tag", required=True)
    parser.add_argument("--expected-run-started-at-epoch-ns", required=True, type=int)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--summary-output", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        summary = validate_proof(
            arguments.evidence_directory,
            repository_root=arguments.repository_root,
            expected_candidate_commit=arguments.expected_candidate_commit,
            expected_candidate_version=arguments.expected_candidate_version,
            expected_candidate_tag=arguments.expected_candidate_tag,
            expected_run_started_at_epoch_ns=arguments.expected_run_started_at_epoch_ns,
            require_pass=arguments.require_pass,
            summary_output=arguments.summary_output,
        )
    except (OSError, RuntimeReportValidationError) as exception:
        raise SystemExit(f"release runtime test reports rejected: {exception}") from exception
    if arguments.require_pass:
        print(
            "PASS releaseRuntimeTestReports: exactly "
            f"{PLAYWRIGHT_TEST_COUNT} Playwright and 2 official SDK tests"
        )
    else:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
