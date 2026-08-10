#!/usr/bin/env python3
"""Explicit registry for independently recomputed V1 supplemental evidence.

Supplemental artifacts are untrusted inputs. A producer can contribute a
status only through a source-controlled validator registered in this module.
The fixed source-review adapter below recomputes the operations-documentation
condition without trusting a producer-supplied status field. Architecture,
runtime, protocol, and browser conditions remain NOT_COVERED until a stronger
dedicated adapter is registered.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
import xml.etree.ElementTree as ET


ALLOWED_RESULTS = frozenset({"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"})
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_REVIEW_PRODUCER = "candidate-source-review"
SOURCE_REVIEW_CHECKS = frozenset({
    "supplemental.operationsDocumentationReview",
    "supplemental.projectIsolationReview",
})
SOURCE_BLOB_FIELDS = frozenset({"gitBlob", "sha256"})
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RELEASE_EVIDENCE_PATH = re.compile(
    r"^release/evidence/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)\.json$"
)

SHARED_BOUNDARY_FIXED_PATHS = frozenset({
    "web-starter-project/src/main/java/dev/webstarter/project/service/ProjectService.java",
    "web-starter-project/src/main/java/dev/webstarter/project/service/impl/ProjectServiceImpl.java",
    "web-starter-project/src/main/java/dev/webstarter/project/web/ProjectController.java",
    "web-starter-mcp/pom.xml",
})
RUNTIME_MODULES = (
    "web-starter-core",
    "web-starter-system",
    "web-starter-project",
    "web-starter-security",
    "web-starter-mcp",
    "web-starter-admin",
)
OPERATIONS_REVIEW_PATHS = frozenset({
    "docs/deployment.md",
    "docs/security.md",
    "docs/recovery-rehearsal.md",
    "docs/v1-to-v2-upgrade-rehearsal.md",
    "scripts/recovery_backup.py",
    "scripts/recovery_restore.py",
    "scripts/rehearse_redis_loss.py",
    "scripts/rehearse_v1_to_v2_upgrade.py",
    "compose.production.yaml",
})
EXPECTED_TOP_LEVEL_ENTRIES = frozenset({
    ".dockerignore",
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".github",
    ".gitignore",
    ".mvn",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "bin",
    "compose.dev.yaml",
    "compose.production.yaml",
    "compose.public-mcp.yaml",
    "compose.yaml",
    "deploy",
    "docs",
    "mvnw",
    "mvnw.cmd",
    "pom.xml",
    "release",
    "scripts",
    "security",
    "web-starter-admin",
    "web-starter-core",
    "web-starter-mcp",
    "web-starter-project",
    "web-starter-security",
    "web-starter-system",
    "web-starter-tooling",
    "web-starter-web",
})
EXPECTED_MAVEN_MODULES = (
    "web-starter-core",
    "web-starter-system",
    "web-starter-security",
    "web-starter-project",
    "web-starter-mcp",
    "web-starter-admin",
    "web-starter-tooling",
)
MAVEN_NAMESPACE = {"m": "http://maven.apache.org/POM/4.0.0"}


class SupplementalValidationError(ValueError):
    """A registered validator failed or returned an invalid result."""


Validator = Callable[
    [str, Sequence[Mapping[str, Any]], Mapping[str, str]],
    str,
]


@dataclass(frozen=True)
class ProducerValidator:
    checks: frozenset[str]
    validator: Validator | None


def _git(root: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
    ):
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(name, None)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    try:
        return subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(root), *arguments,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exception:
        raise SupplementalValidationError("candidate source Git inspection failed") from exception


def _tracked_candidate_files(root: Path, commit: str) -> dict[str, str]:
    result: dict[str, str] = {}
    records = [record for record in _git(
        root, "ls-tree", "-r", "-z", "--full-tree", commit
    ).split(b"\0") if record]
    for record in records:
        if b"\t" not in record:
            raise SupplementalValidationError("candidate Git tree entry is malformed")
        metadata, encoded_path = record.split(b"\t", 1)
        fields = metadata.split(b" ")
        try:
            relative = encoded_path.decode("utf-8", errors="strict")
            object_id = fields[2].decode("ascii", errors="strict")
        except (UnicodeDecodeError, IndexError) as exception:
            raise SupplementalValidationError("candidate Git tree entry is malformed") from exception
        if (
            len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
            or not GIT_OBJECT.fullmatch(object_id)
            or not relative
            or relative.startswith("/")
            or relative in result
        ):
            raise SupplementalValidationError("candidate contains a non-regular or duplicate tracked path")
        result[relative] = object_id
    if not result:
        raise SupplementalValidationError("candidate Git tree is empty")
    return result


def source_review_paths(
    check: str,
    root: Path = REPOSITORY_ROOT,
    commit: str | None = None,
) -> tuple[str, ...]:
    """Return the exact candidate files a source-review artifact must bind."""
    resolved = root.resolve()
    candidate_commit = commit or _git(resolved, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    if not GIT_OBJECT.fullmatch(candidate_commit):
        raise SupplementalValidationError("candidate commit identity is malformed")
    tracked = _tracked_candidate_files(resolved, candidate_commit)
    if check == "supplemental.sharedProjectServiceBoundary":
        paths = set(SHARED_BOUNDARY_FIXED_PATHS)
        paths.update(
            path for path in tracked
            if path.startswith("web-starter-mcp/src/main/java/") and path.endswith(".java")
        )
    elif check == "supplemental.forbiddenCapabilitySourceScan":
        paths = {"pom.xml", *(f"{module}/pom.xml" for module in RUNTIME_MODULES)}
        for module in RUNTIME_MODULES:
            prefix = f"{module}/src/main/java/"
            java_paths = {
                path for path in tracked if path.startswith(prefix) and path.endswith(".java")
            }
            if not java_paths:
                raise SupplementalValidationError(f"runtime Java source root is empty: {module}")
            paths.update(java_paths)
    elif check == "supplemental.operationsDocumentationReview":
        paths = set(OPERATIONS_REVIEW_PATHS)
        paths.update(
            path for path in tracked
            if re.fullmatch(
                r"web-starter-admin/src/main/resources/db/migration/V[0-9]+__[A-Za-z0-9_]+\.sql",
                path,
            )
        )
    elif check == "supplemental.projectIsolationReview":
        paths = set(tracked)
    else:
        raise SupplementalValidationError("source-review check is not registered")
    for relative in paths:
        if relative not in tracked:
            raise SupplementalValidationError(f"source-review candidate file is not a regular Git blob: {relative}")
    return tuple(sorted(paths))


def _verify_candidate_root(candidate: Mapping[str, str], root: Path) -> str:
    expected_fields = {
        "manifestSha256", "gitCommit", "gitTree", "sourceArchiveSha256",
        "releaseTag", "releaseVersion",
    }
    if set(candidate) != expected_fields:
        raise SupplementalValidationError("source-review candidate fields are not exact")
    if not SHA256.fullmatch(candidate["manifestSha256"]) \
            or not SHA256.fullmatch(candidate["sourceArchiveSha256"]) \
            or not GIT_OBJECT.fullmatch(candidate["gitCommit"]) \
            or not GIT_OBJECT.fullmatch(candidate["gitTree"]) \
            or not VERSION.fullmatch(candidate["releaseVersion"]) \
            or candidate["releaseVersion"].endswith("-SNAPSHOT") \
            or candidate["releaseTag"] != f"v{candidate['releaseVersion']}":
        raise SupplementalValidationError("source-review candidate identity is malformed")
    if Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise SupplementalValidationError("source-review root is not the exact Git top-level")
    commit = _git(root, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if commit != candidate["gitCommit"] or tree != candidate["gitTree"]:
        raise SupplementalValidationError("source-review Git identity differs from the candidate")
    tag_reference = f"refs/tags/{candidate['releaseTag']}"
    if (
        _git(root, "cat-file", "-t", tag_reference).decode("ascii").strip() != "tag"
        or _git(root, "rev-parse", f"{tag_reference}^{{commit}}").decode("ascii").strip()
        != commit
    ):
        raise SupplementalValidationError("source-review candidate tag is not annotated at HEAD")
    status = _git(
        root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"
    )
    index = [entry for entry in _git(root, "ls-files", "-v", "-z").split(b"\0") if entry]
    if status or not index or any(not entry.startswith(b"H ") for entry in index):
        raise SupplementalValidationError("source-review candidate worktree is not strictly clean")
    archive = _git(root, "archive", "--format=tar", commit)
    if hashlib.sha256(archive).hexdigest() != candidate["sourceArchiveSha256"]:
        raise SupplementalValidationError("source-review candidate archive binding differs")
    return commit


def _strict_sources(
    observations: Mapping[str, Any],
    expected_paths: Sequence[str],
    root: Path,
    commit: str,
) -> dict[str, bytes]:
    if set(observations) != {"schemaVersion", "sourceBlobs"} \
            or observations.get("schemaVersion") != 1:
        raise SupplementalValidationError("source-review observations are not exact")
    source_blobs = observations.get("sourceBlobs")
    if not isinstance(source_blobs, dict) or set(source_blobs) != set(expected_paths):
        raise SupplementalValidationError("source-review source inventory is not exact")
    tracked = _tracked_candidate_files(root, commit)
    committed_sources: dict[str, bytes] = {}
    for relative in expected_paths:
        value = source_blobs[relative]
        if not isinstance(value, dict) or set(value) != SOURCE_BLOB_FIELDS:
            raise SupplementalValidationError("source-review blob metadata is not exact")
        git_blob, sha256 = value.get("gitBlob"), value.get("sha256")
        if not isinstance(git_blob, str) or not GIT_OBJECT.fullmatch(git_blob) \
                or not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            raise SupplementalValidationError("source-review blob identity is malformed")
        actual_blob = tracked.get(relative)
        if actual_blob is None:
            raise SupplementalValidationError(f"source-review blob is not tracked: {relative}")
        committed = _git(root, "cat-file", "blob", f"{commit}:{relative}")
        if (
            actual_blob != git_blob
            or hashlib.sha256(committed).hexdigest() != sha256
        ):
            raise SupplementalValidationError(f"source-review blob differs: {relative}")
        committed_sources[relative] = committed
    return committed_sources


def _text(sources: Mapping[str, bytes], relative: str) -> str:
    try:
        return sources[relative].decode("utf-8", errors="strict")
    except (KeyError, UnicodeDecodeError) as exception:
        raise SupplementalValidationError(f"source-review file is not UTF-8: {relative}") from exception


def _validate_shared_project_service(sources: Mapping[str, bytes]) -> None:
    service = _text(
        sources,
        "web-starter-project/src/main/java/dev/webstarter/project/service/ProjectService.java",
    )
    controller = _text(
        sources,
        "web-starter-project/src/main/java/dev/webstarter/project/web/ProjectController.java",
    )
    catalog = _text(sources, "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolCatalog.java")
    content = _text(sources, "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpContentCatalog.java")
    required_methods = ("page(", "get(", "create(", "update(", "remove(")
    if "public interface ProjectService" not in service \
            or any(method not in service for method in required_methods):
        raise SupplementalValidationError("ProjectService does not expose the frozen shared operations")
    for label, source in (("REST controller", controller), ("MCP catalog", catalog), ("MCP content", content)):
        if "import dev.webstarter.project.service.ProjectService;" not in source \
                or "ProjectService projectService" not in source:
            raise SupplementalValidationError(f"{label} does not depend on ProjectService")
    for method in required_methods:
        if f"projectService.{method}" not in controller or f"projectService.{method}" not in catalog:
            raise SupplementalValidationError(f"REST and MCP do not share ProjectService.{method[:-1]}")
    for relative in sources:
        if relative.startswith("web-starter-mcp/") and relative.endswith(".java"):
            source = _text(sources, relative)
            if "dev.webstarter.project.persistence" in source or re.search(r"\bProjectMapper\b", source):
                raise SupplementalValidationError("MCP runtime directly references Project persistence")
    mcp_pom = _text(sources, "web-starter-mcp/pom.xml")
    if "<artifactId>web-starter-project</artifactId>" not in mcp_pom:
        raise SupplementalValidationError("MCP module does not declare the shared Project module")


def _validate_forbidden_capabilities(sources: Mapping[str, bytes]) -> None:
    runtime_sources: list[tuple[str, str]] = []
    for relative in sorted(sources):
        if relative.endswith(".java"):
            runtime_sources.append((relative, _text(sources, relative)))
    forbidden_runtime = (
        "io.modelcontextprotocol.client.",
        "McpClient.sync(",
        "McpClient.async(",
        "new ProcessBuilder(",
        "Runtime.getRuntime().exec(",
        "ProcessHandle.",
        "javax.script.",
        "ScriptEngineManager",
        "GroovyShell",
        "javax.tools.JavaCompiler",
        "ToolProvider.getSystemJavaCompiler(",
        "MethodHandles.Lookup.defineClass(",
        "sun.misc.Unsafe",
    )
    for relative, source in runtime_sources:
        if any(token in source for token in forbidden_runtime):
            raise SupplementalValidationError(f"runtime source exposes a forbidden capability: {relative}")
        if relative.startswith("web-starter-mcp/") and (
            "import java.nio.file." in source
            or "import java.io.File;" in source
            or "import java.io.RandomAccessFile;" in source
        ):
            raise SupplementalValidationError("MCP runtime exposes filesystem access")
    catalog = _text(sources, "web-starter-mcp/src/main/java/dev/webstarter/mcp/service/McpToolCatalog.java")
    tool_names = re.findall(
        r'public static final String [A-Z_]+ = "([a-z][a-z0-9.]+)";', catalog
    )
    expected_tools = {
        "system.info", "project.list", "project.get", "project.create",
        "project.update", "project.remove", "audit.list",
    }
    if set(tool_names) != expected_tools or len(tool_names) != len(expected_tools):
        raise SupplementalValidationError("source Tool catalog differs from the frozen seven Tools")
    contributor_sources = [
        relative for relative, source in runtime_sources
        if "implements McpToolContributor" in source
    ]
    if contributor_sources:
        raise SupplementalValidationError("base runtime unexpectedly registers generated MCP contributors")
    admin_pom = _text(sources, "web-starter-admin/pom.xml")
    if "<artifactId>web-starter-tooling</artifactId>" in admin_pom:
        raise SupplementalValidationError("offline tooling is packaged in the runtime application")
    for relative, source in runtime_sources:
        if "dev.webstarter.tooling" in source:
            raise SupplementalValidationError(f"runtime source imports offline tooling: {relative}")


def _validate_operations_documentation(sources: Mapping[str, bytes]) -> None:
    deployment = _text(sources, "docs/deployment.md")
    security = _text(sources, "docs/security.md")
    recovery = _text(sources, "docs/recovery-rehearsal.md")
    upgrade = _text(sources, "docs/v1-to-v2-upgrade-rehearsal.md")
    required_deployment = (
        "## 日志与故障定位",
        "## 备份与恢复",
        "## 升级与回滚",
        "### RSA 签名密钥轮换与回退",
        "recovery-rehearsal.md",
        "compose.production.yaml",
        "WEB_STARTER_APP_DIGEST",
    )
    if any(token not in deployment for token in required_deployment):
        raise SupplementalValidationError("deployment operations documentation is incomplete")
    if any(token not in security for token in (
        "### OAuth RSA 签名密钥轮换", "`exp` NumericDate", "`rev`",
        "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID",
    )):
        raise SupplementalValidationError("RSA lifecycle documentation is incomplete")
    for script in ("recovery_backup.py", "recovery_restore.py", "rehearse_redis_loss.py"):
        if script not in recovery:
            raise SupplementalValidationError(f"recovery documentation omits {script}")
    if "rehearse_v1_to_v2_upgrade.py" not in upgrade or "V1 tag" not in upgrade:
        raise SupplementalValidationError("upgrade rehearsal documentation is incomplete")
    migrations = [
        relative for relative in sources
        if relative.startswith("web-starter-admin/src/main/resources/db/migration/V")
    ]
    versions = [int(match.group(1)) for relative in migrations if (match := re.search(r"/V(\d+)__", relative))]
    if not versions or sorted(versions) != list(range(1, max(versions) + 1)):
        raise SupplementalValidationError("Flyway migration versions are not a contiguous documented sequence")
    if f"V1—V{max(versions)}" not in recovery:
        raise SupplementalValidationError("recovery documentation is stale relative to Flyway")


def _xml_root(sources: Mapping[str, bytes], relative: str) -> ET.Element:
    try:
        return ET.fromstring(sources[relative])
    except (KeyError, ET.ParseError) as exception:
        raise SupplementalValidationError(f"project-isolation POM is invalid: {relative}") from exception


def _validate_project_isolation(sources: Mapping[str, bytes]) -> None:
    paths = set(sources)
    top_level = {relative.split("/", 1)[0] for relative in paths}
    if top_level != EXPECTED_TOP_LEVEL_ENTRIES:
        raise SupplementalValidationError("candidate top-level inventory is not the fixed generic scaffold")

    release_paths = sorted(relative for relative in paths if relative.startswith("release/"))
    for relative in release_paths:
        match = RELEASE_EVIDENCE_PATH.fullmatch(relative)
        if match is None:
            raise SupplementalValidationError(
                f"release evidence inventory escaped its fixed boundary: {relative}"
            )
        try:
            evidence = json.loads(sources[relative])
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise SupplementalValidationError(
                f"release evidence is not valid JSON: {relative}"
            ) from exception
        version = match.group("version")
        release = evidence.get("release") if isinstance(evidence, dict) else None
        if (
            not isinstance(evidence, dict)
            or evidence.get("schemaVersion") != 1
            or not isinstance(release, dict)
            or release.get("tag") != f"v{version}"
            or release.get("version") != version
            or not isinstance(evidence.get("suites"), dict)
        ):
            raise SupplementalValidationError(
                f"release evidence identity differs from its versioned path: {relative}"
            )

    root_pom = _xml_root(sources, "pom.xml")
    modules = tuple(
        element.text.strip()
        for element in root_pom.findall("m:modules/m:module", MAVEN_NAMESPACE)
        if isinstance(element.text, str) and element.text.strip()
    )
    if modules != EXPECTED_MAVEN_MODULES:
        raise SupplementalValidationError("root Maven module inventory is not the fixed generic scaffold")
    root_artifact = root_pom.find("m:artifactId", MAVEN_NAMESPACE)
    if root_artifact is None or root_artifact.text != "web-starter":
        raise SupplementalValidationError("root Maven artifact identity is not generic")

    for module in EXPECTED_MAVEN_MODULES:
        pom_path = f"{module}/pom.xml"
        module_pom = _xml_root(sources, pom_path)
        artifact = module_pom.find("m:artifactId", MAVEN_NAMESPACE)
        if artifact is None or artifact.text != module:
            raise SupplementalValidationError(f"Maven module identity differs from its directory: {module}")
        if not any(
            relative.startswith(f"{module}/src/")
            for relative in paths
        ):
            raise SupplementalValidationError(f"Maven module has no tracked source boundary: {module}")

    try:
        frontend = json.loads(_text(sources, "web-starter-web/package.json"))
    except json.JSONDecodeError as exception:
        raise SupplementalValidationError("frontend package metadata is invalid") from exception
    if not isinstance(frontend, dict) or frontend.get("name") != "web-starter-web":
        raise SupplementalValidationError("frontend package identity is not generic")

    java_paths = sorted(relative for relative in paths if relative.endswith(".java"))
    if not java_paths:
        raise SupplementalValidationError("candidate contains no Java source")
    java_prefix = re.compile(
        r"^(web-starter-(?:admin|core|mcp|project|security|system|tooling))/"
        r"src/(?:main|test)/java/(dev/webstarter(?:/[A-Za-z0-9_]+)*)/"
        r"[A-Za-z0-9_$]+\.java$"
    )
    package_declaration = re.compile(r"(?m)^package\s+([a-zA-Z_][a-zA-Z0-9_.]*);")
    for relative in java_paths:
        match = java_prefix.fullmatch(relative)
        if match is None:
            raise SupplementalValidationError(f"Java source escaped the generic package boundary: {relative}")
        expected_package = match.group(2).replace("/", ".")
        declaration = package_declaration.search(_text(sources, relative))
        if declaration is None or declaration.group(1) != expected_package:
            raise SupplementalValidationError(f"Java package differs from its generic path: {relative}")


def _validate_source_review(
    check: str,
    artifacts: Sequence[Mapping[str, Any]],
    candidate: Mapping[str, str],
) -> str:
    if len(artifacts) != 1:
        raise SupplementalValidationError("source-review check requires exactly one artifact")
    root = REPOSITORY_ROOT.resolve()
    commit = _verify_candidate_root(candidate, root)
    expected_paths = source_review_paths(check, root, commit)
    observations = artifacts[0].get("observations")
    if not isinstance(observations, dict):
        raise SupplementalValidationError("source-review observations must be an object")
    sources = _strict_sources(observations, expected_paths, root, commit)
    if check == "supplemental.sharedProjectServiceBoundary":
        _validate_shared_project_service(sources)
    elif check == "supplemental.forbiddenCapabilitySourceScan":
        _validate_forbidden_capabilities(sources)
    elif check == "supplemental.operationsDocumentationReview":
        _validate_operations_documentation(sources)
    elif check == "supplemental.projectIsolationReview":
        _validate_project_isolation(sources)
    else:
        raise SupplementalValidationError("source-review check is not registered")
    _verify_candidate_root(candidate, root)
    return "PASS"


# This is a code registry, not configuration and not evidence input. Every
# registered producer must have a dedicated validator that recomputes complete
# frozen semantics from status-free observations.
PRODUCER_VALIDATORS: Mapping[str, ProducerValidator] = MappingProxyType({
    SOURCE_REVIEW_PRODUCER: ProducerValidator(
        checks=SOURCE_REVIEW_CHECKS,
        validator=_validate_source_review,
    ),
})


def validate(
    producer: str,
    check: str,
    artifacts: Sequence[Mapping[str, Any]],
    candidate: Mapping[str, str],
) -> str | None:
    """Return a recomputed status, or None when no exact validator is available."""
    registration = PRODUCER_VALIDATORS.get(producer)
    if (
        registration is None
        or check not in registration.checks
        or registration.validator is None
    ):
        return None
    try:
        status = registration.validator(check, artifacts, candidate)
    except Exception as exception:
        raise SupplementalValidationError(
            "registered supplemental validator failed"
        ) from exception
    if status not in ALLOWED_RESULTS:
        raise SupplementalValidationError(
            "registered supplemental validator returned an invalid status"
        )
    return status
