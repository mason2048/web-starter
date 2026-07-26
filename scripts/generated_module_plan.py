#!/usr/bin/env python3
"""Discover and validate generated-module runtime acceptance plans.

The module generator emits static test metadata. This reader never executes a
path or expression from a plan; it only validates exact, derivable locations
that release acceptance may run explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


PLAN_RELATIVE = Path(
    "src/test/resources/META-INF/web-starter/module-acceptance-plan.properties"
)
BASE_FIELDS = frozenset({
    "schemaVersion",
    "module",
    "artifactId",
    "migration",
    "route",
    "plural",
    "apiPath",
    "resourceType",
    "permissions",
    "browserTest",
    "browserTitle",
    "withMcp",
})
MCP_FIELDS = frozenset({"mcpRuntimeTest", "mcpTools"})
MODULE = re.compile(r"^[a-z][a-z0-9]{1,30}$")
ARTIFACT = re.compile(r"^[a-z][a-z0-9-]{1,81}$")
ROUTE = re.compile(r"^/[a-z][a-z0-9/-]{0,126}[a-z0-9]$")
FQCN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.[A-Z][A-Za-z0-9]*McpRuntimeIT$")
TITLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{9,159}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IGNORED_DISCOVERY_DIRECTORIES = frozenset({
    ".git",
    ".idea",
    ".vscode",
    "artifacts",
    "dist",
    "node_modules",
    "playwright-report",
    "target",
    "test-results",
})


class GeneratedModulePlanError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_root(value: Path) -> Path:
    if value.is_symlink() or not value.is_dir():
        raise GeneratedModulePlanError("repository root must be a non-symlink directory")
    return value.resolve(strict=True)


def _safe_file(root: Path, relative: str, label: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != relative:
        raise GeneratedModulePlanError(f"{label} must be a normalized relative path")
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise GeneratedModulePlanError(f"{label} must not traverse a symbolic link")
    resolved = current.resolve(strict=True)
    if not _inside(resolved, root) or not resolved.is_file() or resolved.is_symlink():
        raise GeneratedModulePlanError(f"{label} must resolve to a regular repository file")
    return resolved


def _parse_properties(path: Path) -> dict[str, str]:
    if path.stat().st_size > 16_384:
        raise GeneratedModulePlanError("generated module plan exceeds 16 KiB")
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeError as error:
        raise GeneratedModulePlanError("generated module plan must be UTF-8") from error
    if "\0" in text or "\r" in text:
        raise GeneratedModulePlanError("generated module plan contains unsupported characters")
    result: dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise GeneratedModulePlanError(
                f"generated module plan line {line_number} is not key=value"
            )
        key, value = (part.strip() for part in line.split("=", 1))
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key) or not value:
            raise GeneratedModulePlanError(
                f"generated module plan line {line_number} is invalid"
            )
        if key in result:
            raise GeneratedModulePlanError(f"generated module plan repeats field {key}")
        result[key] = value
    return result


def _class_name(module: str) -> str:
    return module[0].upper() + module[1:]


def _validate_plan(root: Path, path: Path) -> dict[str, Any]:
    relative = path.relative_to(root)
    if (len(relative.parts) != len(PLAN_RELATIVE.parts) + 1
            or relative.parts[1:] != PLAN_RELATIVE.parts):
        raise GeneratedModulePlanError(
            "generated module plan is not at the exact declared artifact location"
        )
    relative_plan = relative.as_posix()
    values = _parse_properties(path)
    with_mcp = values.get("withMcp") == "true"
    if values.get("withMcp") not in {"true", "false"}:
        raise GeneratedModulePlanError("withMcp must be true or false")
    expected_fields = BASE_FIELDS | (MCP_FIELDS if with_mcp else frozenset())
    if set(values) != expected_fields:
        missing = sorted(expected_fields - set(values))
        extra = sorted(set(values) - expected_fields)
        raise GeneratedModulePlanError(
            f"generated module plan field set is not exact; missing={missing}, extra={extra}"
        )
    if values["schemaVersion"] != "1":
        raise GeneratedModulePlanError("generated module plan schemaVersion must equal 1")
    module = values["module"]
    artifact = values["artifactId"]
    if not MODULE.fullmatch(module) or not ARTIFACT.fullmatch(artifact):
        raise GeneratedModulePlanError("generated module identity is invalid")
    module_root = root / relative.parts[0]
    if module_root.parent != root or module_root.name != artifact or not artifact.endswith("-" + module):
        raise GeneratedModulePlanError("generated module plan is not inside its declared artifact")
    class_name = _class_name(module)
    if values["resourceType"] != module:
        raise GeneratedModulePlanError("resourceType does not match the generated module")
    route = values["route"]
    if not ROUTE.fullmatch(route) or "//" in route or ".." in route:
        raise GeneratedModulePlanError("generated module route is invalid")
    plural = values["plural"]
    if not MODULE.fullmatch(plural) or values["apiPath"] != "/api/" + plural:
        raise GeneratedModulePlanError("apiPath does not match the generated resource plural")
    expected_permissions = ",".join(
        f"{module}:{action}" for action in ("list", "create", "update", "remove")
    )
    if values["permissions"] != expected_permissions:
        raise GeneratedModulePlanError("generated module permissions are not the fixed CRUD set")

    prefix = artifact[: -(len(module) + 1)]
    migration_pattern = re.compile(
        rf"^{re.escape(prefix)}-admin/src/main/resources/db/migration/"
        rf"V[1-9][0-9]{{0,17}}__create_{re.escape(module)}_module\.sql$"
    )
    if not migration_pattern.fullmatch(values["migration"]):
        raise GeneratedModulePlanError("generated module migration path is invalid")
    migration = _safe_file(root, values["migration"], "generated module migration")

    expected_browser = f"{prefix}-web/e2e/generated/{module}-runtime.spec.ts"
    if values["browserTest"] != expected_browser:
        raise GeneratedModulePlanError("generated module browser test path is invalid")
    browser = _safe_file(root, values["browserTest"], "generated module browser test")
    if not TITLE.fullmatch(values["browserTitle"]):
        raise GeneratedModulePlanError("generated module browser title is invalid")
    browser_text = browser.read_text(encoding="utf-8", errors="strict")
    if browser_text.count("test(" + repr(values["browserTitle"])) != 1:
        raise GeneratedModulePlanError("generated module browser title is not bound exactly once")

    result: dict[str, Any] = {
        "module": module,
        "artifactId": artifact,
        "migration": values["migration"],
        "migrationSha256": sha256_file(migration),
        "route": route,
        "plural": plural,
        "apiPath": values["apiPath"],
        "resourceType": values["resourceType"],
        "permissions": values["permissions"].split(","),
        "browserTest": values["browserTest"],
        "browserTestSha256": sha256_file(browser),
        "browserTitle": values["browserTitle"],
        "withMcp": with_mcp,
        "planPath": relative_plan,
        "planSha256": sha256_file(path),
    }
    if with_mcp:
        expected_tools = ",".join(
            f"{module}.{action}" for action in ("list", "get", "create", "update", "remove")
        )
        if values["mcpTools"] != expected_tools or not FQCN.fullmatch(values["mcpRuntimeTest"]):
            raise GeneratedModulePlanError("generated MCP runtime metadata is invalid")
        expected_suffix = f".{module}.mcp.{class_name}McpRuntimeIT"
        if not values["mcpRuntimeTest"].endswith(expected_suffix):
            raise GeneratedModulePlanError("generated MCP runtime class does not match the module")
        source_relative = (
            f"{artifact}/src/test/java/"
            + values["mcpRuntimeTest"].replace(".", "/")
            + ".java"
        )
        runtime_test = _safe_file(root, source_relative, "generated MCP runtime test")
        result.update({
            "mcpTools": values["mcpTools"].split(","),
            "mcpRuntimeTest": values["mcpRuntimeTest"],
            "mcpRuntimeTestSource": source_relative,
            "mcpRuntimeTestSha256": sha256_file(runtime_test),
        })
    return result


def discover(repository_root: Path) -> list[dict[str, Any]]:
    root = _safe_root(repository_root)
    candidates: list[Path] = []
    for current_text, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_text)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in IGNORED_DISCOVERY_DIRECTORIES
            and not (current / name).is_symlink()
        )
        if PLAN_RELATIVE.name in file_names:
            candidates.append(current / PLAN_RELATIVE.name)
    plans: list[dict[str, Any]] = []
    for candidate in sorted(candidates):
        if candidate.is_symlink():
            raise GeneratedModulePlanError("generated module plan must not be a symbolic link")
        plans.append(_validate_plan(root, candidate.resolve(strict=True)))
    modules = [plan["module"] for plan in plans]
    if len(modules) != len(set(modules)):
        raise GeneratedModulePlanError("generated module plans repeat a module")
    return plans


def write_private_json(path: Path, document: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GeneratedModulePlanError("output must not already exist")
    parent_input = path.parent
    if parent_input.is_symlink() or not parent_input.is_dir():
        raise GeneratedModulePlanError("output parent must be a non-symlink directory")
    parent_input.resolve(strict=True)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("generated module plan output write made no progress")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repository-root", required=True, type=Path)
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--list-browser", action="store_true")
    mode.add_argument("--list-mcp", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(sys.argv[1:] if argv is None else argv)
        plans = discover(args.repository_root)
        if args.output is not None:
            write_private_json(args.output, {"schemaVersion": 1, "modules": plans})
        elif args.list_browser:
            for plan in plans:
                print("\t".join((plan["artifactId"], plan["browserTest"], plan["browserTitle"])))
        else:
            for plan in plans:
                if plan["withMcp"]:
                    print("\t".join((plan["artifactId"], plan["mcpRuntimeTest"])))
        return 0
    except (GeneratedModulePlanError, OSError, ValueError, UnicodeError) as error:
        print(f"ERROR generated-module-plan: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
