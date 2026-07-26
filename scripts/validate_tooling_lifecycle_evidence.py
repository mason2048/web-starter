#!/usr/bin/env python3
"""Independently validate AC-02/37 and V2-AC-16/17 lifecycle runtime evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence


REPORT_NAME = "v2-tooling-lifecycle-runtime.json"
SUMMARY_NAME = "v2-tooling-lifecycle-runtime-summary.json"
SCHEMA_PATH = "security/v2-tooling-lifecycle-runtime-summary.schema.json"
SOURCE_PATHS = (
    "scripts/rehearse_tooling_lifecycle.py",
    "scripts/validate_tooling_lifecycle_evidence.py",
    SCHEMA_PATH,
    "bin/web-starter",
    "compose.yaml",
    "compose.dev.yaml",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/dev/DeveloperCommands.java",
    "web-starter-tooling/src/main/java/dev/webstarter/tooling/cli/WebStarterCli.java",
    "docs/tooling.md",
    "docs/tooling-lifecycle-runtime-evidence.md",
)
EXPECTED_DOCTOR_CHECKS = {
    "workspace", "maven-wrapper", "launcher", "frontend", "java", "maven",
    "node", "pnpm", "docker-engine", "docker-compose", "compose-wait", "env-file",
    "config:WEB_STARTER_DB_USERNAME", "config:WEB_STARTER_DB_PASSWORD",
    "config:WEB_STARTER_DB_ROOT_PASSWORD", "config:WEB_STARTER_REDIS_PASSWORD",
    "config:WEB_STARTER_TOKEN_PEPPER",
    "config:WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD",
    "port:mysql", "port:redis", "port:app", "port:nginx",
}
SERVICES = {"mysql", "redis", "app", "nginx"}
OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
PROJECT = re.compile(r"^web-starter-tooling-[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
REFERENCE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE = re.compile(
    rb"(?i)(?:wst_(?:pat|svc)_[A-Za-z0-9._~-]{8,}|bearer\s+|"
    rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    rb"BEGIN (?:RSA )?PRIVATE KEY)"
)
BUSINESS_FIXTURE_BASE_ID = 8_000_000_000_000_000_000
BUSINESS_FIXTURE_ID_RANGE = 100_000_000_000_000_000
BUSINESS_FIXTURE_NAME = "Tooling persistence fixture"
BUSINESS_FIXTURE_OWNER = "tooling-rehearsal"
BUSINESS_FIXTURE_DESCRIPTION = "AC-37 compose restart persistence"
BUSINESS_FIXTURE_TIMESTAMP = "2026-01-01 00:00:00.000000"


class ToolingEvidenceError(ValueError):
    """Tooling lifecycle evidence is unsafe, stale or incomplete."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolingEvidenceError(f"JSON repeats field {key}")
        result[key] = value
    return result


def _load_private(path: Path, label: str, maximum: int = 4 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise ToolingEvidenceError(f"{label} must be a real regular file")
    metadata = requested.stat()
    if metadata.st_size <= 0 or metadata.st_size > maximum \
            or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600) \
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid()):
        raise ToolingEvidenceError(f"{label} must be an owned mode-0600 bounded file")
    payload = requested.read_bytes()
    if SENSITIVE.search(payload):
        raise ToolingEvidenceError(f"{label} contains credential-shaped material")
    try:
        document = json.loads(payload.decode("utf-8", errors="strict"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingEvidenceError(f"{label} must be unique-key UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ToolingEvidenceError(f"{label} must contain one object")
    return document, payload


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ToolingEvidenceError(f"{label} has unexpected or missing fields")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolingEvidenceError(f"{label} must be an object")
    return value


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ToolingEvidenceError("tooling observation time is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ToolingEvidenceError("tooling observation time is invalid") from error
    if parsed.tzinfo is None or parsed.astimezone(timezone.utc) > datetime.now(timezone.utc):
        raise ToolingEvidenceError("tooling observation time lacks a valid timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _git_run(root: Path, arguments: Sequence[str], maximum: int = 16 * 1024 * 1024) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C", "LANG": "C"})
    completed = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *arguments],
        cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > maximum \
            or len(completed.stderr) > 64 * 1024:
        raise ToolingEvidenceError("candidate Git inspection failed safely")
    return completed.stdout


def _git(root: Path, *arguments: str) -> str:
    return _git_run(root, arguments).decode("utf-8", errors="strict").strip()


def _candidate(root: Path, reported: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    _exact(
        reported,
        {"gitCommit", "gitTree", "tagObject", "releaseVersion", "releaseTag"},
        "tooling candidate",
    )
    commit = reported.get("gitCommit")
    version = reported.get("releaseVersion")
    tag = reported.get("releaseTag")
    if not isinstance(commit, str) or OBJECT_ID.fullmatch(commit) is None \
            or not isinstance(version, str) or VERSION.fullmatch(version) is None \
            or tag != "v" + version or "SNAPSHOT" in version.upper():
        raise ToolingEvidenceError("tooling candidate identity is invalid")
    candidate = root.resolve(strict=True)
    if _git(candidate, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ToolingEvidenceError("tooling candidate must be clean")
    actual = {
        "gitCommit": _git(candidate, "rev-parse", "HEAD"),
        "gitTree": _git(candidate, "rev-parse", "HEAD^{tree}"),
        "tagObject": _git(candidate, "rev-parse", f"refs/tags/{tag}"),
        "releaseVersion": version,
        "releaseTag": tag,
    }
    if _git(candidate, "cat-file", "-t", f"refs/tags/{tag}") != "tag" \
            or _git(candidate, "rev-list", "-n", "1", tag) != commit \
            or actual != dict(reported):
        raise ToolingEvidenceError("tooling candidate commit, tree or annotated tag differs")
    hashes: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        payload = (candidate / relative).read_bytes()
        if _git_run(candidate, ["show", f"HEAD:{relative}"], 8 * 1024 * 1024) != payload:
            raise ToolingEvidenceError(f"tooling candidate source differs: {relative}")
        hashes[relative] = hashlib.sha256(payload).hexdigest()
    return actual, hashes


def _empty_snapshot(value: Any, label: str) -> None:
    snapshot = _object(value, label)
    _exact(snapshot, {"containers", "volumes", "networks"}, label)
    if snapshot != {"containers": {}, "volumes": [], "networks": []}:
        raise ToolingEvidenceError(f"{label} is not empty")


def _up_snapshot(value: Any, project: str, label: str) -> dict[str, str]:
    snapshot = _object(value, label)
    _exact(snapshot, {"containers", "volumes", "networks"}, label)
    containers = _object(snapshot.get("containers"), label + " containers")
    if set(containers) != SERVICES:
        raise ToolingEvidenceError(f"{label} service inventory differs")
    image_ids: dict[str, str] = {}
    for service, raw in containers.items():
        container = _object(raw, label + " container")
        _exact(container, {"status", "health", "imageId"}, label + " container")
        image_id = container.get("imageId")
        if container.get("status") != "running" or container.get("health") != "healthy" \
                or not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
            raise ToolingEvidenceError(f"{label} service is not running and healthy")
        image_ids[service] = image_id
    if snapshot.get("volumes") != sorted((f"{project}_mysql-data", f"{project}_redis-data")) \
            or snapshot.get("networks") != sorted((f"{project}_app", f"{project}_data")):
        raise ToolingEvidenceError(f"{label} volume or network inventory differs")
    return image_ids


def _preserved_snapshot(value: Any, project: str, label: str) -> dict[str, Any]:
    snapshot = _object(value, label)
    expected = {
        "containers": {},
        "volumes": sorted((f"{project}_mysql-data", f"{project}_redis-data")),
        "networks": [],
    }
    if snapshot != expected:
        raise ToolingEvidenceError(f"{label} did not preserve only named data volumes")
    return snapshot


def _business_record(value: Any, project: str, label: str) -> dict[str, Any]:
    record = _object(value, label)
    _exact(record, {"fixtureId", "fixtureCode", "rowCount", "rowSha256"}, label)
    digest = hashlib.sha256(project.encode("utf-8")).hexdigest()
    fixture_id = BUSINESS_FIXTURE_BASE_ID + (
        int(digest[:16], 16) % BUSINESS_FIXTURE_ID_RANGE
    )
    fixture_code = "TOOLING_" + digest[:16].upper()
    fields = (
        str(fixture_id), BUSINESS_FIXTURE_NAME, fixture_code, str(fixture_id),
        BUSINESS_FIXTURE_OWNER, "ACTIVE", BUSINESS_FIXTURE_DESCRIPTION, "0",
        BUSINESS_FIXTURE_TIMESTAMP, BUSINESS_FIXTURE_TIMESTAMP, "0",
    )
    row_sha256 = hashlib.sha256("\x1f".join(fields).encode("utf-8")).hexdigest()
    expected = {
        "fixtureId": fixture_id,
        "fixtureCode": fixture_code,
        "rowCount": 1,
        "rowSha256": row_sha256,
    }
    if record != expected or type(record.get("fixtureId")) is not int \
            or type(record.get("rowCount")) is not int:
        raise ToolingEvidenceError(f"{label} differs from the deterministic business row")
    return expected


def _bootstrap_credential(value: Any) -> dict[str, Any]:
    credential = _object(value, "bootstrap credential lifecycle")
    _exact(credential, {
        "firstLogin", "passwordHashBeforeRestart",
        "environmentPasswordRemovedBeforeRestart", "secondLogin",
        "passwordHashAfterRestart", "firstRuntimeLogs", "secondRuntimeLogs",
    }, "bootstrap credential lifecycle")
    for name in ("firstLogin", "secondLogin"):
        login = _object(credential.get(name), f"bootstrap credential {name}")
        if login != {"status": 200, "sessionCookie": True}:
            raise ToolingEvidenceError("bootstrap administrator login evidence differs")
    before = credential.get("passwordHashBeforeRestart")
    after = credential.get("passwordHashAfterRestart")
    if (
        not isinstance(before, str)
        or SHA256.fullmatch(before) is None
        or after != before
        or credential.get("environmentPasswordRemovedBeforeRestart") is not True
    ):
        raise ToolingEvidenceError(
            "bootstrap password removal or persisted administrator hash differs"
        )
    log_summaries: dict[str, dict[str, Any]] = {}
    for name in ("firstRuntimeLogs", "secondRuntimeLogs"):
        logs = _object(credential.get(name), f"bootstrap credential {name}")
        _exact(logs, {"byteCount", "sha256", "secretMatches"}, f"bootstrap credential {name}")
        if (
            type(logs.get("byteCount")) is not int
            or logs["byteCount"] < 0
            or not isinstance(logs.get("sha256"), str)
            or SHA256.fullmatch(logs["sha256"]) is None
            or logs.get("secretMatches") != 0
        ):
            raise ToolingEvidenceError("bootstrap runtime log scan differs")
        log_summaries[name] = dict(logs)
    return {
        "firstLoginStatus": 200,
        "secondLoginStatus": 200,
        "passwordHashSha256": before,
        "environmentPasswordRemovedBeforeRestart": True,
        "runtimeLogSecretMatches": 0,
        "runtimeLogSha256": {
            "first": log_summaries["firstRuntimeLogs"]["sha256"],
            "second": log_summaries["secondRuntimeLogs"]["sha256"],
        },
    }


def _runtime_identity(path: Path) -> tuple[dict[str, Any], bytes]:
    identity, payload = _load_private(path, "tooling runtime identity", 1024 * 1024)
    release = _object(identity.get("release"), "runtime identity release")
    images = _object(identity.get("images"), "runtime identity images")
    if identity.get("schemaVersion") != 2 or identity.get("status") != "PASS":
        raise ToolingEvidenceError("runtime identity prerequisite is not PASS")
    return {"release": release, "images": images}, payload


def validate(
    report_path: Path,
    candidate_root: Path,
    runtime_identity_path: Path,
    expected_compose_project: str,
    output: Path | None,
) -> dict[str, Any]:
    report, report_payload = _load_private(report_path, "tooling lifecycle report")
    _exact(report, {
        "schemaVersion", "evidenceType", "status", "acceptanceIds", "observedAt",
        "candidate", "runtime", "doctor", "lifecycle",
    }, "tooling lifecycle report")
    if report.get("schemaVersion") != 1 \
            or report.get("evidenceType") != "toolingLifecycleRuntime" \
            or report.get("status") != "PASS" \
            or report.get("acceptanceIds") != [
                "AC-02", "AC-37", "V2-AC-16", "V2-AC-17",
            ]:
        raise ToolingEvidenceError("tooling lifecycle report contract differs")
    observed_at = _timestamp(report.get("observedAt"))
    candidate, source_hashes = _candidate(
        candidate_root, _object(report.get("candidate"), "tooling candidate")
    )
    runtime = _object(report.get("runtime"), "tooling runtime")
    _exact(runtime, {"composeProject", "images", "ports"}, "tooling runtime")
    project = runtime.get("composeProject")
    if project != expected_compose_project or not isinstance(project, str) \
            or PROJECT.fullmatch(project) is None:
        raise ToolingEvidenceError("tooling Compose project binding differs")
    references = _object(runtime.get("images"), "tooling image references")
    if set(references) != SERVICES or any(
        not isinstance(value, str) or REFERENCE.fullmatch(value) is None
        for value in references.values()
    ):
        raise ToolingEvidenceError("tooling image reference inventory differs")
    ports = _object(runtime.get("ports"), "tooling ports")
    if set(ports) != {"mysql", "redis", "app", "nginx"} \
            or len(set(ports.values())) != 4 \
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 65535
                   for value in ports.values()):
        raise ToolingEvidenceError("tooling port inventory differs")

    doctor = _object(report.get("doctor"), "tooling doctor")
    _exact(doctor, {"checks", "outputSha256"}, "tooling doctor")
    checks = _object(doctor.get("checks"), "tooling doctor checks")
    if set(checks) != EXPECTED_DOCTOR_CHECKS \
            or not isinstance(doctor.get("outputSha256"), str) \
            or SHA256.fullmatch(doctor["outputSha256"]) is None:
        raise ToolingEvidenceError("tooling doctor inventory differs")
    for name, raw in checks.items():
        check = _object(raw, f"tooling doctor check {name}")
        _exact(check, {"status", "detail", "action"}, f"tooling doctor check {name}")
        if check.get("status") != "PASS" \
                or not all(isinstance(check.get(field), str) and 0 < len(check[field]) <= 2048
                           for field in ("detail", "action")):
            raise ToolingEvidenceError("tooling doctor check is not actionable PASS")

    lifecycle = _object(report.get("lifecycle"), "tooling lifecycle")
    _exact(lifecycle, {
        "initial", "firstUp", "businessPersistence", "bootstrapCredential",
        "defaultDown", "rejections", "afterRejections", "secondUp",
        "confirmedVolumeDelete",
    }, "tooling lifecycle")
    _empty_snapshot(lifecycle.get("initial"), "initial tooling resources")
    first_images = _up_snapshot(lifecycle.get("firstUp"), project, "first tooling up")
    bootstrap_credential = _bootstrap_credential(
        lifecycle.get("bootstrapCredential")
    )
    business = _object(lifecycle.get("businessPersistence"), "business persistence")
    _exact(business, {"beforeRestart", "afterRestart"}, "business persistence")
    before_restart = _business_record(
        business.get("beforeRestart"), project, "business row before restart",
    )
    preserved = _preserved_snapshot(lifecycle.get("defaultDown"), project, "default tooling down")
    rejections = _object(lifecycle.get("rejections"), "tooling deletion rejections")
    if rejections != {
        "confirmationWithoutVolumes": 2,
        "wrongProjectConfirmation": 2,
        "missingNonInteractiveConfirmation": 3,
    }:
        raise ToolingEvidenceError("tooling volume deletion rejection contract differs")
    if lifecycle.get("afterRejections") != preserved:
        raise ToolingEvidenceError("rejected deletion changed preserved resources")
    second_images = _up_snapshot(lifecycle.get("secondUp"), project, "second tooling up")
    if first_images != second_images:
        raise ToolingEvidenceError("tooling restart used different image identities")
    after_restart = _business_record(
        business.get("afterRestart"), project, "business row after restart",
    )
    if after_restart != before_restart:
        raise ToolingEvidenceError("business row changed across tooling restart")
    _empty_snapshot(lifecycle.get("confirmedVolumeDelete"), "confirmed tooling deletion")

    identity, identity_payload = _runtime_identity(runtime_identity_path)
    release = identity["release"]
    if release.get("gitCommit") != candidate["gitCommit"] \
            or release.get("version") != candidate["releaseVersion"]:
        raise ToolingEvidenceError("tooling evidence and runtime release identity differ")
    identity_images = identity["images"]
    for service in SERVICES:
        image = _object(identity_images.get(service), f"runtime identity {service} image")
        if image.get("reference") != references[service] \
                or image.get("imageId") != first_images[service]:
            raise ToolingEvidenceError(f"tooling {service} image differs from runtime identity")

    summary = {
        "schemaVersion": 1,
        "acceptanceIds": ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"],
        "status": "PASS",
        "observedAt": observed_at,
        "candidate": candidate,
        "runtime": {
            "composeProject": project,
            "images": {
                service: {
                    "reference": references[service],
                    "imageId": first_images[service],
                }
                for service in sorted(SERVICES)
            },
            "runtimeIdentitySha256": hashlib.sha256(identity_payload).hexdigest(),
            "businessPersistence": before_restart,
            "bootstrapCredential": bootstrap_credential,
        },
        "checks": {
            "bootstrapAdminLoginPassed": "PASS",
            "bootstrapPasswordRemovedBeforeRestart": "PASS",
            "existingAdminPasswordUnchanged": "PASS",
            "bootstrapSecretAbsentFromRuntimeLogs": "PASS",
            "doctorExactInventory": "PASS",
            "doctorSecretsRedacted": "PASS",
            "doctorActionableResults": "PASS",
            "upWaitedForAllServices": "PASS",
            "defaultDownPreservedVolumes": "PASS",
            "rejectedDeletionWasSideEffectFree": "PASS",
            "restartUsedPreservedVolumes": "PASS",
            "businessDataPersistedAcrossRestart": "PASS",
            "confirmedDeletionRemovedAllResources": "PASS",
            "runtimeImagesMatchReleaseIdentity": "PASS",
        },
        "evidence": {
            "reportSha256": hashlib.sha256(report_payload).hexdigest(),
            "sourceSha256": dict(sorted(source_hashes.items())),
        },
    }
    if output is not None:
        target = output.expanduser().absolute()
        if target.name != SUMMARY_NAME or target.exists() or target.is_symlink() \
                or target.parent.is_symlink() or not target.parent.is_dir() \
                or (os.name == "posix" and stat.S_IMODE(target.parent.stat().st_mode) != 0o700):
            raise ToolingEvidenceError("tooling canonical summary output is unsafe")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_summary_bytes(summary))
    return summary


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    return (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--runtime-identity", required=True, type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate(
            args.report, args.candidate_root, args.runtime_identity,
            args.compose_project, args.output,
        )
    except (ToolingEvidenceError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL tooling-lifecycle-evidence: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": summary["status"], "acceptanceIds": summary["acceptanceIds"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
