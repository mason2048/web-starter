#!/usr/bin/env python3
"""Run a candidate-bound, fail-closed V1 regression ledger.

The orchestrator owns no product behavior.  It composes the existing code
gates and immutable release-runtime acceptance, then maps their narrowly
defined observations to the frozen AC-01..AC-42 baseline.  Missing evidence is
always NOT_COVERED and the process returns non-zero unless every item passes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence

import rehearse_production_fail_fast as production_fail_fast_rehearsal
import validate_production_fail_fast_evidence as production_fail_fast_validator
import v1_regression_supplemental_validators as supplemental_validators


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = REPOSITORY_ROOT / "docs/acceptance/v1-acceptance-baseline.md"
COVERAGE_PATH = REPOSITORY_ROOT / "security/v1-regression-coverage.json"
RELEASE_RUNNER = REPOSITORY_ROOT / "scripts/run_release_runtime_acceptance.sh"
FAIL_FAST_REHEARSAL = REPOSITORY_ROOT / "scripts/rehearse_production_fail_fast.py"

ALLOWED_STATUSES = {"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"}
RUNTIME_CHECKS = {
    "authenticatedOperationalMetrics",
    "emptyVolumesAndMigrations",
    "privateBrowserProjectCrud",
    "privateBrowserAccountSecurity",
    "privateBrowserCredentialLifecycle",
    "oauthPkce",
    "oauthClientCredentials",
    "oauthMultiKeyJwksActiveSigning",
    "publicOperationsEndpointsHidden",
    "patPrivatePublicBoundary",
    "officialMcpSdkPublicOAuth",
    "officialMcpSdkPrivatePat",
    "officialMcpSdkCrudAudit",
    "runtimeVersionIdentity",
    "mysqlReadinessAndLiveness",
    "redisReadinessAndLiveness",
    "auditTraceSearchAndCorrelation",
    "unifiedSevenLayerVerify",
}
VERIFY_LAYERS = {"backend", "frontend", "policy", "container", "browser", "oauth", "mcp"}
BASELINE_ROW = re.compile(r"^\|\s*(AC-[0-9]{2})\s*\|\s*(P[01])\s*\|")
CHECK_ID = re.compile(r"^[a-z][A-Za-z0-9.]{2,127}$")
PRODUCER_ID = re.compile(r"^[a-z][a-z0-9.-]{2,63}$")
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASE_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
ARTIFACT_RELATIVE = re.compile(r"^artifacts/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ARTIFACT_ID = re.compile(r"^[a-z][a-z0-9.-]{2,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

SUPPLEMENTAL_CANDIDATE_FIELDS = {
    "manifestSha256",
    "gitCommit",
    "gitTree",
    "sourceArchiveSha256",
    "releaseTag",
    "releaseVersion",
}
SUPPLEMENTAL_ARTIFACT_FIELDS = {
    "schemaVersion",
    "suite",
    "producer",
    "check",
    "candidate",
    "observations",
}

SENSITIVE_OUTPUT = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:password|access_token|refresh_token|client_secret|code_verifier)"
        r"[\"']?\s*[:=]\s*['\"]?[0-9A-Za-z_./+:-]{12,}"
    ),
)
SENSITIVE_HEADER_OUTPUT = re.compile(
    r"(?im)\b(?:authorization|cookie|set-cookie)[\"']?\s*[:=][ \t]*([^\r\n]*)"
)

EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 6


class RegressionError(ValueError):
    """A safety or evidence-contract violation."""


@dataclass(frozen=True)
class Requirement:
    check: str
    description: str


@dataclass(frozen=True)
class AcceptanceItem:
    acceptance_id: str
    level: str
    requirements: tuple[Requirement, ...]


@dataclass(frozen=True)
class Coverage:
    baseline_sha256: str
    items: tuple[AcceptanceItem, ...]


@dataclass(frozen=True)
class FileSnapshot:
    payload: bytes
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise RegressionError(f"{label} has unexpected or missing fields")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegressionError(f"{label} must be an object")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RegressionError(f"{label} must be an array")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise RegressionError(f"JSON object repeats field: {key}")
        document[key] = value
    return document


def _parse_json_bytes(payload: bytes, label: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RegressionError(f"{label} is not valid UTF-8 JSON") from exception


def _snapshot_file(
    path: Path,
    label: str,
    *,
    expected_mode: int,
    maximum_bytes: int,
) -> FileSnapshot:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise RegressionError(f"{label} must be a regular non-symbolic-link file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(requested, flags)
    except OSError as exception:
        raise RegressionError(f"{label} cannot be opened safely") from exception
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
            or (os.name == "posix" and stat.S_IMODE(before.st_mode) != expected_mode)
            or (hasattr(os, "getuid") and before.st_uid != os.getuid())
        ):
            raise RegressionError(f"{label} has an unsafe size, owner, or mode")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = requested.lstat()
    identity = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        stat.S_IMODE(before.st_mode),
    )
    if (
        not payload
        or len(payload) > maximum_bytes
        or len(payload) != before.st_size
        or identity != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            stat.S_IMODE(after.st_mode),
        )
        or identity != (
            current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
            stat.S_IMODE(current.st_mode),
        )
    ):
        raise RegressionError(f"{label} changed while it was read")
    return FileSnapshot(
        payload=payload,
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        mode=stat.S_IMODE(before.st_mode),
    )


def _private_input_directory(path: Path, label: str) -> Path:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_dir():
        raise RegressionError(f"{label} must be a real directory")
    resolved = requested.resolve(strict=True)
    metadata = resolved.stat()
    if (
        (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        or _is_inside(resolved, REPOSITORY_ROOT.resolve())
    ):
        raise RegressionError(f"{label} must be a private repository-external directory")
    return resolved


def _verify_snapshot(path: Path, snapshot: FileSnapshot, label: str) -> None:
    if _snapshot_file(
        path,
        label,
        expected_mode=snapshot.mode,
        maximum_bytes=max(snapshot.size, 1),
    ) != snapshot:
        raise RegressionError(f"{label} changed during validation")


def _load_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise RegressionError(f"{label} must be a regular non-symbolic-link file")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RegressionError(f"{label} is not valid UTF-8 JSON") from exception


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise RegressionError(f"{label} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exception:
        raise RegressionError(f"{label} must be a timezone-aware timestamp") from exception
    if parsed.tzinfo is None:
        raise RegressionError(f"{label} must be a timezone-aware timestamp")
    return parsed.astimezone(timezone.utc)


def _prepare_output_directory(path: Path) -> Path:
    repository = REPOSITORY_ROOT.resolve()
    if path.is_symlink():
        raise RegressionError("output directory must not be a symbolic link")
    resolved = path.expanduser().resolve()
    if _is_inside(resolved, repository) or _is_inside(repository, resolved):
        raise RegressionError("output directory must stay outside the repository")
    if resolved.exists():
        if not resolved.is_dir() or any(resolved.iterdir()):
            raise RegressionError("output directory must be absent or an empty real directory")
    else:
        resolved.mkdir(parents=True, mode=0o700)
    resolved.chmod(0o700)
    return resolved


def _private_directory(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        raise RegressionError("an evidence subdirectory already exists")
    path.mkdir(mode=0o700)
    return path


def _write_private(path: Path, content: bytes) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise RegressionError("evidence parent must be a real directory")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _write_private_json(path: Path, value: Any) -> None:
    document = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_private(path, document.encode("utf-8"))


def _git_bytes(arguments: Sequence[str], root: Path = REPOSITORY_ROOT) -> bytes:
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
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    try:
        return subprocess.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                *arguments,
            ],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exception:
        raise RegressionError("Git identity inspection failed") from exception


def _untracked_identity(root: Path) -> tuple[str, int]:
    names = [
        name for name in _git_bytes(
            ["ls-files", "--others", "--exclude-standard", "-z"], root
        ).split(b"\0") if name
    ]
    names.sort()
    untracked_digest = hashlib.sha256()
    for encoded_name in names:
        path = root / os.fsdecode(encoded_name)
        untracked_digest.update(len(encoded_name).to_bytes(8, "big"))
        untracked_digest.update(encoded_name)
        if path.is_symlink():
            content = os.fsencode(os.readlink(path))
        elif path.is_file():
            content = path.read_bytes()
        else:
            raise RegressionError("an untracked source path is not a regular file")
        untracked_digest.update(len(content).to_bytes(8, "big"))
        untracked_digest.update(content)
    return untracked_digest.hexdigest(), len(names)


def _source_identity() -> dict[str, Any]:
    commit = _git_bytes(["rev-parse", "HEAD"]).decode("ascii").strip()
    if not COMMIT.fullmatch(commit):
        raise RegressionError("Git HEAD is not a full object identifier")
    tree = _git_bytes(["rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
    if not COMMIT.fullmatch(tree):
        raise RegressionError("Git HEAD tree is not a full object identifier")
    source_archive_sha256 = _sha256_bytes(
        _git_bytes(["archive", "--format=tar", commit])
    )
    index_records = [
        record
        for record in _git_bytes(["ls-files", "-v", "-z"]).split(b"\0")
        if record
    ]
    index_normal = bool(index_records) and all(
        record.startswith(b"H ") for record in index_records
    )
    diff = _git_bytes(["diff", "--binary", "--no-ext-diff", "HEAD", "--"])
    untracked_sha, untracked_count = _untracked_identity(REPOSITORY_ROOT)
    return {
        "gitCommit": commit,
        "gitTree": tree,
        "sourceArchiveSha256": source_archive_sha256,
        "indexNormal": index_normal,
        "trackedDiffSha256": _sha256_bytes(diff),
        "untrackedSourceSha256": untracked_sha,
        "untrackedSourceCount": untracked_count,
        "clean": not diff and untracked_count == 0 and index_normal,
    }


def _reference_identity(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_dir():
        raise RegressionError("reference repository must be a real directory")
    resolved = path.resolve()
    if _is_inside(resolved, REPOSITORY_ROOT.resolve()) or _is_inside(
        REPOSITORY_ROOT.resolve(), resolved
    ):
        raise RegressionError("reference repository must be separate from this repository")
    untracked_sha, untracked_count = _untracked_identity(resolved)
    return {
        "head": _sha256_bytes(_git_bytes(["rev-parse", "HEAD"], resolved)),
        "status": _sha256_bytes(_git_bytes(["status", "--porcelain=v1", "-z"], resolved)),
        "worktree": _sha256_bytes(_git_bytes(["diff", "--binary", "--no-ext-diff"], resolved)),
        "index": _sha256_bytes(_git_bytes(["diff", "--cached", "--binary", "--no-ext-diff"], resolved)),
        "untracked": untracked_sha,
        "untrackedCount": untracked_count,
    }


def _load_baseline() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        match = BASELINE_ROW.match(line)
        if match:
            acceptance_id, level = match.groups()
            if acceptance_id in result:
                raise RegressionError("the V1 baseline contains a duplicate acceptance ID")
            result[acceptance_id] = level
    expected = {f"AC-{number:02d}" for number in range(1, 43)}
    if set(result) != expected:
        raise RegressionError("the V1 baseline is not the frozen AC-01..AC-42 set")
    return result


def _load_coverage() -> Coverage:
    document = _require_object(_load_json(COVERAGE_PATH, "coverage map"), "coverage map")
    _require_exact_keys(
        document,
        {"schemaVersion", "suite", "baseline", "baselineSha256", "items"},
        "coverage map",
    )
    if document["schemaVersion"] != 1 or document["suite"] != "v1":
        raise RegressionError("coverage map has an unsupported identity")
    if document["baseline"] != "docs/acceptance/v1-acceptance-baseline.md":
        raise RegressionError("coverage map points to an unexpected baseline")
    baseline_sha = _sha256(BASELINE_PATH)
    if document["baselineSha256"] != baseline_sha:
        raise RegressionError("coverage map is stale relative to the frozen baseline")
    baseline = _load_baseline()
    items: list[AcceptanceItem] = []
    seen: set[str] = set()
    for raw_item in _require_list(document["items"], "coverage items"):
        item = _require_object(raw_item, "coverage item")
        _require_exact_keys(item, {"id", "level", "requirements"}, "coverage item")
        acceptance_id = item["id"]
        if acceptance_id not in baseline or acceptance_id in seen:
            raise RegressionError("coverage map has an unknown or duplicate acceptance ID")
        if item["level"] != baseline[acceptance_id]:
            raise RegressionError("coverage map level does not match the baseline")
        requirements: list[Requirement] = []
        requirement_ids: set[str] = set()
        for raw_requirement in _require_list(item["requirements"], "coverage requirements"):
            requirement = _require_object(raw_requirement, "coverage requirement")
            _require_exact_keys(requirement, {"check", "description"}, "coverage requirement")
            check = requirement["check"]
            description = requirement["description"]
            if not isinstance(check, str) or not CHECK_ID.fullmatch(check):
                raise RegressionError("coverage map contains an invalid check ID")
            if check in requirement_ids:
                raise RegressionError("an acceptance item repeats a required check")
            if not isinstance(description, str) or not (8 <= len(description) <= 512):
                raise RegressionError("coverage requirement description is invalid")
            requirement_ids.add(check)
            requirements.append(Requirement(check, description))
        if not requirements:
            raise RegressionError("every acceptance item needs at least one atomic check")
        seen.add(acceptance_id)
        items.append(AcceptanceItem(acceptance_id, item["level"], tuple(requirements)))
    if seen != set(baseline):
        raise RegressionError("coverage map does not contain exactly AC-01..AC-42")
    items.sort(key=lambda item: item.acceptance_id)
    return Coverage(baseline_sha, tuple(items))


def _safe_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "JAVA_HOME", "LANG", "LC_ALL")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment["CI"] = "true"
    return environment


def _contains_sensitive_text(content: str) -> bool:
    if any(pattern.search(content) for pattern in SENSITIVE_OUTPUT):
        return True
    for match in SENSITIVE_HEADER_OUTPUT.finditer(content):
        value = match.group(1).lstrip()
        if value and not value.startswith(("{", "[")):
            return True
    return False


def _contains_sensitive_output(path: Path) -> bool:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    return _contains_sensitive_text(content)


def _discard_sensitive_evidence(output: Path, errors: list[str]) -> None:
    discarded = False
    for path in output.rglob("*"):
        if path.is_file() and _contains_sensitive_output(path):
            path.unlink()
            discarded = True
    if discarded:
        errors.append("sensitive-evidence-discarded")


def _run_logged_gate(
    output: Path,
    label: str,
    command: Sequence[str],
    *,
    cwd: Path = REPOSITORY_ROOT,
    timeout: int = 1800,
) -> tuple[str, str | None, str | None]:
    logs = output / "logs"
    if not logs.exists():
        logs.mkdir(mode=0o700)
    log_path = logs / f"{label}.log"
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            try:
                result = subprocess.run(
                    list(command), cwd=cwd, env=_safe_environment(), stdout=stream,
                    stderr=subprocess.STDOUT, timeout=timeout, check=False,
                )
                status = "PASS" if result.returncode == 0 else "FAIL"
                error = None if result.returncode == 0 else f"{label}-failed"
            except FileNotFoundError:
                status, error = "ENV_REQUIRED", f"{label}-environment-required"
            except subprocess.TimeoutExpired:
                status, error = "FAIL", f"{label}-timed-out"
    except BaseException:
        log_path.unlink(missing_ok=True)
        raise
    if _contains_sensitive_output(log_path):
        log_path.unlink(missing_ok=True)
        return "FAIL", None, f"{label}-sensitive-output-discarded"
    return status, _sha256(log_path), error


def _allocate_loopback_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
        ports = [listener.getsockname()[1] for listener in sockets]
        if len(set(ports)) != count:
            raise RegressionError("unable to reserve distinct loopback ports")
        return ports
    finally:
        for listener in sockets:
            listener.close()


def _isolated_release_suffix() -> str:
    for _ in range(8):
        suffix = secrets.token_hex(6)
        project = f"web-starter-release-v1reg{suffix}-1"
        occupied = False
        for resource, arguments in (
            ("container", ["ps", "-aq"]),
            ("volume", ["volume", "ls", "-q"]),
            ("network", ["network", "ls", "-q"]),
        ):
            try:
                result = subprocess.run(
                    [
                        "docker", *arguments, "--filter",
                        f"label=com.docker.compose.project={project}",
                    ],
                    env=_safe_environment(), stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=20, check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exception:
                raise RegressionError("Docker isolation preflight is unavailable") from exception
            if result.returncode != 0:
                raise RegressionError("Docker isolation preflight is unavailable")
            if result.stdout.strip():
                occupied = True
                break
        if not occupied:
            return suffix
    raise RegressionError("no unused random release project identity was found")


def _run_quiet_process(
    command: Sequence[str], *, cwd: Path, environment: Mapping[str, str], timeout: int
) -> int:
    try:
        process = subprocess.Popen(
            list(command), cwd=cwd, env=dict(environment), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except FileNotFoundError:
        return 127
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        try:
            os.killpg(process.pid, signal.SIGTERM)
            return process.wait(timeout=30)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            return 124


def _load_candidate(path: Path) -> tuple[dict[str, Any], str]:
    document = _require_object(_load_json(path, "candidate manifest"), "candidate manifest")
    _require_exact_keys(document, {"schemaVersion", "release", "images"}, "candidate manifest")
    if document["schemaVersion"] != 1:
        raise RegressionError("candidate manifest has an unsupported schema version")
    release = _require_object(document["release"], "candidate release")
    _require_exact_keys(release, {"tag", "version", "gitCommit"}, "candidate release")
    if (
        not isinstance(release["version"], str)
        or not RELEASE_VERSION.fullmatch(release["version"])
        or release["version"].endswith("-SNAPSHOT")
        or release["tag"] != "v" + release["version"]
        or not isinstance(release["gitCommit"], str)
        or not COMMIT.fullmatch(release["gitCommit"])
    ):
        raise RegressionError("candidate release identity is invalid")
    images = _require_object(document["images"], "candidate images")
    _require_exact_keys(images, {"app", "nginx", "mysql", "redis"}, "candidate images")
    for name in ("app", "nginx", "mysql", "redis"):
        image = _require_object(images[name], f"candidate {name} image")
        _require_exact_keys(image, {"reference", "digest"}, f"candidate {name} image")
        reference, digest = image["reference"], image["digest"]
        if (
            not isinstance(reference, str)
            or not reference
            or "@" in reference
            or any(character.isspace() for character in reference)
            or not isinstance(digest, str)
            or not DIGEST.fullmatch(digest)
        ):
            raise RegressionError(f"candidate {name} image is not immutable")
    return document, _sha256(path)


def _effective_image(candidate: Mapping[str, Any], name: str) -> str:
    image = candidate["images"][name]
    return f"{image['reference']}@{image['digest']}"


def _verify_candidate_source(candidate: Mapping[str, Any], identity: Mapping[str, Any]) -> None:
    if not identity["clean"]:
        raise RegressionError("full regression requires a clean committed source tree")
    if candidate["release"]["gitCommit"] != identity["gitCommit"]:
        raise RegressionError("candidate manifest commit differs from the checked-out source")
    tag_reference = f"refs/tags/{candidate['release']['tag']}"
    if (
        _git_bytes(["cat-file", "-t", tag_reference]).decode("ascii").strip() != "tag"
        or _git_bytes(["rev-parse", f"{tag_reference}^{{commit}}"]).decode("ascii").strip()
        != identity["gitCommit"]
    ):
        raise RegressionError("full regression requires an annotated candidate tag at HEAD")


def _supplemental_candidate_binding(
    candidate_sha256: str,
    identity: Mapping[str, Any],
) -> dict[str, str]:
    git_commit = identity.get("gitCommit")
    git_tree = identity.get("gitTree")
    source_archive_sha256 = identity.get("sourceArchiveSha256")
    release_tag = identity.get("releaseTag")
    release_version = identity.get("releaseVersion")
    if (
        not SHA256.fullmatch(candidate_sha256)
        or not isinstance(git_commit, str)
        or not COMMIT.fullmatch(git_commit)
        or not isinstance(git_tree, str)
        or not COMMIT.fullmatch(git_tree)
        or not isinstance(source_archive_sha256, str)
        or not SHA256.fullmatch(source_archive_sha256)
        or not isinstance(release_version, str)
        or not RELEASE_VERSION.fullmatch(release_version)
        or release_version.endswith("-SNAPSHOT")
        or release_tag != f"v{release_version}"
    ):
        raise RegressionError("supplemental candidate source identity is invalid")
    return {
        "manifestSha256": candidate_sha256,
        "gitCommit": git_commit,
        "gitTree": git_tree,
        "sourceArchiveSha256": source_archive_sha256,
        "releaseTag": release_tag,
        "releaseVersion": release_version,
    }


def _record_check(
    checks: dict[str, str],
    check_sources: dict[str, dict[str, Any]],
    check: str,
    status: str,
    producer: str,
    source_sha256: str | None,
) -> None:
    if check in checks:
        raise RegressionError("two evidence producers supplied the same atomic check")
    if status not in ALLOWED_STATUSES:
        raise RegressionError("an evidence producer supplied an invalid status")
    checks[check] = status
    source: dict[str, Any] = {"producer": producer}
    if source_sha256 is not None:
        source["sha256"] = source_sha256
    check_sources[check] = source


def _run_non_container_gates(
    output: Path,
    checks: dict[str, str],
    check_sources: dict[str, dict[str, Any]],
    errors: list[str],
    forbidden_terms_file: Path | None,
) -> None:
    commands = (
        ("backend-verify", "gate.backendVerify", [str(REPOSITORY_ROOT / "mvnw"), "--batch-mode", "--no-transfer-progress", "verify"]),
        ("frontend-lint", "gate.frontendLint", ["pnpm", "lint"]),
        ("frontend-typecheck", "gate.frontendTypecheck", ["pnpm", "typecheck"]),
        ("frontend-test", "gate.frontendTest", ["pnpm", "test"]),
        ("frontend-build", "gate.frontendBuild", ["pnpm", "build"]),
        ("python-tests", "gate.pythonTests", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"]),
        ("repository-secrets", "gate.repositorySecretScan", [sys.executable, "-B", "scripts/repository_policy.py", "secrets"]),
    )
    for label, check, command in commands:
        cwd = REPOSITORY_ROOT / "web-starter-web" if label.startswith("frontend-") else REPOSITORY_ROOT
        status, source_sha, error = _run_logged_gate(output, label, command, cwd=cwd)
        _record_check(checks, check_sources, check, status, "orchestrator.non-container", source_sha)
        if error is not None:
            errors.append(error)
    if forbidden_terms_file is None:
        _record_check(
            checks, check_sources, "gate.forbiddenTermScan", "NOT_COVERED",
            "orchestrator.non-container", None,
        )
    else:
        status, source_sha, error = _run_logged_gate(
            output,
            "forbidden-terms",
            [
                sys.executable, "-B", "scripts/repository_policy.py", "forbidden",
                "--forbidden-terms-file", str(forbidden_terms_file),
            ],
        )
        _record_check(
            checks, check_sources, "gate.forbiddenTermScan", status,
            "orchestrator.non-container", source_sha,
        )
        if error is not None:
            errors.append(error)


def _run_module_dry_run(
    output: Path,
    checks: dict[str, str],
    check_sources: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    suffix = secrets.token_hex(4)
    permission_base = 700000 + secrets.randbelow(50000) * 4
    menu_id = 950000 + secrets.randbelow(40000)
    status, source_sha, error = _run_logged_gate(
        output,
        "module-dry-run",
        [
            str(REPOSITORY_ROOT / "bin/web-starter"), "module", "dry-run",
            "--workspace", str(REPOSITORY_ROOT), "--name", f"reg{suffix}",
            "--label", "Regression", "--migration-version",
            datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "--permission-id-base", str(permission_base), "--menu-id", str(menu_id),
            "--with-mcp",
        ],
    )
    _record_check(
        checks, check_sources, "tooling.moduleDryRun", status,
        "orchestrator.module-dry-run", source_sha,
    )
    if error is not None:
        errors.append(error)


def _run_release_runtime(
    output: Path,
    candidate: Mapping[str, Any],
    checks: dict[str, str],
    check_sources: dict[str, dict[str, Any]],
    errors: list[str],
    timeout: int,
) -> None:
    def record_runtime_environment_required() -> None:
        for runtime_check in sorted(RUNTIME_CHECKS):
            _record_check(
                checks, check_sources, f"runtime.{runtime_check}", "ENV_REQUIRED",
                "release-runtime-acceptance", None,
            )

    artifact_root = _private_directory(output / "release-runtime")
    private_port, public_port, management_port = _allocate_loopback_ports(3)
    try:
        suffix = _isolated_release_suffix()
    except RegressionError:
        record_runtime_environment_required()
        errors.append("release-runtime-environment-required")
        return
    compose_project = f"web-starter-v1reg-{suffix}"
    mcp_crud_trace_prefix = "release-sdk"
    environment = _safe_environment()
    environment.update({
        "WEB_STARTER_RELEASE_ARTIFACT_DIR": str(artifact_root),
        "WEB_STARTER_RELEASE_TAG": candidate["release"]["tag"],
        "WEB_STARTER_RELEASE_VERSION": candidate["release"]["version"],
        "GITHUB_SHA": candidate["release"]["gitCommit"],
        "GITHUB_RUN_ID": f"v1reg{suffix}",
        "GITHUB_RUN_ATTEMPT": "1",
        "WEB_STARTER_APP_IMAGE": candidate["images"]["app"]["reference"],
        "WEB_STARTER_APP_DIGEST": candidate["images"]["app"]["digest"],
        "WEB_STARTER_NGINX_IMAGE": candidate["images"]["nginx"]["reference"],
        "WEB_STARTER_NGINX_DIGEST": candidate["images"]["nginx"]["digest"],
        "WEB_STARTER_MYSQL_IMAGE": _effective_image(candidate, "mysql"),
        "WEB_STARTER_REDIS_IMAGE": _effective_image(candidate, "redis"),
        "WEB_STARTER_ACCEPTANCE_PRIVATE_PORT": str(private_port),
        "WEB_STARTER_ACCEPTANCE_PUBLIC_PORT": str(public_port),
        "WEB_STARTER_ACCEPTANCE_MANAGEMENT_PORT": str(management_port),
        "WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT": compose_project,
        "WEB_STARTER_ACCEPTANCE_PUBLIC_HOSTNAME": f"mcp-{suffix}.release.webstarter.test",
        "WEB_STARTER_ACCEPTANCE_PRIVATE_MCP_HOSTNAME": f"private-{suffix}.release.webstarter.test",
    })
    started = datetime.now(timezone.utc)
    exit_code = _run_quiet_process(
        [str(RELEASE_RUNNER)], cwd=REPOSITORY_ROOT, environment=environment, timeout=timeout
    )
    for path in artifact_root.rglob("*"):
        if path.is_symlink():
            errors.append("release-runtime-produced-symbolic-link")
            return
        path.chmod(0o700 if path.is_dir() else 0o600)
    if exit_code != 0:
        if exit_code == 127:
            record_runtime_environment_required()
            errors.append("release-runtime-environment-required")
        else:
            errors.append("release-runtime-failed")
        return
    evidence_path = artifact_root / "release-runtime-acceptance.json"
    try:
        document = _require_object(
            _load_json(evidence_path, "release runtime evidence"), "release runtime evidence"
        )
        _require_exact_keys(
            document,
            {
                "schemaVersion", "status", "observedAt", "release", "images", "identity",
                "checks", "unifiedVerify",
            },
            "release runtime evidence",
        )
        observed = _parse_timestamp(document["observedAt"], "release runtime observedAt")
        expected_release = dict(candidate["release"])
        expected_images = {
            "app": _effective_image(candidate, "app"),
            "nginx": _effective_image(candidate, "nginx"),
        }
        expected_identity = {
            "javaSpecificationVersion": "21",
            "applicationVersion": candidate["release"]["version"],
            "buildVersion": candidate["release"]["version"],
            "composeProject": compose_project,
            "mcpCrudTracePrefix": mcp_crud_trace_prefix,
            "appImage": expected_images["app"],
            "nginxImage": expected_images["nginx"],
            "appOciVersion": candidate["release"]["version"],
            "appOciRevision": candidate["release"]["gitCommit"],
            "nginxOciVersion": candidate["release"]["version"],
            "nginxOciRevision": candidate["release"]["gitCommit"],
        }
        runtime_checks = _require_object(document["checks"], "release runtime checks")
        unified = _require_object(document["unifiedVerify"], "release unified verify evidence")
        _require_exact_keys(
            unified, {"path", "sha256", "status", "layers"},
            "release unified verify evidence",
        )
        if unified.get("path") != "unified-verify-summary.json":
            raise RegressionError("release unified verify path is not canonical")
        unified_path = artifact_root / "unified-verify-summary.json"
        if unified_path.is_symlink() or not unified_path.is_file():
            raise RegressionError("release unified verify summary is missing or symbolic")
        unified_summary = _require_object(
            _load_json(unified_path, "release unified verify summary"),
            "release unified verify summary",
        )
        _require_exact_keys(
            unified_summary, {"schemaVersion", "status", "layers"},
            "release unified verify summary",
        )
        unified_layers = _require_object(
            unified_summary["layers"], "release unified verify layers"
        )
        _require_exact_keys(unified_layers, VERIFY_LAYERS, "release unified verify layers")
        expected_layers = {name: "PASS" for name in sorted(VERIFY_LAYERS)}
        expected_unified = {
            "path": "unified-verify-summary.json",
            "sha256": _sha256(unified_path),
            "status": "PASS",
            "layers": expected_layers,
        }
        if (
            document["schemaVersion"] != 1
            or document["status"] != "PASS"
            or observed < started - timedelta(seconds=5)
            or document["release"] != expected_release
            or document["images"] != expected_images
            or document["identity"] != expected_identity
            or set(runtime_checks) != RUNTIME_CHECKS
            or any(value != "PASS" for value in runtime_checks.values())
            or unified_summary != {
                "schemaVersion": 1, "status": "PASS", "layers": expected_layers
            }
            or unified != expected_unified
        ):
            raise RegressionError("release runtime evidence is stale, partial, or candidate-mismatched")
    except RegressionError:
        errors.append("release-runtime-evidence-invalid")
        return
    source_sha = _sha256(evidence_path)
    for runtime_check in sorted(RUNTIME_CHECKS):
        _record_check(
            checks, check_sources, f"runtime.{runtime_check}", "PASS",
            "release-runtime-acceptance", source_sha,
        )


def _run_fail_fast_rehearsal(
    output: Path,
    candidate: Mapping[str, Any],
    checks: dict[str, str],
    check_sources: dict[str, dict[str, Any]],
    errors: list[str],
    timeout: int,
) -> None:
    evidence_root = output / "production-fail-fast"
    image = _effective_image(candidate, "app")
    exit_code = _run_quiet_process(
        [
            sys.executable, "-B", str(FAIL_FAST_REHEARSAL), "--image", image,
            "--output-dir", str(evidence_root), "--timeout-seconds", "60",
        ],
        cwd=REPOSITORY_ROOT,
        environment=_safe_environment(),
        timeout=timeout,
    )
    if exit_code != 0:
        status = "ENV_REQUIRED" if exit_code in {2, 127} else "FAIL"
        _record_check(
            checks, check_sources, "rehearsal.productionSecurityFailFast", status,
            "production-fail-fast-rehearsal", None,
        )
        errors.append("production-fail-fast-environment-required" if status == "ENV_REQUIRED" else "production-fail-fast-failed")
        return
    try:
        evidence_path = evidence_root / "v2-ac29-production-fail-fast.json"
        candidate_identity = production_fail_fast_rehearsal.capture_candidate(
            REPOSITORY_ROOT
        )
        image_identity = production_fail_fast_rehearsal.inspect_local_app_image(
            image, candidate_identity
        )
        validation = production_fail_fast_validator.validate_evidence(
            evidence_path,
            expected_app_reference=image,
            expected_app_image_id=image_identity.image_id,
            repository_root=REPOSITORY_ROOT,
            require_pass=True,
        )
        if validation.get("status") != "PASS":
            raise RegressionError("production fail-fast evidence is not passing")
        for path in evidence_root.rglob("*"):
            if path.is_symlink():
                raise RegressionError("production fail-fast evidence contains a symbolic link")
            path.chmod(0o700 if path.is_dir() else 0o600)
    except (
        RegressionError,
        production_fail_fast_rehearsal.RehearsalError,
        production_fail_fast_validator.EvidenceValidationError,
        OSError,
        ValueError,
    ):
        _record_check(
            checks, check_sources, "rehearsal.productionSecurityFailFast", "FAIL",
            "production-fail-fast-rehearsal", None,
        )
        errors.append("production-fail-fast-evidence-invalid")
        return
    _record_check(
        checks, check_sources, "rehearsal.productionSecurityFailFast", "PASS",
        "production-fail-fast-rehearsal", _sha256(evidence_path),
    )


def _load_observations(
    paths: Iterable[Path],
    candidate_sha256: str,
    candidate_identity: Mapping[str, Any],
    allowed_checks: set[str],
    checks: dict[str, str],
    check_sources: dict[str, dict[str, Any]],
) -> None:
    expected_candidate = _supplemental_candidate_binding(
        candidate_sha256, candidate_identity
    )
    for path in paths:
        bundle_root = _private_input_directory(
            path.expanduser().absolute().parent, "supplemental observation bundle"
        )
        artifacts_root = _private_input_directory(
            bundle_root / "artifacts", "supplemental artifact directory"
        )
        observation_path = bundle_root / path.name
        observation_snapshot = _snapshot_file(
            observation_path,
            "supplemental observation",
            expected_mode=0o600,
            maximum_bytes=1024 * 1024,
        )
        document = _require_object(
            _parse_json_bytes(observation_snapshot.payload, "supplemental observation"),
            "supplemental observation",
        )
        _require_exact_keys(
            document,
            {
                "schemaVersion", "suite", "candidate", "producer", "observedAt",
                "artifacts", "checks",
            },
            "supplemental observation",
        )
        producer = document["producer"]
        candidate = _require_object(
            document["candidate"], "supplemental candidate binding"
        )
        _require_exact_keys(
            candidate,
            SUPPLEMENTAL_CANDIDATE_FIELDS,
            "supplemental candidate binding",
        )
        if (
            document["schemaVersion"] != 2
            or document["suite"] != "v1"
            or candidate != expected_candidate
            or not isinstance(producer, str)
            or not PRODUCER_ID.fullmatch(producer)
        ):
            raise RegressionError("supplemental observation has the wrong identity")
        _parse_timestamp(document["observedAt"], "supplemental observedAt")
        artifacts: dict[str, tuple[str, Path, FileSnapshot]] = {}
        for raw_artifact in _require_list(document["artifacts"], "supplemental artifacts"):
            artifact = _require_object(raw_artifact, "supplemental artifact")
            _require_exact_keys(artifact, {"id", "path", "sha256"}, "supplemental artifact")
            artifact_id, relative, expected_sha = artifact["id"], artifact["path"], artifact["sha256"]
            if (
                not isinstance(artifact_id, str)
                or not ARTIFACT_ID.fullmatch(artifact_id)
                or artifact_id in artifacts
                or not isinstance(relative, str)
                or not ARTIFACT_RELATIVE.fullmatch(relative)
                or not isinstance(expected_sha, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_sha)
            ):
                raise RegressionError("supplemental artifact metadata is invalid")
            artifact_path = bundle_root / relative
            if artifact_path.parent.resolve(strict=True) != artifacts_root:
                raise RegressionError("supplemental artifact escaped its private directory")
            artifact_snapshot = _snapshot_file(
                artifact_path,
                "supplemental artifact",
                expected_mode=0o600,
                maximum_bytes=4 * 1024 * 1024,
            )
            resolved_artifact = artifact_path.resolve(strict=True)
            if (
                not _is_inside(resolved_artifact, bundle_root)
                or _sha256_bytes(artifact_snapshot.payload) != expected_sha
            ):
                raise RegressionError("supplemental artifact escaped or checksum-drifted")
            artifacts[artifact_id] = (expected_sha, resolved_artifact, artifact_snapshot)
        if not artifacts:
            raise RegressionError("supplemental observation must contain artifacts")
        if {entry.name for entry in bundle_root.iterdir()} != {path.name, "artifacts"}:
            raise RegressionError("supplemental observation bundle contains unexpected entries")
        if {entry.name for entry in artifacts_root.iterdir()} != {
            artifact[1].name for artifact in artifacts.values()
        }:
            raise RegressionError("supplemental artifact directory contains unexpected entries")
        observation_sha = _sha256_bytes(observation_snapshot.payload)
        observed_checks: set[str] = set()
        raw_checks = _require_list(document["checks"], "supplemental checks")
        if not raw_checks:
            raise RegressionError("supplemental observation must contain checks")
        for raw_check in raw_checks:
            check = _require_object(raw_check, "supplemental check")
            _require_exact_keys(check, {"id", "artifactIds"}, "supplemental check")
            check_id = check["id"]
            artifact_ids = _require_list(check["artifactIds"], "supplemental check artifacts")
            if (
                not isinstance(check_id, str)
                or check_id not in allowed_checks
                or not check_id.startswith("supplemental.")
                or check_id in observed_checks
                or not artifact_ids
                or len(set(artifact_ids)) != len(artifact_ids)
                or any(artifact_id not in artifacts for artifact_id in artifact_ids)
            ):
                raise RegressionError("supplemental check metadata is invalid")
            observed_checks.add(check_id)
            evidence_documents: list[dict[str, Any]] = []
            structurally_valid = True
            for artifact_id in artifact_ids:
                _artifact_sha, artifact_path, artifact_snapshot = artifacts[artifact_id]
                try:
                    if _contains_sensitive_text(
                        artifact_snapshot.payload.decode("utf-8", errors="replace")
                    ):
                        raise RegressionError(
                            "supplemental evidence artifact contains sensitive material"
                        )
                    evidence = _require_object(
                        _parse_json_bytes(
                            artifact_snapshot.payload, "supplemental evidence artifact"
                        ),
                        "supplemental evidence artifact",
                    )
                    _require_exact_keys(
                        evidence,
                        SUPPLEMENTAL_ARTIFACT_FIELDS,
                        "supplemental evidence artifact",
                    )
                    evidence_candidate = _require_object(
                        evidence["candidate"],
                        "supplemental artifact candidate binding",
                    )
                    _require_exact_keys(
                        evidence_candidate,
                        SUPPLEMENTAL_CANDIDATE_FIELDS,
                        "supplemental artifact candidate binding",
                    )
                    observations = _require_object(
                        evidence["observations"],
                        "supplemental artifact observations",
                    )
                    if (
                        evidence["schemaVersion"] != 1
                        or evidence["suite"] != "v1"
                        or evidence["producer"] != producer
                        or evidence["check"] != check_id
                        or evidence_candidate != expected_candidate
                        or not observations
                    ):
                        raise RegressionError(
                            "supplemental evidence artifact has the wrong identity"
                        )
                    evidence_documents.append(evidence)
                except RegressionError:
                    structurally_valid = False
                    break

            if not structurally_valid:
                status = "FAIL"
            else:
                try:
                    recomputed = supplemental_validators.validate(
                        producer,
                        check_id,
                        evidence_documents,
                        expected_candidate,
                    )
                except supplemental_validators.SupplementalValidationError:
                    recomputed = "FAIL"
                status = "NOT_COVERED" if recomputed is None else recomputed
            _record_check(
                checks, check_sources, check_id, status, producer,
                _sha256_bytes(
                    (
                        observation_sha
                        + "".join(artifacts[artifact_id][0] for artifact_id in artifact_ids)
                    ).encode("ascii")
                ),
            )
        _verify_snapshot(
            observation_path, observation_snapshot, "supplemental observation"
        )
        for _artifact_id, (_sha, artifact_path, snapshot) in artifacts.items():
            _verify_snapshot(artifact_path, snapshot, "supplemental artifact")
        if {entry.name for entry in bundle_root.iterdir()} != {path.name, "artifacts"} \
                or {entry.name for entry in artifacts_root.iterdir()} != {
                    artifact[1].name for artifact in artifacts.values()
                }:
            raise RegressionError("supplemental observation bundle changed during validation")


def _evaluate(coverage: Coverage, checks: Mapping[str, str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in coverage.items:
        requirements = [
            {"check": requirement.check, "status": checks.get(requirement.check, "NOT_COVERED")}
            for requirement in item.requirements
        ]
        statuses = [requirement["status"] for requirement in requirements]
        if "FAIL" in statuses:
            status = "FAIL"
        elif "ENV_REQUIRED" in statuses:
            status = "ENV_REQUIRED"
        elif "NOT_COVERED" in statuses:
            status = "NOT_COVERED"
        else:
            status = "PASS"
        results.append({
            "id": item.acceptance_id,
            "level": item.level,
            "status": status,
            "requirements": requirements,
        })
    status_counts = {status: 0 for status in ("PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED")}
    level_counts = {level: 0 for level in ("P0", "P1")}
    for result in results:
        status_counts[result["status"]] += 1
        level_counts[result["level"]] += 1
    return results, {"total": len(results), "levels": level_counts, "statuses": status_counts}


def _conclusion(counts: Mapping[str, Any], errors: Sequence[str]) -> str:
    fatal_errors = [error for error in errors if not error.endswith("-environment-required")]
    if fatal_errors or counts["statuses"]["FAIL"]:
        return "FAIL"
    if counts["statuses"]["PASS"] == 42:
        return "PASS"
    return "INCOMPLETE"


def _markdown(ledger: Mapping[str, Any]) -> str:
    lines = [
        "# V1 current-candidate regression ledger",
        "",
        f"- Mode: `{ledger['mode']}`",
        f"- Conclusion: `{ledger['conclusion']}`",
        f"- Candidate commit: `{ledger['source']['gitCommit']}`",
        f"- Baseline SHA-256: `{ledger['baseline']['sha256']}`",
        "",
        "`NOT_COVERED` and `ENV_REQUIRED` are never counted as PASS. Evidence paths and runtime credentials are intentionally omitted.",
        "",
        "| ID | Level | Status | Missing or non-passing atomic checks |",
        "|---|---|---|---|",
    ]
    for result in ledger["results"]:
        gaps = [
            requirement["check"] for requirement in result["requirements"]
            if requirement["status"] != "PASS"
        ]
        lines.append(
            f"| {result['id']} | {result['level']} | {result['status']} | "
            + (", ".join(f"`{gap}`" for gap in gaps) if gaps else "-")
            + " |"
        )
    lines.extend(["", "## Fixed errors", ""])
    if ledger["errors"]:
        lines.extend(f"- `{error}`" for error in ledger["errors"])
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def _write_manifest(output: Path) -> None:
    entries: list[dict[str, Any]] = []
    for path in sorted(output.rglob("*")):
        if path.name == "evidence-manifest.json":
            continue
        if path.is_symlink():
            raise RegressionError("evidence output contains a symbolic link")
        if path.is_dir():
            path.chmod(0o700)
            continue
        path.chmod(0o600)
        entries.append({
            "path": path.relative_to(output).as_posix(),
            "sha256": _sha256(path),
            "mode": format(stat.S_IMODE(path.stat().st_mode), "04o"),
        })
    _write_private_json(output / "evidence-manifest.json", {"schemaVersion": 1, "files": entries})


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the fail-closed current-candidate V1 AC-01..AC-42 regression"
    )
    parser.add_argument("--mode", choices=("plan", "non-container", "full"), default="non-container")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--candidate", type=Path, help="immutable candidate manifest; required by full mode")
    parser.add_argument("--forbidden-terms-file", type=Path)
    parser.add_argument("--reference-repository", type=Path)
    parser.add_argument("--observation", action="append", default=[], type=Path)
    parser.add_argument("--runtime-timeout-seconds", type=int, default=3600)
    parser.add_argument("--fail-fast-timeout-seconds", type=int, default=1800)
    return parser.parse_args(argv)


def run(options: argparse.Namespace) -> tuple[int, Path]:
    if options.runtime_timeout_seconds < 60 or options.runtime_timeout_seconds > 14400:
        raise RegressionError("runtime timeout must be between 60 and 14400 seconds")
    if options.fail_fast_timeout_seconds < 60 or options.fail_fast_timeout_seconds > 3600:
        raise RegressionError("fail-fast timeout must be between 60 and 3600 seconds")
    if options.mode == "full" and options.candidate is None:
        raise RegressionError("full mode requires an immutable candidate manifest")
    if options.mode != "full" and (options.candidate is not None or options.observation):
        raise RegressionError("candidate observations are accepted only in full mode")

    coverage = _load_coverage()
    output = _prepare_output_directory(options.output_dir)
    source_before = _source_identity()
    reference_before = (
        _reference_identity(options.reference_repository)
        if options.reference_repository is not None else None
    )
    candidate: dict[str, Any] | None = None
    candidate_sha: str | None = None
    if options.candidate is not None:
        candidate, candidate_sha = _load_candidate(options.candidate)
        _verify_candidate_source(candidate, source_before)

    checks: dict[str, str] = {}
    check_sources: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    allowed_checks = {
        requirement.check for item in coverage.items for requirement in item.requirements
    }

    if options.mode != "plan":
        _run_non_container_gates(
            output, checks, check_sources, errors, options.forbidden_terms_file
        )
    if options.mode == "full":
        assert candidate is not None and candidate_sha is not None
        _run_module_dry_run(output, checks, check_sources, errors)
        _run_release_runtime(
            output, candidate, checks, check_sources, errors,
            options.runtime_timeout_seconds,
        )
        _run_fail_fast_rehearsal(
            output, candidate, checks, check_sources, errors,
            options.fail_fast_timeout_seconds,
        )
        _load_observations(
            options.observation,
            candidate_sha,
            {
                **source_before,
                "releaseTag": candidate["release"]["tag"],
                "releaseVersion": candidate["release"]["version"],
            },
            allowed_checks,
            checks,
            check_sources,
        )

    _discard_sensitive_evidence(output, errors)

    if reference_before is None:
        if options.mode != "plan":
            _record_check(
                checks, check_sources, "gate.referenceRepositoryUnchanged", "NOT_COVERED",
                "orchestrator.reference-guard", None,
            )
    else:
        reference_after = _reference_identity(options.reference_repository)
        status = "PASS" if reference_before == reference_after else "FAIL"
        _record_check(
            checks, check_sources, "gate.referenceRepositoryUnchanged", status,
            "orchestrator.reference-guard",
            _sha256_bytes(json.dumps(reference_after, sort_keys=True).encode("ascii")),
        )
        if status == "FAIL":
            errors.append("reference-repository-changed-during-run")

    source_after = _source_identity()
    if source_before != source_after:
        errors.append("candidate-source-changed-during-run")
    results, counts = _evaluate(coverage, checks)
    conclusion = _conclusion(counts, errors)
    evidence_sources = sorted(
        {
            (source["producer"], source.get("sha256"))
            for source in check_sources.values()
        },
        key=lambda value: (value[0], value[1] or ""),
    )
    ledger = {
        "schemaVersion": 1,
        "suite": "v1",
        "mode": options.mode,
        "observedAt": _utc_now(),
        "baseline": {
            "path": "docs/acceptance/v1-acceptance-baseline.md",
            "sha256": coverage.baseline_sha256,
        },
        "candidate": {
            "kind": "immutable-release" if candidate is not None else "working-tree",
            "manifestSha256": candidate_sha,
            "release": candidate["release"] if candidate is not None else None,
            "images": {
                name: _effective_image(candidate, name)
                for name in ("app", "nginx", "mysql", "redis")
            } if candidate is not None else None,
        },
        "source": source_after,
        "evidenceSources": [
            {"producer": producer, **({"sha256": sha} if sha is not None else {})}
            for producer, sha in evidence_sources
        ],
        "checks": {check: checks[check] for check in sorted(checks)},
        "results": results,
        "counts": counts,
        "conclusion": conclusion,
        "errors": sorted(set(errors)),
    }
    _write_private_json(output / "v1-regression-ledger.json", ledger)
    _write_private(output / "v1-regression-ledger.md", _markdown(ledger).encode("utf-8"))
    _write_manifest(output)
    if conclusion == "PASS":
        return 0, output
    if conclusion == "FAIL":
        return EXIT_FAIL, output
    return EXIT_INCOMPLETE, output


def main(argv: Sequence[str] | None = None) -> int:
    options = parse_args(argv)
    try:
        exit_code, output = run(options)
    except RegressionError as exception:
        print(f"V1 regression refused safely: {exception}", file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps({
        "suite": "v1",
        "status": "PASS" if exit_code == 0 else ("INCOMPLETE" if exit_code == EXIT_INCOMPLETE else "FAIL"),
        "evidenceDirectory": str(output),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
