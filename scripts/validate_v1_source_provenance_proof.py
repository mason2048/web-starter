#!/usr/bin/env python3
"""Independently validate V2-AC-01 frozen V1 source provenance.

This validator never imports the producer.  It re-reads the annotated V1 tag,
fixed commit/tree, historical baseline and record directly from Git; validates
the current clean release candidate and ancestry; then writes one canonical
0600 summary.  Historical PASS rows are treated only as a traceable V1 record,
never as current-candidate V1 regression evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence
import xml.etree.ElementTree as ElementTree


RESULT_NAME = "v2-ac01-v1-source-provenance.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"
SUMMARY_NAME = "v2-ac01-v1-source-provenance-summary.json"
V1_TAG = "v1.0.0"
V1_TAG_OBJECT = "406e73cca6f4d4e257c2aa08e58815d96b7ca722"
V1_COMMIT = "5ebdb238650d182c17e1493adf47aaa3324f19cb"
V1_TREE = "355c61a77f4dd0f16f0f3d945ee6c8d4f02d956a"
V1_ARCHIVE_SHA256 = "79b220b5a4da72ea3d4bb98203add92bce83fc19e30cd24ebfa084c7bc360ff5"
V1_ANNOTATION = "启程 Web Starter V1 verified baseline"
V1_BASELINE_PATH = "docs/acceptance/v1-acceptance-baseline.md"
V1_BASELINE_SHA256 = "aa9ef7247246165c451e6910db6da167d1385b6e14f3f65fd72a7705e8263994"
V1_RECORD_PATH = "docs/acceptance/v1-acceptance-2026-07-19.md"
V1_RECORD_SHA256 = "81ce417c52f004d74275b591d47748f8868226cccaf3e02a21490d42785336f9"
V2_BASELINE_PATH = "docs/acceptance/v2-acceptance-baseline.md"
ROOT_POM_PATH = "pom.xml"
FRONTEND_MANIFEST_PATH = "web-starter-web/package.json"
PRODUCER_PATH = "scripts/create_v1_source_provenance_proof.py"
VALIDATOR_PATH = "scripts/validate_v1_source_provenance_proof.py"
SCHEMA_PATH = "security/v2-ac01-v1-source-provenance-summary.schema.json"
SOURCE_PATHS = (
    PRODUCER_PATH,
    VALIDATOR_PATH,
    SCHEMA_PATH,
    V2_BASELINE_PATH,
    ROOT_POM_PATH,
    FRONTEND_MANIFEST_PATH,
)

GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
BASELINE_ROW = re.compile(
    r"^\|\s*(AC-[0-9]{2})\s*\|\s*(P[01])\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$"
)
RECORD_ROW = re.compile(
    r"^\|\s*(AC-[0-9]{2})\s*\|\s*"
    r"(PASS|FAIL|NOT_COVERED|ENV_BLOCKED)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$"
)
AUTOMATION_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$")
CHECKED_CONCLUSION = re.compile(r"^- \[x\] (.+)$")
MAX_GIT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024

EXPECTED_IDS = tuple(f"AC-{number:02d}" for number in range(1, 43))
EXPECTED_AUTOMATION_CHECKS = (
    "后端全量",
    "官方 SDK：私有 PAT",
    "官方 SDK：完整项目 CRUD",
    "官方 SDK：自动化 Agent",
    "前端 lint",
    "前端类型",
    "前端测试",
    "前端构建",
    "Compose 配置",
    "仓库策略测试",
    "秘密扫描",
    "禁用业务词",
)
EXPECTED_FINAL_CHECKLIST = (
    "所有 P0 均为 PASS。",
    "所有 P1 均为 PASS。",
    "没有把 NOT_COVERED 或 ENV_BLOCKED 计作 PASS。",
    "Web、OAuth、MCP、数据、安全、部署和模块复制均有独立运行证据。",
    "验收结论限定为本地 `v1.0.0` tag，不冒充远程发布或真实公网部署。",
)

TOP_FIELDS = frozenset({
    "schemaVersion", "acceptanceId", "generatedAt", "candidate", "v1Source",
    "observations", "evidencePolicy",
})
CANDIDATE_FIELDS = frozenset({
    "commit", "tree", "tag", "tagObject", "mavenVersion", "frontendVersion",
    "cleanWorktree", "sourceSha256",
})
V1_SOURCE_FIELDS = frozenset({
    "tag", "tagObject", "commit", "tree", "annotationSha256", "sourceArchiveSha256",
    "baseline", "acceptanceRecord",
})
FILE_BINDING_FIELDS = frozenset({"path", "gitBlob", "sha256"})
OBSERVATION_FIELDS = frozenset({
    "baselineDefinitions", "acceptanceResults", "automationChecks",
    "finalChecklistSha256", "finalConclusion", "releaseDescendsFromV1", "scope",
})
POLICY_FIELDS = frozenset({
    "outsideRepository", "directoryMode", "fileMode", "onlyReportAndChecksum",
    "historicalRuntimeArtifactsRevalidated", "currentCandidateV1RegressionClaimed",
})


class ProofValidationError(ValueError):
    """Raw provenance is malformed, unsafe, stale, or semantically false."""


class ProofNotPassingError(ProofValidationError):
    """The caller required an independently recomputed PASS summary."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int
    sha256: str


@dataclass(frozen=True)
class EvidenceSnapshot:
    directory: Path
    report: FileIdentity
    checksum: FileIdentity
    report_bytes: bytes
    checksum_bytes: bytes


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _exact(value: Mapping[str, Any], fields: Iterable[str], label: str) -> None:
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        raise ProofValidationError(
            f"{label} fields are not exact "
            f"(missing={','.join(sorted(expected - actual))}; "
            f"unknown={','.join(sorted(actual - expected))})"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProofValidationError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProofValidationError(f"{label} must be an array")
    return value


def _git_environment() -> dict[str, str]:
    # An allowlisted environment drops all ambient GIT_CONFIG_KEY_n /
    # GIT_CONFIG_VALUE_n, object, alternate, index and worktree injection.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git_result(repository: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            [
                "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(repository), *arguments,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exception:
        raise ProofValidationError("Git is required to validate V1 provenance") from exception
    if len(completed.stdout) > MAX_GIT_BYTES or len(completed.stderr) > MAX_GIT_BYTES:
        raise ProofValidationError("Git output exceeded the V1 provenance bound")
    return completed


def _git(repository: Path, *arguments: str) -> bytes:
    completed = _git_result(repository, *arguments)
    if completed.returncode != 0:
        raise ProofValidationError("Git could not validate the V1 source provenance")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise ProofValidationError("Git identity is not valid UTF-8") from exception
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise ProofValidationError("Git identity is malformed")
    return value


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProofValidationError(f"{label} repeats field: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ProofValidationError(f"{label} is not strict UTF-8 JSON") from exception
    if not isinstance(value, dict):
        raise ProofValidationError(f"{label} must be an object")
    return value


def _read_regular(path: Path, maximum: int, label: str) -> tuple[FileIdentity, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ProofValidationError(f"{label} must be a regular non-symlink file")
    before = path.stat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exception:
        raise ProofValidationError(f"{label} cannot be opened safely") from exception
    try:
        opened = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    after = path.stat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, stat.S_IMODE(item.st_mode))
        for item in (before, opened, after)
    }
    if len(identities) != 1 or len(payload) != opened.st_size:
        raise ProofValidationError(f"{label} changed while being read")
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_size <= 0
        or opened.st_size > maximum
        or stat.S_IMODE(opened.st_mode) != 0o600
    ):
        raise ProofValidationError(f"{label} must be a non-empty mode 0600 file")
    return FileIdentity(
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        stat.S_IMODE(opened.st_mode),
        _sha256(bytes(payload)),
    ), bytes(payload)


def snapshot_proof(report_path: Path) -> EvidenceSnapshot:
    report_input = report_path.expanduser().absolute()
    if report_input.name != RESULT_NAME:
        raise ProofValidationError(f"raw V1 provenance report must be named {RESULT_NAME}")
    parent_input = report_input.parent
    if parent_input.is_symlink() or not parent_input.is_dir():
        raise ProofValidationError("raw V1 provenance parent must be a real directory")
    directory = parent_input.resolve(strict=True)
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ProofValidationError("raw V1 provenance directory must have mode 0700")
    if {entry.name for entry in directory.iterdir()} != {RESULT_NAME, CHECKSUM_NAME}:
        raise ProofValidationError("raw V1 provenance directory must contain exact report/checksum")
    report = directory / RESULT_NAME
    checksum = directory / CHECKSUM_NAME
    report_identity, report_bytes = _read_regular(report, MAX_REPORT_BYTES, "V1 provenance report")
    checksum_identity, checksum_bytes = _read_regular(checksum, 256, "V1 provenance checksum")
    expected_checksum = f"{report_identity.sha256}  {RESULT_NAME}\n".encode("ascii")
    if checksum_bytes != expected_checksum:
        raise ProofValidationError("raw V1 provenance checksum does not bind report bytes")
    return EvidenceSnapshot(
        directory, report_identity, checksum_identity, report_bytes, checksum_bytes
    )


def _root_version(payload: bytes) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise ProofValidationError("candidate root POM is invalid") from exception
    namespace = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
    element = root.find(f"{namespace}version")
    return element.text.strip() if element is not None and element.text else ""


def _section(text: str, heading: str) -> list[str]:
    lines = text.splitlines()
    try:
        start = lines.index(heading) + 1
    except ValueError as exception:
        raise ProofValidationError(f"historical record lacks section: {heading}") from exception
    result: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        result.append(line)
    return result


def _parse_baseline(payload: bytes) -> list[dict[str, str]]:
    if len(payload) > MAX_DOCUMENT_BYTES or _sha256(payload) != V1_BASELINE_SHA256:
        raise ProofValidationError("frozen V1 baseline bytes differ")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError("frozen V1 baseline is not UTF-8") from exception
    rows: list[dict[str, str]] = []
    for line in _section(text, "## 4. 功能验收矩阵"):
        match = BASELINE_ROW.fullmatch(line)
        if match:
            rows.append({
                "id": match.group(1),
                "level": match.group(2),
                "domainSha256": _sha256(match.group(3).strip().encode()),
                "criteriaSha256": _sha256(match.group(4).strip().encode()),
            })
    if tuple(item["id"] for item in rows) != EXPECTED_IDS:
        raise ProofValidationError("frozen V1 baseline is not exact AC-01..AC-42")
    return rows


def _parse_record(payload: bytes) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    if len(payload) > MAX_DOCUMENT_BYTES or _sha256(payload) != V1_RECORD_SHA256:
        raise ProofValidationError("frozen V1 acceptance record bytes differ")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exception:
        raise ProofValidationError("frozen V1 acceptance record is not UTF-8") from exception
    required_identity = (
        "> 对象：本地 `v1.0.0` 发布基线",
        "> 结论：`PASS`（功能、安全、运行和模块扩展验收）",
        "| Git commit | 以 `git rev-list -n 1 v1.0.0` 解析的本地发布提交为准 |",
        "本记录对应 [V1 验收基线](./v1-acceptance-baseline.md)。",
    )
    if any(value not in text for value in required_identity):
        raise ProofValidationError("V1 acceptance record does not identify its frozen tag")
    results: list[dict[str, str]] = []
    for line in _section(text, "## 3. 逐项结果"):
        match = RECORD_ROW.fullmatch(line)
        if match:
            results.append({
                "id": match.group(1),
                "status": match.group(2),
                "evidenceSha256": _sha256(match.group(3).strip().encode()),
                "notesSha256": _sha256(match.group(4).strip().encode()),
            })
    if tuple(item["id"] for item in results) != EXPECTED_IDS \
            or any(item["status"] != "PASS" for item in results):
        raise ProofValidationError("V1 record does not contain exact AC-01..AC-42 PASS rows")
    automation: list[dict[str, str]] = []
    for line in _section(text, "## 4. 自动化门禁"):
        match = AUTOMATION_ROW.fullmatch(line)
        if not match or match.group(1).strip() in {"检查", "---"}:
            continue
        check, command, result = (match.group(index).strip() for index in range(1, 4))
        automation.append({
            "check": check,
            "commandSha256": _sha256(command.encode()),
            "status": "PASS" if result.startswith("PASS") else result,
            "resultSha256": _sha256(result.encode()),
        })
    if tuple(item["check"] for item in automation) != EXPECTED_AUTOMATION_CHECKS \
            or any(item["status"] != "PASS" for item in automation):
        raise ProofValidationError("V1 automation record is not the exact PASS table")
    final_lines = _section(text, "## 9. 最终结论")
    checklist = [
        match.group(1) for line in final_lines
        if (match := CHECKED_CONCLUSION.fullmatch(line)) is not None
    ]
    if tuple(checklist) != EXPECTED_FINAL_CHECKLIST or "结论：`PASS`" not in final_lines:
        raise ProofValidationError("V1 final conclusion is not exact checked PASS")
    return results, automation, checklist


def _tag_annotation(repository: Path) -> str:
    payload = _git(repository, "cat-file", "-p", f"refs/tags/{V1_TAG}")
    try:
        header, message = payload.decode("utf-8", errors="strict").split("\n\n", 1)
    except (UnicodeDecodeError, ValueError) as exception:
        raise ProofValidationError("V1 annotated tag object is malformed") from exception
    headers = header.splitlines()
    if (
        f"object {V1_COMMIT}" not in headers
        or "type commit" not in headers
        or f"tag {V1_TAG}" not in headers
        or not any(line.startswith("tagger ") for line in headers)
        or message.strip() != V1_ANNOTATION
    ):
        raise ProofValidationError("V1 tag target or annotation differs from frozen source")
    return message.strip()


def _blob_binding(repository: Path, commit: str, path: str) -> tuple[dict[str, str], bytes]:
    payload = _git(repository, "show", f"{commit}:{path}")
    blob = _git_text(repository, "rev-parse", f"{commit}:{path}")
    if GIT_OBJECT.fullmatch(blob) is None \
            or _git_text(repository, "cat-file", "-t", blob) != "blob":
        raise ProofValidationError(f"Git object is not a blob: {path}")
    return {"path": path, "gitBlob": blob, "sha256": _sha256(payload)}, payload


def _verify_candidate(
    repository: Path,
    value: Any,
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    candidate = _object(value, "candidate")
    _exact(candidate, CANDIDATE_FIELDS, "candidate")
    if (
        GIT_OBJECT.fullmatch(expected_commit) is None
        or VERSION.fullmatch(expected_version) is None
        or expected_version.endswith("-SNAPSHOT")
        or expected_tag != f"v{expected_version}"
    ):
        raise ProofValidationError("expected candidate identity is malformed")
    if Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True) != repository:
        raise ProofValidationError("candidate root must be the exact Git top-level")
    head = _git_text(repository, "rev-parse", "HEAD^{commit}")
    tree = _git_text(repository, "rev-parse", "HEAD^{tree}")
    if head != expected_commit:
        raise ProofValidationError("candidate HEAD differs from expected release commit")
    status = _git(
        repository, "status", "--porcelain=v1", "--untracked-files=all",
        "--ignore-submodules=none",
    )
    index = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if status or not index or any(len(record) < 3 or not record.startswith(b"H ") for record in index):
        raise ProofValidationError("candidate must be clean with an ordinary visible Git index")
    tag_ref = f"refs/tags/{expected_tag}"
    if _git_text(repository, "cat-file", "-t", tag_ref) != "tag" \
            or _git_text(repository, "rev-parse", f"{tag_ref}^{{commit}}") != head:
        raise ProofValidationError("candidate release tag must be annotated and resolve to HEAD")
    tag_object = _git_text(repository, "rev-parse", f"{tag_ref}^{{tag}}")
    blobs = {path: _git(repository, "show", f"{head}:{path}") for path in SOURCE_PATHS}
    expected_source = {path: _sha256(payload) for path, payload in sorted(blobs.items())}
    if candidate != {
        "commit": head,
        "tree": tree,
        "tag": expected_tag,
        "tagObject": tag_object,
        "mavenVersion": expected_version,
        "frontendVersion": expected_version,
        "cleanWorktree": True,
        "sourceSha256": expected_source,
    }:
        raise ProofValidationError("candidate self-binding differs from clean release Git state")
    if _root_version(blobs[ROOT_POM_PATH]) != expected_version:
        raise ProofValidationError("candidate Maven version differs from expected release")
    frontend = _strict_json(blobs[FRONTEND_MANIFEST_PATH], "candidate frontend manifest")
    if frontend.get("version") != expected_version:
        raise ProofValidationError("candidate frontend version differs from expected release")
    for path, payload in blobs.items():
        working = repository / path
        if working.is_symlink() or not working.is_file() or working.read_bytes() != payload:
            raise ProofValidationError(f"candidate source differs from commit: {path}")
    return candidate, blobs


def canonical_summary_bytes(summary: Mapping[str, Any]) -> bytes:
    return json.dumps(
        summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def validate_proof(
    report_path: Path,
    repository_root: Path,
    *,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
    require_pass: bool = True,
) -> dict[str, Any]:
    root_input = repository_root.expanduser().absolute()
    if root_input.is_symlink() or not root_input.is_dir():
        raise ProofValidationError("candidate root must be a real directory")
    repository = root_input.resolve(strict=True)
    snapshot = snapshot_proof(report_path)
    if _inside(snapshot.directory, repository) or _inside(repository, snapshot.directory):
        raise ProofValidationError("raw V1 provenance evidence must stay outside candidate")
    document = _strict_json(snapshot.report_bytes, "V1 provenance report")
    _exact(document, TOP_FIELDS, "V1 provenance report")
    if document.get("schemaVersion") != 1 or document.get("acceptanceId") != "V2-AC-01":
        raise ProofValidationError("V1 provenance report identity is invalid")
    if "status" in document:
        raise ProofValidationError("V1 provenance producer must not self-report PASS")
    generated = document.get("generatedAt")
    if not isinstance(generated, str) or not generated.endswith("Z") or len(generated) > 40:
        raise ProofValidationError("V1 provenance generatedAt is invalid")
    candidate, source_blobs = _verify_candidate(
        repository,
        document.get("candidate"),
        expected_candidate_commit,
        expected_candidate_version,
        expected_candidate_tag,
    )

    if _git_text(repository, "cat-file", "-t", f"refs/tags/{V1_TAG}") != "tag":
        raise ProofValidationError("frozen V1 source must be an annotated tag")
    if (
        _git_text(repository, "rev-parse", f"refs/tags/{V1_TAG}^{{tag}}") != V1_TAG_OBJECT
        or _git_text(repository, "rev-parse", f"refs/tags/{V1_TAG}^{{commit}}") != V1_COMMIT
        or _git_text(repository, "rev-parse", f"refs/tags/{V1_TAG}^{{tree}}") != V1_TREE
    ):
        raise ProofValidationError("frozen V1 tag object, commit or tree differs")
    annotation = _tag_annotation(repository)
    archive_sha256 = _sha256(_git(repository, "archive", "--format=tar", V1_COMMIT))
    if archive_sha256 != V1_ARCHIVE_SHA256:
        raise ProofValidationError("frozen V1 source archive bytes differ")
    baseline_binding, baseline_payload = _blob_binding(
        repository, V1_COMMIT, V1_BASELINE_PATH
    )
    record_binding, record_payload = _blob_binding(repository, V1_COMMIT, V1_RECORD_PATH)
    if baseline_binding["sha256"] != V1_BASELINE_SHA256 \
            or record_binding["sha256"] != V1_RECORD_SHA256:
        raise ProofValidationError("frozen V1 baseline or record digest differs")
    baseline_rows = _parse_baseline(baseline_payload)
    record_rows, automation, checklist = _parse_record(record_payload)
    ancestry = _git_result(
        repository, "merge-base", "--is-ancestor", V1_COMMIT, expected_candidate_commit
    )
    if ancestry.returncode != 0:
        raise ProofValidationError("release candidate is not a descendant of frozen V1")
    v2_baseline = source_blobs[V2_BASELINE_PATH].decode("utf-8", errors="strict")
    if (
        f"> V1 来源：本地 tag `{V1_TAG}`，commit `{V1_COMMIT}`" not in v2_baseline
        or "| V2-AC-01 | P0 | V1 来源 | `v1.0.0` 是可解析的本地注释 tag，工作树内容、测试结果和 V1 验收记录可追溯 |"
        not in v2_baseline
    ):
        raise ProofValidationError("candidate V2 baseline does not fix V1 provenance")

    v1_source = _object(document.get("v1Source"), "v1Source")
    _exact(v1_source, V1_SOURCE_FIELDS, "v1Source")
    for label in ("baseline", "acceptanceRecord"):
        _exact(_object(v1_source.get(label), f"v1Source.{label}"), FILE_BINDING_FIELDS, label)
    expected_v1_source = {
        "tag": V1_TAG,
        "tagObject": V1_TAG_OBJECT,
        "commit": V1_COMMIT,
        "tree": V1_TREE,
        "annotationSha256": _sha256(annotation.encode("utf-8")),
        "sourceArchiveSha256": archive_sha256,
        "baseline": baseline_binding,
        "acceptanceRecord": record_binding,
    }
    if v1_source != expected_v1_source:
        raise ProofValidationError("raw V1 source binding differs from independently resolved Git")
    observations = _object(document.get("observations"), "observations")
    _exact(observations, OBSERVATION_FIELDS, "observations")
    expected_observations = {
        "baselineDefinitions": baseline_rows,
        "acceptanceResults": record_rows,
        "automationChecks": automation,
        "finalChecklistSha256": [_sha256(item.encode("utf-8")) for item in checklist],
        "finalConclusion": "PASS",
        "releaseDescendsFromV1": True,
        "scope": "HISTORICAL_SOURCE_TRACEABILITY_ONLY",
    }
    if observations != expected_observations:
        raise ProofValidationError("raw V1 observations differ from historical Git documents")
    policy = _object(document.get("evidencePolicy"), "evidencePolicy")
    _exact(policy, POLICY_FIELDS, "evidencePolicy")
    expected_policy = {
        "outsideRepository": True,
        "directoryMode": "0700",
        "fileMode": "0600",
        "onlyReportAndChecksum": True,
        "historicalRuntimeArtifactsRevalidated": False,
        "currentCandidateV1RegressionClaimed": False,
    }
    if policy != expected_policy:
        raise ProofValidationError("V1 provenance scope/persistence policy is not exact")

    after = snapshot_proof(report_path)
    if after.report != snapshot.report or after.checksum != snapshot.checksum:
        raise ProofValidationError("raw V1 provenance evidence changed during validation")
    candidate_after, blobs_after = _verify_candidate(
        repository,
        document.get("candidate"),
        expected_candidate_commit,
        expected_candidate_version,
        expected_candidate_tag,
    )
    if candidate_after != candidate or blobs_after != source_blobs:
        raise ProofValidationError("candidate changed during V1 provenance validation")
    if require_pass is not True:
        raise ProofNotPassingError("V2-AC-01 validator only emits independently recomputed PASS")

    return {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-01",
        "status": "PASS",
        "candidate": {
            "commit": candidate["commit"],
            "tree": candidate["tree"],
            "tag": candidate["tag"],
            "version": candidate["mavenVersion"],
        },
        "v1Source": {
            "tag": V1_TAG,
            "tagObject": V1_TAG_OBJECT,
            "commit": V1_COMMIT,
            "tree": V1_TREE,
            "tagAnnotationSha256": _sha256(annotation.encode("utf-8")),
            "sourceArchiveSha256": archive_sha256,
            "baselinePath": V1_BASELINE_PATH,
            "baselineBlob": baseline_binding["gitBlob"],
            "baselineSha256": baseline_binding["sha256"],
            "acceptanceRecordPath": V1_RECORD_PATH,
            "acceptanceRecordBlob": record_binding["gitBlob"],
            "acceptanceRecordSha256": record_binding["sha256"],
            "acceptanceResultCount": len(record_rows),
            "acceptancePassCount": sum(item["status"] == "PASS" for item in record_rows),
            "baselineP0Count": sum(item["level"] == "P0" for item in baseline_rows),
            "baselineP1Count": sum(item["level"] == "P1" for item in baseline_rows),
            "automationCheckCount": len(automation),
            "finalCheckedCount": len(checklist),
            "finalConclusion": "PASS",
            "historicalExecutionTrust": "TAGGED_RECORD_ONLY",
        },
        "checks": {
            "annotatedTag": "PASS",
            "fixedTagTarget": "PASS",
            "frozenBaselineDefinitions": "PASS",
            "historicalRecordCompleteness": "PASS",
            "historicalAutomationRecord": "PASS",
            "historicalFinalConclusion": "PASS",
            "releaseAncestry": "PASS",
            "currentCandidateV1Regression": "NOT_CLAIMED",
            "historicalRuntimeArtifacts": "NOT_REVALIDATED",
        },
        "evidence": {
            "reportSha256": snapshot.report.sha256,
            "sourceSha256": candidate["sourceSha256"],
        },
    }


def write_canonical_summary(path: Path, summary: Mapping[str, Any]) -> None:
    target = path.expanduser().absolute()
    if target.name != SUMMARY_NAME:
        raise ProofValidationError(f"canonical V1 provenance summary must be named {SUMMARY_NAME}")
    if target.exists() or target.is_symlink():
        raise ProofValidationError("canonical V1 provenance summary must not already exist")
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir() \
            or stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise ProofValidationError("canonical V1 provenance summary parent must be mode 0700")
    payload = canonical_summary_bytes(summary)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    metadata = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 or target.read_bytes() != payload:
        target.unlink(missing_ok=True)
        raise ProofValidationError("canonical V1 provenance summary publication is not exact")


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate V2-AC-01 V1 source provenance")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-tag", required=True)
    parser.add_argument("--summary-output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate_proof(
            args.evidence,
            args.repository_root,
            expected_candidate_commit=args.expected_candidate_commit,
            expected_candidate_version=args.expected_candidate_version,
            expected_candidate_tag=args.expected_candidate_tag,
            require_pass=True,
        )
        write_canonical_summary(args.summary_output, summary)
    except (OSError, UnicodeDecodeError, ProofValidationError) as exception:
        print(f"FAIL V2-AC-01 V1 source provenance: {exception}", file=sys.stderr)
        return 1
    print("PASS V2-AC-01 V1 source provenance: frozen history is traceable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
