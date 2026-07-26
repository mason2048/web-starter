#!/usr/bin/env python3
"""Create status-free V2-AC-01 observations for the frozen V1 source.

The producer records only Git- and document-derived observations.  It does not
decide PASS and it does not reuse the historical V1 record as a regression run
for the current release candidate.  The independent validator recomputes every
semantic before a canonical summary can enter the release ledger.
"""

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
from typing import Any, Iterable, Mapping, Sequence
import xml.etree.ElementTree as ElementTree


RESULT_NAME = "v2-ac01-v1-source-provenance.json"
CHECKSUM_NAME = RESULT_NAME + ".sha256"
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


class ProofCreationError(ValueError):
    """The source provenance observation cannot be created safely."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _git_environment() -> dict[str, str]:
    # Start from an allowlist.  This intentionally drops GIT_CONFIG_KEY_n /
    # VALUE_n as well as object, alternate, index and worktree injection.
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
        raise ProofCreationError("Git is required for V1 source provenance") from exception
    if len(completed.stdout) > MAX_GIT_BYTES or len(completed.stderr) > MAX_GIT_BYTES:
        raise ProofCreationError("Git output exceeded the V1 provenance bound")
    return completed


def _git(repository: Path, *arguments: str) -> bytes:
    completed = _git_result(repository, *arguments)
    if completed.returncode != 0:
        raise ProofCreationError("Git could not resolve the V1 source provenance")
    return completed.stdout


def _git_text(repository: Path, *arguments: str) -> str:
    try:
        value = _git(repository, *arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise ProofCreationError("Git identity is not valid UTF-8") from exception
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise ProofCreationError("Git identity is malformed")
    return value


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProofCreationError(f"{label} repeats field: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ProofCreationError(f"{label} is not strict UTF-8 JSON") from exception
    if not isinstance(value, dict):
        raise ProofCreationError(f"{label} must be an object")
    return value


def _root_version(payload: bytes) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exception:
        raise ProofCreationError("candidate root POM is invalid") from exception
    namespace = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
    element = root.find(f"{namespace}version")
    return element.text.strip() if element is not None and element.text else ""


def _section(text: str, heading: str, next_heading_prefix: str = "## ") -> list[str]:
    lines = text.splitlines()
    try:
        start = lines.index(heading) + 1
    except ValueError as exception:
        raise ProofCreationError(f"historical record lacks section: {heading}") from exception
    result: list[str] = []
    for line in lines[start:]:
        if line.startswith(next_heading_prefix):
            break
        result.append(line)
    return result


def _parse_baseline(payload: bytes) -> list[dict[str, str]]:
    if len(payload) > MAX_DOCUMENT_BYTES or _sha256(payload) != V1_BASELINE_SHA256:
        raise ProofCreationError("frozen V1 baseline bytes differ")
    text = payload.decode("utf-8", errors="strict")
    rows = []
    for line in _section(text, "## 4. 功能验收矩阵"):
        match = BASELINE_ROW.fullmatch(line)
        if match:
            rows.append({
                "id": match.group(1),
                "level": match.group(2),
                "domainSha256": _sha256(match.group(3).strip().encode()),
                "criteriaSha256": _sha256(match.group(4).strip().encode()),
            })
    if tuple(row["id"] for row in rows) != EXPECTED_IDS:
        raise ProofCreationError("frozen V1 baseline is not exact AC-01..AC-42")
    return rows


def _parse_record(payload: bytes) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    if len(payload) > MAX_DOCUMENT_BYTES or _sha256(payload) != V1_RECORD_SHA256:
        raise ProofCreationError("frozen V1 acceptance record bytes differ")
    text = payload.decode("utf-8", errors="strict")
    if (
        "> 对象：本地 `v1.0.0` 发布基线" not in text
        or "> 结论：`PASS`（功能、安全、运行和模块扩展验收）" not in text
        or "| Git commit | 以 `git rev-list -n 1 v1.0.0` 解析的本地发布提交为准 |" not in text
        or "本记录对应 [V1 验收基线](./v1-acceptance-baseline.md)。" not in text
    ):
        raise ProofCreationError("V1 acceptance record does not identify the frozen local tag")
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
        raise ProofCreationError("V1 acceptance record is not exact 42 PASS results")
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
        raise ProofCreationError("V1 automation gate record is not exact PASS")
    final_lines = _section(text, "## 9. 最终结论")
    checklist = [
        match.group(1) for line in final_lines
        if (match := CHECKED_CONCLUSION.fullmatch(line)) is not None
    ]
    if tuple(checklist) != EXPECTED_FINAL_CHECKLIST \
            or "结论：`PASS`" not in final_lines:
        raise ProofCreationError("V1 final conclusion is not the exact checked PASS record")
    return results, automation, checklist


def _tag_annotation(repository: Path) -> str:
    payload = _git(repository, "cat-file", "-p", f"refs/tags/{V1_TAG}")
    try:
        header, message = payload.decode("utf-8", errors="strict").split("\n\n", 1)
    except (UnicodeDecodeError, ValueError) as exception:
        raise ProofCreationError("V1 annotated tag object is malformed") from exception
    headers = header.splitlines()
    if (
        f"object {V1_COMMIT}" not in headers
        or "type commit" not in headers
        or f"tag {V1_TAG}" not in headers
        or not any(line.startswith("tagger ") for line in headers)
        or message.strip() != V1_ANNOTATION
    ):
        raise ProofCreationError("V1 tag target or annotation differs from the frozen source")
    return message.strip()


def _blob_binding(repository: Path, commit: str, path: str) -> dict[str, str]:
    payload = _git(repository, "show", f"{commit}:{path}")
    blob = _git_text(repository, "rev-parse", f"{commit}:{path}")
    if GIT_OBJECT.fullmatch(blob) is None \
            or _git_text(repository, "cat-file", "-t", blob) != "blob":
        raise ProofCreationError(f"Git object is not a blob: {path}")
    return {"path": path, "gitBlob": blob, "sha256": _sha256(payload)}


def _candidate(
    repository: Path,
    expected_commit: str,
    expected_version: str,
    expected_tag: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if (
        GIT_OBJECT.fullmatch(expected_commit) is None
        or VERSION.fullmatch(expected_version) is None
        or expected_version.endswith("-SNAPSHOT")
        or expected_tag != f"v{expected_version}"
    ):
        raise ProofCreationError("expected release identity is malformed")
    top = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != repository:
        raise ProofCreationError("candidate root must be the exact Git top-level")
    head = _git_text(repository, "rev-parse", "HEAD^{commit}")
    tree = _git_text(repository, "rev-parse", "HEAD^{tree}")
    if head != expected_commit:
        raise ProofCreationError("candidate HEAD differs from expected release commit")
    status = _git(
        repository, "status", "--porcelain=v1", "--untracked-files=all",
        "--ignore-submodules=none",
    )
    index = [record for record in _git(repository, "ls-files", "-v", "-z").split(b"\0") if record]
    if status or not index or any(len(record) < 3 or not record.startswith(b"H ") for record in index):
        raise ProofCreationError("candidate must be clean with an ordinary visible Git index")
    tag_ref = f"refs/tags/{expected_tag}"
    if _git_text(repository, "cat-file", "-t", tag_ref) != "tag" \
            or _git_text(repository, "rev-parse", f"{tag_ref}^{{commit}}") != head:
        raise ProofCreationError("candidate release tag must be annotated and resolve to HEAD")
    tag_object = _git_text(repository, "rev-parse", f"{tag_ref}^{{tag}}")
    blobs = {path: _git(repository, "show", f"{head}:{path}") for path in SOURCE_PATHS}
    if _root_version(blobs[ROOT_POM_PATH]) != expected_version:
        raise ProofCreationError("candidate Maven version differs from expected release")
    frontend = _strict_json(blobs[FRONTEND_MANIFEST_PATH], "candidate frontend manifest")
    if frontend.get("version") != expected_version:
        raise ProofCreationError("candidate frontend version differs from expected release")
    for path, payload in blobs.items():
        working = repository / path
        if working.is_symlink() or not working.is_file() or working.read_bytes() != payload:
            raise ProofCreationError(f"candidate working file differs from commit: {path}")
    return ({
        "commit": head,
        "tree": tree,
        "tag": expected_tag,
        "tagObject": tag_object,
        "mavenVersion": expected_version,
        "frontendVersion": expected_version,
        "cleanWorktree": True,
        "sourceSha256": {path: _sha256(payload) for path, payload in sorted(blobs.items())},
    }, blobs)


def _write_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
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
        path.unlink(missing_ok=True)
        raise


def create_proof(
    repository_root: Path,
    output_directory: Path,
    *,
    expected_candidate_commit: str,
    expected_candidate_version: str,
    expected_candidate_tag: str,
) -> dict[str, Any]:
    root_input = repository_root.expanduser().absolute()
    if root_input.is_symlink() or not root_input.is_dir():
        raise ProofCreationError("candidate root must be a real directory")
    root = root_input.resolve(strict=True)
    output_input = output_directory.expanduser().absolute()
    if output_input.is_symlink() or not output_input.is_dir():
        raise ProofCreationError("raw evidence directory must be a real existing directory")
    output = output_input.resolve(strict=True)
    if _inside(output, root) or _inside(root, output):
        raise ProofCreationError("raw V1 provenance evidence must stay outside the candidate")
    if stat.S_IMODE(output.stat().st_mode) != 0o700 or any(output.iterdir()):
        raise ProofCreationError("raw evidence directory must be empty mode 0700")

    candidate, _ = _candidate(
        root, expected_candidate_commit, expected_candidate_version, expected_candidate_tag
    )
    if _git_text(root, "cat-file", "-t", f"refs/tags/{V1_TAG}") != "tag":
        raise ProofCreationError("frozen V1 source must be an annotated tag")
    if (
        _git_text(root, "rev-parse", f"refs/tags/{V1_TAG}^{{tag}}") != V1_TAG_OBJECT
        or _git_text(root, "rev-parse", f"refs/tags/{V1_TAG}^{{commit}}") != V1_COMMIT
        or _git_text(root, "rev-parse", f"refs/tags/{V1_TAG}^{{tree}}") != V1_TREE
    ):
        raise ProofCreationError("frozen V1 tag object, commit or tree differs")
    annotation = _tag_annotation(root)
    archive_sha256 = _sha256(_git(root, "archive", "--format=tar", V1_COMMIT))
    if archive_sha256 != V1_ARCHIVE_SHA256:
        raise ProofCreationError("frozen V1 source archive bytes differ")
    baseline_payload = _git(root, "show", f"{V1_COMMIT}:{V1_BASELINE_PATH}")
    record_payload = _git(root, "show", f"{V1_COMMIT}:{V1_RECORD_PATH}")
    baseline_rows = _parse_baseline(baseline_payload)
    record_rows, automation, checklist = _parse_record(record_payload)
    ancestry = _git_result(root, "merge-base", "--is-ancestor", V1_COMMIT, candidate["commit"])
    if ancestry.returncode != 0:
        raise ProofCreationError("release candidate is not a descendant of frozen V1")
    v2_baseline = _git(root, "show", f"{candidate['commit']}:{V2_BASELINE_PATH}").decode(
        "utf-8", errors="strict"
    )
    if (
        f"> V1 来源：本地 tag `{V1_TAG}`，commit `{V1_COMMIT}`" not in v2_baseline
        or "| V2-AC-01 | P0 | V1 来源 | `v1.0.0` 是可解析的本地注释 tag，工作树内容、测试结果和 V1 验收记录可追溯 |"
        not in v2_baseline
    ):
        raise ProofCreationError("candidate V2 baseline does not fix the V1 source contract")

    document: dict[str, Any] = {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-01",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "candidate": candidate,
        "v1Source": {
            "tag": V1_TAG,
            "tagObject": V1_TAG_OBJECT,
            "commit": V1_COMMIT,
            "tree": V1_TREE,
            "annotationSha256": _sha256(annotation.encode("utf-8")),
            "sourceArchiveSha256": archive_sha256,
            "baseline": _blob_binding(root, V1_COMMIT, V1_BASELINE_PATH),
            "acceptanceRecord": _blob_binding(root, V1_COMMIT, V1_RECORD_PATH),
        },
        "observations": {
            "baselineDefinitions": baseline_rows,
            "acceptanceResults": record_rows,
            "automationChecks": automation,
            "finalChecklistSha256": [_sha256(item.encode("utf-8")) for item in checklist],
            "finalConclusion": "PASS",
            "releaseDescendsFromV1": True,
            "scope": "HISTORICAL_SOURCE_TRACEABILITY_ONLY",
        },
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
            "onlyReportAndChecksum": True,
            "historicalRuntimeArtifactsRevalidated": False,
            "currentCandidateV1RegressionClaimed": False,
        },
    }
    report_payload = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    checksum_payload = f"{_sha256(report_payload)}  {RESULT_NAME}\n".encode("ascii")
    report = output / RESULT_NAME
    checksum = output / CHECKSUM_NAME
    try:
        _write_file(report, report_payload)
        _write_file(checksum, checksum_payload)
        if {entry.name for entry in output.iterdir()} != {RESULT_NAME, CHECKSUM_NAME}:
            raise ProofCreationError("raw evidence directory contains unexpected files")
        for path, payload in ((report, report_payload), (checksum, checksum_payload)):
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
                    or stat.S_IMODE(metadata.st_mode) != 0o600 or path.read_bytes() != payload:
                raise ProofCreationError("raw V1 provenance evidence publication is not exact")
    except BaseException:
        report.unlink(missing_ok=True)
        checksum.unlink(missing_ok=True)
        raise
    return document


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create V2-AC-01 V1 source observations")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-candidate-version", required=True)
    parser.add_argument("--expected-candidate-tag", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        create_proof(
            args.repository_root,
            args.output_dir,
            expected_candidate_commit=args.expected_candidate_commit,
            expected_candidate_version=args.expected_candidate_version,
            expected_candidate_tag=args.expected_candidate_tag,
        )
    except (OSError, UnicodeDecodeError, ProofCreationError) as exception:
        print(f"FAIL V2-AC-01 V1 source observation: {exception}", file=sys.stderr)
        return 1
    print("PASS V2-AC-01 producer: status-free V1 source observations created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
