from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import unittest

import validate_v1_upgrade_evidence as gate


SHA256 = "a" * 64
RUN_ID = "0123456789ab"
TIMESTAMP = "2026-07-20T00:00:00Z"
GENERATED_AT = "2026-07-20T00:10:00Z"
MAVEN_DISTRIBUTION_URL = (
    "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/"
    "3.9.15/apache-maven-3.9.15-bin.zip"
)


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed.stdout.strip()


def create_clean_candidate(root: Path) -> Path:
    repository = root / "candidate"
    repository.mkdir()
    git(repository, "init")
    git(repository, "config", "user.name", "Web Starter Test")
    git(repository, "config", "user.email", "web-starter-test@example.invalid")
    paths = {
        gate.TOOL_PATH,
        gate.SCHEMA_PATH,
        *gate.CURRENT_ADAPTER_FILES,
        *gate.RUNTIME_SOURCE_FILES,
    }
    for relative in sorted(paths):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == ".mvn/wrapper/maven-wrapper.properties":
            path.write_text(
                "wrapperVersion=3.3.4\n"
                "distributionType=only-script\n"
                f"distributionUrl={MAVEN_DISTRIBUTION_URL}\n"
                f"distributionSha256Sum={SHA256}\n",
                encoding="utf-8",
            )
        else:
            path.write_bytes(f"candidate bytes for {relative}\n".encode("utf-8"))
    git(repository, "add", "--all")
    git(repository, "commit", "-m", "test candidate")
    return repository


def candidate_hashes(repository: Path) -> dict[str, str]:
    return {
        relative: hashlib.sha256((repository / relative).read_bytes()).hexdigest()
        for relative in {
            gate.TOOL_PATH,
            gate.SCHEMA_PATH,
            *gate.CURRENT_ADAPTER_FILES,
            *gate.RUNTIME_SOURCE_FILES,
        }
    }


def java_string_hash(value: str) -> str:
    result = 0
    for character in value:
        result = (result * 31 + ord(character)) & 0xFFFFFFFF
    return format(result, "x")


def component_tree_summary(root: Path) -> dict[str, object]:
    records: list[tuple[str, str, int, int, str]] = []
    file_count = 0
    byte_count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        children: list[Path] = []
        for entry in sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name)):
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            metadata = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                target_bytes = os.readlink(path).encode("utf-8")
                records.append((
                    "L",
                    relative,
                    mode,
                    len(target_bytes),
                    hashlib.sha256(target_bytes).hexdigest(),
                ))
            elif stat.S_ISDIR(metadata.st_mode):
                records.append(("D", relative, mode, 0, ""))
                children.append(path)
            else:
                payload_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                records.append(("F", relative, mode, metadata.st_size, payload_sha256))
                file_count += 1
                byte_count += metadata.st_size
        stack.extend(reversed(children))
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


def write_seed_file(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def bind_document_to_dependency_seed(
    seed_root: Path,
    repository: Path,
    document: dict[str, object],
) -> str:
    digests = candidate_hashes(repository)
    source_hashes = {
        relative: digests[relative] for relative in gate.DEPENDENCY_SEED_SOURCE_FILES
    }
    summaries = {
        component: component_tree_summary(
            seed_root / gate.DEPENDENCY_SEED_COMPONENT_PATHS[component]
        )
        for component in gate.DEPENDENCY_SEED_COMPONENTS
    }
    manifest = {
        "schemaVersion": 1,
        "kind": "web-starter-ac40-dependency-seed",
        "platform": sys.platform,
        "architecture": platform.machine().lower(),
        "versions": dict(gate.DEPENDENCY_SEED_VERSIONS),
        "sourceSha256": source_hashes,
        "components": {
            component: {
                "path": gate.DEPENDENCY_SEED_COMPONENT_PATHS[component],
                **summaries[component],
            }
            for component in gate.DEPENDENCY_SEED_COMPONENTS
        },
    }
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    write_seed_file(seed_root / "manifest.json", manifest_bytes)

    seed_evidence = document["source"]["dependencySeed"]  # type: ignore[index]
    seed_evidence.update({  # type: ignore[union-attr]
        "schemaVersion": 1,
        "kind": manifest["kind"],
        "platform": manifest["platform"],
        "architecture": manifest["architecture"],
        "versions": manifest["versions"],
        "sourceSha256": source_hashes,
        "components": summaries,
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "copiedToPrivateRuntime": True,
        "executionPolicy": dict(gate.DEPENDENCY_SEED_EXECUTION_POLICY),
    })
    recompute_dependency_seed_aggregate(seed_evidence)  # type: ignore[arg-type]
    return seed_evidence["aggregateSha256"]  # type: ignore[index,return-value]


def create_dependency_seed(
    parent: Path,
    repository: Path,
    document: dict[str, object],
) -> tuple[Path, str]:
    seed_root = parent / "dependency-seed"
    seed_root.mkdir(mode=0o700)
    for relative in gate.DEPENDENCY_SEED_COMPONENT_PATHS.values():
        (seed_root / relative).mkdir(mode=0o700)

    wrapper_binary = (
        seed_root
        / gate.DEPENDENCY_SEED_COMPONENT_PATHS["mavenHome"]
        / "wrapper"
        / "dists"
        / "apache-maven-3.9.15"
        / java_string_hash(MAVEN_DISTRIBUTION_URL)
        / "bin"
        / "mvn"
    )
    write_seed_file(wrapper_binary, b"#!/bin/sh\nexit 0\n", mode=0o700)
    maven_repository = seed_root / gate.DEPENDENCY_SEED_COMPONENT_PATHS["mavenRepository"]
    write_seed_file(maven_repository / "org/example/demo/1.0/demo-1.0.pom", b"<project/>\n")
    write_seed_file(maven_repository / "org/example/demo/1.0/demo-1.0.jar", b"jar\n")
    corepack_home = seed_root / gate.DEPENDENCY_SEED_COMPONENT_PATHS["corepackHome"]
    write_seed_file(
        corepack_home / "v1/pnpm/9.15.9/package.json",
        b'{"name":"pnpm","version":"9.15.9"}\n',
    )
    pnpm_store = seed_root / gate.DEPENDENCY_SEED_COMPONENT_PATHS["pnpmStore"]
    write_seed_file(pnpm_store / "v3/files/00/cache-entry", b"pnpm cache\n")
    playwright = seed_root / gate.DEPENDENCY_SEED_COMPONENT_PATHS["playwrightBrowsers"]
    write_seed_file(playwright / "chromium-1228/INSTALLATION_COMPLETE", b"complete\n")
    write_seed_file(
        playwright / "chromium-1228/chrome",
        b"#!/bin/sh\nexit 0\n",
        mode=0o700,
    )
    framework = playwright / "chromium-1228/Framework.framework"
    version_resources = framework / "Versions/149.0/Resources"
    write_seed_file(version_resources / "fixture.dat", b"framework resource\n")
    (framework / "Versions/Current").symlink_to(
        "149.0", target_is_directory=True
    )
    (framework / "Resources").symlink_to(
        "Versions/Current/Resources", target_is_directory=True
    )
    for path in [
        seed_root,
        *(
            item
            for item in seed_root.rglob("*")
            if item.is_dir() and not item.is_symlink()
        ),
    ]:
        path.chmod(0o700)
    return seed_root, bind_document_to_dependency_seed(seed_root, repository, document)


def bind_to_candidate(document: dict[str, object], repository: Path) -> None:
    digests = candidate_hashes(repository)
    source = document["source"]  # type: ignore[assignment]
    source["v2Commit"] = git(repository, "rev-parse", "HEAD^{commit}")  # type: ignore[index]
    source["v2Tree"] = git(repository, "rev-parse", "HEAD^{tree}")  # type: ignore[index]
    source["toolSha256"] = digests[gate.TOOL_PATH]  # type: ignore[index]
    source["schemaSha256"] = digests[gate.SCHEMA_PATH]  # type: ignore[index]
    source["currentAdapterSnapshotSha256"] = {  # type: ignore[index]
        relative: digests[relative] for relative in gate.CURRENT_ADAPTER_FILES
    }
    source["runtimeSourceSha256"] = {  # type: ignore[index]
        relative: digests[relative] for relative in gate.RUNTIME_SOURCE_FILES
    }
    source["dependencySeed"]["sourceSha256"] = {  # type: ignore[index]
        relative: digests[relative] for relative in gate.DEPENDENCY_SEED_SOURCE_FILES
    }
    recompute_dependency_seed_aggregate(source["dependencySeed"])  # type: ignore[index]

    observations = document["observations"]  # type: ignore[assignment]
    for report in observations["mcpSdkSurefire"]:  # type: ignore[index]
        report["testSourceSha256"] = digests[gate.SDK_CLASS_SOURCE[report["testClass"]]]
        report["rootPomSha256"] = digests["pom.xml"]
        report["modulePomSha256"] = digests["web-starter-mcp/pom.xml"]

    playwright = observations["playwright"]  # type: ignore[index]
    playwright["packageJsonSha256"] = digests["web-starter-web/package.json"]
    playwright["lockfileSha256"] = digests["web-starter-web/pnpm-lock.yaml"]
    playwright["configSha256"] = digests["web-starter-web/playwright.config.ts"]
    playwright["testSourceSha256"] = {
        relative: digests[relative] for relative in gate.PLAYWRIGHT_TEST_SOURCES
    }

    migration_by_script = {
        Path(relative).name: relative for relative in gate.V2_ONLY_MIGRATION_FILES
    }
    for row in observations["flywayHistory"]:  # type: ignore[index]
        relative = migration_by_script.get(row["script"])
        if relative is not None:
            row["scriptSha256"] = digests[relative]


def forge_internally_consistent_candidate_hashes(document: dict[str, object]) -> None:
    forged = "f" * 64
    source = document["source"]  # type: ignore[assignment]
    source["toolSha256"] = forged  # type: ignore[index]
    source["schemaSha256"] = forged  # type: ignore[index]
    source["currentAdapterSnapshotSha256"] = {  # type: ignore[index]
        relative: forged for relative in gate.CURRENT_ADAPTER_FILES
    }
    source["runtimeSourceSha256"] = {  # type: ignore[index]
        relative: forged for relative in gate.RUNTIME_SOURCE_FILES
    }
    source["dependencySeed"]["sourceSha256"] = {  # type: ignore[index]
        relative: forged for relative in gate.DEPENDENCY_SEED_SOURCE_FILES
    }
    recompute_dependency_seed_aggregate(source["dependencySeed"])  # type: ignore[index]

    observations = document["observations"]  # type: ignore[assignment]
    for report in observations["mcpSdkSurefire"]:  # type: ignore[index]
        report["testSourceSha256"] = forged
        report["rootPomSha256"] = forged
        report["modulePomSha256"] = forged
    playwright = observations["playwright"]  # type: ignore[index]
    playwright["packageJsonSha256"] = forged
    playwright["lockfileSha256"] = forged
    playwright["configSha256"] = forged
    playwright["testSourceSha256"] = {
        relative: forged for relative in gate.PLAYWRIGHT_TEST_SOURCES
    }
    v2_scripts = {Path(relative).name for relative in gate.V2_ONLY_MIGRATION_FILES}
    for row in observations["flywayHistory"]:  # type: ignore[index]
        if row["script"] in v2_scripts:
            row["scriptSha256"] = forged


def write_evidence(directory: Path, document: dict[str, object]) -> Path:
    directory.chmod(0o700)
    path = directory / "evidence.json"
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def aggregate(statuses: list[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if "ENV_REQUIRED" in statuses:
        return "ENV_REQUIRED"
    if statuses and all(status == "PASS" for status in statuses):
        return "PASS"
    return "NOT_COVERED"


def sdk_reports(count: int) -> list[dict[str, object]]:
    runtime_hashes = {name: SHA256 for name in gate.RUNTIME_SOURCE_FILES}
    return [
        {
            "testClass": test_class,
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "reportSha256": SHA256,
            "testSourceSha256": runtime_hashes[gate.SDK_CLASS_SOURCE[test_class]],
            "rootPomSha256": runtime_hashes["pom.xml"],
            "modulePomSha256": runtime_hashes["web-starter-mcp/pom.xml"],
        }
        for test_class in gate.SDK_CLASS_ORDER[:count]
    ]


def playwright_report() -> dict[str, object]:
    return {
        "tests": 20,
        "failures": 0,
        "skipped": 0,
        "flaky": 0,
        "reportSha256": SHA256,
        "packageJsonSha256": SHA256,
        "lockfileSha256": SHA256,
        "configSha256": SHA256,
        "testSourceSha256": {
            name: SHA256 for name in gate.PLAYWRIGHT_TEST_SOURCES
        },
    }


def recompute_dependency_seed_aggregate(seed: dict[str, object]) -> None:
    aggregate_payload = {
        name: seed[name]
        for name in (
            "kind", "schemaVersion", "platform", "architecture", "versions",
            "sourceSha256", "components",
        )
    }
    seed["aggregateSha256"] = hashlib.sha256(json.dumps(
        aggregate_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def dependency_seed() -> dict[str, object]:
    seed: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "web-starter-ac40-dependency-seed",
        "platform": "darwin",
        "architecture": "arm64",
        "versions": dict(gate.DEPENDENCY_SEED_VERSIONS),
        "sourceSha256": {
            name: SHA256 for name in gate.DEPENDENCY_SEED_SOURCE_FILES
        },
        "components": {
            name: {"treeSha256": SHA256, "fileCount": 1, "byteCount": 1}
            for name in gate.DEPENDENCY_SEED_COMPONENTS
        },
        "manifestSha256": SHA256,
        "aggregateSha256": SHA256,
        "copiedToPrivateRuntime": True,
        "executionPolicy": dict(gate.DEPENDENCY_SEED_EXECUTION_POLICY),
    }
    recompute_dependency_seed_aggregate(seed)
    return seed


def recompute_aggregates(document: dict[str, object]) -> None:
    checks = document["checks"]  # type: ignore[assignment]
    phases = document["phases"]  # type: ignore[assignment]
    acceptance = document["acceptance"]  # type: ignore[assignment]
    for acceptance_id, names in gate.ACCEPTANCE_GROUPS.items():
        statuses = [checks[name]["status"] for name in names]  # type: ignore[index]
        owned = set(names)
        phase_names = (
            gate.PHASE_ORDER
            if acceptance_id == "V2-AC-40"
            else tuple(
                phase_name
                for phase_name, required in gate.PHASE_REQUIRED_CHECKS.items()
                if owned.intersection(required)
            )
        )
        phase_by_name = {phase["name"]: phase for phase in phases}  # type: ignore[index]
        statuses.extend(phase_by_name[name]["status"] for name in phase_names)  # type: ignore[index]
        acceptance[acceptance_id]["status"] = aggregate(statuses)  # type: ignore[index]
    status = aggregate([
        *(checks[name]["status"] for name in gate.REQUIRED_CHECKS),  # type: ignore[index]
        *(phase["status"] for phase in phases),  # type: ignore[index]
    ])
    document["status"] = status
    document["processExitCode"] = gate.STATUS_EXIT_CODES[status]


def fixture(*, completed_non_cleanup_phases: int = 3) -> dict[str, object]:
    checks: dict[str, dict[str, str]] = {
        name: {"status": "NOT_COVERED", "detailCode": "NOT_OBSERVED"}
        for name in gate.REQUIRED_CHECKS
    }
    phases: list[dict[str, object]] = []
    completed_names = set(gate.PHASE_ORDER[:completed_non_cleanup_phases])
    for name in gate.PHASE_ORDER[:-1]:
        if name in completed_names:
            phases.append({
                "name": name,
                "status": "PASS",
                "startedAt": TIMESTAMP,
                "finishedAt": TIMESTAMP,
                "detailCode": gate.PHASE_PASS_DETAILS[name],
            })
            for check_name in gate.PHASE_REQUIRED_CHECKS[name]:
                checks[check_name] = {
                    "status": "PASS",
                    "detailCode": gate.CHECK_PASS_DETAILS[check_name],
                }
        else:
            phases.append({
                "name": name,
                "status": "NOT_COVERED",
                "startedAt": None,
                "finishedAt": None,
                "detailCode": "STOPPED_BEFORE_PHASE",
            })

    checks["cleanup.exactOwnedResources"] = {
        "status": "PASS",
        "detailCode": "EXACT_OWNED_CLEANUP_PASS",
    }
    phases.append({
        "name": "cleanup",
        "status": "PASS",
        "startedAt": TIMESTAMP,
        "finishedAt": TIMESTAMP,
        "detailCode": "EXACT_OWNED_CLEANUP_PASS",
    })

    acceptance: dict[str, dict[str, str]] = {}
    for acceptance_id, names in gate.ACCEPTANCE_GROUPS.items():
        statuses = [checks[name]["status"] for name in names]
        owned = set(names)
        phase_names = (
            gate.PHASE_ORDER
            if acceptance_id == "V2-AC-40"
            else tuple(
                phase_name
                for phase_name, required in gate.PHASE_REQUIRED_CHECKS.items()
                if owned.intersection(required)
            )
        )
        phase_by_name = {str(phase["name"]): phase for phase in phases}
        statuses.extend(str(phase_by_name[name]["status"]) for name in phase_names)
        acceptance[acceptance_id] = {"status": aggregate(statuses)}
    status = aggregate([
        *(checks[name]["status"] for name in gate.REQUIRED_CHECKS),
        *(str(phase["status"]) for phase in phases),
    ])
    observations: dict[str, object] = {}
    if "v2-migration" in completed_names:
        observations = {
            "v1MigrationSha256": {name: SHA256 for name in gate.V1_MIGRATION_FILES},
            "v1TableCount": 10,
            "v2TableCount": 12,
            "v1ProjectionCount": 42,
            "flywayVersions": [1, 2, 3, 4, 5, 6, 7],
            "flywayHistory": [
                {
                    "installedRank": index,
                    "version": index,
                    "description": Path(name).name.split("__", 1)[1][:-4].replace("_", " "),
                    "type": "SQL",
                    "script": Path(name).name,
                    "checksum": index,
                    "success": True,
                    "scriptSha256": SHA256,
                }
                for index, name in enumerate(gate.V2_MIGRATION_FILES, start=1)
            ],
            "credentialTypesCapturedBeforeUpgrade": [
                "OAUTH_ACCESS_TOKEN",
                "OAUTH_CLIENT_SECRET",
                "OAUTH_REFRESH_TOKEN",
                "PERSONAL_ACCESS_TOKEN",
                "SERVICE_ACCOUNT_TOKEN",
            ],
        }
    report_count = max(
        (
            count
            for check_name, count in gate.SDK_MINIMUM_REPORTS_BY_CHECK
            if checks[check_name]["status"] == "PASS"
        ),
        default=0,
    )
    if report_count:
        observations["mcpSdkSurefire"] = sdk_reports(report_count)
    if checks["browser.playwright"]["status"] == "PASS":
        observations["playwright"] = playwright_report()

    return {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-40",
        "status": status,
        "processExitCode": gate.STATUS_EXIT_CODES[status],
        "generatedAt": GENERATED_AT,
        "source": {
            "v1Tag": gate.V1_TAG,
            "v1Commit": gate.V1_COMMIT,
            "toolPath": gate.TOOL_PATH,
            "toolSha256": SHA256,
            "schemaPath": gate.SCHEMA_PATH,
            "schemaSha256": SHA256,
            "v2Commit": "b" * 40,
            "v2Tree": "c" * 40,
            "cleanWorktree": True,
            "currentAdapterSnapshotSha256": {
                name: SHA256 for name in gate.CURRENT_ADAPTER_FILES
            },
            "runtimeSourceSha256": {
                name: SHA256 for name in gate.RUNTIME_SOURCE_FILES
            },
            "inputImageReferences": {
                "mysql": "mysql:8.4",
                "redis": "redis:7.4-alpine",
            },
            "resolvedImageIds": {
                "v2-app": "sha256:" + "1" * 64,
                "v2-nginx": "sha256:" + "2" * 64,
                "mysql": "sha256:" + "3" * 64,
                "redis": "sha256:" + "4" * 64,
            },
            "builtV1ImageIds": {
                "v1-app": "sha256:" + "5" * 64,
                "v1-nginx": "sha256:" + "6" * 64,
            },
            "builtV2ImageIds": {
                "v2-app": "sha256:" + "1" * 64,
                "v2-nginx": "sha256:" + "2" * 64,
            },
            "dependencySeed": dependency_seed(),
        },
        "run": {
            "runId": RUN_ID,
            "composeProject": f"web-starter-ac40-{RUN_ID}",
            "sourceDatabase": f"ws_v1_{RUN_ID}",
            "targetDatabase": f"ws_v1_{RUN_ID}_restore_v2",
            "publishedPortCount": 3,
            "loopbackOnly": True,
            "containerImageIds": {
                **({
                    "v1": {
                        "mysql": "sha256:" + "3" * 64,
                        "redis": "sha256:" + "4" * 64,
                        "app": "sha256:" + "5" * 64,
                        "nginx": "sha256:" + "6" * 64,
                        "mcp-public-nginx": "sha256:" + "6" * 64,
                    },
                } if completed_non_cleanup_phases >= 4 else {}),
                **({
                    "v2": {
                        "mysql": "sha256:" + "3" * 64,
                        "redis": "sha256:" + "4" * 64,
                        "app": "sha256:" + "1" * 64,
                        "nginx": "sha256:" + "2" * 64,
                        "mcp-public-nginx": "sha256:" + "2" * 64,
                    },
                } if completed_non_cleanup_phases >= 6 else {}),
            },
        },
        "phases": phases,
        "checks": checks,
        "acceptance": acceptance,
        "observations": observations,
        "privateCommandLogs": {
            "persisted": False,
            "count": 12,
            "aggregateSha256": SHA256,
        },
        "cleanup": {
            "status": "PASS",
            "exactOwnershipVerified": True,
            "removed": {
                "containers": 0, "volumes": 0, "networks": 0,
                "imageTags": 0, "images": 0,
            },
            "residual": {
                "containers": False, "volumes": False, "networks": False,
                "imageTags": False, "images": False,
            },
            "failureCodes": [],
            "privateRuntimeRemoved": True,
        },
        "evidencePolicy": {
            "outsideRepository": True,
            "directoryMode": "0700",
            "fileMode": "0600",
            "containsSecrets": False,
            "privateRuntimePersisted": False,
        },
    }


def credential_phase_failure(
    passed_check: str,
    report_count: int,
) -> dict[str, object]:
    document = fixture(completed_non_cleanup_phases=6)
    document["phases"][6].update({  # type: ignore[union-attr]
        "status": "FAIL",
        "startedAt": TIMESTAMP,
        "finishedAt": TIMESTAMP,
        "detailCode": "CREDENTIAL_RUNTIME_FAILED",
    })
    document["checks"][passed_check] = {  # type: ignore[index]
        "status": "PASS",
        "detailCode": gate.CHECK_PASS_DETAILS[passed_check],
    }
    document["observations"]["mcpSdkSurefire"] = sdk_reports(report_count)  # type: ignore[index]
    recompute_aggregates(document)
    return document


class ValidateV1UpgradeEvidenceTest(unittest.TestCase):
    def assert_invalid(self, document: dict[str, object], pattern: str | None = None) -> None:
        with self.assertRaises(gate.EvidenceValidationError) as raised:
            gate.validate_document(document)
        if pattern is not None:
            self.assertIn(pattern, str(raised.exception))

    def test_current_preflight_only_document_is_semantically_valid_but_not_pass(self) -> None:
        summary = gate.validate_document(fixture())
        self.assertEqual("NOT_COVERED", summary["status"])
        self.assertEqual(6, summary["processExitCode"])
        self.assertEqual(36, summary["checkCount"])
        self.assertEqual(5, summary["acceptanceCount"])
        self.assertEqual(10, summary["phaseCount"])

    def test_complete_document_passes_with_refresh_rotation_and_reuse_proof(self) -> None:
        document = fixture(completed_non_cleanup_phases=9)
        summary = gate.validate_document(document)
        self.assertEqual("PASS", summary["status"])
        reports = document["observations"]["mcpSdkSurefire"]  # type: ignore[index]
        self.assertEqual(7, len(reports))
        self.assertEqual(
            list(gate.SDK_CLASS_ORDER),
            [report["testClass"] for report in reports],
        )

    def test_pass_path_binds_head_tree_and_all_declared_bytes_to_clean_candidate(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, seed_anchor = create_dependency_seed(
                Path(seed_dir), repository, document
            )
            path = write_evidence(Path(evidence_dir), document)

            summary = gate.validate_document_path(
                path,
                repository_root=repository,
                dependency_seed=seed_root,
                expected_dependency_seed_sha256=seed_anchor,
            )

            self.assertEqual("PASS", summary["status"])
            command = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__).resolve()),
                    "--document", str(path),
                    "--repository-root", str(repository),
                    "--dependency-seed", str(seed_root),
                    "--expected-dependency-seed-sha256", seed_anchor,
                    "--require-pass",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, command.returncode, command.stdout + command.stderr)
            self.assertIn("status=PASS", command.stdout)

    def test_physical_seed_rejects_drift_in_every_mcp_reactor_pom(self) -> None:
        reactor_poms = (
            "pom.xml",
            "web-starter-core/pom.xml",
            "web-starter-system/pom.xml",
            "web-starter-security/pom.xml",
            "web-starter-project/pom.xml",
            "web-starter-mcp/pom.xml",
        )
        for relative in reactor_poms:
            with (
                self.subTest(reactor_pom=relative),
                tempfile.TemporaryDirectory(
                    prefix="web-starter-candidate-pom-drift-"
                ) as candidate_dir,
                tempfile.TemporaryDirectory(
                    prefix="web-starter-evidence-pom-drift-"
                ) as evidence_dir,
                tempfile.TemporaryDirectory(
                    prefix="web-starter-seed-pom-drift-"
                ) as seed_dir,
            ):
                repository = create_clean_candidate(Path(candidate_dir))
                document = fixture(completed_non_cleanup_phases=9)
                bind_to_candidate(document, repository)
                seed_root, trusted_anchor = create_dependency_seed(
                    Path(seed_dir), repository, document
                )

                reactor_pom = repository / relative
                reactor_pom.write_bytes(
                    reactor_pom.read_bytes() + b"changed reactor pom\n"
                )
                git(repository, "add", "--", relative)
                git(repository, "commit", "-m", f"change {relative}")
                bind_to_candidate(document, repository)
                self.assertEqual("PASS", gate.validate_document(document)["status"])
                path = write_evidence(Path(evidence_dir), document)

                with self.assertRaisesRegex(
                    gate.EvidenceValidationError,
                    "manifest is not bound to current candidate bytes",
                ):
                    gate.validate_document_path(
                        path,
                        repository_root=repository,
                        dependency_seed=seed_root,
                        expected_dependency_seed_sha256=trusted_anchor,
                    )

    def test_pass_path_rejects_internally_consistent_forged_candidate_hashes(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, seed_anchor = create_dependency_seed(
                Path(seed_dir), repository, document
            )
            forge_internally_consistent_candidate_hashes(document)
            self.assertEqual("PASS", gate.validate_document(document)["status"])
            path = write_evidence(Path(evidence_dir), document)

            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "does not match the current Git candidate bytes",
            ):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    dependency_seed=seed_root,
                    expected_dependency_seed_sha256=seed_anchor,
                )

    def test_pass_path_rejects_forged_candidate_identity_and_dirty_worktree(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, seed_anchor = create_dependency_seed(
                Path(seed_dir), repository, document
            )
            for field, forged in (("v2Commit", "e" * 40), ("v2Tree", "d" * 40)):
                document["source"][field] = forged  # type: ignore[index]
                self.assertEqual("PASS", gate.validate_document(document)["status"])
                path = write_evidence(Path(evidence_dir), document)
                with self.subTest(field=field), self.assertRaisesRegex(
                    gate.EvidenceValidationError,
                    field,
                ):
                    gate.validate_document_path(
                        path,
                        repository_root=repository,
                        dependency_seed=seed_root,
                        expected_dependency_seed_sha256=seed_anchor,
                    )
                bind_to_candidate(document, repository)

            path = write_evidence(Path(evidence_dir), document)
            (repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(gate.EvidenceValidationError, "not clean"):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    dependency_seed=seed_root,
                    expected_dependency_seed_sha256=seed_anchor,
                )

    def test_pass_path_requires_physical_seed_and_external_trust_anchor(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            path = write_evidence(Path(evidence_dir), document)

            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "requires dependency seed and external SHA-256 trust anchor",
            ):
                gate.validate_document_path(path, repository_root=repository)

    def test_framework_relative_links_are_bound_by_their_raw_target_bytes(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, first_anchor = create_dependency_seed(
                Path(seed_dir), repository, document
            )
            current = (
                seed_root
                / gate.DEPENDENCY_SEED_COMPONENT_PATHS["playwrightBrowsers"]
                / "chromium-1228/Framework.framework/Versions/Current"
            )
            self.assertEqual("149.0", os.readlink(current))
            current.unlink()
            current.symlink_to("./149.0", target_is_directory=True)
            second_anchor = bind_document_to_dependency_seed(
                seed_root, repository, document
            )
            self.assertNotEqual(first_anchor, second_anchor)
            path = write_evidence(Path(evidence_dir), document)

            summary = gate.validate_document_path(
                path,
                repository_root=repository,
                dependency_seed=seed_root,
                expected_dependency_seed_sha256=second_anchor,
                require_pass=True,
            )
            self.assertEqual("PASS", summary["status"])

    def test_playwright_link_policy_rejects_escape_dangling_and_cycles(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="web-starter-candidate-"
        ) as candidate_dir:
            repository = create_clean_candidate(Path(candidate_dir))
            for case in (
                "non-playwright",
                "absolute",
                "escape",
                "escape-reentry",
                "dangling",
                "resolution-cycle",
                "directory-cycle",
            ):
                with (
                    self.subTest(case=case),
                    tempfile.TemporaryDirectory(
                        prefix=f"web-starter-seed-{case}-"
                    ) as seed_dir,
                    tempfile.TemporaryDirectory(
                        prefix=f"web-starter-evidence-{case}-"
                    ) as evidence_dir,
                ):
                    document = fixture(completed_non_cleanup_phases=9)
                    bind_to_candidate(document, repository)
                    seed_root, trusted_anchor = create_dependency_seed(
                        Path(seed_dir), repository, document
                    )
                    browser_root = (
                        seed_root
                        / gate.DEPENDENCY_SEED_COMPONENT_PATHS["playwrightBrowsers"]
                    )
                    if case == "non-playwright":
                        unsafe = (
                            seed_root
                            / gate.DEPENDENCY_SEED_COMPONENT_PATHS["mavenRepository"]
                            / "unsafe-link"
                        )
                        unsafe.symlink_to("org/example/demo/1.0/demo-1.0.jar")
                    elif case == "absolute":
                        (browser_root / "unsafe").symlink_to(
                            (browser_root / "chromium-1228/chrome").resolve()
                        )
                    elif case == "escape":
                        outside = Path(seed_dir) / "outside-browser-seed"
                        outside.write_bytes(b"outside\n")
                        (browser_root / "unsafe").symlink_to(
                            os.path.relpath(outside, browser_root)
                        )
                    elif case == "escape-reentry":
                        (browser_root / "unsafe").symlink_to(
                            "../playwright-browsers/chromium-1228/chrome"
                        )
                    elif case == "dangling":
                        (browser_root / "unsafe").symlink_to("missing-browser-file")
                    elif case == "resolution-cycle":
                        (browser_root / "first").symlink_to("second")
                        (browser_root / "second").symlink_to("first")
                    else:
                        first = browser_root / "first"
                        second = browser_root / "second"
                        first.mkdir(mode=0o700)
                        second.mkdir(mode=0o700)
                        (first / "to-second").symlink_to(
                            "../second", target_is_directory=True
                        )
                        (second / "to-first").symlink_to(
                            "../first", target_is_directory=True
                        )
                    path = write_evidence(Path(evidence_dir), document)

                    with self.assertRaisesRegex(
                        gate.EvidenceValidationError,
                        "link|cyclic|escapes|relative",
                    ):
                        gate.validate_document_path(
                            path,
                            repository_root=repository,
                            dependency_seed=seed_root,
                            expected_dependency_seed_sha256=trusted_anchor,
                        )

    def test_component_tamper_and_recomputed_public_aggregate_cannot_bypass_anchor(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, trusted_anchor = create_dependency_seed(
                Path(seed_dir), repository, document
            )

            tampered_component = (
                seed_root
                / gate.DEPENDENCY_SEED_COMPONENT_PATHS["pnpmStore"]
                / "v3/files/00/cache-entry"
            )
            tampered_component.write_bytes(b"forged pnpm cache\n")
            forged_anchor = bind_document_to_dependency_seed(
                seed_root, repository, document
            )
            self.assertNotEqual(trusted_anchor, forged_anchor)
            self.assertEqual(
                forged_anchor,
                document["source"]["dependencySeed"]["aggregateSha256"],  # type: ignore[index]
            )
            path = write_evidence(Path(evidence_dir), document)

            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "external SHA-256 trust anchor",
            ):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    dependency_seed=seed_root,
                    expected_dependency_seed_sha256=trusted_anchor,
                )

    def test_physical_seed_rescan_enforces_private_modes_and_exact_layout(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, trusted_anchor = create_dependency_seed(
                Path(seed_dir), repository, document
            )
            path = write_evidence(Path(evidence_dir), document)
            cache_entry = (
                seed_root
                / gate.DEPENDENCY_SEED_COMPONENT_PATHS["pnpmStore"]
                / "v3/files/00/cache-entry"
            )
            cache_entry.chmod(0o644)

            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "owner-readable without group, other",
            ):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    dependency_seed=seed_root,
                    expected_dependency_seed_sha256=trusted_anchor,
                )
            cache_entry.chmod(0o600)
            write_seed_file(seed_root / "unexpected", b"not allowed\n")
            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "top-level layout is not exact",
            ):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    dependency_seed=seed_root,
                    expected_dependency_seed_sha256=trusted_anchor,
                )

    def test_physical_seed_platform_identity_cannot_be_relabelled(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="web-starter-candidate-") as candidate_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-evidence-") as evidence_dir,
            tempfile.TemporaryDirectory(prefix="web-starter-seed-") as seed_dir,
        ):
            repository = create_clean_candidate(Path(candidate_dir))
            document = fixture(completed_non_cleanup_phases=9)
            bind_to_candidate(document, repository)
            seed_root, _ = create_dependency_seed(Path(seed_dir), repository, document)
            manifest_path = seed_root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["architecture"] = "forged-architecture"
            manifest_bytes = (
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            write_seed_file(manifest_path, manifest_bytes)
            seed_evidence = document["source"]["dependencySeed"]  # type: ignore[index]
            seed_evidence["architecture"] = "forged-architecture"  # type: ignore[index]
            seed_evidence["manifestSha256"] = hashlib.sha256(  # type: ignore[index]
                manifest_bytes
            ).hexdigest()
            recompute_dependency_seed_aggregate(seed_evidence)  # type: ignore[arg-type]
            forged_anchor = seed_evidence["aggregateSha256"]  # type: ignore[index]
            path = write_evidence(Path(evidence_dir), document)

            with self.assertRaisesRegex(
                gate.EvidenceValidationError,
                "identity does not match the validator runtime",
            ):
                gate.validate_document_path(
                    path,
                    repository_root=repository,
                    dependency_seed=seed_root,
                    expected_dependency_seed_sha256=forged_anchor,  # type: ignore[arg-type]
                )

    def test_flyway_history_is_exact_and_cross_bound_to_frozen_migration_hashes(self) -> None:
        document = fixture(completed_non_cleanup_phases=9)
        history = document["observations"]["flywayHistory"]  # type: ignore[index]
        history[4]["checksum"] = 2**31  # type: ignore[index]
        self.assert_invalid(document, "checksum")

        document = fixture(completed_non_cleanup_phases=9)
        history = document["observations"]["flywayHistory"]  # type: ignore[index]
        history[5]["scriptSha256"] = "b" * 64  # type: ignore[index]
        self.assert_invalid(document, "cross-bound")

        document = fixture(completed_non_cleanup_phases=9)
        history = document["observations"]["flywayHistory"]  # type: ignore[index]
        history.pop()  # type: ignore[union-attr]
        self.assert_invalid(document, "seven rows")
        self.assertEqual(
            "PASS",
            document["acceptance"]["V2-AC-05"]["status"],  # type: ignore[index]
        )

    def test_sdk_reports_accept_only_the_exact_seven_call_prefix_and_milestone_minimums(self) -> None:
        valid_documents = [
            fixture(completed_non_cleanup_phases=4),
            credential_phase_failure("oauth.preUpgradeUserAuthorizationAccepted", 3),
            credential_phase_failure("credential.preUpgradeRefreshRotationAccepted", 3),
            credential_phase_failure("compatibility.mcpReadAndDiscovery", 4),
            credential_phase_failure("credential.oldPatRead", 5),
            credential_phase_failure("credential.preUpgradeServiceAccessAccepted", 6),
            fixture(completed_non_cleanup_phases=9),
        ]
        for index, document in enumerate(valid_documents):
            with self.subTest(valid_prefix=index):
                gate.validate_document(document)

        for index, document in enumerate(valid_documents):
            reports = document["observations"]["mcpSdkSurefire"]  # type: ignore[index]
            if not reports:
                continue
            reports.pop()
            with self.subTest(short_prefix=index):
                self.assert_invalid(document, "shorter than its passed check milestones")

    def test_sdk_reports_reject_reordering_extra_calls_and_non_exact_test_counts(self) -> None:
        reordered = credential_phase_failure("compatibility.mcpReadAndDiscovery", 4)
        reordered["observations"]["mcpSdkSurefire"][3]["testClass"] = (  # type: ignore[index]
            "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT"
        )
        self.assert_invalid(reordered, "exact producer execution prefix")

        extra = fixture(completed_non_cleanup_phases=9)
        extra["observations"]["mcpSdkSurefire"].append(sdk_reports(1)[0])  # type: ignore[index]
        self.assert_invalid(extra, "too many reports")

        multiple_tests = fixture(completed_non_cleanup_phases=4)
        multiple_tests["observations"]["mcpSdkSurefire"][0]["tests"] = 2  # type: ignore[index]
        self.assert_invalid(multiple_tests, "exactly one test")

    def test_rejects_unknown_and_missing_fields_at_nested_boundaries(self) -> None:
        unknown = fixture()
        unknown["invented"] = True
        self.assert_invalid(unknown, "unknown=invented")
        nested = fixture()
        nested["run"]["invented"] = True  # type: ignore[index]
        self.assert_invalid(nested, "run fields")
        missing = fixture()
        del missing["cleanup"]["residual"]  # type: ignore[index]
        self.assert_invalid(missing, "missing=residual")

    def test_pass_requires_exact_hash_maps_and_all_present_hashes_are_canonical(self) -> None:
        missing = fixture(completed_non_cleanup_phases=9)
        del missing["source"]["currentAdapterSnapshotSha256"][gate.CURRENT_ADAPTER_FILES[0]]  # type: ignore[index]
        self.assert_invalid(missing, "exact for PASS")
        extra = fixture()
        extra["source"]["runtimeSourceSha256"]["invented"] = SHA256  # type: ignore[index]
        self.assert_invalid(extra, "unknown keys: invented")
        uppercase = fixture()
        uppercase["source"]["runtimeSourceSha256"][gate.RUNTIME_SOURCE_FILES[0]] = "A" * 64  # type: ignore[index]
        self.assert_invalid(uppercase, "lowercase SHA-256")

    def test_dependency_seed_requires_exact_offline_private_copy_and_source_binding(self) -> None:
        missing = fixture(completed_non_cleanup_phases=9)
        missing["source"]["dependencySeed"] = {}  # type: ignore[index]
        self.assert_invalid(missing, "complete for PASS")

        online = fixture()
        online["source"]["dependencySeed"]["executionPolicy"]["mavenOffline"] = False  # type: ignore[index]
        self.assert_invalid(online, "offline-only")

        retry = fixture()
        retry["source"]["dependencySeed"]["executionPolicy"]["dependencyRetries"] = 1  # type: ignore[index]
        self.assert_invalid(retry, "offline-only")

        source_drift = fixture()
        source_drift["source"]["dependencySeed"]["sourceSha256"]["pom.xml"] = "b" * 64  # type: ignore[index]
        self.assert_invalid(source_drift, "runtimeSourceSha256")

        unknown_component = fixture()
        unknown_component["source"]["dependencySeed"]["components"]["invented"] = {  # type: ignore[index]
            "treeSha256": SHA256, "fileCount": 1, "byteCount": 1,
        }
        self.assert_invalid(unknown_component, "unknown=invented")

        empty_component = fixture()
        empty_component["source"]["dependencySeed"]["components"]["pnpmStore"]["fileCount"] = 0  # type: ignore[index]
        self.assert_invalid(empty_component, "integer >= 1")

        aggregate = fixture()
        aggregate["source"]["dependencySeed"]["aggregateSha256"] = "f" * 64  # type: ignore[index]
        self.assert_invalid(aggregate, "does not match its public fields")

    def test_fail_closed_non_pass_document_accepts_null_identity_and_partial_known_maps(self) -> None:
        document = fixture()
        document["phases"][0].update({  # type: ignore[union-attr]
            "status": "FAIL",
            "detailCode": "SOURCE_FREEZE_FAILED",
        })
        for phase in document["phases"][1:-1]:  # type: ignore[index]
            phase.update({
                "status": "NOT_COVERED",
                "startedAt": None,
                "finishedAt": None,
                "detailCode": "STOPPED_BEFORE_PHASE",
            })
        for name in gate.REQUIRED_CHECKS:
            if name != "cleanup.exactOwnedResources":
                document["checks"][name] = {  # type: ignore[index]
                    "status": "NOT_COVERED",
                    "detailCode": "NOT_OBSERVED",
                }
        document["acceptance"]["V2-AC-40"]["status"] = "FAIL"  # type: ignore[index]
        document["status"] = "FAIL"
        document["processExitCode"] = 1
        source = document["source"]  # type: ignore[assignment]
        source["toolSha256"] = None  # type: ignore[index]
        source["schemaSha256"] = None  # type: ignore[index]
        source["v2Commit"] = None  # type: ignore[index]
        source["v2Tree"] = None  # type: ignore[index]
        source["cleanWorktree"] = False  # type: ignore[index]
        source["currentAdapterSnapshotSha256"] = {}  # type: ignore[index]
        source["runtimeSourceSha256"] = {}  # type: ignore[index]
        source["inputImageReferences"] = {"mysql": "mysql:8.4"}  # type: ignore[index]
        source["resolvedImageIds"] = {}  # type: ignore[index]
        source["builtV1ImageIds"] = {}  # type: ignore[index]
        source["builtV2ImageIds"] = {}  # type: ignore[index]
        document["run"]["containerImageIds"] = {}  # type: ignore[index]
        self.assertEqual("FAIL", gate.validate_document(document)["status"])

    def test_rejects_bad_git_ids_naked_sha_aliases_and_noncanonical_image_ids(self) -> None:
        git_id = fixture()
        git_id["source"]["v2Commit"] = "B" * 40  # type: ignore[index]
        self.assert_invalid(git_id, "lowercase Git object ID")
        for prefix in ("sha256:", "SHA256:"):
            naked = fixture()
            naked["source"]["inputImageReferences"]["mysql"] = prefix + "1" * 64  # type: ignore[index]
            with self.subTest(prefix=prefix):
                self.assert_invalid(naked, "naked sha256")
        image_id = fixture()
        image_id["source"]["resolvedImageIds"]["v2-app"] = "sha256:" + "A" * 64  # type: ignore[index]
        self.assert_invalid(image_id, "lowercase sha256 image ID")

    def test_rejects_unknown_image_keys_missing_resolution_provenance_and_cross_binding_drift(self) -> None:
        unknown = fixture()
        unknown["source"]["builtV1ImageIds"]["worker"] = "sha256:" + "7" * 64  # type: ignore[index]
        self.assert_invalid(unknown, "unknown keys: worker")

        missing_reference = fixture()
        del missing_reference["source"]["inputImageReferences"]["mysql"]  # type: ignore[index]
        self.assert_invalid(missing_reference, "matching input image references")

        no_provenance = fixture(completed_non_cleanup_phases=4)
        del no_provenance["source"]["builtV1ImageIds"]["v1-app"]  # type: ignore[index]
        self.assert_invalid(no_provenance, "no source image provenance")

        v1_drift = fixture(completed_non_cleanup_phases=4)
        v1_drift["run"]["containerImageIds"]["v1"]["app"] = "sha256:" + "7" * 64  # type: ignore[index]
        self.assert_invalid(v1_drift, "not cross-bound")

        v2_drift = fixture(completed_non_cleanup_phases=9)
        v2_drift["run"]["containerImageIds"]["v2"]["mcp-public-nginx"] = "sha256:" + "7" * 64  # type: ignore[index]
        self.assert_invalid(v2_drift, "not cross-bound")

    def test_pass_rejects_partial_runtime_image_sets_and_dirty_or_null_source_identity(self) -> None:
        partial = fixture(completed_non_cleanup_phases=9)
        del partial["run"]["containerImageIds"]["v2"]["redis"]  # type: ignore[index]
        self.assert_invalid(partial, "exact for PASS")
        dirty = fixture(completed_non_cleanup_phases=9)
        dirty["source"]["cleanWorktree"] = False  # type: ignore[index]
        self.assert_invalid(dirty, "cleanWorktree")
        null_commit = fixture(completed_non_cleanup_phases=9)
        null_commit["source"]["v2Commit"] = None  # type: ignore[index]
        self.assert_invalid(null_commit, "present for PASS")

    def test_rejects_run_names_not_derived_from_the_run_id(self) -> None:
        for field in ("composeProject", "sourceDatabase", "targetDatabase"):
            document = fixture()
            document["run"][field] = "safe-but-wrong"  # type: ignore[index]
            with self.subTest(field=field):
                self.assert_invalid(document, field)
        document = fixture()
        document["run"]["runId"] = "ABCDEF012345"  # type: ignore[index]
        self.assert_invalid(document, "lowercase hexadecimal")

    def test_rejects_phase_reordering_missing_execution_and_forged_pass_detail(self) -> None:
        reordered = fixture()
        reordered["phases"][0], reordered["phases"][1] = (  # type: ignore[index]
            reordered["phases"][1],
            reordered["phases"][0],
        )
        self.assert_invalid(reordered, "frozen exact order")
        null_pass = fixture()
        null_pass["phases"][0]["startedAt"] = None  # type: ignore[index]
        self.assert_invalid(null_pass, "PASS phase")
        forged = fixture()
        forged["phases"][0]["detailCode"] = "GENERIC_PASS"  # type: ignore[index]
        self.assert_invalid(forged, "forged PASS")

    def test_phase_status_must_agree_with_its_owned_checks(self) -> None:
        missing_check = fixture(completed_non_cleanup_phases=7)
        missing_check["checks"]["credential.preUpgradeRefreshRotationAccepted"] = {  # type: ignore[index]
            "status": "NOT_COVERED",
            "detailCode": "NOT_OBSERVED",
        }
        self.assert_invalid(missing_check, "PASS phase credential-compatibility")

        phase_failure_after_checks = fixture(completed_non_cleanup_phases=7)
        phase_failure_after_checks["phases"][6].update({  # type: ignore[union-attr]
            "status": "FAIL",
            "detailCode": "CREDENTIAL_RUNTIME_FAILED",
        })
        recompute_aggregates(phase_failure_after_checks)
        validated = gate.validate_document(phase_failure_after_checks)
        self.assertEqual("FAIL", validated["status"])
        self.assertEqual(
            "FAIL",
            phase_failure_after_checks["acceptance"]["V2-AC-05"]["status"],  # type: ignore[index]
        )

    def test_environment_phase_participates_in_ac40_and_top_status(self) -> None:
        document = fixture()
        document["phases"][3].update({  # type: ignore[union-attr]
            "status": "ENV_REQUIRED",
            "startedAt": TIMESTAMP,
            "finishedAt": TIMESTAMP,
            "detailCode": "V1_RUNTIME_ENV_REQUIRED",
        })
        document["acceptance"]["V2-AC-40"]["status"] = "ENV_REQUIRED"  # type: ignore[index]
        document["status"] = "ENV_REQUIRED"
        document["processExitCode"] = 6
        self.assertEqual("ENV_REQUIRED", gate.validate_document(document)["status"])

        forged = fixture()
        forged["phases"][3].update({  # type: ignore[union-attr]
            "status": "ENV_REQUIRED",
            "startedAt": TIMESTAMP,
            "finishedAt": TIMESTAMP,
            "detailCode": "V1_RUNTIME_ENV_REQUIRED",
        })
        self.assert_invalid(forged, "V2-AC-40")

    def test_rejects_non_prefix_check_observations_and_forged_pass_details(self) -> None:
        later = fixture()
        later["checks"]["migration.flywayOneThroughSeven"] = {  # type: ignore[index]
            "status": "PASS",
            "detailCode": gate.CHECK_PASS_DETAILS["migration.flywayOneThroughSeven"],
        }
        self.assert_invalid(later, "unexecuted phase")
        forged = fixture()
        forged["checks"]["source.annotatedV1Tag"]["detailCode"] = "GENERIC_PASS"  # type: ignore[index]
        self.assert_invalid(forged, "forged PASS")

    def test_rejects_forged_refresh_token_pass_even_when_aggregates_are_relabelled(self) -> None:
        document = fixture(completed_non_cleanup_phases=9)
        document["checks"]["credential.preUpgradeRefreshRotationAccepted"] = {  # type: ignore[index]
            "status": "PASS",
            "detailCode": "INVENTED_REFRESH_PASS",
        }
        for acceptance_id in ("V2-AC-05", "V2-AC-40"):
            document["acceptance"][acceptance_id]["status"] = "PASS"  # type: ignore[index]
        document["status"] = "PASS"
        document["processExitCode"] = 0
        self.assert_invalid(document, "forged PASS")

    def test_refresh_not_captured_detail_cannot_be_relabelled_pass(self) -> None:
        document = fixture(completed_non_cleanup_phases=9)
        document["checks"]["credential.preUpgradeRefreshRotationAccepted"] = {  # type: ignore[index]
            "status": "PASS",
            "detailCode": "V1_PKCE_REFRESH_NOT_CAPTURED",
        }
        self.assert_invalid(document, "forged PASS")

    def test_recomputes_each_acceptance_top_status_and_process_exit(self) -> None:
        acceptance = fixture()
        acceptance["acceptance"]["V2-AC-04"]["status"] = "PASS"  # type: ignore[index]
        self.assert_invalid(acceptance, "recomputed check/phase aggregate")
        status = fixture()
        status["status"] = "FAIL"
        status["processExitCode"] = 1
        self.assert_invalid(status, "top-level status")
        exit_code = fixture()
        exit_code["processExitCode"] = 0
        self.assert_invalid(exit_code, "processExitCode")

    def test_rejects_cleanup_and_private_runtime_forgery(self) -> None:
        residual = fixture()
        residual["cleanup"]["residual"]["containers"] = True  # type: ignore[index]
        self.assert_invalid(residual, "cleanup PASS")
        private = fixture()
        private["cleanup"]["privateRuntimeRemoved"] = False  # type: ignore[index]
        self.assert_invalid(private, "persistence fields")
        logs = fixture()
        logs["privateCommandLogs"]["persisted"] = True  # type: ignore[index]
        self.assert_invalid(logs, "persistence fields")
        policy = fixture()
        policy["evidencePolicy"]["containsSecrets"] = True  # type: ignore[index]
        self.assert_invalid(policy, "public evidence policy")

    def test_consistent_cleanup_failure_is_valid_and_recomputed_fail(self) -> None:
        document = fixture()
        document["cleanup"].update({  # type: ignore[union-attr]
            "status": "FAIL",
            "exactOwnershipVerified": False,
            "failureCodes": ["container-removal"],
        })
        document["checks"]["cleanup.exactOwnedResources"] = {  # type: ignore[index]
            "status": "FAIL",
            "detailCode": "EXACT_OWNED_CLEANUP_FAILED",
        }
        document["phases"][-1].update({  # type: ignore[union-attr]
            "status": "FAIL",
            "detailCode": "EXACT_OWNED_CLEANUP_FAILED",
        })
        document["acceptance"]["V2-AC-40"]["status"] = "FAIL"  # type: ignore[index]
        document["status"] = "FAIL"
        document["processExitCode"] = 1
        self.assertEqual("FAIL", gate.validate_document(document)["status"])

    def test_rejects_unknown_or_unbound_sdk_observation(self) -> None:
        document = fixture(completed_non_cleanup_phases=9)
        document["observations"]["invented"] = True  # type: ignore[index]
        self.assert_invalid(document, "unknown=invented")
        unbound = fixture(completed_non_cleanup_phases=9)
        unbound["observations"]["mcpSdkSurefire"][0]["rootPomSha256"] = "b" * 64  # type: ignore[index]
        self.assert_invalid(unbound, "frozen root POM")
        failed = fixture(completed_non_cleanup_phases=9)
        failed["observations"]["mcpSdkSurefire"][0]["failures"] = 1  # type: ignore[index]
        self.assert_invalid(failed, "no failures or skips")

    def test_rejects_secret_shaped_public_material(self) -> None:
        document = fixture(completed_non_cleanup_phases=9)
        document["observations"]["mcpSdkSurefire"][0]["reportSha256"] = (  # type: ignore[index]
            ".".join(("eyJ" + "a" * 11, "b" * 11, "c" * 11))
        )
        # The field also violates SHA-256, but either independent safety check
        # must make the document unusable.
        self.assert_invalid(document)

    def test_duplicate_json_keys_are_rejected_before_semantic_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="web-starter-upgrade-evidence-") as directory:
            root = Path(directory)
            path = root / "duplicate.json"
            path.write_text('{"schemaVersion":1,"schemaVersion":1}\n', encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(gate.EvidenceValidationError, "repeats field"):
                gate.load_document(path)

    def test_cli_exits_zero_for_consistent_not_covered_and_nonzero_for_semantic_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="web-starter-upgrade-evidence-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            seed_arguments = [
                "--dependency-seed", str(root / "unused-for-non-pass"),
                "--expected-dependency-seed-sha256", SHA256,
            ]
            valid = root / "valid.json"
            valid.write_text(json.dumps(fixture(), sort_keys=True) + "\n", encoding="utf-8")
            valid.chmod(0o600)
            passed = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__).resolve()),
                    "--document", str(valid),
                    *seed_arguments,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, passed.returncode, passed.stdout + passed.stderr)
            self.assertIn("status=NOT_COVERED", passed.stdout)

            required = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__).resolve()),
                    "--document", str(valid),
                    *seed_arguments,
                    "--require-pass",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(6, required.returncode, required.stdout + required.stderr)
            self.assertIn("status is NOT_COVERED", required.stderr)

            environment_required = fixture()
            environment_required["phases"][3].update({  # type: ignore[union-attr]
                "status": "ENV_REQUIRED",
                "startedAt": TIMESTAMP,
                "finishedAt": TIMESTAMP,
                "detailCode": "V1_RUNTIME_ENV_REQUIRED",
            })
            environment_required["acceptance"]["V2-AC-40"]["status"] = (  # type: ignore[index]
                "ENV_REQUIRED"
            )
            environment_required["status"] = "ENV_REQUIRED"
            environment_required["processExitCode"] = 6
            environment_path = root / "environment-required.json"
            environment_path.write_text(
                json.dumps(environment_required, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            environment_path.chmod(0o600)
            environment_gate = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__).resolve()),
                    "--document", str(environment_path),
                    *seed_arguments,
                    "--require-pass",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(
                6,
                environment_gate.returncode,
                environment_gate.stdout + environment_gate.stderr,
            )
            self.assertIn("status is ENV_REQUIRED", environment_gate.stderr)

            invalid = root / "invalid.json"
            forged = fixture()
            forged["processExitCode"] = 0
            invalid.write_text(json.dumps(forged, sort_keys=True) + "\n", encoding="utf-8")
            invalid.chmod(0o600)
            failed = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__).resolve()),
                    "--document", str(invalid),
                    *seed_arguments,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, failed.returncode)
            self.assertIn("processExitCode", failed.stderr)

    def test_cli_enforces_the_actual_external_0700_0600_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="web-starter-upgrade-evidence-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "evidence.json"
            path.write_text(json.dumps(fixture()) + "\n", encoding="utf-8")
            path.chmod(0o644)
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__).resolve()),
                    "--document", str(path),
                    "--dependency-seed", str(root / "unused-for-policy-failure"),
                    "--expected-dependency-seed-sha256", SHA256,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("0600", result.stderr)

    def test_implementation_is_standard_library_only_and_does_not_import_the_producer(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertNotIn("import rehearse_v1_to_v2_upgrade", source)
        self.assertNotIn("jsonschema", source)
        self.assertEqual(
            {
                "__future__", "argparse", "datetime", "hashlib", "hmac", "json", "os",
                "pathlib", "platform", "re", "stat", "subprocess", "sys", "typing",
            },
            imported,
        )
        self.assertTrue({"socket", "urllib", "http"}.isdisjoint(imported))


if __name__ == "__main__":
    unittest.main()
