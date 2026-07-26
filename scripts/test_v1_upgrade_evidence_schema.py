from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

import scripts.rehearse_v1_to_v2_upgrade as upgrade


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPOSITORY_ROOT / "security" / "v2-v1-upgrade-rehearsal.schema.json"

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

REACTOR_POMS = (
    "pom.xml",
    "web-starter-core/pom.xml",
    "web-starter-system/pom.xml",
    "web-starter-security/pom.xml",
    "web-starter-project/pom.xml",
    "web-starter-mcp/pom.xml",
)

DEPENDENCY_SEED_SOURCE_FILES = (
    *REACTOR_POMS,
    ".mvn/wrapper/maven-wrapper.properties",
    "mvnw",
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
    "web-starter-web/playwright.config.ts",
)

V2_ONLY_MIGRATION_FILES = (
    "web-starter-admin/src/main/resources/db/migration/V4__add_identity_security_epoch.sql",
    "web-starter-admin/src/main/resources/db/migration/V5__add_mcp_idempotency.sql",
    "web-starter-admin/src/main/resources/db/migration/V6__add_mcp_idempotency_audit.sql",
    "web-starter-admin/src/main/resources/db/migration/V7__add_credential_rotation.sql",
)

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
    *REACTOR_POMS,
    ".mvn/wrapper/maven-wrapper.properties",
    "mvnw",
    *V2_ONLY_MIGRATION_FILES,
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkProjectListRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkCrudRuntimeIT.java",
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
    "web-starter-web/playwright.config.ts",
    "web-starter-web/e2e/frontend-quality-runtime.spec.ts",
    "web-starter-web/e2e/release-runtime.spec.ts",
    "web-starter-web/e2e/v1-management-runtime.spec.ts",
)

V1_MIGRATION_FILES = (
    "web-starter-admin/src/main/resources/db/migration/V1__create_core_schema.sql",
    "web-starter-admin/src/main/resources/db/migration/V2__seed_reference_data.sql",
    "web-starter-admin/src/main/resources/db/migration/V3__add_oauth_refresh_token_families.sql",
)
V2_MIGRATION_FILES = V1_MIGRATION_FILES + V2_ONLY_MIGRATION_FILES

SDK_CLASS_ORDER = (
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT",
    "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT",
)

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

ACCEPTANCE_IDS = ("V2-AC-04", "V2-AC-05", "V2-AC-06", "V2-AC-39", "V2-AC-40")

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

SHA256 = "a" * 64
TIMESTAMP = "2026-07-20T00:00:00Z"


def minimal_pass_document() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-40",
        "status": "PASS",
        "processExitCode": 0,
        "generatedAt": TIMESTAMP,
        "source": {
            "v1Tag": "v1.0.0",
            "v1Commit": "5ebdb238650d182c17e1493adf47aaa3324f19cb",
            "toolPath": "scripts/rehearse_v1_to_v2_upgrade.py",
            "toolSha256": SHA256,
            "schemaPath": "security/v2-v1-upgrade-rehearsal.schema.json",
            "schemaSha256": SHA256,
            "v2Commit": "b" * 40,
            "v2Tree": "c" * 40,
            "cleanWorktree": True,
            "currentAdapterSnapshotSha256": {
                name: SHA256 for name in CURRENT_ADAPTER_FILES
            },
            "runtimeSourceSha256": {name: SHA256 for name in RUNTIME_SOURCE_FILES},
            "inputImageReferences": {
                "mysql": "mysql:8.4",
                "redis": "redis:7.4-alpine",
            },
            "resolvedImageIds": {
                name: "sha256:" + character * 64
                for name, character in {
                    "v2-app": "1", "v2-nginx": "2", "mysql": "3", "redis": "4"
                }.items()
            },
            "builtV1ImageIds": {
                "v1-app": "sha256:" + "5" * 64,
                "v1-nginx": "sha256:" + "6" * 64,
            },
            "builtV2ImageIds": {
                "v2-app": "sha256:" + "1" * 64,
                "v2-nginx": "sha256:" + "2" * 64,
            },
            "dependencySeed": {
                "schemaVersion": 1,
                "kind": "web-starter-ac40-dependency-seed",
                "platform": "darwin",
                "architecture": "arm64",
                "versions": {
                    "maven": "3.9.15", "pnpm": "9.15.9",
                    "playwright": "1.61.1", "chromiumRevision": "1228",
                },
                "sourceSha256": {
                    name: SHA256 for name in DEPENDENCY_SEED_SOURCE_FILES
                },
                "components": {
                    name: {"treeSha256": SHA256, "fileCount": 1, "byteCount": 1}
                    for name in upgrade.DEPENDENCY_SEED_COMPONENTS
                },
                "manifestSha256": SHA256,
                "aggregateSha256": SHA256,
                "copiedToPrivateRuntime": True,
                "executionPolicy": dict(upgrade.DEPENDENCY_SEED_EXECUTION_POLICY),
            },
        },
        "run": {
            "runId": "0123456789ab",
            "composeProject": "web-starter-ac40-0123456789ab",
            "sourceDatabase": "ws_v1_0123456789ab",
            "targetDatabase": "ws_v1_0123456789ab_restore_v2",
            "publishedPortCount": 3,
            "loopbackOnly": True,
            "containerImageIds": {
                "v1": {
                    "mysql": "sha256:" + "3" * 64,
                    "redis": "sha256:" + "4" * 64,
                    "app": "sha256:" + "5" * 64,
                    "nginx": "sha256:" + "6" * 64,
                    "mcp-public-nginx": "sha256:" + "6" * 64,
                },
                "v2": {
                    "mysql": "sha256:" + "3" * 64,
                    "redis": "sha256:" + "4" * 64,
                    "app": "sha256:" + "1" * 64,
                    "nginx": "sha256:" + "2" * 64,
                    "mcp-public-nginx": "sha256:" + "2" * 64,
                },
            },
        },
        "phases": [
            {
                "name": name,
                "status": "PASS",
                "startedAt": TIMESTAMP,
                "finishedAt": TIMESTAMP,
                "detailCode": "OBSERVED_PHASE_PASS",
            }
            for name in PHASE_ORDER
        ],
        "checks": {
            name: {"status": "PASS", "detailCode": "OBSERVED_CHECK_PASS"}
            for name in REQUIRED_CHECKS
        },
        "acceptance": {name: {"status": "PASS"} for name in ACCEPTANCE_IDS},
        "observations": {
            "v1MigrationSha256": {name: SHA256 for name in V1_MIGRATION_FILES},
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
                for index, name in enumerate(V2_MIGRATION_FILES, start=1)
            ],
            "credentialTypesCapturedBeforeUpgrade": [
                "OAUTH_ACCESS_TOKEN",
                "OAUTH_CLIENT_SECRET",
                "OAUTH_REFRESH_TOKEN",
                "PERSONAL_ACCESS_TOKEN",
                "SERVICE_ACCOUNT_TOKEN",
            ],
            "mcpSdkSurefire": [
                {
                    "testClass": test_class,
                    "tests": 1,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "reportSha256": SHA256,
                    "testSourceSha256": SHA256,
                    "rootPomSha256": SHA256,
                    "modulePomSha256": SHA256,
                }
                for test_class in SDK_CLASS_ORDER
            ],
            "playwright": {
                "tests": 20,
                "failures": 0,
                "skipped": 0,
                "flaky": 0,
                "reportSha256": SHA256,
                "packageJsonSha256": SHA256,
                "lockfileSha256": SHA256,
                "configSha256": SHA256,
                "testSourceSha256": {
                    "web-starter-web/e2e/frontend-quality-runtime.spec.ts": SHA256,
                    "web-starter-web/e2e/release-runtime.spec.ts": SHA256,
                    "web-starter-web/e2e/v1-management-runtime.spec.ts": SHA256,
                },
            },
        },
        "privateCommandLogs": {
            "persisted": False,
            "count": 0,
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


class V1UpgradeEvidenceSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="web-starter-schema-validator-")
        cls.validator_root = Path(cls.temporary.name)
        cls.classpath = cls._prepare_networknt_validator()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _mcp_sdk_version(cls) -> str:
        namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
        root = ET.parse(REPOSITORY_ROOT / "pom.xml").getroot()
        value = root.findtext("m:properties/m:mcp-sdk.version", namespaces=namespace)
        if not value:
            raise AssertionError("root pom.xml must declare mcp-sdk.version")
        return value.strip()

    @classmethod
    def _prepare_networknt_validator(cls) -> str:
        pom_path = cls.validator_root / "pom.xml"
        classpath_path = cls.validator_root / "classpath.txt"
        java_path = cls.validator_root / "SchemaProbe.java"
        pom_path.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.webstarter.tests</groupId>
  <artifactId>upgrade-schema-probe</artifactId>
  <version>1</version>
  <dependencies>
    <dependency>
      <groupId>io.modelcontextprotocol.sdk</groupId>
      <artifactId>mcp-json-jackson3</artifactId>
      <version>"""
            + cls._mcp_sdk_version()
            + """</version>
    </dependency>
  </dependencies>
</project>
""",
            encoding="utf-8",
        )
        java_path.write_text(
            """import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.nio.file.Files;
import java.nio.file.Path;

public final class SchemaProbe {
    public static void main(String[] args) throws Exception {
        SchemaRegistry registry = SchemaRegistry.withDefaultDialect(
            SpecificationVersion.DRAFT_2020_12
        );
        Schema schema;
        try (var input = Files.newInputStream(Path.of(args[0]))) {
            schema = registry.getSchema(input, InputFormat.JSON);
        }
        for (int index = 1; index < args.length; index++) {
            String instance = Files.readString(Path.of(args[index]));
            System.out.println(schema.validate(instance, InputFormat.JSON).isEmpty()
                ? "VALID" : "INVALID");
        }
    }
}
""",
            encoding="utf-8",
        )
        dependency_result = subprocess.run(
            [
                str(REPOSITORY_ROOT / "mvnw"),
                "-B",
                "-q",
                "-ntp",
                "-f",
                str(pom_path),
                "dependency:build-classpath",
                "-DincludeScope=runtime",
                f"-Dmdep.outputFile={classpath_path}",
            ],
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if dependency_result.returncode != 0:
            raise AssertionError(
                "existing MCP JSON Schema validator classpath could not be resolved:\n"
                + dependency_result.stdout
                + dependency_result.stderr
            )
        classpath = classpath_path.read_text(encoding="utf-8").strip()
        compile_result = subprocess.run(
            ["javac", "-cp", classpath, str(java_path)],
            cwd=cls.validator_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if compile_result.returncode != 0:
            raise AssertionError(
                "existing MCP JSON Schema validator probe did not compile:\n"
                + compile_result.stdout
                + compile_result.stderr
            )
        return os.pathsep.join((classpath, str(cls.validator_root)))

    def assert_documents_validity(
        self, documents: list[dict[str, object]], expected: list[bool]
    ) -> None:
        paths: list[Path] = []
        for index, document in enumerate(documents):
            path = self.validator_root / f"instance-{index}.json"
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            paths.append(path)
        result = subprocess.run(
            [
                "java",
                "-cp",
                self.classpath,
                "SchemaProbe",
                str(SCHEMA_PATH),
                *(str(path) for path in paths),
            ],
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        actual = [line == "VALID" for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(expected, actual, result.stdout + result.stderr)

    def test_schema_locks_the_frozen_exact_sets(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        source_contract = schema["properties"]["source"]
        source = source_contract["properties"]
        pass_contract = schema["allOf"][0]["then"]["properties"]
        pass_source = pass_contract["source"]["properties"]
        runtime_source_contract = source["runtimeSourceSha256"]
        dependency_source_contract = schema["$defs"]["dependencySeed"][
            "properties"
        ]["sourceSha256"]
        exact_dependency_source_contract = schema["$defs"]["exactDependencySeed"][
            "allOf"
        ][1]["properties"]["sourceSha256"]
        phases = schema["properties"]["phases"]
        self.assertEqual(CURRENT_ADAPTER_FILES, upgrade.CURRENT_ADAPTER_FILES)
        self.assertEqual(RUNTIME_SOURCE_FILES, upgrade.CURRENT_RUNTIME_SOURCE_FILES)
        self.assertEqual(
            DEPENDENCY_SEED_SOURCE_FILES,
            upgrade.DEPENDENCY_SEED_SOURCE_FILES,
        )
        self.assertEqual(REQUIRED_CHECKS, upgrade.REQUIRED_CHECKS)
        self.assertEqual(PHASE_ORDER, upgrade.PHASE_ORDER)
        self.assertTrue({
            "v2Commit", "v2Tree", "cleanWorktree", "inputImageReferences",
            "resolvedImageIds", "builtV1ImageIds", "builtV2ImageIds",
            "dependencySeed",
        }.issubset(source_contract["required"]))
        self.assertEqual(
            set(CURRENT_ADAPTER_FILES),
            set(pass_source["currentAdapterSnapshotSha256"]["required"]),
        )
        self.assertEqual(
            set(RUNTIME_SOURCE_FILES),
            set(pass_source["runtimeSourceSha256"]["required"]),
        )
        self.assertEqual(
            set(RUNTIME_SOURCE_FILES),
            set(runtime_source_contract["properties"]),
        )
        self.assertEqual(31, runtime_source_contract["maxProperties"])
        self.assertEqual(31, pass_source["runtimeSourceSha256"]["minProperties"])
        self.assertEqual(31, pass_source["runtimeSourceSha256"]["maxProperties"])
        self.assertEqual(
            set(DEPENDENCY_SEED_SOURCE_FILES),
            set(dependency_source_contract["properties"]),
        )
        self.assertEqual(11, dependency_source_contract["maxProperties"])
        self.assertEqual(
            set(DEPENDENCY_SEED_SOURCE_FILES),
            set(exact_dependency_source_contract["required"]),
        )
        self.assertEqual(11, exact_dependency_source_contract["minProperties"])
        self.assertEqual(11, exact_dependency_source_contract["maxProperties"])
        newly_bound_reactor_poms = set(REACTOR_POMS[1:-1])
        self.assertTrue(
            newly_bound_reactor_poms.issubset(runtime_source_contract["properties"])
        )
        self.assertTrue(
            newly_bound_reactor_poms.issubset(
                dependency_source_contract["properties"]
            )
        )
        self.assertEqual(set(REQUIRED_CHECKS), set(schema["properties"]["checks"]["required"]))
        self.assertEqual(set(ACCEPTANCE_IDS), set(schema["properties"]["acceptance"]["required"]))
        self.assertEqual(10, phases["minItems"])
        self.assertEqual(10, phases["maxItems"])
        self.assertFalse(phases["items"])
        sdk_prefix = schema["$defs"]["mcpSdkReportPrefix"]
        self.assertEqual(7, sdk_prefix["maxItems"])
        self.assertEqual(7, len(sdk_prefix["prefixItems"]))

    def test_minimal_pass_document_is_valid(self) -> None:
        self.assert_documents_validity([minimal_pass_document()], [True])

    def test_pass_rejects_incomplete_or_non_pass_check_and_acceptance_sets(self) -> None:
        non_pass_check = minimal_pass_document()
        non_pass_check["checks"][REQUIRED_CHECKS[0]]["status"] = "NOT_COVERED"  # type: ignore[index]
        missing_check = minimal_pass_document()
        del missing_check["checks"][REQUIRED_CHECKS[-1]]  # type: ignore[index]
        extra_check = minimal_pass_document()
        extra_check["checks"]["invented.pass"] = {  # type: ignore[index]
            "status": "PASS",
            "detailCode": "INVENTED_CHECK_PASS",
        }
        non_pass_acceptance = minimal_pass_document()
        non_pass_acceptance["acceptance"][ACCEPTANCE_IDS[0]]["status"] = "FAIL"  # type: ignore[index]
        missing_acceptance = minimal_pass_document()
        del missing_acceptance["acceptance"][ACCEPTANCE_IDS[-1]]  # type: ignore[index]
        self.assert_documents_validity(
            [
                non_pass_check,
                missing_check,
                extra_check,
                non_pass_acceptance,
                missing_acceptance,
            ],
            [False] * 5,
        )

    def test_phase_order_is_fixed_unique_and_all_pass(self) -> None:
        swapped = minimal_pass_document()
        swapped["phases"][0], swapped["phases"][1] = swapped["phases"][1], swapped["phases"][0]  # type: ignore[index]
        duplicate = minimal_pass_document()
        duplicate["phases"][1] = deepcopy(duplicate["phases"][0])  # type: ignore[index]
        non_pass = minimal_pass_document()
        non_pass["phases"][4]["status"] = "NOT_COVERED"  # type: ignore[index]
        unobserved = minimal_pass_document()
        unobserved["phases"][4]["startedAt"] = None  # type: ignore[index]
        self.assert_documents_validity(
            [swapped, duplicate, non_pass, unobserved],
            [False] * 4,
        )

    def test_sdk_report_sequence_hashes_and_pass_cardinality_are_frozen(self) -> None:
        missing_from_pass = minimal_pass_document()
        missing_from_pass["observations"]["mcpSdkSurefire"].pop()  # type: ignore[index]

        reordered = minimal_pass_document()
        reordered["status"] = "NOT_COVERED"
        reordered["processExitCode"] = 6
        reordered["checks"]["credential.oldPatRead"]["status"] = "NOT_COVERED"  # type: ignore[index]
        reordered["checks"]["credential.preUpgradeServiceAccessAccepted"]["status"] = "NOT_COVERED"  # type: ignore[index]
        reordered["checks"]["credential.oldPatCrud"]["status"] = "NOT_COVERED"  # type: ignore[index]
        reordered["observations"]["mcpSdkSurefire"] = reordered["observations"]["mcpSdkSurefire"][:4]  # type: ignore[index]
        reordered["observations"]["mcpSdkSurefire"][3]["testClass"] = SDK_CLASS_ORDER[4]  # type: ignore[index]

        too_short_for_refresh = deepcopy(reordered)
        too_short_for_refresh["observations"]["mcpSdkSurefire"] = too_short_for_refresh["observations"]["mcpSdkSurefire"][:3]  # type: ignore[index]
        too_short_for_refresh["observations"]["mcpSdkSurefire"][0]["testClass"] = SDK_CLASS_ORDER[0]  # type: ignore[index]
        too_short_for_refresh["observations"]["mcpSdkSurefire"][1]["testClass"] = SDK_CLASS_ORDER[1]  # type: ignore[index]
        too_short_for_refresh["observations"]["mcpSdkSurefire"][2]["testClass"] = SDK_CLASS_ORDER[2]  # type: ignore[index]

        invalid_hash = minimal_pass_document()
        invalid_hash["observations"]["mcpSdkSurefire"][0]["reportSha256"] = "A" * 64  # type: ignore[index]
        multiple_tests = minimal_pass_document()
        multiple_tests["observations"]["mcpSdkSurefire"][0]["tests"] = 2  # type: ignore[index]
        extra = minimal_pass_document()
        extra["observations"]["mcpSdkSurefire"].append(  # type: ignore[index]
            deepcopy(extra["observations"]["mcpSdkSurefire"][0])  # type: ignore[index]
        )
        self.assert_documents_validity(
            [
                missing_from_pass,
                reordered,
                too_short_for_refresh,
                invalid_hash,
                multiple_tests,
                extra,
            ],
            [False] * 6,
        )

        valid_prefix = minimal_pass_document()
        valid_prefix["status"] = "NOT_COVERED"
        valid_prefix["processExitCode"] = 6
        for check_name in (
            "credential.oldPatRead",
            "credential.preUpgradeServiceAccessAccepted",
            "credential.oldPatCrud",
        ):
            valid_prefix["checks"][check_name]["status"] = "NOT_COVERED"  # type: ignore[index]
        valid_prefix["observations"]["mcpSdkSurefire"] = valid_prefix["observations"]["mcpSdkSurefire"][:4]  # type: ignore[index]
        self.assert_documents_validity([valid_prefix], [True])

    def test_source_hash_maps_are_exact_and_sha256_only(self) -> None:
        missing_adapter = minimal_pass_document()
        del missing_adapter["source"]["currentAdapterSnapshotSha256"][CURRENT_ADAPTER_FILES[0]]  # type: ignore[index]
        extra_adapter = minimal_pass_document()
        extra_adapter["source"]["currentAdapterSnapshotSha256"]["scripts/invented.py"] = SHA256  # type: ignore[index]
        missing_runtime_source = minimal_pass_document()
        del missing_runtime_source["source"]["runtimeSourceSha256"][RUNTIME_SOURCE_FILES[0]]  # type: ignore[index]
        missing_reactor_runtime_sources: list[dict[str, object]] = []
        for relative in REACTOR_POMS[1:-1]:
            document = minimal_pass_document()
            del document["source"]["runtimeSourceSha256"][relative]  # type: ignore[index]
            missing_reactor_runtime_sources.append(document)
        extra_runtime_source = minimal_pass_document()
        extra_runtime_source["source"]["runtimeSourceSha256"]["web-starter-extra/pom.xml"] = SHA256  # type: ignore[index]
        old_runtime_cardinality = minimal_pass_document()
        for relative in REACTOR_POMS[1:-1]:
            del old_runtime_cardinality["source"]["runtimeSourceSha256"][relative]  # type: ignore[index]
        self.assertEqual(
            27,
            len(old_runtime_cardinality["source"]["runtimeSourceSha256"]),  # type: ignore[arg-type,index]
        )
        invalid_hash = minimal_pass_document()
        invalid_hash["source"]["runtimeSourceSha256"][RUNTIME_SOURCE_FILES[0]] = "A" * 64  # type: ignore[index]
        self.assert_documents_validity(
            [
                missing_adapter,
                extra_adapter,
                missing_runtime_source,
                *missing_reactor_runtime_sources,
                extra_runtime_source,
                old_runtime_cardinality,
                invalid_hash,
            ],
            [False] * 10,
        )

    def test_pass_dependency_seed_shape_and_offline_policy_are_exact(self) -> None:
        missing = minimal_pass_document()
        del missing["source"]["dependencySeed"]  # type: ignore[index]
        partial = minimal_pass_document()
        del partial["source"]["dependencySeed"]["components"]["pnpmStore"]  # type: ignore[index]
        missing_reactor_seed_sources: list[dict[str, object]] = []
        for relative in REACTOR_POMS[1:-1]:
            document = minimal_pass_document()
            del document["source"]["dependencySeed"]["sourceSha256"][relative]  # type: ignore[index]
            missing_reactor_seed_sources.append(document)
        extra_seed_source = minimal_pass_document()
        extra_seed_source["source"]["dependencySeed"]["sourceSha256"]["web-starter-extra/pom.xml"] = SHA256  # type: ignore[index]
        old_seed_cardinality = minimal_pass_document()
        for relative in REACTOR_POMS[1:-1]:
            del old_seed_cardinality["source"]["dependencySeed"]["sourceSha256"][relative]  # type: ignore[index]
        self.assertEqual(
            7,
            len(old_seed_cardinality["source"]["dependencySeed"]["sourceSha256"]),  # type: ignore[arg-type,index]
        )
        online = minimal_pass_document()
        online["source"]["dependencySeed"]["executionPolicy"]["pnpmOffline"] = False  # type: ignore[index]
        retry = minimal_pass_document()
        retry["source"]["dependencySeed"]["executionPolicy"]["dependencyRetries"] = 1  # type: ignore[index]
        unknown = minimal_pass_document()
        unknown["source"]["dependencySeed"]["invented"] = True  # type: ignore[index]
        self.assert_documents_validity(
            [
                missing,
                partial,
                *missing_reactor_seed_sources,
                extra_seed_source,
                old_seed_cardinality,
                online,
                retry,
                unknown,
            ],
            [False] * 11,
        )

    def test_pass_requires_exact_git_image_and_runtime_binding_shapes(self) -> None:
        missing_git = minimal_pass_document()
        del missing_git["source"]["v2Tree"]  # type: ignore[index]
        short_git = minimal_pass_document()
        short_git["source"]["v2Commit"] = "b" * 39  # type: ignore[index]
        naked_id = minimal_pass_document()
        naked_id["source"]["inputImageReferences"]["mysql"] = "sha256:" + "1" * 64  # type: ignore[index]
        uppercase_naked_id = minimal_pass_document()
        uppercase_naked_id["source"]["inputImageReferences"]["mysql"] = "SHA256:" + "1" * 64  # type: ignore[index]
        partial_input = minimal_pass_document()
        del partial_input["source"]["inputImageReferences"]["redis"]  # type: ignore[index]
        partial_resolved = minimal_pass_document()
        del partial_resolved["source"]["resolvedImageIds"]["redis"]  # type: ignore[index]
        partial_built = minimal_pass_document()
        del partial_built["source"]["builtV1ImageIds"]["v1-nginx"]  # type: ignore[index]
        partial_v2_built = minimal_pass_document()
        del partial_v2_built["source"]["builtV2ImageIds"]["v2-nginx"]  # type: ignore[index]
        partial_runtime = minimal_pass_document()
        del partial_runtime["run"]["containerImageIds"]["v2"]["mcp-public-nginx"]  # type: ignore[index]
        unknown_runtime = minimal_pass_document()
        unknown_runtime["run"]["containerImageIds"]["v2"]["worker"] = "sha256:" + "1" * 64  # type: ignore[index]
        dirty = minimal_pass_document()
        dirty["source"]["cleanWorktree"] = False  # type: ignore[index]
        self.assert_documents_validity(
            [
                missing_git,
                short_git,
                naked_id,
                uppercase_naked_id,
                partial_input,
                partial_resolved,
                partial_built,
                partial_v2_built,
                partial_runtime,
                unknown_runtime,
                dirty,
            ],
            [False] * 11,
        )

    def test_non_pass_evidence_accepts_known_partial_maps_but_not_unknown_keys(self) -> None:
        partial = minimal_pass_document()
        partial["status"] = "NOT_COVERED"
        partial["processExitCode"] = 6
        partial["source"]["toolSha256"] = None  # type: ignore[index]
        partial["source"]["schemaSha256"] = None  # type: ignore[index]
        partial["source"]["v2Commit"] = None  # type: ignore[index]
        partial["source"]["v2Tree"] = None  # type: ignore[index]
        partial["source"]["cleanWorktree"] = False  # type: ignore[index]
        partial["source"]["currentAdapterSnapshotSha256"] = {}  # type: ignore[index]
        partial["source"]["runtimeSourceSha256"] = {}  # type: ignore[index]
        partial["source"]["inputImageReferences"] = {"mysql": "mysql:8.4"}  # type: ignore[index]
        partial["source"]["resolvedImageIds"] = {}  # type: ignore[index]
        partial["source"]["builtV1ImageIds"] = {}  # type: ignore[index]
        partial["source"]["builtV2ImageIds"] = {}  # type: ignore[index]
        partial["run"]["containerImageIds"] = {}  # type: ignore[index]

        unknown = deepcopy(partial)
        unknown["source"]["resolvedImageIds"]["worker"] = "sha256:" + "1" * 64  # type: ignore[index]
        self.assert_documents_validity([partial, unknown], [True, False])

    def test_pass_rejects_cleanup_or_private_log_forgery(self) -> None:
        residual = minimal_pass_document()
        residual["cleanup"]["residual"]["containers"] = True  # type: ignore[index]
        cleanup_failure = minimal_pass_document()
        cleanup_failure["cleanup"]["failureCodes"] = ["container-residual"]  # type: ignore[index]
        private_runtime = minimal_pass_document()
        private_runtime["cleanup"]["privateRuntimeRemoved"] = False  # type: ignore[index]
        private_logs = minimal_pass_document()
        private_logs["privateCommandLogs"]["persisted"] = True  # type: ignore[index]
        policy_persisted = minimal_pass_document()
        policy_persisted["evidencePolicy"]["privateRuntimePersisted"] = True  # type: ignore[index]
        self.assert_documents_validity(
            [residual, cleanup_failure, private_runtime, private_logs, policy_persisted],
            [False] * 5,
        )


if __name__ == "__main__":
    unittest.main()
