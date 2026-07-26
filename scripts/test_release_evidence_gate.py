from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import production_compose_policy as compose_policy
import release_evidence_gate as gate
import release_security_gate as security_gate
from test_production_compose_policy import valid_model as valid_production_model


COMMIT = "c" * 40
TAG = "v2.0.0"
VERSION = "2.0.0"
DIGESTS = {"app": "sha256:" + "a" * 64, "nginx": "sha256:" + "b" * 64}
NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
FIXTURE_PASS_IDS = {
    "AC-01", "V2-AC-02", "V2-AC-03", "V2-AC-18", "V2-AC-38",
    "V2-AC-42", "V2-AC-43", "V2-AC-44",
}
AC40_ARCHIVE_SHA256 = "3" * 64
AC40_AGGREGATE_SHA256 = "4" * 64
AC40_MANIFEST_SHA256 = "5" * 64


def ac40_upgrade_summary() -> dict:
    return {
        "status": "PASS",
        "source": {
            "dependencySeed": {
                "aggregateSha256": AC40_AGGREGATE_SHA256,
                "manifestSha256": AC40_MANIFEST_SHA256,
                "platform": "linux",
                "architecture": "x86_64",
            }
        },
    }


def ac40_dependency_seed_provenance(**overrides: object) -> dict:
    document: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "web-starter-ac40-dependency-seed-provenance",
        "environment": "release",
        "artifactId": 101,
        "workflowRunId": 202,
        "headRepositoryId": 303,
        "producerHeadSha": COMMIT,
        "archiveSha256": AC40_ARCHIVE_SHA256,
        "aggregateSha256": AC40_AGGREGATE_SHA256,
        "manifestSha256": AC40_MANIFEST_SHA256,
        "platform": "linux",
        "architecture": "x86_64",
    }
    document.update(overrides)
    return document


def write_canonical_private_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    )
    path.chmod(0o600)


def v1_source_provenance_summary() -> dict:
    source_paths = (
        "scripts/create_v1_source_provenance_proof.py",
        "scripts/validate_v1_source_provenance_proof.py",
        "security/v2-ac01-v1-source-provenance-summary.schema.json",
        "docs/acceptance/v2-acceptance-baseline.md",
        "pom.xml",
        "web-starter-web/package.json",
    )
    return {
        "schemaVersion": 1,
        "acceptanceId": "V2-AC-01",
        "status": "PASS",
        "candidate": {
            "commit": COMMIT,
            "tree": "d" * 40,
            "tag": TAG,
            "version": VERSION,
        },
        "v1Source": {
            "tag": "v1.0.0",
            "tagObject": "406e73cca6f4d4e257c2aa08e58815d96b7ca722",
            "commit": "5ebdb238650d182c17e1493adf47aaa3324f19cb",
            "tree": "355c61a77f4dd0f16f0f3d945ee6c8d4f02d956a",
            "tagAnnotationSha256": hashlib.sha256(
                "启程 Web Starter V1 verified baseline".encode("utf-8")
            ).hexdigest(),
            "sourceArchiveSha256": "79b220b5a4da72ea3d4bb98203add92bce83fc19e30cd24ebfa084c7bc360ff5",
            "baselinePath": "docs/acceptance/v1-acceptance-baseline.md",
            "baselineBlob": "d59cbbd26c69c0497b6e0bb28e7c2a9306c02a35",
            "baselineSha256": "aa9ef7247246165c451e6910db6da167d1385b6e14f3f65fd72a7705e8263994",
            "acceptanceRecordPath": "docs/acceptance/v1-acceptance-2026-07-19.md",
            "acceptanceRecordBlob": "9e9346046cb4bff5200487281f15fd7621781562",
            "acceptanceRecordSha256": "81ce417c52f004d74275b591d47748f8868226cccaf3e02a21490d42785336f9",
            "acceptanceResultCount": 42,
            "acceptancePassCount": 42,
            "baselineP0Count": 37,
            "baselineP1Count": 5,
            "automationCheckCount": 12,
            "finalCheckedCount": 5,
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
            "reportSha256": "1" * 64,
            "sourceSha256": {path: "2" * 64 for path in source_paths},
        },
    }


def release_runtime_test_reports_summary() -> dict:
    specs = sorted(
        (
            {"file": relative, "title": title}
            for relative, titles in gate.release_runtime_test_reports.PLAYWRIGHT_SPECS.items()
            for title in titles
        ),
        key=lambda item: (item["file"], item["title"]),
    )
    surefire = [
        {
            "reportFile": report,
            "testClass": identity[0],
            "testMethod": identity[1],
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "retries": 0,
        }
        for report, identity in sorted(
            gate.release_runtime_test_reports.SUREFIRE_TESTS.items()
        )
    ]
    return {
        "schemaVersion": 1,
        "evidenceType": "releaseRuntimeTestReports",
        "status": "PASS",
        "candidate": {
            "commit": COMMIT,
            "tree": "d" * 40,
            "version": VERSION,
            "tag": TAG,
            "tagObject": COMMIT,
        },
        "run": {"startedAtEpochNs": 1_753_000_000_000_000_000},
        "coverage": {
            "playwright": {
                "reportFile": gate.release_runtime_test_reports.PLAYWRIGHT_REPORT,
                "tests": gate.release_runtime_test_reports.PLAYWRIGHT_TEST_COUNT,
                "passed": gate.release_runtime_test_reports.PLAYWRIGHT_TEST_COUNT,
                "skipped": 0,
                "retries": 0,
                "projectName": "default",
                "specs": specs,
            },
            "surefire": surefire,
        },
        "reports": {
            name: hashlib.sha256(name.encode("utf-8")).hexdigest()
            for name in sorted(gate.release_runtime_test_reports.RAW_REPORT_FILES)
        },
        "sources": {
            name: hashlib.sha256(name.encode("utf-8")).hexdigest()
            for name in gate.release_runtime_test_reports.SOURCE_PATHS
        },
    }


def credential_lifecycle_summary() -> dict:
    return {
        "schemaVersion": 1,
        "acceptanceIds": ["V2-AC-24", "V2-AC-27", "V2-AC-28", "V2-AC-36"],
        "status": "PASS",
        "candidate": {
            "releaseTag": TAG,
            "releaseVersion": VERSION,
            "gitCommit": COMMIT,
        },
        "runtime": {"composeProject": "web-starter-release-17"},
        "checks": {
            "cascadeInvalidation": "PASS",
            "authorizationCodeLifecycle": "PASS",
            "fixtureCleanup": "PASS",
            "pepperRotation": "PASS",
            "clientSecretRotation": "PASS",
            "clientCredentialsLifecycle": "PASS",
            "serviceAccountLifecycle": "PASS",
            "personalTokenLifecycle": "PASS",
            "unifiedSecurityRegression": "PASS",
            "plaintextCredentialAbsence": "PASS",
        },
    }


def observability_summary() -> dict:
    return {
        "schemaVersion": 1,
        "acceptanceIds": ["V2-AC-37"],
        "status": "PASS",
        "candidate": {
            "gitCommit": COMMIT,
            "gitTree": "d" * 40,
            "tagObject": "e" * 40,
            "releaseVersion": VERSION,
            "releaseTag": TAG,
        },
        "runtime": {
            "composeProject": "web-starter-release-17",
            "images": {},
            "runtimeIdentitySha256": "f" * 64,
        },
        "checks": {"structuredTraceLog": "PASS"},
        "evidence": {},
    }


def tooling_lifecycle_summary() -> dict:
    return {
        "schemaVersion": 1,
        "acceptanceIds": ["AC-02", "AC-37", "V2-AC-16", "V2-AC-17"],
        "status": "PASS",
        "observedAt": "2026-07-19T11:00:00+00:00",
        "candidate": {
            "gitCommit": COMMIT,
            "gitTree": "d" * 40,
            "tagObject": "e" * 40,
            "releaseVersion": VERSION,
            "releaseTag": TAG,
        },
        "runtime": {
            "composeProject": "web-starter-tooling-17-1",
            "images": {},
            "runtimeIdentitySha256": "f" * 64,
            "businessPersistence": {
                "fixtureId": 8_000_000_000_000_000_001,
                "fixtureCode": "TOOLING_0123456789ABCDEF",
                "rowCount": 1,
                "rowSha256": "1" * 64,
            },
            "bootstrapCredential": {
                "firstLoginStatus": 200,
                "secondLoginStatus": 200,
                "passwordHashSha256": "2" * 64,
                "environmentPasswordRemovedBeforeRestart": True,
                "runtimeLogSecretMatches": 0,
                "runtimeLogSha256": {
                    "first": "3" * 64,
                    "second": "4" * 64,
                },
            },
        },
        "checks": {
            "bootstrapAdminLoginPassed": "PASS",
            "bootstrapPasswordRemovedBeforeRestart": "PASS",
            "existingAdminPasswordUnchanged": "PASS",
            "bootstrapSecretAbsentFromRuntimeLogs": "PASS",
            "doctorExactInventory": "PASS",
            "businessDataPersistedAcrossRestart": "PASS",
        },
        "evidence": {},
    }


def mcp_governance_runtime_summary() -> dict:
    sources = {
        relative: hashlib.sha256(relative.encode("utf-8")).hexdigest()
        for relative in gate.mcp_governance_proof.SOURCE_PATHS.values()
    }
    return {
        "schemaVersion": 1,
        "acceptanceIds": ["V2-AC-34", "V2-AC-35"],
        "status": "PASS",
        "candidate": {
            "commit": COMMIT,
            "tree": "d" * 40,
            "version": VERSION,
            "tag": TAG,
        },
        "runtime": {
            "composeProject": "web-starter-governance-17-1",
            "tracePrefix": gate.MCP_GOVERNANCE_TRACE_PREFIX,
            "transport": "Streamable HTTP",
            "officialSdk": True,
            "sdkVersion": "2.0.0",
            "reports": [
                gate.mcp_governance_proof.MAIN_REPORT,
                gate.mcp_governance_proof.SHUTDOWN_REPORT,
            ],
        },
        "sessionLifecycle": {
            "idleTtlSeconds": 50,
            "absoluteTtlSeconds": 60,
            "maxPerSubject": 2,
            "observations": [
                "IDLE_EXPIRED_404",
                "ABSOLUTE_EXPIRED_WHILE_IDLE_ACTIVE_404",
                "SUBJECT_SESSION_CAP_429_RETRY_AFTER",
                "EXPLICIT_DELETE_THEN_404",
                "EXPIRED_SESSION_REJECTED_BEFORE_TOOL",
            ],
        },
        "rateLimiting": {
            "windowSeconds": 15,
            "maxPerSubject": 5,
            "maxPerClient": 5,
            "riskLimits": {
                "read": 5,
                "write": 5,
                "destructive": 1,
                "protocol": 5,
            },
            "observations": [
                "SUBJECT_BUCKET_429_RETRY_AFTER",
                "CLIENT_BUCKET_429_RETRY_AFTER",
                "DESTRUCTIVE_RISK_BUCKET_429_RETRY_AFTER",
                "RATE_LIMITED_AUDIT_FAILED_OUTCOME",
            ],
        },
        "shutdown": {
            "gracefulRestart": True,
            "ingressContinuity": True,
            "probeBeforeIdleExpiry": True,
            "oldSessionOutcome": "SESSION_NOT_FOUND_404",
            "nginxImageId": "sha256:" + "d" * 64,
            "nginxImageReferenceSha256": hashlib.sha256(
                f"registry.example/nginx@{DIGESTS['nginx']}".encode()
            ).hexdigest(),
            "restartReceipt": gate.mcp_governance_proof.RESTART_RECEIPT,
            "restartReceiptSha256": "7" * 64,
            "restartProducerSha256": sources[
                gate.mcp_governance_proof.SOURCE_PATHS["restartOrchestratorSha256"]
            ],
        },
        "sources": sources,
    }


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, value: object) -> None:
    write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def sbom(name: str, digest: str | None = None) -> dict:
    component = {"type": "container" if digest else "application", "name": name}
    if digest:
        component["version"] = digest
        component["bom-ref"] = f"pkg:oci/{name}@{digest}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": component},
        "components": [{"type": "library", "name": "dependency", "version": "1.0"}],
    }


def trivy_report(reference: str) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": reference,
        "ArtifactType": "container_image",
        "Metadata": {},
        "Results": [],
    }


def production_model() -> dict:
    model = valid_production_model()
    model["services"]["app"]["image"] = f"registry.example/app@{DIGESTS['app']}"
    model["services"]["nginx"]["image"] = f"registry.example/nginx@{DIGESTS['nginx']}"
    model["services"]["mcp-public-nginx"]["image"] = (
        f"registry.example/nginx@{DIGESTS['nginx']}"
    )
    return model


class EvidenceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ac40_dependency_seed = (
            root.parent / f"{root.name}-ac40-dependency-seed"
        )
        self.ac40_dependency_seed.mkdir(mode=0o700)
        self.expected_ac40_dependency_seed_sha256 = AC40_AGGREGATE_SHA256
        self.artifacts = root / "artifacts"
        self.acceptance = root / "release/evidence/v2.0.0.json"
        self.release_images = self.artifacts / "release-images.json"
        self.security_summary = self.artifacts / "security-gate-summary.json"
        self.production_compose = self.artifacts / "production-compose.json"
        self.production_policy = self.artifacts / "production-compose-policy.json"
        self.deployment_images = self.artifacts / "deployment-images.env"
        self.runtime_identity = self.artifacts / "runtime-version-identity.json"
        self.runtime_acceptance = self.artifacts / "release-runtime-acceptance.json"
        self.unified_verify = self.artifacts / "unified-verify-summary.json"
        self.manifest = self.artifacts / "release-evidence.json"

        write(
            root / "pom.xml",
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
            "<modelVersion>4.0.0</modelVersion><version>2.0.0</version></project>\n",
        )
        write_json(root / "web-starter-web/package.json", {"name": "web-starter-web", "version": VERSION})
        write(root / "Dockerfile", "FROM scratch\nUSER 10001:10001\n")
        write(root / "deploy/nginx/Dockerfile", "FROM scratch\nUSER 101:101\nEXPOSE 8080\n")
        for name in ("nginx.conf", "nginx-public.conf"):
            write(
                root / "deploy/nginx" / name,
                "pid /tmp/nginx.pid;\n"
                "client_body_temp_path /tmp/client-body;\n"
                "proxy_temp_path /tmp/proxy-temp;\n"
                "fastcgi_temp_path /tmp/fastcgi-temp;\n"
                "uwsgi_temp_path /tmp/uwsgi-temp;\n"
                "scgi_temp_path /tmp/scgi-temp;\n",
            )
        write(
            root / "docs/acceptance/v1-acceptance-baseline.md",
            "| ID | level | domain | criteria |\n"
            "|---|---|---|---|\n"
            + "".join(
                f"| AC-{number:02d} | {'P1' if number % 10 == 0 else 'P0'} | item | evidence |\n"
                for number in range(1, 43)
            ),
        )
        write(
            root / "docs/acceptance/v2-acceptance-baseline.md",
            "| ID | level | domain | criteria |\n"
            "|---|---|---|---|\n"
            + "".join(
                f"| V2-AC-{number:02d} | {'P1' if number % 10 == 0 else 'P0'} | item | evidence |\n"
                for number in range(1, 46)
            ),
        )
        write(root / "web-starter-admin/src/main/resources/db/migration/V1__core.sql", "select 1;\n")
        write(root / "web-starter-admin/src/main/resources/db/migration/V2__seed.sql", "select 2;\n")
        write_json(
            root / "security/high-vulnerability-exceptions.json",
            {"schemaVersion": 1, "exceptions": []},
        )

        write_json(self.artifacts / "backend.cdx.json", sbom("backend"))
        write_json(self.artifacts / "frontend.cdx.json", sbom("frontend"))
        images = []
        for name, digest in DIGESTS.items():
            write_json(self.artifacts / f"{name}-image.cdx.json", sbom(name, digest))
            reference = f"registry.example/{name}@{digest}"
            write_json(
                self.artifacts / f"raw/{name}-vulnerabilities.json",
                trivy_report(reference),
            )
            write_json(
                self.artifacts / f"raw/{name}-secrets.json",
                trivy_report(reference),
            )
            images.append(
                {
                    "name": name,
                    "reference": reference,
                    "digest": digest,
                    "sbom": f"{name}-image.cdx.json",
                    "vulnerabilityReport": f"raw/{name}-vulnerabilities.json",
                    "secretReport": f"raw/{name}-secrets.json",
                }
            )
        write_json(
            self.release_images,
            {
                "schemaVersion": 1,
                "releaseTag": TAG,
                "releaseVersion": VERSION,
                "gitCommit": COMMIT,
                "sboms": {"backend": "backend.cdx.json", "frontend": "frontend.cdx.json"},
                "images": images,
            },
        )
        security_summary, security_errors = security_gate.evaluate(
            self.release_images,
            root / "security/high-vulnerability-exceptions.json",
            NOW.date(),
            evaluated_at=NOW,
        )
        if security_errors:
            raise AssertionError(security_errors)
        write_json(self.security_summary, security_summary)
        write_json(self.production_compose, production_model())
        compose_policy._write_summary(self.production_policy, self.production_compose, [])
        write(
            self.deployment_images,
            "WEB_STARTER_APP_IMAGE=registry.example/app\n"
            f"WEB_STARTER_APP_DIGEST={DIGESTS['app']}\n"
            "WEB_STARTER_NGINX_IMAGE=registry.example/nginx\n"
            f"WEB_STARTER_NGINX_DIGEST={DIGESTS['nginx']}\n",
        )
        write_json(
            self.runtime_identity,
            {
                "schemaVersion": 2,
                "status": "PASS",
                "observedAt": "2026-07-19T10:20:00+00:00",
                "release": {"version": VERSION, "gitCommit": COMMIT},
                "java": {
                    "specificationVersion": "21",
                    "runtimeVersion": "21.0.8+9-LTS",
                },
                "actuator": {
                    "applicationVersion": VERSION,
                    "buildVersion": VERSION,
                    "buildArtifact": "web-starter-admin",
                    "buildGroup": "dev.webstarter",
                },
                "images": {
                    **{
                        name: {
                            "reference": f"registry.example/{name}@{digest}",
                            "imageId": "sha256:" + ("c" if name == "app" else "d") * 64,
                            "ociVersion": VERSION,
                            "ociRevision": COMMIT,
                        }
                        for name, digest in DIGESTS.items()
                    },
                    **{
                        name: {
                            "reference": production_model()["services"][name]["image"],
                            "imageId": "sha256:" + ("e" if name == "mysql" else "f") * 64,
                            "ociVersion": None,
                            "ociRevision": None,
                        }
                        for name in ("mysql", "redis")
                    },
                },
            },
        )
        unified_layers = {name: "PASS" for name in sorted(gate.VERIFY_LAYERS)}
        write_json(
            self.unified_verify,
            {"schemaVersion": 1, "status": "PASS", "layers": unified_layers},
        )
        write_json(
            self.runtime_acceptance,
            {
                "schemaVersion": 1,
                "status": "PASS",
                "observedAt": "2026-07-19T10:30:00+00:00",
                "release": {"tag": TAG, "version": VERSION, "gitCommit": COMMIT},
                "images": {
                    name: f"registry.example/{name}@{digest}"
                    for name, digest in DIGESTS.items()
                },
                "identity": {
                    "javaSpecificationVersion": "21",
                    "applicationVersion": VERSION,
                    "buildVersion": VERSION,
                    "composeProject": "web-starter-release-17",
                    "mcpCrudTracePrefix": gate.MCP_CRUD_TRACE_PREFIX,
                    "appImage": f"registry.example/app@{DIGESTS['app']}",
                    "nginxImage": f"registry.example/nginx@{DIGESTS['nginx']}",
                    "appOciVersion": VERSION,
                    "appOciRevision": COMMIT,
                    "nginxOciVersion": VERSION,
                    "nginxOciRevision": COMMIT,
                },
                "unifiedVerify": {
                    "path": self.unified_verify.name,
                    "sha256": hashlib.sha256(self.unified_verify.read_bytes()).hexdigest(),
                    "status": "PASS",
                    "layers": unified_layers,
                },
                "checks": {name: "PASS" for name in gate.RUNTIME_CHECKS},
            },
        )
        write_json(
            self.acceptance,
            {
                "schemaVersion": 1,
                "release": {"tag": TAG, "version": VERSION},
                "suites": {
                    "v1": {
                        "results": [
                            self.result(f"AC-{number:02d}") for number in range(1, 43)
                        ]
                    },
                    "v2": {
                        "results": [
                            self.result(f"V2-AC-{number:02d}") for number in range(1, 45)
                        ]
                    },
                },
            },
        )

    def result(self, acceptance_id: str, status: str | None = None) -> dict:
        resolved_status = status or (
            "PASS"
            if acceptance_id in FIXTURE_PASS_IDS
            else "NOT_COVERED"
        )
        evidence_path = self.artifacts / "acceptance" / f"{acceptance_id.lower()}.json"
        write_json(
            evidence_path,
            {"id": acceptance_id, "status": resolved_status, "source": "fixture"},
        )
        return {
            "id": acceptance_id,
            "status": resolved_status,
            "observedAt": "2026-07-19T10:00:00+00:00",
            "evidence": [
                "artifact://"
                + evidence_path.relative_to(self.artifacts).as_posix()
                + "#sha256="
                + gate._sha256(evidence_path)
            ],
        }

    def build(self, **overrides: object) -> dict:
        arguments: dict[str, object] = {
            "repository_root": self.root,
            "artifacts_root": self.artifacts,
            "acceptance_source_path": self.acceptance,
            "release_images_path": self.release_images,
            "security_summary_path": self.security_summary,
            "production_compose_path": self.production_compose,
            "production_policy_path": self.production_policy,
            "deployment_images_path": self.deployment_images,
            "runtime_identity_path": self.runtime_identity,
            "runtime_acceptance_path": self.runtime_acceptance,
            "ac40_dependency_seed_path": self.ac40_dependency_seed,
            "expected_ac40_dependency_seed_sha256": (
                self.expected_ac40_dependency_seed_sha256
            ),
            "tag": TAG,
            "version": VERSION,
            "commit": COMMIT,
            "evaluated_at": NOW,
            "verify_git": False,
        }
        arguments.update(overrides)
        return gate.build_ledger(**arguments)


class ReleaseEvidenceGateTest(unittest.TestCase):
    def test_git_binding_requires_annotated_tag_at_checked_out_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.name", "Release Test"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email", "release-test@example.invalid"],
                check=True,
            )
            write(repository / "tracked.txt", "release\n")
            subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "-q", "-m", "release"], check=True)
            commit = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "-C", str(repository), "tag", "-a", "v2.0.0", "-m", "release"],
                check=True,
            )

            tag_object = gate._verify_git_binding(repository, "v2.0.0", commit)

            self.assertNotEqual(commit, tag_object)
            write(repository / "untracked-evidence.tmp", "ignored by tracked drift guard\n")
            self.assertEqual(tag_object, gate._verify_git_binding(repository, "v2.0.0", commit))
            with self.assertRaisesRegex(gate.EvidenceError, "including untracked files"):
                gate._verify_strict_candidate_root(repository, "v2.0.0", commit)
            (repository / "untracked-evidence.tmp").unlink()
            self.assertEqual(
                repository.resolve(),
                gate._verify_strict_candidate_root(repository, "v2.0.0", commit),
            )

            write(repository / "tracked.txt", "unstaged drift\n")
            with self.assertRaisesRegex(gate.EvidenceError, "tracked-file drift"):
                gate._verify_git_binding(repository, "v2.0.0", commit)
            subprocess.run(
                ["git", "-C", str(repository), "restore", "--", "tracked.txt"], check=True
            )

            write(repository / "tracked.txt", "staged drift\n")
            subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
            with self.assertRaisesRegex(gate.EvidenceError, "tracked-file drift"):
                gate._verify_git_binding(repository, "v2.0.0", commit)
            subprocess.run(
                ["git", "-C", str(repository), "restore", "--staged", "--", "tracked.txt"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "restore", "--", "tracked.txt"], check=True
            )

            subprocess.run(
                ["git", "-C", str(repository), "update-index", "--assume-unchanged", "tracked.txt"],
                check=True,
            )
            write(repository / "tracked.txt", "hidden unstaged drift\n")
            with self.assertRaisesRegex(gate.EvidenceError, "assume-unchanged"):
                gate._verify_git_binding(repository, "v2.0.0", commit)
            subprocess.run(
                ["git", "-C", str(repository), "update-index", "--no-assume-unchanged", "tracked.txt"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "restore", "--", "tracked.txt"], check=True
            )

            gate._verify_repository_file_binding(repository, commit, repository / "tracked.txt")
            write(repository / "tracked.txt", "changed after tag\n")
            with self.assertRaisesRegex(gate.EvidenceError, "differs from tagged commit"):
                gate._verify_repository_file_binding(repository, commit, repository / "tracked.txt")
            subprocess.run(["git", "-C", str(repository), "tag", "v2.0.1"], check=True)
            with self.assertRaisesRegex(gate.EvidenceError, "annotated Git tag"):
                gate._verify_git_binding(repository, "v2.0.1", commit)

    def test_gate_git_calls_drop_ambient_config_object_index_and_worktree_injection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Release Test"],
                check=True,
            )
            subprocess.run(
                [
                    "git", "-C", str(repository), "config", "user.email",
                    "release-test@example.invalid",
                ],
                check=True,
            )
            write(repository / "tracked.txt", "release\n")
            subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "release"],
                check=True,
            )
            expected = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            poison = {
                "GIT_CONFIG_NOSYSTEM": "0",
                "GIT_CONFIG_GLOBAL": str(repository / "malicious-global-config"),
                "GIT_CONFIG_SYSTEM": str(repository / "malicious-system-config"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
                "GIT_DIR": str(repository / "missing-git-dir"),
                "GIT_COMMON_DIR": str(repository / "missing-common-dir"),
                "GIT_WORK_TREE": str(repository / "missing-worktree"),
                "GIT_INDEX_FILE": str(repository / "missing-index"),
                "GIT_OBJECT_DIRECTORY": str(repository / "missing-objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repository / "alternate-objects"),
                "GIT_REPLACE_REF_BASE": "refs/poisoned/replace/",
                "GIT_NO_REPLACE_OBJECTS": "0",
            }
            with mock.patch.dict(os.environ, poison, clear=False):
                environment = gate._git_environment()
                self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
                self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
                self.assertEqual(os.devnull, environment["GIT_CONFIG_SYSTEM"])
                self.assertEqual("0", environment["GIT_CONFIG_COUNT"])
                self.assertEqual("1", environment["GIT_NO_REPLACE_OBJECTS"])
                for name in (
                    "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_DIR",
                    "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    "GIT_REPLACE_REF_BASE",
                ):
                    self.assertNotIn(name, environment)
                self.assertEqual(expected, gate._git(repository, "rev-parse", "HEAD"))

    def test_gate_git_stdout_and_stderr_are_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Release Test"],
                check=True,
            )
            subprocess.run(
                [
                    "git", "-C", str(repository), "config", "user.email",
                    "release-test@example.invalid",
                ],
                check=True,
            )
            write(repository / "large.txt", "x" * 4096)
            subprocess.run(["git", "-C", str(repository), "add", "large.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "large"],
                check=True,
            )
            with mock.patch.object(gate, "MAX_GIT_STDOUT_BYTES", 64), \
                    self.assertRaisesRegex(gate.EvidenceError, "stdout exceeded"):
                gate._git_bytes(repository, "show", "HEAD:large.txt")
            with mock.patch.object(gate, "MAX_GIT_STDERR_BYTES", 64), \
                    self.assertRaisesRegex(gate.EvidenceError, "stderr exceeded"):
                gate._run_git_bounded(
                    repository,
                    "-c",
                    "alias.noisy=!python3 -c 'import sys;sys.stderr.write(\"x\"*4096)'",
                    "noisy",
                )
            source = Path(gate.__file__).read_text(encoding="utf-8")
            self.assertNotIn("subprocess.run(", source)

    def test_only_registered_results_are_independently_verified_and_auto_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            ledger = fixture.build()

            self.assertEqual("FAIL", ledger["gate"]["status"])
            self.assertEqual(DIGESTS["app"], ledger["images"]["app"]["digest"])
            self.assertEqual(
                {"maven": VERSION, "frontend": VERSION}, ledger["release"]["projectVersions"]
            )
            self.assertRegex(ledger["sboms"]["backend"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual("2", ledger["flyway"]["latestVersion"])
            self.assertRegex(ledger["flyway"]["listSha256"], r"^[0-9a-f]{64}$")
            self.assertEqual("PASS", ledger["inputs"]["productionComposePolicy"]["status"])
            self.assertRegex(ledger["inputs"]["productionCompose"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(ledger["inputs"]["deploymentImages"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual("PASS", ledger["inputs"]["releaseRuntimeAcceptance"]["status"])
            self.assertEqual("PASS", ledger["inputs"]["runtimeVersionIdentity"]["status"])
            self.assertEqual("PASS", ledger["inputs"]["unifiedVerify"]["status"])
            self.assertRegex(ledger["inputs"]["unifiedVerify"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(
                ledger["inputs"]["runtimeVersionIdentity"]["sha256"], r"^[0-9a-f]{64}$"
            )
            v2 = {result["id"]: result for result in ledger["acceptance"]["v2"]["results"]}
            self.assertEqual(
                {
                    "AC-01",
                    "AC-02",
                    "AC-03",
                    "AC-04",
                    "AC-05",
                    "AC-06",
                    "AC-07",
                    "AC-08",
                    "AC-09",
                    "AC-10",
                    "AC-11",
                    "AC-12",
                    "AC-13",
                    "AC-14",
                    "AC-15",
                    "AC-16",
                    "AC-17",
                    "AC-18",
                    "AC-19",
                    "AC-20",
                    "AC-21",
                    "AC-22",
                    "AC-23",
                    "AC-24",
                    "AC-25",
                    "AC-26",
                    "AC-27",
                    "AC-28",
                    "AC-29",
                    "AC-30",
                    "AC-31",
                    "AC-32",
                    "AC-33",
                    "AC-34",
                    "AC-35",
                    "AC-36",
                    "AC-37",
                    "AC-38",
                    "AC-39",
                    "AC-41",
                    "AC-42",
                    "V2-AC-01",
                    "V2-AC-02",
                    "V2-AC-03",
                    "V2-AC-04",
                    "V2-AC-05",
                    "V2-AC-06",
                    "V2-AC-07",
                    "V2-AC-08",
                    "V2-AC-09",
                    "V2-AC-10",
                    "V2-AC-11",
                    "V2-AC-12",
                    "V2-AC-13",
                    "V2-AC-14",
                    "V2-AC-15",
                    "V2-AC-16",
                    "V2-AC-17",
                    "V2-AC-18",
                    "V2-AC-19",
                    "V2-AC-20",
                    "V2-AC-21",
                    "V2-AC-22",
                    "V2-AC-23",
                    "V2-AC-24",
                    "V2-AC-25",
                    "V2-AC-26",
                    "V2-AC-27",
                    "V2-AC-28",
                    "V2-AC-29",
                    "V2-AC-30",
                    "V2-AC-31",
                    "V2-AC-32",
                    "V2-AC-33",
                    "V2-AC-34",
                    "V2-AC-35",
                    "V2-AC-36",
                    "V2-AC-37",
                    "V2-AC-38",
                    "V2-AC-39",
                    "V2-AC-40",
                    "V2-AC-41",
                    "V2-AC-42",
                    "V2-AC-43",
                    "V2-AC-44",
                },
                set(gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS),
            )
            accepted = {
                result["id"]: result
                for suite in ("v1", "v2")
                for result in ledger["acceptance"][suite]["results"]
            }
            for acceptance_id in sorted(FIXTURE_PASS_IDS):
                input_names = gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS[acceptance_id]
                result = accepted[acceptance_id]
                self.assertEqual("PASS", result["status"])
                self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", result["evidenceTrust"])
                for input_name in input_names:
                    bound = ledger["inputs"][input_name]
                    self.assertIn(
                        f"artifact://{bound['path']}#sha256={bound['sha256']}",
                        result["evidence"],
                    )
            self.assertEqual("NOT_COVERED", v2["V2-AC-01"]["status"])
            self.assertEqual("CONTENT_HASH_VERIFIED", v2["V2-AC-01"]["evidenceTrust"])
            self.assertIn(
                "V2-AC-01 is NOT_COVERED, not PASS", ledger["gate"]["errors"]
            )
            self.assertEqual("FAIL", v2["V2-AC-45"]["status"])
            self.assertEqual("GATE_DERIVED", v2["V2-AC-45"]["evidenceTrust"])

    def test_ac01_is_bound_to_the_empty_volume_runtime_acceptance(self) -> None:
        self.assertEqual(
            ("releaseRuntimeAcceptance",),
            gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-01"],
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            ledger = fixture.build()
            observed = next(
                item
                for item in ledger["acceptance"]["v1"]["results"]
                if item["id"] == "AC-01"
            )
            self.assertEqual("PASS", observed["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", observed["evidenceTrust"])
            bound = ledger["inputs"]["releaseRuntimeAcceptance"]
            self.assertIn(
                f"artifact://{bound['path']}#sha256={bound['sha256']}",
                observed["evidence"],
            )

    def test_ac41_is_bound_only_to_the_exact_unified_verify_summary(self) -> None:
        self.assertEqual(
            ("unifiedVerify",),
            gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-41"],
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            result = next(
                item
                for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-41"
            )
            result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            ledger = fixture.build()

            observed = next(
                item
                for item in ledger["acceptance"]["v1"]["results"]
                if item["id"] == "AC-41"
            )
            self.assertEqual("PASS", observed["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", observed["evidenceTrust"])
            self.assertIn(
                "artifact://"
                + ledger["inputs"]["unifiedVerify"]["path"]
                + "#sha256="
                + ledger["inputs"]["unifiedVerify"]["sha256"],
                observed["evidence"],
            )
            self.assertEqual(45, ledger["acceptance"]["v2"]["counts"]["total"])

    def test_ac38_requires_runtime_health_observability_and_operations_documentation(
        self,
    ) -> None:
        self.assertEqual(
            (
                "v1OperationsDocumentationSummary",
                "observabilitySummary",
                "releaseRuntimeAcceptance",
            ),
            gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-38"],
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac38"
            private.mkdir(mode=0o700)
            proof = private / gate.v1_operations_documentation.PROOF_NAME
            proof.write_text("{}\n", encoding="utf-8")
            proof.chmod(0o600)
            summary = {
                "schemaVersion": 1,
                "acceptanceIds": ["AC-38"],
                "status": "PASS",
                "candidate": {
                    "commit": COMMIT,
                    "tree": "d" * 40,
                    "tag": TAG,
                    "version": VERSION,
                },
                "checks": {
                    "operationsDocumentationReview": "PASS",
                    "sourceIntegrity": "PASS",
                },
                "evidence": {
                    "proofSha256": "e" * 64,
                    "migrationVersions": [1, 2],
                    "sourceSha256": {"docs/deployment.md": "f" * 64},
                },
            }
            operations_artifact = (
                fixture.artifacts
                / "acceptance"
                / gate.v1_operations_documentation.SUMMARY_NAME
            )
            operations_artifact.write_bytes(
                gate.v1_operations_documentation.canonical_summary_bytes(summary)
            )
            operations_artifact.chmod(0o600)
            baseline = fixture.artifacts / "operational-metrics-baseline.json"
            runtime = fixture.artifacts / "operational-metrics-runtime.json"
            write_json(baseline, {"private": "baseline"})
            write_json(runtime, {"private": "runtime"})
            baseline.chmod(0o600)
            runtime.chmod(0o600)
            metrics_summary = observability_summary()
            metrics_artifact = (
                fixture.artifacts
                / "acceptance"
                / gate.observability_evidence.SUMMARY_NAME
            )
            metrics_artifact.write_bytes(
                gate.observability_evidence.canonical_summary_bytes(metrics_summary)
            )
            metrics_artifact.chmod(0o600)
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item
                for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-38"
            )["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.v1_operations_documentation,
                "validate_proof",
                return_value=summary,
            ) as validate_operations, mock.patch.object(
                gate.observability_evidence,
                "validate",
                return_value=metrics_summary,
            ):
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    v1_operations_documentation_proof_path=proof,
                    v1_operations_documentation_summary_artifact_path=(
                        operations_artifact
                    ),
                    observability_baseline_path=baseline,
                    observability_runtime_path=runtime,
                    observability_summary_artifact_path=metrics_artifact,
                )

            validate_operations.assert_called_once_with(
                proof,
                repository_root=fixture.root.resolve(),
                expected_candidate_commit=COMMIT,
                expected_candidate_tag=TAG,
                expected_candidate_version=VERSION,
            )
            result = next(
                item
                for item in ledger["acceptance"]["v1"]["results"]
                if item["id"] == "AC-38"
            )
            self.assertEqual("PASS", result["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", result["evidenceTrust"])
            for input_name in gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-38"]:
                bound = ledger["inputs"][input_name]
                self.assertIn(
                    f"artifact://{bound['path']}#sha256={bound['sha256']}",
                    result["evidence"],
                )

    def test_missing_p0_or_p1_result_is_structural_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            source["suites"]["v1"]["results"].pop(1)
            write_json(fixture.acceptance, source)

            with self.assertRaisesRegex(gate.EvidenceError, "missing P0/P1 results: AC-02"):
                fixture.build()

    def test_runtime_acceptance_must_match_release_images_and_all_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            runtime = json.loads(fixture.runtime_acceptance.read_text(encoding="utf-8"))
            runtime["images"]["app"] = "registry.example/app@sha256:" + "f" * 64
            write_json(fixture.runtime_acceptance, runtime)
            with self.assertRaisesRegex(
                gate.EvidenceError, "did not use the scanned image digests"
            ):
                fixture.build()

            runtime["images"]["app"] = f"registry.example/app@{DIGESTS['app']}"
            runtime["checks"]["oauthPkce"] = "NOT_COVERED"
            write_json(fixture.runtime_acceptance, runtime)
            with self.assertRaisesRegex(gate.EvidenceError, "not PASS"):
                fixture.build()

    def test_runtime_acceptance_recomputes_unified_verify_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            summary = json.loads(fixture.unified_verify.read_text(encoding="utf-8"))
            summary["layers"]["browser"] = "NOT_COVERED"
            write_json(fixture.unified_verify, summary)

            with self.assertRaisesRegex(
                gate.EvidenceError, "unified seven-layer verify evidence"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            write(
                fixture.unified_verify,
                '{"schemaVersion":1,"status":"PASS","layers":{'
                '"backend":"PASS","browser":"FAIL","browser":"PASS",'
                '"container":"PASS","frontend":"PASS","mcp":"PASS",'
                '"oauth":"PASS","policy":"PASS"}}\n',
            )
            with self.assertRaisesRegex(gate.EvidenceError, "repeats field: browser"):
                fixture.build()

    def test_runtime_acceptance_binds_the_exact_mcp_crud_runtime_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            runtime = json.loads(fixture.runtime_acceptance.read_text(encoding="utf-8"))
            runtime["identity"]["mcpCrudTracePrefix"] = "self-selected-prefix"
            write_json(fixture.runtime_acceptance, runtime)
            with self.assertRaisesRegex(gate.EvidenceError, "trace prefix is invalid"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            runtime = json.loads(fixture.runtime_acceptance.read_text(encoding="utf-8"))
            runtime["identity"]["composeProject"] = "../other-stack"
            write_json(fixture.runtime_acceptance, runtime)
            with self.assertRaisesRegex(gate.EvidenceError, "Compose project identity is invalid"):
                fixture.build()

    def test_runtime_java_actuator_and_oci_identity_must_match_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            runtime = json.loads(fixture.runtime_acceptance.read_text(encoding="utf-8"))
            runtime["identity"]["javaSpecificationVersion"] = "17"
            write_json(fixture.runtime_acceptance, runtime)

            with self.assertRaisesRegex(gate.EvidenceError, "Java, Actuator or OCI identity"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            identity = json.loads(fixture.runtime_identity.read_text(encoding="utf-8"))
            identity["java"]["specificationVersion"] = "17"
            write_json(fixture.runtime_identity, identity)

            with self.assertRaisesRegex(gate.EvidenceError, "actual Java 21"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            identity = json.loads(fixture.runtime_identity.read_text(encoding="utf-8"))
            identity["images"]["redis"]["reference"] = (
                "redis@sha256:" + "9" * 64
            )
            write_json(fixture.runtime_identity, identity)

            with self.assertRaisesRegex(gate.EvidenceError, "runtime redis identity"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            identity = json.loads(fixture.runtime_identity.read_text(encoding="utf-8"))
            identity["images"]["mysql"]["ociVersion"] = VERSION
            write_json(fixture.runtime_identity, identity)

            with self.assertRaisesRegex(gate.EvidenceError, "runtime mysql identity"):
                fixture.build()

    def test_frozen_baseline_cannot_silently_drop_an_acceptance_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            baseline = fixture.root / "docs/acceptance/v2-acceptance-baseline.md"
            lines = [line for line in baseline.read_text(encoding="utf-8").splitlines() if "V2-AC-44" not in line]
            write(baseline, "\n".join(lines) + "\n")

            with self.assertRaisesRegex(gate.EvidenceError, "frozen complete ID set.*V2-AC-44"):
                fixture.build()

    def test_only_four_statuses_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            source["suites"]["v1"]["results"][0]["status"] = "SKIPPED"
            write_json(fixture.acceptance, source)

            with self.assertRaisesRegex(gate.EvidenceError, "unsupported acceptance status"):
                fixture.build()

    def test_acceptance_evidence_must_be_a_supported_content_addressed_uri(self) -> None:
        invalid_references = (
            "trust-me",
            "artifact://acceptance/../outside.json#sha256=" + "a" * 64,
            "artifact://acceptance/ac-01.json#sha256-bound",
            "external://retained-acceptance/ac-01.json#sha256=" + "a" * 64,
            "https://user:password@example.invalid/result.json#sha256=" + "a" * 64,
        )
        for reference in invalid_references:
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as directory:
                fixture = EvidenceFixture(Path(directory))
                source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
                source["suites"]["v1"]["results"][0]["evidence"] = [reference]
                write_json(fixture.acceptance, source)

                with self.assertRaisesRegex(gate.EvidenceError, "supported content-addressed URI"):
                    fixture.build()

    def test_external_evidence_is_rejected_for_pass_and_non_pass_results(self) -> None:
        for status in ("PASS", "NOT_COVERED"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                fixture = EvidenceFixture(Path(directory))
                source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
                result = next(
                    item
                    for item in source["suites"]["v1"]["results"]
                    if item["id"] == "AC-02"
                )
                result["status"] = status
                result["evidence"] = [
                    "external://retained-acceptance/ac-01.json#sha256=" + "a" * 64
                ]
                write_json(fixture.acceptance, source)

                with self.assertRaisesRegex(
                    gate.EvidenceError, "supported content-addressed URI"
                ):
                    fixture.build()

    def test_non_pass_repo_and_artifact_evidence_must_be_readable(self) -> None:
        for reference in (
            "repo://evidence/missing.json#sha256=" + "a" * 64,
            "artifact://acceptance/missing.json#sha256=" + "a" * 64,
        ):
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as directory:
                fixture = EvidenceFixture(Path(directory))
                source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
                result = next(
                    item
                    for item in source["suites"]["v1"]["results"]
                    if item["id"] == "AC-02"
                )
                self.assertEqual("NOT_COVERED", result["status"])
                result["evidence"] = [reference]
                write_json(fixture.acceptance, source)

                with self.assertRaisesRegex(gate.EvidenceError, "missing or is not a regular file"):
                    fixture.build()

    def test_acceptance_evidence_rejects_duplicate_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            evidence = source["suites"]["v2"]["results"][0]["evidence"][0]
            source["suites"]["v2"]["results"][0]["evidence"] = [evidence, evidence]
            write_json(fixture.acceptance, source)

            with self.assertRaisesRegex(gate.EvidenceError, "repeats an evidence reference"):
                fixture.build()

    def test_repo_and_artifact_evidence_are_read_and_hash_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            repo_evidence = fixture.root / "evidence/static/ac-02.json"
            artifact_evidence = fixture.artifacts / "acceptance/ac-06.json"
            write(repo_evidence, '{"status":"NOT_COVERED"}\n')
            write(artifact_evidence, '{"status":"NOT_COVERED"}\n')
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            by_id = {
                item["id"]: item for item in source["suites"]["v1"]["results"]
            }
            by_id["AC-02"]["evidence"] = [
                "repo://evidence/static/ac-02.json#sha256=" + gate._sha256(repo_evidence)
            ]
            by_id["AC-06"]["evidence"] = [
                "artifact://acceptance/ac-06.json#sha256=" + gate._sha256(artifact_evidence)
            ]
            write_json(fixture.acceptance, source)

            ledger = fixture.build()
            results = {result["id"]: result for result in ledger["acceptance"]["v1"]["results"]}
            self.assertEqual("CONTENT_HASH_VERIFIED", results["AC-02"]["evidenceTrust"])
            self.assertEqual("CONTENT_HASH_VERIFIED", results["AC-06"]["evidenceTrust"])
            self.assertEqual("CONTENT_HASH_VERIFIED", results["AC-03"]["evidenceTrust"])

            write(artifact_evidence, '{"status":"REPLACED"}\n')
            with self.assertRaisesRegex(gate.EvidenceError, "artifact evidence checksum"):
                fixture.build()

    def test_hash_valid_unregistered_pass_fails_even_when_git_verification_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            forged = fixture.artifacts / "acceptance/forged-pass.json"
            write_json(forged, {"status": "PASS"})
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            result = next(
                item for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-40"
            )
            result["status"] = "PASS"
            result["evidence"] = [
                "artifact://acceptance/forged-pass.json#sha256=" + gate._sha256(forged)
            ]
            write_json(fixture.acceptance, source)

            with self.assertRaisesRegex(
                gate.EvidenceError,
                "AC-40 PASS is not registered for independent semantic verification",
            ):
                fixture.build()

    def test_registered_pass_still_requires_the_registered_artifact_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            write_json(fixture.runtime_acceptance, {"status": "PASS"})

            with self.assertRaisesRegex(
                gate.EvidenceError, "release runtime acceptance fields are not exact"
            ):
                fixture.build()

    def test_ac01_recomputes_frozen_v1_provenance_and_binds_canonical_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-v1-source"
            private.mkdir(mode=0o700)
            proof = private / "v2-ac01-v1-source-provenance.json"
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            summary = v1_source_provenance_summary()
            artifact = (
                fixture.artifacts
                / "acceptance/v2-ac01-v1-source-provenance-summary.json"
            )
            artifact.write_bytes(
                gate.v1_source_provenance.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item for item in source["suites"]["v2"]["results"]
                if item["id"] == "V2-AC-01"
            )["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.v1_source_provenance,
                "validate_proof",
                return_value=summary,
            ) as validate:
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    v1_source_provenance_proof_path=proof,
                    v1_source_provenance_summary_artifact_path=artifact,
                )

            self.assertEqual(proof, validate.call_args.args[0])
            self.assertEqual(fixture.root.resolve(), validate.call_args.args[1])
            expected = validate.call_args.kwargs
            self.assertEqual(COMMIT, expected["expected_candidate_commit"])
            self.assertEqual(VERSION, expected["expected_candidate_version"])
            self.assertEqual(TAG, expected["expected_candidate_tag"])
            self.assertIs(True, expected["require_pass"])
            ac01 = next(
                item for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-01"
            )
            self.assertEqual("PASS", ac01["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac01["evidenceTrust"])
            self.assertEqual(
                "PASS", ledger["inputs"]["v1SourceProvenanceSummary"]["status"]
            )

    def test_ac01_rejects_partial_noncanonical_scope_or_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-v1-source"
            private.mkdir(mode=0o700)
            proof = private / "v2-ac01-v1-source-provenance.json"
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            artifact = (
                fixture.artifacts
                / "acceptance/v2-ac01-v1-source-provenance-summary.json"
            )

            with self.assertRaisesRegex(gate.EvidenceError, "requires both"):
                fixture.build(v1_source_provenance_proof_path=proof)

            summary = v1_source_provenance_summary()
            write_json(artifact, {"schemaVersion": 1, "status": "PASS", "forged": True})
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.v1_source_provenance, "validate_proof", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "canonical summary differs"):
                fixture.build(
                    v1_source_provenance_proof_path=proof,
                    v1_source_provenance_summary_artifact_path=artifact,
                )

            artifact.write_bytes(
                gate.v1_source_provenance.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o644)
            with mock.patch.object(
                gate.v1_source_provenance, "validate_proof", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "mode 0600"):
                fixture.build(
                    v1_source_provenance_proof_path=proof,
                    v1_source_provenance_summary_artifact_path=artifact,
                )

            artifact.chmod(0o600)
            wrong_scope = v1_source_provenance_summary()
            wrong_scope["checks"]["currentCandidateV1Regression"] = "PASS"
            with mock.patch.object(
                gate.v1_source_provenance, "validate_proof", return_value=wrong_scope
            ), self.assertRaisesRegex(gate.EvidenceError, "scope or semantic checks"):
                fixture.build(
                    v1_source_provenance_proof_path=proof,
                    v1_source_provenance_summary_artifact_path=artifact,
                )

    def test_release_runtime_reports_recompute_exact_20_plus_2_and_bind_minimal_ac_set(
        self,
    ) -> None:
        report_acceptance_ids = {
            "AC-03", "AC-04", "AC-05", "AC-06", "AC-07", "AC-08", "AC-09",
            "AC-10", "AC-11", "AC-12", "AC-13", "AC-14",
            "AC-19", "AC-20", "AC-22", "AC-23", "AC-25", "AC-26", "AC-27",
            "AC-28", "AC-29", "AC-30", "AC-31", "AC-32", "AC-33",
            "AC-34",
            "AC-35",
            "AC-36",
            "V2-AC-19", "V2-AC-20", "V2-AC-21", "V2-AC-22",
            "V2-AC-23", "V2-AC-25", "V2-AC-30", "V2-AC-39",
        }
        report_only_pass_ids = report_acceptance_ids - {
            "AC-19", "AC-20", "AC-22", "AC-23", "AC-26", "AC-29", "AC-34", "V2-AC-20",
        }
        self.assertEqual(
            report_acceptance_ids,
            {
                acceptance_id
                for acceptance_id, bindings in (
                    gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS.items()
                )
                if "releaseRuntimeTestReports" in bindings
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            raw = Path(directory) / "private-runtime-reports"
            raw.mkdir(mode=0o700)
            summary = release_runtime_test_reports_summary()
            artifact = (
                fixture.artifacts
                / "acceptance/release-runtime-test-reports-summary.json"
            )
            artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)

            redis_raw = Path(directory) / "private-ac41"
            redis_raw.mkdir(mode=0o700)
            redis_evidence = redis_raw / "v2-ac41-redis-loss.json"
            write_json(redis_evidence, {"status": "PASS", "sanitized": True})
            redis_evidence.chmod(0o600)
            redis_artifact = fixture.artifacts / "acceptance/v2-ac41-redis-loss.json"
            redis_artifact.write_bytes(redis_evidence.read_bytes())

            upgrade_raw = Path(directory) / "private-upgrade"
            upgrade_raw.mkdir(mode=0o700)
            upgrade_evidence = upgrade_raw / "v2-v1-upgrade-rehearsal.json"
            write_json(upgrade_evidence, {"status": "PASS", "sanitized": True})
            upgrade_evidence.chmod(0o600)
            upgrade_artifact = (
                fixture.artifacts / "acceptance/v2-v1-upgrade-rehearsal.json"
            )
            upgrade_artifact.write_bytes(upgrade_evidence.read_bytes())
            upgrade_artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            for suite in ("v1", "v2"):
                for result in source["suites"][suite]["results"]:
                    if result["id"] in report_only_pass_ids:
                        result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=summary,
            ), mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ), self.assertRaisesRegex(
                gate.EvidenceError,
                "AC-04 independently verified artifact redisLossRehearsal",
            ):
                fixture.build(
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=raw,
                    release_runtime_test_reports_summary_artifact_path=artifact,
                    v1_upgrade_evidence_path=upgrade_evidence,
                    v1_upgrade_artifact_path=upgrade_artifact,
                )

            with mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=summary,
            ) as validate, mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ), mock.patch.object(
                gate.redis_loss_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ):
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=raw,
                    release_runtime_test_reports_summary_artifact_path=artifact,
                    v1_upgrade_evidence_path=upgrade_evidence,
                    v1_upgrade_artifact_path=upgrade_artifact,
                    redis_loss_evidence_path=redis_evidence,
                    redis_loss_artifact_path=redis_artifact,
                )

            self.assertEqual(raw.resolve(), validate.call_args.args[0])
            self.assertEqual(fixture.root.resolve(), validate.call_args.kwargs["repository_root"])
            self.assertEqual(COMMIT, validate.call_args.kwargs["expected_candidate_commit"])
            self.assertEqual(VERSION, validate.call_args.kwargs["expected_candidate_version"])
            self.assertEqual(TAG, validate.call_args.kwargs["expected_candidate_tag"])
            self.assertEqual(
                summary["run"]["startedAtEpochNs"],
                validate.call_args.kwargs["expected_run_started_at_epoch_ns"],
            )
            self.assertIs(True, validate.call_args.kwargs["require_pass"])
            bound = ledger["inputs"]["releaseRuntimeTestReports"]
            self.assertEqual("PASS", bound["status"])
            self.assertEqual(
                hashlib.sha256(artifact.read_bytes()).hexdigest(), bound["sha256"]
            )
            for suite in ("v1", "v2"):
                by_id = {
                    result["id"]: result
                    for result in ledger["acceptance"][suite]["results"]
                }
                for acceptance_id in report_only_pass_ids.intersection(by_id):
                    result = by_id[acceptance_id]
                    self.assertEqual("PASS", result["status"])
                    self.assertEqual(
                        "GATE_INDEPENDENTLY_VERIFIED",
                        result["evidenceTrust"],
                    )
                    for input_name in gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS[
                        acceptance_id
                    ]:
                        input_binding = ledger["inputs"][input_name]
                        self.assertIn(
                            f"artifact://{input_binding['path']}#sha256={input_binding['sha256']}",
                            result["evidence"],
                        )
            v2_by_id = {
                result["id"]: result
                for result in ledger["acceptance"]["v2"]["results"]
            }
            self.assertEqual("NOT_COVERED", v2_by_id["V2-AC-20"]["status"])

            gate._write_json(fixture.manifest, ledger)
            with self.assertRaisesRegex(gate.EvidenceError, "requires both"):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    candidate_validation_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    v1_upgrade_evidence_path=upgrade_evidence,
                    redis_loss_evidence_path=redis_evidence,
                    verify_git=False,
                )
            with mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=summary,
            ) as verify_validate, mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ), mock.patch.object(
                gate.redis_loss_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ), self.assertRaisesRegex(gate.EvidenceError, "gate is not PASS"):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    candidate_validation_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    release_runtime_test_reports_directory_path=raw,
                    v1_upgrade_evidence_path=upgrade_evidence,
                    redis_loss_evidence_path=redis_evidence,
                    verify_git=False,
                )
            self.assertEqual(raw.resolve(), verify_validate.call_args.args[0])

    def test_release_runtime_reports_reject_missing_tampered_and_wrong_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            raw = Path(directory) / "private-runtime-reports"
            raw.mkdir(mode=0o700)
            artifact = (
                fixture.artifacts
                / "acceptance/release-runtime-test-reports-summary.json"
            )
            with self.assertRaisesRegex(gate.EvidenceError, "requires both"):
                fixture.build(
                    release_runtime_test_reports_directory_path=raw,
                )

            summary = release_runtime_test_reports_summary()
            tampered = json.loads(json.dumps(summary))
            tampered["reports"][gate.release_runtime_test_reports.PLAYWRIGHT_REPORT] = "0" * 64
            artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(tampered)
            )
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=summary,
            ), self.assertRaisesRegex(gate.EvidenceError, "canonical summary differs"):
                fixture.build(
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=raw,
                    release_runtime_test_reports_summary_artifact_path=artifact,
                )

            wrong_candidate = release_runtime_test_reports_summary()
            wrong_candidate["candidate"]["commit"] = "e" * 40
            artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(wrong_candidate)
            )
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=wrong_candidate,
            ), self.assertRaisesRegex(gate.EvidenceError, "candidate identity differs"):
                fixture.build(
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=raw,
                    release_runtime_test_reports_summary_artifact_path=artifact,
                )

            artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o644)
            with self.assertRaisesRegex(gate.EvidenceError, "private fixed file"):
                fixture.build(
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=raw,
                    release_runtime_test_reports_summary_artifact_path=artifact,
                )

            artifact.chmod(0o600)
            inside_repository = fixture.root / "private-runtime-reports"
            inside_repository.mkdir(mode=0o700)
            with self.assertRaisesRegex(gate.EvidenceError, "isolated from repositories"):
                fixture.build(
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=inside_repository,
                    release_runtime_test_reports_summary_artifact_path=artifact,
                )

    def test_ac40_pass_is_independently_recomputed_and_public_copy_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac40"
            private.mkdir(mode=0o700)
            evidence = private / "v2-v1-upgrade-rehearsal.json"
            write_json(evidence, {"status": "PASS", "sanitized": True})
            evidence.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/v2-v1-upgrade-rehearsal.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(evidence.read_bytes())
            provenance = (
                fixture.artifacts
                / gate.AC40_DEPENDENCY_SEED_PROVENANCE_PATH
            )
            write_canonical_private_json(
                provenance, ac40_dependency_seed_provenance()
            )

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            for acceptance_id in (
                "V2-AC-04", "V2-AC-05", "V2-AC-06", "V2-AC-40"
            ):
                result = next(
                    item
                    for item in source["suites"]["v2"]["results"]
                    if item["id"] == acceptance_id
                )
                result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value=ac40_upgrade_summary(),
            ), self.assertRaisesRegex(
                gate.EvidenceError,
                "ac40DependencySeedProvenance",
            ):
                fixture.build(
                    v1_upgrade_evidence_path=evidence,
                    v1_upgrade_artifact_path=artifact,
                )

            with mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value=ac40_upgrade_summary(),
            ) as validate:
                ledger = fixture.build(
                    v1_upgrade_evidence_path=evidence,
                    v1_upgrade_artifact_path=artifact,
                    ac40_dependency_seed_provenance_path=provenance,
                )

            self.assertEqual(
                fixture.root.resolve(),
                validate.call_args.kwargs["repository_root"].resolve(),
            )
            self.assertEqual(
                fixture.ac40_dependency_seed,
                validate.call_args.kwargs["dependency_seed"],
            )
            self.assertEqual(
                fixture.expected_ac40_dependency_seed_sha256,
                validate.call_args.kwargs["expected_dependency_seed_sha256"],
            )
            self.assertTrue(validate.call_args.kwargs["require_pass"])
            results = {
                item["id"]: item for item in ledger["acceptance"]["v2"]["results"]
            }
            for acceptance_id in (
                "V2-AC-04", "V2-AC-05", "V2-AC-06", "V2-AC-40"
            ):
                self.assertEqual(
                    "GATE_INDEPENDENTLY_VERIFIED",
                    results[acceptance_id]["evidenceTrust"],
                )
            self.assertIn("v1UpgradeRehearsal", ledger["inputs"])
            self.assertIn("ac40DependencySeedProvenance", ledger["inputs"])
            ac40_result = results["V2-AC-40"]
            for input_name in (
                "v1UpgradeRehearsal", "ac40DependencySeedProvenance"
            ):
                binding = ledger["inputs"][input_name]
                self.assertIn(
                    f"artifact://{binding['path']}#sha256={binding['sha256']}",
                    ac40_result["evidence"],
                )

            for field, value in (
                ("path", "acceptance/tampered-provenance.json"),
                ("sha256", "0" * 64),
            ):
                with self.subTest(manifest_binding=field):
                    tampered = json.loads(json.dumps(ledger))
                    tampered["inputs"]["ac40DependencySeedProvenance"][field] = value
                    gate._write_json(fixture.manifest, tampered)
                    with mock.patch.object(
                        gate.v1_upgrade_evidence,
                        "validate_document_path",
                        return_value=ac40_upgrade_summary(),
                    ), self.assertRaisesRegex(
                        gate.EvidenceError,
                        "manifest does not match",
                    ):
                        gate.verify_ledger(
                            manifest_path=fixture.manifest,
                            repository_root=fixture.root,
                            artifacts_root=fixture.artifacts,
                            tag=TAG,
                            version=VERSION,
                            commit=COMMIT,
                            v1_upgrade_evidence_path=evidence,
                            ac40_dependency_seed_path=fixture.ac40_dependency_seed,
                            expected_ac40_dependency_seed_sha256=(
                                fixture.expected_ac40_dependency_seed_sha256
                            ),
                            ac40_dependency_seed_provenance_path=provenance,
                            verify_git=False,
                        )

            gate._write_json(fixture.manifest, ledger)
            with self.assertRaisesRegex(
                gate.EvidenceError,
                "explicitly supplied",
            ):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    v1_upgrade_evidence_path=evidence,
                    ac40_dependency_seed_path=fixture.ac40_dependency_seed,
                    expected_ac40_dependency_seed_sha256=(
                        fixture.expected_ac40_dependency_seed_sha256
                    ),
                    verify_git=False,
                )
            with mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value=ac40_upgrade_summary(),
            ), self.assertRaisesRegex(gate.EvidenceError, "gate is not PASS"):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    v1_upgrade_evidence_path=evidence,
                    ac40_dependency_seed_path=fixture.ac40_dependency_seed,
                    expected_ac40_dependency_seed_sha256=(
                        fixture.expected_ac40_dependency_seed_sha256
                    ),
                    ac40_dependency_seed_provenance_path=provenance,
                    verify_git=False,
                )

    def test_ac40_dependency_seed_provenance_rejects_semantic_and_file_tampering(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac40"
            private.mkdir(mode=0o700)
            evidence = private / "v2-v1-upgrade-rehearsal.json"
            write_json(evidence, {"status": "PASS", "sanitized": True})
            evidence.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/v2-v1-upgrade-rehearsal.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(evidence.read_bytes())
            provenance = (
                fixture.artifacts
                / gate.AC40_DEPENDENCY_SEED_PROVENANCE_PATH
            )

            def build_with(document: dict) -> dict:
                write_canonical_private_json(provenance, document)
                with mock.patch.object(
                    gate.v1_upgrade_evidence,
                    "validate_document_path",
                    return_value=ac40_upgrade_summary(),
                ):
                    return fixture.build(
                        v1_upgrade_evidence_path=evidence,
                        v1_upgrade_artifact_path=artifact,
                        ac40_dependency_seed_provenance_path=provenance,
                    )

            ledger = build_with(ac40_dependency_seed_provenance())
            binding = ledger["inputs"]["ac40DependencySeedProvenance"]
            self.assertEqual(
                gate.AC40_DEPENDENCY_SEED_PROVENANCE_PATH,
                binding["path"],
            )
            self.assertEqual(gate._sha256(provenance), binding["sha256"])
            self.assertEqual("PASS", binding["status"])

            mutations: tuple[tuple[str, dict, str], ...] = (
                (
                    "unknown field",
                    ac40_dependency_seed_provenance(unexpected=True),
                    "fields are not exact",
                ),
                (
                    "kind",
                    ac40_dependency_seed_provenance(kind="other"),
                    "kind is invalid",
                ),
                (
                    "environment",
                    ac40_dependency_seed_provenance(environment="staging"),
                    "environment must be release",
                ),
                (
                    "artifact id",
                    ac40_dependency_seed_provenance(artifactId=0),
                    "positive integer",
                ),
                (
                    "release commit",
                    ac40_dependency_seed_provenance(producerHeadSha="d" * 40),
                    "release commit",
                ),
                (
                    "archive digest",
                    ac40_dependency_seed_provenance(archiveSha256="A" * 64),
                    "lowercase SHA-256",
                ),
                (
                    "aggregate digest",
                    ac40_dependency_seed_provenance(aggregateSha256="6" * 64),
                    "independently validated AC-40",
                ),
                (
                    "manifest digest",
                    ac40_dependency_seed_provenance(manifestSha256="7" * 64),
                    "independently validated AC-40",
                ),
                (
                    "platform",
                    ac40_dependency_seed_provenance(platform="darwin"),
                    "Linux x86_64",
                ),
                (
                    "architecture",
                    ac40_dependency_seed_provenance(architecture="arm64"),
                    "Linux x86_64",
                ),
            )
            for label, document, message in mutations:
                with self.subTest(label=label), self.assertRaisesRegex(
                    gate.EvidenceError,
                    message,
                ):
                    build_with(document)

            missing = ac40_dependency_seed_provenance()
            del missing["manifestSha256"]
            with self.assertRaisesRegex(gate.EvidenceError, "fields are not exact"):
                build_with(missing)

            write_canonical_private_json(
                provenance, ac40_dependency_seed_provenance()
            )
            provenance.chmod(0o644)
            with mock.patch.object(
                gate.v1_upgrade_evidence,
                "validate_document_path",
                return_value=ac40_upgrade_summary(),
            ), self.assertRaisesRegex(gate.EvidenceError, "private fixed file"):
                fixture.build(
                    v1_upgrade_evidence_path=evidence,
                    v1_upgrade_artifact_path=artifact,
                    ac40_dependency_seed_provenance_path=provenance,
                )

            provenance.chmod(0o600)
            hardlink = provenance.with_name("receipt-hardlink.json")
            os.link(provenance, hardlink)
            try:
                with mock.patch.object(
                    gate.v1_upgrade_evidence,
                    "validate_document_path",
                    return_value=ac40_upgrade_summary(),
                ), self.assertRaisesRegex(gate.EvidenceError, "private fixed file"):
                    fixture.build(
                        v1_upgrade_evidence_path=evidence,
                        v1_upgrade_artifact_path=artifact,
                        ac40_dependency_seed_provenance_path=provenance,
                    )
            finally:
                hardlink.unlink()

    def test_ac07_pass_is_recomputed_against_runtime_image_identity_and_public_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac07"
            private.mkdir(mode=0o700)
            evidence = private / "v2-ac07-migration-failure.json"
            recovery = private / "v2-ac40.json"
            write_json(evidence, {"status": "PASS", "sanitized": True})
            write_json(recovery, {"status": "PASS", "sanitized": True})
            evidence.chmod(0o600)
            recovery.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/v2-ac07-migration-failure.json"
            artifact.write_bytes(evidence.read_bytes())

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            result = next(
                item for item in source["suites"]["v2"]["results"]
                if item["id"] == "V2-AC-07"
            )
            result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.migration_failure_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ) as validate:
                ledger = fixture.build(
                    migration_failure_evidence_path=evidence,
                    migration_failure_ac40_evidence_path=recovery,
                    migration_failure_artifact_path=artifact,
                )

            keyword = validate.call_args.kwargs
            self.assertEqual(
                fixture.ac40_dependency_seed,
                keyword["ac40_dependency_seed"],
            )
            self.assertEqual(
                fixture.expected_ac40_dependency_seed_sha256,
                keyword["expected_ac40_dependency_seed_sha256"],
            )
            self.assertEqual(
                json.loads(fixture.runtime_identity.read_text(encoding="utf-8"))["images"]["app"]["imageId"],
                keyword["expected_app_image_id"],
            )
            self.assertEqual(
                production_model()["services"]["mysql"]["image"],
                json.loads(fixture.runtime_identity.read_text(encoding="utf-8"))["images"]["mysql"]["reference"],
            )
            ac07 = next(
                item for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-07"
            )
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac07["evidenceTrust"])
            self.assertIn("migrationFailureRehearsal", ledger["inputs"])

    def test_ac41_pass_is_recomputed_with_all_four_runtime_images(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac41"
            private.mkdir(mode=0o700)
            evidence = private / "v2-ac41-redis-loss.json"
            write_json(evidence, {"status": "PASS", "sanitized": True})
            evidence.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/v2-ac41-redis-loss.json"
            artifact.write_bytes(evidence.read_bytes())

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            result = next(
                item for item in source["suites"]["v2"]["results"]
                if item["id"] == "V2-AC-41"
            )
            result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.redis_loss_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ) as validate:
                ledger = fixture.build(
                    redis_loss_evidence_path=evidence,
                    redis_loss_artifact_path=artifact,
                )

            expected_images = validate.call_args.kwargs["expected_images"]
            self.assertEqual({"app", "nginx", "mysql", "redis"}, set(expected_images))
            self.assertTrue(all("@sha256:" in item["reference"] for item in expected_images.values()))
            ac41 = next(
                item for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-41"
            )
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac41["evidenceTrust"])
            self.assertIn("redisLossRehearsal", ledger["inputs"])

    def test_ac16_ac31_and_ac32_share_one_independently_recomputed_mcp_crud_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-mcp-proof"
            private.mkdir(mode=0o700)
            proof = private / "mcp-crud-runtime-proof.properties"
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            summary = {
                "schemaVersion": 1,
                "acceptanceIds": ["AC-16", "V2-AC-31", "V2-AC-32"],
                "status": "PASS",
                "candidate": {"commit": COMMIT, "version": VERSION, "tag": TAG},
                "runtime": {
                    "composeProject": "web-starter-release-17",
                    "tracePrefix": gate.MCP_CRUD_TRACE_PREFIX,
                },
                "checks": {
                    "officialSdkRuntime": "PASS",
                    "businessTransactionRollback": "PASS",
                    "successBusinessAuditAtomicity": "PASS",
                    "failedMcpAuditPersists": "PASS",
                    "idempotencyReservationRollback": "PASS",
                    "faultInjectionCleaned": "PASS",
                    "transactionalStorage": "PASS",
                },
            }
            artifact = fixture.artifacts / "acceptance/mcp-crud-runtime-proof-summary.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(
                (
                    json.dumps(
                        summary,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )
            artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item
                for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-16"
            )["status"] = "PASS"
            for acceptance_id in ("V2-AC-31", "V2-AC-32"):
                result = next(
                    item
                    for item in source["suites"]["v2"]["results"]
                    if item["id"] == acceptance_id
                )
                result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.mcp_crud_proof,
                "validate_proof",
                return_value=summary,
            ) as validate:
                ledger = fixture.build(
                    mcp_crud_proof_path=proof,
                    mcp_crud_summary_artifact_path=artifact,
                )

            expected = validate.call_args.kwargs
            self.assertEqual(COMMIT, expected["expected_candidate_commit"])
            self.assertEqual(VERSION, expected["expected_candidate_version"])
            self.assertEqual(TAG, expected["expected_candidate_tag"])
            self.assertEqual("web-starter-release-17", expected["expected_compose_project"])
            self.assertEqual(
                gate.MCP_CRUD_TRACE_PREFIX, expected["expected_trace_prefix"]
            )
            v1_results = {
                item["id"]: item for item in ledger["acceptance"]["v1"]["results"]
            }
            self.assertEqual(
                "GATE_INDEPENDENTLY_VERIFIED",
                v1_results["AC-16"]["evidenceTrust"],
            )
            results = {
                item["id"]: item for item in ledger["acceptance"]["v2"]["results"]
            }
            for acceptance_id in ("V2-AC-31", "V2-AC-32"):
                self.assertEqual(
                    "GATE_INDEPENDENTLY_VERIFIED",
                    results[acceptance_id]["evidenceTrust"],
                )
            self.assertIn("mcpCrudRuntimeProofSummary", ledger["inputs"])

    def test_mcp_crud_summary_must_be_canonical_and_match_the_validated_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-mcp-proof"
            private.mkdir(mode=0o700)
            proof = private / "mcp-crud-runtime-proof.properties"
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/mcp-crud-runtime-proof-summary.json"
            write_json(artifact, {"schemaVersion": 1, "status": "PASS", "forged": True})
            artifact.chmod(0o600)
            validated = {
                "schemaVersion": 1,
                "acceptanceIds": ["AC-16", "V2-AC-31", "V2-AC-32"],
                "status": "PASS",
                "candidate": {"commit": COMMIT},
                "checks": {
                    "officialSdkRuntime": "PASS",
                    "businessTransactionRollback": "PASS",
                    "successBusinessAuditAtomicity": "PASS",
                    "failedMcpAuditPersists": "PASS",
                    "idempotencyReservationRollback": "PASS",
                    "faultInjectionCleaned": "PASS",
                    "transactionalStorage": "PASS",
                },
            }

            with mock.patch.object(
                gate.mcp_crud_proof,
                "validate_proof",
                return_value=validated,
            ), self.assertRaisesRegex(gate.EvidenceError, "canonical summary differs"):
                gate._collect_mcp_crud_runtime_proof(
                    proof_path=proof,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    runtime_binding={
                        "composeProject": "web-starter-release-17",
                        "mcpCrudTracePrefix": gate.MCP_CRUD_TRACE_PREFIX,
                    },
                )

    def test_v1_oauth_security_and_v2_lifecycle_items_share_recomputed_credential_evidence(self) -> None:
        acceptance_ids = {
            "AC-17", "AC-18", "AC-19", "AC-20", "AC-21", "AC-22", "AC-23", "AC-24", "AC-34",
            "V2-AC-24", "V2-AC-27", "V2-AC-28", "V2-AC-36",
        }
        self.assertEqual(
            acceptance_ids,
            {
                acceptance_id
                for acceptance_id, bindings in gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS.items()
                if "credentialLifecycleSummary" in bindings
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            raw = Path(directory) / "private-credential-lifecycle"
            raw.mkdir(mode=0o700)
            raw.chmod(0o700)
            report = raw / gate.credential_lifecycle_evidence.REPORT_NAME
            write(report, "private-report-placeholder\n")
            report.chmod(0o600)
            write_json(fixture.artifacts / "oauth-runtime.json", {"status": "PASS"})
            summary = credential_lifecycle_summary()
            artifact = (
                fixture.artifacts
                / "acceptance"
                / gate.credential_lifecycle_evidence.SUMMARY_NAME
            )
            artifact.write_bytes(
                gate.credential_lifecycle_evidence.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)

            runtime_raw = Path(directory) / "private-runtime-reports"
            runtime_raw.mkdir(mode=0o700)
            runtime_raw.chmod(0o700)
            runtime_summary = release_runtime_test_reports_summary()
            runtime_artifact = (
                fixture.artifacts
                / "acceptance/release-runtime-test-reports-summary.json"
            )
            runtime_artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(runtime_summary)
            )
            runtime_artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            for result in source["suites"]["v2"]["results"]:
                if result["id"] in acceptance_ids:
                    result["status"] = "PASS"
            for acceptance_id in ("AC-17", "AC-18", "AC-19", "AC-20", "AC-21", "AC-22", "AC-23", "AC-24", "AC-34"):
                next(
                    result for result in source["suites"]["v1"]["results"]
                    if result["id"] == acceptance_id
                )["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.credential_lifecycle_evidence,
                "validate",
                return_value=summary,
            ) as validate, mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=runtime_summary,
            ):
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    credential_lifecycle_report_path=report,
                    credential_lifecycle_summary_artifact_path=artifact,
                    release_runtime_test_reports_directory_path=runtime_raw,
                    release_runtime_test_reports_summary_artifact_path=runtime_artifact,
                )

            validate.assert_called_once_with(
                report.absolute(),
                fixture.root.resolve(),
                fixture.runtime_identity.resolve(),
                (fixture.artifacts / "oauth-runtime.json").resolve(),
                "web-starter-release-17",
                None,
            )
            binding = ledger["inputs"]["credentialLifecycleSummary"]
            self.assertEqual("PASS", binding["status"])
            self.assertEqual(
                f"acceptance/{gate.credential_lifecycle_evidence.SUMMARY_NAME}",
                binding["path"],
            )
            results = {
                result["id"]: result
                for suite in ("v1", "v2")
                for result in ledger["acceptance"][suite]["results"]
            }
            for acceptance_id in acceptance_ids:
                self.assertEqual(
                    "GATE_INDEPENDENTLY_VERIFIED",
                    results[acceptance_id]["evidenceTrust"],
                )
                self.assertIn(
                    f"artifact://{binding['path']}#sha256={binding['sha256']}",
                    results[acceptance_id]["evidence"],
                )
            runtime_binding = ledger["inputs"]["releaseRuntimeTestReports"]
            for acceptance_id in ("AC-19", "AC-20", "AC-22", "AC-23", "AC-34"):
                self.assertIn(
                    f"artifact://{runtime_binding['path']}#sha256={runtime_binding['sha256']}",
                    results[acceptance_id]["evidence"],
                )

    def test_credential_lifecycle_rejects_drifted_canonical_or_nonisolated_raw_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            write_json(fixture.artifacts / "oauth-runtime.json", {"status": "PASS"})
            summary = credential_lifecycle_summary()
            artifact = (
                fixture.artifacts
                / "acceptance"
                / gate.credential_lifecycle_evidence.SUMMARY_NAME
            )
            artifact.write_bytes(b"{}\n")
            artifact.chmod(0o600)
            raw = Path(directory) / "private-credential-lifecycle"
            raw.mkdir(mode=0o700)
            raw.chmod(0o700)
            report = raw / gate.credential_lifecycle_evidence.REPORT_NAME
            write(report, "private-report-placeholder\n")
            report.chmod(0o600)

            with mock.patch.object(
                gate.credential_lifecycle_evidence, "validate", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "byte-for-byte"):
                gate._collect_credential_lifecycle_evidence(
                    report_path=report,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    runtime_identity_path=fixture.runtime_identity,
                    compose_project="web-starter-release-17",
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                )

            artifact.write_bytes(
                gate.credential_lifecycle_evidence.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)
            inside = fixture.root / "private-credential-lifecycle"
            inside.mkdir(mode=0o700)
            inside.chmod(0o700)
            inside_report = inside / gate.credential_lifecycle_evidence.REPORT_NAME
            write(inside_report, "private-report-placeholder\n")
            inside_report.chmod(0o600)
            with self.assertRaisesRegex(gate.EvidenceError, "isolated from repositories"):
                gate._collect_credential_lifecycle_evidence(
                    report_path=inside_report,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    runtime_identity_path=fixture.runtime_identity,
                    compose_project="web-starter-release-17",
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                )

    def test_ac37_uses_recomputed_metrics_runtime_identity_and_canonical_summary(self) -> None:
        self.assertEqual(
            {"AC-38", "V2-AC-37"},
            {
                acceptance_id
                for acceptance_id, bindings in gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS.items()
                if "observabilitySummary" in bindings
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            baseline = fixture.artifacts / "operational-metrics-baseline.json"
            runtime = fixture.artifacts / "operational-metrics-runtime.json"
            write_json(baseline, {"private": "baseline"})
            write_json(runtime, {"private": "runtime"})
            baseline.chmod(0o600)
            runtime.chmod(0o600)
            summary = observability_summary()
            artifact = (
                fixture.artifacts
                / "acceptance"
                / gate.observability_evidence.SUMMARY_NAME
            )
            artifact.write_bytes(
                gate.observability_evidence.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            for result in source["suites"]["v2"]["results"]:
                if result["id"] == "V2-AC-37":
                    result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.observability_evidence, "validate", return_value=summary
            ) as validate:
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    observability_baseline_path=baseline,
                    observability_runtime_path=runtime,
                    observability_summary_artifact_path=artifact,
                )

            validate.assert_called_once_with(
                baseline.resolve(),
                runtime.resolve(),
                fixture.root.resolve(),
                fixture.runtime_identity.resolve(),
                "web-starter-release-17",
                TAG,
                None,
            )
            binding = ledger["inputs"]["observabilitySummary"]
            result = next(
                item for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-37"
            )
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", result["evidenceTrust"])
            self.assertIn(
                f"artifact://{binding['path']}#sha256={binding['sha256']}",
                result["evidence"],
            )

            artifact.write_bytes(b"{}\n")
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.observability_evidence, "validate", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "byte-for-byte"):
                gate._collect_observability_evidence(
                    baseline_path=baseline,
                    runtime_path=runtime,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    runtime_identity_path=fixture.runtime_identity,
                    compose_project="web-starter-release-17",
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                )

    def test_ac02_ac37_ac16_and_ac17_share_one_recomputed_tooling_lifecycle_report(
        self,
    ) -> None:
        self.assertEqual(
            {"AC-02", "AC-37", "V2-AC-16", "V2-AC-17"},
            {
                acceptance_id
                for acceptance_id, bindings in gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS.items()
                if "toolingLifecycleSummary" in bindings
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            raw = Path(directory) / "private-tooling-lifecycle"
            raw.mkdir(mode=0o700)
            raw.chmod(0o700)
            report = raw / gate.tooling_lifecycle_evidence.REPORT_NAME
            write(report, "private-report-placeholder\n")
            report.chmod(0o600)
            summary = tooling_lifecycle_summary()
            artifact = (
                fixture.artifacts
                / "acceptance"
                / gate.tooling_lifecycle_evidence.SUMMARY_NAME
            )
            artifact.write_bytes(
                gate.tooling_lifecycle_evidence.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            for result in source["suites"]["v1"]["results"]:
                if result["id"] in {"AC-02", "AC-37"}:
                    result["status"] = "PASS"
            for result in source["suites"]["v2"]["results"]:
                if result["id"] in {"V2-AC-16", "V2-AC-17"}:
                    result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.tooling_lifecycle_evidence, "validate", return_value=summary
            ) as validate:
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    tooling_lifecycle_report_path=report,
                    tooling_lifecycle_summary_artifact_path=artifact,
                    tooling_lifecycle_compose_project="web-starter-tooling-17-1",
                )

            validate.assert_called_once_with(
                report.absolute(),
                fixture.root.resolve(),
                fixture.runtime_identity.resolve(),
                "web-starter-tooling-17-1",
                None,
            )
            binding = ledger["inputs"]["toolingLifecycleSummary"]
            v1_results = {
                item["id"]: item for item in ledger["acceptance"]["v1"]["results"]
            }
            v2_results = {
                item["id"]: item for item in ledger["acceptance"]["v2"]["results"]
            }
            self.assertEqual(
                "GATE_INDEPENDENTLY_VERIFIED", v1_results["AC-37"]["evidenceTrust"],
            )
            self.assertIn(
                f"artifact://{binding['path']}#sha256={binding['sha256']}",
                v1_results["AC-37"]["evidence"],
            )
            self.assertEqual(
                "GATE_INDEPENDENTLY_VERIFIED",
                v1_results["AC-02"]["evidenceTrust"],
            )
            self.assertIn(
                f"artifact://{binding['path']}#sha256={binding['sha256']}",
                v1_results["AC-02"]["evidence"],
            )
            unified = ledger["inputs"]["unifiedVerify"]
            self.assertIn(
                f"artifact://{unified['path']}#sha256={unified['sha256']}",
                v1_results["AC-02"]["evidence"],
            )
            for acceptance_id in ("V2-AC-16", "V2-AC-17"):
                self.assertEqual(
                    "GATE_INDEPENDENTLY_VERIFIED",
                    v2_results[acceptance_id]["evidenceTrust"],
                )
                self.assertIn(
                    f"artifact://{binding['path']}#sha256={binding['sha256']}",
                    v2_results[acceptance_id]["evidence"],
                )

            artifact.write_bytes(b"{}\n")
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.tooling_lifecycle_evidence, "validate", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "byte-for-byte"):
                gate._collect_tooling_lifecycle_evidence(
                    report_path=report,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    runtime_identity_path=fixture.runtime_identity,
                    compose_project="web-starter-tooling-17-1",
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                )

    def test_ac34_and_ac35_share_one_release_identity_bound_governance_proof(self) -> None:
        governance_acceptance_ids = {"V2-AC-34", "V2-AC-35"}
        self.assertEqual(
            governance_acceptance_ids,
            {
                acceptance_id
                for acceptance_id, bindings in (
                    gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS.items()
                )
                if "mcpGovernanceRuntimeSummary" in bindings
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            raw = Path(directory) / "private-mcp-governance-proof"
            raw.mkdir(mode=0o700)
            raw.chmod(0o700)
            proof = raw / gate.mcp_governance_proof.PROOF_FILE
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            summary = mcp_governance_runtime_summary()
            artifact = (
                fixture.artifacts / "acceptance/mcp-governance-runtime-summary.json"
            )
            artifact.write_bytes(
                gate.mcp_governance_proof.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            for result in source["suites"]["v2"]["results"]:
                if result["id"] in governance_acceptance_ids:
                    result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            governance_project = "web-starter-governance-17-1"
            ac26_project = "web-starter-ac26-17-1"
            with mock.patch.object(
                gate.mcp_governance_proof,
                "validate_proof",
                return_value=summary,
            ) as validate, mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ):
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    mcp_governance_proof_path=proof,
                    mcp_governance_summary_artifact_path=artifact,
                    mcp_governance_compose_project=governance_project,
                    jwks_rotation_compose_project=ac26_project,
                    jwks_rotation_terminal_mode="expiry",
                )

            expected = validate.call_args.kwargs
            runtime_identity = json.loads(fixture.runtime_identity.read_text())
            self.assertEqual(fixture.root.resolve(), expected["repository_root"])
            self.assertEqual(COMMIT, expected["expected_candidate_commit"])
            self.assertEqual(VERSION, expected["expected_candidate_version"])
            self.assertEqual(TAG, expected["expected_candidate_tag"])
            self.assertEqual(governance_project, expected["expected_compose_project"])
            self.assertEqual(
                gate.MCP_GOVERNANCE_TRACE_PREFIX,
                expected["expected_trace_prefix"],
            )
            for name in ("app", "nginx", "redis"):
                self.assertEqual(
                    runtime_identity["images"][name]["reference"],
                    expected[f"expected_{name}_reference"],
                )
                self.assertEqual(
                    runtime_identity["images"][name]["imageId"],
                    expected[f"expected_{name}_image_id"],
                )
            self.assertIs(True, expected["require_pass"])
            binding = ledger["inputs"]["mcpGovernanceRuntimeSummary"]
            self.assertEqual("PASS", binding["status"])
            results = {
                result["id"]: result for result in ledger["acceptance"]["v2"]["results"]
            }
            for acceptance_id in governance_acceptance_ids:
                self.assertEqual(
                    "GATE_INDEPENDENTLY_VERIFIED",
                    results[acceptance_id]["evidenceTrust"],
                )
                self.assertIn(
                    f"artifact://{binding['path']}#sha256={binding['sha256']}",
                    results[acceptance_id]["evidence"],
                )

            gate._write_json(fixture.manifest, ledger)
            with mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ), self.assertRaisesRegex(gate.EvidenceError, "requires both"):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    candidate_validation_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    mcp_governance_compose_project=governance_project,
                    jwks_rotation_compose_project=ac26_project,
                    jwks_rotation_terminal_mode="expiry",
                    verify_git=False,
                )
            with mock.patch.object(
                gate.mcp_governance_proof,
                "validate_proof",
                return_value=summary,
            ) as verify_validate, mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ), self.assertRaisesRegex(gate.EvidenceError, "gate is not PASS"):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    candidate_validation_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    mcp_governance_proof_path=proof,
                    mcp_governance_compose_project=governance_project,
                    jwks_rotation_compose_project=ac26_project,
                    jwks_rotation_terminal_mode="expiry",
                    verify_git=False,
                )
            self.assertEqual(proof.absolute(), verify_validate.call_args.args[0])

    def test_mcp_governance_rejects_partial_drifted_or_nonisolated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            raw = Path(directory) / "private-mcp-governance-proof"
            raw.mkdir(mode=0o700)
            raw.chmod(0o700)
            proof = raw / gate.mcp_governance_proof.PROOF_FILE
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            summary = mcp_governance_runtime_summary()
            artifact = (
                fixture.artifacts / "acceptance/mcp-governance-runtime-summary.json"
            )
            artifact.write_bytes(
                gate.mcp_governance_proof.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)
            common = {
                "candidate_validation_root": fixture.root,
                "mcp_governance_compose_project": "web-starter-governance-17-1",
                "jwks_rotation_compose_project": "web-starter-ac26-17-1",
                "jwks_rotation_terminal_mode": "expiry",
            }

            with mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ), self.assertRaisesRegex(gate.EvidenceError, "requires both"):
                fixture.build(mcp_governance_proof_path=proof, **common)

            for governance_project, ac26_project in (
                ("web-starter-release-17", "web-starter-ac26-17-1"),
                ("web-starter-governance-17-1", "web-starter-governance-17-1"),
                ("governance-17-1", "web-starter-ac26-17-1"),
            ):
                with self.subTest(project=governance_project, ac26=ac26_project), mock.patch.object(
                    gate, "_collect_jwks_rotation_evidence", return_value=None
                ), self.assertRaisesRegex(
                    gate.EvidenceError, "Compose project|bounded governance"
                ):
                    fixture.build(
                        mcp_governance_proof_path=proof,
                        mcp_governance_summary_artifact_path=artifact,
                        mcp_governance_compose_project=governance_project,
                        jwks_rotation_compose_project=ac26_project,
                        jwks_rotation_terminal_mode="expiry",
                        candidate_validation_root=fixture.root,
                    )

            tampered = json.loads(json.dumps(summary))
            tampered["shutdown"]["restartReceiptSha256"] = "0" * 64
            artifact.write_bytes(
                gate.mcp_governance_proof.canonical_summary_bytes(tampered)
            )
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.mcp_governance_proof, "validate_proof", return_value=summary
            ), mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ), self.assertRaisesRegex(gate.EvidenceError, "byte-for-byte"):
                fixture.build(
                    mcp_governance_proof_path=proof,
                    mcp_governance_summary_artifact_path=artifact,
                    **common,
                )

            for name, field, value, pattern in (
                ("candidate", "commit", "e" * 40, "candidate identity differs"),
                (
                    "runtime",
                    "composeProject",
                    "web-starter-governance-other-1",
                    "runtime identity differs",
                ),
            ):
                with self.subTest(binding=name):
                    drifted = json.loads(json.dumps(summary))
                    drifted[name][field] = value
                    artifact.write_bytes(
                        gate.mcp_governance_proof.canonical_summary_bytes(drifted)
                    )
                    artifact.chmod(0o600)
                    with mock.patch.object(
                        gate.mcp_governance_proof,
                        "validate_proof",
                        return_value=drifted,
                    ), mock.patch.object(
                        gate, "_collect_jwks_rotation_evidence", return_value=None
                    ), self.assertRaisesRegex(gate.EvidenceError, pattern):
                        fixture.build(
                            mcp_governance_proof_path=proof,
                            mcp_governance_summary_artifact_path=artifact,
                            **common,
                        )

            artifact.write_bytes(
                gate.mcp_governance_proof.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o644)
            with mock.patch.object(
                gate.mcp_governance_proof, "validate_proof", return_value=summary
            ), mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ), self.assertRaisesRegex(gate.EvidenceError, "owned private fixed file"):
                fixture.build(
                    mcp_governance_proof_path=proof,
                    mcp_governance_summary_artifact_path=artifact,
                    **common,
                )

            artifact.chmod(0o600)
            inside = fixture.root / "private-mcp-governance-proof"
            inside.mkdir(mode=0o700)
            inside_proof = inside / gate.mcp_governance_proof.PROOF_FILE
            write(inside_proof, "private-proof-placeholder\n")
            inside_proof.chmod(0o600)
            with mock.patch.object(
                gate, "_collect_jwks_rotation_evidence", return_value=None
            ), self.assertRaisesRegex(gate.EvidenceError, "isolated from repositories"):
                fixture.build(
                    mcp_governance_proof_path=inside_proof,
                    mcp_governance_summary_artifact_path=artifact,
                    **common,
                )

    def test_ac33_uses_one_candidate_bound_tool_contract_proof_and_canonical_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-mcp-tool-contract-proof"
            private.mkdir(mode=0o700)
            proof = private / "mcp-tool-contract-runtime-proof.properties"
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            summary = {
                "schemaVersion": 1,
                "status": "PASS",
                "acceptanceId": "V2-AC-33",
                "candidate": {
                    "commit": COMMIT,
                    "tree": "d" * 40,
                    "version": VERSION,
                    "tag": TAG,
                },
                "runtime": {
                    "composeProject": "web-starter-release-17",
                    "tracePrefix": gate.MCP_TOOL_CONTRACT_TRACE_PREFIX,
                },
            }
            artifact = (
                fixture.artifacts
                / "acceptance/mcp-tool-contract-runtime-proof-summary.json"
            )
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(gate.mcp_tool_contract_proof.canonical_summary_bytes(summary))
            artifact.chmod(0o600)
            runtime_raw = Path(directory) / "private-runtime-reports"
            runtime_raw.mkdir(mode=0o700)
            runtime_summary = release_runtime_test_reports_summary()
            runtime_artifact = (
                fixture.artifacts
                / "acceptance/release-runtime-test-reports-summary.json"
            )
            runtime_artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(
                    runtime_summary
                )
            )
            runtime_artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item
                for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-26"
            )["status"] = "PASS"
            result = next(
                item
                for item in source["suites"]["v2"]["results"]
                if item["id"] == "V2-AC-33"
            )
            result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.mcp_tool_contract_proof,
                "validate_proof",
                return_value=summary,
            ) as validate, mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=runtime_summary,
            ):
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    mcp_tool_contract_proof_path=proof,
                    mcp_tool_contract_summary_artifact_path=artifact,
                    release_runtime_test_reports_directory_path=runtime_raw,
                    release_runtime_test_reports_summary_artifact_path=(
                        runtime_artifact
                    ),
                )

            expected = validate.call_args.kwargs
            self.assertEqual(fixture.root.resolve(), expected["repository_root"])
            self.assertEqual(COMMIT, expected["expected_candidate_commit"])
            self.assertEqual(VERSION, expected["expected_candidate_version"])
            self.assertEqual(TAG, expected["expected_candidate_tag"])
            self.assertEqual("web-starter-release-17", expected["expected_compose_project"])
            self.assertEqual(
                gate.MCP_TOOL_CONTRACT_TRACE_PREFIX,
                expected["expected_trace_prefix"],
            )
            self.assertIs(True, expected["require_pass"])
            ac33 = next(
                item
                for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-33"
            )
            self.assertEqual("PASS", ac33["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac33["evidenceTrust"])
            self.assertEqual(
                "PASS", ledger["inputs"]["mcpToolContractSummary"]["status"]
            )
            ac26 = next(
                item
                for item in ledger["acceptance"]["v1"]["results"]
                if item["id"] == "AC-26"
            )
            self.assertEqual("PASS", ac26["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac26["evidenceTrust"])
            self.assertEqual(
                {
                    "releaseRuntimeTestReports",
                    "mcpToolContractSummary",
                    "runtimeVersionIdentity",
                    "releaseRuntimeAcceptance",
                },
                set(gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-26"]),
            )

    def test_ac33_rejects_partial_noncanonical_or_publicly_readable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-mcp-tool-contract-proof"
            private.mkdir(mode=0o700)
            proof = private / "mcp-tool-contract-runtime-proof.properties"
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            artifact = (
                fixture.artifacts
                / "acceptance/mcp-tool-contract-runtime-proof-summary.json"
            )
            summary = {
                "schemaVersion": 1,
                "status": "PASS",
                "acceptanceId": "V2-AC-33",
                "candidate": {
                    "commit": COMMIT,
                    "tree": "d" * 40,
                    "version": VERSION,
                    "tag": TAG,
                },
                "runtime": {
                    "composeProject": "web-starter-release-17",
                    "tracePrefix": gate.MCP_TOOL_CONTRACT_TRACE_PREFIX,
                },
            }

            with self.assertRaisesRegex(gate.EvidenceError, "requires both"):
                fixture.build(mcp_tool_contract_proof_path=proof)

            write_json(artifact, {"schemaVersion": 1, "status": "PASS", "forged": True})
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.mcp_tool_contract_proof, "validate_proof", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "canonical summary differs"):
                fixture.build(
                    mcp_tool_contract_proof_path=proof,
                    mcp_tool_contract_summary_artifact_path=artifact,
                )

            artifact.write_bytes(gate.mcp_tool_contract_proof.canonical_summary_bytes(summary))
            artifact.chmod(0o644)
            with mock.patch.object(
                gate.mcp_tool_contract_proof, "validate_proof", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "mode 0600"):
                fixture.build(
                    mcp_tool_contract_proof_path=proof,
                    mcp_tool_contract_summary_artifact_path=artifact,
                )

    def test_ac26_recomputes_submitted_mode_against_candidate_runtime_and_canonical_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac26"
            private.mkdir(mode=0o700)
            report = private / "v2-ac26-jwks-rotation.json"
            write(report, "private-proof-placeholder\n")
            report.chmod(0o600)
            app_reference = f"registry.example/app@{DIGESTS['app']}"
            nginx_reference = f"registry.example/nginx@{DIGESTS['nginx']}"
            summary = {
                "schemaVersion": 1,
                "acceptanceId": "V2-AC-26",
                "status": "PASS",
                "candidate": {"commit": COMMIT, "tag": TAG, "version": VERSION},
                "runtime": {
                    "composeProject": "web-starter-ac26-17-1",
                    "appReference": app_reference,
                    "appImageId": "sha256:" + "c" * 64,
                    "nginxReference": nginx_reference,
                    "nginxImageId": "sha256:" + "d" * 64,
                    "publicOriginSha256": hashlib.sha256(
                        gate.JWKS_ROTATION_PUBLIC_ORIGIN.encode()
                    ).hexdigest(),
                    "privateOriginSha256": hashlib.sha256(
                        gate.JWKS_ROTATION_PRIVATE_ORIGIN.encode()
                    ).hexdigest(),
                    "publicPort": 28443,
                    "privatePort": 28088,
                    "tracePrefix": gate.JWKS_ROTATION_TRACE_PREFIX,
                },
                "rotation": {
                    "oldKid": "release-ac26-old",
                    "newKid": "release-ac26-new",
                    "terminalMode": "expiry",
                    "retainUntilEpochSeconds": 1_800_000_000,
                },
                "checks": {
                    "realOAuthIssuance": "PASS",
                    "activeAndRetiringJwks": "PASS",
                    "newCredentialUsesActiveKid": "PASS",
                    "oldCredentialWithinWindowMcp": "PASS",
                    "oldCredentialTerminalRejection": "PASS",
                    "newCredentialContinuity": "PASS",
                    "traceAuditCorrelation": "PASS",
                    "privateMaterialNotPersisted": "PASS",
                    "unknownKidRuntime": "NOT_COVERED",
                    "invalidActiveRuntime": "NOT_COVERED",
                },
                "evidence": {
                    "reportSha256": "1" * 64,
                    "runtimeIdentitySha256": "2" * 64,
                    "sourceSha256": {"scripts/rehearse_jwks_rotation.py": "3" * 64},
                },
            }
            artifact = (
                fixture.artifacts / "acceptance/v2-ac26-jwks-rotation-summary.json"
            )
            artifact.write_bytes(
                json.dumps(summary, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            artifact.chmod(0o600)
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item
                for item in source["suites"]["v2"]["results"]
                if item["id"] == "V2-AC-26"
            )["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.jwks_rotation_evidence, "validate_evidence", return_value=summary
            ) as validate:
                ledger = fixture.build(
                    candidate_validation_root=fixture.root,
                    jwks_rotation_evidence_path=report,
                    jwks_rotation_summary_artifact_path=artifact,
                    jwks_rotation_compose_project="web-starter-ac26-17-1",
                    jwks_rotation_terminal_mode="expiry",
                )

            self.assertEqual(report, validate.call_args.args[0])
            self.assertEqual(fixture.root.resolve(), validate.call_args.args[1])
            self.assertEqual(fixture.runtime_identity.resolve(), validate.call_args.args[2])
            expected = validate.call_args.kwargs
            self.assertEqual(COMMIT, expected["expected_candidate_commit"])
            self.assertEqual(VERSION, expected["expected_candidate_version"])
            self.assertEqual(TAG, expected["expected_candidate_tag"])
            self.assertEqual("web-starter-ac26-17-1", expected["expected_compose_project"])
            self.assertEqual(app_reference, expected["expected_app_reference"])
            self.assertEqual("sha256:" + "c" * 64, expected["expected_app_image_id"])
            self.assertEqual(nginx_reference, expected["expected_nginx_reference"])
            self.assertEqual("sha256:" + "d" * 64, expected["expected_nginx_image_id"])
            self.assertEqual(
                gate.JWKS_ROTATION_PUBLIC_ORIGIN, expected["expected_public_origin"]
            )
            self.assertEqual(
                gate.JWKS_ROTATION_PRIVATE_ORIGIN, expected["expected_private_origin"]
            )
            self.assertEqual(
                gate.JWKS_ROTATION_TRACE_PREFIX, expected["expected_trace_prefix"]
            )
            self.assertEqual("expiry", expected["expected_terminal_mode"])
            self.assertIs(True, expected["require_pass"])
            ac26 = next(
                item
                for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-26"
            )
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac26["evidenceTrust"])
            self.assertEqual("PASS", ledger["inputs"]["jwksRotationSummary"]["status"])

    def test_ac26_rejects_partial_noncanonical_mode_mismatch_or_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac26"
            private.mkdir(mode=0o700)
            report = private / "v2-ac26-jwks-rotation.json"
            write(report, "private-proof-placeholder\n")
            report.chmod(0o600)
            runtime = {
                "composeProject": "web-starter-ac26-17-1",
                "appReference": f"registry.example/app@{DIGESTS['app']}",
                "appImageId": "sha256:" + "c" * 64,
                "nginxReference": f"registry.example/nginx@{DIGESTS['nginx']}",
                "nginxImageId": "sha256:" + "d" * 64,
                "publicOriginSha256": hashlib.sha256(
                    gate.JWKS_ROTATION_PUBLIC_ORIGIN.encode()
                ).hexdigest(),
                "privateOriginSha256": hashlib.sha256(
                    gate.JWKS_ROTATION_PRIVATE_ORIGIN.encode()
                ).hexdigest(),
                "publicPort": 28443,
                "privatePort": 28088,
                "tracePrefix": gate.JWKS_ROTATION_TRACE_PREFIX,
            }
            summary = {
                "schemaVersion": 1,
                "acceptanceId": "V2-AC-26",
                "status": "PASS",
                "candidate": {"commit": COMMIT, "tag": TAG, "version": VERSION},
                "runtime": runtime,
                "rotation": {
                    "oldKid": "release-ac26-old",
                    "newKid": "release-ac26-new",
                    "terminalMode": "expiry",
                    "retainUntilEpochSeconds": 1_800_000_000,
                },
                "checks": {
                    "realOAuthIssuance": "PASS",
                    "activeAndRetiringJwks": "PASS",
                    "newCredentialUsesActiveKid": "PASS",
                    "oldCredentialWithinWindowMcp": "PASS",
                    "oldCredentialTerminalRejection": "PASS",
                    "newCredentialContinuity": "PASS",
                    "traceAuditCorrelation": "PASS",
                    "privateMaterialNotPersisted": "PASS",
                    "unknownKidRuntime": "NOT_COVERED",
                    "invalidActiveRuntime": "NOT_COVERED",
                },
                "evidence": {
                    "reportSha256": "1" * 64,
                    "runtimeIdentitySha256": "2" * 64,
                    "sourceSha256": {},
                },
            }
            artifact = (
                fixture.artifacts / "acceptance/v2-ac26-jwks-rotation-summary.json"
            )

            with self.assertRaisesRegex(gate.EvidenceError, "requires the private raw report"):
                fixture.build(jwks_rotation_evidence_path=report)

            write_json(artifact, {"schemaVersion": 1, "status": "PASS", "forged": True})
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.jwks_rotation_evidence, "validate_evidence", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "canonical summary differs"):
                fixture.build(
                    jwks_rotation_evidence_path=report,
                    jwks_rotation_summary_artifact_path=artifact,
                    jwks_rotation_compose_project="web-starter-ac26-17-1",
                    jwks_rotation_terminal_mode="expiry",
                )

            artifact.write_bytes(
                json.dumps(summary, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.jwks_rotation_evidence, "validate_evidence", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "mode or key binding differs"):
                fixture.build(
                    jwks_rotation_evidence_path=report,
                    jwks_rotation_summary_artifact_path=artifact,
                    jwks_rotation_compose_project="web-starter-ac26-17-1",
                    jwks_rotation_terminal_mode="revocation",
                )

            artifact.chmod(0o644)
            with mock.patch.object(
                gate.jwks_rotation_evidence, "validate_evidence", return_value=summary
            ), self.assertRaisesRegex(gate.EvidenceError, "mode 0600"):
                fixture.build(
                    jwks_rotation_evidence_path=report,
                    jwks_rotation_summary_artifact_path=artifact,
                    jwks_rotation_compose_project="web-starter-ac26-17-1",
                    jwks_rotation_terminal_mode="expiry",
                )

    def test_ac08_through_ac15_share_one_independently_recomputed_generator_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_root = Path(directory) / "private"
            private_root.mkdir(mode=0o700)
            fixture = EvidenceFixture(Path(directory) / "repository")
            bundle = private_root / "generator-bundle"
            bundle.mkdir(mode=0o700)
            forbidden_terms = private_root / "forbidden-terms.txt"
            write(forbidden_terms, "external-test-term\n")
            forbidden_terms.chmod(0o600)
            summary = {
                "schemaVersion": 1,
                "status": "PASS",
                "acceptanceIds": [f"V2-AC-{number:02d}" for number in range(8, 16)],
                "coverage": {
                    f"V2-AC-{number:02d}": "PASS" for number in range(8, 16)
                },
                "candidate": {"commit": COMMIT, "tag": TAG, "version": VERSION},
            }
            artifact = (
                fixture.artifacts
                / "acceptance/v2-generator-acceptance-summary.json"
            )
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(
                (
                    json.dumps(
                        summary,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )
            artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                result
                for result in source["suites"]["v1"]["results"]
                if result["id"] == "AC-42"
            )["status"] = "PASS"
            for result in source["suites"]["v2"]["results"]:
                if result["id"] in summary["acceptanceIds"]:
                    result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.generator_acceptance_evidence,
                "validate_bundle",
                return_value=summary,
            ) as validate:
                ledger = fixture.build(
                    generator_acceptance_bundle_path=bundle,
                    generator_forbidden_terms_path=forbidden_terms,
                    generator_acceptance_artifact_path=artifact,
                )

            validate.assert_called_once_with(
                bundle,
                repository_root=fixture.root.resolve(),
                forbidden_terms=forbidden_terms,
                require_pass=True,
            )
            self.assertEqual(
                "PASS", ledger["inputs"]["generatorAcceptanceSummary"]["status"]
            )
            results = {
                result["id"]: result
                for result in ledger["acceptance"]["v2"]["results"]
            }
            bound = ledger["inputs"]["generatorAcceptanceSummary"]
            reference = f"artifact://{bound['path']}#sha256={bound['sha256']}"
            for acceptance_id in summary["acceptanceIds"]:
                self.assertEqual(
                    "GATE_INDEPENDENTLY_VERIFIED",
                    results[acceptance_id]["evidenceTrust"],
                )
                self.assertIn(reference, results[acceptance_id]["evidence"])
            ac42 = next(
                result
                for result in ledger["acceptance"]["v1"]["results"]
                if result["id"] == "AC-42"
            )
            self.assertEqual("PASS", ac42["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac42["evidenceTrust"])
            self.assertIn(reference, ac42["evidence"])

    def test_generator_public_summary_must_be_canonical_mode_0600_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_root = Path(directory) / "private"
            private_root.mkdir(mode=0o700)
            fixture = EvidenceFixture(Path(directory) / "repository")
            bundle = private_root / "generator-bundle"
            bundle.mkdir(mode=0o700)
            forbidden_terms = private_root / "forbidden-terms.txt"
            write(forbidden_terms, "external-test-term\n")
            forbidden_terms.chmod(0o600)
            acceptance_ids = [f"V2-AC-{number:02d}" for number in range(8, 16)]
            summary = {
                "schemaVersion": 1,
                "status": "PASS",
                "acceptanceIds": acceptance_ids,
                "coverage": {acceptance_id: "PASS" for acceptance_id in acceptance_ids},
            }
            artifact = (
                fixture.artifacts
                / "acceptance/v2-generator-acceptance-summary.json"
            )
            write_json(artifact, summary)
            artifact.chmod(0o600)

            with mock.patch.object(
                gate.generator_acceptance_evidence,
                "validate_bundle",
                return_value=summary,
            ), self.assertRaisesRegex(gate.EvidenceError, "canonical summary differs"):
                gate._collect_generator_acceptance_evidence(
                    bundle_path=bundle,
                    forbidden_terms_path=forbidden_terms,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                )

            artifact.write_bytes(
                (
                    json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8")
            )
            artifact.chmod(0o644)
            with mock.patch.object(
                gate.generator_acceptance_evidence,
                "validate_bundle",
                return_value=summary,
            ), self.assertRaisesRegex(gate.EvidenceError, "mode 0600"):
                gate._collect_generator_acceptance_evidence(
                    bundle_path=bundle,
                    forbidden_terms_path=forbidden_terms,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                )

    def test_generator_gate_fails_closed_when_any_private_input_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            with self.assertRaisesRegex(
                gate.EvidenceError, "private raw bundle, external forbidden terms"
            ):
                gate._collect_generator_acceptance_evidence(
                    bundle_path=Path(directory) / "raw",
                    forbidden_terms_path=None,
                    artifact_path=None,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                )

    def test_generator_raw_inputs_must_remain_outside_both_repository_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            bundle = fixture.root / "untrusted-raw-bundle"
            bundle.mkdir()
            terms = Path(directory) / "forbidden-terms.txt"
            write(terms, "external-test-term\n")
            artifact = fixture.artifacts / "acceptance/generator-summary.json"
            write_json(artifact, {"status": "PASS"})
            artifact.chmod(0o600)
            with self.assertRaisesRegex(
                gate.EvidenceError, "outside both repository worktrees"
            ):
                gate._collect_generator_acceptance_evidence(
                    bundle_path=bundle,
                    forbidden_terms_path=terms,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    release_repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                )

    def test_ac29_pass_is_recomputed_against_the_runtime_app_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac29"
            private.mkdir(mode=0o700)
            evidence = private / "v2-ac29-production-fail-fast.json"
            write_json(evidence, {"acceptanceId": "V2-AC-29", "status": "PASS"})
            evidence.chmod(0o600)
            checksum = private / "v2-ac29-production-fail-fast.json.sha256"
            write(
                checksum,
                f"{gate._sha256(evidence)}  v2-ac29-production-fail-fast.json\n",
            )
            checksum.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/v2-ac29-production-fail-fast.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(evidence.read_bytes())
            runtime_raw = Path(directory) / "private-runtime-reports"
            runtime_raw.mkdir(mode=0o700)
            runtime_summary = release_runtime_test_reports_summary()
            runtime_artifact = (
                fixture.artifacts
                / "acceptance/release-runtime-test-reports-summary.json"
            )
            runtime_artifact.write_bytes(
                gate.release_runtime_test_reports.canonical_summary_bytes(
                    runtime_summary
                )
            )
            runtime_artifact.chmod(0o600)

            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item
                for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-29"
            )["status"] = "PASS"
            next(
                item
                for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-39"
            )["status"] = "PASS"
            result = next(
                item
                for item in source["suites"]["v2"]["results"]
                if item["id"] == "V2-AC-29"
            )
            result["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.production_fail_fast_evidence,
                "validate_evidence",
                return_value={
                    "acceptanceId": "V2-AC-29",
                    "status": "PASS",
                    "candidateHead": COMMIT,
                    "candidateTag": TAG,
                    "imageReference": json.loads(
                        fixture.runtime_identity.read_text(encoding="utf-8")
                    )["images"]["app"]["reference"],
                    "imageId": json.loads(
                        fixture.runtime_identity.read_text(encoding="utf-8")
                    )["images"]["app"]["imageId"],
                },
            ) as validate, mock.patch.object(
                gate.release_runtime_test_reports,
                "validate_proof",
                return_value=runtime_summary,
            ):
                ledger = fixture.build(
                    production_fail_fast_evidence_path=evidence,
                    production_fail_fast_artifact_path=artifact,
                    candidate_validation_root=fixture.root,
                    release_runtime_test_reports_directory_path=runtime_raw,
                    release_runtime_test_reports_summary_artifact_path=(
                        runtime_artifact
                    ),
                )

            expected_identity = json.loads(
                fixture.runtime_identity.read_text(encoding="utf-8")
            )["images"]["app"]
            self.assertEqual(
                expected_identity["reference"],
                validate.call_args.kwargs["expected_app_reference"],
            )
            self.assertEqual(
                expected_identity["imageId"],
                validate.call_args.kwargs["expected_app_image_id"],
            )
            ac29 = next(
                item
                for item in ledger["acceptance"]["v2"]["results"]
                if item["id"] == "V2-AC-29"
            )
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac29["evidenceTrust"])
            self.assertIn("productionFailFastRehearsal", ledger["inputs"])
            v1_ac29 = next(
                item
                for item in ledger["acceptance"]["v1"]["results"]
                if item["id"] == "AC-29"
            )
            self.assertEqual("PASS", v1_ac29["status"])
            self.assertEqual(
                "GATE_INDEPENDENTLY_VERIFIED", v1_ac29["evidenceTrust"]
            )
            self.assertEqual(
                {
                    "releaseRuntimeTestReports",
                    "productionFailFastRehearsal",
                    "runtimeVersionIdentity",
                    "releaseRuntimeAcceptance",
                },
                set(gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-29"]),
            )
            v1_ac39 = next(
                item
                for item in ledger["acceptance"]["v1"]["results"]
                if item["id"] == "AC-39"
            )
            self.assertEqual("PASS", v1_ac39["status"])
            self.assertEqual(
                "GATE_INDEPENDENTLY_VERIFIED", v1_ac39["evidenceTrust"]
            )
            self.assertEqual(
                {"unifiedVerify", "productionFailFastRehearsal"},
                set(gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS["AC-39"]),
            )
            for input_name in ("unifiedVerify", "productionFailFastRehearsal"):
                bound = ledger["inputs"][input_name]
                self.assertIn(
                    f"artifact://{bound['path']}#sha256={bound['sha256']}",
                    v1_ac39["evidence"],
                )

    def test_semantic_rehearsal_copy_cannot_differ_from_validated_original(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac41"
            private.mkdir(mode=0o700)
            evidence = private / "v2-ac41-redis-loss.json"
            write_json(evidence, {"status": "PASS"})
            evidence.chmod(0o600)
            artifact = fixture.artifacts / "acceptance/v2-ac41-redis-loss.json"
            write_json(artifact, {"status": "PASS", "forged": True})

            with mock.patch.object(
                gate.redis_loss_evidence,
                "validate_document_path",
                return_value={"status": "PASS"},
            ), self.assertRaisesRegex(gate.EvidenceError, "public artifact copy differs"):
                gate._collect_redis_loss_evidence(
                    evidence_path=evidence,
                    artifact_path=artifact,
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    runtime_images=json.loads(
                        fixture.runtime_identity.read_text(encoding="utf-8")
                    )["images"],
                )

    def test_every_non_pass_status_blocks_and_ac45_is_fail(self) -> None:
        for status in ("FAIL", "NOT_COVERED", "ENV_REQUIRED"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                fixture = EvidenceFixture(Path(directory))
                source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
                source["suites"]["v2"]["results"][0]["status"] = status
                write_json(fixture.acceptance, source)

                ledger = fixture.build()

                self.assertEqual("FAIL", ledger["gate"]["status"])
                self.assertIn(f"V2-AC-01 is {status}, not PASS", ledger["gate"]["errors"])
                ac45 = next(
                    result
                    for result in ledger["acceptance"]["v2"]["results"]
                    if result["id"] == "V2-AC-45"
                )
                self.assertEqual("FAIL", ac45["status"])

    def test_gate_owned_ac45_cannot_be_claimed_by_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            source["suites"]["v2"]["results"].append(fixture.result("V2-AC-45"))
            write_json(fixture.acceptance, source)

            with self.assertRaisesRegex(gate.EvidenceError, "gate-owned acceptance id"):
                fixture.build()

    def test_digest_sbom_and_security_gate_must_match_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            release_images = json.loads(fixture.release_images.read_text(encoding="utf-8"))
            release_images["images"][0]["digest"] = "sha256:" + "d" * 64
            write_json(fixture.release_images, release_images)
            with self.assertRaisesRegex(gate.EvidenceError, "reference is not digest-bound"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            summary = json.loads(fixture.security_summary.read_text(encoding="utf-8"))
            summary["status"] = "FAIL"
            write_json(fixture.security_summary, summary)
            with self.assertRaisesRegex(gate.EvidenceError, "not PASS"):
                fixture.build()

    def test_forged_security_summary_or_replaced_trivy_report_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            forged = {
                "schemaVersion": 1,
                "status": "PASS",
                "releaseVersion": VERSION,
                "gitCommit": COMMIT,
                "policyDate": NOW.date().isoformat(),
                "evaluatedAt": NOW.isoformat(),
                "errors": [],
            }
            write_json(fixture.security_summary, forged)

            with self.assertRaisesRegex(
                gate.EvidenceError, "does not match its SBOM, Trivy and exception inputs"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            report_path = fixture.artifacts / "raw/app-vulnerabilities.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["Results"] = [
                {
                    "Target": "layer",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-9999",
                            "PkgName": "tampered-library",
                            "InstalledVersion": "1.0",
                            "Severity": "CRITICAL",
                        }
                    ],
                }
            ]
            write_json(report_path, report)

            with self.assertRaisesRegex(
                gate.EvidenceError, "does not match its SBOM, Trivy and exception inputs"
            ):
                fixture.build()

    def test_security_policy_date_cannot_be_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            summary = json.loads(fixture.security_summary.read_text(encoding="utf-8"))
            summary["policyDate"] = "2026-07-18"
            summary["evaluatedAt"] = "2026-07-18T23:59:00+00:00"
            write_json(fixture.security_summary, summary)

            with self.assertRaisesRegex(gate.EvidenceError, "must match the release gate UTC date"):
                fixture.build()

    def test_compose_policy_and_deployment_inputs_are_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            model = json.loads(fixture.production_compose.read_text(encoding="utf-8"))
            model["services"]["app"]["image"] = "registry.example/other@" + DIGESTS["app"]
            write_json(fixture.production_compose, model)
            compose_policy._write_summary(fixture.production_policy, fixture.production_compose, [])
            with self.assertRaisesRegex(gate.EvidenceError, "does not use the scanned release digest"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            summary = json.loads(fixture.production_policy.read_text(encoding="utf-8"))
            summary["composeSha256"] = "f" * 64
            write_json(fixture.production_policy, summary)
            with self.assertRaisesRegex(gate.EvidenceError, "checksum-drifted"):
                fixture.build()

        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            write(
                fixture.deployment_images,
                fixture.deployment_images.read_text(encoding="utf-8").replace(
                    DIGESTS["nginx"], "sha256:" + "f" * 64
                ),
            )
            with self.assertRaisesRegex(gate.EvidenceError, "not exactly bound"):
                fixture.build()

    def test_independent_verification_detects_bound_file_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            gate._write_json(fixture.manifest, fixture.build())
            write(fixture.root / "web-starter-admin/src/main/resources/db/migration/V2__seed.sql", "changed;\n")

            with self.assertRaisesRegex(gate.EvidenceError, "does not match its bound source evidence"):
                gate.verify_ledger(
                    manifest_path=fixture.manifest,
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    tag=TAG,
                    version=VERSION,
                    commit=COMMIT,
                    verify_git=False,
                )

    def test_release_identity_must_be_v_tag_version_and_commit_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            with self.assertRaisesRegex(gate.EvidenceError, "without its v prefix"):
                gate.build_ledger(
                    repository_root=fixture.root,
                    artifacts_root=fixture.artifacts,
                    acceptance_source_path=fixture.acceptance,
                    release_images_path=fixture.release_images,
                    security_summary_path=fixture.security_summary,
                    production_compose_path=fixture.production_compose,
                    production_policy_path=fixture.production_policy,
                    deployment_images_path=fixture.deployment_images,
                    runtime_identity_path=fixture.runtime_identity,
                    runtime_acceptance_path=fixture.runtime_acceptance,
                    tag=TAG,
                    version="2.0.1",
                    commit=COMMIT,
                    evaluated_at=NOW,
                    verify_git=False,
                )

    def test_acceptance_input_cannot_claim_a_self_referential_git_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            source["release"]["gitCommit"] = COMMIT
            write_json(fixture.acceptance, source)

            with self.assertRaisesRegex(
                gate.EvidenceError, "acceptance evidence release fields are not exact"
            ):
                fixture.build()

    def test_snapshot_or_frontend_version_drift_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            write_json(
                fixture.root / "web-starter-web/package.json",
                {"name": "web-starter-web", "version": "2.0.0-SNAPSHOT"},
            )

            with self.assertRaisesRegex(gate.EvidenceError, "without SNAPSHOT"):
                fixture.build()

    def test_schemas_are_json_and_enumerate_only_supported_statuses(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        for name in ("release-acceptance-input.schema.json", "release-evidence.schema.json"):
            schema = json.loads((repository_root / "security" / name).read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertIn("$defs", schema)
            self.assertEqual(
                {"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"},
                set(schema["$defs"]["result"]["properties"]["status"]["enum"]),
            )
        acceptance_schema = json.loads(
            (repository_root / "security/release-acceptance-input.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual({"tag", "version"}, set(acceptance_schema["$defs"]["release"]["required"]))
        self.assertNotIn("gitCommit", acceptance_schema["$defs"]["release"]["properties"])
        self.assertTrue(acceptance_schema["$defs"]["result"]["properties"]["evidence"]["uniqueItems"])
        evidence_pattern = acceptance_schema["$defs"]["result"]["properties"]["evidence"][
            "items"
        ]["pattern"]
        self.assertNotIn("external", evidence_pattern)
        registered_pass_ids = set(
            acceptance_schema["$defs"]["result"]["allOf"][0]["then"]["properties"][
                "id"
            ]["enum"]
        )
        self.assertEqual(
            set(gate.INDEPENDENTLY_VERIFIED_ACCEPTANCE_BINDINGS), registered_pass_ids
        )
        release_schema = json.loads(
            (repository_root / "security/release-evidence.schema.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            "generatorAcceptanceSummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "mcpToolContractSummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "jwksRotationSummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "v1SourceProvenanceSummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "releaseRuntimeTestReports",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "mcpGovernanceRuntimeSummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "observabilitySummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "toolingLifecycleSummary",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "ac40DependencySeedProvenance",
            release_schema["properties"]["inputs"]["properties"],
        )
        self.assertIn(
            "ac40DependencySeedProvenance",
            release_schema["properties"]["inputs"]["required"],
        )
        self.assertEqual(
            {"$ref": "#/$defs/securityGateFile"},
            release_schema["properties"]["inputs"]["properties"][
                "ac40DependencySeedProvenance"
            ],
        )
        self.assertTrue(release_schema["$defs"]["result"]["properties"]["evidence"]["uniqueItems"])
        self.assertEqual(
            {
                "CONTENT_HASH_VERIFIED",
                "GATE_INDEPENDENTLY_VERIFIED",
                "GATE_DERIVED",
            },
            set(
                release_schema["$defs"]["result"]["properties"]["evidenceTrust"][
                    "enum"
                ]
            ),
        )

    def test_ac40_dependency_seed_provenance_cli_and_workflow_wiring_are_mandatory(
        self,
    ) -> None:
        common = [
            "--repository-root", ".",
            "--artifacts-root", "artifacts",
            "--tag", TAG,
            "--version", VERSION,
            "--commit", COMMIT,
        ]
        build_arguments = [
            "build", *common,
            "--acceptance-results", "acceptance.json",
            "--release-images", "images.json",
            "--security-summary", "security.json",
            "--production-compose", "compose.json",
            "--production-policy", "policy.json",
            "--deployment-images", "images.env",
            "--runtime-identity", "identity.json",
            "--runtime-acceptance", "runtime.json",
            "--output", "release-evidence.json",
        ]
        verify_arguments = [
            "verify", *common,
            "--manifest", "release-evidence.json",
        ]
        for command in (build_arguments, verify_arguments):
            errors = io.StringIO()
            with self.subTest(command=command[0]), contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as raised:
                    gate.main(command)
            self.assertEqual(2, raised.exception.code)
            for option in (
                "--ac40-dependency-seed",
                "--expected-ac40-dependency-seed-sha256",
                "--ac40-dependency-seed-provenance",
            ):
                self.assertIn(option, errors.getvalue())

        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "AC40_SEED_PROVENANCE: ${{ steps.ac40_seed.outputs.provenance_receipt }}",
            workflow,
        )
        build_call = workflow.split(
            "python3 -B scripts/release_evidence_gate.py build", 1
        )[1].split("python3 -B scripts/release_evidence_gate.py verify", 1)[0]
        verify_call = workflow.split(
            "python3 -B scripts/release_evidence_gate.py verify", 1
        )[1].split("\n      - name:", 1)[0]
        for call in (build_call, verify_call):
            with self.subTest(call="build" if call is build_call else "verify"):
                self.assertIn(
                    '--ac40-dependency-seed "${AC40_DEPENDENCY_SEED}"',
                    call,
                )
                self.assertIn(
                    '--expected-ac40-dependency-seed-sha256 "${AC40_DEPENDENCY_SEED_SHA256}"',
                    call,
                )
                self.assertIn(
                    '--ac40-dependency-seed-provenance "${GITHUB_WORKSPACE}/${AC40_SEED_PROVENANCE}"',
                    call,
                )
        self.assertIn(
            "AC40_DEPENDENCY_SEED: ${{ steps.ac40_seed.outputs.path }}",
            workflow,
        )
        self.assertIn(
            "AC40_DEPENDENCY_SEED_SHA256: ${{ steps.release_environment.outputs.seed_sha256 }}",
            workflow,
        )
        self.assertEqual(2, workflow.count("--ac40-dependency-seed-provenance"))
        self.assertEqual(3, workflow.count("--ac40-dependency-seed \""))
        self.assertEqual(
            3,
            workflow.count("--expected-ac40-dependency-seed-sha256 \""),
        )

    def test_release_workflow_keeps_generator_raw_inputs_private_and_gate_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        required_tokens = (
            "secrets.WEB_STARTER_FORBIDDEN_TERMS",
            "vars.WEB_STARTER_MYSQL_IMAGE",
            "vars.WEB_STARTER_REDIS_IMAGE",
            "vars.WEB_STARTER_REGISTRY_IMAGE",
            '"${CANDIDATE_VALIDATION_ROOT}/scripts/rehearse_generator_acceptance.py"',
            '"${CANDIDATE_VALIDATION_ROOT}/scripts/validate_generator_acceptance_evidence.py"',
            '--output "${GENERATOR_ACCEPTANCE_BUNDLE}"',
            'os.O_WRONLY | os.O_CREAT | os.O_EXCL',
            "--generator-acceptance-bundle",
            "--generator-forbidden-terms",
            "--generator-acceptance-artifact",
            "artifacts/acceptance/v2-generator-acceptance-summary.json",
        )
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, workflow)
        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/v2-generator-acceptance-summary.json",
            upload_block,
        )
        for private_name in (
            "generator_acceptance_bundle",
            "generator_forbidden_terms",
            "generator_summary_dir",
        ):
            self.assertNotIn(private_name, upload_block)

    def test_ac01_workflow_keeps_raw_history_observation_private_and_gate_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        for token in (
            "Produce and independently validate frozen V1 source provenance",
            '"${CANDIDATE_VALIDATION_ROOT}/scripts/create_v1_source_provenance_proof.py"',
            '"${CANDIDATE_VALIDATION_ROOT}/scripts/validate_v1_source_provenance_proof.py"',
            "--v1-source-provenance-proof",
            "--v1-source-provenance-summary-artifact",
            "artifacts/acceptance/v2-ac01-v1-source-provenance-summary.json",
        ):
            with self.subTest(token=token):
                self.assertIn(token, workflow)
        self.assertGreaterEqual(workflow.count("--v1-source-provenance-proof"), 2)
        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/v2-ac01-v1-source-provenance-summary.json",
            upload_block,
        )
        self.assertNotIn("steps.recovery.outputs.v1_source", upload_block)
        self.assertNotIn("v2-ac01-v1-source-provenance.json\n", upload_block)

    def test_ac15_recomputes_transport_parity_and_binds_canonical_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory) / "repository")
            private = Path(directory) / "private-ac15"
            private.mkdir(mode=0o700)
            proof = private / gate.project_transport_parity_proof.PROOF_FILE
            write(proof, "private-proof-placeholder\n")
            proof.chmod(0o600)
            summary = {
                "schemaVersion": 1,
                "acceptanceId": "AC-15",
                "status": "PASS",
                "candidate": {
                    "commit": COMMIT,
                    "tree": "d" * 40,
                    "version": VERSION,
                    "tag": TAG,
                },
            }
            artifact = (
                fixture.artifacts
                / "acceptance/v1-ac15-project-transport-parity-summary.json"
            )
            artifact.write_bytes(
                gate.project_transport_parity_proof.canonical_summary_bytes(summary)
            )
            artifact.chmod(0o600)
            source = json.loads(fixture.acceptance.read_text(encoding="utf-8"))
            next(
                item for item in source["suites"]["v1"]["results"]
                if item["id"] == "AC-15"
            )["status"] = "PASS"
            write_json(fixture.acceptance, source)

            with mock.patch.object(
                gate.project_transport_parity_proof,
                "validate_proof",
                return_value=summary,
            ):
                ledger = fixture.build(
                    project_transport_parity_proof_path=proof,
                    project_transport_parity_summary_artifact_path=artifact,
                )
            ac15 = next(
                result for result in ledger["acceptance"]["v1"]["results"]
                if result["id"] == "AC-15"
            )
            bound = ledger["inputs"]["v1ProjectTransportParitySummary"]
            self.assertEqual("PASS", ac15["status"])
            self.assertEqual("GATE_INDEPENDENTLY_VERIFIED", ac15["evidenceTrust"])
            self.assertIn(
                f"artifact://{bound['path']}#sha256={bound['sha256']}",
                ac15["evidence"],
            )

            artifact.write_bytes(b"{}\n")
            artifact.chmod(0o600)
            with mock.patch.object(
                gate.project_transport_parity_proof,
                "validate_proof",
                return_value=summary,
            ), self.assertRaisesRegex(
                gate.EvidenceError, "canonical summary differs"
            ):
                fixture.build(
                    project_transport_parity_proof_path=proof,
                    project_transport_parity_summary_artifact_path=artifact,
                )

    def test_ac15_workflow_keeps_raw_proof_private_and_gate_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        for token in (
            "Produce and independently validate V1 AC-15 transport parity",
            "ProjectTransportParityIT#provesRestAndMcpShareProjectServiceWithoutProjectPersistenceDependency",
            "-Dsurefire.useFile=false",
            '"${CANDIDATE_VALIDATION_ROOT}/scripts/create_project_transport_parity_proof.py"',
            '"${CANDIDATE_VALIDATION_ROOT}/scripts/validate_project_transport_parity_proof.py"',
            "--project-transport-parity-proof",
            "--project-transport-parity-summary-artifact",
            "artifacts/acceptance/v1-ac15-project-transport-parity-summary.json",
        ):
            with self.subTest(token=token):
                self.assertIn(token, workflow)
        self.assertGreaterEqual(
            workflow.count("--project-transport-parity-proof"), 2
        )
        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/v1-ac15-project-transport-parity-summary.json",
            upload_block,
        )
        self.assertNotIn("project_transport_proof_dir", upload_block)
        self.assertNotIn("project-transport-parity-proof.properties", upload_block)

    def test_ac01_producer_validator_and_schema_are_release_policy_sources(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for relative in (
            "scripts/create_v1_source_provenance_proof.py",
            "scripts/validate_v1_source_provenance_proof.py",
            "security/v2-ac01-v1-source-provenance-summary.schema.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)
        for relative in (
            "scripts/create_project_transport_parity_proof.py",
            "scripts/validate_project_transport_parity_proof.py",
            "security/v1-ac15-project-transport-parity-summary.schema.json",
            "web-starter-admin/src/test/java/dev/webstarter/admin/acceptance/ProjectTransportParityIT.java",
            ".github/workflows/build-ac40-dependency-seed.yml",
            "scripts/build_v1_upgrade_dependency_seed.py",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)

    def test_release_runtime_reports_workflow_is_formal_private_and_gate_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")

        def assert_wiring(document: str) -> None:
            required = (
                'WEB_STARTER_RUN_RELEASE_RUNTIME_TEST_REPORTS_FORMAL: "true"',
                "WEB_STARTER_RELEASE_RUNTIME_TEST_REPORTS_DIR: ${{ steps.recovery.outputs.release_runtime_test_reports_dir }}",
                "--release-runtime-test-reports-directory",
                "--release-runtime-test-reports-summary-artifact",
                "artifacts/acceptance/release-runtime-test-reports-summary.json",
            )
            for token in required:
                self.assertIn(token, document)
            self.assertGreaterEqual(
                document.count("--release-runtime-test-reports-directory"), 2
            )

        assert_wiring(workflow)
        with self.assertRaises(AssertionError):
            assert_wiring(
                workflow.replace(
                    "--release-runtime-test-reports-directory",
                    "--removed-private-runtime-reports-directory",
                )
            )

        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/release-runtime-test-reports-summary.json",
            upload_block,
        )
        self.assertNotIn("release_runtime_test_reports_dir", upload_block)
        for raw_name in (
            "playwright-release-runtime.json",
            "TEST-dev.webstarter.mcp.acceptance.McpSdkRuntimeIT.xml",
            "TEST-dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT.xml",
            "release-runtime-test-reports-proof.json",
        ):
            self.assertNotIn(raw_name, upload_block)

        install = workflow.index("pnpm install --frozen-lockfile --offline")
        clean = workflow.index(
            'git -C "${candidate_validation_root}" status --porcelain=v1 --untracked-files=all',
            install,
        )
        runtime = workflow.index(
            "Run immutable-image empty-volume full-stack acceptance", clean
        )
        self.assertLess(install, clean)
        self.assertLess(clean, runtime)
        self.assertIn(
            '"${candidate_validation_root}/web-starter-web/node_modules/.bin/playwright" --version',
            workflow[install:runtime],
        )

    def test_release_runtime_reports_adapter_sources_are_release_policy_bound(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for relative in (
            "scripts/create_release_runtime_test_reports_proof.py",
            "scripts/validate_release_runtime_test_reports_proof.py",
            "security/release-runtime-test-reports-summary.schema.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)

    def test_mcp_governance_workflow_is_formal_private_gate_bound_and_cleaned(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        required = (
            'mcp_governance_proof_dir="${RUNNER_TEMP}/web-starter-mcp-governance-proof-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            "WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL: \"true\"",
            "WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR: ${{ steps.recovery.outputs.mcp_governance_proof_dir }}",
            "WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT: web-starter-governance-${{ github.run_id }}-${{ github.run_attempt }}",
            "--mcp-governance-proof",
            "--mcp-governance-summary-artifact artifacts/acceptance/mcp-governance-runtime-summary.json",
            "--mcp-governance-compose-project",
            "Remove the exact private MCP governance proof directory",
            "shutil.rmtree(target)",
            "artifacts/acceptance/mcp-governance-runtime-summary.json",
        )
        for token in required:
            with self.subTest(token=token):
                self.assertIn(token, workflow)
        self.assertGreaterEqual(workflow.count("--mcp-governance-proof"), 2)
        self.assertGreaterEqual(workflow.count("--mcp-governance-compose-project"), 2)

        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/mcp-governance-runtime-summary.json",
            upload_block,
        )
        for private_name in (
            "mcp_governance_proof_dir",
            "mcp-governance-runtime-proof.properties",
            "mcp-governance-restart-receipt.json",
            gate.mcp_governance_proof.MAIN_REPORT,
            gate.mcp_governance_proof.SHUTDOWN_REPORT,
        ):
            self.assertNotIn(private_name, upload_block)
        cleanup = workflow.index("Remove the exact private MCP governance proof directory")
        checksum = workflow.index("Checksum safe release evidence")
        upload = workflow.index("Upload SBOM and sanitised release evidence")
        self.assertLess(cleanup, checksum)
        self.assertLess(checksum, upload)

    def test_mcp_governance_sources_are_release_policy_bound(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for relative in (
            "scripts/acceptance_network.py",
            "scripts/generated_module_plan.py",
            "scripts/prepare_mcp_governance_runtime.py",
            "scripts/v1_upgrade_refresh.py",
            "scripts/run_mcp_governance_runtime_acceptance.sh",
            "scripts/create_mcp_governance_runtime_proof.py",
            "scripts/validate_mcp_governance_runtime_proof.py",
            "scripts/orchestrate_mcp_governance_restart.py",
            "security/v2-ac34-ac35-mcp-governance-summary.schema.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)

    def test_generator_producer_validator_and_schema_are_release_policy_sources(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for relative in (
            "scripts/rehearse_generator_acceptance.py",
            "scripts/validate_generator_acceptance_evidence.py",
            "security/v2-generator-acceptance.schema.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)

    def test_ac33_workflow_keeps_raw_and_token_material_private_and_gate_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        required_tokens = (
            'WEB_STARTER_RUN_MCP_TOOL_CONTRACT_FORMAL: "true"',
            "WEB_STARTER_MCP_TOOL_CONTRACT_PROOF_DIR",
            "--mcp-tool-contract-proof",
            "--mcp-tool-contract-summary-artifact",
            "artifacts/acceptance/mcp-tool-contract-runtime-proof-summary.json",
        )
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, workflow)
        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/mcp-tool-contract-runtime-proof-summary.json",
            upload_block,
        )
        self.assertNotIn("mcp_tool_contract_proof_dir", upload_block)
        self.assertNotIn("mcp_tool_contract_proof", upload_block)
        self.assertNotIn("pat-crud.json", upload_block)

    def test_ac33_producer_validator_and_schema_are_release_policy_sources(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for relative in (
            "scripts/create_mcp_tool_contract_runtime_proof.py",
            "scripts/validate_mcp_tool_contract_runtime_proof.py",
            "security/v2-ac33-mcp-tool-contract-summary.schema.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)

    def test_ac26_workflow_keeps_raw_keys_and_credentials_private_and_gate_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (
            repository_root / ".github/workflows/release-supply-chain.yml"
        ).read_text(encoding="utf-8")
        for token in (
            'WEB_STARTER_RUN_AC26_FORMAL: "true"',
            "WEB_STARTER_AC26_EVIDENCE_DIR",
            "WEB_STARTER_AC26_COMPOSE_PROJECT: web-starter-ac26-",
            "WEB_STARTER_AC26_TERMINAL_MODE: expiry",
            "--jwks-rotation-evidence",
            "--jwks-rotation-summary-artifact",
            "--jwks-rotation-compose-project",
            "--jwks-rotation-terminal-mode",
            "artifacts/acceptance/v2-ac26-jwks-rotation-summary.json",
        ):
            with self.subTest(token=token):
                self.assertIn(token, workflow)
        upload_block = workflow.split(
            "- name: Upload SBOM and sanitised release evidence", 1
        )[1]
        self.assertIn(
            "artifacts/acceptance/v2-ac26-jwks-rotation-summary.json",
            upload_block,
        )
        self.assertNotIn("steps.recovery.outputs.ac26", upload_block)
        self.assertNotIn("v2-ac26-jwks-rotation.json\n", upload_block)
        self.assertNotIn("oauth-jwk", upload_block)
        self.assertNotIn("ac26-credentials", upload_block)

    def test_ac26_producer_validator_and_schema_are_release_policy_sources(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for relative in (
            "scripts/acceptance_jwk_set.py",
            "scripts/rehearse_jwks_rotation.py",
            "scripts/validate_jwks_rotation_evidence.py",
            "security/v2-ac26-jwks-rotation.schema.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(f'repository_root / "{relative}"', source)

    def test_repository_baselines_and_flyway_inventory_are_parseable(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        baselines = gate._load_baselines(repository_root)
        flyway = gate._collect_flyway(repository_root)

        self.assertEqual(42, len(baselines["v1"]["rows"]))
        self.assertEqual(45, len(baselines["v2"]["rows"]))
        self.assertEqual("P0", baselines["v2"]["rows"]["V2-AC-45"])
        self.assertGreaterEqual(len(flyway["migrations"]), 1)
        self.assertEqual(flyway["migrations"][-1]["version"], flyway["latestVersion"])

    def test_flyway_rejects_unversioned_or_nested_sql(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migration = root / "web-starter-admin/src/main/resources/db/migration"
            write(migration / "V1__core.sql", "select 1;\n")
            write(migration / "R__mutable_view.sql", "select 2;\n")

            with self.assertRaisesRegex(gate.EvidenceError, "unversioned Flyway SQL"):
                gate._collect_flyway(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migration = root / "web-starter-admin/src/main/resources/db/migration"
            write(migration / "V1__core.sql", "select 1;\n")
            write(migration / "nested/V2__hidden.sql", "select 2;\n")

            with self.assertRaisesRegex(gate.EvidenceError, "top-level versioned migration"):
                gate._collect_flyway(root)

    def test_release_commit_inventory_detects_deleted_migration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Release Test"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "release-test@example.invalid"],
                check=True,
            )
            migration = root / "web-starter-admin/src/main/resources/db/migration"
            write(migration / "V1__core.sql", "select 1;\n")
            write(migration / "V2__second.sql", "select 2;\n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "release"], check=True)
            commit = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (migration / "V2__second.sql").unlink()
            flyway = gate._collect_flyway(root)

            with self.assertRaisesRegex(gate.EvidenceError, "differs from the release commit"):
                gate._verify_migration_inventory_binding(root, commit, flyway)

    def test_frozen_migration_bytes_cannot_be_changed_in_a_later_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Release Test"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "release-test@example.invalid"],
                check=True,
            )
            migration = root / "web-starter-admin/src/main/resources/db/migration"
            expected: set[str] = set()
            for number in range(1, 4):
                path = migration / f"V{number}__migration_{number}.sql"
                write(path, f"select {number};\n")
                expected.add(path.relative_to(root).as_posix())
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "v1"], check=True)
            baseline_commit = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            write(migration / "V2__migration_2.sql", "select 200;\n")
            flyway = gate._collect_flyway(root)

            with self.assertRaisesRegex(gate.EvidenceError, "migration bytes changed"):
                gate._verify_historical_migration_bytes(
                    root, baseline_commit, expected, flyway
                )

    def test_release_scratch_and_tag_evidence_are_outside_git_and_image_contexts(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        gitignore = set(
            (repository_root / ".gitignore").read_text(encoding="utf-8").splitlines()
        )
        dockerignore = set(
            (repository_root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        )

        self.assertTrue({"/artifacts/", "/.release-tools/"}.issubset(gitignore))
        self.assertTrue(
            {"artifacts", ".release-tools", "release/evidence"}.issubset(dockerignore)
        )

    def test_release_workflow_gates_before_immutable_promotion_and_upload(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (repository_root / ".github/workflows/release-supply-chain.yml").read_text(
            encoding="utf-8"
        )
        security = workflow.index("Enforce Critical, High-exception and secret policy")
        compose = workflow.index("Expand and enforce the actual production Compose model")
        runtime = workflow.index("Run immutable-image empty-volume full-stack acceptance")
        evidence = workflow.index("Build and verify complete release evidence")
        immutable = workflow.index("Resolve release image tags without overwrite")
        promotion = workflow.index("Promote scanned digests to release tags")
        upload = workflow.index("Upload SBOM and sanitised release evidence")
        self.assertLess(security, evidence)
        self.assertLess(security, compose)
        self.assertLess(compose, evidence)
        self.assertLess(compose, runtime)
        self.assertLess(runtime, evidence)
        self.assertLess(evidence, upload)
        self.assertLess(upload, immutable)
        self.assertLess(immutable, promotion)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn('release/evidence/${RELEASE_TAG}.json', workflow)
        self.assertIn("artifacts/release-evidence.json", workflow)
        self.assertIn("artifacts/production-compose.json", workflow)
        self.assertIn("artifacts/production-compose-policy.json", workflow)
        self.assertIn("--production-compose artifacts/production-compose.json", workflow)
        self.assertIn("--runtime-acceptance artifacts/release-runtime-acceptance.json", workflow)
        self.assertIn("--runtime-identity artifacts/runtime-version-identity.json", workflow)
        self.assertIn("scripts/run_release_runtime_acceptance.sh", workflow)
        self.assertIn("--production-policy artifacts/production-compose-policy.json", workflow)
        self.assertIn("--deployment-images artifacts/deployment-images.env", workflow)
        self.assertIn("steps.app.outputs.digest", workflow[compose:evidence])
        self.assertIn("steps.nginx.outputs.digest", workflow[compose:evidence])
        self.assertIn(
            'backend_jar="web-starter-admin/target/web-starter-admin-${RELEASE_VERSION}.jar"',
            workflow,
        )
        self.assertIn(
            '--ignore-file "${GITHUB_WORKSPACE}/security/trivy-release.ignore"', workflow
        )
        self.assertEqual(4, workflow.count("scan_release_image "))
        self.assertIn("scripts/release_trivy.py", workflow)
        self.assertNotIn(".release-tools/trivy image", workflow)
        self.assertIn("test ! -L security/trivy-release.ignore", workflow)
        self.assertIn("test ! -s security/trivy-release.ignore", workflow)
        self.assertEqual(0, (repository_root / "security/trivy-release.ignore").stat().st_size)
        self.assertIn("release tag state is unknown because registry inspection failed", workflow)
        self.assertNotIn("manifest unknown|not found|no such manifest", workflow)
        self.assertIn("manifest unknown|no such manifest", workflow)
        self.assertIn("refusing to overwrite a release tag bound to another digest", workflow)
        self.assertIn("promoted release tag does not resolve to the scanned digest", workflow)
        self.assertIn("inputs.version || github.ref_name", workflow)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", workflow)
        self.assertNotIn("context: .", workflow)
        self.assertIn('git archive --format=tar "${GITHUB_SHA}"', workflow)
        self.assertEqual(2, workflow.count("context: ${{ steps.release_context.outputs.path }}"))

    def test_runtime_acceptance_runner_and_gate_use_the_same_check_contract(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        runner = (repository_root / "scripts/run_release_runtime_acceptance.sh").read_text(
            encoding="utf-8"
        )
        marker = '    "checks": {'
        self.assertEqual(1, runner.count(marker))
        checks_block = runner.split(marker, 1)[1].split("\n    },\n}", 1)[0]
        emitted_checks = set(
            re.findall(r'^        "([A-Za-z][A-Za-z0-9]+)": "PASS",?$', checks_block, re.MULTILINE)
        )
        self.assertEqual(gate.RUNTIME_CHECKS, emitted_checks)


if __name__ == "__main__":
    unittest.main()
