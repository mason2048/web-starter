from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import re
import tempfile
import unittest

import release_security_gate as gate


DIGESTS = {
    "app": "sha256:" + ("a" * 64),
    "nginx": "sha256:" + ("b" * 64),
}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def sbom(component_name: str, digest: str | None = None) -> dict:
    component = {
        "type": "container" if digest else "application",
        "name": component_name,
        "version": digest or "2.0.0",
    }
    if digest:
        component["bom-ref"] = f"pkg:oci/{component_name}@{digest}"
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


def trivy_result(kind: str, findings: list[object]) -> dict:
    field = "Vulnerabilities" if kind == "vuln" else "Secrets"
    return {
        "Target": "sha256:layer",
        "Class": "os-pkgs" if kind == "vuln" else "secret",
        "Type": "alpine" if kind == "vuln" else "secret",
        field: findings,
    }


class Evidence:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest = root / "manifest.json"
        self.exceptions = root / "exceptions.json"
        write_json(root / "backend.cdx.json", sbom("backend"))
        write_json(root / "frontend.cdx.json", sbom("frontend"))
        images = []
        for name, digest in DIGESTS.items():
            reference = f"registry.example/{name}@{digest}"
            write_json(root / f"{name}.cdx.json", sbom(name, digest))
            write_json(
                root / f"{name}-vuln.json",
                trivy_report(reference),
            )
            write_json(
                root / f"{name}-secret.json",
                trivy_report(reference),
            )
            images.append(
                {
                    "name": name,
                    "reference": reference,
                    "digest": digest,
                    "sbom": f"{name}.cdx.json",
                    "vulnerabilityReport": f"{name}-vuln.json",
                    "secretReport": f"{name}-secret.json",
                }
            )
        write_json(
            self.manifest,
            {
                "schemaVersion": 1,
                "releaseVersion": "v2.0.0",
                "gitCommit": "c" * 40,
                "sboms": {"backend": "backend.cdx.json", "frontend": "frontend.cdx.json"},
                "images": images,
            },
        )
        write_json(self.exceptions, {"schemaVersion": 1, "exceptions": []})

    def report(self, image: str, kind: str) -> dict:
        return json.loads((self.root / f"{image}-{kind}.json").read_text(encoding="utf-8"))

    def write_report(self, image: str, kind: str, value: dict) -> None:
        write_json(self.root / f"{image}-{kind}.json", value)


class ReleaseSecurityGateTest(unittest.TestCase):
    def test_workflows_and_build_inputs_use_immutable_trust_roots(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/release-supply-chain.yml",
        ):
            workflow = (repository_root / relative).read_text(encoding="utf-8")
            action_refs = re.findall(r"\buses:\s*[^\s@]+@([^\s#]+)", workflow)
            self.assertTrue(action_refs, relative)
            self.assertTrue(
                all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs),
                f"{relative} contains a mutable or malformed action ref: {action_refs}",
            )

        for relative in ("Dockerfile", "deploy/nginx/Dockerfile"):
            dockerfile = (repository_root / relative).read_text(encoding="utf-8")
            base_images = re.findall(r"^FROM\s+(\S+)", dockerfile, flags=re.MULTILINE)
            self.assertTrue(base_images, relative)
            self.assertTrue(
                all(re.search(r"@sha256:[0-9a-f]{64}$", image) for image in base_images),
                f"{relative} contains an unpinned base image: {base_images}",
            )

        wrapper = (
            repository_root / ".mvn/wrapper/maven-wrapper.properties"
        ).read_text(encoding="utf-8")
        self.assertRegex(wrapper, r"(?m)^distributionSha256Sum=[0-9a-f]{64}$")

        dependabot = (repository_root / ".github/dependabot.yml").read_text(encoding="utf-8")
        self.assertEqual(2, dependabot.count("package-ecosystem: docker"))

    def test_release_workflow_scans_digest_before_tag_promotion(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        workflow = (repository_root / ".github/workflows/release-supply-chain.yml").read_text(
            encoding="utf-8"
        )

        gate_position = workflow.index("Enforce Critical, High-exception and secret policy")
        promotion_position = workflow.index("Promote scanned digests to release tags")
        upload_position = workflow.index("Upload SBOM and sanitised release evidence")
        upload_section = workflow[upload_position:]

        self.assertLess(gate_position, promotion_position)
        self.assertIn('app_reference="${APP_IMAGE}@${APP_DIGEST}"', workflow)
        self.assertIn('nginx_reference="${NGINX_IMAGE}@${NGINX_DIGEST}"', workflow)
        self.assertGreaterEqual(workflow.count("sbom: true"), 2)
        self.assertIn("scripts/release_trivy.py", workflow)
        self.assertIn("--config \"${GITHUB_WORKSPACE}/security/trivy-release.yaml\"", workflow)
        self.assertIn(
            "--secret-config \"${GITHUB_WORKSPACE}/security/trivy-secret-release.yaml\"",
            workflow,
        )
        self.assertIn("--work-root \"${trivy_work_root}\"", workflow)
        self.assertIn('scan_release_image vuln "${APP_REFERENCE}"', workflow)
        self.assertIn('scan_release_image secret "${NGINX_REFERENCE}"', workflow)
        self.assertNotIn(".release-tools/trivy image", workflow)
        self.assertIn("SYFT_CHECKSUMS_SHA256", workflow)
        self.assertIn("TRIVY_CHECKSUMS_SHA256", workflow)
        self.assertNotIn("app-secrets.json", upload_section)
        self.assertNotIn("nginx-secrets.json", upload_section)

    def test_clean_digest_bound_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))

            summary, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertEqual([], errors)
            self.assertEqual("PASS", summary["status"])
            self.assertEqual(1, summary["backendSbomComponents"])
            self.assertRegex(summary["backendSbomSha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(2, len(summary["images"]))
            self.assertTrue(
                all(
                    re.fullmatch(r"[0-9a-f]{64}", image["vulnerabilityReportSha256"])
                    for image in summary["images"]
                )
            )

    def test_summary_hashes_change_when_a_clean_report_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            before, errors = gate.evaluate(
                evidence.manifest, evidence.exceptions, date(2026, 7, 19)
            )
            self.assertEqual([], errors)
            report = evidence.report("app", "vuln")
            report["Metadata"]["tamperMarker"] = "replacement"
            evidence.write_report("app", "vuln", report)

            after, errors = gate.evaluate(
                evidence.manifest, evidence.exceptions, date(2026, 7, 19)
            )

            self.assertEqual([], errors)
            before_app = next(image for image in before["images"] if image["name"] == "app")
            after_app = next(image for image in after["images"] if image["name"] == "app")
            self.assertNotEqual(
                before_app["vulnerabilityReportSha256"],
                after_app["vulnerabilityReportSha256"],
            )

    def test_manifest_evidence_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            report = evidence.root / "app-vuln.json"
            report.unlink()
            report.symlink_to(evidence.root / "nginx-vuln.json")

            summary, errors = gate.evaluate(
                evidence.manifest, evidence.exceptions, date(2026, 7, 19)
            )

            self.assertEqual("FAIL", summary["status"])
            self.assertTrue(any("vulnerability report is missing or invalid" in error for error in errors))

    def test_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            report = evidence.report("app", "vuln")
            report["ArtifactName"] = "registry.example/app@sha256:" + ("d" * 64)
            evidence.write_report("app", "vuln", report)

            _, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("not bound" in error for error in errors))

    def test_image_manifest_requires_a_repository_digest_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            manifest = json.loads(evidence.manifest.read_text(encoding="utf-8"))
            manifest["images"][0]["reference"] = "@" + DIGESTS["app"]
            write_json(evidence.manifest, manifest)

            summary, errors = gate.evaluate(
                evidence.manifest, evidence.exceptions, date(2026, 7, 19)
            )

            self.assertEqual("FAIL", summary["status"])
            self.assertTrue(any("reference is not bound" in error for error in errors), errors)

    def test_critical_is_unconditionally_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            report = evidence.report("app", "vuln")
            report["Results"] = [
                trivy_result(
                    "vuln",
                    [
                        {
                            "VulnerabilityID": "CVE-2099-0001",
                            "PkgName": "critical-lib",
                            "InstalledVersion": "1.0",
                            "Severity": "CRITICAL",
                        }
                    ],
                )
            ]
            evidence.write_report("app", "vuln", report)

            summary, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("Critical" in error for error in errors))
            app = next(image for image in summary["images"] if image["name"] == "app")
            self.assertEqual(1, app["criticalVulnerabilities"])

    def test_high_requires_exact_accountable_unexpired_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            report = evidence.report("app", "vuln")
            report["Results"] = [
                trivy_result(
                    "vuln",
                    [
                        {
                            "VulnerabilityID": "CVE-2099-0002",
                            "PkgName": "high-lib",
                            "InstalledVersion": "2.3.4",
                            "Severity": "HIGH",
                        }
                    ],
                )
            ]
            evidence.write_report("app", "vuln", report)

            _, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))
            self.assertTrue(any("lack a current exact exception" in error for error in errors))

            write_json(
                evidence.exceptions,
                {
                    "schemaVersion": 1,
                    "exceptions": [
                        {
                            "id": "app-cve-2099-0002",
                            "image": "app",
                            "vulnerabilityId": "CVE-2099-0002",
                            "packageName": "high-lib",
                            "installedVersion": "2.3.4",
                            "owner": "platform-security",
                            "expiresOn": "2026-08-01",
                            "reason": "Vendor patch is scheduled in the current maintenance window.",
                        }
                    ],
                },
            )

            summary, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertEqual([], errors)
            app = next(image for image in summary["images"] if image["name"] == "app")
            self.assertEqual(["app-cve-2099-0002"], app["approvedHighExceptions"])

    def test_expired_or_unused_exception_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            write_json(
                evidence.exceptions,
                {
                    "schemaVersion": 1,
                    "exceptions": [
                        {
                            "id": "stale-cve-2099-0003",
                            "image": "nginx",
                            "vulnerabilityId": "CVE-2099-0003",
                            "packageName": "stale-lib",
                            "installedVersion": "1.0",
                            "owner": "platform-security",
                            "expiresOn": "2026-07-18",
                            "reason": "This stale decision must be rejected by the release policy.",
                        }
                    ],
                },
            )

            _, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("expired" in error for error in errors))
            self.assertTrue(any("unused or stale" in error for error in errors))

    def test_secret_blocks_without_copying_match_material_to_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            secret_material = "sensitive-material-must-not-escape"
            report = evidence.report("nginx", "secret")
            report["Results"] = [
                trivy_result(
                    "secret",
                    [
                        {
                            "RuleID": "private-key",
                            "Severity": "CRITICAL",
                            "Match": secret_material,
                            "Code": {"Lines": [{"Content": secret_material}]},
                        }
                    ],
                )
            ]
            evidence.write_report("nginx", "secret", report)

            summary, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("secret finding" in error for error in errors))
            self.assertNotIn(secret_material, json.dumps(summary))

    def test_empty_or_digest_unbound_sbom_is_not_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            write_json(evidence.root / "app.cdx.json", sbom("app", "sha256:" + ("d" * 64)))

            _, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("SBOM metadata is not bound" in error for error in errors))

    def test_digest_hidden_in_unrelated_sbom_metadata_does_not_bind_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            fake = sbom("app")
            fake["metadata"]["component"]["properties"] = [
                {"name": "untrusted", "value": DIGESTS["app"]}
            ]
            write_json(evidence.root / "app.cdx.json", fake)

            _, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("component is not a container" in error for error in errors))

    def test_oci_sbom_identity_with_another_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory))
            fake = sbom("app", DIGESTS["app"])
            fake["metadata"]["component"]["bom-ref"] = "pkg:oci/app@sha256:" + ("d" * 64)
            write_json(evidence.root / "app.cdx.json", fake)

            _, errors = gate.evaluate(evidence.manifest, evidence.exceptions, date(2026, 7, 19))

            self.assertTrue(any("bom-ref names a different digest" in error for error in errors))

    def test_malformed_vulnerability_report_shapes_fail_closed(self) -> None:
        cases = (
            ("results-not-array", "not-an-array", "lacks scanner results"),
            ("result-not-object", ["not-an-object"], "result #1 must be an object"),
            (
                "result-fields-missing",
                [{"Vulnerabilities": []}],
                "lacks required fields: Target,Class,Type",
            ),
            (
                "findings-null",
                [{"Target": "layer", "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": None}],
                "Vulnerabilities must be an array",
            ),
            (
                "finding-not-object",
                [trivy_result("vuln", ["not-an-object"])],
                "Vulnerabilities #1 must be an object",
            ),
            (
                "finding-fields-missing",
                [trivy_result("vuln", [{"VulnerabilityID": "CVE-2099-1"}])],
                "lacks required fields: PkgName,InstalledVersion,Severity",
            ),
            (
                "severity-unknown",
                [
                    trivy_result(
                        "vuln",
                        [
                            {
                                "VulnerabilityID": "CVE-2099-1",
                                "PkgName": "library",
                                "InstalledVersion": "1.0",
                                "Severity": "URGENT",
                            }
                        ],
                    )
                ],
                "unsupported severity",
            ),
        )
        for label, results, expected_error in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                evidence = Evidence(Path(directory))
                report = evidence.report("app", "vuln")
                report["Results"] = results
                evidence.write_report("app", "vuln", report)

                summary, errors = gate.evaluate(
                    evidence.manifest, evidence.exceptions, date(2026, 7, 19)
                )

                self.assertEqual("FAIL", summary["status"])
                self.assertTrue(any(expected_error in error for error in errors), errors)

    def test_trivy_top_level_schema_drift_fails_closed(self) -> None:
        cases = (
            ("schema-version", "SchemaVersion", 3, "not a supported Trivy JSON document"),
            ("artifact-type", "ArtifactType", "filesystem", "does not describe a container image"),
            ("metadata", "Metadata", [], "lacks image metadata"),
        )
        for label, field, value, expected_error in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                evidence = Evidence(Path(directory))
                report = evidence.report("app", "vuln")
                report[field] = value
                evidence.write_report("app", "vuln", report)

                summary, errors = gate.evaluate(
                    evidence.manifest, evidence.exceptions, date(2026, 7, 19)
                )

                self.assertEqual("FAIL", summary["status"])
                self.assertTrue(any(expected_error in error for error in errors), errors)

    def test_malformed_secret_report_shapes_fail_closed(self) -> None:
        cases = (
            (
                "findings-null",
                [{"Target": "layer", "Class": "secret", "Type": "secret", "Secrets": None}],
                "Secrets must be an array",
            ),
            (
                "finding-not-object",
                [trivy_result("secret", ["not-an-object"])],
                "Secrets #1 must be an object",
            ),
            (
                "finding-fields-missing",
                [trivy_result("secret", [{"RuleID": "private-key"}])],
                "lacks required fields: Severity",
            ),
            (
                "wrong-scanner-field",
                [
                    {
                        "Target": "layer",
                        "Class": "secret",
                        "Type": "secret",
                        "Vulnerabilities": [],
                    }
                ],
                "wrong scanner",
            ),
        )
        for label, results, expected_error in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                evidence = Evidence(Path(directory))
                report = evidence.report("nginx", "secret")
                report["Results"] = results
                evidence.write_report("nginx", "secret", report)

                summary, errors = gate.evaluate(
                    evidence.manifest, evidence.exceptions, date(2026, 7, 19)
                )

                self.assertEqual("FAIL", summary["status"])
                self.assertTrue(any(expected_error in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
