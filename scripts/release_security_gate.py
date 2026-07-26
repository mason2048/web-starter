#!/usr/bin/env python3
"""Evaluate digest-bound image scans and CycloneDX SBOM release evidence.

Critical vulnerabilities and every secret finding are unconditionally blocking.
High vulnerabilities require an exact, current exception with an accountable
owner and expiry date. Output is deliberately sanitised and never copies secret
matches, source snippets, tokens, or scanner descriptions.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
PLACEHOLDER = re.compile(r"(?:example|placeholder|replace|unknown|nobody|todo|tbd)", re.I)
TRIVY_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass(frozen=True)
class HighFinding:
    image: str
    vulnerability_id: str
    package_name: str
    installed_version: str

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.image,
            self.vulnerability_id,
            self.package_name,
            self.installed_version,
        )


@dataclass(frozen=True)
class HighException:
    exception_id: str
    image: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    owner: str
    expires_on: date
    reason: str

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.image,
            self.vulnerability_id,
            self.package_name,
            self.installed_version,
        )


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _manifest_path(manifest_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("manifest evidence path must be a non-empty string")
    root = manifest_path.parent.resolve()
    candidate = root / value
    if candidate.is_symlink():
        raise ValueError("manifest evidence path must not be a symbolic link")
    resolved = candidate.resolve()
    if not _inside(resolved, root):
        raise ValueError("manifest evidence path escapes its artifact directory")
    if not resolved.is_file():
        raise ValueError("manifest evidence path is not a regular file")
    return resolved


def _validate_sbom(path: Path, expected_digest: str | None = None) -> int:
    document = _load_json(path)
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not CycloneDX JSON")
    if not re.fullmatch(r"1\.[4-7]", str(document.get("specVersion", ""))):
        raise ValueError("SBOM uses an unsupported CycloneDX specification")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("SBOM contains no components")
    if expected_digest is not None:
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("image SBOM lacks metadata")
        component = metadata.get("component")
        if not isinstance(component, dict):
            raise ValueError("image SBOM lacks its metadata component")
        if component.get("type") != "container":
            raise ValueError("image SBOM metadata component is not a container")
        if not isinstance(component.get("name"), str) or not component["name"].strip():
            raise ValueError("image SBOM metadata component lacks a name")
        if component.get("version") != expected_digest:
            raise ValueError("image SBOM metadata is not bound to the expected digest")
        for field in ("purl", "bom-ref"):
            identity = component.get(field)
            if isinstance(identity, str) and identity.startswith("pkg:oci/"):
                if "@" + expected_digest not in identity:
                    raise ValueError(f"image SBOM metadata {field} names a different digest")
    return len(components)


def _parse_exceptions(document: Any, as_of: date) -> tuple[list[HighException], list[str]]:
    errors: list[str] = []
    exceptions: list[HighException] = []
    if not isinstance(document, dict) or document.get("schemaVersion") != 1:
        return [], ["High exception file must use schemaVersion 1"]
    raw_entries = document.get("exceptions")
    if not isinstance(raw_entries, list):
        return [], ["High exception file must contain an exceptions array"]

    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str, str, str]] = set()
    for index, raw in enumerate(raw_entries, start=1):
        label = f"High exception #{index}"
        if not isinstance(raw, dict):
            errors.append(f"{label} must be an object")
            continue
        required = (
            "id",
            "image",
            "vulnerabilityId",
            "packageName",
            "installedVersion",
            "owner",
            "expiresOn",
            "reason",
        )
        missing = [field for field in required if not isinstance(raw.get(field), str) or not raw[field].strip()]
        if missing:
            errors.append(f"{label} lacks required fields: {','.join(missing)}")
            continue
        try:
            expires_on = date.fromisoformat(raw["expiresOn"])
        except ValueError:
            errors.append(f"{label} expiresOn must be an ISO calendar date")
            continue
        entry = HighException(
            exception_id=raw["id"].strip(),
            image=raw["image"].strip(),
            vulnerability_id=raw["vulnerabilityId"].strip(),
            package_name=raw["packageName"].strip(),
            installed_version=raw["installedVersion"].strip(),
            owner=raw["owner"].strip(),
            expires_on=expires_on,
            reason=raw["reason"].strip(),
        )
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", entry.exception_id):
            errors.append(f"{label} id is not a stable policy identifier")
        if entry.exception_id in seen_ids:
            errors.append(f"{label} duplicates exception id")
        if entry.key() in seen_keys:
            errors.append(f"{label} duplicates an existing finding scope")
        if len(entry.owner) < 3 or PLACEHOLDER.search(entry.owner):
            errors.append(f"{label} owner is not accountable")
        if len(entry.reason) < 20 or PLACEHOLDER.search(entry.reason):
            errors.append(f"{label} reason is not a substantive risk decision")
        if entry.expires_on < as_of:
            errors.append(f"{label} expired before this release")
        seen_ids.add(entry.exception_id)
        seen_keys.add(entry.key())
        exceptions.append(entry)
    return exceptions, errors


def _required_text(document: dict[str, Any], field: str) -> bool:
    return isinstance(document.get(field), str) and bool(document[field].strip())


def _validate_report_binding(report: Any, reference: str, digest: str, kind: str) -> list[str]:
    if not isinstance(report, dict):
        return [f"{kind} report must be a JSON object"]
    errors: list[str] = []
    if report.get("SchemaVersion") != 2:
        errors.append(f"{kind} report is not a supported Trivy JSON document")
    artifact_name = report.get("ArtifactName")
    if not isinstance(artifact_name, str) or not artifact_name.endswith("@" + digest):
        errors.append(f"{kind} report is not bound to the expected image digest")
    else:
        expected_repository = reference.rsplit("@", 1)[0]
        actual_repository = artifact_name.rsplit("@", 1)[0]
        if expected_repository != actual_repository:
            errors.append(f"{kind} report names a different image repository")
    if report.get("ArtifactType") != "container_image":
        errors.append(f"{kind} report does not describe a container image")
    if not isinstance(report.get("Metadata"), dict):
        errors.append(f"{kind} report lacks image metadata")

    results = report.get("Results")
    if not isinstance(results, list):
        errors.append(f"{kind} report lacks scanner results")
        return errors

    finding_field = "Vulnerabilities" if kind == "vulnerability" else "Secrets"
    forbidden_field = "Secrets" if kind == "vulnerability" else "Vulnerabilities"
    required_finding_fields = (
        ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")
        if kind == "vulnerability"
        else ("RuleID", "Severity")
    )
    for result_index, result in enumerate(results, start=1):
        label = f"{kind} report result #{result_index}"
        if not isinstance(result, dict):
            errors.append(f"{label} must be an object")
            continue
        missing_result_fields = [
            field for field in ("Target", "Class", "Type") if not _required_text(result, field)
        ]
        if missing_result_fields:
            errors.append(f"{label} lacks required fields: {','.join(missing_result_fields)}")
        if forbidden_field in result:
            errors.append(f"{label} contains findings from the wrong scanner")
        if finding_field not in result:
            continue
        findings = result[finding_field]
        if not isinstance(findings, list):
            errors.append(f"{label} {finding_field} must be an array when present")
            continue
        for finding_index, finding in enumerate(findings, start=1):
            finding_label = f"{label} {finding_field} #{finding_index}"
            if not isinstance(finding, dict):
                errors.append(f"{finding_label} must be an object")
                continue
            missing_finding_fields = [
                field for field in required_finding_fields if not _required_text(finding, field)
            ]
            if missing_finding_fields:
                errors.append(
                    f"{finding_label} lacks required fields: {','.join(missing_finding_fields)}"
                )
                continue
            severity = finding["Severity"].strip().upper()
            if severity not in TRIVY_SEVERITIES:
                errors.append(f"{finding_label} uses an unsupported severity")
    return errors


def _vulnerability_findings(report: dict[str, Any], image: str) -> tuple[int, set[HighFinding]]:
    critical = 0
    high: set[HighFinding] = set()
    for result in report["Results"]:
        vulnerabilities = result.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities:
            severity = vulnerability["Severity"].strip().upper()
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high.add(
                    HighFinding(
                        image=image,
                        vulnerability_id=vulnerability["VulnerabilityID"].strip(),
                        package_name=vulnerability["PkgName"].strip(),
                        installed_version=vulnerability["InstalledVersion"].strip(),
                    )
                )
    return critical, high


def _secret_count(report: dict[str, Any]) -> int:
    count = 0
    for result in report["Results"]:
        count += len(result.get("Secrets", []))
    return count


def evaluate(
    manifest_path: Path,
    exceptions_path: Path,
    as_of: date,
    evaluated_at: datetime | None = None,
) -> tuple[dict[str, Any], list[str]]:
    observation_time = evaluated_at or datetime.now(timezone.utc).replace(microsecond=0)
    if observation_time.tzinfo is None:
        raise ValueError("release security evaluation time must include a timezone")
    errors: list[str] = []
    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "FAIL",
        "evaluatedAt": observation_time.isoformat(),
        "policyDate": as_of.isoformat(),
        "images": [],
    }
    try:
        manifest = _load_json(manifest_path)
    except (OSError, json.JSONDecodeError):
        return summary, ["release image manifest is missing or invalid JSON"]
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        return summary, ["release image manifest must use schemaVersion 1"]

    commit = str(manifest.get("gitCommit", ""))
    version = str(manifest.get("releaseVersion", ""))
    summary["gitCommit"] = commit
    summary["releaseVersion"] = version
    if not COMMIT.fullmatch(commit):
        errors.append("release manifest Git commit is invalid")
    if not VERSION.fullmatch(version):
        errors.append("release manifest version is not a semantic release version")

    try:
        exception_document = _load_json(exceptions_path)
        summary["highExceptionPolicySha256"] = hashlib.sha256(
            exceptions_path.read_bytes()
        ).hexdigest()
    except (OSError, json.JSONDecodeError):
        exception_document = None
        errors.append("High exception file is missing or invalid JSON")
    exceptions, exception_errors = _parse_exceptions(exception_document, as_of)
    errors.extend(exception_errors)
    exceptions_by_key = {entry.key(): entry for entry in exceptions}
    used_exception_ids: set[str] = set()

    sboms = manifest.get("sboms", {})
    if not isinstance(sboms, dict):
        errors.append("release manifest lacks backend/frontend SBOM paths")
    else:
        for name in ("backend", "frontend"):
            try:
                sbom_path = _manifest_path(manifest_path, sboms.get(name))
                count = _validate_sbom(sbom_path)
                summary[f"{name}SbomComponents"] = count
                summary[f"{name}SbomSha256"] = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
            except (OSError, json.JSONDecodeError, ValueError) as exception:
                errors.append(f"{name} SBOM failed validation: {exception}")

    images = manifest.get("images")
    if not isinstance(images, list) or not images:
        errors.append("release manifest must contain image evidence")
        images = []
    seen_names: set[str] = set()
    for raw_image in images:
        if not isinstance(raw_image, dict):
            errors.append("release image entry must be an object")
            continue
        name = str(raw_image.get("name", ""))
        reference = str(raw_image.get("reference", ""))
        digest = str(raw_image.get("digest", ""))
        image_summary: dict[str, Any] = {
            "name": name,
            "reference": reference,
            "digest": digest,
            "criticalVulnerabilities": 0,
            "highVulnerabilities": 0,
            "approvedHighExceptions": [],
            "secretFindings": 0,
        }
        summary["images"].append(image_summary)
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", name) or name in seen_names:
            errors.append("release image names must be unique stable identifiers")
        seen_names.add(name)
        if (
            not DIGEST.fullmatch(digest)
            or not IMAGE_REFERENCE.fullmatch(reference)
            or reference.rsplit("@", 1)[1] != digest
        ):
            errors.append(f"{name or 'image'}: reference is not bound to its sha256 digest")
            continue

        try:
            image_sbom_path = _manifest_path(manifest_path, raw_image.get("sbom"))
            sbom_count = _validate_sbom(
                image_sbom_path,
                expected_digest=digest,
            )
            image_summary["sbomComponents"] = sbom_count
            image_summary["sbomSha256"] = hashlib.sha256(image_sbom_path.read_bytes()).hexdigest()
        except (OSError, json.JSONDecodeError, ValueError) as exception:
            errors.append(f"{name}: image SBOM failed validation: {exception}")

        reports: dict[str, dict[str, Any]] = {}
        for kind, field in (("vulnerability", "vulnerabilityReport"), ("secret", "secretReport")):
            try:
                report_path = _manifest_path(manifest_path, raw_image.get(field))
                report = _load_json(report_path)
            except (OSError, json.JSONDecodeError, ValueError):
                errors.append(f"{name}: {kind} report is missing or invalid")
                continue
            binding_errors = _validate_report_binding(report, reference, digest, kind)
            errors.extend(f"{name}: {error}" for error in binding_errors)
            if not binding_errors:
                reports[kind] = report
                image_summary[f"{kind}ReportSha256"] = hashlib.sha256(
                    report_path.read_bytes()
                ).hexdigest()

        vulnerability_report = reports.get("vulnerability")
        if vulnerability_report is not None:
            critical, high = _vulnerability_findings(vulnerability_report, name)
            image_summary["criticalVulnerabilities"] = critical
            image_summary["highVulnerabilities"] = len(high)
            if critical:
                errors.append(f"{name}: {critical} Critical vulnerability finding(s) block release")
            missing_high = 0
            for finding in high:
                exception = exceptions_by_key.get(finding.key())
                if exception is None:
                    missing_high += 1
                else:
                    used_exception_ids.add(exception.exception_id)
                    image_summary["approvedHighExceptions"].append(exception.exception_id)
            image_summary["approvedHighExceptions"].sort()
            if missing_high:
                errors.append(f"{name}: {missing_high} High vulnerability finding(s) lack a current exact exception")

        secret_report = reports.get("secret")
        if secret_report is not None:
            secret_count = _secret_count(secret_report)
            image_summary["secretFindings"] = secret_count
            if secret_count:
                errors.append(f"{name}: {secret_count} secret finding(s) block release")

    missing_images = sorted({"app", "nginx"} - seen_names)
    if missing_images:
        errors.append(f"release manifest lacks final image evidence: {','.join(missing_images)}")

    unused = sorted(entry.exception_id for entry in exceptions if entry.exception_id not in used_exception_ids)
    if unused:
        errors.append(f"High exception file contains {len(unused)} unused or stale entry/entries")
    summary["errors"] = errors
    summary["status"] = "PASS" if not errors else "FAIL"
    return summary, errors


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--as-of", type=date.fromisoformat, default=datetime.now(timezone.utc).date())
    args = parser.parse_args(argv)

    summary, errors = evaluate(args.manifest.resolve(), args.exceptions.resolve(), args.as_of)
    _write_json(args.output.resolve(), summary)
    if errors:
        for error in errors:
            print(f"FAIL release-security-gate: {error}")
        return 1
    print("PASS release-security-gate: digest-bound SBOM, secret and vulnerability policies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
