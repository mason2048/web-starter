#!/usr/bin/env python3
"""Independently validate V2 credential-lifecycle runtime evidence.

The validator never imports the producer and never contacts the runtime. It
recomputes PASS from the sanitized observations, binds them to a clean annotated
release candidate and separately generated runtime/OAuth identity documents,
then emits one canonical public summary.
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
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


REPORT_NAME = "v2-credential-lifecycle-runtime.json"
SUMMARY_NAME = "v2-credential-lifecycle-runtime-summary.json"
TOOL_PATH = "scripts/rehearse_credential_lifecycle.py"
VALIDATOR_PATH = "scripts/validate_credential_lifecycle_evidence.py"
SCHEMA_PATH = "security/v2-credential-lifecycle-runtime-summary.schema.json"
SOURCE_PATHS = (
    TOOL_PATH,
    VALIDATOR_PATH,
    "scripts/verify_oauth_runtime.py",
    SCHEMA_PATH,
    "deploy/nginx/external-mcp.conf",
    "web-starter-system/src/main/java/dev/webstarter/system/service/UserService.java",
    "web-starter-system/src/main/java/dev/webstarter/system/service/impl/UserServiceImpl.java",
    "web-starter-security/src/main/java/dev/webstarter/security/web/AccountSecurityController.java",
    "web-starter-security/src/main/java/dev/webstarter/security/session/IdentitySecurityLifecycleAdapter.java",
    "web-starter-security/src/main/java/dev/webstarter/security/token/CredentialPepperKeyRing.java",
    "web-starter-security/src/main/java/dev/webstarter/security/token/AccessCredentialService.java",
    "web-starter-security/src/main/java/dev/webstarter/security/oauth/OAuthClientManagementService.java",
    "web-starter-security/src/main/java/dev/webstarter/security/oauth/OAuthClientSecretPasswordEncoder.java",
    "web-starter-admin/src/main/resources/db/migration/V7__add_credential_rotation.sql",
    "web-starter-web/src/views/security/AccountSecurityView.vue",
)

ACCEPTANCE_IDS = ["V2-AC-24", "V2-AC-27", "V2-AC-28", "V2-AC-36"]
ACTIONS = ["password-reset", "subject-disable", "subject-remove", "security-logout"]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
TRACE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
DIGEST_REFERENCE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
MAX_REPORT = 2 * 1024 * 1024
MAX_IDENTITY = 512 * 1024


class EvidenceError(ValueError):
    """Raised when evidence is missing, unsafe, stale or semantically incomplete."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_payload(path: Path, maximum: int, label: str) -> bytes:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise EvidenceError(f"{label} must be a real regular file")
    metadata = requested.stat()
    if (
        metadata.st_size <= 0
        or metadata.st_size > maximum
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise EvidenceError(f"{label} must be an owned mode-0600 bounded file")
    return requested.read_bytes()


def _json_payload(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    payload = _private_payload(path, maximum, label)
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is not valid unique-key UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must contain one JSON object")
    return value, payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"JSON repeats field {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be an array")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise EvidenceError(f"{label} has unexpected or missing fields")


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(f"{label} is not ISO-8601") from error
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must contain a timezone")
    parsed = parsed.astimezone(timezone.utc)
    if parsed > datetime.now(timezone.utc).replace(microsecond=0):
        raise EvidenceError(f"{label} is in the future")
    return parsed


def _git(root: Path, arguments: Sequence[str], maximum: int = 8 * 1024 * 1024) -> bytes:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name, None)
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C", "LANG": "C"})
    completed = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *arguments], cwd=root,
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > maximum or len(completed.stderr) > 64 * 1024:
        raise EvidenceError("candidate Git inspection failed safely")
    return completed.stdout


def _candidate(root: Path, tag: str, version: str, commit: str) -> dict[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise EvidenceError("candidate root must be a real directory")
    root = root.resolve(strict=True)
    if VERSION.fullmatch(version) is None or tag != "v" + version or COMMIT.fullmatch(commit) is None:
        raise EvidenceError("reported candidate release identity is invalid")
    if _git(root, ["status", "--porcelain=v1", "--untracked-files=all"]).strip():
        raise EvidenceError("formal credential-lifecycle candidate must be clean")
    head = _git(root, ["rev-parse", "HEAD"]).decode().strip()
    tree = _git(root, ["rev-parse", "HEAD^{tree}"]).decode().strip()
    tag_type = _git(root, ["cat-file", "-t", f"refs/tags/{tag}"]).decode().strip()
    tag_commit = _git(root, ["rev-list", "-n", "1", tag]).decode().strip()
    tag_object = _git(root, ["rev-parse", f"refs/tags/{tag}"]).decode().strip()
    if head != commit or tag_commit != commit or tag_type != "tag" or not COMMIT.fullmatch(tree):
        raise EvidenceError("candidate annotated tag, commit or tree binding differs")
    root_pom = (root / "pom.xml").read_text(encoding="utf-8")
    frontend = json.loads((root / "web-starter-web/package.json").read_text(encoding="utf-8"))
    if f"<version>{version}</version>" not in root_pom or frontend.get("version") != version:
        raise EvidenceError("candidate Maven and frontend versions do not match the release")
    return {"releaseTag": tag, "releaseVersion": version, "gitCommit": commit,
            "gitTree": tree, "tagObject": tag_object}


def _validate_report(
    report: dict[str, Any],
    report_payload: bytes,
    candidate_root: Path,
    runtime_identity: dict[str, Any],
    runtime_identity_sha: str,
    oauth_report: dict[str, Any],
    oauth_report_sha: str,
    compose_project: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    _exact(report, {
        "schemaVersion", "acceptanceIds", "status", "observedAt", "candidate", "runtime",
        "cascadeInvalidation", "pepperRotation", "clientSecretRotation",
        "clientCredentialsLifecycle", "serviceAccountLifecycle", "personalTokenLifecycle",
        "securityRegression", "secretHandling", "sources",
    }, "credential lifecycle report")
    if report.get("schemaVersion") != 1 or report.get("acceptanceIds") != ACCEPTANCE_IDS or report.get("status") != "PASS":
        raise EvidenceError("credential lifecycle report is not exact PASS")
    _timestamp(report.get("observedAt"), "credential lifecycle observedAt")
    candidate = _object(report.get("candidate"), "credential lifecycle candidate")
    _exact(candidate, {"releaseTag", "releaseVersion", "gitCommit", "appImageReference", "nginxImageReference"},
           "credential lifecycle candidate")
    binding = _candidate(
        candidate_root, str(candidate.get("releaseTag", "")), str(candidate.get("releaseVersion", "")),
        str(candidate.get("gitCommit", "")),
    )
    for name in ("appImageReference", "nginxImageReference"):
        if not isinstance(candidate.get(name), str) or DIGEST_REFERENCE.fullmatch(candidate[name]) is None:
            raise EvidenceError("credential lifecycle image binding is not immutable")
    if runtime_identity.get("status") != "PASS":
        raise EvidenceError("separate runtime identity is not PASS")
    images = _object(runtime_identity.get("images"), "runtime identity images")
    if (
        candidate["appImageReference"] != _object(images.get("app"), "runtime app image").get("reference")
        or candidate["nginxImageReference"] != _object(images.get("nginx"), "runtime Nginx image").get("reference")
    ):
        raise EvidenceError("credential lifecycle images differ from runtime identity")

    runtime = _object(report.get("runtime"), "credential lifecycle runtime")
    _exact(runtime, {"composeProject", "privateOrigin", "privateMcpOrigin", "publicOrigin",
                     "runtimeIdentitySha256", "oauthRuntimeReportSha256"}, "credential lifecycle runtime")
    if PROJECT.fullmatch(compose_project) is None or runtime.get("composeProject") != compose_project:
        raise EvidenceError("credential lifecycle Compose project binding differs")
    if runtime.get("runtimeIdentitySha256") != runtime_identity_sha or runtime.get("oauthRuntimeReportSha256") != oauth_report_sha:
        raise EvidenceError("credential lifecycle prerequisite evidence digests differ")
    if (
        urlparse(str(runtime.get("publicOrigin", ""))).scheme != "https"
        or urlparse(str(runtime.get("privateOrigin", ""))).scheme not in {"http", "https"}
        or urlparse(str(runtime.get("privateMcpOrigin", ""))).scheme not in {"http", "https"}
    ):
        raise EvidenceError("credential lifecycle runtime origins are invalid")
    oauth_checks = _object(oauth_report.get("checks"), "OAuth runtime checks")
    if oauth_report.get("status") != "PASS" or any(
        oauth_checks.get(name) != "PASS"
        for name in (
            "oauthMetadataConsistency", "dynamicClientRegistrationDisabled",
            "wwwAuthenticate", "clientCredentials",
            "clientCredentialsShortLived", "oauthPublicMcp", "patPrivateMcp",
            "patPublicRejected", "invalidOriginRejected",
        )
    ):
        raise EvidenceError("credential lifecycle OAuth negative prerequisites are incomplete")

    cascade = _object(report.get("cascadeInvalidation"), "cascade invalidation")
    _exact(cascade, {"cases"}, "cascade invalidation")
    cases = _list(cascade.get("cases"), "cascade invalidation cases")
    if len(cases) != len(ACTIONS):
        raise EvidenceError("cascade invalidation must contain four exact actions")
    traces: set[str] = set()
    for expected_action, value in zip(ACTIONS, cases):
        case = _object(value, f"cascade {expected_action}")
        _exact(case, {
            "action", "traceId", "oauthGrantType", "pkceMethod",
            "oauthAccessExpiresInSeconds", "oauthBeforeHttpStatus",
            "sessionNextHttpStatus", "oauthAccessNextHttpStatus",
            "oauthRefreshNextHttpStatus", "oauthRefreshError", "patNextHttpStatus",
            "operationAuditObserved", "fixtureCleanupTraceId",
            "fixtureReadAfterCleanupHttpStatus", "fixtureCleanupAuditObserved",
        }, f"cascade {expected_action}")
        trace = case.get("traceId")
        cleanup_trace = case.get("fixtureCleanupTraceId")
        expires_in = case.get("oauthAccessExpiresInSeconds")
        if (
            case.get("action") != expected_action
            or not isinstance(trace, str) or TRACE.fullmatch(trace) is None or trace in traces
            or not isinstance(cleanup_trace, str)
            or TRACE.fullmatch(cleanup_trace) is None
            or cleanup_trace != (
                trace if expected_action == "subject-remove" else trace + "-cleanup"
            )
            or case.get("oauthGrantType") != "authorization_code"
            or case.get("pkceMethod") != "S256"
            or isinstance(expires_in, bool)
            or not isinstance(expires_in, int)
            or not 0 < expires_in <= 3600
            or case.get("oauthBeforeHttpStatus") != 200
            or case.get("sessionNextHttpStatus") != 401
            or case.get("oauthAccessNextHttpStatus") != 401
            or case.get("oauthRefreshNextHttpStatus") not in {400, 401}
            or case.get("oauthRefreshError") != "invalid_grant"
            or case.get("patNextHttpStatus") != 401
            or case.get("operationAuditObserved") is not True
            or case.get("fixtureReadAfterCleanupHttpStatus") != 404
            or case.get("fixtureCleanupAuditObserved") is not True
        ):
            raise EvidenceError(f"cascade {expected_action} does not prove next-request invalidation")
        traces.add(trace)

    pepper = _object(report.get("pepperRotation"), "Pepper rotation")
    _exact(pepper, {"beforeVersion", "afterVersion", "authenticationHttpStatus", "activeHashMatched",
                    "lastUsedRecorded", "databasePlaintextAbsent", "runtimeLogPlaintextAbsent"},
           "Pepper rotation")
    if (
        not isinstance(pepper.get("beforeVersion"), str)
        or not isinstance(pepper.get("afterVersion"), str)
        or pepper["beforeVersion"] == pepper["afterVersion"]
        or pepper.get("authenticationHttpStatus") != 200
        or any(pepper.get(name) is not True for name in (
            "activeHashMatched", "lastUsedRecorded", "databasePlaintextAbsent", "runtimeLogPlaintextAbsent"
        ))
    ):
        raise EvidenceError("Pepper rotation observations are incomplete")

    client_secret = _object(report.get("clientSecretRotation"), "Client Secret rotation")
    _exact(client_secret, {"overlapSeconds", "oldDuringHttpStatus", "newDuringHttpStatus",
                           "oldAfterHttpStatus", "oldAfterError", "newAfterHttpStatus",
                           "preRegisteredClientObserved", "operationAuditObserved"},
           "Client Secret rotation")
    if (
        client_secret.get("overlapSeconds") != 2
        or client_secret.get("oldDuringHttpStatus") != 200
        or client_secret.get("newDuringHttpStatus") != 200
        or client_secret.get("oldAfterHttpStatus") not in {400, 401}
        or client_secret.get("oldAfterError") != "invalid_client"
        or client_secret.get("newAfterHttpStatus") != 200
        or client_secret.get("preRegisteredClientObserved") is not True
        or client_secret.get("operationAuditObserved") is not True
    ):
        raise EvidenceError("Client Secret overlap observations are incomplete")

    client_credentials = _object(
        report.get("clientCredentialsLifecycle"), "Client Credentials lifecycle"
    )
    _exact(client_credentials, {
        "shortLivedTokenObserved", "roleRevocationHttpStatus", "roleRestorationHttpStatus",
        "revocationAuditObserved", "restorationAuditObserved",
    }, "Client Credentials lifecycle")
    if (
        client_credentials.get("shortLivedTokenObserved") is not True
        or client_credentials.get("roleRevocationHttpStatus") != 401
        or client_credentials.get("roleRestorationHttpStatus") != 200
        or client_credentials.get("revocationAuditObserved") is not True
        or client_credentials.get("restorationAuditObserved") is not True
    ):
        raise EvidenceError("Client Credentials lifecycle observations are incomplete")

    service_account = _object(
        report.get("serviceAccountLifecycle"), "service account lifecycle"
    )
    _exact(service_account, {
        "createdEnabledWithRole", "roleRemovalErrorCode", "roleRestorationHttpStatus",
        "explicitRevocationHttpStatus", "peerAfterSingleRevocationHttpStatus",
        "disabledTokenHttpStatuses", "allExistingTokenRowsRevoked",
        "reenabledOldTokenHttpStatuses", "replacementTokenHttpStatus",
        "operationAuditsObserved",
    }, "service account lifecycle")
    if (
        service_account.get("createdEnabledWithRole") is not True
        or service_account.get("roleRemovalErrorCode") != "FORBIDDEN"
        or service_account.get("roleRestorationHttpStatus") != 200
        or service_account.get("explicitRevocationHttpStatus") != 401
        or service_account.get("peerAfterSingleRevocationHttpStatus") != 200
        or service_account.get("disabledTokenHttpStatuses") != [401, 401]
        or service_account.get("allExistingTokenRowsRevoked") is not True
        or service_account.get("reenabledOldTokenHttpStatuses") != [401, 401]
        or service_account.get("replacementTokenHttpStatus") != 200
        or service_account.get("operationAuditsObserved") is not True
    ):
        raise EvidenceError("service account lifecycle observations are incomplete")

    personal_token = _object(
        report.get("personalTokenLifecycle"), "personal token lifecycle"
    )
    _exact(personal_token, {
        "boundUserObserved", "oneTimePlaintextObserved", "databaseHashAndHintObserved",
        "scopeDeniedCode", "beforeExpiryHttpStatus", "afterExpiryHttpStatus",
        "revokedHttpStatus", "ipRestrictedHttpStatus", "lastUsedRecorded",
        "lifecycleFieldsObserved",
    }, "personal token lifecycle")
    if (
        personal_token.get("boundUserObserved") is not True
        or personal_token.get("oneTimePlaintextObserved") is not True
        or personal_token.get("databaseHashAndHintObserved") is not True
        or personal_token.get("scopeDeniedCode") != "FORBIDDEN"
        or personal_token.get("beforeExpiryHttpStatus") != 200
        or personal_token.get("afterExpiryHttpStatus") != 401
        or personal_token.get("revokedHttpStatus") != 401
        or personal_token.get("ipRestrictedHttpStatus") != 401
        or personal_token.get("lastUsedRecorded") is not True
        or personal_token.get("lifecycleFieldsObserved") is not True
    ):
        raise EvidenceError("personal token lifecycle observations are incomplete")

    security = _object(report.get("securityRegression"), "security regression")
    _exact(security, {"rbacAllowedScopeDeniedCode", "scopeAllowedRbacDeniedCode",
                      "disabledSubjectRejected", "revokedCredentialHttpStatus", "privatePatHttpStatus",
                      "publicPatHttpStatus", "privateServiceTokenHttpStatus",
                      "publicServiceTokenHttpStatus", "invalidHostHttpStatus", "invalidOriginRejected",
                      "scopeDeniedAuditObserved", "rbacDeniedAuditObserved", "correlatedAuditsObserved"},
           "security regression")
    if (
        security.get("rbacAllowedScopeDeniedCode") != "FORBIDDEN"
        or security.get("scopeAllowedRbacDeniedCode") != "FORBIDDEN"
        or security.get("disabledSubjectRejected") is not True
        or security.get("revokedCredentialHttpStatus") != 401
        or security.get("privatePatHttpStatus") != 200
        or security.get("publicPatHttpStatus") != 401
        or security.get("privateServiceTokenHttpStatus") != 200
        or security.get("publicServiceTokenHttpStatus") != 401
        or isinstance(security.get("invalidHostHttpStatus"), bool)
        or not isinstance(security.get("invalidHostHttpStatus"), int)
        or not 400 <= security["invalidHostHttpStatus"] < 500
        or any(security.get(name) is not True for name in (
            "invalidOriginRejected", "scopeDeniedAuditObserved", "rbacDeniedAuditObserved",
            "correlatedAuditsObserved",
        ))
    ):
        raise EvidenceError("unified V1 security-negative regression observations are incomplete")

    handling = _object(report.get("secretHandling"), "secret handling")
    _exact(handling, {"rawCredentialsPersisted", "databaseDumpScanned", "runtimeLogsScanned",
                      "errorResponsesScanned", "runtimeSensitiveHeadersAbsent",
                      "sensitiveValueCount"}, "secret handling")
    if (
        handling.get("rawCredentialsPersisted") is not False
        or handling.get("databaseDumpScanned") is not True
        or handling.get("runtimeLogsScanned") is not True
        or handling.get("errorResponsesScanned") is not True
        or handling.get("runtimeSensitiveHeadersAbsent") is not True
        or isinstance(handling.get("sensitiveValueCount"), bool)
        or not isinstance(handling.get("sensitiveValueCount"), int)
        or handling["sensitiveValueCount"] < 20
    ):
        raise EvidenceError("secret persistence scan is incomplete")
    if re.search(rb"wst_(?:pat|svc)_[A-Za-z0-9_-]{20,}", report_payload) or re.search(
        rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", report_payload
    ):
        raise EvidenceError("sanitized credential lifecycle report contains credential-shaped material")

    sources = _object(report.get("sources"), "credential lifecycle sources")
    if set(sources) != set(SOURCE_PATHS):
        raise EvidenceError("credential lifecycle source inventory differs from the fixed contract")
    source_hashes: dict[str, str] = {}
    for path in SOURCE_PATHS:
        expected = sources.get(path)
        actual = _sha256(candidate_root.resolve(strict=True) / path)
        if not isinstance(expected, str) or SHA256.fullmatch(expected) is None or expected != actual:
            raise EvidenceError(f"credential lifecycle source hash differs: {path}")
        source_hashes[path] = actual
    return binding, source_hashes


def validate(
    report_path: Path,
    candidate_root: Path,
    runtime_identity_path: Path,
    oauth_runtime_report_path: Path,
    compose_project: str,
    output_path: Path | None,
) -> dict[str, Any]:
    report, report_payload = _json_payload(report_path, MAX_REPORT, "credential lifecycle report")
    runtime_identity, _ = _json_payload(runtime_identity_path, MAX_IDENTITY, "runtime identity")
    oauth_report, _ = _json_payload(oauth_runtime_report_path, MAX_IDENTITY, "OAuth runtime report")
    runtime_sha = _sha256(runtime_identity_path)
    oauth_sha = _sha256(oauth_runtime_report_path)
    binding, source_hashes = _validate_report(
        report, report_payload, candidate_root, runtime_identity, runtime_sha,
        oauth_report, oauth_sha, compose_project,
    )
    summary = {
        "schemaVersion": 1,
        "acceptanceIds": ACCEPTANCE_IDS,
        "status": "PASS",
        "candidate": {
            **binding,
            "appImageReference": report["candidate"]["appImageReference"],
            "nginxImageReference": report["candidate"]["nginxImageReference"],
        },
        "runtime": {
            "composeProject": compose_project,
            "runtimeIdentitySha256": runtime_sha,
            "oauthRuntimeReportSha256": oauth_sha,
        },
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
        "evidence": {"reportSha256": _sha256(report_path), "sourceSha256": source_hashes},
    }
    if output_path is not None:
        output = output_path.expanduser().absolute()
        if output.name != SUMMARY_NAME or output.exists() or output.is_symlink():
            raise EvidenceError("canonical credential lifecycle summary path is unsafe")
        if output.parent.is_symlink() or not output.parent.is_dir():
            raise EvidenceError("canonical credential lifecycle summary parent is unsafe")
        if os.name == "posix" and stat.S_IMODE(output.parent.stat().st_mode) != 0o700:
            raise EvidenceError("canonical credential lifecycle summary parent must have mode 0700")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
    parser.add_argument("--oauth-runtime-report", required=True, type=Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        summary = validate(
            args.report, args.candidate_root, args.runtime_identity, args.oauth_runtime_report,
            args.compose_project, args.output,
        )
    except (EvidenceError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL credential-lifecycle-evidence: {error}", file=sys.stderr)
        return 1
    print("PASS credential-lifecycle-evidence: " + ",".join(summary["acceptanceIds"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
