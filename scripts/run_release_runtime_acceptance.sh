#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
artifact_root="${WEB_STARTER_RELEASE_ARTIFACT_DIR:-${repository_root}/artifacts}"
runtime_root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/web-starter-release-runtime.XXXXXX")"
run_ac41_formal="${WEB_STARTER_RUN_AC41_FORMAL:-false}"
run_ac29_formal="${WEB_STARTER_RUN_AC29_FORMAL:-false}"
run_ac26_formal="${WEB_STARTER_RUN_AC26_FORMAL:-false}"
run_mcp_crud_proof_formal="${WEB_STARTER_RUN_MCP_CRUD_PROOF_FORMAL:-false}"
run_mcp_tool_contract_formal="${WEB_STARTER_RUN_MCP_TOOL_CONTRACT_FORMAL:-false}"
run_release_runtime_test_reports_formal="${WEB_STARTER_RUN_RELEASE_RUNTIME_TEST_REPORTS_FORMAL:-false}"
run_mcp_governance_formal="${WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL:-false}"
mcp_governance_proof_root="${WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR:-}"
run_credential_lifecycle_formal="${WEB_STARTER_RUN_CREDENTIAL_LIFECYCLE_FORMAL:-false}"
run_observability_formal="${WEB_STARTER_RUN_OBSERVABILITY_FORMAL:-false}"
early_runtime_cleanup() {
  local exit_code=$?
  trap - EXIT
  find "${runtime_root}" -type f -exec chmod u+rw {} + 2>/dev/null || true
  rm -rf -- "${runtime_root}" || exit_code=1
  exit "${exit_code}"
}
trap early_runtime_cleanup EXIT
raw_project_name="${WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT:-web-starter-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}}"
project_name="$(python3 -B - "${raw_project_name}" "${run_ac41_formal}" <<'PY'
import hashlib
import re
import sys

value = sys.argv[1]
formal = sys.argv[2]
if formal not in {"true", "false"}:
    raise SystemExit("WEB_STARTER_RUN_AC41_FORMAL must be exactly true or false")
if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value):
    raise SystemExit("release Compose project name is invalid")
if len(value) > 63:
    suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    value = value[:54].rstrip("-_") + "-" + suffix
if len(value) > 63:
    raise SystemExit("release Compose project name could not be bounded")
if formal == "true" and not re.fullmatch(
    r"web-starter-ac41-[a-z0-9][a-z0-9-]{0,39}", value
):
    raise SystemExit("formal AC-41 requires an isolated web-starter-ac41-* Compose project")
print(value)
PY
)"
private_port="${WEB_STARTER_ACCEPTANCE_PRIVATE_PORT:-18088}"
public_port="${WEB_STARTER_ACCEPTANCE_PUBLIC_PORT:-18443}"
management_port="${WEB_STARTER_ACCEPTANCE_MANAGEMENT_PORT:-18081}"
public_hostname="${WEB_STARTER_ACCEPTANCE_PUBLIC_HOSTNAME:-mcp.release.webstarter.test}"
private_mcp_hostname="${WEB_STARTER_ACCEPTANCE_PRIVATE_MCP_HOSTNAME:-mcp-private.release.webstarter.test}"
private_url="http://localhost:${private_port}"
private_mcp_url="http://${private_mcp_hostname}:${private_port}"
public_url="https://${public_hostname}:${public_port}"
runtime_env="${runtime_root}/runtime.env"
credential_root="${runtime_root}/credentials"
refreshed_read_token="${credential_root}/pat-read-refreshed.json"
unified_read_token="${credential_root}/pat-read-unified.json"
certificate_root="${runtime_root}/tls"
truststore="${runtime_root}/acceptance-truststore.p12"
hosts_file="${runtime_root}/acceptance-hosts"
oauth_active_private="${runtime_root}/oauth-active-private.pem"
oauth_active_der="${runtime_root}/oauth-active-private.der"
oauth_retiring_private="${runtime_root}/oauth-retiring-private.pem"
oauth_retiring_der="${runtime_root}/oauth-retiring-private.der"
oauth_jwk_set="${runtime_root}/oauth-jwk-set.json"
management_override="${runtime_root}/management.override.yaml"
playwright_output="${runtime_root}/playwright-output"
unified_verify_evidence="${runtime_root}/unified-verify-evidence"
unified_verify_summary="${artifact_root}/unified-verify-summary.json"
unified_verify_failure_root="${WEB_STARTER_UNIFIED_VERIFY_FAILURE_DIR:-}"
generated_module_plan="${runtime_root}/generated-module-plan.json"
generated_module_plan_after="${runtime_root}/generated-module-plan-after.json"
generated_module_summary="${artifact_root}/generated-module-runtime.json"
if [[ "${run_mcp_crud_proof_formal}" == "true" ]]; then
  mcp_crud_proof_root="${WEB_STARTER_MCP_CRUD_PROOF_DIR:-}"
  mcp_crud_candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-}"
else
  mcp_crud_proof_root="${runtime_root}/mcp-crud-proof"
  mcp_crud_candidate_root="${repository_root}"
fi
mcp_crud_report="${mcp_crud_proof_root}/TEST-dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT.xml"
mcp_crud_proof="${mcp_crud_proof_root}/mcp-crud-runtime-proof.properties"
mcp_crud_transaction_receipt="${mcp_crud_proof_root}/mcp-crud-transaction-receipt.properties"
mcp_crud_trace_prefix="release-sdk"
mcp_crud_transaction_constraint="chk_webstarter_ac16_tx_audit"
mcp_crud_transaction_project_code="MCP_TX_ROLLBACK"
mcp_crud_transaction_key="crud-transaction-rollback"
mcp_crud_summary_root="${runtime_root}/mcp-crud-summary"
mcp_crud_raw_summary="${mcp_crud_summary_root}/mcp-crud-runtime-proof-summary.json"
acceptance_artifact_root="${artifact_root}/acceptance"
observability_candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-${repository_root}}"
observability_summary_root="${runtime_root}/observability-summary"
observability_private_summary="${observability_summary_root}/v2-observability-runtime-summary.json"
observability_public_summary="${acceptance_artifact_root}/v2-observability-runtime-summary.json"
mcp_crud_public_summary="${acceptance_artifact_root}/mcp-crud-runtime-proof-summary.json"
if [[ "${run_credential_lifecycle_formal}" == "true" ]]; then
  credential_lifecycle_raw_root="${WEB_STARTER_CREDENTIAL_LIFECYCLE_EVIDENCE_DIR:-}"
  credential_lifecycle_candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-}"
else
  credential_lifecycle_raw_root=""
  credential_lifecycle_candidate_root="${repository_root}"
fi
if [[ "${run_observability_formal}" == "true" ]]; then
  mkdir -p "${observability_summary_root}"
  chmod 700 "${observability_summary_root}"
fi
credential_lifecycle_report="${credential_lifecycle_raw_root}/v2-credential-lifecycle-runtime.json"
credential_lifecycle_summary_root="${runtime_root}/credential-lifecycle-summary"
credential_lifecycle_private_summary="${credential_lifecycle_summary_root}/v2-credential-lifecycle-runtime-summary.json"
credential_lifecycle_public_summary="${acceptance_artifact_root}/v2-credential-lifecycle-runtime-summary.json"
if [[ "${run_mcp_tool_contract_formal}" == "true" ]]; then
  mcp_tool_contract_proof_root="${WEB_STARTER_MCP_TOOL_CONTRACT_PROOF_DIR:-}"
  mcp_tool_contract_candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-}"
else
  mcp_tool_contract_proof_root="${runtime_root}/mcp-tool-contract-proof"
  mcp_tool_contract_candidate_root="${repository_root}"
fi
if [[ "${run_credential_lifecycle_formal}" == "true" ]]; then
  mkdir -p "${credential_lifecycle_summary_root}"
  chmod 700 "${credential_lifecycle_summary_root}"
fi
mcp_tool_contract_report="${mcp_tool_contract_proof_root}/TEST-dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT.xml"
mcp_tool_contract_proof="${mcp_tool_contract_proof_root}/mcp-tool-contract-runtime-proof.properties"
mcp_tool_contract_trace_prefix="release-tool-contract"
mcp_tool_contract_summary_root="${runtime_root}/mcp-tool-contract-summary"
mcp_tool_contract_raw_summary="${mcp_tool_contract_summary_root}/mcp-tool-contract-runtime-proof-summary.json"
mcp_tool_contract_public_summary="${acceptance_artifact_root}/mcp-tool-contract-runtime-proof-summary.json"
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  release_runtime_reports_raw_root="${WEB_STARTER_RELEASE_RUNTIME_TEST_REPORTS_DIR:-}"
  release_runtime_reports_candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-}"
  release_runtime_playwright_report="${release_runtime_reports_raw_root}/playwright-release-runtime.json"
else
  release_runtime_reports_raw_root=""
  release_runtime_reports_candidate_root="${repository_root}"
  release_runtime_playwright_report=""
fi
release_runtime_sdk_public_reports="${runtime_root}/release-runtime-sdk-public-reports"
release_runtime_sdk_private_reports="${runtime_root}/release-runtime-sdk-private-reports"
release_runtime_reports_summary_root="${runtime_root}/release-runtime-test-reports-summary"
release_runtime_reports_private_summary="${release_runtime_reports_summary_root}/release-runtime-test-reports-summary.json"
release_runtime_reports_public_summary="${acceptance_artifact_root}/release-runtime-test-reports-summary.json"
if [[ "${run_ac26_formal}" == "true" ]]; then
  ac26_evidence_root="${WEB_STARTER_AC26_EVIDENCE_DIR:-}"
  ac26_candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-}"
else
  ac26_evidence_root="${runtime_root}/ac26-evidence"
  ac26_candidate_root="${repository_root}"
fi
ac26_report="${ac26_evidence_root}/v2-ac26-jwks-rotation.json"
ac26_summary_root="${runtime_root}/ac26-summary"
ac26_raw_summary="${ac26_summary_root}/v2-ac26-jwks-rotation-summary.json"
ac26_public_summary="${acceptance_artifact_root}/v2-ac26-jwks-rotation-summary.json"
ac26_project_name="${WEB_STARTER_AC26_COMPOSE_PROJECT:-web-starter-ac26-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}}"
ac26_terminal_mode="${WEB_STARTER_AC26_TERMINAL_MODE:-expiry}"
ac26_trace_prefix="release-ac26"
ac26_private_port="${WEB_STARTER_AC26_PRIVATE_PORT:-28088}"
ac26_public_port="${WEB_STARTER_AC26_PUBLIC_PORT:-28443}"
ac26_management_port="${WEB_STARTER_AC26_MANAGEMENT_PORT:-28081}"
ac26_public_hostname="mcp.ac26.webstarter.test"
ac26_private_mcp_hostname="mcp-private.ac26.webstarter.test"
ac26_private_url="http://127.0.0.1:${ac26_private_port}"
ac26_private_mcp_url="http://${ac26_private_mcp_hostname}:${ac26_private_port}"
ac26_public_url="https://${ac26_public_hostname}:${ac26_public_port}"
ac26_runtime_env="${runtime_root}/ac26-runtime.env"
ac26_management_override="${runtime_root}/ac26-management.override.yaml"
ac26_credential_root="${runtime_root}/ac26-credentials"
ac26_key_root="${runtime_root}/ac26-keys"
ac26_initial_jwk_set="${ac26_key_root}/initial.json"
ac26_rotated_jwk_set="${ac26_key_root}/rotated.json"
ac26_terminal_jwk_set="${ac26_key_root}/revoked.json"
ac26_old_kid="release-ac26-old"
ac26_new_kid="release-ac26-new"
ac41_raw_report=""
ac41_raw_checksum=""
ac41_public_report="${acceptance_artifact_root}/v2-ac41-redis-loss.json"
ac41_public_checksum="${ac41_public_report}.sha256"
ac29_raw_report=""
ac29_raw_checksum=""
ac29_public_report="${acceptance_artifact_root}/v2-ac29-production-fail-fast.json"
oauth_active_kid="release-active-2026"
oauth_retiring_kid="release-retiring-2025"
oauth_retiring_retain_until="$(python3 -B - <<'PY'
import time

# The release access-token TTL is ten minutes. Keep the old verification key
# for two hours so the real acceptance run cannot accidentally cross its
# exclusive retain-until boundary while still exercising a bounded window.
print(int(time.time()) + 7200)
PY
)"
production_compose=(docker compose --env-file "${runtime_env}" -f "${repository_root}/compose.production.yaml" -p "${project_name}")
compose=(docker compose --env-file "${runtime_env}" -f "${repository_root}/compose.production.yaml" -f "${management_override}" -p "${project_name}")
compose_owned=0
ac16_constraint_owned=0
ac26_compose=()
ac26_compose_owned=0

mkdir -p "${artifact_root}" "${certificate_root}" "${playwright_output}" "${mcp_crud_summary_root}"
chmod 700 "${runtime_root}" "${certificate_root}" "${playwright_output}" "${mcp_crud_summary_root}"
if [[ "${run_mcp_crud_proof_formal}" == "false" ]]; then
  mkdir -p "${mcp_crud_proof_root}"
  chmod 700 "${mcp_crud_proof_root}"
fi
if [[ "${run_mcp_tool_contract_formal}" == "true" ]]; then
  mkdir -p "${mcp_tool_contract_summary_root}"
  chmod 700 "${mcp_tool_contract_summary_root}"
fi
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  mkdir -p \
    "${release_runtime_sdk_public_reports}" \
    "${release_runtime_sdk_private_reports}" \
    "${release_runtime_reports_summary_root}"
  chmod 700 \
    "${release_runtime_sdk_public_reports}" \
    "${release_runtime_sdk_private_reports}" \
    "${release_runtime_reports_summary_root}"
fi
if [[ "${run_ac26_formal}" == "true" ]]; then
  mkdir -p "${ac26_summary_root}" "${ac26_key_root}"
  chmod 700 "${ac26_summary_root}" "${ac26_key_root}"
fi

require_value() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "release runtime acceptance requires ${name}" >&2
    exit 2
  fi
}

require_digest_reference() {
  local name="$1"
  require_value "${name}"
  if [[ ! "${!name}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "${name} must be an immutable image reference including @sha256 digest" >&2
    exit 2
  fi
}

require_image_parts() {
  local image_name="$1"
  local digest_name="$2"
  require_value "${image_name}"
  require_value "${digest_name}"
  if [[ "${!image_name}" =~ [@[:space:]] || ! "${!digest_name}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "${image_name} and ${digest_name} must form an immutable image reference" >&2
    exit 2
  fi
}

require_digest_reference WEB_STARTER_MYSQL_IMAGE
require_digest_reference WEB_STARTER_REDIS_IMAGE
require_image_parts WEB_STARTER_APP_IMAGE WEB_STARTER_APP_DIGEST
require_image_parts WEB_STARTER_NGINX_IMAGE WEB_STARTER_NGINX_DIGEST
require_value WEB_STARTER_RELEASE_TAG
require_value WEB_STARTER_RELEASE_VERSION
require_value GITHUB_SHA
if [[ -n "${unified_verify_failure_root}" ]]; then
  require_value RUNNER_TEMP
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${unified_verify_failure_root}" \
    "${repository_root}" \
    "${artifact_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

runner = Path(sys.argv[1]).expanduser().resolve(strict=True)
requested = Path(sys.argv[2]).expanduser().absolute()
repository = Path(sys.argv[3]).resolve(strict=True)
artifact = Path(sys.argv[4]).expanduser().absolute()
if requested.is_symlink() or not requested.exists():
    raise SystemExit("unified verify failure directory must be an existing real directory")
target = requested.resolve(strict=True)
metadata = target.stat()
if target.parent != runner or not stat.S_ISDIR(metadata.st_mode) \
        or stat.S_IMODE(metadata.st_mode) != 0o700 \
        or metadata.st_uid != os.geteuid() or any(target.iterdir()):
    raise SystemExit(
        "unified verify failure directory must be an empty owned mode-0700 RUNNER_TEMP child"
    )
for other, label in ((repository, "repository"), (artifact, "artifact")):
    resolved = other.resolve(strict=False)
    if target == resolved or target in resolved.parents or resolved in target.parents:
        raise SystemExit(f"unified verify failure directory must be isolated from the {label}")
PY
fi
if [[ "${WEB_STARTER_RELEASE_TAG}" != "v${WEB_STARTER_RELEASE_VERSION}" ]]; then
  echo "WEB_STARTER_RELEASE_TAG must equal v plus WEB_STARTER_RELEASE_VERSION" >&2
  exit 2
fi
if [[ "${run_mcp_governance_formal}" != "true" \
    && "${run_mcp_governance_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_credential_lifecycle_formal}" != "true" \
    && "${run_credential_lifecycle_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_CREDENTIAL_LIFECYCLE_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_observability_formal}" != "true" \
    && "${run_observability_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_OBSERVABILITY_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_observability_formal}" == "true" ]]; then
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  if [[ "${observability_candidate_root}" != "${credential_lifecycle_candidate_root}" \
      && "${run_credential_lifecycle_formal}" == "true" ]]; then
    echo "observability and credential lifecycle must bind the same candidate" >&2
    exit 2
  fi
fi
if [[ "${run_credential_lifecycle_formal}" == "true" ]]; then
  require_value RUNNER_TEMP
  require_value WEB_STARTER_CREDENTIAL_LIFECYCLE_EVIDENCE_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${credential_lifecycle_raw_root}" \
    "${credential_lifecycle_candidate_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

runner = Path(sys.argv[1]).expanduser().resolve(strict=True)
raw_requested = Path(sys.argv[2]).expanduser().absolute()
candidate_requested = Path(sys.argv[3]).expanduser().absolute()
for requested, label in ((raw_requested, "credential lifecycle evidence"),
                         (candidate_requested, "candidate validation")):
    if requested.is_symlink():
        raise SystemExit(f"{label} directory must not be a symbolic link")
    resolved = requested.resolve(strict=True)
    metadata = resolved.stat()
    if resolved.parent != runner or not stat.S_ISDIR(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o700 \
            or metadata.st_uid != os.geteuid():
        raise SystemExit(f"{label} directory must be an owned mode-0700 RUNNER_TEMP child")
if raw_requested.resolve(strict=True) == candidate_requested.resolve(strict=True):
    raise SystemExit("credential lifecycle evidence and candidate directories must differ")
if any(raw_requested.iterdir()):
    raise SystemExit("credential lifecycle evidence directory must be empty")
PY
fi
if [[ "${run_observability_formal}" == "true" ]]; then
  if [[ -e "${observability_public_summary}" || -L "${observability_public_summary}" ]]; then
    echo "release observability summary artifact already exists" >&2
    exit 2
  fi
fi
if [[ "${run_mcp_governance_formal}" == "true" ]]; then
  WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT="${project_name}" \
  WEB_STARTER_AC26_COMPOSE_PROJECT="${ac26_project_name}" \
  bash "${repository_root}/scripts/run_mcp_governance_runtime_acceptance.sh" preflight
fi
if [[ ! "${project_name}" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; then
  echo "release acceptance Compose project name is invalid" >&2
  exit 2
fi
if [[ "${run_mcp_crud_proof_formal}" != "true" && "${run_mcp_crud_proof_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_MCP_CRUD_PROOF_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_mcp_crud_proof_formal}" == "true" ]]; then
  require_value RUNNER_TEMP
  require_value WEB_STARTER_MCP_CRUD_PROOF_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${WEB_STARTER_MCP_CRUD_PROOF_DIR}" \
    "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" <<'PY'
from pathlib import Path
import stat
import sys

runner_temp = Path(sys.argv[1]).expanduser().resolve(strict=True)
candidate = Path(sys.argv[2]).expanduser().absolute()
if candidate.is_symlink():
    raise SystemExit("MCP CRUD proof directory must not be a symbolic link")
proof = candidate.resolve(strict=True)
if proof.parent != runner_temp:
    raise SystemExit("MCP CRUD raw proof must be an independent RUNNER_TEMP child directory")
metadata = proof.stat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("MCP CRUD raw proof directory must be a real 0700 directory")
if any(proof.iterdir()):
    raise SystemExit("MCP CRUD raw proof directory must be empty")
candidate_root_path = Path(sys.argv[3]).expanduser().absolute()
if candidate_root_path.is_symlink():
    raise SystemExit("candidate validation root must not be a symbolic link")
candidate_root = candidate_root_path.resolve(strict=True)
candidate_metadata = candidate_root.stat()
if candidate_root.parent != runner_temp:
    raise SystemExit("candidate validation root must be an independent RUNNER_TEMP child")
if (
    candidate_root == proof
    or not stat.S_ISDIR(candidate_metadata.st_mode)
    or stat.S_IMODE(candidate_metadata.st_mode) != 0o700
):
    raise SystemExit("candidate validation root must be a distinct real 0700 directory")
PY
fi
if [[ "${run_mcp_tool_contract_formal}" != "true" && "${run_mcp_tool_contract_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_MCP_TOOL_CONTRACT_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_mcp_tool_contract_formal}" == "true" ]]; then
  require_value RUNNER_TEMP
  require_value WEB_STARTER_MCP_TOOL_CONTRACT_PROOF_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${WEB_STARTER_MCP_TOOL_CONTRACT_PROOF_DIR}" \
    "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" <<'PY'
from pathlib import Path
import stat
import sys

runner_temp = Path(sys.argv[1]).expanduser().resolve(strict=True)
proof_path = Path(sys.argv[2]).expanduser().absolute()
if proof_path.is_symlink():
    raise SystemExit("MCP Tool contract proof directory must not be a symbolic link")
proof = proof_path.resolve(strict=True)
if proof.parent != runner_temp:
    raise SystemExit(
        "MCP Tool contract raw proof must be an independent RUNNER_TEMP child directory"
    )
metadata = proof.stat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("MCP Tool contract raw proof directory must be a real 0700 directory")
if any(proof.iterdir()):
    raise SystemExit("MCP Tool contract raw proof directory must be empty")
candidate_path = Path(sys.argv[3]).expanduser().absolute()
if candidate_path.is_symlink():
    raise SystemExit("MCP Tool contract candidate root must not be a symbolic link")
candidate = candidate_path.resolve(strict=True)
candidate_metadata = candidate.stat()
if candidate.parent != runner_temp:
    raise SystemExit("MCP Tool contract candidate root must be a RUNNER_TEMP child")
if (
    candidate == proof
    or not stat.S_ISDIR(candidate_metadata.st_mode)
    or stat.S_IMODE(candidate_metadata.st_mode) != 0o700
):
    raise SystemExit("MCP Tool contract candidate root must be a distinct real 0700 directory")
PY
fi
if [[ "${run_release_runtime_test_reports_formal}" != "true" \
    && "${run_release_runtime_test_reports_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_RELEASE_RUNTIME_TEST_REPORTS_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  if [[ "${WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS+x}" == "x" ]]; then
    echo "formal release runtime reports reject ambient WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS" >&2
    exit 2
  fi
  if [[ "${WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED+x}" == "x" ]]; then
    echo "formal release runtime reports reject ambient WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED" >&2
    exit 2
  fi
  require_value RUNNER_TEMP
  require_value WEB_STARTER_RELEASE_RUNTIME_TEST_REPORTS_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${WEB_STARTER_RELEASE_RUNTIME_TEST_REPORTS_DIR}" \
    "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" \
    "${repository_root}" \
    "${artifact_root}" \
    "${GITHUB_SHA}" \
    "${WEB_STARTER_RELEASE_TAG}" \
    "${WEB_STARTER_RELEASE_VERSION}" <<'PY'
import os
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

runner_temp_path = Path(sys.argv[1]).expanduser().absolute()
if runner_temp_path.is_symlink() or not runner_temp_path.is_dir():
    raise SystemExit("RUNNER_TEMP must be a real directory for formal runtime reports")
runner_temp = runner_temp_path.resolve(strict=True)

raw_path = Path(sys.argv[2]).expanduser().absolute()
if raw_path.is_symlink():
    raise SystemExit("release runtime reports raw directory must not be a symbolic link")
raw = raw_path.resolve(strict=True)
raw_metadata = raw.stat()
if raw.parent != runner_temp:
    raise SystemExit(
        "release runtime reports raw directory must be an independent RUNNER_TEMP child"
    )
if (
    not stat.S_ISDIR(raw_metadata.st_mode)
    or stat.S_IMODE(raw_metadata.st_mode) != 0o700
    or raw_metadata.st_uid != os.geteuid()
):
    raise SystemExit("release runtime reports raw directory must be owned mode 0700")
if any(raw.iterdir()):
    raise SystemExit("release runtime reports raw directory must start empty")

repository = Path(sys.argv[4]).resolve(strict=True)
artifact_root = Path(sys.argv[5]).resolve(strict=True)

def contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False

if contains(repository, raw) or contains(raw, repository):
    raise SystemExit(
        "release runtime reports raw directory must be external to the source repository"
    )
if contains(artifact_root, raw) or contains(raw, artifact_root):
    raise SystemExit(
        "release runtime reports raw directory must be isolated from public artifacts"
    )

candidate_path = Path(sys.argv[3]).expanduser().absolute()
if candidate_path.is_symlink():
    raise SystemExit("release runtime reports candidate root must not be a symbolic link")
candidate = candidate_path.resolve(strict=True)
candidate_metadata = candidate.stat()
if candidate.parent != runner_temp:
    raise SystemExit("release runtime reports candidate root must be a RUNNER_TEMP child")
if (
    candidate == raw
    or not stat.S_ISDIR(candidate_metadata.st_mode)
    or stat.S_IMODE(candidate_metadata.st_mode) != 0o700
    or candidate_metadata.st_uid != os.geteuid()
):
    raise SystemExit(
        "release runtime reports candidate root must be a distinct owned mode-0700 directory"
    )

commit, tag, version = sys.argv[6:9]
object_id = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
release_version = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
if object_id.fullmatch(commit) is None:
    raise SystemExit("release runtime reports candidate commit has an invalid format")
if release_version.fullmatch(version) is None or "SNAPSHOT" in version.upper():
    raise SystemExit("release runtime reports candidate version must be non-SNAPSHOT")
if tag != f"v{version}":
    raise SystemExit("release runtime reports candidate tag must equal v plus version")

git_environment = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_COUNT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
}

def git(*arguments: str) -> bytes:
    completed = subprocess.run(
        [
            "git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-C", str(candidate), *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=git_environment,
    )
    if completed.returncode != 0 or len(completed.stdout) > 16 * 1024 * 1024 \
            or len(completed.stderr) > 16 * 1024 * 1024:
        raise SystemExit("Git could not validate the release runtime reports candidate")
    return completed.stdout

def git_text(*arguments: str) -> str:
    try:
        value = git(*arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exception:
        raise SystemExit("release runtime reports Git identity is not UTF-8") from exception
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise SystemExit("release runtime reports Git identity is malformed")
    return value

top = Path(git_text("rev-parse", "--show-toplevel")).resolve(strict=True)
if top != candidate or git_text("rev-parse", "--verify", "HEAD^{commit}") != commit:
    raise SystemExit("release runtime reports candidate root or HEAD differs")
if git_text("cat-file", "-t", f"refs/tags/{tag}") != "tag" \
        or git_text("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != commit:
    raise SystemExit("release runtime reports candidate tag is not annotated at HEAD")
index_records = [record for record in git("ls-files", "-v", "-z").split(b"\0") if record]
if not index_records or any(
    len(record) < 3 or not record.startswith(b"H ") for record in index_records
):
    raise SystemExit("release runtime reports candidate index contains hidden entries")
if git(
    "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"
):
    raise SystemExit("release runtime reports candidate worktree must be clean")
for relative in (
    "scripts/create_release_runtime_test_reports_proof.py",
    "scripts/validate_release_runtime_test_reports_proof.py",
    "web-starter-web/package.json",
    "web-starter-web/pnpm-lock.yaml",
):
    entry = git("ls-tree", "-z", commit, "--", relative)
    if not entry.startswith((b"100644 blob ", b"100755 blob ")) \
            or not entry.endswith(b"\t" + relative.encode("utf-8") + b"\0"):
        raise SystemExit(f"release runtime reports candidate lacks fixed source: {relative}")

frontend = candidate / "web-starter-web"
node_modules_path = frontend / "node_modules"
if node_modules_path.is_symlink() or not node_modules_path.is_dir():
    raise SystemExit(
        "release runtime reports candidate lacks local frontend dependencies"
    )
node_modules = node_modules_path.resolve(strict=True)
if node_modules.parent != frontend:
    raise SystemExit("release runtime reports candidate node_modules escaped the frontend")

manifest_path = frontend / "package.json"
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
    raise SystemExit("release runtime reports candidate frontend manifest is invalid") from exception
if not isinstance(manifest, dict) \
        or not isinstance(manifest.get("devDependencies"), dict) \
        or manifest["devDependencies"].get("@playwright/test") != "1.61.1":
    raise SystemExit("release runtime reports candidate does not pin Playwright 1.61.1")

installed_manifest_path = node_modules_path / "@playwright" / "test" / "package.json"
try:
    installed_document = json.loads(
        installed_manifest_path.read_text(encoding="utf-8")
    )
    installed_manifest = installed_manifest_path.resolve(strict=True)
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
    raise SystemExit("release runtime reports candidate lacks local Playwright 1.61.1") from exception
if not contains(node_modules, installed_manifest) \
        or not isinstance(installed_document, dict) \
        or installed_document.get("version") != "1.61.1":
    raise SystemExit("release runtime reports candidate local Playwright version differs")

playwright_path = node_modules_path / ".bin" / "playwright"
try:
    playwright_metadata = playwright_path.lstat()
    playwright = playwright_path.resolve(strict=True)
except OSError as exception:
    raise SystemExit("release runtime reports candidate lacks a local Playwright binary") from exception
if not (stat.S_ISREG(playwright_metadata.st_mode) or stat.S_ISLNK(playwright_metadata.st_mode)) \
        or not contains(node_modules, playwright) \
        or not playwright.is_file() \
        or not os.access(playwright_path, os.X_OK):
    raise SystemExit("release runtime reports candidate local Playwright binary is unsafe")
try:
    playwright_version = subprocess.run(
        [str(playwright_path), "--version"],
        cwd=frontend,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
        },
    )
except OSError as exception:
    raise SystemExit("release runtime reports local Playwright could not execute") from exception
if len(playwright_version.stdout) > 1024 or len(playwright_version.stderr) > 1024 \
        or playwright_version.returncode != 0 \
        or playwright_version.stdout.decode("utf-8", errors="strict").strip() != "Version 1.61.1" \
        or playwright_version.stderr:
    raise SystemExit("release runtime reports local Playwright is not exactly 1.61.1")
PY
fi
if [[ "${run_ac26_formal}" != "true" && "${run_ac26_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_AC26_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_ac26_formal}" == "true" ]]; then
  require_value RUNNER_TEMP
  require_value WEB_STARTER_AC26_EVIDENCE_DIR
  require_value WEB_STARTER_AC26_COMPOSE_PROJECT
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${WEB_STARTER_AC26_EVIDENCE_DIR}" \
    "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" \
    "${ac26_project_name}" \
    "${ac26_terminal_mode}" \
    "${ac26_private_port}" \
    "${ac26_public_port}" \
    "${ac26_management_port}" \
    "${private_port}" \
    "${public_port}" \
    "${management_port}" <<'PY'
from pathlib import Path
import re
import stat
import sys

runner_temp = Path(sys.argv[1]).expanduser().resolve(strict=True)
evidence_path = Path(sys.argv[2]).expanduser().absolute()
if evidence_path.is_symlink():
    raise SystemExit("AC-26 evidence directory must not be a symbolic link")
evidence = evidence_path.resolve(strict=True)
if evidence.parent != runner_temp:
    raise SystemExit("AC-26 raw evidence must be an independent RUNNER_TEMP child directory")
metadata = evidence.stat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("AC-26 raw evidence directory must be a real 0700 directory")
if any(evidence.iterdir()):
    raise SystemExit("AC-26 raw evidence directory must be empty")
candidate_path = Path(sys.argv[3]).expanduser().absolute()
if candidate_path.is_symlink():
    raise SystemExit("AC-26 candidate root must not be a symbolic link")
candidate = candidate_path.resolve(strict=True)
candidate_metadata = candidate.stat()
if candidate.parent != runner_temp:
    raise SystemExit("AC-26 candidate root must be an independent RUNNER_TEMP child")
if (
    candidate == evidence
    or not stat.S_ISDIR(candidate_metadata.st_mode)
    or stat.S_IMODE(candidate_metadata.st_mode) != 0o700
):
    raise SystemExit("AC-26 candidate root must be a distinct real 0700 directory")
if re.fullmatch(r"web-starter-ac26-[a-z0-9][a-z0-9-]{0,39}", sys.argv[4]) is None:
    raise SystemExit("AC-26 Compose project must use the fixed isolated namespace")
if sys.argv[5] not in {"expiry", "revocation"}:
    raise SystemExit("AC-26 terminal mode must be exactly expiry or revocation")
try:
    ac26_ports = [int(value) for value in sys.argv[6:9]]
    main_ports = [int(value) for value in sys.argv[9:12]]
except ValueError as exception:
    raise SystemExit("AC-26 acceptance ports must be numeric") from exception
if any(port < 1024 or port > 65535 for port in ac26_ports):
    raise SystemExit("AC-26 acceptance ports must be unprivileged TCP ports")
if len(set(ac26_ports)) != 3 or set(ac26_ports).intersection(main_ports):
    raise SystemExit("AC-26 ports must be distinct from each other and the main release stack")
PY
  if [[ "${ac26_project_name}" == "${project_name}" ]]; then
    echo "AC-26 must use a Compose project distinct from the main release stack" >&2
    exit 2
  fi
fi
if [[ "${run_ac29_formal}" != "true" && "${run_ac29_formal}" != "false" ]]; then
  echo "WEB_STARTER_RUN_AC29_FORMAL must be exactly true or false" >&2
  exit 2
fi
if [[ "${run_ac26_formal}" == "true" ]]; then
  if [[ -e "${ac26_public_summary}" || -L "${ac26_public_summary}" ]]; then
    echo "release AC-26 JWKS rotation summary artifact already exists" >&2
    exit 2
  fi
fi
if [[ -e "${release_runtime_reports_public_summary}" \
    || -L "${release_runtime_reports_public_summary}" ]]; then
  echo "release runtime test reports canonical summary already exists" >&2
  exit 2
fi
if [[ "${run_ac29_formal}" == "true" ]]; then
  require_value RUNNER_TEMP
  require_value WEB_STARTER_AC29_EVIDENCE_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${WEB_STARTER_AC29_EVIDENCE_DIR}" \
    "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" <<'PY'
from pathlib import Path
import stat
import sys

runner_temp = Path(sys.argv[1]).expanduser().resolve(strict=True)
candidate = Path(sys.argv[2]).expanduser().absolute()
if candidate.is_symlink():
    raise SystemExit("AC-29 evidence directory must not be a symbolic link")
evidence = candidate.resolve(strict=True)
if evidence.parent != runner_temp:
    raise SystemExit("AC-29 raw evidence must be an independent RUNNER_TEMP child directory")
metadata = evidence.stat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("AC-29 raw evidence directory must be a real 0700 directory")
if any(evidence.iterdir()):
    raise SystemExit("AC-29 raw evidence directory must be empty")
candidate_root_path = Path(sys.argv[3]).expanduser().absolute()
if candidate_root_path.is_symlink():
    raise SystemExit("AC-29 candidate validation root must not be a symbolic link")
candidate_root = candidate_root_path.resolve(strict=True)
candidate_metadata = candidate_root.stat()
if candidate_root.parent != runner_temp:
    raise SystemExit("AC-29 candidate validation root must be a RUNNER_TEMP child")
if (
    candidate_root == evidence
    or not stat.S_ISDIR(candidate_metadata.st_mode)
    or stat.S_IMODE(candidate_metadata.st_mode) != 0o700
):
    raise SystemExit("AC-29 candidate validation root must be a distinct real 0700 directory")
PY
  ac29_raw_report="${WEB_STARTER_AC29_EVIDENCE_DIR}/v2-ac29-production-fail-fast.json"
  ac29_raw_checksum="${ac29_raw_report}.sha256"
fi
if [[ "${run_ac41_formal}" == "true" ]]; then
  require_value RUNNER_TEMP
  require_value WEB_STARTER_AC41_EVIDENCE_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${WEB_STARTER_AC41_EVIDENCE_DIR}" \
    "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" <<'PY'
from pathlib import Path
import stat
import sys

runner_temp = Path(sys.argv[1]).expanduser().resolve(strict=True)
candidate = Path(sys.argv[2]).expanduser().absolute()
if candidate.is_symlink():
    raise SystemExit("AC-41 evidence directory must not be a symbolic link")
evidence = candidate.resolve(strict=True)
if evidence.parent != runner_temp:
    raise SystemExit("AC-41 raw evidence must be an independent RUNNER_TEMP child directory")
metadata = evidence.stat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("AC-41 raw evidence directory must be a real 0700 directory")
if any(evidence.iterdir()):
    raise SystemExit("AC-41 raw evidence directory must be empty")
candidate_root_path = Path(sys.argv[3]).expanduser().absolute()
if candidate_root_path.is_symlink():
    raise SystemExit("AC-41 candidate validation root must not be a symbolic link")
candidate_root = candidate_root_path.resolve(strict=True)
candidate_metadata = candidate_root.stat()
if candidate_root.parent != runner_temp:
    raise SystemExit("AC-41 candidate validation root must be a RUNNER_TEMP child")
if (
    candidate_root == evidence
    or not stat.S_ISDIR(candidate_metadata.st_mode)
    or stat.S_IMODE(candidate_metadata.st_mode) != 0o700
):
    raise SystemExit("AC-41 candidate validation root must be a distinct real 0700 directory")
PY
  ac41_raw_report="${WEB_STARTER_AC41_EVIDENCE_DIR}/v2-ac41-redis-loss.json"
  ac41_raw_checksum="${ac41_raw_report}.sha256"
fi

for acceptance_hostname in "${public_hostname}" "${private_mcp_hostname}"; do
  if [[ ! "${acceptance_hostname}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.test$ ]]; then
    echo "release acceptance hostnames must be reserved lowercase .test DNS names" >&2
    exit 2
  fi
done
if [[ "${public_hostname}" == "${private_mcp_hostname}" ]]; then
  echo "public and private MCP acceptance hostnames must differ" >&2
  exit 2
fi

python3 -B "${repository_root}/scripts/generated_module_plan.py" \
  --repository-root "${repository_root}" \
  --output "${generated_module_plan}"
generated_module_count="$(python3 -B - "${generated_module_plan}" <<'PY'
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
modules = document.get("modules")
if document.get("schemaVersion") != 1 or not isinstance(modules, list):
    raise SystemExit("generated module plan snapshot is invalid")
print(len(modules))
PY
)"
generated_mcp_tools="$(python3 -B - "${generated_module_plan}" <<'PY'
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
tools = []
for module in document["modules"]:
    tools.extend(module.get("mcpTools", []))
if len(tools) != len(set(tools)):
    raise SystemExit("generated module plans repeat an MCP Tool")
print(",".join(tools))
PY
)"

expected_generated_modules="${WEB_STARTER_EXPECTED_GENERATED_MODULES:-}"
expected_generated_mcp_modules="${WEB_STARTER_EXPECTED_GENERATED_MCP_MODULES:-}"
if [[ -n "${expected_generated_modules}" || -n "${expected_generated_mcp_modules}" ]]; then
  if [[ -z "${expected_generated_modules}" || -z "${expected_generated_mcp_modules}" ]]; then
    echo "both generated-module expectation variables must be set together" >&2
    exit 2
  fi
  python3 -B - \
    "${generated_module_plan}" \
    "${expected_generated_modules}" \
    "${expected_generated_mcp_modules}" <<'PY'
import json
from pathlib import Path
import re
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
module_pattern = re.compile(r"^[a-z][a-z0-9]{1,30}$")

def expected(value):
    if value == "-":
        return []
    names = value.split(",")
    if any(not module_pattern.fullmatch(name) for name in names):
        raise SystemExit("generated-module expectations use an invalid module name")
    if len(names) != len(set(names)) or names != sorted(names):
        raise SystemExit("generated-module expectations must be unique and sorted")
    return names

actual = sorted(module["module"] for module in document["modules"])
actual_mcp = sorted(module["module"] for module in document["modules"] if module["withMcp"])
if actual != expected(sys.argv[2]) or actual_mcp != expected(sys.argv[3]):
    raise SystemExit(
        f"generated-module plan differs from the explicit expectation: "
        f"modules={actual}, mcpModules={actual_mcp}"
    )
PY
fi

write_sanitized_compose_status() {
  local raw_status="${runtime_root}/runtime-compose-status.txt"
  if ! "${compose[@]}" ps --all --format '{{.Service}}|{{.State}}|{{.Health}}' \
      > "${raw_status}" 2>/dev/null; then
    return 1
  fi
  python3 -B "${repository_root}/scripts/sanitize_compose_status.py" \
    --input "${raw_status}" \
    --output "${artifact_root}/runtime-compose-ps.json"
}

wait_for_compose_services_healthy() {
  local deadline=$((SECONDS + 60))
  local observed=""
  local expected=$'app|running|healthy\nmcp-public-nginx|running|healthy\nmysql|running|healthy\nnginx|running|healthy\nredis|running|healthy'
  while (( SECONDS < deadline )); do
    observed="$(
      "${compose[@]}" ps --all --format '{{.Service}}|{{.State}}|{{.Health}}' \
        2>/dev/null | LC_ALL=C sort
    )" || observed=""
    if [[ "${observed}" == "${expected}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "release Compose services did not return to the exact healthy state" >&2
  return 1
}

retire_main_stack_before_governance() {
  if [[ ${compose_owned} -ne 1 || ${ac16_constraint_owned} -ne 0 ]]; then
    echo "release Compose stack is not safe to retire before MCP governance" >&2
    return 1
  fi
  "${compose[@]}" unpause mysql >/dev/null 2>&1 || true
  "${compose[@]}" unpause redis >/dev/null 2>&1 || true
  wait_for_compose_services_healthy
  write_sanitized_compose_status
  "${compose[@]}" logs --no-color app nginx mcp-public-nginx \
    > "${runtime_root}/runtime-application.log" 2>&1
  "${compose[@]}" down --volumes --remove-orphans
  require_unused_compose_project
  compose_owned=0
}

mysql_exec() {
  "${compose[@]}" exec -T mysql sh -ec \
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --batch --skip-column-names --raw --silent -uroot web_starter'
}

mysql_scalar() {
  local query_text="$1"
  local observed
  observed="$(mysql_exec <<< "${query_text}")"
  if [[ ! "${observed}" =~ ^[0-9]+$ ]]; then
    echo "release MySQL scalar query returned a non-numeric result" >&2
    return 1
  fi
  printf '%s' "${observed}"
}

cleanup() {
  local exit_code=$?
  local cleanup_failed=0
  set +e
  if [[ ${ac26_compose_owned} -eq 1 && -f "${ac26_runtime_env}" ]]; then
    # AC26 may fail after issuing a credential or before its final protocol
    # assertion. Keep raw logs private, then remove the entire dedicated stack
    # and its volumes so no credential, audit row, or fixture can leak into the
    # main release stack or a later run.
    "${ac26_compose[@]}" logs --no-color app nginx mcp-public-nginx \
      > "${runtime_root}/ac26-runtime-application.log" 2>&1
    "${ac26_compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 \
      || cleanup_failed=1
    require_unused_compose_project "${ac26_project_name}" >/dev/null 2>&1 \
      || cleanup_failed=1
  fi
  if [[ ${compose_owned} -eq 1 && -f "${runtime_env}" ]]; then
    if [[ ${ac16_constraint_owned} -eq 1 ]]; then
      if mysql_exec >/dev/null <<'SQL'
ALTER TABLE sys_operation_log DROP CHECK chk_webstarter_ac16_tx_audit;
SQL
      then
        ac16_constraint_owned=0
      else
        cleanup_failed=1
      fi
    fi
    "${compose[@]}" unpause mysql >/dev/null 2>&1 || true
    "${compose[@]}" unpause redis >/dev/null 2>&1 || true
    # Never publish the full Compose ps JSON: its Command field can contain
    # expanded database or Redis passwords. The allowlisted summary contains
    # service health metadata only.
    if [[ ${exit_code} -eq 0 ]]; then
      wait_for_compose_services_healthy || cleanup_failed=1
    fi
    write_sanitized_compose_status || cleanup_failed=1
    # Raw application and proxy logs may contain ephemeral protocol material on
    # exceptional paths. Keep them only inside the private runtime directory,
    # which is deleted below, and publish the sanitised status/metric reports.
    "${compose[@]}" logs --no-color app nginx mcp-public-nginx > "${runtime_root}/runtime-application.log" 2>&1
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || cleanup_failed=1
    require_unused_compose_project >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "${run_release_runtime_test_reports_formal}" == "true" \
      && -d "${release_runtime_reports_raw_root}" \
      && ! -L "${release_runtime_reports_raw_root}" ]]; then
    # Formal raw reports intentionally survive under RUNNER_TEMP for the later
    # evidence gate, but never relax their private permissions on success or
    # failure. No raw path or content is copied into public diagnostics.
    chmod 700 "${release_runtime_reports_raw_root}" >/dev/null 2>&1 || cleanup_failed=1
    find "${release_runtime_reports_raw_root}" -maxdepth 1 -type f \
      -exec chmod 600 {} + >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "${run_credential_lifecycle_formal}" == "true" \
      && -d "${credential_lifecycle_raw_root}" \
      && ! -L "${credential_lifecycle_raw_root}" ]]; then
    chmod 700 "${credential_lifecycle_raw_root}" >/dev/null 2>&1 || cleanup_failed=1
    find "${credential_lifecycle_raw_root}" -maxdepth 1 -type f \
      -exec chmod 600 {} + >/dev/null 2>&1 || cleanup_failed=1
  fi
  find "${runtime_root}" -type f -exec chmod u+rw {} + 2>/dev/null
  rm -rf -- "${runtime_root}" || cleanup_failed=1
  if [[ ${cleanup_failed} -ne 0 && ${exit_code} -eq 0 ]]; then
    exit_code=1
  fi
  if [[ ${exit_code} -ne 0 ]]; then
    echo "FAIL release-runtime-acceptance; sanitised diagnostics are in ${artifact_root}" >&2
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

require_unused_compose_project() {
  local target_project="${1:-${project_name}}"
  local existing=""
  local filter="label=com.docker.compose.project=${target_project}"
  existing="$(docker container ls --all --quiet --filter "${filter}")" || {
    echo "cannot establish release acceptance container isolation" >&2
    return 1
  }
  if [[ -n "${existing}" ]]; then
    echo "release acceptance Compose project already owns containers" >&2
    return 1
  fi
  existing="$(docker volume ls --quiet --filter "${filter}")" || {
    echo "cannot establish release acceptance volume isolation" >&2
    return 1
  }
  if [[ -n "${existing}" ]]; then
    echo "release acceptance Compose project already owns volumes" >&2
    return 1
  fi
  existing="$(docker network ls --quiet --filter "${filter}")" || {
    echo "cannot establish release acceptance network isolation" >&2
    return 1
  }
  if [[ -n "${existing}" ]]; then
    echo "release acceptance Compose project already owns networks" >&2
    return 1
  fi
}

for runtime_artifact in \
  runtime-production-compose-policy.json \
  runtime-version-identity.json \
  operational-metrics-baseline.json \
  oauth-runtime.json \
  operational-metrics-runtime.json \
  unified-verify-summary.json \
  generated-module-runtime.json \
  release-runtime-acceptance.json \
  runtime-compose-ps.json; do
  if [[ -e "${artifact_root}/${runtime_artifact}" || -L "${artifact_root}/${runtime_artifact}" ]]; then
    echo "release runtime artifact already exists: ${runtime_artifact}" >&2
    exit 2
  fi
done
if [[ "${run_ac41_formal}" == "true" ]]; then
  for ac41_artifact in "${ac41_public_report}" "${ac41_public_checksum}"; do
    if [[ -e "${ac41_artifact}" || -L "${ac41_artifact}" ]]; then
      echo "release AC-41 artifact already exists: ${ac41_artifact}" >&2
      exit 2
    fi
  done
fi
if [[ "${run_mcp_crud_proof_formal}" == "true" ]]; then
  if [[ -e "${mcp_crud_public_summary}" || -L "${mcp_crud_public_summary}" ]]; then
    echo "release MCP CRUD summary artifact already exists" >&2
    exit 2
  fi
fi
if [[ "${run_credential_lifecycle_formal}" == "true" ]]; then
  if [[ -e "${credential_lifecycle_public_summary}" \
      || -L "${credential_lifecycle_public_summary}" ]]; then
    echo "release credential lifecycle summary artifact already exists" >&2
    exit 2
  fi
fi
if [[ "${run_mcp_tool_contract_formal}" == "true" ]]; then
  if [[ -e "${mcp_tool_contract_public_summary}" || -L "${mcp_tool_contract_public_summary}" ]]; then
    echo "release MCP Tool contract summary artifact already exists" >&2
    exit 2
  fi
fi
if [[ "${run_ac29_formal}" == "true" ]]; then
  if [[ -e "${ac29_public_report}" || -L "${ac29_public_report}" ]]; then
    echo "release AC-29 artifact already exists" >&2
    exit 2
  fi
fi

random_secret() {
  openssl rand -base64 48 | tr -d '\n'
}

rsa_private_der() {
  local source="$1"
  local target="$2"
  if openssl rsa -in "${source}" -traditional -outform DER \
      -out "${target}" >/dev/null 2>&1; then
    return
  fi
  # LibreSSL's rsa command already emits PKCS#1 and has no -traditional flag.
  openssl rsa -in "${source}" -outform DER -out "${target}" >/dev/null 2>&1
}

wait_for_http_status() {
  local url="$1"
  local expected="$2"
  local label="$3"
  local attempts=90
  local status=""
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
      --max-time 10 "${url}" 2>/dev/null || true)"
    if [[ "${status}" == "${expected}" ]]; then
      return
    fi
    sleep 1
  done
  echo "${label} expected HTTP ${expected}, last observed ${status:-none}" >&2
  return 1
}

copy_release_runtime_surefire_report() {
  local source_directory="$1"
  local report_name="$2"
  local started_at_epoch_ns="$3"
  python3 -B - \
    "${source_directory}" \
    "${release_runtime_reports_raw_root}" \
    "${report_name}" \
    "${started_at_epoch_ns}" \
    "${runtime_root}" <<'PY'
import os
from pathlib import Path
import stat
import sys
import time

playwright_name = "playwright-release-runtime.json"
public_name = "TEST-dev.webstarter.mcp.acceptance.McpSdkRuntimeIT.xml"
private_name = "TEST-dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT.xml"
expected_before = {
    public_name: {playwright_name},
    private_name: {playwright_name, public_name},
}
report_name = sys.argv[3]
if report_name not in expected_before:
    raise SystemExit("release runtime Surefire report name is not fixed")
try:
    started_at = int(sys.argv[4], 10)
except ValueError as exception:
    raise SystemExit("release runtime report start time is invalid") from exception
if started_at <= 0 or started_at > time.time_ns():
    raise SystemExit("release runtime report start time is invalid")

source_path = Path(sys.argv[1]).expanduser().absolute()
raw_path = Path(sys.argv[2]).expanduser().absolute()
runtime_root = Path(sys.argv[5]).resolve(strict=True)
for path, label in ((source_path, "Surefire"), (raw_path, "raw")):
    if path.is_symlink() or not path.is_dir():
        raise SystemExit(f"release runtime {label} directory must be real")
source = source_path.resolve(strict=True)
raw = raw_path.resolve(strict=True)
if source.parent != runtime_root:
    raise SystemExit("release runtime Surefire directory escaped the private runtime root")

directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
    | getattr(os, "O_NOFOLLOW", 0)
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
source_descriptor = os.open(source, directory_flags)
raw_descriptor = os.open(raw, directory_flags)
created = False
try:
    source_directory_metadata = os.fstat(source_descriptor)
    raw_directory_metadata = os.fstat(raw_descriptor)
    for metadata, label in (
        (source_directory_metadata, "Surefire"),
        (raw_directory_metadata, "raw"),
    ):
        if not stat.S_ISDIR(metadata.st_mode) \
                or stat.S_IMODE(metadata.st_mode) != 0o700 \
                or metadata.st_uid != os.geteuid():
            raise SystemExit(
                f"release runtime {label} directory must be owned mode 0700"
            )
    if set(os.listdir(source_descriptor)) != {report_name}:
        raise SystemExit(
            "release runtime Surefire directory contains a missing, .txt, or extra report"
        )
    if set(os.listdir(raw_descriptor)) != expected_before[report_name]:
        raise SystemExit("release runtime raw report inventory changed before copy")

    source_file = os.open(report_name, read_flags, dir_fd=source_descriptor)
    try:
        before_path = os.stat(
            report_name, dir_fd=source_descriptor, follow_symlinks=False
        )
        before = os.fstat(source_file)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or (before_path.st_dev, before_path.st_ino)
                != (before.st_dev, before.st_ino)
            or before.st_size <= 0
            or before.st_size > 8 * 1024 * 1024
            or before.st_mtime_ns < started_at
            or before.st_mtime_ns > time.time_ns() + 5_000_000_000
        ):
            raise SystemExit(
                "release runtime Surefire report is unsafe, stale, or future-dated"
            )
        chunks = []
        remaining = 8 * 1024 * 1024 + 1
        while remaining > 0:
            chunk = os.read(source_file, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(source_file)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            stat.S_IMODE(value.st_mode),
            value.st_uid,
            value.st_nlink,
        )
        if len(payload) != before.st_size or identity(before) != identity(after):
            raise SystemExit("release runtime Surefire report changed while being read")
    finally:
        os.close(source_file)

    target = os.open(report_name, write_flags, 0o600, dir_fd=raw_descriptor)
    created = True
    try:
        os.fchmod(target, 0o600)
        remaining_payload = memoryview(payload)
        while remaining_payload:
            written = os.write(target, remaining_payload)
            if written <= 0:
                raise SystemExit("release runtime raw report copy made no progress")
            remaining_payload = remaining_payload[written:]
        os.fsync(target)
        target_metadata = os.fstat(target)
        if not stat.S_ISREG(target_metadata.st_mode) \
                or stat.S_IMODE(target_metadata.st_mode) != 0o600 \
                or target_metadata.st_uid != os.geteuid() \
                or target_metadata.st_nlink != 1:
            raise SystemExit("release runtime copied report is not private")
    finally:
        os.close(target)
    if set(os.listdir(source_descriptor)) != {report_name} \
            or set(os.listdir(raw_descriptor)) \
                != expected_before[report_name] | {report_name}:
        raise SystemExit("release runtime report directories changed during copy")
    current_source = os.stat(report_name, dir_fd=source_descriptor, follow_symlinks=False)
    if identity(current_source) != identity(before):
        raise SystemExit("release runtime Surefire report changed after copy")
    copied = os.open(report_name, read_flags, dir_fd=raw_descriptor)
    try:
        copied_payload = b""
        while True:
            chunk = os.read(copied, 1024 * 1024)
            if not chunk:
                break
            copied_payload += chunk
        copied_metadata = os.fstat(copied)
        if copied_payload != payload or stat.S_IMODE(copied_metadata.st_mode) != 0o600:
            raise SystemExit("release runtime copied report differs from source")
    finally:
        os.close(copied)
except BaseException:
    if created:
        try:
            os.unlink(report_name, dir_fd=raw_descriptor)
        except OSError:
            pass
    raise
finally:
    os.close(source_descriptor)
    os.close(raw_descriptor)
PY
}

admin_password="$(random_secret)"
db_root_password="$(random_secret)"
db_password="$(random_secret)"
redis_password="$(random_secret)"
token_pepper="$(random_secret)"
credential_pepper="$(random_secret)"
credential_pepper_retiring="$(random_secret)"
management_password="$(random_secret)"
management_username="release_ops"

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj "/CN=${public_hostname}" \
  -addext "subjectAltName=DNS:${public_hostname}" \
  -keyout "${certificate_root}/tls.key" \
  -out "${certificate_root}/tls.crt" >/dev/null 2>&1
chmod 600 "${certificate_root}/tls.key" "${certificate_root}/tls.crt"
printf '127.0.0.1 %s %s\n' "${public_hostname}" "${private_mcp_hostname}" > "${hosts_file}"
chmod 600 "${hosts_file}"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "${oauth_active_private}" >/dev/null 2>&1
rsa_private_der "${oauth_active_private}" "${oauth_active_der}"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "${oauth_retiring_private}" >/dev/null 2>&1
rsa_private_der "${oauth_retiring_private}" "${oauth_retiring_der}"
chmod 600 "${oauth_active_private}" "${oauth_active_der}" \
  "${oauth_retiring_private}" "${oauth_retiring_der}"
python3 -B "${repository_root}/scripts/acceptance_jwk_set.py" \
  --active-private-der "${oauth_active_der}" \
  --retiring-private-der "${oauth_retiring_der}" \
  --active-kid "${oauth_active_kid}" \
  --retiring-kid "${oauth_retiring_kid}" \
  --retiring-retain-until-epoch-seconds "${oauth_retiring_retain_until}" \
  --output "${oauth_jwk_set}"

export RUNTIME_DB_PASSWORD="${db_password}"
export RUNTIME_DB_ROOT_PASSWORD="${db_root_password}"
export RUNTIME_REDIS_PASSWORD="${redis_password}"
export RUNTIME_TOKEN_PEPPER="${token_pepper}"
export RUNTIME_CREDENTIAL_PEPPER="${credential_pepper}"
export RUNTIME_CREDENTIAL_PEPPER_RETIRING="${credential_pepper_retiring}"
export RUNTIME_ADMIN_PASSWORD="${admin_password}"
export RUNTIME_MANAGEMENT_USERNAME="${management_username}"
export RUNTIME_MANAGEMENT_PASSWORD="${management_password}"
export RUNTIME_PUBLIC_URL="${public_url}"
export RUNTIME_PRIVATE_URL="${private_url}"
export RUNTIME_PUBLIC_HOSTNAME="${public_hostname}"
export RUNTIME_PRIVATE_MCP_HOSTNAME="${private_mcp_hostname}"
export RUNTIME_PRIVATE_PORT="${private_port}"
export RUNTIME_PUBLIC_PORT="${public_port}"
export RUNTIME_TLS_CERT="${certificate_root}/tls.crt"
export RUNTIME_TLS_KEY="${certificate_root}/tls.key"
export RUNTIME_OAUTH_JWK_SET_FILE="${oauth_jwk_set}"
export RUNTIME_OAUTH_ACTIVE_KID="${oauth_active_kid}"

python3 -B - "${runtime_env}" <<'PY'
from pathlib import Path
import os
import sys

target = Path(sys.argv[1])
names = [
    "WEB_STARTER_MYSQL_IMAGE", "WEB_STARTER_REDIS_IMAGE",
    "WEB_STARTER_APP_IMAGE", "WEB_STARTER_APP_DIGEST",
    "WEB_STARTER_NGINX_IMAGE", "WEB_STARTER_NGINX_DIGEST",
]
values = {name: os.environ[name] for name in names}
values.update({
    "WEB_STARTER_GIT_COMMIT": os.environ["GITHUB_SHA"],
    "WEB_STARTER_DB_USERNAME": "web_starter",
    "WEB_STARTER_DB_PASSWORD": os.environ["RUNTIME_DB_PASSWORD"],
    "WEB_STARTER_DB_ROOT_PASSWORD": os.environ["RUNTIME_DB_ROOT_PASSWORD"],
    "WEB_STARTER_REDIS_PASSWORD": os.environ["RUNTIME_REDIS_PASSWORD"],
    "WEB_STARTER_TOKEN_PEPPER": os.environ["RUNTIME_TOKEN_PEPPER"],
    "WEB_STARTER_CREDENTIAL_PEPPER": os.environ["RUNTIME_CREDENTIAL_PEPPER"],
    "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION": "release-v2",
    "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING": os.environ[
        "RUNTIME_CREDENTIAL_PEPPER_RETIRING"
    ],
    "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION": "release-v1",
    "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "release_admin",
    "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": os.environ["RUNTIME_ADMIN_PASSWORD"],
    "WEB_STARTER_BOOTSTRAP_ADMIN_DISPLAY_NAME": "系统管理员",
    "WEB_STARTER_MANAGEMENT_USERNAME": os.environ["RUNTIME_MANAGEMENT_USERNAME"],
    "WEB_STARTER_MANAGEMENT_PASSWORD": os.environ["RUNTIME_MANAGEMENT_PASSWORD"],
    "WEB_STARTER_OAUTH_ISSUER": os.environ["RUNTIME_PUBLIC_URL"],
    "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": os.environ["RUNTIME_PUBLIC_URL"] + "/mcp",
    "WEB_STARTER_OAUTH_RSA_JWK_SET": Path(os.environ["RUNTIME_OAUTH_JWK_SET_FILE"])
        .read_text(encoding="utf-8").strip(),
    "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": os.environ["RUNTIME_OAUTH_ACTIVE_KID"],
    "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "false",
    "WEB_STARTER_MCP_ALLOWED_HOSTS": (
        os.environ["RUNTIME_PUBLIC_HOSTNAME"] + ":" + os.environ["RUNTIME_PUBLIC_PORT"]
        + "," + os.environ["RUNTIME_PRIVATE_MCP_HOSTNAME"] + ":"
        + os.environ["RUNTIME_PRIVATE_PORT"]
    ),
    "WEB_STARTER_MCP_ALLOWED_ORIGINS": os.environ["RUNTIME_PUBLIC_URL"],
    "WEB_STARTER_HTTP_BIND_ADDRESS": "127.0.0.1",
    "WEB_STARTER_HTTP_PORT": os.environ["RUNTIME_PRIVATE_PORT"],
    "WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS": "127.0.0.1",
    "WEB_STARTER_PUBLIC_MCP_PORT": os.environ["RUNTIME_PUBLIC_PORT"],
    "WEB_STARTER_PUBLIC_TLS_CERT_FILE": os.environ["RUNTIME_TLS_CERT"],
    "WEB_STARTER_PUBLIC_TLS_KEY_FILE": os.environ["RUNTIME_TLS_KEY"],
    "WEB_STARTER_LOG_LEVEL": "INFO",
})
for name, value in values.items():
    if any(character in value for character in "\r\n\0"):
        raise SystemExit(f"unsafe multiline runtime value: {name}")
target.write_text("".join(f"{name}={value}\n" for name, value in values.items()), encoding="utf-8")
target.chmod(0o600)
PY
unset RUNTIME_DB_PASSWORD RUNTIME_DB_ROOT_PASSWORD RUNTIME_REDIS_PASSWORD
unset RUNTIME_TOKEN_PEPPER RUNTIME_CREDENTIAL_PEPPER RUNTIME_CREDENTIAL_PEPPER_RETIRING
unset RUNTIME_ADMIN_PASSWORD
unset RUNTIME_MANAGEMENT_USERNAME RUNTIME_MANAGEMENT_PASSWORD
unset RUNTIME_OAUTH_JWK_SET_FILE RUNTIME_OAUTH_ACTIVE_KID

python3 -B - "${management_override}" "${management_port}" <<'PY'
from pathlib import Path
import os
import sys

target = Path(sys.argv[1])
try:
    port = int(sys.argv[2])
except ValueError as error:
    raise SystemExit("management acceptance port must be numeric") from error
if port < 1024 or port > 65535:
    raise SystemExit("management acceptance port must be between 1024 and 65535")
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, (
        "services:\n"
        "  app:\n"
        "    ports:\n"
        f"      - \"127.0.0.1:{port}:8081\"\n"
    ).encode())
finally:
    os.close(descriptor)
PY

"${production_compose[@]}" config --quiet
"${compose[@]}" config --quiet
python3 -B "${repository_root}/scripts/production_compose_policy.py" \
  --compose-json <("${production_compose[@]}" config --format json) \
  --repository-root "${repository_root}" \
  --output "${artifact_root}/runtime-production-compose-policy.json"
require_unused_compose_project
compose_owned=1
"${compose[@]}" up -d --wait --wait-timeout 300

export WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL="${private_url}"
export WEB_STARTER_ACCEPTANCE_PRIVATE_MCP_BASE_URL="${private_mcp_url}"
export WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL="${public_url}"
export WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS="${public_hostname},${private_mcp_hostname}"
export WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS="127.0.0.1"
export WEB_STARTER_BROWSER_BASE_URL="${private_url}"
export WEB_STARTER_OAUTH_ACCEPTANCE_BASE_URL="${public_url}"
export WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME="release_admin"
export WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD="${admin_password}"
export WEB_STARTER_ACCEPTANCE_INSECURE_TLS="true"
export WEB_STARTER_PLAYWRIGHT_OUTPUT_DIR="${playwright_output}"
export WEB_STARTER_ACCEPTANCE_OAUTH_ACTIVE_KID="${oauth_active_kid}"
export WEB_STARTER_ACCEPTANCE_OAUTH_RETIRING_KID="${oauth_retiring_kid}"
export WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX="${mcp_crud_trace_prefix}"
python3 -B "${repository_root}/scripts/prepare_release_runtime_acceptance.py" \
  --repository-root "${repository_root}" \
  --output-directory "${credential_root}"
export WEB_STARTER_ACCEPTANCE_MANIFEST="${credential_root}/manifest.json"
export WEB_STARTER_OAUTH_ACCEPTANCE_MANIFEST="${credential_root}/manifest.json"
export WEB_STARTER_ACCEPTANCE_MANAGEMENT_USERNAME="${management_username}"
export WEB_STARTER_ACCEPTANCE_MANAGEMENT_PASSWORD="${management_password}"

app_container_id="$("${compose[@]}" ps -q app)"
nginx_container_id="$("${compose[@]}" ps -q nginx)"
mysql_container_id="$("${compose[@]}" ps -q mysql)"
redis_container_id="$("${compose[@]}" ps -q redis)"
python3 -B "${repository_root}/scripts/verify_runtime_identity.py" \
  --management-base-url "http://127.0.0.1:${management_port}" \
  --compose-project "${project_name}" \
  --app-container-id "${app_container_id}" \
  --nginx-container-id "${nginx_container_id}" \
  --mysql-container-id "${mysql_container_id}" \
  --redis-container-id "${redis_container_id}" \
  --app-reference "${WEB_STARTER_APP_IMAGE}@${WEB_STARTER_APP_DIGEST}" \
  --nginx-reference "${WEB_STARTER_NGINX_IMAGE}@${WEB_STARTER_NGINX_DIGEST}" \
  --mysql-reference "${WEB_STARTER_MYSQL_IMAGE}" \
  --redis-reference "${WEB_STARTER_REDIS_IMAGE}" \
  --expected-version "${WEB_STARTER_RELEASE_VERSION}" \
  --expected-commit "${GITHUB_SHA}" \
  --output "${artifact_root}/runtime-version-identity.json"

if [[ "${run_ac26_formal}" == "true" ]]; then
  # AC26 owns a second, fixed-name Compose project. It shares only immutable
  # image inputs with the main release stack; database, Redis, credentials,
  # signing material, ports, audit rows and cleanup are all isolated.
  ac26_initial_source="${ac26_key_root}/initial-source.json"
  ac26_initial_source_expiry="$(python3 -B -c 'import time; print(int(time.time()) + 3600)')"
  python3 -B "${ac26_candidate_root}/scripts/acceptance_jwk_set.py" \
    --active-private-der "${oauth_retiring_der}" \
    --retiring-private-der "${oauth_active_der}" \
    --active-kid "${ac26_old_kid}" \
    --retiring-kid "${ac26_new_kid}" \
    --retiring-retain-until-epoch-seconds "${ac26_initial_source_expiry}" \
    --output "${ac26_initial_source}"
  python3 -B - "${ac26_initial_source}" "${ac26_initial_jwk_set}" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
metadata = source.lstat()
if source.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
        or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("AC-26 initial key source must be a regular mode 0600 file")
document = json.loads(source.read_text(encoding="utf-8"))
keys = document.get("keys") if isinstance(document, dict) else None
if not isinstance(keys, list) or len(keys) != 2 or not isinstance(keys[0], dict):
    raise SystemExit("AC-26 initial key source is malformed")
payload = (json.dumps({"keys": [keys[0]]}, sort_keys=True, separators=(",", ":")) + "\n").encode()
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    if os.name == "posix":
        os.fchmod(descriptor, 0o600)
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY

  python3 -B - \
    "${runtime_env}" \
    "${ac26_initial_jwk_set}" \
    "${ac26_runtime_env}" \
    "${ac26_public_url}" \
    "${ac26_public_hostname}" \
    "${ac26_private_mcp_hostname}" \
    "${ac26_private_port}" \
    "${ac26_public_port}" \
    "${ac26_old_kid}" <<'PY'
import json
import os
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
ring = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
target = Path(sys.argv[3])
public_url = sys.argv[4]
public_hostname = sys.argv[5]
private_hostname = sys.argv[6]
private_port = sys.argv[7]
public_port = sys.argv[8]
active_kid = sys.argv[9]
values = {}
for line in source.read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit("base release environment is malformed")
    key, value = line.split("=", 1)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", key) is None or key in values:
        raise SystemExit("base release environment repeats or malforms a key")
    values[key] = value
values.update({
    "WEB_STARTER_OAUTH_ISSUER": public_url,
    "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": public_url + "/mcp",
    "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": "",
    "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": "",
    "WEB_STARTER_OAUTH_RSA_JWK_SET": json.dumps(
        ring, sort_keys=True, separators=(",", ":")
    ),
    "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": active_kid,
    "WEB_STARTER_MCP_ALLOWED_HOSTS": (
        f"{public_hostname}:{public_port},{private_hostname}:{private_port}"
    ),
    "WEB_STARTER_MCP_ALLOWED_ORIGINS": public_url,
    "WEB_STARTER_HTTP_BIND_ADDRESS": "127.0.0.1",
    "WEB_STARTER_HTTP_PORT": private_port,
    "WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS": "127.0.0.1",
    "WEB_STARTER_PUBLIC_MCP_PORT": public_port,
})
for name, value in values.items():
    if any(character in value for character in "\r\n\0"):
        raise SystemExit(f"unsafe multiline AC-26 runtime value: {name}")
payload = "".join(f"{name}={values[name]}\n" for name in sorted(values)).encode()
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    if os.name == "posix":
        os.fchmod(descriptor, 0o600)
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY
  python3 -B - "${ac26_management_override}" "${ac26_management_port}" <<'PY'
from pathlib import Path
import os
import sys

target = Path(sys.argv[1])
port = int(sys.argv[2])
payload = (
    "services:\n"
    "  app:\n"
    "    ports:\n"
    f"      - \"127.0.0.1:{port}:8081\"\n"
).encode()
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    if os.name == "posix":
        os.fchmod(descriptor, 0o600)
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY
  ac26_compose=(
    docker compose --env-file "${ac26_runtime_env}"
    -f "${ac26_candidate_root}/compose.production.yaml"
    -f "${ac26_management_override}"
    -p "${ac26_project_name}"
  )
  "${ac26_compose[@]}" config --quiet
  require_unused_compose_project "${ac26_project_name}"
  ac26_compose_owned=1
  "${ac26_compose[@]}" up -d --wait --wait-timeout 300

  export WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL="${ac26_private_url}"
  export WEB_STARTER_ACCEPTANCE_PRIVATE_MCP_BASE_URL="${ac26_private_mcp_url}"
  export WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL="${ac26_public_url}"
  export WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS="${ac26_public_hostname},${ac26_private_mcp_hostname}"
  export WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS="127.0.0.1"
  export WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME="release_admin"
  export WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD="${admin_password}"
  export WEB_STARTER_ACCEPTANCE_INSECURE_TLS="true"
  export WEB_STARTER_ACCEPTANCE_OAUTH_ACTIVE_KID="${ac26_old_kid}"
  export WEB_STARTER_ACCEPTANCE_OAUTH_RETIRING_KID="${ac26_new_kid}"
  export WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX="release-ac26-setup"
  python3 -B "${ac26_candidate_root}/scripts/prepare_release_runtime_acceptance.py" \
    --repository-root "${ac26_candidate_root}" \
    --output-directory "${ac26_credential_root}"

  ac26_retain_until="$(python3 -B -c 'import time; print(int(time.time()) + 90)')"
  python3 -B "${ac26_candidate_root}/scripts/acceptance_jwk_set.py" \
    --active-private-der "${oauth_active_der}" \
    --retiring-private-der "${oauth_retiring_der}" \
    --active-kid "${ac26_new_kid}" \
    --retiring-kid "${ac26_old_kid}" \
    --retiring-retain-until-epoch-seconds "${ac26_retain_until}" \
    --output "${ac26_rotated_jwk_set}"
  if [[ "${ac26_terminal_mode}" == "revocation" ]]; then
    python3 -B - "${ac26_rotated_jwk_set}" "${ac26_terminal_jwk_set}" <<'PY'
import json
import os
from pathlib import Path
import sys

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
keys = source.get("keys") if isinstance(source, dict) else None
if not isinstance(keys, list) or len(keys) != 2 or not isinstance(keys[1], dict):
    raise SystemExit("AC-26 rotated key ring is malformed")
keys[1]["rev"] = {"reason": "emergency-rotation-acceptance"}
payload = (json.dumps(source, sort_keys=True, separators=(",", ":")) + "\n").encode()
target = Path(sys.argv[2])
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    if os.name == "posix":
        os.fchmod(descriptor, 0o600)
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY
  fi

  ac26_identity_fields="${runtime_root}/ac26-runtime-identity.tsv"
  python3 -B - \
    "${artifact_root}/runtime-version-identity.json" \
    "${WEB_STARTER_RELEASE_VERSION}" \
    "${GITHUB_SHA}" > "${ac26_identity_fields}" <<'PY'
import json
from pathlib import Path
import re
import stat
import sys

path = Path(sys.argv[1])
metadata = path.lstat()
if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
        or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("AC-26 runtime identity must be a regular mode 0600 file")
document = json.loads(path.read_text(encoding="utf-8"))
if document.get("status") != "PASS" or document.get("release") != {
    "version": sys.argv[2], "gitCommit": sys.argv[3]
}:
    raise SystemExit("AC-26 runtime identity differs from the release")
images = document.get("images")
if not isinstance(images, dict):
    raise SystemExit("AC-26 runtime identity lacks images")
values = []
for name in ("app", "nginx"):
    image = images.get(name)
    if not isinstance(image, dict):
        raise SystemExit(f"AC-26 runtime identity lacks {name}")
    reference = image.get("reference")
    image_id = image.get("imageId")
    if not isinstance(reference, str) or re.fullmatch(
        r"[^\s@]+@sha256:[0-9a-f]{64}", reference
    ) is None or not isinstance(image_id, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_id
    ) is None:
        raise SystemExit(f"AC-26 runtime {name} identity is not immutable")
    values.extend((reference, image_id))
print("\t".join(values))
PY
  chmod 600 "${ac26_identity_fields}"
  IFS=$'\t' read -r \
    ac26_app_reference ac26_app_image_id \
    ac26_nginx_reference ac26_nginx_image_id \
    < "${ac26_identity_fields}"

  ac26_producer=(
    python3 -B "${ac26_candidate_root}/scripts/rehearse_jwks_rotation.py"
    --repository-root "${ac26_candidate_root}"
    --runtime-manifest "${ac26_credential_root}/manifest.json"
    --runtime-identity "${artifact_root}/runtime-version-identity.json"
    --compose-env-file "${ac26_runtime_env}"
    --compose-override "${ac26_management_override}"
    --compose-project "${ac26_project_name}"
    --trace-prefix "${ac26_trace_prefix}"
    --initial-jwk-set "${ac26_initial_jwk_set}"
    --rotated-jwk-set "${ac26_rotated_jwk_set}"
    --old-kid "${ac26_old_kid}"
    --new-kid "${ac26_new_kid}"
    --terminal-mode "${ac26_terminal_mode}"
    --max-wait-seconds 180
    --output-dir "${ac26_evidence_root}"
  )
  if [[ "${ac26_terminal_mode}" == "revocation" ]]; then
    ac26_producer+=(--terminal-jwk-set "${ac26_terminal_jwk_set}")
  fi
  "${ac26_producer[@]}"

  python3 -B "${ac26_candidate_root}/scripts/validate_jwks_rotation_evidence.py" \
    --repository-root "${ac26_candidate_root}" \
    --evidence "${ac26_report}" \
    --runtime-identity "${artifact_root}/runtime-version-identity.json" \
    --expected-candidate-commit "${GITHUB_SHA}" \
    --expected-candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
    --expected-candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
    --expected-compose-project "${ac26_project_name}" \
    --expected-app-reference "${ac26_app_reference}" \
    --expected-app-image-id "${ac26_app_image_id}" \
    --expected-nginx-reference "${ac26_nginx_reference}" \
    --expected-nginx-image-id "${ac26_nginx_image_id}" \
    --expected-public-origin "${ac26_public_url}" \
    --expected-private-origin "${ac26_private_url}" \
    --expected-trace-prefix "${ac26_trace_prefix}" \
    --expected-terminal-mode "${ac26_terminal_mode}" \
    --summary-output "${ac26_raw_summary}"

  python3 -B - \
    "${artifact_root}" \
    "${ac26_raw_summary}" \
    "${ac26_public_summary}" \
    "${ac26_evidence_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

artifact_root = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2]).absolute()
target = Path(sys.argv[3]).absolute()
raw_path = Path(sys.argv[4]).absolute()
if raw_path.is_symlink():
    raise SystemExit("AC-26 raw evidence directory became a symbolic link")
raw_root = raw_path.resolve(strict=True)

source_parent = source.parent
parent_metadata = source_parent.lstat()
if source_parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode) \
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700 \
        or {entry.name for entry in source_parent.iterdir()} != {source.name}:
    raise SystemExit("AC-26 canonical summary must remain one file in a real 0700 directory")
source_metadata = source.lstat()
if source.is_symlink() or not stat.S_ISREG(source_metadata.st_mode) \
        or stat.S_IMODE(source_metadata.st_mode) != 0o600:
    raise SystemExit("AC-26 canonical summary must be a regular mode 0600 file")
source_snapshot = (
    source_metadata.st_dev, source_metadata.st_ino, source_metadata.st_size,
    source_metadata.st_mtime_ns, stat.S_IMODE(source_metadata.st_mode),
)
payload = source.read_bytes()

expected_raw_names = {
    "v2-ac26-jwks-rotation.json",
    "v2-ac26-jwks-rotation.json.sha256",
}
raw_metadata = raw_root.lstat()
if not stat.S_ISDIR(raw_metadata.st_mode) or stat.S_IMODE(raw_metadata.st_mode) != 0o700 \
        or {entry.name for entry in raw_root.iterdir()} != expected_raw_names:
    raise SystemExit("AC-26 raw evidence must remain the exact private two-file set")
raw_snapshots = {}
raw_payloads = {}
for name in expected_raw_names:
    raw_file = raw_root / name
    metadata = raw_file.lstat()
    if raw_file.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("AC-26 raw evidence files must be regular mode 0600 files")
    raw_snapshots[name] = (
        metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, stat.S_IMODE(metadata.st_mode),
    )
    raw_payloads[name] = raw_file.read_bytes()

public_parent = target.parent
if public_parent.exists():
    metadata = public_parent.lstat()
    if public_parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit("public acceptance artifact directory is unsafe")
else:
    public_parent.mkdir(mode=0o700)
if public_parent.resolve(strict=True).parent != artifact_root:
    raise SystemExit("public AC-26 summary must be a direct acceptance artifact")
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
    target_metadata = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(target_metadata.st_mode) \
            or stat.S_IMODE(target_metadata.st_mode) != 0o600 \
            or target.read_bytes() != payload:
        raise SystemExit("public AC-26 summary is not an exact private copy")
    current_source = source.lstat()
    if (
        current_source.st_dev, current_source.st_ino, current_source.st_size,
        current_source.st_mtime_ns, stat.S_IMODE(current_source.st_mode),
    ) != source_snapshot or source.read_bytes() != payload:
        raise SystemExit("AC-26 canonical summary changed during publication")
    for name in expected_raw_names:
        raw_file = raw_root / name
        metadata = raw_file.lstat()
        current = (
            metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, stat.S_IMODE(metadata.st_mode),
        )
        if current != raw_snapshots[name] or raw_file.read_bytes() != raw_payloads[name]:
            raise SystemExit("AC-26 raw evidence changed during publication")
except BaseException:
    target.unlink(missing_ok=True)
    raise
PY
  cmp -s "${ac26_raw_summary}" "${ac26_public_summary}"
  "${ac26_compose[@]}" down --volumes --remove-orphans
  require_unused_compose_project "${ac26_project_name}"
  ac26_compose_owned=0

  # Restore the main-stack environment before its browser, OAuth and MCP
  # acceptance continues.
  export WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL="${private_url}"
  export WEB_STARTER_ACCEPTANCE_PRIVATE_MCP_BASE_URL="${private_mcp_url}"
  export WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL="${public_url}"
  export WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS="${public_hostname},${private_mcp_hostname}"
  export WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS="127.0.0.1"
  export WEB_STARTER_ACCEPTANCE_OAUTH_ACTIVE_KID="${oauth_active_kid}"
  export WEB_STARTER_ACCEPTANCE_OAUTH_RETIRING_KID="${oauth_retiring_kid}"
  export WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX="${mcp_crud_trace_prefix}"
fi

if [[ "${run_ac29_formal}" == "true" ]]; then
  ac29_identity_fields="${runtime_root}/ac29-runtime-identity.tsv"
  python3 -B - \
    "${artifact_root}/runtime-version-identity.json" \
    "${WEB_STARTER_APP_IMAGE}@${WEB_STARTER_APP_DIGEST}" \
    "${WEB_STARTER_RELEASE_VERSION}" \
    "${GITHUB_SHA}" > "${ac29_identity_fields}" <<'PY'
import json
from pathlib import Path
import re
import stat
import sys

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"runtime identity repeats field: {key}")
        result[key] = value
    return result

def reject_constant(value):
    raise SystemExit(f"runtime identity contains non-finite number: {value}")

path = Path(sys.argv[1])
metadata = path.lstat()
if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
        or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("runtime identity must be a regular mode 0600 file")
try:
    document = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("runtime identity is not strict UTF-8 JSON") from error
if document.get("schemaVersion") != 2 or document.get("status") != "PASS":
    raise SystemExit("runtime identity is not a schemaVersion 2 PASS document")
if document.get("release") != {"version": sys.argv[3], "gitCommit": sys.argv[4]}:
    raise SystemExit("runtime identity release differs from the candidate")
images = document.get("images")
if not isinstance(images, dict) or set(images) != {"app", "nginx", "mysql", "redis"}:
    raise SystemExit("runtime identity does not contain the exact four services")
app = images.get("app")
if not isinstance(app, dict) or set(app) != {
    "reference", "imageId", "ociVersion", "ociRevision"
}:
    raise SystemExit("runtime App image identity has unexpected fields")
reference = app.get("reference")
image_id = app.get("imageId")
if reference != sys.argv[2] or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", reference) is None:
    raise SystemExit("runtime App reference differs from the release digest")
if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
    raise SystemExit("runtime App image ID is invalid")
if app.get("ociVersion") != sys.argv[3] or app.get("ociRevision") != sys.argv[4]:
    raise SystemExit("runtime App OCI identity differs from the candidate")
print(f"{reference}\t{image_id}")
PY
  chmod 600 "${ac29_identity_fields}"
  IFS=$'\t' read -r ac29_app_reference ac29_app_image_id \
    < "${ac29_identity_fields}"

  (
    cd -- "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}"
    python3 -B "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}/scripts/rehearse_production_fail_fast.py" \
      --repository-root "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" \
      --image "${ac29_app_reference}" \
      --output-dir "${WEB_STARTER_AC29_EVIDENCE_DIR}" \
      --timeout-seconds 60
    python3 -B "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}/scripts/validate_production_fail_fast_evidence.py" \
      --repository-root "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" \
      --evidence "${ac29_raw_report}" \
      --expected-app-reference "${ac29_app_reference}" \
      --expected-app-image-id "${ac29_app_image_id}" \
      --require-pass
  )

  python3 -B - \
    "${artifact_root}" \
    "${ac29_raw_report}" \
    "${ac29_raw_checksum}" \
    "${ac29_public_report}" <<'PY'
from pathlib import Path
import hashlib
import os
import stat
import sys

artifact_root = Path(sys.argv[1]).resolve(strict=True)
raw_report = Path(sys.argv[2])
raw_checksum = Path(sys.argv[3])
public_report = Path(sys.argv[4])
if raw_report.parent != raw_checksum.parent:
    raise SystemExit("AC-29 raw report and checksum must be siblings")
raw_parent = raw_report.parent
parent_metadata = raw_parent.lstat()
if raw_parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode) \
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700:
    raise SystemExit("AC-29 raw evidence parent must remain a real mode 0700 directory")
if {entry.name for entry in raw_parent.iterdir()} != {raw_report.name, raw_checksum.name}:
    raise SystemExit("AC-29 raw evidence directory must contain exactly report and checksum")

source_metadata = {}
source_bytes = {}
for source in (raw_report, raw_checksum):
    metadata = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("AC-29 raw evidence files must be regular mode 0600 files")
    source_metadata[source] = (
        metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
        stat.S_IMODE(metadata.st_mode),
    )
    source_bytes[source] = source.read_bytes()
report_bytes = source_bytes[raw_report]
checksum_bytes = source_bytes[raw_checksum]
digest = hashlib.sha256(report_bytes).hexdigest()
if checksum_bytes != f"{digest}  {raw_report.name}\n".encode("ascii"):
    raise SystemExit("AC-29 raw checksum does not bind the report bytes")

public_parent = public_report.parent
if public_parent.exists():
    metadata = public_parent.lstat()
    if public_parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit("public acceptance artifact directory is unsafe")
else:
    public_parent.mkdir(mode=0o700)
if public_parent.resolve(strict=True).parent != artifact_root:
    raise SystemExit("public acceptance artifacts must be direct children of the artifact root")
descriptor = os.open(
    public_report,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(report_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    public_metadata = public_report.lstat()
    if public_report.is_symlink() or not stat.S_ISREG(public_metadata.st_mode) \
            or stat.S_IMODE(public_metadata.st_mode) != 0o600 \
            or public_report.read_bytes() != report_bytes:
        raise SystemExit("public AC-29 evidence copy is not exact and private")
    for source in (raw_report, raw_checksum):
        metadata = source.lstat()
        current = (
            metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
            stat.S_IMODE(metadata.st_mode),
        )
        if current != source_metadata[source] or source.read_bytes() != source_bytes[source]:
            raise SystemExit("AC-29 raw evidence changed while creating the public copy")
except BaseException:
    public_report.unlink(missing_ok=True)
    raise
PY
  cmp -s "${ac29_raw_report}" "${ac29_public_report}"
fi

python3 -B "${repository_root}/scripts/verify_operational_metrics.py" \
  --management-base-url "http://127.0.0.1:${management_port}" \
  --output "${artifact_root}/operational-metrics-baseline.json"

python3 -B "${repository_root}/scripts/verify_oauth_runtime.py" \
  --manifest "${credential_root}/manifest.json" \
  --output "${artifact_root}/oauth-runtime.json"

if [[ "${run_credential_lifecycle_formal}" == "true" ]]; then
  python3 -B "${credential_lifecycle_candidate_root}/scripts/rehearse_credential_lifecycle.py" \
    --repository-root "${credential_lifecycle_candidate_root}" \
    --manifest "${credential_root}/manifest.json" \
    --runtime-identity "${artifact_root}/runtime-version-identity.json" \
    --oauth-runtime-report "${artifact_root}/oauth-runtime.json" \
    --compose-file "${credential_lifecycle_candidate_root}/compose.production.yaml" \
    --compose-override "${management_override}" \
    --env-file "${runtime_env}" \
    --compose-project "${project_name}" \
    --output "${credential_lifecycle_report}"

  python3 -B "${credential_lifecycle_candidate_root}/scripts/validate_credential_lifecycle_evidence.py" \
    --report "${credential_lifecycle_report}" \
    --candidate-root "${credential_lifecycle_candidate_root}" \
    --runtime-identity "${artifact_root}/runtime-version-identity.json" \
    --oauth-runtime-report "${artifact_root}/oauth-runtime.json" \
    --compose-project "${project_name}" \
    --output "${credential_lifecycle_private_summary}"

  python3 -B - \
    "${credential_lifecycle_private_summary}" \
    "${credential_lifecycle_public_summary}" \
    "${artifact_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

source = Path(sys.argv[1]).resolve(strict=True)
target = Path(sys.argv[2]).absolute()
artifact_root = Path(sys.argv[3]).resolve(strict=True)
if source.is_symlink() or stat.S_IMODE(source.stat().st_mode) != 0o600:
    raise SystemExit("credential lifecycle canonical summary is not a private regular file")
parent = target.parent
if parent.exists():
    if parent.is_symlink() or not parent.is_dir():
        raise SystemExit("credential lifecycle public summary parent is unsafe")
else:
    parent.mkdir(mode=0o700)
if parent.resolve(strict=True).parent != artifact_root:
    raise SystemExit("credential lifecycle public summary must be in artifacts/acceptance")
payload = source.read_bytes()
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
except BaseException:
    target.unlink(missing_ok=True)
    raise
if target.read_bytes() != payload or stat.S_IMODE(target.stat().st_mode) != 0o600:
    target.unlink(missing_ok=True)
    raise SystemExit("credential lifecycle public summary copy differs")
PY
fi

keytool -importcert -noprompt -alias web-starter-release-runtime \
  -file "${certificate_root}/tls.crt" \
  -keystore "${truststore}" \
  -storetype PKCS12 \
  -storepass changeit >/dev/null
export JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=${truststore} -Djavax.net.ssl.trustStorePassword=changeit -Djdk.net.hosts.file=${hosts_file} -Dhttp.nonProxyHosts=${public_hostname}|${private_mcp_hostname}|localhost|127.*"
export WEB_STARTER_MCP_OWNER_ID
WEB_STARTER_MCP_OWNER_ID="$(python3 -c 'import json,os; print(json.load(open(os.environ["WEB_STARTER_ACCEPTANCE_MANIFEST"]))["ownerId"])')"
export WEB_STARTER_MCP_PROJECT_ID
WEB_STARTER_MCP_PROJECT_ID="$(python3 -c 'import json,os; print(json.load(open(os.environ["WEB_STARTER_ACCEPTANCE_MANIFEST"]))["projectId"])')"
export WEB_STARTER_MCP_TRACE_PREFIX="${WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX}"
export WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS="${generated_mcp_tools}"

# The browser AC39 gate queries the exact audit rows written by this official
# SDK CRUD run. Publish the frozen prefix explicitly and create the fixture
# before Playwright; otherwise the browser could only pass against stale data.
export WEB_STARTER_MCP_BASE_URL="${private_mcp_url}"
export WEB_STARTER_MCP_TOKEN_RESPONSE_FILE="${credential_root}/pat-crud.json"
mcp_crud_constraint_before="$(mysql_scalar \
  "SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema='web_starter' AND table_name='sys_operation_log' AND constraint_name='${mcp_crud_transaction_constraint}' AND constraint_type='CHECK';")"
if [[ "${mcp_crud_constraint_before}" != "0" ]]; then
  echo "AC-16 transaction fault constraint already exists before the isolated test" >&2
  exit 1
fi
mysql_exec >/dev/null <<'SQL'
ALTER TABLE sys_operation_log
  ADD CONSTRAINT chk_webstarter_ac16_tx_audit
  CHECK (NOT (
    trace_id = 'release-sdk-transaction-audit-failure'
    AND module = 'project'
    AND action = 'CREATE'
    AND result = 'SUCCESS'
  )) ENFORCED;
SQL
ac16_constraint_owned=1
mcp_crud_constraint_during="$(mysql_scalar \
  "SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema='web_starter' AND table_name='sys_operation_log' AND constraint_name='${mcp_crud_transaction_constraint}' AND constraint_type='CHECK' AND enforced='YES';")"
if [[ "${mcp_crud_constraint_during}" != "1" ]]; then
  echo "AC-16 transaction fault constraint was not installed exactly once" >&2
  exit 1
fi
mcp_crud_started_ns="$(python3 -B -c 'import time; print(time.time_ns())')"
set +e
(
  cd -- "${mcp_crud_candidate_root}"
  ./mvnw --batch-mode --no-transfer-progress \
    -pl web-starter-mcp -am \
    -Dtest=dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT \
    -Dweb-starter.mcp.surefire-reports-directory="${mcp_crud_proof_root}" \
    -Dsurefire.useFile=false \
    -Dsurefire.failIfNoSpecifiedTests=false test
)
mcp_crud_test_exit=$?
set -e
mysql_exec >/dev/null <<'SQL'
ALTER TABLE sys_operation_log DROP CHECK chk_webstarter_ac16_tx_audit;
SQL
ac16_constraint_owned=0
mcp_crud_constraint_after="$(mysql_scalar \
  "SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema='web_starter' AND table_name='sys_operation_log' AND constraint_name='${mcp_crud_transaction_constraint}';")"
if [[ "${mcp_crud_constraint_after}" != "0" ]]; then
  echo "AC-16 transaction fault constraint remains after the isolated test" >&2
  exit 1
fi
if [[ ${mcp_crud_test_exit} -ne 0 ]]; then
  echo "official MCP SDK CRUD acceptance failed after AC-16 fault cleanup" >&2
  exit "${mcp_crud_test_exit}"
fi

mcp_crud_transaction_key_hash="$(python3 -B - "${mcp_crud_transaction_key}" <<'PY'
import hashlib
import sys

print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest())
PY
)"
mcp_crud_failure_trace="${mcp_crud_trace_prefix}-transaction-audit-failure"
mcp_crud_success_trace="${mcp_crud_trace_prefix}-create-first"
mcp_crud_failed_project_rows="$(mysql_scalar \
  "SELECT COUNT(*) FROM biz_project WHERE code='${mcp_crud_transaction_project_code}';")"
mcp_crud_failed_operation_rows="$(mysql_scalar \
  "SELECT COUNT(*) FROM sys_operation_log WHERE trace_id='${mcp_crud_failure_trace}';")"
mcp_crud_failed_mcp_rows="$(mysql_scalar \
  "SELECT COUNT(*) FROM sys_mcp_call_log WHERE trace_id='${mcp_crud_failure_trace}';")"
mcp_crud_failed_mcp_expected_rows="$(mysql_scalar \
  "SELECT COUNT(*) FROM sys_mcp_call_log WHERE trace_id='${mcp_crud_failure_trace}' AND tool_name='project.create' AND result='FAILED' AND error_code='INTERNAL_ERROR' AND idempotency_key_hash='${mcp_crud_transaction_key_hash}' AND replayed=FALSE AND deleted=0;")"
mcp_crud_failed_idempotency_rows="$(mysql_scalar \
  "SELECT COUNT(*) FROM mcp_idempotency_record WHERE idempotency_key_hash='${mcp_crud_transaction_key_hash}';")"
mcp_crud_success_atomic_rows="$(mysql_scalar \
  "SELECT COUNT(*) FROM biz_project p JOIN sys_operation_log o ON o.resource_id=CAST(p.id AS CHAR) JOIN sys_mcp_call_log m ON m.trace_id=o.trace_id WHERE o.trace_id='${mcp_crud_success_trace}' AND o.module='project' AND o.action='CREATE' AND o.result='SUCCESS' AND o.deleted=0 AND m.tool_name='project.create' AND m.result='SUCCESS' AND m.error_code IS NULL AND m.replayed=FALSE AND m.deleted=0;")"
mcp_crud_transactional_tables="$(mysql_scalar \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='web_starter' AND table_name IN ('biz_project','sys_operation_log','sys_mcp_call_log','mcp_idempotency_record') AND engine='InnoDB';")"

python3 -B - \
  "${mcp_crud_transaction_receipt}" \
  "${mcp_crud_constraint_during}" \
  "${mcp_crud_constraint_after}" \
  "${mcp_crud_failed_project_rows}" \
  "${mcp_crud_failed_operation_rows}" \
  "${mcp_crud_failed_mcp_rows}" \
  "${mcp_crud_failed_mcp_expected_rows}" \
  "${mcp_crud_failed_idempotency_rows}" \
  "${mcp_crud_success_atomic_rows}" \
  "${mcp_crud_transactional_tables}" <<'PY'
from pathlib import Path
import os
import sys

target = Path(sys.argv[1]).absolute()
numeric = sys.argv[2:]
if len(numeric) != 9 or any(not value.isdigit() for value in numeric):
    raise SystemExit("AC-16 database observations must be canonical non-negative integers")
values = (
    ("schemaVersion", "1"),
    ("databaseName", "web_starter"),
    ("constraintName", "chk_webstarter_ac16_tx_audit"),
    ("failureTrace", "release-sdk-transaction-audit-failure"),
    ("failureProjectCode", "MCP_TX_ROLLBACK"),
    ("failureIdempotencyKeyHash", "b43c6f477a4e894c03e54c53fcba80207b2f8e9804bd7525af0be2a6608586a2"),
    ("successTrace", "release-sdk-create-first"),
    ("constraintRowsDuringFault", numeric[0]),
    ("constraintRowsAfterCleanup", numeric[1]),
    ("failedProjectRows", numeric[2]),
    ("failedOperationAuditRows", numeric[3]),
    ("failedMcpAuditRows", numeric[4]),
    ("failedMcpAuditExpectedRows", numeric[5]),
    ("failedIdempotencyRows", numeric[6]),
    ("successBusinessOperationMcpRows", numeric[7]),
    ("transactionalTableRows", numeric[8]),
)
payload = "".join(f"{key}={value}\n" for key, value in values).encode("utf-8")
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise SystemExit("AC-16 receipt write made no progress")
        remaining = remaining[written:]
finally:
    os.close(descriptor)
PY
chmod 600 "${mcp_crud_report}"
python3 -B "${mcp_crud_candidate_root}/scripts/create_mcp_crud_runtime_proof.py" \
  --repository-root "${mcp_crud_candidate_root}" \
  --report "${mcp_crud_report}" \
  --transaction-receipt "${mcp_crud_transaction_receipt}" \
  --output "${mcp_crud_proof}" \
  --candidate-commit "${GITHUB_SHA}" \
  --candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
  --candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
  --compose-project "${project_name}" \
  --trace-prefix "${WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX}" \
  --started-at-epoch-ns "${mcp_crud_started_ns}"

if [[ "${run_mcp_crud_proof_formal}" == "true" ]]; then
  python3 -B "${mcp_crud_candidate_root}/scripts/validate_mcp_crud_runtime_proof.py" \
    --repository-root "${mcp_crud_candidate_root}" \
    --proof "${mcp_crud_proof}" \
    --expected-candidate-commit "${GITHUB_SHA}" \
    --expected-candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
    --expected-candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
    --expected-compose-project "${project_name}" \
    --expected-trace-prefix "${mcp_crud_trace_prefix}" \
    --require-pass \
    --summary-output "${mcp_crud_summary_root}"

  python3 -B - \
    "${artifact_root}" \
    "${mcp_crud_raw_summary}" \
    "${mcp_crud_public_summary}" <<'PY'
from pathlib import Path
import os
import stat
import sys

artifact_root = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2])
target = Path(sys.argv[3])
metadata = source.lstat()
if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("MCP CRUD canonical summary is not a regular file")
if stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("MCP CRUD canonical summary must be mode 0600")
if stat.S_IMODE(source.parent.stat().st_mode) != 0o700:
    raise SystemExit("MCP CRUD canonical summary parent must remain mode 0700")
payload = source.read_bytes()
public_parent = target.parent
if public_parent.exists():
    if public_parent.is_symlink() or not public_parent.is_dir():
        raise SystemExit("public acceptance artifact directory is unsafe")
else:
    public_parent.mkdir(mode=0o700)
if public_parent.resolve(strict=True).parent != artifact_root:
    raise SystemExit("public MCP CRUD summary must be a direct acceptance artifact")
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
except BaseException:
    target.unlink(missing_ok=True)
    raise
if target.read_bytes() != payload:
    target.unlink(missing_ok=True)
    raise SystemExit("public MCP CRUD summary is not byte-identical to the validated summary")
PY
  cmp -s "${mcp_crud_raw_summary}" "${mcp_crud_public_summary}"
fi

if [[ "${run_mcp_tool_contract_formal}" == "true" ]]; then
  # AC33 is a separate official-SDK contract test, not a second CRUD proof run.
  # Its successful path removes the project it creates. If an assertion fails
  # before that removal, the EXIT trap still destroys this isolated Compose
  # project's volumes and verifies that no project resources remain.
  python3 -B - \
    "${credential_root}" \
    "${credential_root}/pat-crud.json" \
    "${mcp_tool_contract_proof_root}" <<'PY'
from pathlib import Path
import stat
import sys

credential_root = Path(sys.argv[1]).resolve(strict=True)
token_path = Path(sys.argv[2]).absolute()
proof_root = Path(sys.argv[3]).resolve(strict=True)
metadata = token_path.lstat()
if token_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("MCP Tool contract token response must be a regular private file")
if stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("MCP Tool contract token response must have mode 0600")
if token_path.resolve(strict=True).parent != credential_root:
    raise SystemExit("MCP Tool contract token response escaped the private credential root")
if token_path.resolve(strict=True).parent == proof_root or any(proof_root.iterdir()):
    raise SystemExit("MCP Tool contract raw proof must start empty and contain no token response")
PY
  export WEB_STARTER_MCP_BASE_URL="${private_mcp_url}"
  export WEB_STARTER_MCP_TOKEN_RESPONSE_FILE="${credential_root}/pat-crud.json"
  export WEB_STARTER_MCP_TRACE_PREFIX="${mcp_tool_contract_trace_prefix}"
  mcp_tool_contract_started_ns="$(python3 -B -c 'import time; print(time.time_ns())')"
  (
    cd -- "${mcp_tool_contract_candidate_root}"
    ./mvnw --batch-mode --no-transfer-progress \
      -pl web-starter-mcp -am \
      -Dtest=dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT \
      -Dweb-starter.mcp.surefire-reports-directory="${mcp_tool_contract_proof_root}" \
      -Dsurefire.useFile=false \
      -Dsurefire.failIfNoSpecifiedTests=false test
  )
  chmod 600 "${mcp_tool_contract_report}"
  python3 -B \
    "${mcp_tool_contract_candidate_root}/scripts/create_mcp_tool_contract_runtime_proof.py" \
    --repository-root "${mcp_tool_contract_candidate_root}" \
    --report "${mcp_tool_contract_report}" \
    --output "${mcp_tool_contract_proof}" \
    --candidate-commit "${GITHUB_SHA}" \
    --candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
    --candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
    --compose-project "${project_name}" \
    --trace-prefix "${mcp_tool_contract_trace_prefix}" \
    --started-at-epoch-ns "${mcp_tool_contract_started_ns}"
  python3 -B \
    "${mcp_tool_contract_candidate_root}/scripts/validate_mcp_tool_contract_runtime_proof.py" \
    --repository-root "${mcp_tool_contract_candidate_root}" \
    --proof "${mcp_tool_contract_proof}" \
    --expected-candidate-commit "${GITHUB_SHA}" \
    --expected-candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
    --expected-candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
    --expected-compose-project "${project_name}" \
    --expected-trace-prefix "${mcp_tool_contract_trace_prefix}" \
    --require-pass \
    --summary-output "${mcp_tool_contract_summary_root}"

  python3 -B - \
    "${artifact_root}" \
    "${mcp_tool_contract_raw_summary}" \
    "${mcp_tool_contract_public_summary}" \
    "${mcp_tool_contract_proof_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

artifact_root = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2]).absolute()
target = Path(sys.argv[3]).absolute()
raw_root = Path(sys.argv[4]).resolve(strict=True)

source_parent = source.parent
parent_metadata = source_parent.lstat()
if source_parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode) \
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700:
    raise SystemExit("MCP Tool contract canonical summary parent must be a real 0700 directory")
if {entry.name for entry in source_parent.iterdir()} != {source.name}:
    raise SystemExit("MCP Tool contract canonical summary directory must contain one exact file")
source_metadata = source.lstat()
if source.is_symlink() or not stat.S_ISREG(source_metadata.st_mode) \
        or stat.S_IMODE(source_metadata.st_mode) != 0o600:
    raise SystemExit("MCP Tool contract canonical summary must be a regular mode 0600 file")
source_snapshot = (
    source_metadata.st_dev,
    source_metadata.st_ino,
    source_metadata.st_size,
    source_metadata.st_mtime_ns,
    stat.S_IMODE(source_metadata.st_mode),
)
payload = source.read_bytes()

expected_raw_names = {
    "TEST-dev.webstarter.mcp.acceptance.McpSdkToolContractRuntimeIT.xml",
    "mcp-tool-contract-runtime-proof.properties",
}
raw_parent_metadata = raw_root.lstat()
if raw_root.is_symlink() or not stat.S_ISDIR(raw_parent_metadata.st_mode) \
        or stat.S_IMODE(raw_parent_metadata.st_mode) != 0o700 \
        or {entry.name for entry in raw_root.iterdir()} != expected_raw_names:
    raise SystemExit("MCP Tool contract raw proof must remain one exact private two-file set")
raw_snapshots = {}
raw_payloads = {}
for name in expected_raw_names:
    raw_file = raw_root / name
    metadata = raw_file.lstat()
    if raw_file.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("MCP Tool contract raw proof files must be regular mode 0600 files")
    raw_snapshots[name] = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        stat.S_IMODE(metadata.st_mode),
    )
    raw_payloads[name] = raw_file.read_bytes()

public_parent = target.parent
if public_parent.exists():
    metadata = public_parent.lstat()
    if public_parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit("public acceptance artifact directory is unsafe")
else:
    public_parent.mkdir(mode=0o700)
if public_parent.resolve(strict=True).parent != artifact_root:
    raise SystemExit("public MCP Tool contract summary must be a direct acceptance artifact")
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
    target_metadata = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(target_metadata.st_mode) \
            or stat.S_IMODE(target_metadata.st_mode) != 0o600 \
            or target.read_bytes() != payload:
        raise SystemExit("public MCP Tool contract summary is not an exact private copy")
    current_source = source.lstat()
    if (
        current_source.st_dev,
        current_source.st_ino,
        current_source.st_size,
        current_source.st_mtime_ns,
        stat.S_IMODE(current_source.st_mode),
    ) != source_snapshot or source.read_bytes() != payload:
        raise SystemExit("MCP Tool contract canonical summary changed during publication")
    for name in expected_raw_names:
        raw_file = raw_root / name
        metadata = raw_file.lstat()
        current = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            stat.S_IMODE(metadata.st_mode),
        )
        if current != raw_snapshots[name] or raw_file.read_bytes() != raw_payloads[name]:
            raise SystemExit("MCP Tool contract raw proof changed during publication")
except BaseException:
    target.unlink(missing_ok=True)
    raise
PY
  cmp -s "${mcp_tool_contract_raw_summary}" "${mcp_tool_contract_public_summary}"
  export WEB_STARTER_MCP_TRACE_PREFIX="${WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX}"
fi

release_runtime_reports_started_ns=""
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  release_runtime_reports_started_ns="$(python3 -B -c 'import time; print(time.time_ns())')"
  python3 -B - \
    "${release_runtime_reports_raw_root}" \
    "${release_runtime_playwright_report}" <<'PY'
import os
from pathlib import Path
import stat
import sys

raw_path = Path(sys.argv[1]).expanduser().absolute()
target = Path(sys.argv[2]).expanduser().absolute()
if raw_path.is_symlink() or not raw_path.is_dir():
    raise SystemExit("release runtime Playwright raw directory must be real")
raw = raw_path.resolve(strict=True)
if target.parent.resolve(strict=True) != raw \
        or target.name != "playwright-release-runtime.json" \
        or target.exists() or target.is_symlink():
    raise SystemExit("release runtime Playwright report target is unsafe")
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
directory = os.open(raw, flags)
created = False
try:
    metadata = os.fstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o700 \
            or metadata.st_uid != os.geteuid() \
            or os.listdir(directory):
        raise SystemExit(
            "release runtime Playwright raw directory must remain empty owned mode 0700"
        )
    output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target.name, output_flags, 0o600, dir_fd=directory)
    created = True
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if set(os.listdir(directory)) != {target.name}:
        raise SystemExit("release runtime Playwright report precreation changed raw inventory")
except BaseException:
    if created:
        try:
            os.unlink(target.name, dir_fd=directory)
        except OSError:
            pass
    raise
finally:
    os.close(directory)
PY
  export PLAYWRIGHT_JSON_OUTPUT_FILE="${release_runtime_playwright_report}"
  (
    cd "${release_runtime_reports_candidate_root}/web-starter-web"
    pnpm exec playwright test \
      e2e/release-runtime.spec.ts \
      e2e/frontend-quality-runtime.spec.ts \
      e2e/v1-management-runtime.spec.ts \
      --reporter=json
  )
  unset PLAYWRIGHT_JSON_OUTPUT_FILE
  python3 -B - \
    "${release_runtime_reports_raw_root}" \
    "${release_runtime_playwright_report}" \
    "${release_runtime_reports_started_ns}" <<'PY'
import os
from pathlib import Path
import stat
import sys
import time

raw = Path(sys.argv[1]).resolve(strict=True)
report = Path(sys.argv[2])
started_at = int(sys.argv[3], 10)
if report.parent.resolve(strict=True) != raw or report.is_symlink() or not report.is_file():
    raise SystemExit("release runtime Playwright reporter did not preserve its fixed target")
raw_metadata = raw.stat()
report_metadata = report.stat()
if stat.S_IMODE(raw_metadata.st_mode) != 0o700 \
        or raw_metadata.st_uid != os.geteuid() \
        or stat.S_IMODE(report_metadata.st_mode) != 0o600 \
        or report_metadata.st_uid != os.geteuid() \
        or report_metadata.st_nlink != 1 \
        or report_metadata.st_size <= 0 \
        or report_metadata.st_mtime_ns < started_at \
        or report_metadata.st_mtime_ns > time.time_ns() + 5_000_000_000 \
        or set(os.listdir(raw)) != {report.name}:
    raise SystemExit("release runtime Playwright report is unsafe, stale, or extra")
PY
else
  echo "release browser suite deferred to the single seven-layer verifier execution"
fi

generated_browser_count=0
while IFS=$'\t' read -r generated_artifact generated_browser_test generated_browser_title; do
  if [[ -z "${generated_artifact}" || -z "${generated_browser_test}" || -z "${generated_browser_title}" ]]; then
    echo "generated browser acceptance metadata is incomplete" >&2
    exit 1
  fi
  generated_web_root="${generated_browser_test%%/e2e/*}"
  generated_test_relative="${generated_browser_test#${generated_web_root}/}"
  generated_browser_report="${runtime_root}/generated-browser-${generated_browser_count}.json"
  (cd "${repository_root}/${generated_web_root}" && \
    PLAYWRIGHT_JSON_OUTPUT_FILE="${generated_browser_report}" \
      pnpm exec playwright test "${generated_test_relative}" --reporter=line,json)
  python3 -B - \
    "${generated_browser_report}" \
    "${generated_browser_title}" \
    "${repository_root}/${generated_browser_test}" \
    "${repository_root}/${generated_web_root}" <<'PY'
import json
from pathlib import Path
import sys

report_path = Path(sys.argv[1])
expected_title = sys.argv[2]
expected_file = Path(sys.argv[3]).resolve(strict=True)
web_root = Path(sys.argv[4]).resolve(strict=True)
if report_path.is_symlink() or not report_path.is_file():
    raise SystemExit("generated browser test did not create its private JSON report")
document = json.loads(report_path.read_text(encoding="utf-8"))
matched = []

def visit(suites):
    for suite in suites or []:
        for spec in suite.get("specs", []):
            if spec.get("title") == expected_title:
                matched.append(spec)
        visit(suite.get("suites", []))

visit(document.get("suites", []))
if len(matched) != 1:
    raise SystemExit("generated browser report does not contain exactly one expected test")
spec = matched[0]
reported_file = Path(spec.get("file", ""))
if not reported_file.is_absolute():
    # Playwright reports spec paths relative to the configured testDir. The
    # generated-module contract fixes that directory at <web-root>/e2e.
    reported_file = (web_root / "e2e" / reported_file).resolve(strict=True)
else:
    reported_file = reported_file.resolve(strict=True)
if reported_file != expected_file:
    raise SystemExit("generated browser report identifies a different source file")
tests = spec.get("tests", [])
if len(tests) != 1 or tests[0].get("expectedStatus") != "passed":
    raise SystemExit("generated browser report does not contain one expected passing test")
results = tests[0].get("results", [])
if len(results) != 1 or results[0].get("status") != "passed" or spec.get("ok") is not True:
    raise SystemExit("generated browser test was skipped, retried, or failed")
PY
  generated_browser_count=$((generated_browser_count + 1))
done < <(python3 -B "${repository_root}/scripts/generated_module_plan.py" \
  --repository-root "${repository_root}" --list-browser)
if [[ ${generated_browser_count} -ne ${generated_module_count} ]]; then
  echo "not every generated module executed its explicit browser runtime test" >&2
  exit 1
fi
python3 -B "${repository_root}/scripts/refresh_release_runtime_read_token.py" \
  --repository-root "${repository_root}" \
  --credential-directory "${credential_root}" \
  --manifest "${credential_root}/manifest.json" \
  --output "${refreshed_read_token}"
unset WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD

export WEB_STARTER_MCP_BASE_URL="${public_url}"
export WEB_STARTER_MCP_TOKEN_RESPONSE_FILE="${credential_root}/oauth-token.json"
export WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE="SERVICE_ACCOUNT"
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  (
    # This canonical report may claim the frozen seven-Tool inventory only
    # when the wider generated-module rehearsal cannot extend the expectation.
    unset WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS
    unset WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED
    export WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED=false
    cd "${release_runtime_reports_candidate_root}"
    ./mvnw --batch-mode --no-transfer-progress \
      -pl web-starter-mcp -am \
      -Dtest=dev.webstarter.mcp.acceptance.McpSdkRuntimeIT \
      -Dweb-starter.mcp.surefire-reports-directory="${release_runtime_sdk_public_reports}" \
      -Dsurefire.useFile=false \
      -Dsurefire.failIfNoSpecifiedTests=false test
  )
  copy_release_runtime_surefire_report \
    "${release_runtime_sdk_public_reports}" \
    "TEST-dev.webstarter.mcp.acceptance.McpSdkRuntimeIT.xml" \
    "${release_runtime_reports_started_ns}"
else
  "${repository_root}/mvnw" --batch-mode --no-transfer-progress \
    -pl web-starter-mcp -am \
    -Dtest=dev.webstarter.mcp.acceptance.McpSdkRuntimeIT \
    -Dsurefire.failIfNoSpecifiedTests=false test
fi
unset WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE

export WEB_STARTER_MCP_BASE_URL="${private_mcp_url}"
export WEB_STARTER_MCP_TOKEN_RESPONSE_FILE="${refreshed_read_token}"
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  (
    unset WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS
    unset WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED
    export WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED=false
    cd "${release_runtime_reports_candidate_root}"
    ./mvnw --batch-mode --no-transfer-progress \
      -pl web-starter-mcp -am \
      -Dtest=dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT \
      -Dweb-starter.mcp.surefire-reports-directory="${release_runtime_sdk_private_reports}" \
      -Dsurefire.useFile=false \
      -Dsurefire.failIfNoSpecifiedTests=false test
  )
  copy_release_runtime_surefire_report \
    "${release_runtime_sdk_private_reports}" \
    "TEST-dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT.xml" \
    "${release_runtime_reports_started_ns}"
else
  "${repository_root}/mvnw" --batch-mode --no-transfer-progress \
    -pl web-starter-mcp -am \
    -Dtest=dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT \
    -Dsurefire.failIfNoSpecifiedTests=false test
fi

if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  python3 -B \
    "${release_runtime_reports_candidate_root}/scripts/create_release_runtime_test_reports_proof.py" \
    --repository-root "${release_runtime_reports_candidate_root}" \
    --evidence-directory "${release_runtime_reports_raw_root}" \
    --candidate-commit "${GITHUB_SHA}" \
    --candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
    --candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
    --run-started-at-epoch-ns "${release_runtime_reports_started_ns}"

  python3 -B \
    "${release_runtime_reports_candidate_root}/scripts/validate_release_runtime_test_reports_proof.py" \
    --repository-root "${release_runtime_reports_candidate_root}" \
    --evidence-directory "${release_runtime_reports_raw_root}" \
    --expected-candidate-commit "${GITHUB_SHA}" \
    --expected-candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
    --expected-candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
    --expected-run-started-at-epoch-ns "${release_runtime_reports_started_ns}" \
    --require-pass \
    --summary-output "${release_runtime_reports_summary_root}"

  python3 -B - \
    "${artifact_root}" \
    "${release_runtime_reports_raw_root}" \
    "${release_runtime_reports_summary_root}" \
    "${release_runtime_reports_private_summary}" \
    "${release_runtime_reports_public_summary}" <<'PY'
import os
from pathlib import Path
import stat
import sys

artifact_root = Path(sys.argv[1]).resolve(strict=True)
raw_path = Path(sys.argv[2]).expanduser().absolute()
summary_path = Path(sys.argv[3]).expanduser().absolute()
source = Path(sys.argv[4]).expanduser().absolute()
target = Path(sys.argv[5]).expanduser().absolute()
for path, label in ((raw_path, "raw"), (summary_path, "summary")):
    if path.is_symlink() or not path.is_dir():
        raise SystemExit(f"release runtime reports {label} directory must be real")
raw = raw_path.resolve(strict=True)
summary = summary_path.resolve(strict=True)
expected_raw_names = {
    "playwright-release-runtime.json",
    "TEST-dev.webstarter.mcp.acceptance.McpSdkRuntimeIT.xml",
    "TEST-dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT.xml",
    "release-runtime-test-reports-proof.json",
}
if set(os.listdir(raw)) != expected_raw_names:
    raise SystemExit("release runtime reports raw directory is not the exact four-file set")
if set(os.listdir(summary)) != {source.name} \
        or source.name != "release-runtime-test-reports-summary.json" \
        or source.parent.resolve(strict=True) != summary:
    raise SystemExit("release runtime reports private summary inventory is invalid")

def snapshot(path: Path, maximum: int) -> tuple[tuple[int, ...], bytes]:
    if path.is_symlink() or not path.is_file():
        raise SystemExit("release runtime reports evidence file is not regular")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) \
                or stat.S_IMODE(before.st_mode) != 0o600 \
                or before.st_uid != os.geteuid() \
                or before.st_nlink != 1 \
                or before.st_size <= 0 or before.st_size > maximum:
            raise SystemExit("release runtime reports evidence file is not private")
        chunks = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            stat.S_IMODE(before.st_mode),
            before.st_uid,
            before.st_nlink,
        )
        current = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            stat.S_IMODE(after.st_mode),
            after.st_uid,
            after.st_nlink,
        )
        if len(payload) != before.st_size or identity != current:
            raise SystemExit("release runtime reports evidence changed while read")
        return identity, payload
    finally:
        os.close(descriptor)

raw_snapshots = {
    name: snapshot(raw / name, 8 * 1024 * 1024)
    for name in sorted(expected_raw_names)
}
source_snapshot, payload = snapshot(source, 1024 * 1024)
public_parent = target.parent
if public_parent.exists():
    if public_parent.is_symlink() or not public_parent.is_dir():
        raise SystemExit("public release runtime reports directory is unsafe")
else:
    public_parent.mkdir(mode=0o700)
if public_parent.resolve(strict=True).parent != artifact_root \
        or target.name != "release-runtime-test-reports-summary.json" \
        or target.exists() or target.is_symlink():
    raise SystemExit("public release runtime reports target is unsafe")
public_metadata = public_parent.stat()
if stat.S_IMODE(public_metadata.st_mode) != 0o700 \
        or public_metadata.st_uid != os.geteuid():
    raise SystemExit("public release runtime reports directory must be owned mode 0700")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
created = False
try:
    descriptor = os.open(target, flags, 0o600)
    created = True
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise SystemExit("public runtime reports copy made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if snapshot(target, 1024 * 1024)[1] != payload \
            or snapshot(source, 1024 * 1024) != (source_snapshot, payload):
        raise SystemExit("public runtime reports summary is not a byte-exact copy")
    for name, expected in raw_snapshots.items():
        if snapshot(raw / name, 8 * 1024 * 1024) != expected:
            raise SystemExit("release runtime reports raw evidence changed during publication")
    if set(os.listdir(raw)) != expected_raw_names \
            or set(os.listdir(summary)) != {source.name}:
        raise SystemExit("release runtime reports private inventories changed")
except BaseException:
    if created:
        target.unlink(missing_ok=True)
    raise
PY
  cmp -s \
    "${release_runtime_reports_private_summary}" \
    "${release_runtime_reports_public_summary}"
fi

generated_mcp_count=0
export WEB_STARTER_GENERATED_MCP_BASE_URL="${private_mcp_url}"
export WEB_STARTER_GENERATED_MCP_TOKEN_RESPONSE_FILE="${credential_root}/pat-crud.json"
while IFS=$'\t' read -r generated_artifact generated_runtime_test; do
  if [[ -z "${generated_artifact}" || -z "${generated_runtime_test}" ]]; then
    echo "generated MCP acceptance metadata is incomplete" >&2
    exit 1
  fi
  export WEB_STARTER_GENERATED_MCP_TRACE_PREFIX="release-generated-${generated_mcp_count}"
  generated_report="${repository_root}/${generated_artifact}/target/surefire-reports/TEST-${generated_runtime_test}.xml"
  generated_test_started_ns="$(python3 -B -c 'import time; print(time.time_ns())')"
  "${repository_root}/mvnw" --batch-mode --no-transfer-progress \
    -pl "${generated_artifact}" -am \
    -Dtest="${generated_runtime_test}" \
    -Dsurefire.failIfNoSpecifiedTests=false test
  python3 -B - \
    "${generated_report}" \
    "${generated_runtime_test}" \
    "${generated_test_started_ns}" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

report = Path(sys.argv[1])
expected_class = sys.argv[2]
started_ns = int(sys.argv[3])
if report.is_symlink() or not report.is_file():
    raise SystemExit("generated MCP RuntimeIT did not create its exact Surefire report")
if report.stat().st_mtime_ns < started_ns:
    raise SystemExit("generated MCP RuntimeIT Surefire report is stale")
root = ET.parse(report).getroot()
counts = {
    name: int(root.attrib.get(name, "-1"))
    for name in ("tests", "failures", "errors", "skipped")
}
if counts != {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}:
    raise SystemExit(f"generated MCP RuntimeIT result is not one passing test: {counts}")
cases = root.findall("testcase")
if len(cases) != 1 or cases[0].attrib.get("classname") != expected_class:
    raise SystemExit("generated MCP RuntimeIT report does not identify the expected class")
PY
  generated_mcp_count=$((generated_mcp_count + 1))
done < <(python3 -B "${repository_root}/scripts/generated_module_plan.py" \
  --repository-root "${repository_root}" --list-mcp)
unset WEB_STARTER_GENERATED_MCP_BASE_URL
unset WEB_STARTER_GENERATED_MCP_TOKEN_RESPONSE_FILE
unset WEB_STARTER_GENERATED_MCP_TRACE_PREFIX

if [[ ${generated_module_count} -gt 0 ]]; then
  python3 -B "${repository_root}/scripts/generated_module_plan.py" \
    --repository-root "${repository_root}" \
    --output "${generated_module_plan_after}"
  if ! cmp -s "${generated_module_plan}" "${generated_module_plan_after}"; then
    echo "generated module runtime sources changed during acceptance" >&2
    exit 1
  fi
  python3 -B - \
    "${generated_module_plan}" \
    "${generated_module_summary}" \
    "${generated_browser_count}" \
    "${generated_mcp_count}" <<'PY'
import json
import os
from pathlib import Path
import sys

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
modules = source["modules"]
browser_count = int(sys.argv[3])
mcp_count = int(sys.argv[4])
expected_mcp = sum(1 for module in modules if module["withMcp"])
if browser_count != len(modules) or mcp_count != expected_mcp:
    raise SystemExit("generated module runtime counts do not match the frozen plans")
sanitized = []
for module in modules:
    sanitized.append({
        "module": module["module"],
        "artifactId": module["artifactId"],
        "migrationSha256": module["migrationSha256"],
        "planSha256": module["planSha256"],
        "browserTestSha256": module["browserTestSha256"],
        "browserStatus": "PASS",
        "mcpRuntimeTestSha256": module.get("mcpRuntimeTestSha256"),
        "mcpStatus": "PASS" if module["withMcp"] else "NOT_REQUESTED",
    })
document = {"schemaVersion": 1, "status": "PASS", "modules": sanitized}
payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
descriptor = os.open(Path(sys.argv[2]), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY
fi

export WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD="${admin_password}"
export WEB_STARTER_MCP_BASE_URL="${private_mcp_url}"
export WEB_STARTER_MCP_TRACE_PREFIX="release-unified-verify"
export WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE="${refreshed_read_token}"
export WEB_STARTER_VERIFY_REFRESH_READ_TOKEN_OUTPUT="${unified_read_token}"
export WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE="${mcp_crud_proof}"
export WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX="${WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX}"
export WEB_STARTER_VERIFY_CANDIDATE_COMMIT="${GITHUB_SHA}"
export WEB_STARTER_VERIFY_CANDIDATE_VERSION="${WEB_STARTER_RELEASE_VERSION}"
export WEB_STARTER_VERIFY_CANDIDATE_TAG="${WEB_STARTER_RELEASE_TAG}"
export WEB_STARTER_VERIFY_COMPOSE_MODE="production"
if [[ "${run_release_runtime_test_reports_formal}" == "true" ]]; then
  export WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_DIR="${release_runtime_reports_raw_root}"
  export WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_STARTED_AT_EPOCH_NS="${release_runtime_reports_started_ns}"
fi
# The seven-layer verifier is a consumer of the already-created runtime. Its
# policy tests must not inherit formal orchestration controls or raw-evidence
# locations from this outer runner, otherwise their subprocess fixtures are
# stateful and can disagree with an otherwise identical direct policy run.
unset WEB_STARTER_RUN_AC41_FORMAL
unset WEB_STARTER_RUN_AC29_FORMAL
unset WEB_STARTER_RUN_AC26_FORMAL
unset WEB_STARTER_RUN_MCP_CRUD_PROOF_FORMAL
unset WEB_STARTER_RUN_MCP_TOOL_CONTRACT_FORMAL
unset WEB_STARTER_RUN_RELEASE_RUNTIME_TEST_REPORTS_FORMAL
unset WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL
unset WEB_STARTER_RUN_CREDENTIAL_LIFECYCLE_FORMAL
unset WEB_STARTER_RUN_OBSERVABILITY_FORMAL
unset WEB_STARTER_AC41_EVIDENCE_DIR
unset WEB_STARTER_AC29_EVIDENCE_DIR
unset WEB_STARTER_AC26_EVIDENCE_DIR
unset WEB_STARTER_MCP_CRUD_PROOF_DIR
unset WEB_STARTER_MCP_TOOL_CONTRACT_PROOF_DIR
unset WEB_STARTER_RELEASE_RUNTIME_TEST_REPORTS_DIR
unset WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR
unset WEB_STARTER_CREDENTIAL_LIFECYCLE_EVIDENCE_DIR
set +e
"${repository_root}/bin/web-starter" verify \
  --workspace "${repository_root}" \
  --env-file "${runtime_env}" \
  --project-name "${project_name}" \
  --evidence-dir "${unified_verify_evidence}"
unified_verify_exit=$?
set -e
if [[ ${unified_verify_exit} -ne 0 && -n "${unified_verify_failure_root}" ]]; then
  python3 -B - \
    "${unified_verify_evidence}" \
    "${unified_verify_failure_root}" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys

source = Path(sys.argv[1]).resolve(strict=True)
target = Path(sys.argv[2]).resolve(strict=True)
source_metadata = source.stat()
target_metadata = target.stat()
if source.is_symlink() or target.is_symlink() \
        or not stat.S_ISDIR(source_metadata.st_mode) \
        or not stat.S_ISDIR(target_metadata.st_mode) \
        or stat.S_IMODE(source_metadata.st_mode) != 0o700 \
        or stat.S_IMODE(target_metadata.st_mode) != 0o700 \
        or source_metadata.st_uid != os.geteuid() \
        or target_metadata.st_uid != os.geteuid() \
        or any(target.iterdir()):
    raise SystemExit("unified verify private failure directories are unsafe")
summary_path = source / "summary.json"
document = json.loads(summary_path.read_text(encoding="utf-8"))
layers = document.get("layers")
if not isinstance(layers, list):
    raise SystemExit("unified verify private summary has no layer inventory")
names = {"summary.json", "summary.md"}
for layer in layers:
    if not isinstance(layer, dict) or layer.get("status") != "FAIL":
        continue
    steps = layer.get("steps")
    if not isinstance(steps, list):
        raise SystemExit("failed unified verify layer has no step inventory")
    for step in steps:
        if not isinstance(step, dict) or step.get("status") != "FAIL":
            continue
        name = step.get("log")
        if not isinstance(name, str) or Path(name).name != name:
            raise SystemExit("failed unified verify log name is unsafe")
        names.add(name)
if names == {"summary.json", "summary.md"}:
    raise SystemExit("unified verify failure did not identify a failed step log")
for name in sorted(names):
    requested = source / name
    metadata = requested.lstat()
    if requested.is_symlink() or not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 \
            or metadata.st_uid != os.geteuid() \
            or metadata.st_nlink != 1 \
            or metadata.st_size <= 0 or metadata.st_size > 32 * 1024 * 1024:
        raise SystemExit("unified verify failed-step log is not a bounded private file")
    payload = requested.read_bytes()
    descriptor = os.open(
        target / name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if (target / name).read_bytes() != payload:
        raise SystemExit("unified verify private failure log copy differs")
PY
fi
unset WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD
unset WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE
unset WEB_STARTER_VERIFY_REFRESH_READ_TOKEN_OUTPUT
unset WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE
unset WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX
unset WEB_STARTER_VERIFY_CANDIDATE_COMMIT
unset WEB_STARTER_VERIFY_CANDIDATE_VERSION
unset WEB_STARTER_VERIFY_CANDIDATE_TAG
unset WEB_STARTER_VERIFY_COMPOSE_MODE
unset WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_DIR
unset WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_STARTED_AT_EPOCH_NS
unset WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS
unset WEB_STARTER_ACCEPTANCE_MCP_CRUD_TRACE_PREFIX

python3 -B - \
  "${unified_verify_evidence}/summary.json" \
  "${unified_verify_summary}" \
  "${unified_verify_exit}" <<'PY'
import json
import os
from pathlib import Path
import sys

expected_layers = {
    "backend", "frontend", "policy", "container", "browser", "oauth", "mcp"
}
allowed_statuses = {"PASS", "FAIL", "NOT_COVERED", "ENV_REQUIRED"}
def unique_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise SystemExit(f"unified verify JSON repeats field: {key}")
        document[key] = value
    return document

source = json.loads(
    Path(sys.argv[1]).read_text(encoding="utf-8"), object_pairs_hook=unique_object
)
if set(source) != {"schemaVersion", "generatedAt", "status", "layers"}:
    raise SystemExit("unified verify summary has unexpected fields")
if source["schemaVersion"] != 1 or not isinstance(source["layers"], list):
    raise SystemExit("unified verify summary has an unsupported schema")
layers = {}
for layer in source["layers"]:
    if not isinstance(layer, dict) or not isinstance(layer.get("name"), str):
        raise SystemExit("unified verify layer is invalid")
    name = layer["name"]
    status = layer.get("status")
    if name in layers or status not in allowed_statuses:
        raise SystemExit("unified verify layer status is invalid or duplicated")
    layers[name] = status
if set(layers) != expected_layers:
    raise SystemExit("unified verify summary is missing a required layer")
passed = all(status == "PASS" for status in layers.values())
expected_overall = "PASS" if passed else "INCOMPLETE_OR_FAILED"
if source["status"] != expected_overall or (int(sys.argv[3]) == 0) != passed:
    raise SystemExit("unified verify exit status disagrees with its layer evidence")
document = {
    "schemaVersion": 1,
    "status": expected_overall,
    "layers": {name: layers[name] for name in sorted(layers)},
}
payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
descriptor = os.open(Path(sys.argv[2]), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY
if [[ ${unified_verify_exit} -ne 0 ]]; then
  echo "unified seven-layer verify did not pass; see unified-verify-summary.json" >&2
  exit "${unified_verify_exit}"
fi

python3 -B "${repository_root}/scripts/verify_operational_metrics.py" \
  --management-base-url "http://127.0.0.1:${management_port}" \
  --baseline "${artifact_root}/operational-metrics-baseline.json" \
  --require-rate-limited \
  --require-structured-log \
  --compose-file "${repository_root}/compose.production.yaml" \
  --compose-override "${management_override}" \
  --env-file "${runtime_env}" \
  --compose-project "${project_name}" \
  --output "${artifact_root}/operational-metrics-runtime.json"
if [[ "${run_observability_formal}" == "true" ]]; then
  python3 -B "${observability_candidate_root}/scripts/validate_observability_evidence.py" \
    --baseline "${artifact_root}/operational-metrics-baseline.json" \
    --runtime "${artifact_root}/operational-metrics-runtime.json" \
    --candidate-root "${observability_candidate_root}" \
    --runtime-identity "${artifact_root}/runtime-version-identity.json" \
    --compose-project "${project_name}" \
    --release-tag "${WEB_STARTER_RELEASE_TAG}" \
    --output "${observability_private_summary}"

  python3 -B - \
    "${observability_private_summary}" \
    "${observability_public_summary}" \
    "${artifact_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

source = Path(sys.argv[1]).expanduser().absolute()
target = Path(sys.argv[2]).expanduser().absolute()
artifact = Path(sys.argv[3]).resolve(strict=True)
if source.is_symlink() or not source.is_file() or target.exists() or target.is_symlink():
    raise SystemExit("observability canonical summary paths are unsafe")
metadata = source.stat()
if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid():
    raise SystemExit("observability canonical summary is not private")
target_parent = target.parent.resolve(strict=True)
try:
    target_parent.relative_to(artifact)
except ValueError as error:
    raise SystemExit("observability public summary escaped artifacts") from error
payload = source.read_bytes()
descriptor = os.open(
    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
)
try:
    os.write(descriptor, payload)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if target.read_bytes() != payload or stat.S_IMODE(target.stat().st_mode) != 0o600:
    raise SystemExit("observability public summary differs from canonical bytes")
PY
fi
unset WEB_STARTER_ACCEPTANCE_MANAGEMENT_USERNAME
unset WEB_STARTER_ACCEPTANCE_MANAGEMENT_PASSWORD

"${compose[@]}" pause mysql
wait_for_http_status "${private_url}/actuator/health/readiness" 503 "MySQL outage readiness"
wait_for_http_status "${private_url}/actuator/health/liveness" 200 "MySQL outage liveness"
"${compose[@]}" unpause mysql
wait_for_http_status "${private_url}/actuator/health/readiness" 200 "MySQL recovery readiness"

"${compose[@]}" pause redis
wait_for_http_status "${private_url}/actuator/health/readiness" 503 "Redis outage readiness"
wait_for_http_status "${private_url}/actuator/health/liveness" 200 "Redis outage liveness"
"${compose[@]}" unpause redis
wait_for_http_status "${private_url}/actuator/health/readiness" 200 "Redis recovery readiness"

if [[ "${run_ac41_formal}" == "true" ]]; then
  ac41_identity_fields="${runtime_root}/ac41-runtime-identity.tsv"
  python3 -B - \
    "${artifact_root}/runtime-version-identity.json" \
    "${WEB_STARTER_RELEASE_VERSION}" \
    "${GITHUB_SHA}" > "${ac41_identity_fields}" <<'PY'
import json
from pathlib import Path
import re
import sys

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"runtime identity repeats field: {key}")
        result[key] = value
    return result

def reject_constant(value):
    raise SystemExit(f"runtime identity contains non-finite number: {value}")

try:
    document = json.loads(
        Path(sys.argv[1]).read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("runtime identity is not strict UTF-8 JSON") from error
if document.get("schemaVersion") != 2 or document.get("status") != "PASS":
    raise SystemExit("runtime identity is not a schemaVersion 2 PASS document")
images = document.get("images")
if not isinstance(images, dict) or set(images) != {"app", "nginx", "mysql", "redis"}:
    raise SystemExit("runtime identity does not contain the exact four services")
digest_reference = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
image_id = re.compile(r"^sha256:[0-9a-f]{64}$")
values = []
for service in ("app", "nginx", "mysql", "redis"):
    identity = images[service]
    if not isinstance(identity, dict):
        raise SystemExit(f"runtime {service} image identity is invalid")
    reference = identity.get("reference")
    identifier = identity.get("imageId")
    if not isinstance(reference, str) or digest_reference.fullmatch(reference) is None:
        raise SystemExit(f"runtime {service} reference is not digest-bound")
    if not isinstance(identifier, str) or image_id.fullmatch(identifier) is None:
        raise SystemExit(f"runtime {service} image ID is invalid")
    if service in {"app", "nginx"}:
        if (
            identity.get("ociVersion") != sys.argv[2]
            or identity.get("ociRevision") != sys.argv[3]
        ):
            raise SystemExit(f"runtime {service} OCI identity differs from the candidate")
    elif identity.get("ociVersion") is not None or identity.get("ociRevision") is not None:
        raise SystemExit(f"runtime {service} must not borrow candidate OCI identity")
    values.extend((reference, identifier))
print("\t".join(values))
PY
  chmod 600 "${ac41_identity_fields}"
  IFS=$'\t' read -r \
    ac41_app_reference ac41_app_image_id \
    ac41_nginx_reference ac41_nginx_image_id \
    ac41_mysql_reference ac41_mysql_image_id \
    ac41_redis_reference ac41_redis_image_id \
    < "${ac41_identity_fields}"

  WEB_STARTER_REHEARSAL_USERNAME="release_admin" \
  WEB_STARTER_REHEARSAL_PASSWORD="${admin_password}" \
  python3 -B "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}/scripts/rehearse_redis_loss.py" \
    --compose-project "${project_name}" \
    --confirm-project "${project_name}" \
    --compose-file "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}/compose.production.yaml" \
    --env-file "${runtime_env}" \
    --expected-database web_starter \
    --mode formal \
    --base-url "${public_url}" \
    --report-file "${ac41_raw_report}" \
    --expected-app-reference "${ac41_app_reference}" \
    --expected-app-image-id "${ac41_app_image_id}" \
    --expected-nginx-reference "${ac41_nginx_reference}" \
    --expected-nginx-image-id "${ac41_nginx_image_id}" \
    --expected-mysql-reference "${ac41_mysql_reference}" \
    --expected-mysql-image-id "${ac41_mysql_image_id}" \
    --expected-redis-reference "${ac41_redis_reference}" \
    --expected-redis-image-id "${ac41_redis_image_id}" \
    > "${runtime_root}/ac41-command-output.json"

  python3 -B "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}/scripts/validate_redis_loss_evidence.py" \
    --document "${ac41_raw_report}" \
    --repository-root "${WEB_STARTER_CANDIDATE_VALIDATION_ROOT}" \
    --expected-app-reference "${ac41_app_reference}" \
    --expected-app-image-id "${ac41_app_image_id}" \
    --expected-nginx-reference "${ac41_nginx_reference}" \
    --expected-nginx-image-id "${ac41_nginx_image_id}" \
    --expected-mysql-reference "${ac41_mysql_reference}" \
    --expected-mysql-image-id "${ac41_mysql_image_id}" \
    --expected-redis-reference "${ac41_redis_reference}" \
    --expected-redis-image-id "${ac41_redis_image_id}"

  python3 -B - \
    "${artifact_root}" \
    "${ac41_raw_report}" \
    "${ac41_raw_checksum}" \
    "${ac41_public_report}" \
    "${ac41_public_checksum}" <<'PY'
from pathlib import Path
import hashlib
import os
import stat
import sys

artifact_root = Path(sys.argv[1]).resolve(strict=True)
raw_report = Path(sys.argv[2])
raw_checksum = Path(sys.argv[3])
public_report = Path(sys.argv[4])
public_checksum = Path(sys.argv[5])
for source in (raw_report, raw_checksum):
    metadata = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("AC-41 raw evidence is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("AC-41 raw evidence files must be mode 0600")
if stat.S_IMODE(raw_report.parent.stat().st_mode) != 0o700:
    raise SystemExit("AC-41 raw evidence parent must remain mode 0700")
report_bytes = raw_report.read_bytes()
checksum_bytes = raw_checksum.read_bytes()
digest = hashlib.sha256(report_bytes).hexdigest()
if checksum_bytes != f"{digest}  {raw_report.name}\n".encode("ascii"):
    raise SystemExit("AC-41 raw checksum does not bind the report bytes")
public_parent = public_report.parent
if public_parent.exists():
    if public_parent.is_symlink() or not public_parent.is_dir():
        raise SystemExit("public acceptance artifact directory is unsafe")
else:
    public_parent.mkdir(mode=0o700)
if public_parent.resolve(strict=True).parent != artifact_root:
    raise SystemExit("public acceptance artifacts must be direct children of the artifact root")
if public_checksum.parent != public_parent:
    raise SystemExit("public AC-41 report and checksum must be siblings")
created = []
try:
    for target, payload in (
        (public_report, report_bytes),
        (public_checksum, checksum_bytes),
    ):
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created.append(target)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    if public_report.read_bytes() != report_bytes or public_checksum.read_bytes() != checksum_bytes:
        raise SystemExit("public AC-41 evidence is not byte-identical to the raw evidence")
except BaseException:
    for target in created:
        target.unlink(missing_ok=True)
    raise
PY
  cmp -s "${ac41_raw_report}" "${ac41_public_report}"
  cmp -s "${ac41_raw_checksum}" "${ac41_public_checksum}"
fi

if [[ "${run_mcp_governance_formal}" == "true" ]]; then
  # The governance proof owns a second full production stack. Retire the main
  # stack only after all of its browser, protocol, resilience and observability
  # evidence is complete, so the fixed 40-second restart SLO is measured
  # without unrelated release-stack resource contention.
  retire_main_stack_before_governance
  WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR="${mcp_governance_proof_root}" \
  WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT="${project_name}" \
  WEB_STARTER_AC26_COMPOSE_PROJECT="${ac26_project_name}" \
  bash "${repository_root}/scripts/run_mcp_governance_runtime_acceptance.sh" run
fi

python3 -B - \
  "${artifact_root}/release-runtime-acceptance.json" \
  "${artifact_root}/runtime-version-identity.json" \
  "${unified_verify_summary}" \
  "${project_name}" \
  "${mcp_crud_trace_prefix}" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

identity = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if identity.get("status") != "PASS":
    raise SystemExit("runtime version identity is not PASS")
unified_path = Path(sys.argv[3])
unified = json.loads(unified_path.read_text(encoding="utf-8"))
expected_layers = {
    name: "PASS"
    for name in ("backend", "browser", "container", "frontend", "mcp", "oauth", "policy")
}
if unified != {"schemaVersion": 1, "status": "PASS", "layers": expected_layers}:
    raise SystemExit("unified seven-layer verify summary is not PASS")
document = {
    "schemaVersion": 1,
    "status": "PASS",
    "observedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "release": {
        "tag": os.environ.get("WEB_STARTER_RELEASE_TAG", "local"),
        "version": os.environ.get("WEB_STARTER_RELEASE_VERSION", "local"),
        "gitCommit": os.environ.get("GITHUB_SHA", "local"),
    },
    "images": {
        "app": os.environ["WEB_STARTER_APP_IMAGE"] + "@" + os.environ["WEB_STARTER_APP_DIGEST"],
        "nginx": os.environ["WEB_STARTER_NGINX_IMAGE"] + "@" + os.environ["WEB_STARTER_NGINX_DIGEST"],
    },
    "identity": {
        "javaSpecificationVersion": identity["java"]["specificationVersion"],
        "applicationVersion": identity["actuator"]["applicationVersion"],
        "buildVersion": identity["actuator"]["buildVersion"],
        "composeProject": sys.argv[4],
        "mcpCrudTracePrefix": sys.argv[5],
        "appImage": identity["images"]["app"]["reference"],
        "nginxImage": identity["images"]["nginx"]["reference"],
        "appOciVersion": identity["images"]["app"]["ociVersion"],
        "appOciRevision": identity["images"]["app"]["ociRevision"],
        "nginxOciVersion": identity["images"]["nginx"]["ociVersion"],
        "nginxOciRevision": identity["images"]["nginx"]["ociRevision"],
    },
    "unifiedVerify": {
        "path": unified_path.name,
        "sha256": hashlib.sha256(unified_path.read_bytes()).hexdigest(),
        "status": unified["status"],
        "layers": unified["layers"],
    },
    "checks": {
        "runtimeVersionIdentity": "PASS",
        "emptyVolumesAndMigrations": "PASS",
        "privateBrowserProjectCrud": "PASS",
        "privateBrowserAccountSecurity": "PASS",
        "privateBrowserCredentialLifecycle": "PASS",
        "oauthPkce": "PASS",
        "oauthClientCredentials": "PASS",
        "oauthMultiKeyJwksActiveSigning": "PASS",
        "publicOperationsEndpointsHidden": "PASS",
        "patPrivatePublicBoundary": "PASS",
        "officialMcpSdkPublicOAuth": "PASS",
        "officialMcpSdkPrivatePat": "PASS",
        "officialMcpSdkCrudAudit": "PASS",
        "auditTraceSearchAndCorrelation": "PASS",
        "authenticatedOperationalMetrics": "PASS",
        "mysqlReadinessAndLiveness": "PASS",
        "redisReadinessAndLiveness": "PASS",
        "unifiedSevenLayerVerify": "PASS",
    },
}
payload = (json.dumps(document, indent=2) + "\n").encode()
descriptor = os.open(Path(sys.argv[1]), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY

echo "PASS release-runtime-acceptance: immutable empty-volume dual-ingress stack passed browser, OAuth and official MCP SDK gates"
