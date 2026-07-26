#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

mode="${1:-run}"
if [[ "${mode}" != "preflight" && "${mode}" != "run" ]]; then
  echo "MCP governance runner mode must be preflight or run" >&2
  exit 2
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
artifact_root="${WEB_STARTER_RELEASE_ARTIFACT_DIR:-${repository_root}/artifacts}"
proof_root="${WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR:-}"
candidate_root="${WEB_STARTER_CANDIDATE_VALIDATION_ROOT:-}"
project_name="${WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT:-}"
private_port="${WEB_STARTER_MCP_GOVERNANCE_PRIVATE_PORT:-38088}"
public_port="${WEB_STARTER_MCP_GOVERNANCE_PUBLIC_PORT:-38443}"
management_port="${WEB_STARTER_MCP_GOVERNANCE_MANAGEMENT_PORT:-38081}"
public_hostname="mcp.governance.webstarter.test"
private_hostname="mcp-private.governance.webstarter.test"
private_url="http://127.0.0.1:${private_port}"
private_mcp_url="http://${private_hostname}:${private_port}"
public_url="https://${public_hostname}:${public_port}"
trace_prefix="release-governance"
public_summary="${artifact_root}/acceptance/mcp-governance-runtime-summary.json"

require_value() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "MCP governance runtime acceptance requires ${name}" >&2
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

reject_ambient_governance_configuration() {
  local name
  local fixed_names=(
    WEB_STARTER_MCP_SESSION_ENABLED
    WEB_STARTER_MCP_SESSION_IDLE_TTL
    WEB_STARTER_MCP_SESSION_ABSOLUTE_TTL
    WEB_STARTER_MCP_SESSION_MAX_PER_SUBJECT
    WEB_STARTER_MCP_SESSION_RESERVATION_TTL
    WEB_STARTER_MCP_RATE_LIMIT_ENABLED
    WEB_STARTER_MCP_RATE_LIMIT_WINDOW
    WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_SUBJECT
    WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_CLIENT
    WEB_STARTER_MCP_RATE_LIMIT_MAX_READ
    WEB_STARTER_MCP_RATE_LIMIT_MAX_WRITE
    WEB_STARTER_MCP_RATE_LIMIT_MAX_DESTRUCTIVE
    WEB_STARTER_MCP_RATE_LIMIT_MAX_PROTOCOL
    WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR
    WEB_STARTER_MCP_GOVERNANCE_STATE_FILE
    WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX
    WEB_STARTER_MCP_GOVERNANCE_EXPECTED_VERSION
    WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT
    WEB_STARTER_GOVERNANCE_PRIVATE_BASE_URL
    WEB_STARTER_GOVERNANCE_PUBLIC_BASE_URL
    WEB_STARTER_GOVERNANCE_ADMIN_USERNAME
    WEB_STARTER_GOVERNANCE_ADMIN_PASSWORD
    WEB_STARTER_GOVERNANCE_OAUTH_ACTIVE_KID
    WEB_STARTER_REDIS_PASSWORD
  )
  for name in "${fixed_names[@]}"; do
    if [[ "${!name+x}" == "x" ]]; then
      echo "formal MCP governance rejects ambient ${name}" >&2
      exit 2
    fi
  done
  if [[ -n "${SSLKEYLOGFILE:-}" ]]; then
    echo "formal MCP governance requires SSLKEYLOGFILE to be unset" >&2
    exit 2
  fi
}

preflight() {
  require_value RUNNER_TEMP
  require_value WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR
  require_value WEB_STARTER_CANDIDATE_VALIDATION_ROOT
  require_value WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT
  require_value WEB_STARTER_RELEASE_TAG
  require_value WEB_STARTER_RELEASE_VERSION
  require_value GITHUB_SHA
  require_digest_reference WEB_STARTER_MYSQL_IMAGE
  require_digest_reference WEB_STARTER_REDIS_IMAGE
  require_image_parts WEB_STARTER_APP_IMAGE WEB_STARTER_APP_DIGEST
  require_image_parts WEB_STARTER_NGINX_IMAGE WEB_STARTER_NGINX_DIGEST
  reject_ambient_governance_configuration

  if [[ "${WEB_STARTER_RELEASE_TAG}" != "v${WEB_STARTER_RELEASE_VERSION}" ]]; then
    echo "MCP governance release tag must equal v plus release version" >&2
    exit 2
  fi

  python3 -B - \
    "${RUNNER_TEMP}" \
    "${proof_root}" \
    "${candidate_root}" \
    "${repository_root}" \
    "${artifact_root}" \
    "${public_summary}" \
    "${project_name}" \
    "${WEB_STARTER_RELEASE_TAG}" \
    "${WEB_STARTER_RELEASE_VERSION}" \
    "${GITHUB_SHA}" \
    "${private_port}" "${public_port}" "${management_port}" \
    "${WEB_STARTER_ACCEPTANCE_PRIVATE_PORT:-18088}" \
    "${WEB_STARTER_ACCEPTANCE_PUBLIC_PORT:-18443}" \
    "${WEB_STARTER_ACCEPTANCE_MANAGEMENT_PORT:-18081}" \
    "${WEB_STARTER_AC26_PRIVATE_PORT:-28088}" \
    "${WEB_STARTER_AC26_PUBLIC_PORT:-28443}" \
    "${WEB_STARTER_AC26_MANAGEMENT_PORT:-28081}" \
    "${WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT:-}" \
    "${WEB_STARTER_AC26_COMPOSE_PROJECT:-}" <<'PY'
from pathlib import Path
import os
import re
import stat
import subprocess
import sys

(
    runner_temp_arg, raw_arg, candidate_arg, repository_arg, artifact_arg,
    public_summary_arg, project, tag, version, commit, *remaining,
) = sys.argv[1:]

runner_temp_path = Path(runner_temp_arg).expanduser().absolute()
if runner_temp_path.is_symlink() or not runner_temp_path.is_dir():
    raise SystemExit("MCP governance RUNNER_TEMP must be a real directory")
runner_temp = runner_temp_path.resolve(strict=True)

raw_path = Path(raw_arg).expanduser().absolute()
if raw_path.is_symlink():
    raise SystemExit("MCP governance raw proof directory must not be a symbolic link")
raw = raw_path.resolve(strict=True)
raw_metadata = raw.stat()
if raw.parent != runner_temp:
    raise SystemExit("MCP governance raw proof must be an independent RUNNER_TEMP child directory")
if not stat.S_ISDIR(raw_metadata.st_mode) \
        or stat.S_IMODE(raw_metadata.st_mode) != 0o700 \
        or raw_metadata.st_uid != os.geteuid():
    raise SystemExit("MCP governance raw proof directory must be owned mode 0700")
if any(raw.iterdir()):
    raise SystemExit("MCP governance raw proof directory must start empty")

candidate_path = Path(candidate_arg).expanduser().absolute()
if candidate_path.is_symlink():
    raise SystemExit("MCP governance candidate root must not be a symbolic link")
candidate = candidate_path.resolve(strict=True)
candidate_metadata = candidate.stat()
if candidate.parent != runner_temp:
    raise SystemExit("MCP governance candidate root must be a RUNNER_TEMP child")
if candidate == raw or not stat.S_ISDIR(candidate_metadata.st_mode) \
        or stat.S_IMODE(candidate_metadata.st_mode) != 0o700 \
        or candidate_metadata.st_uid != os.geteuid():
    raise SystemExit("MCP governance candidate root must be a distinct owned mode-0700 directory")

repository = Path(repository_arg).resolve(strict=True)
artifact = Path(artifact_arg).expanduser().resolve(strict=False)
public_summary = Path(public_summary_arg).expanduser().absolute()
if raw == repository or repository in raw.parents or raw in repository.parents:
    raise SystemExit("MCP governance raw proof must stay outside the repository")
if raw == artifact or artifact in raw.parents or raw in artifact.parents:
    raise SystemExit("MCP governance raw proof must stay outside public artifacts")
if public_summary.name != "mcp-governance-runtime-summary.json" \
        or public_summary.parent.name != "acceptance" \
        or public_summary.parent.parent.resolve(strict=False) != artifact:
    raise SystemExit("MCP governance public summary path is not fixed")
if public_summary.exists() or public_summary.is_symlink():
    raise SystemExit("MCP governance public summary already exists")

if re.fullmatch(r"web-starter-governance-[a-z0-9][a-z0-9-]{0,39}", project) is None:
    raise SystemExit("formal MCP governance requires a web-starter-governance-* Compose project")
main_project, ac26_project = remaining[9:11]
if project in {value for value in (main_project, ac26_project) if value}:
    raise SystemExit("MCP governance Compose project must be distinct from other release stacks")

try:
    ports = [int(value) for value in remaining[:9]]
except ValueError as exception:
    raise SystemExit("MCP governance acceptance ports must be numeric") from exception
governance_ports, other_ports = ports[:3], ports[3:]
if any(port < 1024 or port > 65535 for port in governance_ports):
    raise SystemExit("MCP governance acceptance ports must be unprivileged TCP ports")
if len(set(governance_ports)) != 3 or set(governance_ports).intersection(other_ports):
    raise SystemExit("MCP governance ports must be unique and distinct from other release stacks")

if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", tag) is None \
        or tag != "v" + version or "SNAPSHOT" in version.upper():
    raise SystemExit("MCP governance candidate version or tag is invalid")
if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", commit) is None:
    raise SystemExit("MCP governance candidate commit is invalid")

required = (
    "compose.production.yaml",
    "mvnw",
    ".mvn/wrapper/maven-wrapper.properties",
    "pom.xml",
    "web-starter-mcp/pom.xml",
    "web-starter-web/package.json",
    "scripts/acceptance_jwk_set.py",
    "scripts/acceptance_network.py",
    "scripts/generated_module_plan.py",
    "scripts/prepare_mcp_governance_runtime.py",
    "scripts/prepare_release_runtime_acceptance.py",
    "scripts/v1_upgrade_refresh.py",
    "scripts/create_mcp_governance_runtime_proof.py",
    "scripts/validate_mcp_governance_runtime_proof.py",
    "scripts/orchestrate_mcp_governance_restart.py",
    "security/v2-ac34-ac35-mcp-governance-summary.schema.json",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/config/McpRateLimitProperties.java",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/config/McpSessionProperties.java",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/McpSessionShutdownCleanup.java",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/RedisMcpRateLimiter.java",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/governance/RedisMcpSessionRegistry.java",
    "web-starter-mcp/src/main/java/dev/webstarter/mcp/web/McpGovernanceFilter.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpGovernanceRuntimeSupport.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkGovernanceRuntimeIT.java",
    "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkGovernanceShutdownRuntimeIT.java",
)
if any((candidate / relative).is_symlink() or not (candidate / relative).is_file()
       for relative in required):
    raise SystemExit("MCP governance candidate lacks a fixed runtime source")
if not os.access(candidate / "mvnw", os.X_OK):
    raise SystemExit("MCP governance candidate Maven wrapper is not executable")

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
        ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
         "-C", str(candidate), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
        env=git_environment,
    )
    if completed.returncode != 0 or len(completed.stdout) > 16 * 1024 * 1024 \
            or len(completed.stderr) > 16 * 1024 * 1024:
        raise SystemExit("MCP governance candidate Git validation failed")
    return completed.stdout

def git_text(*arguments: str) -> str:
    value = git(*arguments).decode("utf-8", errors="strict").strip()
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise SystemExit("MCP governance candidate Git identity is malformed")
    return value

if Path(git_text("rev-parse", "--show-toplevel")).resolve(strict=True) != candidate \
        or git_text("rev-parse", "--verify", "HEAD^{commit}") != commit:
    raise SystemExit("MCP governance candidate root or HEAD differs")
if git_text("cat-file", "-t", f"refs/tags/{tag}") != "tag" \
        or git_text("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != commit:
    raise SystemExit("MCP governance candidate tag is not annotated at HEAD")
if git("status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
    raise SystemExit("MCP governance candidate worktree must be clean")
PY
}

preflight
if [[ "${mode}" == "preflight" ]]; then
  echo "PASS mcp-governance-runtime-preflight: isolated inputs are ready"
  exit 0
fi

runtime_root="$(mktemp -d "${RUNNER_TEMP}/web-starter-mcp-governance-runtime.XXXXXX")"
runtime_env="${runtime_root}/runtime.env"
management_override="${runtime_root}/management.override.yaml"
credential_root="${runtime_root}/credentials"
certificate_root="${runtime_root}/tls"
key_root="${runtime_root}/keys"
hosts_file="${runtime_root}/hosts"
active_private="${key_root}/active-private.pem"
active_der="${key_root}/active-private.der"
retiring_private="${key_root}/retiring-private.pem"
retiring_der="${key_root}/retiring-private.der"
jwk_set="${key_root}/jwk-set.json"
main_report_root="${runtime_root}/main-surefire"
shutdown_report_root="${runtime_root}/shutdown-surefire"
summary_root="${runtime_root}/summary"
state_file="${proof_root}/mcp-governance-shutdown-probe.properties"
restart_receipt="${proof_root}/mcp-governance-restart-receipt.json"
proof_file="${proof_root}/mcp-governance-runtime-proof.properties"
private_summary="${summary_root}/mcp-governance-runtime-proof-summary.json"
active_kid="release-governance-active"
retiring_kid="release-governance-retiring"
compose_owned=0
governance_compose=()
runtime_device=""
runtime_inode=""

run_with_timeout() {
  local timeout_seconds="$1"
  shift
  python3 -B - "${timeout_seconds}" "$@" <<'PY'
import os
import signal
import subprocess
import sys

process = None
forwarded_signal = None


class ForwardedSignal(RuntimeError):
    pass


def terminate_process_group() -> None:
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # Kill the whole session after the grace period even if the direct child
    # already exited: Maven/Compose descendants may still own the process group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise SystemExit(125)


def forward_signal(signum: int, _frame: object) -> None:
    global forwarded_signal
    forwarded_signal = signum
    if process is not None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    raise ForwardedSignal


handled_signals = tuple(
    value for value in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)
    if value is not None
)
previous_handlers = {
    value: signal.signal(value, forward_signal) for value in handled_signals
}
try:
    process = subprocess.Popen(
        sys.argv[2:],
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
except OSError as exception:
    for value, previous in previous_handlers.items():
        signal.signal(value, previous)
    raise SystemExit(f"could not start bounded command: {exception}") from exception
try:
    try:
        return_code = process.wait(timeout=float(sys.argv[1]))
    except subprocess.TimeoutExpired:
        terminate_process_group()
        raise SystemExit(124)
except ForwardedSignal:
    received = forwarded_signal
    for value in handled_signals:
        signal.signal(value, signal.SIG_IGN)
    terminate_process_group()
    if received is None:
        raise SystemExit(125)
    signal.signal(received, signal.SIG_DFL)
    os.kill(os.getpid(), received)
    raise SystemExit(128 + received)
except BaseException:
    for value in handled_signals:
        signal.signal(value, signal.SIG_IGN)
    terminate_process_group()
    raise
finally:
    if forwarded_signal is None:
        for value, previous in previous_handlers.items():
            signal.signal(value, previous)
raise SystemExit(return_code)
PY
}

require_unused_governance_project() {
  python3 -B - "${project_name}" <<'PY'
import subprocess
import sys

project = sys.argv[1]
label = "label=com.docker.compose.project=" + project
for resource in ("container", "volume", "network"):
    arguments = ["docker", resource, "ls"]
    if resource == "container":
        arguments.append("--all")
    arguments.extend(["--quiet", "--filter", label])
    completed = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit("cannot establish MCP governance Compose isolation")
    if completed.stdout.strip():
        raise SystemExit("MCP governance Compose project still owns " + resource + " resources")
PY
}

remove_private_runtime_root() {
  python3 -B - \
    "${RUNNER_TEMP}" \
    "${runtime_root}" \
    "${runtime_device}" \
    "${runtime_inode}" <<'PY'
from pathlib import Path
import os
import stat
import sys

runner_requested = Path(sys.argv[1]).expanduser().absolute()
runtime_requested = Path(sys.argv[2]).expanduser().absolute()
expected = (int(sys.argv[3]), int(sys.argv[4]))
if runner_requested.is_symlink() or runtime_requested.is_symlink():
    raise SystemExit("MCP governance private runtime path became a symbolic link")
runner = runner_requested.resolve(strict=True)
if runtime_requested.parent.resolve(strict=True) != runner \
        or not runtime_requested.name.startswith("web-starter-mcp-governance-runtime."):
    raise SystemExit("MCP governance private runtime root escaped RUNNER_TEMP")

directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
    | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
runner_descriptor = os.open(runner, directory_flags)
runtime_descriptor = None
entry_count = 0


def directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() \
            or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("MCP governance private runtime directory is unsafe")
    return metadata.st_dev, metadata.st_ino


def remove_contents(descriptor: int, root_device: int, depth: int = 0) -> None:
    global entry_count
    if depth > 32:
        raise SystemExit("MCP governance private runtime tree is too deep")
    for name in os.listdir(descriptor):
        entry_count += 1
        if entry_count > 10000 or not name or name in {".", ".."} \
                or "/" in name or "\0" in name:
            raise SystemExit("MCP governance private runtime inventory is unsafe")
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        entry_identity = (metadata.st_dev, metadata.st_ino)
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_dev != root_device or metadata.st_uid != os.geteuid():
                raise SystemExit("MCP governance private runtime crosses a filesystem boundary")
            child = os.open(name, directory_flags, dir_fd=descriptor)
            try:
                if directory_identity(child) != entry_identity:
                    raise SystemExit("MCP governance private runtime directory changed")
                remove_contents(child, root_device, depth + 1)
                os.fsync(child)
            finally:
                os.close(child)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) \
                    or (current.st_dev, current.st_ino) != entry_identity:
                raise SystemExit("MCP governance private runtime directory was replaced")
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


try:
    runtime_descriptor = os.open(
        runtime_requested.name, directory_flags, dir_fd=runner_descriptor)
    if directory_identity(runtime_descriptor) != expected:
        raise SystemExit("MCP governance private runtime root identity changed")
    remove_contents(runtime_descriptor, expected[0])
    os.fsync(runtime_descriptor)
finally:
    if runtime_descriptor is not None:
        os.close(runtime_descriptor)

current = os.stat(
    runtime_requested.name, dir_fd=runner_descriptor, follow_symlinks=False)
if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != expected:
    os.close(runner_descriptor)
    raise SystemExit("MCP governance private runtime root was replaced before removal")
os.rmdir(runtime_requested.name, dir_fd=runner_descriptor)
os.fsync(runner_descriptor)
os.close(runner_descriptor)
if runtime_requested.exists() or runtime_requested.is_symlink():
    raise SystemExit("MCP governance private runtime root still exists")
PY
}

cleanup() {
  local exit_code=$?
  local cleanup_failed=0
  trap - EXIT
  set +e
  if [[ ${compose_owned} -eq 1 && ${#governance_compose[@]} -gt 0 ]]; then
    run_with_timeout 120 "${governance_compose[@]}" down --volumes --remove-orphans \
      >/dev/null 2>&1 || cleanup_failed=1
    require_unused_governance_project >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ -n "${runtime_device}" && -n "${runtime_inode}" ]]; then
    remove_private_runtime_root >/dev/null 2>&1 || cleanup_failed=1
  else
    cleanup_failed=1
  fi
  if [[ ${cleanup_failed} -ne 0 && ${exit_code} -eq 0 ]]; then
    exit_code=1
  fi
  if [[ ${exit_code} -ne 0 ]]; then
    echo "FAIL mcp-governance-runtime-acceptance" >&2
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

runtime_identity="$(python3 -B - "${RUNNER_TEMP}" "${runtime_root}" <<'PY'
from pathlib import Path
import os
import stat
import sys

runner_requested = Path(sys.argv[1]).expanduser().absolute()
runtime_requested = Path(sys.argv[2]).expanduser().absolute()
if runner_requested.is_symlink() or runtime_requested.is_symlink():
    raise SystemExit("MCP governance private runtime root must not be a symbolic link")
runner = runner_requested.resolve(strict=True)
runtime = runtime_requested.resolve(strict=True)
metadata = runtime.stat()
if runtime.parent != runner or not stat.S_ISDIR(metadata.st_mode) \
        or stat.S_IMODE(metadata.st_mode) != 0o700 \
        or metadata.st_uid != os.geteuid():
    raise SystemExit("MCP governance private runtime root is not an owned RUNNER_TEMP child")
print(f"{metadata.st_dev}:{metadata.st_ino}")
PY
)"
runtime_device="${runtime_identity%%:*}"
runtime_inode="${runtime_identity##*:}"

mkdir -m 700 "${certificate_root}" "${key_root}" "${main_report_root}" \
  "${shutdown_report_root}" "${summary_root}"

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
  openssl rsa -in "${source}" -outform DER -out "${target}" >/dev/null 2>&1
}

admin_password="$(random_secret)"
db_root_password="$(random_secret)"
db_password="$(random_secret)"
redis_password="$(random_secret)"
token_pepper="$(random_secret)"
credential_pepper="$(random_secret)"
management_password="$(random_secret)"
management_username="governance_ops"

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj "/CN=${public_hostname}" \
  -addext "subjectAltName=DNS:${public_hostname}" \
  -keyout "${certificate_root}/tls.key" \
  -out "${certificate_root}/tls.crt" >/dev/null 2>&1
chmod 600 "${certificate_root}/tls.key" "${certificate_root}/tls.crt"
printf '127.0.0.1 %s %s\n' "${public_hostname}" "${private_hostname}" > "${hosts_file}"
chmod 600 "${hosts_file}"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "${active_private}" >/dev/null 2>&1
rsa_private_der "${active_private}" "${active_der}"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "${retiring_private}" >/dev/null 2>&1
rsa_private_der "${retiring_private}" "${retiring_der}"
chmod 600 "${active_private}" "${active_der}" "${retiring_private}" "${retiring_der}"
retiring_retain_until="$(python3 -B -c 'import time; print(int(time.time()) + 3600)')"
python3 -B "${candidate_root}/scripts/acceptance_jwk_set.py" \
  --active-private-der "${active_der}" \
  --retiring-private-der "${retiring_der}" \
  --active-kid "${active_kid}" \
  --retiring-kid "${retiring_kid}" \
  --retiring-retain-until-epoch-seconds "${retiring_retain_until}" \
  --output "${jwk_set}"

redis_reference="${WEB_STARTER_REDIS_IMAGE}"
app_reference="${WEB_STARTER_APP_IMAGE}@${WEB_STARTER_APP_DIGEST}"
nginx_reference="${WEB_STARTER_NGINX_IMAGE}@${WEB_STARTER_NGINX_DIGEST}"

export GOV_RUNTIME_DB_PASSWORD="${db_password}"
export GOV_RUNTIME_DB_ROOT_PASSWORD="${db_root_password}"
export GOV_RUNTIME_REDIS_PASSWORD="${redis_password}"
export GOV_RUNTIME_TOKEN_PEPPER="${token_pepper}"
export GOV_RUNTIME_CREDENTIAL_PEPPER="${credential_pepper}"
export GOV_RUNTIME_ADMIN_PASSWORD="${admin_password}"
export GOV_RUNTIME_MANAGEMENT_USERNAME="${management_username}"
export GOV_RUNTIME_MANAGEMENT_PASSWORD="${management_password}"
export GOV_RUNTIME_PUBLIC_URL="${public_url}"
export GOV_RUNTIME_PUBLIC_HOSTNAME="${public_hostname}"
export GOV_RUNTIME_PRIVATE_HOSTNAME="${private_hostname}"
export GOV_RUNTIME_PRIVATE_PORT="${private_port}"
export GOV_RUNTIME_PUBLIC_PORT="${public_port}"
export GOV_RUNTIME_TLS_CERT="${certificate_root}/tls.crt"
export GOV_RUNTIME_TLS_KEY="${certificate_root}/tls.key"
export GOV_RUNTIME_JWK_SET_FILE="${jwk_set}"
export GOV_RUNTIME_ACTIVE_KID="${active_kid}"

python3 -B - "${runtime_env}" <<'PY'
from pathlib import Path
import os
import stat
import sys

values = {
    "WEB_STARTER_MYSQL_IMAGE": os.environ["WEB_STARTER_MYSQL_IMAGE"],
    "WEB_STARTER_REDIS_IMAGE": os.environ["WEB_STARTER_REDIS_IMAGE"],
    "WEB_STARTER_APP_IMAGE": os.environ["WEB_STARTER_APP_IMAGE"],
    "WEB_STARTER_APP_DIGEST": os.environ["WEB_STARTER_APP_DIGEST"],
    "WEB_STARTER_NGINX_IMAGE": os.environ["WEB_STARTER_NGINX_IMAGE"],
    "WEB_STARTER_NGINX_DIGEST": os.environ["WEB_STARTER_NGINX_DIGEST"],
    "WEB_STARTER_GIT_COMMIT": os.environ["GITHUB_SHA"],
    "WEB_STARTER_DB_USERNAME": "web_starter",
    "WEB_STARTER_DB_PASSWORD": os.environ["GOV_RUNTIME_DB_PASSWORD"],
    "WEB_STARTER_DB_ROOT_PASSWORD": os.environ["GOV_RUNTIME_DB_ROOT_PASSWORD"],
    "WEB_STARTER_REDIS_PASSWORD": os.environ["GOV_RUNTIME_REDIS_PASSWORD"],
    "WEB_STARTER_TOKEN_PEPPER": os.environ["GOV_RUNTIME_TOKEN_PEPPER"],
    "WEB_STARTER_CREDENTIAL_PEPPER": os.environ["GOV_RUNTIME_CREDENTIAL_PEPPER"],
    "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION": "governance-v1",
    "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME": "governance_admin",
    "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD": os.environ["GOV_RUNTIME_ADMIN_PASSWORD"],
    "WEB_STARTER_BOOTSTRAP_ADMIN_DISPLAY_NAME": "Governance Administrator",
    "WEB_STARTER_MANAGEMENT_USERNAME": os.environ["GOV_RUNTIME_MANAGEMENT_USERNAME"],
    "WEB_STARTER_MANAGEMENT_PASSWORD": os.environ["GOV_RUNTIME_MANAGEMENT_PASSWORD"],
    "WEB_STARTER_OAUTH_ISSUER": os.environ["GOV_RUNTIME_PUBLIC_URL"],
    "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE": os.environ["GOV_RUNTIME_PUBLIC_URL"] + "/mcp",
    "WEB_STARTER_OAUTH_RSA_JWK_SET": Path(os.environ["GOV_RUNTIME_JWK_SET_FILE"])
        .read_text(encoding="utf-8").strip(),
    "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": os.environ["GOV_RUNTIME_ACTIVE_KID"],
    "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED": "false",
    "WEB_STARTER_INTERNAL_TOKENS_ENABLED": "true",
    "WEB_STARTER_MCP_ALLOWED_HOSTS": (
        os.environ["GOV_RUNTIME_PUBLIC_HOSTNAME"] + ":" + os.environ["GOV_RUNTIME_PUBLIC_PORT"]
        + "," + os.environ["GOV_RUNTIME_PRIVATE_HOSTNAME"] + ":"
        + os.environ["GOV_RUNTIME_PRIVATE_PORT"]
    ),
    "WEB_STARTER_MCP_ALLOWED_ORIGINS": os.environ["GOV_RUNTIME_PUBLIC_URL"],
    "WEB_STARTER_HTTP_BIND_ADDRESS": "127.0.0.1",
    "WEB_STARTER_HTTP_PORT": os.environ["GOV_RUNTIME_PRIVATE_PORT"],
    "WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS": "127.0.0.1",
    "WEB_STARTER_PUBLIC_MCP_PORT": os.environ["GOV_RUNTIME_PUBLIC_PORT"],
    "WEB_STARTER_PUBLIC_TLS_CERT_FILE": os.environ["GOV_RUNTIME_TLS_CERT"],
    "WEB_STARTER_PUBLIC_TLS_KEY_FILE": os.environ["GOV_RUNTIME_TLS_KEY"],
    "WEB_STARTER_MCP_SESSION_ENABLED": "true",
    "WEB_STARTER_MCP_SESSION_IDLE_TTL": "50s",
    "WEB_STARTER_MCP_SESSION_ABSOLUTE_TTL": "60s",
    "WEB_STARTER_MCP_SESSION_MAX_PER_SUBJECT": "2",
    "WEB_STARTER_MCP_SESSION_RESERVATION_TTL": "30s",
    "WEB_STARTER_MCP_RATE_LIMIT_ENABLED": "true",
    "WEB_STARTER_MCP_RATE_LIMIT_WINDOW": "15s",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_SUBJECT": "5",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_CLIENT": "5",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_READ": "5",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_WRITE": "5",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_DESTRUCTIVE": "1",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_PROTOCOL": "5",
    "WEB_STARTER_LOG_LEVEL": "INFO",
}
for name, value in values.items():
    if any(character in value for character in "\r\n\0"):
        raise SystemExit("unsafe multiline MCP governance runtime value: " + name)
target = Path(sys.argv[1])
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    payload = "".join(f"{name}={value}\n" for name, value in values.items()).encode()
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit("could not write the complete MCP governance runtime env")
        view = view[written:]
    os.fsync(descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 \
            or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 \
            or metadata.st_size != len(payload):
        raise SystemExit("MCP governance runtime env metadata is invalid")
finally:
    os.close(descriptor)
PY
unset GOV_RUNTIME_DB_PASSWORD GOV_RUNTIME_DB_ROOT_PASSWORD GOV_RUNTIME_REDIS_PASSWORD
unset GOV_RUNTIME_TOKEN_PEPPER GOV_RUNTIME_CREDENTIAL_PEPPER GOV_RUNTIME_ADMIN_PASSWORD
unset GOV_RUNTIME_MANAGEMENT_USERNAME GOV_RUNTIME_MANAGEMENT_PASSWORD
unset GOV_RUNTIME_PUBLIC_URL GOV_RUNTIME_PUBLIC_HOSTNAME GOV_RUNTIME_PRIVATE_HOSTNAME
unset GOV_RUNTIME_PRIVATE_PORT GOV_RUNTIME_PUBLIC_PORT GOV_RUNTIME_TLS_CERT GOV_RUNTIME_TLS_KEY
unset GOV_RUNTIME_JWK_SET_FILE GOV_RUNTIME_ACTIVE_KID

python3 -B - "${management_override}" "${management_port}" <<'PY'
from pathlib import Path
import os
import stat
import sys

port = int(sys.argv[2])
target = Path(sys.argv[1])
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    payload = (
        "services:\n"
        "  app:\n"
        "    ports:\n"
        f"      - \"127.0.0.1:{port}:8081\"\n"
        "    healthcheck:\n"
        "      test: [\"CMD\", \"curl\", \"-fsS\", \"http://127.0.0.1:8081/actuator/health/readiness\"]\n"
        "      interval: 1s\n"
        "      timeout: 2s\n"
        "      retries: 90\n"
        "      start_period: 1s\n"
    ).encode()
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit("could not write the complete MCP governance Compose override")
        view = view[written:]
    os.fsync(descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o600 \
            or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 \
            or metadata.st_size != len(payload):
        raise SystemExit("MCP governance Compose override metadata is invalid")
finally:
    os.close(descriptor)
PY

# Docker Compose gives exported shell variables precedence over --env-file.
# Remove every value owned by the private runtime file before resolving it.
while IFS='=' read -r compose_name _compose_value; do
  unset "${compose_name}"
done < "${runtime_env}"

governance_compose=(
  docker compose
  --env-file "${runtime_env}"
  -f "${candidate_root}/compose.production.yaml"
  -f "${management_override}"
  -p "${project_name}"
)

run_with_timeout 60 "${governance_compose[@]}" config --quiet
require_unused_governance_project
compose_owned=1
run_with_timeout 360 "${governance_compose[@]}" up -d --wait --wait-timeout 300

export WEB_STARTER_GOVERNANCE_PRIVATE_BASE_URL="${private_url}"
export WEB_STARTER_GOVERNANCE_PUBLIC_BASE_URL="${public_url}"
export WEB_STARTER_GOVERNANCE_ADMIN_USERNAME="governance_admin"
export WEB_STARTER_GOVERNANCE_ADMIN_PASSWORD="${admin_password}"
export WEB_STARTER_GOVERNANCE_OAUTH_ACTIVE_KID="${active_kid}"
export WEB_STARTER_ACCEPTANCE_INSECURE_TLS="true"
export WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS="${public_hostname},${private_hostname}"
export WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS="127.0.0.1"
run_with_timeout 180 python3 -B "${candidate_root}/scripts/prepare_mcp_governance_runtime.py" \
  --repository-root "${candidate_root}" \
  --output-directory "${credential_root}"
unset WEB_STARTER_GOVERNANCE_ADMIN_PASSWORD

app_container_id="$(run_with_timeout 30 "${governance_compose[@]}" ps -q app)"
redis_container_id="$(run_with_timeout 30 "${governance_compose[@]}" ps -q redis)"
nginx_container_id="$(run_with_timeout 30 "${governance_compose[@]}" ps -q nginx)"
public_nginx_container_id="$(
  run_with_timeout 30 "${governance_compose[@]}" ps -q mcp-public-nginx
)"
app_image_id="$(run_with_timeout 30 docker inspect --format '{{.Image}}' "${app_container_id}")"
redis_image_id="$(run_with_timeout 30 docker inspect --format '{{.Image}}' "${redis_container_id}")"
nginx_image_id="$(run_with_timeout 30 docker inspect --format '{{.Image}}' "${nginx_container_id}")"
public_nginx_image_id="$(
  run_with_timeout 30 docker inspect --format '{{.Image}}' "${public_nginx_container_id}"
)"
if [[ ! "${app_container_id}" =~ ^[0-9a-f]{64}$ \
    || ! "${redis_container_id}" =~ ^[0-9a-f]{64}$ \
    || ! "${nginx_container_id}" =~ ^[0-9a-f]{64}$ \
    || ! "${public_nginx_container_id}" =~ ^[0-9a-f]{64}$ \
    || "${nginx_container_id}" == "${public_nginx_container_id}" \
    || ! "${app_image_id}" =~ ^sha256:[0-9a-f]{64}$ \
    || ! "${redis_image_id}" =~ ^sha256:[0-9a-f]{64}$ \
    || ! "${nginx_image_id}" =~ ^sha256:[0-9a-f]{64}$ \
    || "${public_nginx_image_id}" != "${nginx_image_id}" ]]; then
  echo "MCP governance container image identity is invalid" >&2
  exit 1
fi

# Prewarm compilation before the shutdown probe clock starts. The post-restart
# Maven/Surefire launch is part of the fixed 45-second end-to-end observation
# window; the restart orchestrator must restore health within its first 40 seconds.
(
  cd -- "${candidate_root}"
  run_with_timeout 600 ./mvnw --batch-mode --no-transfer-progress \
    -pl web-starter-mcp -am \
    -DskipTests test-compile
)

export JAVA_TOOL_OPTIONS="-Djdk.net.hosts.file=${hosts_file} -Dhttp.nonProxyHosts=${public_hostname}|${private_hostname}|localhost|127.*"
export WEB_STARTER_MCP_BASE_URL="${private_mcp_url}"
export WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR="${credential_root}"
export WEB_STARTER_MCP_GOVERNANCE_STATE_FILE="${state_file}"
export WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX="${trace_prefix}"
export WEB_STARTER_MCP_GOVERNANCE_EXPECTED_VERSION="${WEB_STARTER_RELEASE_VERSION}"
export WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT="${GITHUB_SHA}"

main_started_ns="$(python3 -B -c 'import time; print(time.time_ns())')"
(
  cd -- "${candidate_root}"
  run_with_timeout 300 ./mvnw --batch-mode --no-transfer-progress \
    -pl web-starter-mcp -am \
    -Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT \
    -Dweb-starter.mcp.surefire-reports-directory="${main_report_root}" \
    -Dsurefire.useFile=false \
    -Dsurefire.failIfNoSpecifiedTests=false test
)
chmod 600 "${main_report_root}/TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT.xml"
(
  cd -- "${candidate_root}"
  python3 -B - \
    "${main_report_root}" \
    "TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT.xml" \
    "${proof_root}" <<'PY'
from pathlib import Path
import sys
from scripts.create_mcp_governance_runtime_proof import stage_surefire_report

stage_surefire_report(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
PY
)

restart_started_ns="$(python3 -B -c 'import time; print(time.time_ns())')"
WEB_STARTER_REDIS_PASSWORD="${redis_password}" \
run_with_timeout 120 python3 -B "${candidate_root}/scripts/orchestrate_mcp_governance_restart.py" \
  --repository-root "${candidate_root}" \
  --state-file "${state_file}" \
  --output "${restart_receipt}" \
  --compose-project "${project_name}" \
  --app-container-id "${app_container_id}" \
  --redis-container-id "${redis_container_id}" \
  --nginx-container-id "${nginx_container_id}" \
  --public-nginx-container-id "${public_nginx_container_id}" \
  --expected-app-image-id "${app_image_id}" \
  --expected-app-reference "${app_reference}" \
  --expected-redis-image-id "${redis_image_id}" \
  --expected-redis-reference "${redis_reference}" \
  --expected-nginx-image-id "${nginx_image_id}" \
  --expected-nginx-reference "${nginx_reference}" \
  --candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
  --candidate-commit "${GITHUB_SHA}" \
  --trace-prefix "${trace_prefix}"

(
  cd -- "${candidate_root}"
  run_with_timeout 120 ./mvnw --batch-mode --no-transfer-progress \
    -pl web-starter-mcp -am \
    -Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT \
    -Dweb-starter.mcp.surefire-reports-directory="${shutdown_report_root}" \
    -DforkCount=0 \
    -Dsurefire.useFile=false \
    -Dsurefire.failIfNoSpecifiedTests=false test
)
chmod 600 "${shutdown_report_root}/TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT.xml"
(
  cd -- "${candidate_root}"
  python3 -B - \
    "${shutdown_report_root}" \
    "TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT.xml" \
    "${proof_root}" <<'PY'
from pathlib import Path
import sys
from scripts.create_mcp_governance_runtime_proof import stage_surefire_report

stage_surefire_report(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
PY
)

run_with_timeout 120 python3 -B "${candidate_root}/scripts/create_mcp_governance_runtime_proof.py" \
  --repository-root "${candidate_root}" \
  --raw-directory "${proof_root}" \
  --output "${proof_file}" \
  --candidate-commit "${GITHUB_SHA}" \
  --candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
  --candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
  --compose-project "${project_name}" \
  --trace-prefix "${trace_prefix}" \
  --main-started-at-epoch-ns "${main_started_ns}" \
  --restart-started-at-epoch-ns "${restart_started_ns}"

run_with_timeout 120 python3 -B "${candidate_root}/scripts/validate_mcp_governance_runtime_proof.py" \
  --proof "${proof_file}" \
  --repository-root "${candidate_root}" \
  --expected-candidate-commit "${GITHUB_SHA}" \
  --expected-candidate-version "${WEB_STARTER_RELEASE_VERSION}" \
  --expected-candidate-tag "${WEB_STARTER_RELEASE_TAG}" \
  --expected-compose-project "${project_name}" \
  --expected-trace-prefix "${trace_prefix}" \
  --expected-app-reference "${app_reference}" \
  --expected-app-image-id "${app_image_id}" \
  --expected-nginx-reference "${nginx_reference}" \
  --expected-nginx-image-id "${nginx_image_id}" \
  --expected-redis-reference "${redis_reference}" \
  --expected-redis-image-id "${redis_image_id}" \
  --require-pass \
  --summary-output "${summary_root}"

run_with_timeout 120 "${governance_compose[@]}" down --volumes --remove-orphans
require_unused_governance_project
compose_owned=0

mkdir -p "${artifact_root}"
chmod 700 "${artifact_root}"
python3 -B - \
  "${artifact_root}" \
  "${proof_root}" \
  "${summary_root}" \
  "${private_summary}" \
  "${public_summary}" <<'PY'
from pathlib import Path
import os
import stat
import sys

artifact_requested = Path(sys.argv[1]).expanduser().absolute()
raw_requested = Path(sys.argv[2]).expanduser().absolute()
summary_requested = Path(sys.argv[3]).expanduser().absolute()
if any(path.is_symlink() for path in (artifact_requested, raw_requested, summary_requested)):
    raise SystemExit("MCP governance publication directories must not be symbolic links")
artifact = artifact_requested.resolve(strict=True)
raw = raw_requested.resolve(strict=True)
summary = summary_requested.resolve(strict=True)
source = Path(sys.argv[4]).expanduser().absolute()
target = Path(sys.argv[5]).expanduser().absolute()
expected_raw = {
    "TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT.xml",
    "TEST-dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT.xml",
    "mcp-governance-shutdown-probe.properties",
    "mcp-governance-restart-receipt.json",
    "mcp-governance-runtime-proof.properties",
}


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
        metadata.st_ctime_ns, stat.S_IMODE(metadata.st_mode), metadata.st_uid,
        metadata.st_nlink,
    )


def snapshot_descriptor(
    descriptor: int, maximum: int
) -> tuple[tuple[int, ...], bytes]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 \
            or before.st_uid != os.geteuid() or before.st_nlink != 1 \
            or before.st_size <= 0 or before.st_size > maximum:
        raise SystemExit("MCP governance evidence file is not private")
    payload = b""
    while len(payload) <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(payload)))
        if not chunk:
            break
        payload += chunk
    after = os.fstat(descriptor)
    if len(payload) != before.st_size or identity(before) != identity(after):
        raise SystemExit("MCP governance evidence changed while read")
    return identity(before), payload


def snapshot_at(
    directory: int, name: str, maximum: int
) -> tuple[tuple[int, ...], bytes]:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory,
    )
    try:
        return snapshot_descriptor(descriptor, maximum)
    finally:
        os.close(descriptor)


def owned_directory_identity(descriptor: int, label: str) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 \
            or metadata.st_uid != os.geteuid():
        raise SystemExit(label + " must be an owned mode-0700 directory")
    return metadata.st_dev, metadata.st_ino


def directory_path_matches(path: Path, expected: tuple[int, int]) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) \
        and not path.is_symlink() \
        and (metadata.st_dev, metadata.st_ino) == expected \
        and stat.S_IMODE(metadata.st_mode) == 0o700 \
        and metadata.st_uid == os.geteuid()


def directory_entry_matches(
    parent: int, name: str, expected: tuple[int, int]
) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) \
        and (metadata.st_dev, metadata.st_ino) == expected \
        and stat.S_IMODE(metadata.st_mode) == 0o700 \
        and metadata.st_uid == os.geteuid()


public_parent = target.parent
if source.name != "mcp-governance-runtime-proof-summary.json" \
        or source.parent.resolve(strict=False) != summary \
        or target.name != "mcp-governance-runtime-summary.json" \
        or public_parent.name != "acceptance" \
        or public_parent.parent.resolve(strict=False) != artifact:
    raise SystemExit("MCP governance summary source or target is unsafe")
directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
    | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
opened_descriptors = []
try:
    for path in (raw, summary, artifact):
        opened_descriptors.append(os.open(path, directory_flags))
except BaseException:
    for opened in reversed(opened_descriptors):
        os.close(opened)
    raise
raw_descriptor, summary_descriptor, artifact_descriptor = opened_descriptors
public_descriptor = None
created = False
created_identity = None
try:
    raw_identity = owned_directory_identity(raw_descriptor, "MCP governance raw proof")
    summary_identity = owned_directory_identity(
        summary_descriptor, "MCP governance private summary directory")
    artifact_identity = owned_directory_identity(
        artifact_descriptor, "MCP governance artifact root")
    if not directory_path_matches(raw, raw_identity) \
            or not directory_path_matches(summary, summary_identity) \
            or not directory_path_matches(artifact, artifact_identity):
        raise SystemExit("MCP governance publication directory identity changed")
    if set(os.listdir(raw_descriptor)) != expected_raw:
        raise SystemExit("MCP governance raw proof is not the exact five-file set")
    if set(os.listdir(summary_descriptor)) != {source.name}:
        raise SystemExit("MCP governance private summary inventory is invalid")
    raw_snapshots = {
        name: snapshot_at(raw_descriptor, name, 8 * 1024 * 1024)
        for name in expected_raw
    }
    source_snapshot = snapshot_at(summary_descriptor, source.name, 1024 * 1024)
    payload = source_snapshot[1]

    try:
        os.mkdir("acceptance", mode=0o700, dir_fd=artifact_descriptor)
        os.fsync(artifact_descriptor)
    except FileExistsError:
        pass
    public_descriptor = os.open("acceptance", directory_flags, dir_fd=artifact_descriptor)
    public_identity = owned_directory_identity(
        public_descriptor, "MCP governance public acceptance directory")
    if not directory_entry_matches(artifact_descriptor, "acceptance", public_identity) \
            or not directory_path_matches(artifact, artifact_identity) \
            or not directory_path_matches(public_parent, public_identity):
        raise SystemExit("MCP governance public acceptance directory identity changed")
    try:
        os.stat(target.name, dir_fd=public_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("MCP governance public summary target already exists")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target.name, flags, 0o600, dir_fd=public_descriptor)
    created = True
    try:
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        if not stat.S_ISREG(metadata.st_mode) \
                or stat.S_IMODE(metadata.st_mode) != 0o600 \
                or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 \
                or metadata.st_size != 0:
            raise SystemExit("MCP governance public summary reservation is invalid")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SystemExit("MCP governance public summary copy made no progress")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) \
                or stat.S_IMODE(metadata.st_mode) != 0o600 \
                or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 \
                or metadata.st_size != len(payload) \
                or (metadata.st_dev, metadata.st_ino) != created_identity:
            raise SystemExit("MCP governance public summary metadata is invalid")
    finally:
        os.close(descriptor)
    os.fsync(public_descriptor)

    if snapshot_at(public_descriptor, target.name, 1024 * 1024)[1] != payload \
            or snapshot_at(summary_descriptor, source.name, 1024 * 1024) != source_snapshot:
        raise SystemExit("MCP governance public summary is not byte-identical")
    for name, expected in raw_snapshots.items():
        if snapshot_at(raw_descriptor, name, 8 * 1024 * 1024) != expected:
            raise SystemExit("MCP governance raw proof changed during publication")
    if set(os.listdir(raw_descriptor)) != expected_raw \
            or set(os.listdir(summary_descriptor)) != {source.name}:
        raise SystemExit("MCP governance private inventories changed during publication")
    if not directory_path_matches(raw, raw_identity) \
            or not directory_path_matches(summary, summary_identity) \
            or not directory_path_matches(artifact, artifact_identity) \
            or not directory_entry_matches(artifact_descriptor, "acceptance", public_identity) \
            or not directory_path_matches(public_parent, public_identity):
        raise SystemExit("MCP governance publication directory changed during copy")
except BaseException:
    if created and public_descriptor is not None and created_identity is not None:
        try:
            current = os.stat(
                target.name, dir_fd=public_descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == created_identity:
                os.unlink(target.name, dir_fd=public_descriptor)
                os.fsync(public_descriptor)
        except FileNotFoundError:
            pass
    raise
finally:
    if public_descriptor is not None:
        os.close(public_descriptor)
    for opened in reversed(opened_descriptors):
        os.close(opened)
PY
cmp -s "${private_summary}" "${public_summary}"

echo "PASS mcp-governance-runtime-acceptance: isolated session, rate-limit and shutdown proof validated"
