from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


REJECTED_AMBIENT_NAMES = (
    "WEB_STARTER_MCP_SESSION_ENABLED",
    "WEB_STARTER_MCP_SESSION_IDLE_TTL",
    "WEB_STARTER_MCP_SESSION_ABSOLUTE_TTL",
    "WEB_STARTER_MCP_SESSION_MAX_PER_SUBJECT",
    "WEB_STARTER_MCP_SESSION_RESERVATION_TTL",
    "WEB_STARTER_MCP_RATE_LIMIT_ENABLED",
    "WEB_STARTER_MCP_RATE_LIMIT_WINDOW",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_SUBJECT",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_CLIENT",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_READ",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_WRITE",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_DESTRUCTIVE",
    "WEB_STARTER_MCP_RATE_LIMIT_MAX_PROTOCOL",
    "WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR",
    "WEB_STARTER_MCP_GOVERNANCE_STATE_FILE",
    "WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX",
    "WEB_STARTER_MCP_GOVERNANCE_EXPECTED_VERSION",
    "WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT",
    "WEB_STARTER_GOVERNANCE_PRIVATE_BASE_URL",
    "WEB_STARTER_GOVERNANCE_PUBLIC_BASE_URL",
    "WEB_STARTER_GOVERNANCE_ADMIN_USERNAME",
    "WEB_STARTER_GOVERNANCE_ADMIN_PASSWORD",
    "WEB_STARTER_GOVERNANCE_OAUTH_ACTIVE_KID",
    "WEB_STARTER_REDIS_PASSWORD",
    "SSLKEYLOGFILE",
)

REQUIRED_CANDIDATE_PATHS = (
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


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    return completed.stdout.strip()


def _candidate_fixture(candidate: Path, source_root: Path) -> str:
    candidate.mkdir(mode=0o700)
    for relative in REQUIRED_CANDIDATE_PATHS:
        source = source_root / relative
        target = candidate / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    (candidate / "mvnw").chmod(0o755)

    _git(candidate, "init", "-q")
    _git(candidate, "config", "user.email", "governance-preflight@example.invalid")
    _git(candidate, "config", "user.name", "Governance Preflight")
    _git(candidate, "add", "--all")
    _git(candidate, "commit", "-q", "-m", "candidate fixture")
    _git(candidate, "tag", "-a", "v2.0.0", "-m", "v2.0.0")
    commit = _git(candidate, "rev-parse", "HEAD^{commit}")
    _git(candidate, "checkout", "--detach", "-q", commit)
    candidate.chmod(0o700)
    return commit


def _environment(base: Path, commit: str) -> dict[str, str]:
    environment = os.environ.copy()
    for name in REJECTED_AMBIENT_NAMES:
        environment.pop(name, None)
    environment.update(
        {
            "RUNNER_TEMP": str(base / "runner-temp"),
            "WEB_STARTER_RELEASE_ARTIFACT_DIR": str(base / "artifacts"),
            "WEB_STARTER_MCP_GOVERNANCE_PROOF_DIR": str(
                base / "runner-temp" / "governance-raw"
            ),
            "WEB_STARTER_CANDIDATE_VALIDATION_ROOT": str(
                base / "runner-temp" / "candidate"
            ),
            "WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT": (
                "web-starter-governance-preflight"
            ),
            "WEB_STARTER_ACCEPTANCE_COMPOSE_PROJECT": "web-starter-release-preflight",
            "WEB_STARTER_AC26_COMPOSE_PROJECT": "web-starter-ac26-preflight",
            "WEB_STARTER_MYSQL_IMAGE": "registry.invalid/mysql@sha256:" + "1" * 64,
            "WEB_STARTER_REDIS_IMAGE": "registry.invalid/redis@sha256:" + "2" * 64,
            "WEB_STARTER_APP_IMAGE": "registry.invalid/web-starter",
            "WEB_STARTER_APP_DIGEST": "sha256:" + "3" * 64,
            "WEB_STARTER_NGINX_IMAGE": "registry.invalid/nginx",
            "WEB_STARTER_NGINX_DIGEST": "sha256:" + "4" * 64,
            "WEB_STARTER_RELEASE_TAG": "v2.0.0",
            "WEB_STARTER_RELEASE_VERSION": "2.0.0",
            "GITHUB_SHA": commit,
        }
    )
    return environment


def _fixture(base: Path, source_root: Path) -> tuple[dict[str, str], Path, Path]:
    runner_temp = base / "runner-temp"
    runner_temp.mkdir(mode=0o700)
    raw = runner_temp / "governance-raw"
    raw.mkdir(mode=0o700)
    candidate = runner_temp / "candidate"
    commit = _candidate_fixture(candidate, source_root)
    return _environment(base, commit), raw, candidate


def _preflight(
    source_root: Path, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            str(source_root / "scripts/run_mcp_governance_runtime_acceptance.sh"),
            "preflight",
        ],
        cwd=source_root,
        env=environment,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )


class McpGovernanceRuntimeRunnerTest(unittest.TestCase):
    def test_bash_syntax_and_fixed_formal_wiring(self) -> None:
        root = Path(__file__).resolve().parents[1]
        child_path = root / "scripts/run_mcp_governance_runtime_acceptance.sh"
        main_path = root / "scripts/run_release_runtime_acceptance.sh"
        for path in (child_path, main_path):
            result = subprocess.run(
                ["bash", "-n", str(path)],
                cwd=root,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)

        child = child_path.read_text(encoding="utf-8")
        main = main_path.read_text(encoding="utf-8")
        self.assertIn(
            'run_mcp_governance_formal="${WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL:-false}"',
            main,
        )
        self.assertEqual(
            1,
            main.count(
                'bash "${repository_root}/scripts/run_mcp_governance_runtime_acceptance.sh" preflight'
            ),
        )
        self.assertEqual(
            1,
            main.count(
                'bash "${repository_root}/scripts/run_mcp_governance_runtime_acceptance.sh" run'
            ),
        )
        self.assertLess(
            main.index("run_mcp_governance_runtime_acceptance.sh\" preflight"),
            main.index("run_mcp_governance_runtime_acceptance.sh\" run"),
        )

        self.assertIn(
            'public_summary="${artifact_root}/acceptance/mcp-governance-runtime-summary.json"',
            child,
        )
        self.assertIn('project_name="${WEB_STARTER_MCP_GOVERNANCE_COMPOSE_PROJECT:-}"', child)
        self.assertIn('private_port="${WEB_STARTER_MCP_GOVERNANCE_PRIVATE_PORT:-38088}"', child)
        self.assertIn('public_port="${WEB_STARTER_MCP_GOVERNANCE_PUBLIC_PORT:-38443}"', child)
        self.assertIn('management_port="${WEB_STARTER_MCP_GOVERNANCE_MANAGEMENT_PORT:-38081}"', child)
        self.assertIn("MCP governance Compose project must be distinct", child)
        self.assertEqual(
            1, child.count('python3 -B - "${project_name}" <<\'PY\'')
        )
        self.assertIn('interval: 1s', child)
        self.assertIn('down --volumes --remove-orphans', child)
        self.assertIn('for resource in ("container", "volume", "network")', child)
        self.assertIn('arguments.append("--all")', child)
        self.assertIn("remove_private_runtime_root()", child)
        self.assertIn('dir_fd=runner_descriptor', child)
        self.assertNotIn('rm -rf -- "${runtime_root}"', child)

        for fixed_value in (
            '"WEB_STARTER_MCP_SESSION_IDLE_TTL": "50s"',
            '"WEB_STARTER_MCP_SESSION_ABSOLUTE_TTL": "60s"',
            '"WEB_STARTER_MCP_SESSION_MAX_PER_SUBJECT": "2"',
            '"WEB_STARTER_MCP_RATE_LIMIT_WINDOW": "15s"',
            '"WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_SUBJECT": "5"',
            '"WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_CLIENT": "5"',
            '"WEB_STARTER_MCP_RATE_LIMIT_MAX_DESTRUCTIVE": "1"',
        ):
            self.assertIn(fixed_value, child)
        self.assertIn("formal MCP governance rejects ambient", child)
        self.assertIn('"scripts/acceptance_network.py"', child)
        self.assertIn('"scripts/generated_module_plan.py"', child)
        self.assertIn(
            '"web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/'
            'McpSdkGovernanceRuntimeIT.java"',
            child,
        )

        prewarm = child.index("-DskipTests test-compile")
        main_test = child.index(
            "-Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT"
        )
        orchestrator = child.index(
            'python3 -B "${candidate_root}/scripts/orchestrate_mcp_governance_restart.py"'
        )
        shutdown_test = child.index(
            "-Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT"
        )
        producer = child.index(
            'python3 -B "${candidate_root}/scripts/create_mcp_governance_runtime_proof.py"'
        )
        validator = child.index(
            'python3 -B "${candidate_root}/scripts/validate_mcp_governance_runtime_proof.py"'
        )
        publication = child.index('expected_raw = {', validator)
        self.assertLess(prewarm, main_test)
        self.assertLess(main_test, orchestrator)
        self.assertLess(orchestrator, shutdown_test)
        self.assertLess(shutdown_test, producer)
        self.assertLess(producer, validator)
        self.assertLess(validator, publication)
        self.assertEqual(2, child.count("-Dsurefire.useFile=false"))
        shutdown_invocation = child[
            child.index(
                "-Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT"
            ):
            child.index(
                "stage_surefire_report(Path(sys.argv[1])",
                child.index(
                    "-Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT"
                ),
            )
        ]
        self.assertIn("-DforkCount=0", shutdown_invocation)
        self.assertNotIn(
            "-DforkCount=0",
            child[
                child.index(
                    "-Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceRuntimeIT"
                ):
                child.index(
                    "-Dtest=dev.webstarter.mcp.acceptance.McpSdkGovernanceShutdownRuntimeIT"
                )
            ],
        )
        self.assertIn('main_report_root="${runtime_root}/main-surefire"', child)
        self.assertIn('shutdown_report_root="${runtime_root}/shutdown-surefire"', child)
        self.assertEqual(2, child.count("stage_surefire_report(Path(sys.argv[1])"))
        self.assertIn(
            'WEB_STARTER_REDIS_PASSWORD="${redis_password}" \\'
            + "\n"
            + "run_with_timeout 120 python3 -B",
            child,
        )
        self.assertNotIn("--redis-password", child)
        self.assertIn("start_new_session=True", child)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", child)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", child)
        self.assertIn("run_with_timeout 600 ./mvnw", child)
        self.assertIn('run_with_timeout 360 "${governance_compose[@]}" up', child)
        for option in (
            "--expected-app-reference",
            "--expected-app-image-id",
            "--expected-nginx-reference",
            "--expected-nginx-image-id",
            "--expected-redis-reference",
            "--expected-redis-image-id",
        ):
            self.assertGreaterEqual(child.count(option), 2)
        self.assertIn('--nginx-container-id "${nginx_container_id}"', child)
        self.assertIn(
            '--public-nginx-container-id "${public_nginx_container_id}"', child
        )
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", child)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', child)
        self.assertIn('dir_fd=public_descriptor', child)
        self.assertIn('os.unlink(target.name, dir_fd=public_descriptor)', child)
        self.assertIn('snapshot_at(raw_descriptor', child)
        self.assertIn('snapshot_at(summary_descriptor', child)
        self.assertIn('directory_entry_matches(artifact_descriptor, "acceptance"', child)
        self.assertIn('cmp -s "${private_summary}" "${public_summary}"', child)

    def test_preflight_accepts_one_clean_isolated_annotated_candidate(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            environment, _raw, _candidate = _fixture(Path(directory), root)
            result = _preflight(root, environment)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("PASS mcp-governance-runtime-preflight", result.stdout)

    def test_preflight_rejects_ambient_governance_configuration(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            environment, _raw, _candidate = _fixture(Path(directory), root)
            environment["WEB_STARTER_MCP_SESSION_IDLE_TTL"] = ""
            result = _preflight(root, environment)
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn(
            "formal MCP governance rejects ambient WEB_STARTER_MCP_SESSION_IDLE_TTL",
            result.stderr,
        )

    def test_preflight_rejects_unsafe_or_nonempty_raw_directory(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            environment, raw, _candidate = _fixture(Path(directory), root)
            raw.chmod(0o755)
            result = _preflight(root, environment)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("raw proof directory must be owned mode 0700", result.stderr)

            raw.chmod(0o700)
            unexpected = raw / "unexpected.txt"
            unexpected.write_text("not evidence\n", encoding="utf-8")
            unexpected.chmod(0o600)
            result = _preflight(root, environment)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("raw proof directory must start empty", result.stderr)

    def test_preflight_rejects_port_collision_and_existing_public_summary(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            environment, _raw, _candidate = _fixture(base, root)
            environment["WEB_STARTER_MCP_GOVERNANCE_PRIVATE_PORT"] = "18088"
            result = _preflight(root, environment)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("ports must be unique and distinct", result.stderr)

            environment.pop("WEB_STARTER_MCP_GOVERNANCE_PRIVATE_PORT")
            acceptance = base / "artifacts" / "acceptance"
            acceptance.mkdir(parents=True, mode=0o700)
            stale = acceptance / "mcp-governance-runtime-summary.json"
            stale.write_text('{"status":"PASS"}\n', encoding="utf-8")
            stale.chmod(0o600)
            result = _preflight(root, environment)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("public summary already exists", result.stderr)

    def test_preflight_rejects_candidate_drift(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            environment, _raw, candidate = _fixture(Path(directory), root)
            marker = candidate / "untracked-runtime-input.txt"
            marker.write_text("drift\n", encoding="utf-8")
            result = _preflight(root, environment)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("candidate worktree must be clean", result.stderr)

    def test_main_runner_rejects_non_boolean_formal_flag_before_docker(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runner_temp = base / "runner-temp"
            runner_temp.mkdir(mode=0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "RUNNER_TEMP": str(runner_temp),
                    "WEB_STARTER_RELEASE_ARTIFACT_DIR": str(base / "artifacts"),
                    "WEB_STARTER_MYSQL_IMAGE": "registry.invalid/mysql@sha256:" + "1" * 64,
                    "WEB_STARTER_REDIS_IMAGE": "registry.invalid/redis@sha256:" + "2" * 64,
                    "WEB_STARTER_APP_IMAGE": "registry.invalid/web-starter",
                    "WEB_STARTER_APP_DIGEST": "sha256:" + "3" * 64,
                    "WEB_STARTER_NGINX_IMAGE": "registry.invalid/nginx",
                    "WEB_STARTER_NGINX_DIGEST": "sha256:" + "4" * 64,
                    "WEB_STARTER_RELEASE_TAG": "v2.0.0",
                    "WEB_STARTER_RELEASE_VERSION": "2.0.0",
                    "GITHUB_SHA": "5" * 40,
                    "WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL": "TRUE",
                }
            )
            result = subprocess.run(
                ["bash", str(root / "scripts/run_release_runtime_acceptance.sh")],
                cwd=root,
                env=environment,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn(
            "WEB_STARTER_RUN_MCP_GOVERNANCE_FORMAL must be exactly true or false",
            result.stderr,
        )

    def test_fixture_permissions_are_private(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            environment, raw, candidate = _fixture(Path(directory), root)
            self.assertEqual(0o700, stat.S_IMODE(raw.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(candidate.stat().st_mode))
            self.assertEqual(str(candidate), environment["WEB_STARTER_CANDIDATE_VALIDATION_ROOT"])


if __name__ == "__main__":
    unittest.main()
