from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "build-ac40-dependency-seed.yml"
WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
RELEASE_WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "release-supply-chain.yml"
).read_text(encoding="utf-8")
CI_WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
).read_text(encoding="utf-8")


class Ac40DependencySeedWorkflowContractTest(unittest.TestCase):
    def assert_ordered(self, *needles: str) -> None:
        positions = []
        for needle in needles:
            position = WORKFLOW.find(needle)
            self.assertGreaterEqual(position, 0, f"missing workflow contract: {needle}")
            positions.append(position)
        self.assertEqual(positions, sorted(positions), f"workflow order is invalid: {needles}")

    def test_is_manual_tag_bound_least_privilege_release_environment_job(self) -> None:
        trigger = WORKFLOW[WORKFLOW.index("on:\n") : WORKFLOW.index("\npermissions:\n")]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn("version:", trigger)
        self.assertIn("Existing annotated semantic Git tag", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("schedule:", trigger)

        permissions = WORKFLOW[
            WORKFLOW.index("permissions:\n") : WORKFLOW.index("\nconcurrency:\n")
        ]
        self.assertEqual(
            permissions,
            "permissions:\n  actions: read\n  contents: read\n",
        )
        self.assertIn("runs-on: ubuntu-24.04", WORKFLOW)
        self.assertIn("environment:\n      name: release", WORKFLOW)
        self.assertEqual(1, WORKFLOW.count("${{ secrets.WEB_STARTER_FORBIDDEN_TERMS }}"))
        self.assertNotRegex(WORKFLOW, r"(?m)^\s+packages:\s*")

    def test_first_step_verifies_required_reviewers_before_checkout(self) -> None:
        steps = WORKFLOW.index("    steps:\n")
        first_step = WORKFLOW.index(
            "- name: Verify protected release Environment before checkout", steps
        )
        checkout = WORKFLOW.index("uses: actions/checkout@", steps)
        self.assertLess(first_step, checkout)
        between = WORKFLOW[first_step:checkout]
        self.assertIn(
            "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/environments/release",
            between,
        )
        self.assertIn('.type == "required_reviewers"', between)
        self.assertIn("(.reviewers | length > 0)", between)
        self.assertNotIn("${{ secrets.", between)
        self.assertNotIn("/environments/release/variables", between)

    def test_all_third_party_actions_are_full_sha_pinned_and_cacheless(self) -> None:
        uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", WORKFLOW)
        self.assertEqual(
            uses,
            [
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9",
                "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            ],
        )
        for action in uses:
            self.assertRegex(action, r"@[0-9a-f]{40}$")
        self.assertNotRegex(WORKFLOW, r"(?m)^\s+cache:\s*")
        self.assertNotIn("pnpm/action-setup", WORKFLOW)
        self.assertNotIn("actions/cache", WORKFLOW)
        self.assertNotRegex(WORKFLOW, r"(?m)^\s+HOME:\s*")
        for global_cache_path in ("~/.m2", "/home/runner", "~/.pnpm-store", "${HOME}", "$HOME/"):
            self.assertNotIn(global_cache_path, WORKFLOW)

    def test_checkout_is_annotated_semantic_tag_exact_and_clean(self) -> None:
        self.assertIn("ref: ${{ inputs.version }}", WORKFLOW)
        self.assertIn("fetch-depth: 0", WORKFLOW)
        self.assertIn("clean: true", WORKFLOW)
        self.assertIn("persist-credentials: false", WORKFLOW)
        self.assertIn("git cat-file -t \"${tag_ref}\"", WORKFLOW)
        self.assertIn("!= \"tag\"", WORKFLOW)
        self.assertIn('tag_commit="$(git rev-parse "${tag_ref}^{commit}")"', WORKFLOW)
        self.assertIn('head_commit="$(git rev-parse HEAD)"', WORKFLOW)
        self.assertIn('"${tag_commit}" != "${GITHUB_SHA}"', WORKFLOW)
        self.assertIn('"${head_commit}" != "${GITHUB_SHA}"', WORKFLOW)
        self.assertIn("git status --porcelain=v1", WORKFLOW)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", WORKFLOW)

    def test_all_dependency_sources_start_in_private_runner_temp_roots(self) -> None:
        self.assertIn(
            'private_root="${RUNNER_TEMP}/web-starter-ac40-seed-build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            WORKFLOW,
        )
        self.assertGreaterEqual(WORKFLOW.count("umask 077"), 2)
        self.assertIn('mkdir -m 700 "${private_root}"', WORKFLOW)
        for root in (
            "maven-wrapper-home",
            "maven-repository",
            "corepack-home",
            "pnpm-store",
            "pnpm-virtual-store",
            "playwright-browsers",
            "npm-cache",
            "xdg-cache",
            "seed-output",
            "extract-output",
        ):
            self.assertIn(root, WORKFLOW)
        self.assertIn("AC40 dependency cache root was not created empty", WORKFLOW)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o700", WORKFLOW)
        self.assertNotIn("private_user_home", WORKFLOW)
        self.assertIn("MAVEN_USER_HOME: ${{ steps.roots.outputs.maven_wrapper_cache }}", WORKFLOW)
        self.assertIn("COREPACK_HOME: ${{ steps.roots.outputs.corepack_home }}", WORKFLOW)
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH: ${{ steps.roots.outputs.playwright_browsers }}", WORKFLOW)

    def test_maven_closure_is_central_only_checksum_fail_and_project_free(self) -> None:
        self.assertGreaterEqual(WORKFLOW.count("https://repo.maven.apache.org/maven2"), 3)
        self.assertIn("<id>central</id>", WORKFLOW)
        self.assertIn("<mirrorOf>*</mirrorOf>", WORKFLOW)
        self.assertGreaterEqual(WORKFLOW.count("<checksumPolicy>fail</checksumPolicy>"), 4)
        self.assertIn('"-Dmaven.repo.local=${MAVEN_REPOSITORY}"', WORKFLOW)
        self.assertRegex(
            WORKFLOW,
            r"-DskipTests -DskipITs -pl web-starter-mcp -am clean install",
        )
        self.assertIn(
            "-Dtest=dev.webstarter.mcp.acceptance.McpRuntimeToolExpectationsTest",
            WORKFLOW,
        )
        self.assertIn("-Dsurefire.failIfNoSpecifiedTests=true", WORKFLOW)
        self.assertIn("-Dsurefire.rerunFailingTestsCount=0", WORKFLOW)
        self.assertIn('project_artifacts = repository / "dev" / "webstarter"', WORKFLOW)
        self.assertIn("shutil.rmtree(project_artifacts)", WORKFLOW)
        self.assertIn('"${MAVEN_REPOSITORY}/dev/webstarter"', WORKFLOW)
        self.assertIn('"${MAVEN_USER_HOME}/repository"', WORKFLOW)

    def test_pnpm_and_playwright_closure_is_exact_and_browser_is_launched(self) -> None:
        self.assertIn("COREPACK_NPM_REGISTRY: https://registry.npmjs.org", WORKFLOW)
        self.assertGreaterEqual(WORKFLOW.count("https://registry.npmjs.org/"), 2)
        self.assertIn("corepack prepare pnpm@9.15.9 --activate", WORKFLOW)
        self.assertIn("corepack pnpm@9.15.9 --version", WORKFLOW)
        self.assertIn("${COREPACK_HOME}/v1/pnpm/9.15.9/package.json", WORKFLOW)
        self.assertIn("--frozen-lockfile", WORKFLOW)
        self.assertIn("--ignore-scripts", WORKFLOW)
        self.assertIn("--package-import-method=copy", WORKFLOW)
        self.assertIn('--store-dir "${PNPM_STORE_ROOT}"', WORKFLOW)
        self.assertIn('--virtual-store-dir "${PNPM_VIRTUAL_STORE}"', WORKFLOW)
        self.assertIn("process.env.PNPM_VIRTUAL_STORE", WORKFLOW)
        self.assertIn("privateDependencyRoots", WORKFLOW)
        self.assertIn("resolved outside the private dependency roots", WORKFLOW)
        self.assertIn('"${PNPM_STORE_ROOT}/v3/files"', WORKFLOW)
        self.assertIn("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1", WORKFLOW)
        self.assertIn("@playwright/test/package.json').version", WORKFLOW)
        self.assertIn("!= \"1.61.1\"", WORKFLOW)
        self.assertIn("browser.name === 'chromium'", WORKFLOW)
        self.assertIn("!= \"1228\"", WORKFLOW)
        self.assertIn("exec playwright install chromium", WORKFLOW)
        self.assertIn('chromium_root="${PLAYWRIGHT_BROWSERS_PATH}/chromium-1228"', WORKFLOW)
        self.assertIn("chromium.launch({ headless: true })", WORKFLOW)
        self.assertIn("await page.setContent", WORKFLOW)
        for duplicate in (
            "npm_config_userconfig:",
            "npm_config_globalconfig:",
            "npm_config_cache:",
            "npm_config_registry:",
        ):
            self.assertNotIn(duplicate, WORKFLOW)

    def test_playwright_revision_probe_executes_against_strict_dependency_layout(self) -> None:
        match = re.search(
            r"chromium_revision=\"\$\(node <<'JS'\n(?P<script>.*?)\n\s*JS\n\s*\)\"",
            WORKFLOW,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "Playwright revision probe is not an executable Node heredoc")
        script = textwrap.dedent(match.group("script"))

        with tempfile.TemporaryDirectory() as temporary:
            web = Path(temporary) / "web"
            node_modules = web / "node_modules"
            pnpm = Path(temporary) / "pnpm-virtual-store"
            test_dependencies = pnpm / "@playwright+test@1.61.1" / "node_modules"
            playwright_dependencies = pnpm / "playwright@1.61.1" / "node_modules"
            core_dependencies = pnpm / "playwright-core@1.61.1" / "node_modules"
            test_package = test_dependencies / "@playwright" / "test"
            playwright_package = playwright_dependencies / "playwright"
            core_package = core_dependencies / "playwright-core"
            for path, name in (
                (test_package / "package.json", "@playwright/test"),
                (playwright_package / "package.json", "playwright"),
                (core_package / "package.json", "playwright-core"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps({"name": name, "version": "1.61.1"}),
                    encoding="utf-8",
                )
            (core_package / "browsers.json").write_text(
                json.dumps({"browsers": [{"name": "chromium", "revision": "1228"}]}),
                encoding="utf-8",
            )

            direct_scope = node_modules / "@playwright"
            direct_scope.mkdir(parents=True)
            (direct_scope / "test").symlink_to(test_package, target_is_directory=True)
            (test_dependencies / "playwright").symlink_to(
                Path("../../playwright@1.61.1/node_modules/playwright"),
                target_is_directory=True,
            )
            (playwright_dependencies / "playwright-core").symlink_to(
                Path("../../playwright-core@1.61.1/node_modules/playwright-core"),
                target_is_directory=True,
            )

            self.assertFalse((node_modules / "playwright").exists())
            self.assertFalse((node_modules / "playwright-core").exists())
            result = subprocess.run(
                ["node"],
                cwd=web,
                env={**os.environ, "PNPM_VIRTUAL_STORE": str(pnpm)},
                input=script,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("1228", result.stdout)

            escaped_package = Path(temporary) / "escaped" / "@playwright" / "test"
            escaped_package.mkdir(parents=True)
            (escaped_package / "package.json").write_text(
                json.dumps({"name": "@playwright/test", "version": "1.61.1"}),
                encoding="utf-8",
            )
            (direct_scope / "test").unlink()
            (direct_scope / "test").symlink_to(escaped_package, target_is_directory=True)
            escaped = subprocess.run(
                ["node"],
                cwd=web,
                env={**os.environ, "PNPM_VIRTUAL_STORE": str(pnpm)},
                input=script,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, escaped.returncode)
            self.assertIn("resolved outside the private dependency roots", escaped.stderr)

    def test_policy_build_extract_and_upload_steps_are_fail_closed_and_ordered(self) -> None:
        self.assert_ordered(
            "Run repository secret and protected forbidden-vocabulary policy",
            "Build source-bound deterministic AC40 dependency seed",
            "Extract and independently revalidate the raw seed archive",
            "Require source tree to remain candidate-exact before upload",
            "Upload immutable raw AC40 dependency seed tar",
        )
        self.assertIn("python3 -B scripts/repository_policy.py secrets", WORKFLOW)
        self.assertIn("python3 -B scripts/repository_policy.py forbidden", WORKFLOW)
        policy = WORKFLOW.index("Run repository secret and protected forbidden-vocabulary policy")
        build = WORKFLOW.index("Build source-bound deterministic AC40 dependency seed")
        policy_block = WORKFLOW[policy:build]
        self.assertIn(
            "python3 -B -m unittest discover -s scripts -p 'test_repository_policy.py'",
            policy_block,
        )
        self.assertNotIn("python3 -B -m unittest scripts.test_repository_policy", policy_block)
        self.assertIn(
            "FORBIDDEN_TERMS_SECRET: ${{ secrets.WEB_STARTER_FORBIDDEN_TERMS }}",
            policy_block,
        )
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", policy_block)
        self.assertIn('--forbidden-terms-file "${forbidden_terms_file}"', policy_block)
        for argument in (
            '--maven-home "${MAVEN_WRAPPER_CACHE}"',
            '--maven-repository "${MAVEN_REPOSITORY}"',
            '--corepack-home "${COREPACK_HOME}"',
            '--pnpm-store-root "${PNPM_STORE_ROOT}"',
            '--playwright-browsers "${PLAYWRIGHT_BROWSERS_PATH}"',
            '--archive-output "${archive}"',
            '--receipt-output "${receipt}"',
        ):
            self.assertIn(argument, WORKFLOW)
        self.assertIn("build_v1_upgrade_dependency_seed.py extract-verify", WORKFLOW)
        self.assertIn('--expected-archive-sha256 "${ARCHIVE_SHA256}"', WORKFLOW)
        self.assertIn('--expected-aggregate-sha256 "${AGGREGATE_SHA256}"', WORKFLOW)
        self.assertGreaterEqual(WORKFLOW.count("cmp --silent"), 3)

    def test_raw_artifact_and_provenance_match_release_consumer_contract(self) -> None:
        basename = "web-starter-ac40-dependency-seed-linux-x86_64.tar"
        self.assertGreaterEqual(WORKFLOW.count(basename), 4)
        direct_upload = WORKFLOW[
            WORKFLOW.index("- name: Upload immutable raw AC40 dependency seed tar") :
            WORKFLOW.index("- name: Verify uploaded artifact digest", WORKFLOW.index("- name: Upload immutable raw AC40 dependency seed tar"))
        ]
        self.assertIn(
            "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            direct_upload,
        )
        self.assertIn("path: ${{ steps.seed.outputs.archive }}", direct_upload)
        self.assertIn("archive: false", direct_upload)
        self.assertIn("if-no-files-found: error", direct_upload)
        self.assertNotRegex(direct_upload, r"(?m)^\s+name:\s+web-starter")
        self.assertIn('"${UPLOAD_ARTIFACT_DIGEST}" != "${ARCHIVE_SHA256}"', WORKFLOW)
        self.assertIn('--arg digest "sha256:${ARCHIVE_SHA256}"', WORKFLOW)
        self.assertIn('and .name == $name', WORKFLOW)
        self.assertIn('and .workflow_run.id == $run_id', WORKFLOW)
        self.assertIn(
            '"workflowPath": ".github/workflows/build-ac40-dependency-seed.yml"',
            WORKFLOW,
        )
        self.assertIn(
            '--arg producer_workflow ".github/workflows/build-ac40-dependency-seed.yml"',
            RELEASE_WORKFLOW,
        )
        self.assertIn(f'--arg name "{basename}"', RELEASE_WORKFLOW)
        self.assertIn(f'archive="${{AC40_SEED_DOWNLOAD_ROOT}}/{basename}"', RELEASE_WORKFLOW)
        self.assertIn('.event == "workflow_dispatch"', RELEASE_WORKFLOW)
        self.assertIn('.head_sha == $producer_sha', RELEASE_WORKFLOW)
        self.assertIn('"headSha": sys.argv[9]', WORKFLOW)
        self.assertIn('"annotatedTag": sys.argv[10]', WORKFLOW)
        self.assertIn("Upload receipt and provenance review bundle", WORKFLOW)
        for summary_field in (
            "Raw tar artifact ID",
            "Producer workflow run ID",
            "Archive SHA-256",
            "Aggregate SHA-256",
            "Manifest SHA-256",
            "Platform",
            "Architecture",
            "Head SHA",
            "Annotated tag",
        ):
            self.assertIn(summary_field, WORKFLOW)
        self.assertIn("anchor_bundle=\"$(jq -cnS", WORKFLOW)
        self.assertIn(
            "WEB_STARTER_AC40_DEPENDENCY_SEED_ANCHORS", WORKFLOW
        )
        self.assertIn(
            "'{aggregateSha256:$aggregateSha256,archiveSha256:$archiveSha256,artifactId:$artifactId,workflowRunId:$workflowRunId}'",
            WORKFLOW,
        )

    def test_ci_checks_full_history_workflow_syntax_and_release_commit(self) -> None:
        self.assertEqual(4, CI_WORKFLOW.count("fetch-depth: 0"))
        self.assertNotIn("fetch-depth: 1", CI_WORKFLOW)
        self.assertIn(
            "Validate GitHub Actions workflows with pinned actionlint",
            CI_WORKFLOW,
        )
        self.assertIn("ACTIONLINT_VERSION: 1.7.12", CI_WORKFLOW)
        self.assertIn(
            "ACTIONLINT_LINUX_AMD64_SHA256: "
            "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
            CI_WORKFLOW,
        )
        self.assertIn(
            "https://github.com/rhysd/actionlint/releases/download/"
            "v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz",
            CI_WORKFLOW,
        )
        self.assertIn('sha256sum --check --strict -', CI_WORKFLOW)
        self.assertIn('"${install_root}/actionlint" -shellcheck= -color', CI_WORKFLOW)
        self.assertIn("WEB_STARTER_GIT_COMMIT: ${{ github.sha }}", CI_WORKFLOW)
        self.assertIn(
            '"${{ steps.compose_cli.outputs.binary }}" '
            "-f compose.production.yaml config "
            "--format json",
            CI_WORKFLOW,
        )
        self.assertIn(
            '"${{ steps.compose_cli.outputs.binary }}" '
            "-f compose.production.yaml config "
            "--format json",
            RELEASE_WORKFLOW,
        )
        for workflow in (CI_WORKFLOW, RELEASE_WORKFLOW):
            compose_step_start = workflow.index(
                "- name: Install pinned Docker Compose serializer"
            )
            compose_step_end = workflow.index("\n      - name:", compose_step_start + 1)
            compose_step = workflow[compose_step_start:compose_step_end]
            self.assertIn("DOCKER_COMPOSE_VERSION: 5.3.1", workflow)
            self.assertIn(
                "DOCKER_COMPOSE_LINUX_X86_64_SHA256: "
                "f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959",
                workflow,
            )
            self.assertIn(
                "https://github.com/docker/compose/releases/download/"
                "v${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64",
                workflow,
            )
            self.assertIn(
                "printf '%s  %s\\n' "
                '"${DOCKER_COMPOSE_LINUX_X86_64_SHA256}" "${binary}" \\',
                compose_step,
            )
            self.assertIn("sha256sum --check --strict -", compose_step)
            self.assertIn(
                'test "$("${binary}" version --short)" = "${DOCKER_COMPOSE_VERSION}"',
                workflow,
            )
            self.assertNotIn(
                "docker compose -f compose.production.yaml config",
                workflow,
            )


if __name__ == "__main__":
    unittest.main()
