package dev.webstarter.tooling.dev;

import dev.webstarter.tooling.Digests;
import dev.webstarter.tooling.ToolingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeveloperCommandsTest {

    @TempDir
    Path temporary;

    private int workspaceNumber;

    @Test
    void doctorReportsPlaceholdersWithoutPrintingTheirValues() throws Exception {
        Path workspace = workspace();
        Path envFile = workspace.resolve(".env");
        Files.writeString(envFile, """
                WEB_STARTER_DB_USERNAME=web_starter
                WEB_STARTER_DB_PASSWORD=replace-with-private-database-value
                WEB_STARTER_DB_ROOT_PASSWORD=local-root-value-123
                WEB_STARTER_REDIS_PASSWORD=local-redis-value-123
                WEB_STARTER_TOKEN_PEPPER=01234567890123456789012345678901
                WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD=
                """);
        privateFile(envFile);
        RecordingExecutor executor = versionsExecutor();
        DeveloperCommands commands = commands(executor, Map.of(), prompt -> null);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        int exit = commands.doctor(workspace, envFile, new PrintStream(bytes));

        String output = bytes.toString(StandardCharsets.UTF_8);
        assertEquals(ToolingException.PREREQUISITE, exit);
        assertTrue(output.contains("config:WEB_STARTER_DB_PASSWORD"));
        assertTrue(output.contains("placeholder value detected"));
        assertFalse(output.contains("replace-with-private-database-value"));
        assertTrue(output.contains("DOCTOR FAIL"));
    }

    @Test
    void upValidatesThenWaitsForReadiness() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        RecordingExecutor executor = new RecordingExecutor(command -> 0, command -> "ok\n");
        DeveloperCommands commands = commands(executor, Map.of(), prompt -> null);

        int exit = commands.up(workspace, envFile, "web-starter", 123, false, System.out);

        assertEquals(0, exit);
        assertEquals(2, executor.commands.size());
        assertTrue(executor.commands.get(0).contains("config"));
        List<String> up = executor.commands.get(1);
        assertTrue(up.containsAll(List.of("up", "-d", "--build", "--wait", "--wait-timeout", "123")));
        assertFalse(up.contains("--volumes"));
    }

    @Test
    void downPreservesVolumesByDefault() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        RecordingExecutor executor = new RecordingExecutor(command -> 0, command -> "stopped\n");
        DeveloperCommands commands = commands(executor, Map.of(), prompt -> null);

        int exit = commands.down(workspace, envFile, "web-starter", false, null, System.out);

        assertEquals(0, exit);
        assertEquals(1, executor.commands.size());
        assertTrue(executor.commands.getFirst().containsAll(List.of("down", "--remove-orphans")));
        assertFalse(executor.commands.getFirst().contains("--volumes"));
    }

    @Test
    void volumeDeletionRequiresAnInteractivePhraseOrExactNonInteractiveAcknowledgement()
            throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        RecordingExecutor rejectedExecutor = new RecordingExecutor(command -> 0, command -> "");
        DeveloperCommands rejected = commands(rejectedExecutor, Map.of(), prompt -> null);

        ToolingException missing = assertThrows(ToolingException.class,
                () -> rejected.down(workspace, envFile, "web-starter", true, null, System.out));
        assertEquals(ToolingException.PREREQUISITE, missing.exitCode());
        assertTrue(rejectedExecutor.commands.isEmpty());

        ToolingException mismatch = assertThrows(ToolingException.class,
                () -> rejected.down(workspace, envFile, "web-starter", true, "other", System.out));
        assertEquals(ToolingException.USAGE, mismatch.exitCode());
        assertTrue(rejectedExecutor.commands.isEmpty());

        RecordingExecutor interactiveExecutor = new RecordingExecutor(command -> 0, command -> "stopped\n");
        DeveloperCommands interactive = commands(interactiveExecutor, Map.of(),
                prompt -> "DELETE VOLUMES web-starter");
        assertEquals(0, interactive.down(
                workspace, envFile, "web-starter", true, null, System.out));
        assertTrue(interactiveExecutor.commands.getFirst().contains("--volumes"));

        RecordingExecutor explicitExecutor = new RecordingExecutor(command -> 0, command -> "stopped\n");
        DeveloperCommands explicit = commands(explicitExecutor, Map.of(), prompt -> null);
        assertEquals(0, explicit.down(
                workspace, envFile, "web-starter", true, "web-starter", System.out));
        assertTrue(explicitExecutor.commands.getFirst().contains("--volumes"));
    }

    @Test
    void verifyContinuesAllLayersAndRecordsMissingRuntimeCoverageHonestly() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        Path mcpRuntime = workspace.resolve(
                "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java");
        Files.createDirectories(mcpRuntime.getParent());
        Files.writeString(mcpRuntime, "// marker\n");
        Path evidence = temporary.resolve("evidence");
        RecordingExecutor executor = new RecordingExecutor(
                command -> command.contains("verify") ? 1 : 0,
                command -> command.contains("ps")
                        ? "mysql|running|healthy\nredis|running|healthy\n"
                                + "app|running|healthy\nnginx|running|healthy\n"
                        : "ok\n");
        DeveloperCommands commands = commands(executor, Map.of(), prompt -> null);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        int exit = commands.verify(workspace, envFile, evidence, "web-starter",
                new PrintStream(bytes));

        assertEquals(DeveloperCommands.VERIFICATION_FAILED, exit);
        String summary = Files.readString(evidence.resolve("summary.json"));
        assertTrue(summary.contains("\"name\":\"backend\",\"status\":\"FAIL\""));
        assertTrue(summary.contains("\"name\":\"frontend\",\"status\":\"PASS\""));
        assertTrue(summary.contains("\"name\":\"policy\",\"status\":\"PASS\""));
        assertTrue(summary.contains("\"name\":\"container\",\"status\":\"PASS\""));
        assertTrue(summary.contains("\"name\":\"browser\",\"status\":\"NOT_COVERED\""));
        assertTrue(summary.contains("\"name\":\"oauth\",\"status\":\"NOT_COVERED\""));
        assertTrue(summary.contains("\"name\":\"mcp\",\"status\":\"ENV_REQUIRED\""));
        assertTrue(executor.commands.stream().anyMatch(command -> command.contains("lint")));
        for (String policyTest : List.of("test_repository_policy.py",
                "test_production_compose_policy.py", "test_release_security_gate.py",
                "test_recovery_harness.py")) {
            assertTrue(executor.commands.stream()
                    .anyMatch(command -> command.contains(policyTest)));
        }
        assertTrue(executor.commands.stream()
                .anyMatch(command -> command.stream()
                        .anyMatch(argument -> argument.endsWith("repository_policy.py"))
                        && command.contains("secrets")));
        assertTrue(executor.commands.stream().anyMatch(command -> command.contains("ps")));
        assertTrue(bytes.toString(StandardCharsets.UTF_8).contains("VERIFY INCOMPLETE_OR_FAILED"));
        assertPrivateEvidence(evidence);
    }

    @Test
    void policyVerificationRemovesAmbientReleaseOrchestrationEnvironment() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        RecordingExecutor executor = new RecordingExecutor(command -> 0,
                command -> command.contains("ps")
                        ? "mysql|running|healthy\nredis|running|healthy\n"
                                + "app|running|healthy\nnginx|running|healthy\n"
                        : "ok\n");
        Map<String, String> ambient = Map.ofEntries(
                Map.entry("WEB_STARTER_RUN_AC41_FORMAL", "true"),
                Map.entry("WEB_STARTER_ACCEPTANCE_MANIFEST", "/private/runtime/manifest.json"),
                Map.entry("GITHUB_SHA", "a".repeat(40)),
                Map.entry("RUNNER_TEMP", "/private/runtime"),
                Map.entry("JAVA_TOOL_OPTIONS", "-Dprivate.runtime=true"),
                Map.entry("SSLKEYLOGFILE", "/private/runtime/tls.keys"),
                Map.entry("PATH", "/usr/bin:/bin"));
        DeveloperCommands commands = commands(executor, ambient, prompt -> null);

        commands.verify(workspace, envFile, temporary.resolve("isolated-policy-evidence"),
                "web-starter", System.out);

        for (String policyTest : List.of("test_repository_policy.py",
                "test_production_compose_policy.py", "test_release_security_gate.py",
                "test_recovery_harness.py", "repository_policy.py")) {
            int policyIndex = 0;
            while (executor.commands.get(policyIndex).stream()
                    .noneMatch(argument -> argument.endsWith(policyTest))) {
                policyIndex++;
            }
            String removals = executor.environments.get(policyIndex)
                    .get(ProcessExecutor.ENVIRONMENT_REMOVALS);
            assertTrue(removals.contains("WEB_STARTER_RUN_AC41_FORMAL"));
            assertTrue(removals.contains("WEB_STARTER_ACCEPTANCE_MANIFEST"));
            assertTrue(removals.contains("GITHUB_SHA"));
            assertTrue(removals.contains("RUNNER_TEMP"));
            assertTrue(removals.contains("JAVA_TOOL_OPTIONS"));
            assertTrue(removals.contains("SSLKEYLOGFILE"));
            assertFalse(removals.contains("PATH"));
        }
    }

    @Test
    void repositorySecretScanFailureBlocksUnifiedVerification() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        RecordingExecutor executor = new RecordingExecutor(
                command -> command.stream()
                        .anyMatch(argument -> argument.endsWith("repository_policy.py"))
                        && command.contains("secrets") ? 1 : 0,
                command -> command.contains("ps")
                        ? "mysql|running|healthy\nredis|running|healthy\n"
                                + "app|running|healthy\nnginx|running|healthy\n"
                        : "ok\n");
        DeveloperCommands commands = commands(executor, Map.of(), prompt -> null);
        Path evidence = temporary.resolve("secret-scan-failure-evidence");

        int exit = commands.verify(workspace, envFile, evidence, "web-starter", System.out);

        assertEquals(DeveloperCommands.VERIFICATION_FAILED, exit);
        String summary = Files.readString(evidence.resolve("summary.json"));
        assertTrue(summary.contains("\"name\":\"policy\",\"status\":\"FAIL\""));
        assertTrue(Files.isRegularFile(evidence.resolve("policy-repository-secret-scan.log")));
    }

    @Test
    void stoppedComposeStackIsEnvironmentRequiredRatherThanPass() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        RecordingExecutor executor = new RecordingExecutor(command -> 0,
                command -> command.contains("ps") ? "" : "ok\n");
        DeveloperCommands commands = commands(executor, Map.of(), prompt -> null);
        Path evidence = temporary.resolve("stopped-evidence");

        int exit = commands.verify(workspace, envFile, evidence, "web-starter", System.out);

        assertEquals(DeveloperCommands.VERIFICATION_FAILED, exit);
        String summary = Files.readString(evidence.resolve("summary.json"));
        assertTrue(summary.contains("\"name\":\"container\",\"status\":\"ENV_REQUIRED\""));
        assertTrue(Files.readString(evidence.resolve("container-runtime-status.log")).isEmpty());
    }

    @Test
    void verifyProductionModeQueriesEveryServiceFromTheProductionComposeModel() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        RecordingExecutor executor = new RecordingExecutor(command -> 0,
                command -> command.contains("ps")
                        ? "mysql|running|healthy\nredis|running|healthy\n"
                                + "app|running|healthy\nnginx|running|healthy\n"
                                + "mcp-public-nginx|running|healthy\n"
                        : "ok\n");
        DeveloperCommands commands = commands(executor,
                Map.of("WEB_STARTER_VERIFY_COMPOSE_MODE", "production"), prompt -> null);
        Path evidence = temporary.resolve("production-compose-evidence");

        commands.verify(workspace, envFile, evidence, "web-starter-release-1", System.out);

        String summary = Files.readString(evidence.resolve("summary.json"));
        assertTrue(summary.contains("\"name\":\"container\",\"status\":\"PASS\""));
        List<List<String>> composeCommands = executor.commands.stream()
                .filter(command -> command.contains("config") || command.contains("ps"))
                .toList();
        assertEquals(2, composeCommands.size());
        assertTrue(composeCommands.stream().allMatch(command -> command.stream()
                .anyMatch(value -> value.endsWith("compose.production.yaml"))));
        assertTrue(composeCommands.stream().noneMatch(command -> command.stream()
                .anyMatch(value -> value.endsWith("compose.dev.yaml"))));
    }

    @Test
    void verifyCanOnlyPassWhenEveryFixedRuntimeLayerActuallyRuns() throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        Files.writeString(workspace.resolve("web-starter-web/package.json"),
                "{\"scripts\":{\"test:e2e\":\"playwright test\"}}\n");
        Files.writeString(workspace.resolve("web-starter-web/playwright.config.ts"), "// marker\n");
        Files.writeString(Files.createDirectories(workspace.resolve("scripts"))
                .resolve("verify_oauth_runtime.py"), "# marker\n");
        Path acceptance = Files.createDirectories(workspace.resolve(
                "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance"));
        for (String name : List.of("McpSdkRuntimeIT.java", "McpSdkProjectListRuntimeIT.java",
                "McpSdkCrudRuntimeIT.java")) {
            Files.writeString(acceptance.resolve(name), "// marker\n");
        }
        Path readToken = temporary.resolve("read-token.json");
        Path runtimeManifest = temporary.resolve("runtime-manifest.json");
        Files.writeString(readToken, "{\"access_token\":\"not-used-by-fake-executor\"}\n");
        Files.writeString(runtimeManifest, "{\"schemaVersion\":1}\n");
        privateFile(readToken);
        privateFile(runtimeManifest);
        Files.writeString(workspace.resolve("web-starter-mcp/pom.xml"), "<project/>\n");
        Files.writeString(workspace.resolve(".gitignore"), ".env\n");
        String candidateCommit = commitWorkspace(workspace);
        Path crudProof = writeCrudProof(workspace, temporary.resolve("crud-proof-complete"),
                candidateCommit, "2.0.0", "v2.0.0", "web-starter", "release-sdk");
        Map<String, String> runtime = Map.ofEntries(
                Map.entry("WEB_STARTER_BROWSER_BASE_URL", "http://127.0.0.1:8088"),
                Map.entry("WEB_STARTER_ACCEPTANCE_MANIFEST", runtimeManifest.toString()),
                Map.entry("WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME", "acceptance-admin"),
                Map.entry("WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD", "not-used-by-fake-executor"),
                Map.entry("WEB_STARTER_OAUTH_ACCEPTANCE_BASE_URL", "http://127.0.0.1:8088"),
                Map.entry("WEB_STARTER_OAUTH_ACCEPTANCE_MANIFEST", runtimeManifest.toString()),
                Map.entry("WEB_STARTER_MCP_BASE_URL", "http://127.0.0.1:8088"),
                Map.entry("WEB_STARTER_MCP_OWNER_ID", "1"),
                Map.entry("WEB_STARTER_MCP_PROJECT_ID", "2"),
                Map.entry("WEB_STARTER_MCP_TRACE_PREFIX", "v2-test"),
                Map.entry("WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE", readToken.toString()),
                Map.entry("WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE", crudProof.toString()),
                Map.entry("WEB_STARTER_VERIFY_CANDIDATE_COMMIT", candidateCommit),
                Map.entry("WEB_STARTER_VERIFY_CANDIDATE_VERSION", "2.0.0"),
                Map.entry("WEB_STARTER_VERIFY_CANDIDATE_TAG", "v2.0.0"),
                Map.entry("WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX", "release-sdk"));
        RecordingExecutor executor = new RecordingExecutor(command -> 0,
                command -> command.contains("ps")
                        ? "mysql|running|healthy\nredis|running|healthy\n"
                                + "app|running|healthy\nnginx|running|healthy\n"
                        : "ok\n");
        DeveloperCommands commands = commands(executor, runtime, prompt -> null);
        Path evidence = temporary.resolve("complete-evidence");

        int exit = commands.verify(workspace, envFile, evidence, "web-starter", System.out);

        assertEquals(0, exit);
        String summary = Files.readString(evidence.resolve("summary.json"));
        for (String layer : List.of("backend", "frontend", "policy", "container", "browser",
                "oauth", "mcp")) {
            assertTrue(summary.contains("\"name\":\"" + layer + "\",\"status\":\"PASS\""));
        }
        assertTrue(executor.commands.stream().anyMatch(command -> command.contains("test:e2e")));
        assertTrue(executor.commands.stream().anyMatch(command -> command.stream()
                .anyMatch(value -> value.contains("verify_oauth_runtime.py"))));
        assertEquals(2, executor.commands.stream().filter(command -> command.stream()
                .anyMatch(value -> value.contains("dev.webstarter.mcp.acceptance.McpSdk"))).count());
        int contractCommand = executor.commands.indexOf(executor.commands.stream()
                .filter(command -> command.stream().anyMatch(
                        value -> value.contains("McpSdkRuntimeIT")))
                .findFirst()
                .orElseThrow());
        assertEquals("USER", executor.environments.get(contractCommand)
                .get("WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE"));
        assertEquals("false", executor.environments.get(contractCommand)
                .get("WEB_STARTER_MCP_EXPECTED_CLIENT_ID_PRESENT"));
        assertTrue(executor.commands.stream().noneMatch(command -> command.stream()
                .anyMatch(value -> value.contains("McpSdkCrudRuntimeIT"))));
        assertTrue(Files.readString(evidence.resolve("mcp-sdk-crud-audit-proof.log"))
                .contains("candidate/source/POM/report/transaction-receipt hashes "
                        + "and runtime identity match"));
        assertPrivateEvidence(evidence);
    }

    @Test
    void formalVerifyRevalidatesTheSingleRuntimeReportAndRefreshesAfterLifecycleTests()
            throws Exception {
        Path workspace = workspace();
        Path envFile = validEnv(workspace);
        addPolicyTests(workspace);
        Path scripts = workspace.resolve("scripts");
        for (String name : List.of(
                "validate_release_runtime_test_reports_proof.py",
                "refresh_release_runtime_read_token.py",
                "verify_oauth_runtime.py")) {
            Files.writeString(scripts.resolve(name), "# marker\n");
        }
        Path acceptance = Files.createDirectories(workspace.resolve(
                "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance"));
        Files.writeString(acceptance.resolve("McpSdkCrudRuntimeIT.java"), "// marker\n");
        Files.writeString(workspace.resolve("web-starter-mcp/pom.xml"), "<project/>\n");
        Files.writeString(workspace.resolve(".gitignore"), ".env\n");
        String candidateCommit = commitWorkspace(workspace);
        Path crudProof = writeCrudProof(workspace, temporary.resolve("formal-crud-proof"),
                candidateCommit, "2.0.0", "v2.0.0", "web-starter", "release-sdk");
        Path rawReports = Files.createDirectory(temporary.resolve("formal-runtime-reports"));
        privateDirectory(rawReports);
        Path credentialDirectory = Files.createDirectory(
                temporary.resolve("formal-runtime-credentials"));
        privateDirectory(credentialDirectory);
        Path manifest = credentialDirectory.resolve("manifest.json");
        Files.writeString(manifest, "{\"schemaVersion\":1}\n");
        privateFile(manifest);
        Path unifiedToken = credentialDirectory.resolve("pat-read-unified.json");

        Map<String, String> runtime = Map.ofEntries(
                Map.entry("WEB_STARTER_ACCEPTANCE_MANIFEST", manifest.toString()),
                Map.entry("WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME", "acceptance-admin"),
                Map.entry("WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD",
                        "not-used-by-fake-executor"),
                Map.entry("WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL",
                        "http://127.0.0.1:18088"),
                Map.entry("WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL",
                        "https://localhost:18443"),
                Map.entry("WEB_STARTER_OAUTH_ACCEPTANCE_BASE_URL",
                        "https://localhost:18443"),
                Map.entry("WEB_STARTER_OAUTH_ACCEPTANCE_MANIFEST", manifest.toString()),
                Map.entry("WEB_STARTER_VERIFY_REFRESH_READ_TOKEN_OUTPUT",
                        unifiedToken.toString()),
                Map.entry("WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_DIR",
                        rawReports.toString()),
                Map.entry(
                        "WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_STARTED_AT_EPOCH_NS",
                        "123456789"),
                Map.entry("WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE", crudProof.toString()),
                Map.entry("WEB_STARTER_VERIFY_CANDIDATE_COMMIT", candidateCommit),
                Map.entry("WEB_STARTER_VERIFY_CANDIDATE_VERSION", "2.0.0"),
                Map.entry("WEB_STARTER_VERIFY_CANDIDATE_TAG", "v2.0.0"),
                Map.entry("WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX", "release-sdk"));
        RecordingExecutor executor = new RecordingExecutor(command -> 0,
                command -> command.contains("ps")
                        ? "mysql|running|healthy\nredis|running|healthy\n"
                                + "app|running|healthy\nnginx|running|healthy\n"
                        : "ok\n");
        DeveloperCommands commands = commands(executor, runtime, prompt -> null);
        Path evidence = temporary.resolve("formal-proof-evidence");

        int exit = commands.verify(workspace, envFile, evidence, "web-starter", System.out);

        assertEquals(0, exit);
        assertEquals(2, executor.commands.stream().filter(command -> command.stream()
                .anyMatch(value -> value.contains(
                        "validate_release_runtime_test_reports_proof.py"))).count());
        assertEquals(1, executor.commands.stream().filter(command -> command.stream()
                .anyMatch(value -> value.contains(
                        "refresh_release_runtime_read_token.py"))).count());
        assertTrue(executor.commands.stream().noneMatch(command -> command.contains("test:e2e")));
        assertTrue(executor.commands.stream().noneMatch(command -> command.stream()
                .anyMatch(value -> value.contains("McpSdkRuntimeIT")
                        || value.contains("McpSdkProjectListRuntimeIT"))));
        int oauthCommand = executor.commands.indexOf(executor.commands.stream()
                .filter(command -> command.stream()
                        .anyMatch(value -> value.contains("verify_oauth_runtime.py")))
                .findFirst()
                .orElseThrow());
        assertEquals(unifiedToken.toAbsolutePath().normalize().toString(),
                executor.environments.get(oauthCommand)
                        .get("WEB_STARTER_OAUTH_ACCEPTANCE_PAT_RESPONSE_FILE"));
        assertTrue(Files.isDirectory(
                evidence.resolve("browser-runtime-report-proof")));
        assertTrue(Files.isDirectory(
                evidence.resolve("mcp-runtime-report-proof")));
        assertPrivateEvidence(evidence);
    }

    private static Path writeCrudProof(Path workspace, Path proofDirectory, String commit,
            String version, String tag, String project, String tracePrefix) throws Exception {
        Files.createDirectory(proofDirectory);
        privateDirectory(proofDirectory);
        Path report = proofDirectory.resolve(McpCrudRuntimeProof.REPORT_FILE);
        Files.writeString(report, """
                <?xml version="1.0" encoding="UTF-8"?>
                <testsuite name="dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"
                  tests="1" failures="0" errors="0" skipped="0" flakes="0">
                  <testcase
                    name="provesEachWriteCommitsOnceAcrossConcurrencyRetryConflictAndAudit"
                    classname="dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"/>
                </testsuite>
                """);
        privateFile(report);
        Path transactionReceipt = proofDirectory.resolve(
                McpCrudRuntimeProof.TRANSACTION_RECEIPT_FILE);
        Files.writeString(transactionReceipt, """
                schemaVersion=1
                databaseName=web_starter
                constraintName=chk_webstarter_ac16_tx_audit
                failureTrace=%s-transaction-audit-failure
                failureProjectCode=MCP_TX_ROLLBACK
                failureIdempotencyKeyHash=b43c6f477a4e894c03e54c53fcba80207b2f8e9804bd7525af0be2a6608586a2
                successTrace=%s-create-first
                constraintRowsDuringFault=1
                constraintRowsAfterCleanup=0
                failedProjectRows=0
                failedOperationAuditRows=0
                failedMcpAuditRows=1
                failedMcpAuditExpectedRows=1
                failedIdempotencyRows=0
                successBusinessOperationMcpRows=1
                transactionalTableRows=4
                """.formatted(tracePrefix, tracePrefix));
        privateFile(transactionReceipt);
        Path source = workspace.resolve(McpCrudRuntimeProof.SOURCE_PATH);
        Path rootPom = workspace.resolve(McpCrudRuntimeProof.ROOT_POM_PATH);
        Path modulePom = workspace.resolve(McpCrudRuntimeProof.MODULE_POM_PATH);
        String candidateTree = git(workspace, "rev-parse", "HEAD^{tree}").trim();
        Path proof = proofDirectory.resolve(McpCrudRuntimeProof.PROOF_FILE);
        Files.writeString(proof, """
                schemaVersion=2
                testClass=%s
                testMethod=%s
                sourcePath=%s
                sourceSha256=%s
                rootPomPath=%s
                rootPomSha256=%s
                modulePomPath=%s
                modulePomSha256=%s
                reportFile=%s
                reportSha256=%s
                transactionReceiptFile=%s
                transactionReceiptSha256=%s
                candidateCommit=%s
                candidateTree=%s
                candidateVersion=%s
                candidateTag=%s
                composeProject=%s
                tracePrefix=%s
                startedAtEpochNs=1
                """.formatted(
                McpCrudRuntimeProof.TEST_CLASS,
                McpCrudRuntimeProof.TEST_METHOD,
                McpCrudRuntimeProof.SOURCE_PATH,
                Digests.sha256(Files.readAllBytes(source)),
                McpCrudRuntimeProof.ROOT_POM_PATH,
                Digests.sha256(Files.readAllBytes(rootPom)),
                McpCrudRuntimeProof.MODULE_POM_PATH,
                Digests.sha256(Files.readAllBytes(modulePom)),
                McpCrudRuntimeProof.REPORT_FILE,
                Digests.sha256(Files.readAllBytes(report)),
                McpCrudRuntimeProof.TRANSACTION_RECEIPT_FILE,
                Digests.sha256(Files.readAllBytes(transactionReceipt)),
                commit,
                candidateTree,
                version,
                tag,
                project,
                tracePrefix));
        privateFile(proof);
        return proof;
    }

    private static String commitWorkspace(Path workspace) throws Exception {
        git(workspace, "init", "-q");
        git(workspace, "config", "user.email", "developer-commands@example.invalid");
        git(workspace, "config", "user.name", "Developer Commands Test");
        git(workspace, "add", ".");
        git(workspace, "commit", "-q", "-m", "candidate fixture");
        return git(workspace, "rev-parse", "HEAD^{commit}").trim();
    }

    private static String git(Path workspace, String... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-C");
        command.add(workspace.toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IOException("git fixture command failed: " + output);
        }
        return output;
    }

    private DeveloperCommands commands(ProcessExecutor executor, Map<String, String> environment,
            DeveloperCommands.ConfirmationReader confirmation) {
        return new DeveloperCommands(executor, environment, confirmation,
                () -> Instant.parse("2026-07-19T04:00:00Z"));
    }

    private RecordingExecutor versionsExecutor() {
        return new RecordingExecutor(command -> 0, command -> {
            if (command.contains("-version")) {
                return "openjdk version \"26.0.0\"\n";
            }
            if (command.getFirst().endsWith("mvnw") || command.getFirst().endsWith("mvnw.cmd")) {
                return "Apache Maven 3.9.11\n";
            }
            if (command.getFirst().equals("node")) {
                return "v24.1.0\n";
            }
            if (command.getFirst().equals("pnpm")) {
                return "9.15.9\n";
            }
            if (command.contains("up") && command.contains("--help")) {
                return "--wait wait for services\n";
            }
            return "28.0.0\n";
        });
    }

    private Path workspace() throws Exception {
        Path root = Files.createDirectory(temporary.resolve("workspace-" + workspaceNumber++));
        Files.writeString(root.resolve("pom.xml"), "<project/>\n");
        Files.createDirectories(root.resolve("web-starter-tooling"));
        Files.createDirectories(root.resolve("web-starter-web"));
        Files.writeString(root.resolve("web-starter-web/package.json"), "{\"scripts\":{}}\n");
        Files.writeString(root.resolve("compose.yaml"), "services: {}\n");
        Files.writeString(root.resolve("compose.dev.yaml"), "services: {}\n");
        Files.writeString(root.resolve("compose.production.yaml"), "services: {}\n");
        Path wrapper = root.resolve(isWindows() ? "mvnw.cmd" : "mvnw");
        Files.writeString(wrapper, "wrapper\n");
        Path launcher = root.resolve(isWindows() ? "bin/web-starter.cmd" : "bin/web-starter");
        Files.createDirectories(launcher.getParent());
        Files.writeString(launcher, "launcher\n");
        executable(wrapper);
        executable(launcher);
        return root;
    }

    private Path validEnv(Path workspace) throws Exception {
        Path envFile = workspace.resolve(".env");
        Files.writeString(envFile, """
                WEB_STARTER_DB_USERNAME=web_starter
                WEB_STARTER_DB_PASSWORD=local-database-value-123
                WEB_STARTER_DB_ROOT_PASSWORD=local-root-value-123
                WEB_STARTER_REDIS_PASSWORD=local-redis-value-123
                WEB_STARTER_TOKEN_PEPPER=01234567890123456789012345678901
                WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD=
                """);
        privateFile(envFile);
        return envFile;
    }

    private static void addPolicyTests(Path workspace) throws IOException {
        Path scripts = Files.createDirectories(workspace.resolve("scripts"));
        Files.writeString(scripts.resolve("repository_policy.py"), "# marker\n");
        for (String name : List.of("test_repository_policy.py", "test_production_compose_policy.py",
                "test_release_security_gate.py", "test_recovery_harness.py")) {
            Files.writeString(scripts.resolve(name), "# marker\n");
        }
    }

    private static void privateFile(Path path) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        }
    }

    private static void privateDirectory(Path path) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        }
    }

    private static void assertPrivateEvidence(Path directory) throws IOException {
        if (!posix(directory)) {
            return;
        }
        assertEquals(EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE),
                Files.getPosixFilePermissions(directory));
        try (var files = Files.list(directory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                assertEquals(EnumSet.of(
                                PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE),
                        Files.getPosixFilePermissions(file));
            }
        }
    }

    private static void executable(Path path) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        }
    }

    private static boolean posix(Path path) throws IOException {
        FileStore store = Files.getFileStore(path);
        return store.supportsFileAttributeView("posix");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("windows");
    }

    private static final class RecordingExecutor implements ProcessExecutor {
        private final List<List<String>> commands = new ArrayList<>();
        private final List<Map<String, String>> environments = new ArrayList<>();
        private final Function<List<String>, Integer> exitCodes;
        private final Function<List<String>, String> outputs;

        private RecordingExecutor(Function<List<String>, Integer> exitCodes,
                Function<List<String>, String> outputs) {
            this.exitCodes = exitCodes;
            this.outputs = outputs;
        }

        @Override
        public Execution execute(List<String> command, Path workingDirectory,
                Map<String, String> environment, OutputStream output) {
            List<String> copy = List.copyOf(command);
            commands.add(copy);
            environments.add(Map.copyOf(environment));
            try {
                output.write(outputs.apply(copy).getBytes(StandardCharsets.UTF_8));
            }
            catch (IOException exception) {
                throw new AssertionError(exception);
            }
            return new Execution(exitCodes.apply(copy));
        }
    }
}
