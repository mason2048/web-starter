package dev.webstarter.tooling.dev;

import dev.webstarter.tooling.Checks;
import dev.webstarter.tooling.ToolingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Safe local lifecycle and evidence-collecting verification commands. */
public final class DeveloperCommands {

    public static final int VERIFICATION_FAILED = 6;

    private static final Pattern PROJECT_NAME = Pattern.compile("[a-z0-9][a-z0-9_-]{0,62}");
    private static final Pattern VERSION = Pattern.compile("(?<![0-9])([0-9]+)(?:\\.([0-9]+))?(?:\\.([0-9]+))?");
    private static final DateTimeFormatter EVIDENCE_TIME = DateTimeFormatter
            .ofPattern("yyyyMMdd'T'HHmmss.SSS'Z'")
            .withLocale(Locale.ROOT)
            .withZone(ZoneOffset.UTC);
    private static final List<String> REQUIRED_LOCAL_CONFIGURATION = List.of(
            "WEB_STARTER_DB_USERNAME",
            "WEB_STARTER_DB_PASSWORD",
            "WEB_STARTER_DB_ROOT_PASSWORD",
            "WEB_STARTER_REDIS_PASSWORD",
            "WEB_STARTER_TOKEN_PEPPER");
    private static final List<String> DEVELOPMENT_EXPECTED_SERVICES =
            List.of("mysql", "redis", "app", "nginx");
    private static final List<String> PRODUCTION_EXPECTED_SERVICES =
            List.of("mysql", "redis", "app", "nginx", "mcp-public-nginx");
    private static final List<String> POLICY_TEST_FILES = List.of(
            "test_repository_policy.py",
            "test_production_compose_policy.py",
            "test_release_security_gate.py",
            "test_recovery_harness.py");
    private static final String REPOSITORY_POLICY_SCRIPT = "repository_policy.py";
    private static final Set<String> PLACEHOLDER_FRAGMENTS = Set.of(
            "replace-with", "change-me", "changeme", "todo", "your-password", "your-secret");
    private static final List<String> MCP_COMMON_ENVIRONMENT = List.of(
            "WEB_STARTER_MCP_BASE_URL",
            "WEB_STARTER_MCP_OWNER_ID",
            "WEB_STARTER_MCP_PROJECT_ID",
            "WEB_STARTER_MCP_TRACE_PREFIX");
    private static final String RELEASE_RUNTIME_REPORTS_DIRECTORY =
            "WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_DIR";
    private static final String RELEASE_RUNTIME_REPORTS_STARTED =
            "WEB_STARTER_VERIFY_RELEASE_RUNTIME_TEST_REPORTS_STARTED_AT_EPOCH_NS";
    private static final String REFRESHED_READ_TOKEN_OUTPUT =
            "WEB_STARTER_VERIFY_REFRESH_READ_TOKEN_OUTPUT";
    private static final String OAUTH_PAT_RESPONSE_FILE =
            "WEB_STARTER_OAUTH_ACCEPTANCE_PAT_RESPONSE_FILE";
    private static final List<String> RELEASE_RUNTIME_REPORT_PROOF_ENVIRONMENT = List.of(
            RELEASE_RUNTIME_REPORTS_DIRECTORY,
            RELEASE_RUNTIME_REPORTS_STARTED,
            "WEB_STARTER_VERIFY_CANDIDATE_COMMIT",
            "WEB_STARTER_VERIFY_CANDIDATE_VERSION",
            "WEB_STARTER_VERIFY_CANDIDATE_TAG");
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);

    private final ProcessExecutor executor;
    private final Map<String, String> environment;
    private final ConfirmationReader confirmationReader;
    private final InstantSource instantSource;

    public DeveloperCommands() {
        this(ProcessExecutor.system(), System.getenv(), prompt -> {
            if (System.console() == null) {
                return null;
            }
            return System.console().readLine("%s", prompt);
        }, Instant::now);
    }

    DeveloperCommands(ProcessExecutor executor, Map<String, String> environment,
            ConfirmationReader confirmationReader, InstantSource instantSource) {
        this.executor = Objects.requireNonNull(executor, "executor");
        this.environment = Map.copyOf(environment);
        this.confirmationReader = Objects.requireNonNull(confirmationReader, "confirmationReader");
        this.instantSource = Objects.requireNonNull(instantSource, "instantSource");
    }

    public int doctor(Path workspace, Path configuredEnvFile, PrintStream out) {
        Path root = requireWorkspace(workspace);
        Path envFile = resolveEnvFile(root, configuredEnvFile);
        List<DoctorCheck> checks = new ArrayList<>();

        checks.add(directoryCheck("workspace", root,
                "choose a readable and writable Web Starter workspace"));
        checks.add(pathCheck("maven-wrapper", wrapper(root), true, isPosix(),
                "restore the Maven Wrapper and its executable bit"));
        checks.add(pathCheck("launcher", launcher(root), true, isPosix(),
                "restore bin/web-starter and its executable bit"));
        checks.add(pathCheck("frontend", root.resolve("web-starter-web/package.json"), true, false,
                "restore web-starter-web/package.json"));

        checks.add(versionCheck("java", List.of("java", "-version"), root,
                version -> version.major() >= 21 && version.major() < 27,
                "Java 21 through 26 is required by the Maven enforcer"));
        checks.add(versionCheck("maven", List.of(wrapper(root).toString(), "--version"), root,
                version -> version.major() > 3 || version.major() == 3 && version.minor() >= 9,
                "use the checked-in Maven Wrapper with Maven 3.9 or newer"));
        checks.add(versionCheck("node", List.of("node", "--version"), root,
                version -> version.major() > 22 || version.major() == 22 && version.minor() >= 12,
                "install Node.js 22.12 or newer"));
        checks.add(versionCheck("pnpm", List.of("pnpm", "--version"), root,
                version -> version.major() > 9 || version.major() == 9 && version.minor() >= 15,
                "enable Corepack and install pnpm 9.15 or newer"));

        DoctorCheck docker = commandCheck("docker-engine",
                List.of("docker", "version", "--format", "{{.Server.Version}}"), root,
                "start Docker and grant this user access to its daemon");
        checks.add(docker);
        checks.add(commandCheck("docker-compose",
                List.of("docker", "compose", "version", "--short"), root,
                "install the Docker Compose plugin"));
        checks.add(commandOutputCheck("compose-wait",
                List.of("docker", "compose", "up", "--help"), root, "--wait",
                "upgrade Docker Compose to a release that supports up --wait"));

        Map<String, String> configuration = Map.of();
        if (!Files.exists(envFile, LinkOption.NOFOLLOW_LINKS)) {
            checks.add(new DoctorCheck(CheckStatus.FAIL, "configuration",
                    envFile + " is absent",
                    "copy .env.example to .env, replace every placeholder, then chmod 600 .env"));
        }
        else {
            checks.add(envFilePermissionCheck(envFile));
            try {
                configuration = readEnvironmentFile(envFile);
                checks.addAll(configurationChecks(configuration));
            }
            catch (ToolingException exception) {
                checks.add(new DoctorCheck(CheckStatus.FAIL, "configuration",
                        "the env file cannot be safely parsed", exception.getMessage()));
            }
        }

        for (PortConfig port : configuredPorts(configuration)) {
            checks.add(portCheck(port));
        }

        printDoctor(checks, out, envFile);
        return checks.stream().anyMatch(check -> check.status() == CheckStatus.FAIL)
                ? ToolingException.PREREQUISITE : 0;
    }

    public int up(Path workspace, Path configuredEnvFile, String projectName,
            int timeoutSeconds, boolean noBuild, PrintStream out) {
        Path root = requireWorkspace(workspace);
        String safeProject = requireProjectName(projectName);
        Path envFile = requireSafeRuntimeEnv(root, configuredEnvFile);
        if (timeoutSeconds < 1 || timeoutSeconds > 1800) {
            throw Checks.usage("--timeout-seconds must be between 1 and 1800");
        }

        List<String> compose = composeCommand(root, envFile, safeProject);
        out.println("Validating Compose configuration (secrets are not printed)...");
        int configExit = executeTo(composeWith(compose, "config", "--quiet"), root, Map.of(), out);
        if (configExit != 0) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "Docker Compose configuration is invalid; no services were started");
        }

        List<String> command = new ArrayList<>(compose);
        command.addAll(List.of("up", "-d"));
        if (!noBuild) {
            command.add("--build");
        }
        command.addAll(List.of("--wait", "--wait-timeout", String.valueOf(timeoutSeconds)));
        out.printf("Starting %s and waiting up to %d seconds for readiness...%n",
                safeProject, timeoutSeconds);
        int upExit = executeTo(command, root, Map.of(), out);
        if (upExit != 0) {
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "Compose did not reach readiness; inspect docker compose ps and logs");
        }
        out.printf("READY project=%s dataVolumes=preserved%n", safeProject);
        return 0;
    }

    public int down(Path workspace, Path configuredEnvFile, String projectName,
            boolean deleteVolumes, String nonInteractiveConfirmation, PrintStream out) {
        Path root = requireWorkspace(workspace);
        String safeProject = requireProjectName(projectName);
        Path envFile = requireExistingEnvFile(root, configuredEnvFile);
        if (!deleteVolumes && nonInteractiveConfirmation != null) {
            throw Checks.usage("--confirm-delete-volumes is valid only together with --volumes");
        }
        if (deleteVolumes) {
            confirmVolumeDeletion(safeProject, nonInteractiveConfirmation);
        }

        List<String> command = composeCommand(root, envFile, safeProject);
        command.addAll(List.of("down", "--remove-orphans"));
        if (deleteVolumes) {
            command.add("--volumes");
        }
        int exit = executeTo(command, root, Map.of(), out);
        if (exit != 0) {
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "Compose shutdown failed; no additional cleanup was attempted");
        }
        out.printf("DOWN project=%s volumes=%s%n", safeProject,
                deleteVolumes ? "deleted-after-confirmation" : "preserved");
        return 0;
    }

    public int verify(Path workspace, Path configuredEnvFile, Path configuredEvidenceDirectory,
            String projectName, PrintStream out) {
        Path root = requireWorkspace(workspace);
        String safeProject = requireProjectName(projectName);
        Path envFile = resolveEnvFile(root, configuredEnvFile);
        Path evidenceDirectory = createEvidenceDirectory(root, configuredEvidenceDirectory);
        List<LayerOutcome> outcomes = new ArrayList<>();

        outcomes.add(runLayer(evidenceDirectory, out, "backend", List.of(
                step("maven-verify", List.of(wrapper(root).toString(), "--batch-mode",
                        "--no-transfer-progress", "verify"), root))));

        Path frontend = root.resolve("web-starter-web");
        if (!Files.isRegularFile(frontend.resolve("package.json"), LinkOption.NOFOLLOW_LINKS)) {
            outcomes.add(recordUnavailable(evidenceDirectory, out, "frontend", LayerStatus.NOT_COVERED,
                    "web-starter-web/package.json is absent"));
        }
        else {
            outcomes.add(runLayer(evidenceDirectory, out, "frontend", List.of(
                    step("lint", List.of("pnpm", "lint"), frontend),
                    step("typecheck", List.of("pnpm", "typecheck"), frontend),
                    step("unit-test", List.of("pnpm", "test"), frontend),
                    step("production-build", List.of("pnpm", "build"), frontend))));
        }

        if (policyTestsPresent(root)) {
            Map<String, String> policyEnvironment = policyTestEnvironment();
            List<StepSpec> policySteps = new ArrayList<>(POLICY_TEST_FILES.stream()
                    .map(file -> step(policyStepName(file), pythonTestCommand(file), root,
                            policyEnvironment))
                    .toList());
            policySteps.add(step("repository-secret-scan",
                    List.of(pythonExecutable(), "-B", "scripts/" + REPOSITORY_POLICY_SCRIPT,
                            "secrets"),
                    root, policyEnvironment));
            outcomes.add(runLayer(evidenceDirectory, out, "policy", policySteps));
        }
        else {
            outcomes.add(recordUnavailable(evidenceDirectory, out, "policy", LayerStatus.NOT_COVERED,
                    "one or more checked-in policy test suites are absent"));
        }

        outcomes.add(containerLayer(root, envFile, safeProject, evidenceDirectory, out));
        outcomes.add(browserLayer(root, evidenceDirectory, out));
        outcomes.add(oauthLayer(root, evidenceDirectory, out));
        outcomes.add(mcpLayer(root, safeProject, evidenceDirectory, out));

        writeSummary(evidenceDirectory, outcomes);
        printVerifySummary(outcomes, evidenceDirectory, out);
        return outcomes.stream().allMatch(outcome -> outcome.status() == LayerStatus.PASS)
                ? 0 : VERIFICATION_FAILED;
    }

    private LayerOutcome containerLayer(Path root, Path envFile, String projectName,
            Path evidenceDirectory, PrintStream out) {
        if (!Files.isRegularFile(envFile, LinkOption.NOFOLLOW_LINKS)) {
            return recordUnavailable(evidenceDirectory, out, "container", LayerStatus.ENV_REQUIRED,
                    "runtime env file is absent; run doctor and create .env before up");
        }
        String composeMode = environment.get("WEB_STARTER_VERIFY_COMPOSE_MODE");
        List<String> compose;
        List<String> expectedServices;
        if (blank(composeMode)) {
            compose = composeCommand(root, envFile, projectName);
            expectedServices = DEVELOPMENT_EXPECTED_SERVICES;
        }
        else if ("production".equals(composeMode)) {
            compose = productionComposeCommand(root, envFile, projectName);
            expectedServices = PRODUCTION_EXPECTED_SERVICES;
        }
        else {
            return recordUnavailable(evidenceDirectory, out, "container", LayerStatus.FAIL,
                    "WEB_STARTER_VERIFY_COMPOSE_MODE must be production when set");
        }
        StepSpec status = new StepSpec("runtime-status",
                composeWith(compose, "ps", "--all", "--format",
                        "{{.Service}}|{{.State}}|{{.Health}}"), root, Map.of(),
                execution -> classifyComposeStatus(execution.output(), expectedServices),
                null, LayerStatus.ENV_REQUIRED);
        return runLayer(evidenceDirectory, out, "container", List.of(
                step("compose-config", composeWith(compose, "config", "--quiet"), root), status));
    }

    private LayerOutcome browserLayer(Path root, Path evidenceDirectory, PrintStream out) {
        List<StepSpec> steps = new ArrayList<>();
        if (releaseRuntimeReportProofRequested()) {
            List<String> missing = missingReleaseRuntimeReportProofInputs();
            if (!missing.isEmpty()) {
                return recordUnavailable(evidenceDirectory, out, "browser",
                        LayerStatus.ENV_REQUIRED,
                        "missing release runtime report proof inputs: "
                                + String.join(", ", missing));
            }
            steps.add(releaseRuntimeReportProofStep(
                    root, evidenceDirectory, "browser-runtime-report-proof"));
        }
        else {
        Path frontend = root.resolve("web-starter-web");
        Path packageJson = frontend.resolve("package.json");
        boolean hasPlaywright = Files.isRegularFile(frontend.resolve("playwright.config.ts"),
                LinkOption.NOFOLLOW_LINKS)
                || Files.isRegularFile(frontend.resolve("playwright.config.js"), LinkOption.NOFOLLOW_LINKS);
        boolean hasScript = fileContains(packageJson, "\"test:e2e\"");
        if (!hasPlaywright || !hasScript) {
            return recordUnavailable(evidenceDirectory, out, "browser", LayerStatus.NOT_COVERED,
                    "no checked-in Playwright config plus test:e2e script exists");
        }
        List<String> missing = new ArrayList<>();
        for (String name : List.of(
                "WEB_STARTER_BROWSER_BASE_URL",
                "WEB_STARTER_ACCEPTANCE_MANIFEST",
                "WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME",
                "WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD")) {
            if (blank(environment.get(name))) {
                missing.add(name);
            }
        }
        if (!missing.isEmpty()) {
            return recordUnavailable(evidenceDirectory, out, "browser", LayerStatus.ENV_REQUIRED,
                    "missing browser acceptance inputs: " + String.join(", ", missing));
        }
            steps.add(step("playwright-e2e", List.of("pnpm", "test:e2e"), frontend));
        }

        String refreshedOutput = environment.get(REFRESHED_READ_TOKEN_OUTPUT);
        if (!blank(refreshedOutput)) {
            String manifest = environment.get("WEB_STARTER_ACCEPTANCE_MANIFEST");
            if (blank(manifest)) {
                return recordUnavailable(evidenceDirectory, out, "browser",
                        LayerStatus.ENV_REQUIRED,
                        "missing browser post-lifecycle token input: "
                                + "WEB_STARTER_ACCEPTANCE_MANIFEST");
            }
            Path manifestPath = Path.of(manifest).toAbsolutePath().normalize();
            Path credentialDirectory = manifestPath.getParent();
            if (credentialDirectory == null) {
                return recordUnavailable(evidenceDirectory, out, "browser",
                        LayerStatus.ENV_REQUIRED,
                        "browser post-lifecycle manifest has no credential directory");
            }
            steps.add(step("refresh-read-token", List.of(
                    pythonExecutable(), "-B",
                    root.resolve("scripts/refresh_release_runtime_read_token.py").toString(),
                    "--repository-root", root.toString(),
                    "--credential-directory", credentialDirectory.toString(),
                    "--manifest", manifestPath.toString(),
                    "--output", Path.of(refreshedOutput).toAbsolutePath().normalize().toString()),
                    root));
        }
        return runLayer(evidenceDirectory, out, "browser", steps);
    }

    private LayerOutcome oauthLayer(Path root, Path evidenceDirectory, PrintStream out) {
        Path runner = root.resolve("scripts/verify_oauth_runtime.py");
        if (!Files.isRegularFile(runner, LinkOption.NOFOLLOW_LINKS)) {
            return recordUnavailable(evidenceDirectory, out, "oauth", LayerStatus.NOT_COVERED,
                    "scripts/verify_oauth_runtime.py is not checked in");
        }
        List<String> missing = new ArrayList<>();
        for (String name : List.of(
                "WEB_STARTER_OAUTH_ACCEPTANCE_BASE_URL",
                "WEB_STARTER_OAUTH_ACCEPTANCE_MANIFEST")) {
            if (blank(environment.get(name))) {
                missing.add(name);
            }
        }
        if (!missing.isEmpty()) {
            return recordUnavailable(evidenceDirectory, out, "oauth", LayerStatus.ENV_REQUIRED,
                    "missing OAuth acceptance inputs: " + String.join(", ", missing));
        }
        Map<String, String> overrides = blank(environment.get(REFRESHED_READ_TOKEN_OUTPUT))
                ? Map.of()
                : Map.of(OAUTH_PAT_RESPONSE_FILE,
                        Path.of(environment.get(REFRESHED_READ_TOKEN_OUTPUT))
                                .toAbsolutePath().normalize().toString());
        return runLayer(evidenceDirectory, out, "oauth", List.of(
                step("oauth-runtime", List.of(pythonExecutable(), runner.toString()), root,
                        overrides)));
    }

    private LayerOutcome mcpLayer(Path root, String projectName, Path evidenceDirectory,
            PrintStream out) {
        if (releaseRuntimeReportProofRequested()) {
            List<String> missing = new ArrayList<>(missingReleaseRuntimeReportProofInputs());
            for (String name : List.of(
                    "WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE",
                    "WEB_STARTER_VERIFY_CANDIDATE_COMMIT",
                    "WEB_STARTER_VERIFY_CANDIDATE_VERSION",
                    "WEB_STARTER_VERIFY_CANDIDATE_TAG",
                    "WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX")) {
                if (blank(environment.get(name)) && !missing.contains(name)) {
                    missing.add(name);
                }
            }
            if (!missing.isEmpty()) {
                return recordUnavailable(evidenceDirectory, out, "mcp",
                        LayerStatus.ENV_REQUIRED,
                        "missing MCP proof inputs: " + String.join(", ", missing));
            }
            Path crudProofPath = Path.of(
                    environment.get("WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE"))
                    .toAbsolutePath().normalize();
            return runLayer(evidenceDirectory, out, "mcp", List.of(
                    releaseRuntimeReportProofStep(
                            root, evidenceDirectory, "mcp-runtime-report-proof"),
                    mcpCrudProofStep(root, projectName, crudProofPath)));
        }

        Path runtimeTest = root.resolve(
                "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkRuntimeIT.java");
        if (!Files.isRegularFile(runtimeTest, LinkOption.NOFOLLOW_LINKS)) {
            return recordUnavailable(evidenceDirectory, out, "mcp", LayerStatus.NOT_COVERED,
                    "official MCP SDK runtime acceptance tests are absent");
        }
        List<String> missing = new ArrayList<>();
        for (String name : MCP_COMMON_ENVIRONMENT) {
            if (blank(environment.get(name))) {
                missing.add(name);
            }
        }
        String refreshedReadToken = environment.get(REFRESHED_READ_TOKEN_OUTPUT);
        String readToken = blank(refreshedReadToken)
                ? environment.get("WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE")
                : refreshedReadToken;
        String crudProof = environment.get("WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE");
        if (blank(readToken)) {
            missing.add("WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE");
        }
        if (blank(crudProof)) {
            missing.add("WEB_STARTER_VERIFY_MCP_CRUD_PROOF_FILE");
        }
        for (String name : List.of(
                "WEB_STARTER_VERIFY_CANDIDATE_COMMIT",
                "WEB_STARTER_VERIFY_CANDIDATE_VERSION",
                "WEB_STARTER_VERIFY_CANDIDATE_TAG",
                "WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX")) {
            if (blank(environment.get(name))) {
                missing.add(name);
            }
        }
        if (!missing.isEmpty()) {
            return recordUnavailable(evidenceDirectory, out, "mcp", LayerStatus.ENV_REQUIRED,
                    "missing MCP acceptance inputs: " + String.join(", ", missing));
        }
        Path readTokenPath;
        Path crudProofPath;
        try {
            readTokenPath = requirePrivateTokenFile(root, readToken,
                    blank(refreshedReadToken)
                            ? "WEB_STARTER_VERIFY_MCP_READ_TOKEN_RESPONSE_FILE"
                            : REFRESHED_READ_TOKEN_OUTPUT);
            crudProofPath = Path.of(crudProof).toAbsolutePath().normalize();
        }
        catch (RuntimeException exception) {
            return recordUnavailable(evidenceDirectory, out, "mcp", LayerStatus.ENV_REQUIRED,
                    exception.getMessage());
        }
        List<String> base = List.of(wrapper(root).toString(), "--batch-mode", "--no-transfer-progress",
                "-pl", "web-starter-mcp", "-am", "-Dsurefire.failIfNoSpecifiedTests=false", "test");
        return runLayer(evidenceDirectory, out, "mcp", List.of(
                mcpStep("sdk-contract", base, root, "McpSdkRuntimeIT", readTokenPath, "contract"),
                mcpStep("sdk-list-rbac", base, root, "McpSdkProjectListRuntimeIT", readTokenPath, "list"),
                mcpCrudProofStep(root, projectName, crudProofPath)));
    }

    private boolean releaseRuntimeReportProofRequested() {
        return !blank(environment.get(RELEASE_RUNTIME_REPORTS_DIRECTORY))
                || !blank(environment.get(RELEASE_RUNTIME_REPORTS_STARTED));
    }

    private List<String> missingReleaseRuntimeReportProofInputs() {
        return RELEASE_RUNTIME_REPORT_PROOF_ENVIRONMENT.stream()
                .filter(name -> blank(environment.get(name)))
                .toList();
    }

    private StepSpec releaseRuntimeReportProofStep(
            Path root, Path evidenceDirectory, String outputName) {
        Path summaryOutput = createPrivateSubdirectory(evidenceDirectory, outputName);
        return step("release-runtime-report-proof", List.of(
                pythonExecutable(), "-B",
                root.resolve("scripts/validate_release_runtime_test_reports_proof.py").toString(),
                "--repository-root", root.toString(),
                "--evidence-directory", environment.get(RELEASE_RUNTIME_REPORTS_DIRECTORY),
                "--expected-candidate-commit",
                environment.get("WEB_STARTER_VERIFY_CANDIDATE_COMMIT"),
                "--expected-candidate-version",
                environment.get("WEB_STARTER_VERIFY_CANDIDATE_VERSION"),
                "--expected-candidate-tag",
                environment.get("WEB_STARTER_VERIFY_CANDIDATE_TAG"),
                "--expected-run-started-at-epoch-ns",
                environment.get(RELEASE_RUNTIME_REPORTS_STARTED),
                "--require-pass",
                "--summary-output", summaryOutput.toString()), root);
    }

    private StepSpec mcpStep(String name, List<String> base, Path root, String testClass,
            Path tokenFile, String traceSuffix) {
        List<String> command = new ArrayList<>(base);
        command.add(command.size() - 1,
                "-Dtest=dev.webstarter.mcp.acceptance." + testClass);
        Map<String, String> overrides = new LinkedHashMap<>();
        overrides.put("WEB_STARTER_MCP_TOKEN_RESPONSE_FILE", tokenFile.toString());
        overrides.put("WEB_STARTER_MCP_TRACE_PREFIX",
                environment.get("WEB_STARTER_MCP_TRACE_PREFIX") + "-" + traceSuffix);
        if ("McpSdkRuntimeIT".equals(testClass)) {
            overrides.put("WEB_STARTER_MCP_EXPECTED_ACTOR_TYPE", "USER");
            overrides.put("WEB_STARTER_MCP_EXPECTED_CLIENT_ID_PRESENT", "false");
        }
        return new StepSpec(name, List.copyOf(command), root, Map.copyOf(overrides), null,
                null, LayerStatus.FAIL);
    }

    private StepSpec mcpCrudProofStep(Path root, String projectName, Path proofPath) {
        McpCrudRuntimeProof.Expected expected = new McpCrudRuntimeProof.Expected(
                environment.get("WEB_STARTER_VERIFY_CANDIDATE_COMMIT"),
                environment.get("WEB_STARTER_VERIFY_CANDIDATE_VERSION"),
                environment.get("WEB_STARTER_VERIFY_CANDIDATE_TAG"),
                projectName,
                environment.get("WEB_STARTER_VERIFY_MCP_CRUD_TRACE_PREFIX"));
        LocalStep check = output -> {
            try {
                McpCrudRuntimeProof.Validation validation = McpCrudRuntimeProof.validate(
                        root, proofPath, expected);
                output.write(("validated one private Surefire testcase for "
                        + validation.testClass() + "#" + validation.testMethod()
                        + "; candidate/source/POM/report/transaction-receipt hashes "
                        + "and runtime identity match\n")
                        .getBytes(StandardCharsets.UTF_8));
                return new StepAssessment(LayerStatus.PASS,
                        "single prior CRUD SDK execution proof is valid");
            }
            catch (McpCrudRuntimeProof.ProofException exception) {
                output.write(("FAIL: " + exception.getMessage() + System.lineSeparator())
                        .getBytes(StandardCharsets.UTF_8));
                return new StepAssessment(LayerStatus.FAIL, exception.getMessage());
            }
        };
        return new StepSpec("sdk-crud-audit-proof", List.of(), root, Map.of(), null,
                check, LayerStatus.FAIL);
    }

    private LayerOutcome runLayer(Path evidenceDirectory, PrintStream out, String name,
            List<StepSpec> steps) {
        out.printf("[%s] START%n", name);
        Instant started = instantSource.now();
        List<StepOutcome> results = new ArrayList<>();
        LayerStatus status = LayerStatus.PASS;
        String reason = "all fixed checks passed";
        for (StepSpec step : steps) {
            Path log = evidenceDirectory.resolve(name + "-" + step.name() + ".log");
            StepOutcome result = executeStep(step, log);
            results.add(result);
            if (result.status() == LayerStatus.FAIL) {
                status = LayerStatus.FAIL;
                reason = "one or more fixed checks failed";
            }
            else if (result.status() == LayerStatus.ENV_REQUIRED && status != LayerStatus.FAIL) {
                status = LayerStatus.ENV_REQUIRED;
                reason = result.reason();
            }
            out.printf("[%s/%s] %s exit=%d log=%s%n", name, step.name(), result.status(),
                    result.exitCode(), evidenceDirectory.relativize(log));
        }
        LayerOutcome outcome = new LayerOutcome(name, status, reason, started, instantSource.now(), results);
        out.printf("[%s] %s%n", name, status);
        return outcome;
    }

    private StepOutcome executeStep(StepSpec step, Path log) {
        try (OutputStream output = newPrivateOutputStream(log)) {
            if (step.localStep() != null) {
                StepAssessment assessment = step.localStep().execute(output);
                int exitCode = assessment.status() == LayerStatus.PASS ? 0 : 1;
                return new StepOutcome(step.name(), assessment.status(), exitCode,
                        assessment.reason(), log);
            }
            ProcessExecutor.Execution execution = executor.execute(
                    step.command(), step.workingDirectory(), step.environment(), output);
            if (execution.exitCode() != 0) {
                return new StepOutcome(step.name(), step.failureStatus(), execution.exitCode(),
                        "command returned a nonzero exit code", log);
            }
        }
        catch (IOException exception) {
            return new StepOutcome(step.name(), LayerStatus.FAIL, 5,
                    "could not create or write the evidence log", log);
        }
        if (step.classifier() != null) {
            try {
                StepAssessment assessment = step.classifier().apply(new LoggedExecution(
                        Files.readString(log, StandardCharsets.UTF_8)));
                if (assessment != null && assessment.status() != LayerStatus.PASS) {
                    return new StepOutcome(step.name(), assessment.status(), 0, assessment.reason(), log);
                }
            }
            catch (IOException exception) {
                return new StepOutcome(step.name(), LayerStatus.FAIL, 5,
                        "could not read the evidence log", log);
            }
        }
        return new StepOutcome(step.name(), LayerStatus.PASS, 0, "passed", log);
    }

    private LayerOutcome recordUnavailable(Path evidenceDirectory, PrintStream out, String name,
            LayerStatus status, String reason) {
        Instant now = instantSource.now();
        Path log = evidenceDirectory.resolve(name + "-status.log");
        try {
            writePrivateString(log, status + ": " + reason + System.lineSeparator());
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "cannot write verification evidence for " + name, exception);
        }
        LayerOutcome outcome = new LayerOutcome(name, status, reason, now, now, List.of(
                new StepOutcome("prerequisite", status, 0, reason, log)));
        out.printf("[%s] %s reason=%s%n", name, status, reason);
        return outcome;
    }

    private static StepAssessment classifyComposeStatus(String output, List<String> expectedServices) {
        Map<String, String[]> services = new LinkedHashMap<>();
        for (String line : output.lines().toList()) {
            String[] values = line.trim().split("\\|", -1);
            if (values.length >= 3 && !values[0].isBlank()) {
                services.put(values[0], values);
            }
        }
        List<String> missing = expectedServices.stream()
                .filter(service -> !services.containsKey(service))
                .toList();
        if (!missing.isEmpty()) {
            return new StepAssessment(LayerStatus.ENV_REQUIRED,
                    "Compose services are not running: " + String.join(", ", missing)
                            + "; run ./bin/web-starter up");
        }
        for (String service : expectedServices) {
            String[] values = services.get(service);
            if (!"running".equalsIgnoreCase(values[1]) || !"healthy".equalsIgnoreCase(values[2])) {
                return new StepAssessment(LayerStatus.FAIL,
                        "Compose service " + service + " is not running and healthy");
            }
        }
        return new StepAssessment(LayerStatus.PASS, "all Compose services are running and healthy");
    }

    private Path requirePrivateTokenFile(Path root, String rawPath, String name) {
        Path path = Path.of(rawPath).toAbsolutePath().normalize();
        if (!path.isAbsolute() || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(path)) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    name + " must identify an existing non-symlink regular file");
        }
        if (path.startsWith(root)) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    name + " must stay outside the Git workspace");
        }
        if (isPosix()) {
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path,
                        LinkOption.NOFOLLOW_LINKS);
                if (permissions.contains(PosixFilePermission.GROUP_READ)
                        || permissions.contains(PosixFilePermission.OTHERS_READ)
                        || permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    throw new ToolingException(ToolingException.PREREQUISITE,
                            name + " must be private (chmod 600)");
                }
            }
            catch (IOException exception) {
                throw new ToolingException(ToolingException.PREREQUISITE,
                        "cannot inspect permissions for " + name, exception);
            }
        }
        return path;
    }

    private Path createEvidenceDirectory(Path root, Path configured) {
        Path path = configured == null
                ? root.resolve("target/web-starter-verify/" + EVIDENCE_TIME.format(instantSource.now()))
                : configured.toAbsolutePath().normalize();
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ToolingException(ToolingException.CONFLICT,
                    "evidence directory must not already exist: " + path);
        }
        try {
            if (isPosix()) {
                FileAttribute<Set<PosixFilePermission>> permissions =
                        PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS);
                Files.createDirectories(path, permissions);
                Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS);
            }
            else {
                Files.createDirectories(path);
            }
            return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "cannot create evidence directory: " + path, exception);
        }
    }

    private static Path createPrivateSubdirectory(Path parent, String name) {
        Path path = parent.resolve(name);
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ToolingException(ToolingException.CONFLICT,
                    "private verification subdirectory already exists: " + name);
        }
        try {
            if (isPosix()) {
                FileAttribute<Set<PosixFilePermission>> permissions =
                        PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS);
                Files.createDirectory(path, permissions);
                Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS);
            }
            else {
                Files.createDirectory(path);
            }
            return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "cannot create private verification subdirectory: " + name, exception);
        }
    }

    private void writeSummary(Path evidenceDirectory, List<LayerOutcome> outcomes) {
        Instant generatedAt = instantSource.now();
        boolean passed = outcomes.stream().allMatch(outcome -> outcome.status() == LayerStatus.PASS);
        StringBuilder markdown = new StringBuilder("# Web Starter verification evidence\n\n")
                .append("Generated: ").append(generatedAt).append("\n\n")
                .append("Overall: ").append(passed ? "PASS" : "INCOMPLETE_OR_FAILED").append("\n\n")
                .append("| Layer | Status | Reason |\n")
                .append("|---|---|---|\n");
        for (LayerOutcome outcome : outcomes) {
            markdown.append("| ").append(outcome.name()).append(" | ")
                    .append(outcome.status()).append(" | ")
                    .append(escapeMarkdown(outcome.reason())).append(" |\n");
        }

        StringBuilder json = new StringBuilder("{\n  \"schemaVersion\": 1,\n")
                .append("  \"generatedAt\": \"").append(generatedAt).append("\",\n")
                .append("  \"status\": \"")
                .append(passed ? "PASS" : "INCOMPLETE_OR_FAILED")
                .append("\",\n  \"layers\": [\n");
        for (int index = 0; index < outcomes.size(); index++) {
            LayerOutcome outcome = outcomes.get(index);
            json.append("    {\"name\":\"").append(json(outcome.name()))
                    .append("\",\"status\":\"").append(outcome.status())
                    .append("\",\"reason\":\"").append(json(outcome.reason()))
                    .append("\",\"startedAt\":\"").append(outcome.startedAt())
                    .append("\",\"finishedAt\":\"").append(outcome.finishedAt())
                    .append("\",\"steps\":[");
            for (int stepIndex = 0; stepIndex < outcome.steps().size(); stepIndex++) {
                StepOutcome step = outcome.steps().get(stepIndex);
                json.append("{\"name\":\"").append(json(step.name()))
                        .append("\",\"status\":\"").append(step.status())
                        .append("\",\"exitCode\":").append(step.exitCode())
                        .append(",\"reason\":\"").append(json(step.reason()))
                        .append("\",\"log\":\"")
                        .append(json(evidenceDirectory.relativize(step.log()).toString()))
                        .append("\"}");
                if (stepIndex + 1 < outcome.steps().size()) {
                    json.append(',');
                }
            }
            json.append("]}");
            if (index + 1 < outcomes.size()) {
                json.append(',');
            }
            json.append('\n');
        }
        json.append("  ]\n}\n");
        try {
            writePrivateString(evidenceDirectory.resolve("summary.md"), markdown);
            writePrivateString(evidenceDirectory.resolve("summary.json"), json);
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "cannot write verification summary", exception);
        }
    }

    private static OutputStream newPrivateOutputStream(Path path) throws IOException {
        if (isPosix()) {
            FileAttribute<Set<PosixFilePermission>> permissions =
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS);
            return Channels.newOutputStream(Files.newByteChannel(path,
                    Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), permissions));
        }
        return Files.newOutputStream(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static void writePrivateString(Path path, CharSequence value) throws IOException {
        try (OutputStream output = newPrivateOutputStream(path)) {
            output.write(value.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void printVerifySummary(List<LayerOutcome> outcomes, Path evidenceDirectory,
            PrintStream out) {
        out.println("VERIFY SUMMARY");
        for (LayerOutcome outcome : outcomes) {
            out.printf("%-10s %s%n", outcome.name(), outcome.status());
        }
        boolean passed = outcomes.stream().allMatch(outcome -> outcome.status() == LayerStatus.PASS);
        out.printf("VERIFY %s evidence=%s%n", passed ? "PASS" : "INCOMPLETE_OR_FAILED",
                evidenceDirectory);
    }

    private DoctorCheck versionCheck(String name, List<String> command, Path root,
            java.util.function.Predicate<SemanticVersion> accepted, String action) {
        Captured captured = capture(command, root, Map.of());
        if (captured.exitCode() != 0) {
            return new DoctorCheck(CheckStatus.FAIL, name, "command unavailable or failed", action);
        }
        Matcher matcher = VERSION.matcher(captured.output());
        if (!matcher.find()) {
            return new DoctorCheck(CheckStatus.FAIL, name, "version could not be parsed", action);
        }
        SemanticVersion version = new SemanticVersion(integer(matcher.group(1)),
                integer(matcher.group(2)), integer(matcher.group(3)));
        return accepted.test(version)
                ? new DoctorCheck(CheckStatus.PASS, name, "version " + version, "none")
                : new DoctorCheck(CheckStatus.FAIL, name, "unsupported version " + version, action);
    }

    private DoctorCheck commandCheck(String name, List<String> command, Path root, String action) {
        Captured captured = capture(command, root, Map.of());
        return captured.exitCode() == 0
                ? new DoctorCheck(CheckStatus.PASS, name, firstNonBlankLine(captured.output()), "none")
                : new DoctorCheck(CheckStatus.FAIL, name, "command unavailable or failed", action);
    }

    private DoctorCheck commandOutputCheck(String name, List<String> command, Path root,
            String expected, String action) {
        Captured captured = capture(command, root, Map.of());
        return captured.exitCode() == 0 && captured.output().contains(expected)
                ? new DoctorCheck(CheckStatus.PASS, name, expected + " is supported", "none")
                : new DoctorCheck(CheckStatus.FAIL, name, expected + " is not available", action);
    }

    private Captured capture(List<String> command, Path root, Map<String, String> overrides) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ProcessExecutor.Execution execution = executor.execute(command, root, overrides, output);
        return new Captured(execution.exitCode(), output.toString(StandardCharsets.UTF_8));
    }

    private int executeTo(List<String> command, Path root, Map<String, String> overrides,
            PrintStream out) {
        return executor.execute(command, root, overrides, out).exitCode();
    }

    private static DoctorCheck pathCheck(String name, Path path, boolean readable,
            boolean executable, String action) {
        boolean exists = Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path);
        boolean accepted = exists && (!readable || Files.isReadable(path))
                && (!executable || Files.isExecutable(path));
        return accepted
                ? new DoctorCheck(CheckStatus.PASS, name, path.toString(), "none")
                : new DoctorCheck(CheckStatus.FAIL, name, "missing or inaccessible: " + path, action);
    }

    private static DoctorCheck directoryCheck(String name, Path path, String action) {
        boolean accepted = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                && !Files.isSymbolicLink(path) && Files.isReadable(path) && Files.isWritable(path);
        return accepted
                ? new DoctorCheck(CheckStatus.PASS, name, path.toString(), "none")
                : new DoctorCheck(CheckStatus.FAIL, name, "missing or inaccessible: " + path, action);
    }

    private static DoctorCheck envFilePermissionCheck(Path envFile) {
        if (!Files.isRegularFile(envFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(envFile)) {
            return new DoctorCheck(CheckStatus.FAIL, "env-file", "not a regular non-symlink file",
                    "replace it with a private regular file");
        }
        if (!Files.isReadable(envFile)) {
            return new DoctorCheck(CheckStatus.FAIL, "env-file", "not readable",
                    "grant the current user read access");
        }
        if (isPosix()) {
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(envFile,
                        LinkOption.NOFOLLOW_LINKS);
                Set<PosixFilePermission> unsafe = EnumSet.of(
                        PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                        PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE);
                if (permissions.stream().anyMatch(unsafe::contains)) {
                    return new DoctorCheck(CheckStatus.FAIL, "env-file", "permissions are too broad",
                            "run chmod 600 " + envFile);
                }
            }
            catch (IOException exception) {
                return new DoctorCheck(CheckStatus.FAIL, "env-file", "permissions cannot be inspected",
                        "verify ownership and set mode 600");
            }
        }
        return new DoctorCheck(CheckStatus.PASS, "env-file", "private regular file", "none");
    }

    private static List<DoctorCheck> configurationChecks(Map<String, String> configuration) {
        List<DoctorCheck> checks = new ArrayList<>();
        for (String name : REQUIRED_LOCAL_CONFIGURATION) {
            String value = configuration.get(name);
            if (blank(value)) {
                checks.add(new DoctorCheck(CheckStatus.FAIL, "config:" + name, "missing or empty",
                        "set a local-only non-placeholder value in the env file"));
            }
            else if (placeholder(value)) {
                checks.add(new DoctorCheck(CheckStatus.FAIL, "config:" + name, "placeholder value detected",
                        "replace the placeholder with a local-only secret"));
            }
            else if ("WEB_STARTER_TOKEN_PEPPER".equals(name) && value.length() < 32) {
                checks.add(new DoctorCheck(CheckStatus.FAIL, "config:" + name, "value is shorter than 32 characters",
                        "generate at least 32 random bytes outside the repository"));
            }
            else {
                checks.add(new DoctorCheck(CheckStatus.PASS, "config:" + name, "configured", "none"));
            }
        }
        String bootstrapPassword = configuration.get("WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD");
        if (blank(bootstrapPassword)) {
            checks.add(new DoctorCheck(CheckStatus.WARN,
                    "config:WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD", "empty",
                    "set it only for an empty database; an initialized database may keep it empty"));
        }
        else if (placeholder(bootstrapPassword)) {
            checks.add(new DoctorCheck(CheckStatus.FAIL,
                    "config:WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD", "placeholder value detected",
                    "replace it for first boot or clear it after initialization"));
        }
        else {
            checks.add(new DoctorCheck(CheckStatus.PASS,
                    "config:WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD", "configured", "none"));
        }
        return checks;
    }

    private static DoctorCheck portCheck(PortConfig port) {
        if (port.port() < 1 || port.port() > 65535) {
            return new DoctorCheck(CheckStatus.FAIL, "port:" + port.name(), "invalid port",
                    "set " + port.environmentName() + " to a value from 1 through 65535");
        }
        try (ServerSocket socket = new ServerSocket()) {
            socket.setReuseAddress(false);
            socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port.port()));
            return new DoctorCheck(CheckStatus.PASS, "port:" + port.name(),
                    port.port() + " is available on loopback", "none");
        }
        catch (IOException exception) {
            return new DoctorCheck(CheckStatus.WARN, "port:" + port.name(),
                    port.port() + " is already in use",
                    "confirm it belongs to this Compose project or change " + port.environmentName());
        }
    }

    private static void printDoctor(List<DoctorCheck> checks, PrintStream out, Path envFile) {
        checks.forEach(check -> out.printf("%-5s %-38s %s%s%n", check.status(), check.name(),
                check.detail(), "none".equals(check.action()) ? "" : "; action: " + check.action()));
        long failed = checks.stream().filter(check -> check.status() == CheckStatus.FAIL).count();
        long warnings = checks.stream().filter(check -> check.status() == CheckStatus.WARN).count();
        out.printf("DOCTOR %s failures=%d warnings=%d env=%s%n",
                failed == 0 ? "PASS" : "FAIL", failed, warnings, envFile);
    }

    private static Map<String, String> readEnvironmentFile(Path envFile) {
        try {
            Map<String, String> values = new LinkedHashMap<>();
            int lineNumber = 0;
            for (String rawLine : Files.readAllLines(envFile, StandardCharsets.UTF_8)) {
                lineNumber++;
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int separator = line.indexOf('=');
                if (separator < 1) {
                    throw new ToolingException(ToolingException.PREREQUISITE,
                            "invalid env syntax at line " + lineNumber);
                }
                String name = line.substring(0, separator).trim();
                String value = line.substring(separator + 1).trim();
                if (!name.matches("[A-Z][A-Z0-9_]*")) {
                    throw new ToolingException(ToolingException.PREREQUISITE,
                            "invalid env name at line " + lineNumber);
                }
                if (value.length() >= 2 && ((value.startsWith("\"") && value.endsWith("\""))
                        || (value.startsWith("'") && value.endsWith("'")))) {
                    value = value.substring(1, value.length() - 1);
                }
                if (values.putIfAbsent(name, value) != null) {
                    throw new ToolingException(ToolingException.PREREQUISITE,
                            "duplicate env name at line " + lineNumber);
                }
            }
            return Map.copyOf(values);
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "cannot read env file", exception);
        }
    }

    private static List<PortConfig> configuredPorts(Map<String, String> configuration) {
        return List.of(
                port(configuration, "mysql", "WEB_STARTER_DB_PORT", 33060),
                port(configuration, "redis", "WEB_STARTER_REDIS_PORT", 63790),
                port(configuration, "app", "WEB_STARTER_SERVER_PORT", 8080),
                port(configuration, "nginx", "WEB_STARTER_HTTP_PORT", 8088));
    }

    private static PortConfig port(Map<String, String> configuration, String name,
            String environmentName, int fallback) {
        String value = configuration.get(environmentName);
        if (blank(value)) {
            return new PortConfig(name, environmentName, fallback);
        }
        try {
            return new PortConfig(name, environmentName, Integer.parseInt(value));
        }
        catch (NumberFormatException exception) {
            return new PortConfig(name, environmentName, -1);
        }
    }

    private Path requireSafeRuntimeEnv(Path root, Path configuredEnvFile) {
        Path envFile = requireExistingEnvFile(root, configuredEnvFile);
        DoctorCheck permissions = envFilePermissionCheck(envFile);
        if (permissions.status() == CheckStatus.FAIL) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    permissions.detail() + "; " + permissions.action());
        }
        List<DoctorCheck> failures = configurationChecks(readEnvironmentFile(envFile)).stream()
                .filter(check -> check.status() == CheckStatus.FAIL)
                .toList();
        if (!failures.isEmpty()) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "unsafe or incomplete local configuration: "
                            + failures.stream().map(DoctorCheck::name).sorted().toList());
        }
        return envFile;
    }

    private static Path requireExistingEnvFile(Path root, Path configuredEnvFile) {
        Path envFile = resolveEnvFile(root, configuredEnvFile);
        if (!Files.isRegularFile(envFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(envFile)) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "env file must be an existing non-symlink regular file: " + envFile);
        }
        return envFile;
    }

    private static Path resolveEnvFile(Path root, Path configuredEnvFile) {
        Path envFile = configuredEnvFile == null ? root.resolve(".env") : configuredEnvFile;
        if (!envFile.isAbsolute()) {
            envFile = root.resolve(envFile);
        }
        return envFile.toAbsolutePath().normalize();
    }

    private static Path requireWorkspace(Path workspace) {
        Path candidate = workspace == null ? Path.of(".") : workspace;
        try {
            Path root = candidate.toAbsolutePath().normalize().toRealPath(LinkOption.NOFOLLOW_LINKS);
            if (!Files.isRegularFile(root.resolve("pom.xml"), LinkOption.NOFOLLOW_LINKS)
                    || !Files.isDirectory(root.resolve("web-starter-tooling"), LinkOption.NOFOLLOW_LINKS)) {
                throw new ToolingException(ToolingException.PREREQUISITE,
                        "workspace is not a Web Starter source tree: " + root);
            }
            return root;
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "workspace does not exist or cannot be resolved: " + candidate, exception);
        }
    }

    private static String requireProjectName(String projectName) {
        String value = blank(projectName) ? "web-starter" : projectName.trim();
        if (!PROJECT_NAME.matcher(value).matches()) {
            throw Checks.usage("--project-name must match " + PROJECT_NAME.pattern());
        }
        return value;
    }

    private void confirmVolumeDeletion(String projectName, String nonInteractiveConfirmation) {
        if (nonInteractiveConfirmation != null) {
            if (!projectName.equals(nonInteractiveConfirmation)) {
                throw Checks.usage("--confirm-delete-volumes must exactly equal --project-name ("
                        + projectName + ")");
            }
            return;
        }
        String expected = "DELETE VOLUMES " + projectName;
        String response = confirmationReader.read(
                "This permanently deletes MySQL and Redis volumes for " + projectName
                        + ". Type '" + expected + "': ");
        if (!expected.equals(response)) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "volume deletion was not confirmed; in non-interactive use add "
                            + "--confirm-delete-volumes " + projectName);
        }
    }

    private static List<String> composeCommand(Path root, Path envFile, String projectName) {
        return new ArrayList<>(List.of("docker", "compose", "--project-name", projectName,
                "--env-file", envFile.toString(), "-f", root.resolve("compose.yaml").toString(),
                "-f", root.resolve("compose.dev.yaml").toString()));
    }

    private static List<String> productionComposeCommand(Path root, Path envFile,
            String projectName) {
        return new ArrayList<>(List.of("docker", "compose", "--project-name", projectName,
                "--env-file", envFile.toString(), "-f",
                root.resolve("compose.production.yaml").toString()));
    }

    private static List<String> composeWith(List<String> base, String... arguments) {
        List<String> command = new ArrayList<>(base);
        command.addAll(Arrays.asList(arguments));
        return List.copyOf(command);
    }

    private static StepSpec step(String name, List<String> command, Path workingDirectory) {
        return new StepSpec(name, List.copyOf(command), workingDirectory, Map.of(), null,
                null, LayerStatus.FAIL);
    }

    private static StepSpec step(String name, List<String> command, Path workingDirectory,
            Map<String, String> environment) {
        return new StepSpec(name, List.copyOf(command), workingDirectory, Map.copyOf(environment),
                null, null, LayerStatus.FAIL);
    }

    private Map<String, String> policyTestEnvironment() {
        List<String> removals = environment.keySet().stream()
                .filter(DeveloperCommands::isReleaseOrchestrationEnvironment)
                .sorted()
                .toList();
        if (removals.isEmpty()) {
            return Map.of();
        }
        return Map.of(ProcessExecutor.ENVIRONMENT_REMOVALS, String.join(",", removals));
    }

    private static boolean isReleaseOrchestrationEnvironment(String name) {
        return name.startsWith("WEB_STARTER_")
                || name.startsWith("GITHUB_")
                || name.startsWith("RUNNER_")
                || Set.of("CI", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
                        "SSLKEYLOGFILE").contains(name);
    }

    private static boolean policyTestsPresent(Path root) {
        return Files.isRegularFile(root.resolve("scripts").resolve(REPOSITORY_POLICY_SCRIPT),
                LinkOption.NOFOLLOW_LINKS)
                && POLICY_TEST_FILES.stream()
                .allMatch(name -> Files.isRegularFile(root.resolve("scripts").resolve(name),
                        LinkOption.NOFOLLOW_LINKS));
    }

    private static List<String> pythonTestCommand(String testFile) {
        return List.of(pythonExecutable(), "-m", "unittest", "discover", "-s", "scripts",
                "-p", testFile);
    }

    private static String policyStepName(String testFile) {
        return testFile.substring("test_".length(), testFile.length() - ".py".length())
                .replace('_', '-') + "-tests";
    }

    private static String pythonExecutable() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")
                ? "python" : "python3";
    }

    private static boolean fileContains(Path file, String needle) {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        try {
            return Files.readString(file, StandardCharsets.UTF_8).contains(needle);
        }
        catch (IOException exception) {
            return false;
        }
    }

    private static boolean placeholder(String value) {
        String normalized = value.toLowerCase(Locale.ROOT);
        return PLACEHOLDER_FRAGMENTS.stream().anyMatch(normalized::contains);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static int integer(String value) {
        return value == null ? 0 : Integer.parseInt(value);
    }

    private static String firstNonBlankLine(String output) {
        return output.lines().map(String::trim).filter(line -> !line.isBlank()).findFirst()
                .orElse("command completed");
    }

    private static Path wrapper(Path root) {
        return root.resolve(isWindows() ? "mvnw.cmd" : "mvnw");
    }

    private static Path launcher(Path root) {
        return root.resolve(isWindows() ? "bin/web-starter.cmd" : "bin/web-starter");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
    }

    private static boolean isPosix() {
        try {
            FileStore store = Files.getFileStore(Path.of(".").toAbsolutePath());
            return store.supportsFileAttributeView("posix");
        }
        catch (IOException exception) {
            return false;
        }
    }

    private static String escapeMarkdown(String value) {
        return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ");
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    public enum LayerStatus {
        PASS,
        FAIL,
        NOT_COVERED,
        ENV_REQUIRED
    }

    private enum CheckStatus {
        PASS,
        WARN,
        FAIL
    }

    @FunctionalInterface
    interface ConfirmationReader {
        String read(String prompt);
    }

    @FunctionalInterface
    interface InstantSource {
        Instant now();
    }

    @FunctionalInterface
    private interface LocalStep {
        StepAssessment execute(OutputStream output) throws IOException;
    }

    private record DoctorCheck(CheckStatus status, String name, String detail, String action) {
    }

    private record SemanticVersion(int major, int minor, int patch) {
        @Override
        public String toString() {
            return major + "." + minor + "." + patch;
        }
    }

    private record PortConfig(String name, String environmentName, int port) {
    }

    private record Captured(int exitCode, String output) {
    }

    private record LoggedExecution(String output) {
    }

    private record StepAssessment(LayerStatus status, String reason) {
    }

    private record StepSpec(String name, List<String> command, Path workingDirectory,
            Map<String, String> environment, Function<LoggedExecution, StepAssessment> classifier,
            LocalStep localStep, LayerStatus failureStatus) {
    }

    private record StepOutcome(String name, LayerStatus status, int exitCode, String reason, Path log) {
    }

    private record LayerOutcome(String name, LayerStatus status, String reason, Instant startedAt,
            Instant finishedAt, List<StepOutcome> steps) {
    }
}
