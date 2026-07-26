package dev.webstarter.tooling.module;

import dev.webstarter.tooling.ChangePlan;
import dev.webstarter.tooling.Checks;
import dev.webstarter.tooling.GitTargetGuard;
import dev.webstarter.tooling.ToolingException;
import dev.webstarter.tooling.WorkspaceTransaction;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ModuleGenerator {

    private static final Pattern MIGRATION_FILE = Pattern.compile("V([1-9][0-9]{0,17})__.*\\.sql");
    private static final Pattern VERSIONED_MIGRATION_FILE = Pattern.compile("V.+__.*\\.sql");

    public ChangePlan plan(Path workspaceRoot, ModuleSpec spec) {
        WorkspaceIdentity workspace = WorkspaceIdentity.load(workspaceRoot);
        Path admin = workspace.adminDirectory();
        Path web = workspace.webDirectory();
        String moduleDirectory = workspace.artifactId() + "-" + spec.name();
        String packageName = workspace.groupId() + "." + spec.name();
        Path javaRoot = Path.of(moduleDirectory, "src/main/java").resolve(workspace.packagePath()).resolve(spec.name());
        Path migrationDirectory = admin.resolve("src/main/resources/db/migration");
        if (!Files.isDirectory(migrationDirectory, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(migrationDirectory)) {
            throw Checks.conflict("admin Flyway migration directory is missing");
        }

        checkSemanticConflicts(workspace, spec, migrationDirectory);

        ChangePlan plan = new ChangePlan(workspace.root());
        plan.add(Path.of(moduleDirectory, "pom.xml"), ModuleTemplates.pom(workspace, spec));
        plan.add(javaRoot.resolve("domain").resolve(spec.className() + ".java"),
                ModuleTemplates.domain(packageName, spec));
        plan.add(javaRoot.resolve("dto").resolve(spec.className() + "CreateRequest.java"),
                ModuleTemplates.createRequest(packageName, spec));
        plan.add(javaRoot.resolve("dto").resolve(spec.className() + "UpdateRequest.java"),
                ModuleTemplates.updateRequest(packageName, spec));
        plan.add(javaRoot.resolve("dto").resolve(spec.className() + "Response.java"),
                ModuleTemplates.response(packageName, spec));
        plan.add(javaRoot.resolve("persistence/mapper").resolve(spec.className() + "Mapper.java"),
                ModuleTemplates.mapper(packageName, spec));
        plan.add(javaRoot.resolve("config").resolve(spec.className() + "PersistenceConfiguration.java"),
                ModuleTemplates.persistenceConfiguration(packageName, spec));
        plan.add(javaRoot.resolve("service").resolve(spec.className() + "Permissions.java"),
                ModuleTemplates.permissions(packageName, spec));
        plan.add(javaRoot.resolve("service").resolve(spec.className() + "Service.java"),
                ModuleTemplates.service(packageName, spec));
        plan.add(javaRoot.resolve("service/impl").resolve(spec.className() + "ServiceImpl.java"),
                ModuleTemplates.serviceImplementation(packageName, spec));
        plan.add(javaRoot.resolve("web").resolve(spec.className() + "Controller.java"),
                ModuleTemplates.controller(packageName, spec));
        plan.add(javaRoot.resolve("audit").resolve(spec.className() + "OperationAuditRouteContributor.java"),
                ModuleTemplates.operationAuditRouteContributor(packageName, spec));

        Path testJavaRoot = Path.of(moduleDirectory, "src/test/java")
                .resolve(workspace.packagePath()).resolve(spec.name());
        plan.add(testJavaRoot.resolve("service/impl").resolve(spec.className() + "ServiceImplTest.java"),
                ModuleTemplates.serviceImplementationTest(packageName, spec));
        plan.add(testJavaRoot.resolve("web").resolve(spec.className() + "ControllerTest.java"),
                ModuleTemplates.controllerTest(packageName, spec));
        plan.add(testJavaRoot.resolve("audit").resolve(
                        spec.className() + "OperationAuditRouteContributorTest.java"),
                ModuleTemplates.operationAuditRouteContributorTest(packageName, spec));

        Path migration = workspace.root().relativize(migrationDirectory)
                .resolve("V" + spec.migrationVersion() + "__create_" + spec.name() + "_module.sql");
        plan.add(migration, ModuleTemplates.migration(spec));

        Path featureRoot = workspace.root().relativize(web).resolve("src/features").resolve(spec.name());
        plan.add(featureRoot.resolve("types.ts"), ModuleTemplates.frontendTypes(spec));
        plan.add(featureRoot.resolve("api.ts"), ModuleTemplates.frontendApi(spec));
        plan.add(featureRoot.resolve("api.spec.ts"), ModuleTemplates.frontendContractTest(spec));
        plan.add(featureRoot.resolve(spec.className() + "View.vue"), ModuleTemplates.frontendView(spec));
        Path browserRuntimeTest = workspace.root().relativize(web)
                .resolve("e2e/generated").resolve(spec.name() + "-runtime.spec.ts");
        plan.add(browserRuntimeTest, ModuleTemplates.browserRuntimeTest(spec));
        plan.add(Path.of(moduleDirectory,
                        "src/test/resources/META-INF/web-starter/module-acceptance-plan.properties"),
                ModuleTemplates.moduleAcceptancePlan(
                        workspace, spec, migration, browserRuntimeTest));

        if (spec.withMcp()) {
            plan.add(Path.of(moduleDirectory, "src/main/resources/META-INF/web-starter/mcp-tool-plan.properties"),
                    ModuleTemplates.mcpPlan(packageName, spec));
            plan.add(javaRoot.resolve("mcp").resolve(spec.className() + "McpToolContributor.java"),
                    ModuleTemplates.mcpContributor(packageName, spec));
            Path mcpTestJavaRoot = testJavaRoot.resolve("mcp");
            plan.add(mcpTestJavaRoot.resolve(spec.className() + "McpToolContributorTest.java"),
                    ModuleTemplates.mcpContributorTest(packageName, spec));
            plan.add(mcpTestJavaRoot.resolve(spec.className() + "McpRuntimeIT.java"),
                    ModuleTemplates.mcpRuntimeTest(packageName, spec));
        }

        patchRootPom(plan, workspace, spec);
        patchAdminPom(plan, workspace, spec);
        patchFrontend(plan, workspace, spec);
        GitTargetGuard.verify(plan);
        plan.preflight();
        return plan;
    }

    public void generate(ChangePlan plan) {
        GitTargetGuard.verify(plan);
        new WorkspaceTransaction().apply(plan);
    }

    private static void patchRootPom(ChangePlan plan, WorkspaceIdentity workspace, ModuleSpec spec) {
        Path path = Path.of("pom.xml");
        String original = readUtf8(workspace.root().resolve(path));
        String anchor = "        <module>" + workspace.artifactId() + "-mcp</module>\n";
        String addition = "        <module>" + workspace.artifactId() + "-" + spec.name() + "</module>\n";
        plan.modify(path, insertOnce(original, anchor, addition + anchor, "root Maven module anchor"));
    }

    private static void patchAdminPom(ChangePlan plan, WorkspaceIdentity workspace, ModuleSpec spec) {
        Path path = Path.of(workspace.artifactId() + "-admin", "pom.xml");
        String original = readUtf8(workspace.root().resolve(path));
        String artifact = "            <artifactId>" + workspace.artifactId() + "-mcp</artifactId>";
        int artifactIndex = uniqueIndex(original, artifact, "Admin MCP dependency anchor");
        int dependencyStart = original.lastIndexOf("        <dependency>", artifactIndex);
        if (dependencyStart < 0) {
            throw Checks.conflict("Admin MCP dependency block is malformed");
        }
        String addition = """
                        <dependency>
                            <groupId>%s</groupId>
                            <artifactId>%s-%s</artifactId>
                            <version>${project.version}</version>
                        </dependency>
                """.formatted(workspace.groupId(), workspace.artifactId(), spec.name());
        String updated = original.substring(0, dependencyStart) + addition + original.substring(dependencyStart);
        plan.modify(path, updated);
    }

    private static void patchFrontend(ChangePlan plan, WorkspaceIdentity workspace, ModuleSpec spec) {
        Path webRoot = Path.of(workspace.artifactId() + "-web", "src");

        Path menuPath = webRoot.resolve("constants/menu.ts");
        String menu = readUtf8(workspace.root().resolve(menuPath));
        String menuAnchor = "  USERS: '2011',\n";
        plan.modify(menuPath, insertOnce(menu, menuAnchor,
                ModuleTemplates.menuConstant(spec) + menuAnchor, "front-end menu constant anchor"));

        Path navigationPath = webRoot.resolve("navigation/manifest.ts");
        String navigation = readUtf8(workspace.root().resolve(navigationPath));
        String navigationAnchor = "  // @web-starter-module-navigation\n";
        plan.modify(navigationPath, insertOnce(navigation, navigationAnchor,
                ModuleTemplates.navigationItem(spec) + navigationAnchor,
                "front-end typed navigation manifest anchor"));
    }

    private static void checkSemanticConflicts(
            WorkspaceIdentity workspace,
            ModuleSpec spec,
            Path migrationDirectory) {
        Path moduleDirectory = workspace.root().resolve(workspace.artifactId() + "-" + spec.name());
        if (Files.exists(moduleDirectory, LinkOption.NOFOLLOW_LINKS)) {
            throw Checks.conflict("module directory already exists");
        }
        BigInteger requested = new BigInteger(spec.migrationVersion());
        BigInteger highest = BigInteger.ZERO;
        List<Path> registrationFiles = new ArrayList<>();
        try (var paths = Files.list(migrationDirectory)) {
            for (Path path : paths.toList()) {
                if (path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".sql")) {
                    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
                        throw Checks.conflict("Flyway migration entries must be non-symlink regular files");
                    }
                    registrationFiles.add(path);
                }
                Matcher matcher = MIGRATION_FILE.matcher(path.getFileName().toString());
                if (matcher.matches()) {
                    BigInteger current = new BigInteger(matcher.group(1));
                    if (current.compareTo(highest) > 0) {
                        highest = current;
                    }
                    if (current.equals(requested)) {
                        throw Checks.conflict("migration version already exists: " + spec.migrationVersion());
                    }
                }
                else if (VERSIONED_MIGRATION_FILE.matcher(path.getFileName().toString()).matches()) {
                    throw Checks.conflict(
                            "non-canonical Flyway migration filename prevents safe numeric ordering: "
                                    + path.getFileName());
                }
            }
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE, "unable to inspect Flyway migrations", exception);
        }
        if (requested.compareTo(highest) <= 0) {
            throw Checks.conflict("migration version must be greater than the current highest version " + highest);
        }

        registrationFiles.add(workspace.webDirectory().resolve("src/constants/menu.ts"));
        registrationFiles.add(workspace.webDirectory().resolve("src/navigation/manifest.ts"));
        List<SemanticConflict> conflicts = semanticConflicts(spec);
        for (Path file : registrationFiles) {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)) {
                throw Checks.conflict("required registration file is missing or unsafe: "
                        + workspace.root().relativize(file));
            }
            if (fileSize(file) > 2_000_000) {
                throw Checks.conflict("registration file exceeds the 2 MB safety limit: "
                        + workspace.root().relativize(file));
            }
            String content = readUtf8(file);
            for (SemanticConflict conflict : conflicts) {
                if (conflict.pattern().matcher(content).find()) {
                    throw Checks.conflict(
                            "module identifier conflicts with an existing registration: " + conflict.identifier());
                }
            }
        }

        SemanticConflict apiConflict = new SemanticConflict(
                Pattern.compile("['\"]" + Pattern.quote("/api/" + spec.plural()) + "/?['\"]"),
                "api path /api/" + spec.plural());
        for (Path file : javaRegistrationFiles(workspace)) {
            if (fileSize(file) > 2_000_000) {
                throw Checks.conflict("Java registration file exceeds the 2 MB safety limit: "
                        + workspace.root().relativize(file));
            }
            if (apiConflict.pattern().matcher(readUtf8(file)).find()) {
                throw Checks.conflict(
                        "module identifier conflicts with an existing registration: "
                                + apiConflict.identifier());
            }
        }
    }

    private static List<Path> javaRegistrationFiles(WorkspaceIdentity workspace) {
        List<Path> files = new ArrayList<>();
        String modulePrefix = workspace.artifactId() + "-";
        try (var children = Files.list(workspace.root())) {
            for (Path module : children.toList()) {
                if (!module.getFileName().toString().startsWith(modulePrefix)) {
                    continue;
                }
                if (Files.isSymbolicLink(module)) {
                    throw Checks.conflict("workspace module directories must not be symbolic links");
                }
                if (!Files.isDirectory(module, LinkOption.NOFOLLOW_LINKS)) {
                    continue;
                }
                Path javaRoot = module.resolve("src/main/java");
                if (!Files.exists(javaRoot, LinkOption.NOFOLLOW_LINKS)) {
                    continue;
                }
                if (Files.isSymbolicLink(javaRoot)
                        || !Files.isDirectory(javaRoot, LinkOption.NOFOLLOW_LINKS)) {
                    throw Checks.conflict("Java source roots must be non-symlink directories");
                }
                try (var paths = Files.walk(javaRoot)) {
                    for (Path path : paths.toList()) {
                        if (Files.isSymbolicLink(path)) {
                            throw Checks.conflict("Java source trees must not contain symbolic links");
                        }
                        if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                                && path.getFileName().toString().endsWith(".java")) {
                            files.add(path);
                        }
                    }
                }
            }
        }
        catch (IOException exception) {
            throw new ToolingException(
                    ToolingException.IO_FAILURE, "unable to inspect Java API registrations", exception);
        }
        return List.copyOf(files);
    }

    private static List<SemanticConflict> semanticConflicts(ModuleSpec spec) {
        List<SemanticConflict> conflicts = new ArrayList<>();
        conflicts.add(new SemanticConflict(Pattern.compile(
                "(?i)\\bCREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?"
                        + "(?:`?[a-z0-9_]+`?\\.)?`?" + Pattern.quote(spec.table())
                        + "`?(?=\\s|\\()"), "table " + spec.table()));
        for (String action : List.of("list", "create", "update", "remove")) {
            String permission = spec.name() + ":" + action;
            conflicts.add(new SemanticConflict(
                    Pattern.compile("(?i)['\"]" + Pattern.quote(permission) + "['\"]"),
                    "permission " + permission));
        }
        conflicts.add(idConflict(spec.menuId(), "menu id"));
        conflicts.add(idConflict(spec.permissionIdBase(), "permission id"));
        conflicts.add(idConflict(spec.permissionIdBase() + 1, "permission id"));
        conflicts.add(idConflict(spec.permissionIdBase() + 2, "permission id"));
        conflicts.add(idConflict(spec.permissionIdBase() + 3, "permission id"));
        conflicts.add(new SemanticConflict(
                Pattern.compile("['\"]" + Pattern.quote(spec.route()) + "['\"]"),
                "route " + spec.route()));
        return List.copyOf(conflicts);
    }

    private static SemanticConflict idConflict(long id, String type) {
        return new SemanticConflict(Pattern.compile("\\(\\s*" + id + "\\s*,"), type + " " + id);
    }

    private static long fileSize(Path file) {
        try {
            return Files.size(file);
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE, "unable to inspect registration file", exception);
        }
    }

    private record SemanticConflict(Pattern pattern, String identifier) {
    }

    private static String insertOnce(String original, String anchor, String replacement, String description) {
        int index = uniqueIndex(original, anchor, description);
        return original.substring(0, index) + replacement + original.substring(index + anchor.length());
    }

    private static int uniqueIndex(String original, String anchor, String description) {
        int first = original.indexOf(anchor);
        if (first < 0 || original.indexOf(anchor, first + anchor.length()) >= 0) {
            throw Checks.conflict(description + " must exist exactly once");
        }
        return first;
    }

    private static String readUtf8(Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE, "unable to read " + path.getFileName(), exception);
        }
    }
}
