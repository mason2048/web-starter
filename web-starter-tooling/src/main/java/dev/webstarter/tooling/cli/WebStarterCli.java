package dev.webstarter.tooling.cli;

import dev.webstarter.tooling.ChangePlan;
import dev.webstarter.tooling.CliOptions;
import dev.webstarter.tooling.ToolingException;
import dev.webstarter.tooling.dev.DeveloperCommands;
import dev.webstarter.tooling.module.ModuleDeclarationReader;
import dev.webstarter.tooling.module.ModuleGenerator;
import dev.webstarter.tooling.module.ModuleSpec;
import dev.webstarter.tooling.project.ProjectInitializer;
import dev.webstarter.tooling.project.ProjectSpec;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Set;

public final class WebStarterCli {

    private static final Set<String> PROJECT_VALUES = Set.of(
            "source", "name", "product-name", "group-id", "package-prefix",
            "database", "env-prefix", "output");
    private static final Set<String> MODULE_VALUES = Set.of(
            "workspace", "name", "label", "plural", "table", "route",
            "migration-version", "permission-id-base", "menu-id", "declaration");
    private static final Set<String> INLINE_MODULE_VALUES = Set.of(
            "name", "label", "plural", "table", "route",
            "migration-version", "permission-id-base", "menu-id");
    private static final Set<String> DOCTOR_VALUES = Set.of("workspace", "env-file");
    private static final Set<String> UP_VALUES = Set.of(
            "workspace", "env-file", "project-name", "timeout-seconds");
    private static final Set<String> DOWN_VALUES = Set.of(
            "workspace", "env-file", "project-name", "confirm-delete-volumes");
    private static final Set<String> VERIFY_VALUES = Set.of(
            "workspace", "env-file", "project-name", "evidence-dir");

    private WebStarterCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        try {
            if (args.length == 0 || "help".equals(args[0]) || "--help".equals(args[0])) {
                usage(out);
                return 0;
            }
            return switch (args[0]) {
                case "project" -> project(args, out);
                case "module" -> module(args, out);
                case "doctor" -> doctor(args, out);
                case "up" -> up(args, out);
                case "down" -> down(args, out);
                case "verify" -> verify(args, out);
                default -> throw new ToolingException(ToolingException.USAGE, "unknown command: " + args[0]);
            };
        }
        catch (ToolingException exception) {
            err.println("ERROR [" + exception.exitCode() + "]: " + exception.getMessage());
            return exception.exitCode();
        }
        catch (RuntimeException exception) {
            err.println("ERROR [5]: unexpected tooling failure: " + exception.getClass().getSimpleName());
            return ToolingException.IO_FAILURE;
        }
    }

    private static int project(String[] args, PrintStream out) {
        if (args.length < 2 || !"init".equals(args[1])) {
            throw new ToolingException(ToolingException.USAGE, "expected: project init");
        }
        CliOptions options = CliOptions.parse(args, 2, PROJECT_VALUES, Set.of("dry-run"));
        String groupId = options.required("group-id");
        ProjectSpec spec = new ProjectSpec(
                options.required("name"),
                options.required("product-name"),
                groupId,
                options.optional("package-prefix", groupId),
                options.required("database"),
                options.required("env-prefix"),
                Path.of(options.required("output")));
        ProjectInitializer initializer = new ProjectInitializer();
        ProjectInitializer.ProjectPlan plan = initializer.plan(
                Path.of(options.optional("source", ".")), spec);
        out.printf("PROJECT %s files=%d digest=%s%n", spec.name(), plan.files().size(), plan.digest());
        if (options.flag("dry-run")) {
            for (ProjectInitializer.PlannedFile file : plan.files()) {
                out.println("ADD " + file.relativePath());
            }
            out.println("DRY_RUN no files written");
            return 0;
        }
        initializer.apply(plan);
        out.println("CREATED " + plan.output());
        return 0;
    }

    private static int module(String[] args, PrintStream out) {
        if (args.length < 2 || !("validate".equals(args[1]) || "dry-run".equals(args[1]) || "generate".equals(args[1]))) {
            throw new ToolingException(ToolingException.USAGE,
                    "expected: module validate, module dry-run, or module generate");
        }
        String action = args[1];
        CliOptions options = CliOptions.parse(args, 2, MODULE_VALUES, Set.of("with-mcp"));
        ModuleSpec spec = moduleSpec(options);
        ModuleGenerator generator = new ModuleGenerator();
        ChangePlan plan = generator.plan(Path.of(options.optional("workspace", ".")), spec);
        out.printf("MODULE %s changes=%d digest=%s mcp=%s%n",
                spec.name(), plan.changes().size(), plan.digest(), spec.withMcp());
        if ("validate".equals(action)) {
            out.println("VALID no files written");
            return 0;
        }
        if ("dry-run".equals(action)) {
            for (ChangePlan.Change change : plan.changes()) {
                out.println(change.kind() + " " + change.relativePath());
            }
            out.println("DRY_RUN no files written");
            return 0;
        }
        generator.generate(plan);
        out.println("GENERATED " + spec.name());
        if (spec.withMcp()) {
            out.println("MCP contributor, schemas, governance metadata, and official SDK runtime test generated");
        }
        return 0;
    }

    private static ModuleSpec moduleSpec(CliOptions options) {
        String declaration = options.optional("declaration", null);
        if (declaration != null) {
            boolean hasInlineValue = INLINE_MODULE_VALUES.stream()
                    .anyMatch(name -> options.optional(name, null) != null);
            if (hasInlineValue) {
                throw new ToolingException(
                        ToolingException.USAGE,
                        "--declaration cannot be combined with inline module fields");
            }
            return ModuleDeclarationReader.read(declaration)
                    .withMcpEnabled(options.flag("with-mcp"));
        }
        return ModuleSpec.from(
                options.required("name"),
                options.required("label"),
                options.optional("plural", null),
                options.optional("table", null),
                options.optional("route", null),
                options.required("migration-version"),
                options.required("permission-id-base"),
                options.required("menu-id"),
                options.flag("with-mcp"));
    }

    private static int doctor(String[] args, PrintStream out) {
        CliOptions options = CliOptions.parse(args, 1, DOCTOR_VALUES, Set.of());
        return new DeveloperCommands().doctor(
                Path.of(options.optional("workspace", ".")),
                optionalPath(options.optional("env-file", null)), out);
    }

    private static int up(String[] args, PrintStream out) {
        CliOptions options = CliOptions.parse(args, 1, UP_VALUES, Set.of("no-build"));
        return new DeveloperCommands().up(
                Path.of(options.optional("workspace", ".")),
                optionalPath(options.optional("env-file", null)),
                options.optional("project-name", "web-starter"),
                positiveInteger(options.optional("timeout-seconds", "300"), "--timeout-seconds"),
                options.flag("no-build"), out);
    }

    private static int down(String[] args, PrintStream out) {
        CliOptions options = CliOptions.parse(args, 1, DOWN_VALUES, Set.of("volumes"));
        return new DeveloperCommands().down(
                Path.of(options.optional("workspace", ".")),
                optionalPath(options.optional("env-file", null)),
                options.optional("project-name", "web-starter"),
                options.flag("volumes"),
                options.optional("confirm-delete-volumes", null), out);
    }

    private static int verify(String[] args, PrintStream out) {
        CliOptions options = CliOptions.parse(args, 1, VERIFY_VALUES, Set.of());
        return new DeveloperCommands().verify(
                Path.of(options.optional("workspace", ".")),
                optionalPath(options.optional("env-file", null)),
                optionalPath(options.optional("evidence-dir", null)),
                options.optional("project-name", "web-starter"), out);
    }

    private static Path optionalPath(String value) {
        return value == null ? null : Path.of(value);
    }

    private static int positiveInteger(String value, String name) {
        try {
            int result = Integer.parseInt(value);
            if (result <= 0) {
                throw new NumberFormatException("not positive");
            }
            return result;
        }
        catch (NumberFormatException exception) {
            throw new ToolingException(ToolingException.USAGE, name + " must be a positive integer");
        }
    }

    private static void usage(PrintStream out) {
        out.println("""
                启程 Web Starter offline tooling

                project init --name <slug> --product-name <name> --group-id <java.package>
                  --database <lower_snake> --env-prefix <UPPER_SNAKE_> --output <empty-or-absent-dir>
                  [--package-prefix <same-as-group>] [--source <clean-git-worktree>] [--dry-run]

                module validate|dry-run|generate --name <module> --label <display-name>
                  --migration-version <digits> --permission-id-base <id> --menu-id <id>
                  [--workspace <dir>] [--plural <plural>] [--table <table>] [--route </route>]
                  [--with-mcp]
                module validate|dry-run|generate --declaration <module.json> [--workspace <dir>]

                doctor [--workspace <dir>] [--env-file <private-env-file>]

                up [--workspace <dir>] [--env-file <private-env-file>]
                  [--project-name <name>] [--timeout-seconds <1-1800>] [--no-build]

                down [--workspace <dir>] [--env-file <private-env-file>]
                  [--project-name <name>] [--volumes]
                  [--confirm-delete-volumes <exact-project-name>]

                verify [--workspace <dir>] [--env-file <private-env-file>]
                  [--project-name <name>] [--evidence-dir <new-directory>]
                """);
    }
}
