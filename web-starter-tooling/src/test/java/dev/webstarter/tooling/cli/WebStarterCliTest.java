package dev.webstarter.tooling.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebStarterCliTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void helpIsAvailableWithoutBuildingAWorkspace() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        int exit = WebStarterCli.run(new String[]{"help"}, new PrintStream(output), System.err);

        assertEquals(0, exit);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("module validate|dry-run|generate"));
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("--declaration <module.json>"));
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("doctor [--workspace"));
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("verify [--workspace"));
    }

    @Test
    void unknownOptionsReturnStableUsageExit() {
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exit = WebStarterCli.run(
                new String[]{"module", "validate", "--unknown", "value"},
                System.out,
                new PrintStream(error));

        assertEquals(2, exit);
        assertTrue(error.toString(StandardCharsets.UTF_8).contains("unknown option"));
    }

    @Test
    void declarationCannotBeMixedWithInlineModuleFields() throws Exception {
        Path declaration = temporaryDirectory.resolve("module.json");
        Files.writeString(declaration, """
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """);
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exit = WebStarterCli.run(
                new String[]{
                        "module", "validate", "--declaration", declaration.toString(),
                        "--name", "other"
                },
                System.out,
                new PrintStream(error));

        assertEquals(2, exit);
        assertTrue(error.toString(StandardCharsets.UTF_8).contains("cannot be combined"));
    }

    @Test
    void declarationAcceptsExplicitCliMcpFlagWithoutWritingDuringValidation() throws Exception {
        Path workspace = createWorkspace();
        Path declaration = temporaryDirectory.resolve("module-with-mcp.json");
        Files.writeString(declaration, """
                {"schemaVersion":1,"name":"widget","label":"部件",
                 "migrationVersion":"4","permissionIdBase":7100,"menuId":8100}
                """);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exit = WebStarterCli.run(
                new String[]{
                        "module", "validate", "--workspace", workspace.toString(),
                        "--declaration", declaration.toString(), "--with-mcp"
                },
                new PrintStream(output),
                new PrintStream(error));

        assertEquals(0, exit, error.toString(StandardCharsets.UTF_8));
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("mcp=true"));
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("VALID no files written"));
        assertTrue(Files.notExists(workspace.resolve("web-starter-widget")));
    }

    private Path createWorkspace() throws Exception {
        Path root = temporaryDirectory.resolve("workspace");
        Files.createDirectories(root.resolve("web-starter-admin/src/main/resources/db/migration"));
        Files.createDirectories(root.resolve("web-starter-web/src/constants"));
        Files.createDirectories(root.resolve("web-starter-web/src/navigation"));
        Files.writeString(root.resolve("pom.xml"), """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>dev.webstarter</groupId>
                  <artifactId>web-starter</artifactId>
                  <version>2.0.0-SNAPSHOT</version>
                  <modules>
                        <module>web-starter-core</module>
                        <module>web-starter-mcp</module>
                        <module>web-starter-admin</module>
                  </modules>
                </project>
                """);
        Files.writeString(root.resolve("web-starter-admin/pom.xml"), """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>dev.webstarter</groupId>
                            <artifactId>web-starter-mcp</artifactId>
                            <version>${project.version}</version>
                        </dependency>
                    </dependencies>
                </project>
                """);
        Files.writeString(root.resolve("web-starter-admin/src/main/resources/db/migration/V1__base.sql"),
                "CREATE TABLE sys_example (id BIGINT);\n");
        Files.writeString(root.resolve("web-starter-web/src/constants/menu.ts"), """
                export const MENU_IDS = {
                  USERS: '2011',
                } as const
                """);
        Files.writeString(root.resolve("web-starter-web/src/navigation/manifest.ts"), """
                export const APP_NAVIGATION = [
                  // @web-starter-module-navigation
                ]
                """);
        return root;
    }
}
