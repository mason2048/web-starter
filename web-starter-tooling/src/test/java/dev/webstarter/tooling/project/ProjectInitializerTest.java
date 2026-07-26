package dev.webstarter.tooling.project;

import dev.webstarter.tooling.Digests;
import dev.webstarter.tooling.ToolingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ProjectInitializerTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void copiesOnlyTrackedSafeFilesAndAppliesControlledIdentityReplacement() throws Exception {
        Path source = createTemplateRepository();
        Path output = temporaryDirectory.resolve("sample-app");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);
        ProjectInitializer initializer = new ProjectInitializer();

        ProjectInitializer.ProjectPlan plan = initializer.plan(source, spec);

        assertFalse(Files.exists(output), "planning must not create the output directory");
        assertTrue(plan.files().stream().anyMatch(file -> file.relativePath().toString().contains("sample-app-core")));
        initializer.apply(plan);

        Path application = output.resolve(
                "sample-app-core/src/main/java/com/example/sample/SampleAppApplication.java");
        assertTrue(Files.isRegularFile(application));
        String applicationText = Files.readString(application);
        assertTrue(applicationText.contains("package com.example.sample"));
        assertTrue(applicationText.contains("class SampleAppApplication"));
        assertEquals("SAMPLE_APP_DB_URL=jdbc:mysql://db/sample_app\n", Files.readString(output.resolve(".env.example")));
        assertFalse(Files.exists(output.resolve(".env")));
        assertFalse(Files.exists(output.resolve("server.pem")));
        assertFalse(Files.exists(output.resolve("docs/acceptance/v1-acceptance-2026-07-19.md")));
        assertFalse(Files.exists(output.resolve("release/evidence/v2.0.0.json")));
        assertFalse(Files.exists(output.resolve("target/root-build.txt")));
        assertFalse(Files.exists(output.resolve("dist/root-bundle.js")));
        assertFalse(Files.exists(output.resolve("node_modules/pkg/index.js")));
        assertFalse(Files.exists(output.resolve("vault.kdbx")));
        assertFalse(Files.exists(output.resolve("untracked.txt")));
        assertFalse(Files.exists(output.resolve(".git")));

        byte[] generatedSource = Files.readAllBytes(
                output.resolve("sample-app-web/contracts/private-api.openapi.json"));
        String generatedTypes = Files.readString(
                output.resolve("sample-app-web/src/api/generated/privateApiContract.ts"));
        assertTrue(generatedTypes.contains(
                "/* source-sha256: " + Digests.sha256(generatedSource) + " */"));
        assertTrue(new String(generatedSource, StandardCharsets.UTF_8)
                .contains("x-sample-app-type-imports"));
    }

    @Test
    void refusesNonEmptyOutputWithoutChangingIt() throws Exception {
        Path source = createTemplateRepository();
        Path output = temporaryDirectory.resolve("occupied");
        Files.createDirectory(output);
        Files.writeString(output.resolve("owned.txt"), "keep");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);

        ToolingException failure = assertThrows(ToolingException.class,
                () -> new ProjectInitializer().plan(source, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertEquals("keep", Files.readString(output.resolve("owned.txt")));
    }

    @Test
    void replacementValuesAreNotReprocessedAsTemplateTokens() throws Exception {
        Path source = createTemplateRepository();
        Path output = temporaryDirectory.resolve("web-starter-extension");
        ProjectSpec spec = new ProjectSpec(
                "web-starter-extension",
                "航线 Web Starter",
                "com.example.webstarter",
                "com.example.webstarter",
                "web_starter_extension",
                "MY_WEB_STARTER_",
                output);

        ProjectInitializer.ProjectPlan plan = new ProjectInitializer().plan(source, spec);
        new ProjectInitializer().apply(plan);

        Path application = output.resolve(
                "web-starter-extension-core/src/main/java/com/example/webstarter/"
                        + "WebStarterExtensionApplication.java");
        assertTrue(Files.isRegularFile(application));
        assertTrue(Files.readString(application).contains("package com.example.webstarter"));
        assertTrue(Files.readString(output.resolve("pom.xml"))
                .contains("<name>航线 Web Starter</name>"));
        assertFalse(Files.readString(output.resolve("pom.xml"))
                .contains("航线 航线 Web Starter"));
        assertEquals(
                "MY_WEB_STARTER_DB_URL=jdbc:mysql://db/web_starter_extension\n",
                Files.readString(output.resolve(".env.example")));
    }

    @Test
    void rejectsOutputThatResolvesInsideTemplateThroughAnAncestorSymlink() throws Exception {
        Path source = createTemplateRepository();
        Path physicalParent = Files.createDirectory(source.resolve("generated"));
        Path alias = temporaryDirectory.resolve("template-alias");
        Files.createSymbolicLink(alias, source);
        Path output = alias.resolve("generated/derived-app");
        ProjectSpec spec = new ProjectSpec(
                "derived-app", "派生管理系统", "com.example.derived", "com.example.derived",
                "derived_app", "DERIVED_APP_", output);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ProjectInitializer().plan(source, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertFalse(Files.exists(physicalParent.resolve("derived-app")));
    }

    @Test
    void rejectsProductNamesThatCouldChangeGeneratedSyntaxOrPaths() {
        Path output = temporaryDirectory.resolve("unsafe-product");

        ToolingException markup = assertThrows(ToolingException.class, () -> new ProjectSpec(
                "sample-app", "R&D 管理", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output));
        ToolingException path = assertThrows(ToolingException.class, () -> new ProjectSpec(
                "sample-app", "管理/平台", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output));
        ToolingException dotSegment = assertThrows(ToolingException.class, () -> new ProjectSpec(
                "sample-app", "..", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output));

        assertEquals(ToolingException.USAGE, markup.exitCode());
        assertEquals(ToolingException.USAGE, path.exitCode());
        assertEquals(ToolingException.USAGE, dotSegment.exitCode());
        assertFalse(Files.exists(output));
    }

    @Test
    void rejectsNonLowercaseOrRestrictedJavaPackageSegments() {
        Path output = temporaryDirectory.resolve("unsafe-package");

        ToolingException uppercase = assertThrows(ToolingException.class, () -> new ProjectSpec(
                "sample-app", "示例管理系统", "com.Example.sample", "com.Example.sample",
                "sample_app", "SAMPLE_APP_", output));
        ToolingException restricted = assertThrows(ToolingException.class, () -> new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.record", "com.example.record",
                "sample_app", "SAMPLE_APP_", output));

        assertEquals(ToolingException.USAGE, uppercase.exitCode());
        assertEquals(ToolingException.USAGE, restricted.exitCode());
        assertFalse(Files.exists(output));
    }

    @Test
    void refusesTrackedSymbolicLinksBeforePublishingOutput() throws Exception {
        Path source = createTemplateRepository();
        Files.createSymbolicLink(source.resolve("tracked-link"), Path.of("pom.xml"));
        git(source, "add", "tracked-link");
        git(source, "commit", "-q", "-m", "tracked link fixture");
        Path output = temporaryDirectory.resolve("symlink-output");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ProjectInitializer().plan(source, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertFalse(Files.exists(output));
    }

    @Test
    void doesNotExecuteRepositoryConfiguredFsmonitorDuringPlanning() throws Exception {
        Path source = createTemplateRepository();
        Path marker = temporaryDirectory.resolve("fsmonitor-was-executed");
        Path hook = source.resolve(".git/hooks/fsmonitor-probe");
        Files.writeString(hook, "#!/bin/sh\n: > \"" + marker + "\"\nprintf 'token\\n'\n");
        hook.toFile().setExecutable(true, true);
        git(source, "config", "core.fsmonitor", hook.toString());
        Path output = temporaryDirectory.resolve("fsmonitor-output");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);

        ProjectInitializer.ProjectPlan plan = new ProjectInitializer().plan(source, spec);

        assertFalse(plan.files().isEmpty());
        assertFalse(Files.exists(marker), "read-only planning must disable repository fsmonitor hooks");
        assertFalse(Files.exists(output));
    }

    @Test
    void planDigestBindsTrackedExecutableMode() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path source = createTemplateRepository();
        Path output = temporaryDirectory.resolve("digest-output");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);
        ProjectInitializer initializer = new ProjectInitializer();

        String regularDigest = initializer.plan(source, spec).digest();
        assertTrue(source.resolve("pom.xml").toFile().setExecutable(true, false));
        git(source, "add", "pom.xml");
        git(source, "commit", "-q", "-m", "change executable mode");
        String executableDigest = initializer.plan(source, spec).digest();

        assertFalse(regularDigest.equals(executableDigest));
        assertFalse(Files.exists(output));
    }

    @Test
    void hiddenGitIndexFlagsCannotMaskModifiedTemplateContent() throws Exception {
        Path source = createTemplateRepository();
        Path output = temporaryDirectory.resolve("hidden-index-output");
        git(source, "update-index", "--assume-unchanged", "pom.xml");
        Files.writeString(source.resolve("pom.xml"),
                "<artifactId>web-starter</artifactId><name>hidden uncommitted content</name>\n");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ProjectInitializer().plan(source, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertTrue(failure.getMessage().contains("template index"));
        assertFalse(Files.exists(output));
    }

    @Test
    void doesNotExecuteLocallyConfiguredGitContentFilters() throws Exception {
        Path source = createTemplateRepository();
        Files.writeString(source.resolve(".gitattributes"), "pom.xml filter=probe\n");
        git(source, "add", ".gitattributes");
        git(source, "commit", "-q", "-m", "content filter fixture");
        Path marker = temporaryDirectory.resolve("content-filter-was-executed");
        Path filter = source.resolve(".git/hooks/filter-probe");
        Files.writeString(filter, "#!/bin/sh\n: > \"" + marker + "\"\ncat\n");
        filter.toFile().setExecutable(true, true);
        git(source, "config", "filter.probe.clean", filter.toString());
        Files.writeString(source.resolve("pom.xml"),
                "<artifactId>web-starter</artifactId><name>changed through filter</name>\n");
        Path output = temporaryDirectory.resolve("filter-output");
        ProjectSpec spec = new ProjectSpec(
                "sample-app", "示例管理系统", "com.example.sample", "com.example.sample",
                "sample_app", "SAMPLE_APP_", output);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ProjectInitializer().plan(source, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertTrue(failure.getMessage().contains("content filters"));
        assertFalse(Files.exists(marker));
        assertFalse(Files.exists(output));
    }

    private Path createTemplateRepository() throws Exception {
        Path source = temporaryDirectory.resolve("template");
        Files.createDirectories(source.resolve("web-starter-core/src/main/java/dev/webstarter"));
        Files.createDirectories(source.resolve("web-starter-web/contracts"));
        Files.createDirectories(source.resolve("web-starter-web/src/api/generated"));
        Files.createDirectories(source.resolve("docs/acceptance"));
        Files.createDirectories(source.resolve("release/evidence"));
        Files.createDirectories(source.resolve("target"));
        Files.createDirectories(source.resolve("dist"));
        Files.createDirectories(source.resolve("node_modules/pkg"));
        Files.writeString(source.resolve("web-starter-core/src/main/java/dev/webstarter/WebStarterApplication.java"),
                "package dev.webstarter; public class WebStarterApplication {}\n");
        Files.writeString(source.resolve("pom.xml"),
                "<artifactId>web-starter</artifactId><name>启程 Web Starter</name>\n");
        Files.writeString(source.resolve(".env.example"),
                "WEB_STARTER_DB_URL=jdbc:mysql://db/web_starter\n");
        byte[] contract = "{\"x-web-starter-type-imports\":{}}\n".getBytes(StandardCharsets.UTF_8);
        Files.write(source.resolve("web-starter-web/contracts/private-api.openapi.json"), contract);
        Files.writeString(source.resolve("web-starter-web/src/api/generated/privateApiContract.ts"),
                "/* This file is generated. */\n/* source-sha256: " + Digests.sha256(contract)
                        + " */\nexport const contractName = 'web-starter'\n");
        Files.writeString(source.resolve(".env"), "WEB_STARTER_PASSWORD=local-only\n");
        Files.writeString(source.resolve("server.pem"), "not-a-real-key\n");
        Files.writeString(source.resolve("docs/acceptance/v1-acceptance-2026-07-19.md"), "local evidence\n");
        Files.writeString(source.resolve("release/evidence/v2.0.0.json"), "{\"sourceOnly\":true}\n");
        Files.writeString(source.resolve("target/root-build.txt"), "root build output\n");
        Files.writeString(source.resolve("dist/root-bundle.js"), "root bundle\n");
        Files.writeString(source.resolve("node_modules/pkg/index.js"), "dependency\n");
        Files.writeString(source.resolve("vault.kdbx"), "not-a-real-vault\n");
        Files.writeString(source.resolve("untracked.txt"), "do not copy\n");
        git(source, "init", "-q");
        git(source, "config", "user.email", "tooling-test@example.invalid");
        git(source, "config", "user.name", "Tooling Test");
        git(source, "add", "-f", ".env", ".env.example", "server.pem", "vault.kdbx", "pom.xml",
                "web-starter-core", "web-starter-web", "docs", "release",
                "target", "dist", "node_modules");
        git(source, "commit", "-q", "-m", "fixture");
        return source;
    }

    private static void git(Path root, String... arguments) throws Exception {
        List<String> command = new java.util.ArrayList<>();
        command.add("git");
        command.add("-C");
        command.add(root.toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] output = process.getInputStream().readAllBytes();
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IOException("git fixture command failed: " + new String(output));
        }
    }
}
