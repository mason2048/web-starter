package dev.webstarter.tooling.module;

import dev.webstarter.tooling.ChangePlan;
import dev.webstarter.tooling.ToolingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModuleGeneratorTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void dryRunPlanDoesNotWriteAndGeneratePublishesACompleteFixedModel() throws Exception {
        Path workspace = createWorkspace();
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "4", "5100", "6100", false);
        ModuleGenerator generator = new ModuleGenerator();

        ChangePlan plan = generator.plan(workspace, spec);

        assertEquals(before, treeDigest(workspace));
        assertFalse(Files.exists(workspace.resolve("web-starter-asset")));
        assertTrue(plan.changes().stream().anyMatch(change ->
                change.relativePath().toString().endsWith("AssetServiceImpl.java")));
        String serviceImplementation = plan.changes().stream()
                .filter(change -> change.relativePath().toString().endsWith("AssetServiceImpl.java"))
                .map(change -> new String(change.content(), StandardCharsets.UTF_8))
                .findFirst()
                .orElseThrow();
        assertTrue(serviceImplementation.contains("import dev.webstarter.asset.service.AssetService;"));
        assertTrue(serviceImplementation.contains("caller.displayName(), \"asset\", action"));
        String service = contentEndingWith(plan, "AssetService.java");
        assertTrue(service.contains("create(@Valid AssetCreateRequest request)"));
        assertTrue(service.contains("update(Long id, @Valid AssetUpdateRequest request)"));
        String serviceTest = contentEndingWith(plan, "AssetServiceImplTest.java");
        assertTrue(serviceTest.contains("createRequiresPermissionNormalizesCodeAndWritesAudit"));
        assertTrue(serviceTest.contains("createIsDeniedBeforePersistenceWhenPermissionIsMissing"));
        assertTrue(serviceTest.contains("interfaceAndImplementationExposeMatchingValidConstraints"));
        assertTrue(serviceTest.contains("Proxy.newProxyInstance"));
        assertFalse(serviceTest.contains("org.mockito"));
        String controllerTest = contentEndingWith(plan, "AssetControllerTest.java");
        assertTrue(controllerTest.contains("createReturnsTheSharedServiceResult"));
        assertTrue(controllerTest.contains("removeDelegatesTheOptimisticLockVersion"));
        assertFalse(controllerTest.contains("org.mockito"));
        String auditContributor = contentEndingWith(plan, "AssetOperationAuditRouteContributor.java");
        assertTrue(auditContributor.contains(
                "OperationAuditRoute.serviceOwned(\"/api/assets\", \"asset\", \"asset\")"));
        assertFalse(auditContributor.contains("dev.webstarter.admin"));
        String auditContributorTest = contentEndingWith(
                plan, "AssetOperationAuditRouteContributorTest.java");
        assertTrue(auditContributorTest.contains("successAuditedByService"));
        assertTrue(auditContributorTest.contains("/api/assets-archive"));
        assertFalse(plan.changes().stream().anyMatch(change ->
                change.relativePath().toString().contains("mcp-tool-plan")));
        String acceptancePlan = contentEndingWith(
                plan, "module-acceptance-plan.properties");
        assertTrue(acceptancePlan.contains("withMcp=false"));
        assertTrue(acceptancePlan.contains(
                "browserTest=web-starter-web/e2e/generated/asset-runtime.spec.ts"));
        assertFalse(acceptancePlan.contains("mcpRuntimeTest="));
        String browserRuntime = contentEndingWith(plan, "asset-runtime.spec.ts");
        assertTrue(browserRuntime.contains(
                "generated asset module closes browser CRUD conflict authorization and audit loop"));
        assertTrue(browserRuntime.contains("expect(conflictResponse.status()).toBe(409)"));
        assertTrue(browserRuntime.contains("new URL('/api/logs/operation', runtime.privateBaseUrl)"));
        assertFalse(browserRuntime.contains("/api/logs/operations"));
        assertTrue(browserRuntime.contains("entry.result === 'FAILURE'"));
        assertFalse(browserRuntime.contains("entry.result === 'FAILED'"));
        assertTrue(browserRuntime.contains(
                "throw new Error('Audit response contains forbidden credential material')"));
        assertFalse(browserRuntime.contains("not.toContain(adminPassword)"));
        assertTrue(browserRuntime.contains("expect(forbidden).toBe(403)"));
        assertFalse(browserRuntime.contains("%s"));
        assertFalse(contentEndingWith(plan, "web-starter-asset/pom.xml")
                .contains("<artifactId>web-starter-mcp</artifactId>"));
        assertFalse(plan.changes().stream().anyMatch(change ->
                change.relativePath().toString().startsWith("web-starter-admin/src/main/java")));

        generator.generate(plan);

        Path module = workspace.resolve("web-starter-asset");
        assertTrue(Files.isRegularFile(module.resolve(
                "src/main/java/dev/webstarter/asset/domain/Asset.java")));
        assertTrue(Files.isRegularFile(module.resolve(
                "src/test/java/dev/webstarter/asset/service/impl/AssetServiceImplTest.java")));
        assertTrue(Files.isRegularFile(module.resolve(
                "src/test/java/dev/webstarter/asset/web/AssetControllerTest.java")));
        assertTrue(Files.isRegularFile(module.resolve(
                "src/main/java/dev/webstarter/asset/audit/AssetOperationAuditRouteContributor.java")));
        assertTrue(Files.isRegularFile(module.resolve(
                "src/test/java/dev/webstarter/asset/audit/AssetOperationAuditRouteContributorTest.java")));
        String entity = Files.readString(module.resolve(
                "src/main/java/dev/webstarter/asset/domain/Asset.java"));
        assertTrue(entity.contains("private String code;"));
        assertTrue(entity.contains("private String name;"));
        assertTrue(entity.contains("private String status;"));
        assertTrue(entity.contains("private String description;"));
        assertTrue(entity.contains("private Integer version;"));
        assertTrue(Files.readString(workspace.resolve("pom.xml")).contains("<module>web-starter-asset</module>"));
        assertTrue(Files.readString(workspace.resolve("web-starter-admin/pom.xml"))
                .contains("<artifactId>web-starter-asset</artifactId>"));
        assertTrue(Files.isRegularFile(workspace.resolve(
                "web-starter-admin/src/main/resources/db/migration/V4__create_asset_module.sql")));
        assertTrue(Files.isRegularFile(workspace.resolve(
                "web-starter-web/src/features/asset/AssetView.vue")));
        assertTrue(Files.isRegularFile(workspace.resolve(
                "web-starter-web/e2e/generated/asset-runtime.spec.ts")));
        assertTrue(Files.isRegularFile(module.resolve(
                "src/test/resources/META-INF/web-starter/module-acceptance-plan.properties")));
        String generatedView = Files.readString(workspace.resolve(
                "web-starter-web/src/features/asset/AssetView.vue"));
        assertTrue(generatedView.contains("useStandardCrudPage<AssetRecord>"));
        assertTrue(generatedView.contains("fetchPage: listAssets"));
        assertTrue(generatedView.contains("status: AssetStatus"));
        assertFalse(generatedView.contains("%s"));
        String navigation = Files.readString(workspace.resolve(
                "web-starter-web/src/navigation/manifest.ts"));
        assertTrue(navigation.contains("path: '/assets'"));
        assertTrue(navigation.contains("permission: 'asset:list'"));
    }

    @Test
    void withMcpIsExplicitAndAddsCompiledContributorSchemasAndOfficialSdkRuntimeTest() throws Exception {
        Path workspace = createWorkspace();
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "4", "5100", "6100", true);

        ChangePlan plan = new ModuleGenerator().plan(workspace, spec);

        assertTrue(plan.changes().stream().anyMatch(change ->
                change.relativePath().toString().endsWith("mcp-tool-plan.properties")));
        String contributor = contentEndingWith(plan, "AssetMcpToolContributor.java");
        assertTrue(contributor.contains("implements McpToolContributor"));
        assertTrue(contributor.contains("McpToolSupport.IDEMPOTENCY_KEY"));
        assertTrue(contributor.contains("AssetPermissions.CREATE"));
        assertTrue(contributor.contains("McpToolRisk.DESTRUCTIVE"));
        assertTrue(contentEndingWith(plan, "AssetMcpToolContributorTest.java")
                .contains("outputSchema()).containsKey(\"oneOf\")"));
        assertTrue(contentEndingWith(plan, "AssetMcpRuntimeIT.java")
                .contains("HttpClientStreamableHttpTransport"));
        String acceptancePlan = contentEndingWith(
                plan, "module-acceptance-plan.properties");
        assertTrue(acceptancePlan.contains("withMcp=true"));
        assertTrue(acceptancePlan.contains(
                "mcpRuntimeTest=dev.webstarter.asset.mcp.AssetMcpRuntimeIT"));
        assertTrue(acceptancePlan.contains(
                "mcpTools=asset.list,asset.get,asset.create,asset.update,asset.remove"));
        String pom = contentEndingWith(plan, "web-starter-asset/pom.xml");
        assertTrue(pom.contains("<artifactId>web-starter-mcp</artifactId>"));
        assertFalse(plan.changes().stream().anyMatch(change ->
                change.relativePath().startsWith("web-starter-mcp/src/main/java")));
    }

    @Test
    void conflictStopsBeforeAnyWrite() throws Exception {
        Path workspace = createWorkspace();
        Files.createDirectory(workspace.resolve("web-starter-asset"));
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "4", "5100", "6100", false);

        ToolingException failure = assertThrows(ToolingException.class,
                () -> new ModuleGenerator().plan(workspace, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertEquals(before, treeDigest(workspace));
    }

    @Test
    void lowerCaseAndWhitespaceSqlRegistrationsAreDetectedWithoutWriting() throws Exception {
        Path workspace = createWorkspace();
        Files.writeString(workspace.resolve(
                "web-starter-admin/src/main/resources/db/migration/V2__existing_asset.sql"),
                "create table   `biz_asset` (id bigint);\n");
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "4", "5100", "6100", false);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ModuleGenerator().plan(workspace, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertTrue(failure.getMessage().contains("table biz_asset"));
        assertEquals(before, treeDigest(workspace));
    }

    @Test
    void documentationMentionsDoNotCreateFalseSemanticConflicts() throws Exception {
        Path workspace = createWorkspace();
        Files.createDirectories(workspace.resolve("docs"));
        Files.writeString(workspace.resolve("docs/example.md"),
                "Example only: CREATE TABLE biz_asset and 'asset:list' at '/assets'.\n");
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "4", "5100", "6100", false);

        ChangePlan plan = new ModuleGenerator().plan(workspace, spec);

        assertEquals(before, treeDigest(workspace));
        assertTrue(plan.changes().stream().anyMatch(change ->
                change.relativePath().toString().endsWith("AssetController.java")));
    }

    @Test
    void apiCollectionConflictIsDetectedIndependentlyOfTheFrontendRoute() throws Exception {
        Path workspace = createWorkspace();
        Path controller = workspace.resolve(
                "web-starter-project/src/main/java/dev/webstarter/project/web/ProjectController.java");
        Files.createDirectories(controller.getParent());
        Files.writeString(controller, "@RequestMapping(\"/api/projects\") class ProjectController {}\n");
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", "projects", null, "/assets", "4", "5100", "6100", false);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ModuleGenerator().plan(workspace, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertTrue(failure.getMessage().contains("api path /api/projects"));
        assertEquals(before, treeDigest(workspace));
    }

    @Test
    void customFrontendRouteDoesNotChangeTheApiCollectionPath() throws Exception {
        Path workspace = createWorkspace();
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", "inventory", null, "/asset-console", "4", "5100", "6100", false);

        ChangePlan plan = new ModuleGenerator().plan(workspace, spec);

        String acceptancePlan = contentEndingWith(plan, "module-acceptance-plan.properties");
        assertTrue(acceptancePlan.contains("route=/asset-console"));
        assertTrue(acceptancePlan.contains("plural=inventory"));
        assertTrue(acceptancePlan.contains("apiPath=/api/inventory"));
        assertTrue(contentEndingWith(plan, "asset-runtime.spec.ts")
                .contains("const apiPath = '/api/inventory'"));
    }

    @Test
    void JavaReservedModuleNamesAndOversizedTablesAreRejectedBeforePlanning() throws Exception {
        Path workspace = createWorkspace();
        String before = treeDigest(workspace);

        for (String reserved : List.of("class", "record", "module", "yield")) {
            ToolingException failure = assertThrows(ToolingException.class, () -> ModuleSpec.from(
                    reserved, "无效模块", null, null, null, "4", "5100", "6100", false));
            assertEquals(ToolingException.USAGE, failure.exitCode());
        }
        ToolingException tableFailure = assertThrows(ToolingException.class, () -> ModuleSpec.from(
                "asset", "资产", null, "a".repeat(54), null, "4", "5100", "6100", false));
        assertEquals(ToolingException.USAGE, tableFailure.exitCode());
        assertEquals(before, treeDigest(workspace));
    }

    @Test
    void customMySqlReservedTableNameIsAlwaysQuoted() throws Exception {
        Path workspace = createWorkspace();
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, "order", null, "4", "5100", "6100", false);

        ChangePlan plan = new ModuleGenerator().plan(workspace, spec);

        assertTrue(contentEndingWith(plan, "Asset.java").contains("@TableName(\"`order`\")"));
        assertTrue(contentEndingWith(plan, "AssetMapper.java").contains("UPDATE `order`"));
        assertTrue(contentEndingWith(plan, "V4__create_asset_module.sql")
                .contains("CREATE TABLE `order`"));
    }

    @Test
    void duplicateRegistrationAnchorFailsWithoutWriting() throws Exception {
        Path workspace = createWorkspace();
        Path navigation = workspace.resolve("web-starter-web/src/navigation/manifest.ts");
        Files.writeString(navigation, Files.readString(navigation)
                .replace("  // @web-starter-module-navigation\n",
                        "  // @web-starter-module-navigation\n  // @web-starter-module-navigation\n"));
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "4", "5100", "6100", false);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ModuleGenerator().plan(workspace, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertTrue(failure.getMessage().contains("must exist exactly once"));
        assertEquals(before, treeDigest(workspace));
    }

    @Test
    void nonCanonicalVersionedMigrationFailsClosedWithoutWriting() throws Exception {
        Path workspace = createWorkspace();
        Files.writeString(workspace.resolve(
                "web-starter-admin/src/main/resources/db/migration/V04__ambiguous.sql"),
                "CREATE TABLE unrelated_table (id BIGINT);\n");
        String before = treeDigest(workspace);
        ModuleSpec spec = ModuleSpec.from(
                "asset", "资产", null, null, null, "5", "5100", "6100", false);

        ToolingException failure = assertThrows(
                ToolingException.class, () -> new ModuleGenerator().plan(workspace, spec));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertTrue(failure.getMessage().contains("non-canonical Flyway migration"));
        assertEquals(before, treeDigest(workspace));
    }

    private Path createWorkspace() throws Exception {
        Path root = temporaryDirectory.resolve("workspace-" + System.nanoTime());
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
                  PROJECTS: '2002',
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

    private static String treeDigest(Path root) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(candidate -> !candidate.equals(root))
                    .sorted(Comparator.naturalOrder()).toList()) {
                digest.update((byte) (Files.isDirectory(path) ? 'D' : 'F'));
                digest.update(root.relativize(path).toString().getBytes(StandardCharsets.UTF_8));
                if (Files.isRegularFile(path)) {
                    digest.update(Files.readAllBytes(path));
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String contentEndingWith(ChangePlan plan, String suffix) {
        return plan.changes().stream()
                .filter(change -> change.relativePath().toString().endsWith(suffix))
                .map(change -> new String(change.content(), StandardCharsets.UTF_8))
                .findFirst()
                .orElseThrow();
    }
}
