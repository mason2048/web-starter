package dev.webstarter.admin.acceptance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.mcp.service.McpContentCatalog;
import dev.webstarter.mcp.service.McpIdempotencyService;
import dev.webstarter.mcp.service.McpInvocationService;
import dev.webstarter.mcp.service.McpRuntimeIdentity;
import dev.webstarter.mcp.service.McpToolCatalog;
import dev.webstarter.project.persistence.mapper.ProjectMapper;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.project.service.impl.ProjectServiceImpl;
import dev.webstarter.project.web.ProjectController;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.service.AuditQueryService;
import dev.webstarter.system.service.SystemIdentityService;
import io.modelcontextprotocol.json.McpJsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;

class ProjectTransportParityIT {

    private static final String MCP_CLASS_PREFIX = "dev/webstarter/mcp/";
    private static final List<String> FORBIDDEN_PROJECT_PERSISTENCE_REFERENCES = List.of(
            "dev/webstarter/project/persistence/",
            "dev.webstarter.project.persistence.",
            "ProjectMapper");

    @Test
    void provesRestAndMcpShareProjectServiceWithoutProjectPersistenceDependency() throws Exception {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean("callerContext", CallerContext.class,
                    () -> mock(CallerContext.class));
            context.registerBean("permissionService", PermissionService.class,
                    () -> mock(PermissionService.class));
            context.registerBean("projectMapper", ProjectMapper.class,
                    () -> mock(ProjectMapper.class));
            context.registerBean("systemIdentityService", SystemIdentityService.class,
                    () -> mock(SystemIdentityService.class));
            context.registerBean("auditLogRecorder", AuditLogRecorder.class,
                    () -> mock(AuditLogRecorder.class));
            context.registerBean("projectService", ProjectServiceImpl.class);
            context.registerBean("auditQueryService", AuditQueryService.class,
                    () -> mock(AuditQueryService.class));
            context.registerBean("mcpInvocationService", McpInvocationService.class,
                    () -> mock(McpInvocationService.class));
            context.registerBean("mcpIdempotencyService", McpIdempotencyService.class,
                    () -> mock(McpIdempotencyService.class));
            context.registerBean("mcpJsonMapper", McpJsonMapper.class,
                    () -> mock(McpJsonMapper.class));
            context.registerBean("mcpRuntimeIdentity", McpRuntimeIdentity.class,
                    () -> new McpRuntimeIdentity("test", "local"));
            context.registerBean("projectController", ProjectController.class);
            context.registerBean("mcpToolCatalog", McpToolCatalog.class);
            context.registerBean("mcpContentCatalog", McpContentCatalog.class);
            context.refresh();

            assertEquals(Set.of("projectService"),
                    Set.of(context.getBeanNamesForType(ProjectService.class)));
            ProjectService sharedProjectService = context.getBean(ProjectService.class);
            assertInstanceOf(ProjectServiceImpl.class,
                    AopProxyUtils.getSingletonTarget(sharedProjectService) == null
                            ? sharedProjectService
                            : AopProxyUtils.getSingletonTarget(sharedProjectService));
            assertSame(sharedProjectService, projectServiceField(
                    context.getBean(ProjectController.class)));
            assertSame(sharedProjectService, projectServiceField(
                    context.getBean(McpToolCatalog.class)));
            assertSame(sharedProjectService, projectServiceField(
                    context.getBean(McpContentCatalog.class)));

            assertEquals(Set.of("projectMapper"),
                    Set.of(context.getBeanNamesForType(ProjectMapper.class)));
            assertDirectServiceBoundary(context, "projectController");
            assertDirectServiceBoundary(context, "mcpToolCatalog");
            assertDirectServiceBoundary(context, "mcpContentCatalog");
        }

        List<ClassPayload> runtimeClasses = mcpRuntimeClasses();
        Set<String> classNames = runtimeClasses.stream()
                .map(ClassPayload::name)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        assertTrue(classNames.contains(MCP_CLASS_PREFIX + "service/McpToolCatalog.class"));
        assertTrue(classNames.contains(MCP_CLASS_PREFIX + "service/McpContentCatalog.class"));
        assertTrue(classNames.contains(MCP_CLASS_PREFIX + "service/McpInvocationService.class"));
        assertFalse(runtimeClasses.isEmpty(), "MCP production classes must be discoverable");

        for (ClassPayload runtimeClass : runtimeClasses) {
            String constantPoolText = new String(
                    runtimeClass.payload(), StandardCharsets.ISO_8859_1);
            for (String forbidden : FORBIDDEN_PROJECT_PERSISTENCE_REFERENCES) {
                assertFalse(constantPoolText.contains(forbidden),
                        () -> runtimeClass.name() + " references forbidden project persistence type "
                                + forbidden);
            }
        }
    }

    private static Object projectServiceField(Object adapter) {
        Object value = ReflectionTestUtils.getField(adapter, "projectService");
        assertTrue(value instanceof ProjectService,
                () -> adapter.getClass().getName() + " must expose its injected ProjectService field");
        return value;
    }

    private static void assertDirectServiceBoundary(
            AnnotationConfigApplicationContext context,
            String adapterBeanName) {
        Set<String> dependencies = Set.of(
                context.getBeanFactory().getDependenciesForBean(adapterBeanName));
        assertTrue(dependencies.contains("projectService"),
                () -> adapterBeanName + " must directly depend on the shared ProjectService bean");
        assertFalse(dependencies.contains("projectMapper"),
                () -> adapterBeanName + " must not directly depend on ProjectMapper");
    }

    private static List<ClassPayload> mcpRuntimeClasses() throws Exception {
        URI codeSource = McpToolCatalog.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI();
        Path location = Path.of(codeSource).toAbsolutePath().normalize();
        if (Files.isDirectory(location)) {
            return classesFromDirectory(location);
        }
        return classesFromJar(location);
    }

    private static List<ClassPayload> classesFromDirectory(Path classpathRoot) throws IOException {
        Path packageRoot = classpathRoot.resolve(MCP_CLASS_PREFIX);
        assertTrue(Files.isDirectory(packageRoot),
                () -> "MCP runtime package is missing from " + classpathRoot);
        List<ClassPayload> result = new ArrayList<>();
        try (var paths = Files.walk(packageRoot)) {
            paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".class"))
                    .sorted()
                    .forEach(path -> result.add(new ClassPayload(
                            classpathRoot.relativize(path).toString().replace('\\', '/'),
                            readBytes(path))));
        }
        return List.copyOf(result);
    }

    private static List<ClassPayload> classesFromJar(Path jarPath) throws IOException {
        List<ClassPayload> result = new ArrayList<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            List<JarEntry> entries = jar.stream()
                    .filter(entry -> !entry.isDirectory())
                    .filter(entry -> entry.getName().startsWith(MCP_CLASS_PREFIX))
                    .filter(entry -> entry.getName().endsWith(".class"))
                    .sorted(Comparator.comparing(JarEntry::getName))
                    .toList();
            for (JarEntry entry : entries) {
                try (var input = jar.getInputStream(entry)) {
                    result.add(new ClassPayload(entry.getName(), input.readAllBytes()));
                }
            }
        }
        return List.copyOf(result);
    }

    private static byte[] readBytes(Path path) {
        try {
            return Files.readAllBytes(path);
        }
        catch (IOException exception) {
            throw new IllegalStateException("cannot read MCP runtime class " + path, exception);
        }
    }

    private record ClassPayload(String name, byte[] payload) {

        private ClassPayload {
            payload = payload.clone();
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }
    }
}
