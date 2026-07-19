package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.project.dto.ProjectResponse;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.McpCallAuditEvent;
import dev.webstarter.system.service.AuditQueryService;

class McpToolCatalogTest {

    @Test
    void exposesOnlyTheSevenReviewedToolNames() {
        McpToolCatalog catalog = catalog(mock(McpInvocationService.class));

        List<String> names = catalog.specifications().stream()
                .map(specification -> specification.tool().name())
                .toList();

        assertThat(names).containsExactly(
                "system.info",
                "project.list",
                "project.get",
                "project.create",
                "project.update",
                "project.remove",
                "audit.list");
        assertThat(names).noneMatch(name -> name.matches("(?i).*(sql|shell|exec|file|code).*"));

        SyncToolSpecification create = catalog.specifications().stream()
                .filter(item -> "project.create".equals(item.tool().name()))
                .findFirst().orElseThrow();
        Map<String, Object> properties = objectMap(create.tool().inputSchema().get("properties"));
        assertThat(objectMap(properties.get("status")))
                .containsEntry("enum", List.of("PLANNING", "IN_PROGRESS", "ARCHIVED"));
        assertThat(objectMap(properties.get("name"))).containsEntry("maxLength", 120);
        assertThat(objectMap(properties.get("code")))
                .containsEntry("maxLength", 64)
                .containsEntry("pattern", "[A-Za-z][A-Za-z0-9_-]{1,63}");
        assertThat(objectMap(properties.get("description"))).containsEntry("maxLength", 2000);
        assertThat(objectMap(properties.get("ownerId")))
                .containsEntry("type", "string")
                .containsEntry("pattern", McpIdentifierContract.POSITIVE_LONG_PATTERN);

        for (String toolName : List.of("project.get", "project.update", "project.remove")) {
            SyncToolSpecification idTool = catalog.specifications().stream()
                    .filter(item -> toolName.equals(item.tool().name()))
                    .findFirst().orElseThrow();
            Map<String, Object> idProperties = objectMap(idTool.tool().inputSchema().get("properties"));
            assertThat(objectMap(idProperties.get("id")))
                    .as("%s project id contract", toolName)
                    .containsEntry("type", "string")
                    .containsEntry("pattern", McpIdentifierContract.POSITIVE_LONG_PATTERN);
        }

        Pattern idPattern = Pattern.compile(McpIdentifierContract.POSITIVE_LONG_PATTERN);
        assertThat(idPattern.matcher("9007199254740993").matches()).isTrue();
        assertThat(idPattern.matcher(Long.toString(Long.MAX_VALUE)).matches()).isTrue();
        assertThat(idPattern.matcher("9223372036854775808").matches()).isFalse();
    }

    @Test
    void projectListUsesSharedPermissionServiceBusinessServiceAndAudit() {
        CallerContext callerContext = mock(CallerContext.class);
        PermissionService permissionService = mock(PermissionService.class);
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        McpFailureAuditService failureAuditService = mock(McpFailureAuditService.class);
        CurrentCaller caller = caller();
        when(callerContext.required()).thenReturn(caller);
        ProjectService projectService = mock(ProjectService.class);
        long unsafeId = 9_007_199_254_740_993L;
        when(projectService.page(2, 50, "starter", "IN_PROGRESS", unsafeId))
                .thenReturn(PageResult.of(List.of(new ProjectResponse(
                        unsafeId,
                        "Starter",
                        "STARTER",
                        unsafeId + 1,
                        "Owner",
                        "IN_PROGRESS",
                        null,
                        3,
                        null,
                        null)), 1, 2, 50));
        McpInvocationService invocation = new McpInvocationService(
                callerContext, permissionService, auditLogRecorder, failureAuditService);
        McpToolCatalog catalog = new McpToolCatalog(
                projectService,
                mock(AuditQueryService.class),
                invocation,
                McpJsonDefaults.getMapper());
        SyncToolSpecification specification = catalog.specifications().stream()
                .filter(item -> "project.list".equals(item.tool().name()))
                .findFirst()
                .orElseThrow();

        var result = specification.callHandler().apply(null, new CallToolRequest(
                "project.list",
                Map.of("page", 2, "size", 50, "keyword", "starter", "status", "IN_PROGRESS",
                        "ownerId", "9007199254740993")));

        assertThat(result.isError()).isFalse();
        Map<String, Object> output = objectMap(result.structuredContent());
        Map<String, Object> project = objectMap(((List<?>) output.get("records")).getFirst());
        assertThat(project)
                .containsEntry("id", "9007199254740993")
                .containsEntry("ownerId", "9007199254740994")
                .containsEntry("version", 3);
        assertThat(output.get("total")).isEqualTo(1L).isInstanceOf(Number.class);
        assertThat(output.get("page")).isEqualTo(2L).isInstanceOf(Number.class);
        assertThat(output.get("size")).isEqualTo(50L).isInstanceOf(Number.class);
        verify(permissionService).requirePermission(caller, "project:list");
        verify(projectService).page(2, 50, "starter", "IN_PROGRESS", unsafeId);
        verify(auditLogRecorder).recordMcpCall(org.mockito.ArgumentMatchers.any(McpCallAuditEvent.class));
    }

    @Test
    void invalidToolArgumentsAreAuditedInsideInvocationBoundary() {
        CallerContext callerContext = mock(CallerContext.class);
        PermissionService permissionService = mock(PermissionService.class);
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        McpFailureAuditService failureAuditService = mock(McpFailureAuditService.class);
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER, "1", "operator", "Operator", "token-1", null,
                Set.of("project:create"), Set.of("project:create"), Set.of(), "trace-1");
        when(callerContext.required()).thenReturn(caller);
        ProjectService projectService = mock(ProjectService.class);
        McpInvocationService invocation = new McpInvocationService(
                callerContext, permissionService, auditLogRecorder, failureAuditService);
        McpToolCatalog catalog = new McpToolCatalog(
                projectService, mock(AuditQueryService.class), invocation, McpJsonDefaults.getMapper());
        SyncToolSpecification specification = catalog.specifications().stream()
                .filter(item -> "project.create".equals(item.tool().name()))
                .findFirst()
                .orElseThrow();

        var result = specification.callHandler().apply(null, new CallToolRequest(
                "project.create",
                Map.of("name", "Example", "code", "EXAMPLE", "status", "ACTIVE")));

        assertThat(result.isError()).isTrue();
        assertThat(objectMap(result.structuredContent()))
                .containsEntry("code", "INVALID_ARGUMENT");
        verify(permissionService).requirePermission(caller, "project:create");
        verify(projectService, never()).create(org.mockito.ArgumentMatchers.any());
        verify(failureAuditService).record(org.mockito.ArgumentMatchers.argThat(event ->
                "FAILED".equals(event.result()) && "INVALID_ARGUMENT".equals(event.errorCode())));
    }

    private static McpToolCatalog catalog(McpInvocationService invocationService) {
        return new McpToolCatalog(
                mock(ProjectService.class),
                mock(AuditQueryService.class),
                invocationService,
                McpJsonDefaults.getMapper());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectMap(Object value) {
        return (Map<String, Object>) value;
    }

    private static CurrentCaller caller() {
        return new CurrentCaller(
                CallerType.USER,
                "1",
                "operator",
                "Operator",
                "token-1",
                null,
                Set.of("project:list"),
                Set.of("project:list"),
                Set.of(),
                "trace-1");
    }
}
