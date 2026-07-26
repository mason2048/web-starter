package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.json.schema.jackson3.JacksonJsonSchemaValidatorSupplier;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.mcp.governance.McpToolRisk;
import dev.webstarter.project.dto.ProjectResponse;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.McpCallAuditEvent;
import dev.webstarter.system.service.AuditQueryService;

class McpToolCatalogTest {

    @Test
    void mergesStaticContributorsAndKeepsPermissionAndRiskMetadataAligned() {
        SyncToolSpecification specification = SyncToolSpecification.builder()
                .tool(Tool.builder()
                        .name("asset.list")
                        .description("List assets")
                        .inputSchema(Map.of(
                                "type", "object",
                                "properties", Map.of(),
                                "required", List.of(),
                                "additionalProperties", false))
                        .build())
                .callHandler((exchange, request) -> null)
                .build();
        McpToolContributor contributor = () -> List.of(new McpToolContribution(
                specification, "asset:list", McpToolRisk.READ));
        McpToolCatalog catalog = new McpToolCatalog(
                mock(ProjectService.class), mock(AuditQueryService.class),
                mock(McpInvocationService.class), mock(McpIdempotencyService.class),
                McpJsonDefaults.getMapper(), List.of(contributor));

        assertThat(catalog.specifications()).extracting(item -> item.tool().name())
                .endsWith("asset.list");
        assertThat(catalog.permissionForRegisteredTool("asset.list")).isEqualTo("asset:list");
        assertThat(catalog.riskForRegisteredTool("asset.list")).isEqualTo(McpToolRisk.READ);
        assertThat(catalog.permissionForRegisteredTool("unknown.tool")).isNull();
        assertThat(catalog.riskForRegisteredTool("unknown.tool")).isEqualTo(McpToolRisk.PROTOCOL);
    }

    @Test
    void rejectsContributorNamesThatCollideWithBuiltInsOrOtherModules() {
        SyncToolSpecification specification = SyncToolSpecification.builder()
                .tool(Tool.builder()
                        .name("project.list")
                        .description("Collision")
                        .inputSchema(Map.of("type", "object", "properties", Map.of(),
                                "required", List.of(), "additionalProperties", false))
                        .build())
                .callHandler((exchange, request) -> null)
                .build();
        McpToolContributor contributor = () -> List.of(new McpToolContribution(
                specification, "asset:list", McpToolRisk.READ));

        assertThatThrownBy(() -> new McpToolCatalog(
                mock(ProjectService.class), mock(AuditQueryService.class),
                mock(McpInvocationService.class), mock(McpIdempotencyService.class),
                McpJsonDefaults.getMapper(), List.of(contributor)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate MCP Tool name");
    }

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
                .containsEntry("pattern", "^[A-Za-z][A-Za-z0-9_-]{1,63}$");
        assertThat(objectMap(properties.get("description"))).containsEntry("maxLength", 2000);
        assertThat(objectMap(properties.get("ownerId")))
                .containsEntry("type", "string")
                .containsEntry("pattern", McpIdentifierContract.POSITIVE_LONG_PATTERN);
        assertThat(objectMap(properties.get(McpIdempotencyService.ARGUMENT_NAME)))
                .containsEntry("type", "string")
                .containsEntry("minLength", 16)
                .containsEntry("maxLength", 128)
                .containsEntry("pattern", "^[A-Za-z0-9._:-]+$");
        List<?> createOutputs = (List<?>) create.tool().outputSchema().get("oneOf");
        assertThat(objectMap(objectMap(createOutputs.getFirst()).get("properties")))
                .containsKeys("id", "name", "code", "ownerId", "status", "version");
        assertThat(objectMap(objectMap(createOutputs.get(1)).get("properties")))
                .containsKeys("code", "message", "traceId");
        assertThat(objectMap(objectMap(objectMap(createOutputs.get(1)).get("properties")).get("code")))
                .containsEntry("pattern", McpToolCatalog.TOOL_ERROR_CODE_PATTERN);
        assertThat(create.tool().annotations().readOnlyHint()).isFalse();

        SyncToolSpecification audit = catalog.specifications().stream()
                .filter(item -> "audit.list".equals(item.tool().name()))
                .findFirst().orElseThrow();
        Map<String, Object> auditProperties = objectMap(audit.tool().inputSchema().get("properties"));
        assertThat(auditProperties).containsKeys("actorName", "toolName", "result", "traceId");
        assertThat(objectMap(auditProperties.get("traceId")))
                .containsEntry("minLength", 8)
                .containsEntry("maxLength", 64)
                .containsEntry("pattern", "^[A-Za-z0-9._-]{8,64}$");
        assertThat(create.tool().annotations().destructiveHint()).isFalse();
        assertThat(create.tool().annotations().idempotentHint()).isFalse();

        SyncToolSpecification remove = catalog.specifications().stream()
                .filter(item -> "project.remove".equals(item.tool().name()))
                .findFirst().orElseThrow();
        List<?> removeOutputs = (List<?>) remove.tool().outputSchema().get("oneOf");
        assertThat(objectMap(objectMap(removeOutputs.getFirst()).get("properties")))
                .containsKeys("id", "removed");
        assertThat(remove.tool().annotations().destructiveHint()).isTrue();
        assertThat(remove.tool().annotations().idempotentHint()).isTrue();

        SyncToolSpecification update = catalog.specifications().stream()
                .filter(item -> "project.update".equals(item.tool().name()))
                .findFirst().orElseThrow();
        assertThat(update.tool().annotations().destructiveHint()).isTrue();
        assertThat(update.tool().annotations().idempotentHint()).isTrue();

        var successValidation = new JacksonJsonSchemaValidatorSupplier().get().validate(
                create.tool().outputSchema(),
                Map.of(
                        "id", "42",
                        "name", "Example",
                        "code", "EXAMPLE",
                        "ownerId", "7",
                        "status", "PLANNING",
                        "version", 0,
                        "createdAt", "2026-07-19T10:00:00"));
        assertThat(successValidation.valid()).as(successValidation.errorMessage()).isTrue();

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
                mock(McpIdempotencyService.class),
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
                projectService,
                mock(AuditQueryService.class),
                invocation,
                mock(McpIdempotencyService.class),
                McpJsonDefaults.getMapper());
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
        var outputValidation = new JacksonJsonSchemaValidatorSupplier().get().validate(
                specification.tool().outputSchema(), result.structuredContent());
        assertThat(outputValidation.valid()).as(outputValidation.errorMessage()).isTrue();
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
                mock(McpIdempotencyService.class),
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
