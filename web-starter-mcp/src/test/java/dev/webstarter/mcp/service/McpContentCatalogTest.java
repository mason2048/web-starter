package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema.GetPromptRequest;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.project.dto.ProjectResponse;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.McpCallAuditEvent;

class McpContentCatalogTest {

    @Test
    void exposesOneReadOnlyResourceAndOneBoundedPrompt() {
        McpContentCatalog catalog = new McpContentCatalog(
                mock(ProjectService.class),
                mock(McpInvocationService.class),
                McpJsonDefaults.getMapper());

        assertThat(catalog.resources())
                .extracting(item -> item.resource().uri())
                .containsExactly("web-starter://system/info");
        assertThat(catalog.prompts())
                .extracting(item -> item.prompt().name())
                .containsExactly("project.summary");
        assertThat(catalog.prompts().getFirst().prompt().arguments())
                .extracting(argument -> argument.name())
                .containsExactly("projectId");
    }

    @Test
    void promptAcceptsProtocolStringArgumentAndAuditsInvalidArguments() {
        CallerContext callerContext = mock(CallerContext.class);
        PermissionService permissionService = mock(PermissionService.class);
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        McpFailureAuditService failureAuditService = mock(McpFailureAuditService.class);
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER, "1", "operator", "Operator", "token-1", null,
                Set.of("project:list"), Set.of("project:list"), Set.of(), "trace-1");
        when(callerContext.required()).thenReturn(caller);
        McpInvocationService invocation = new McpInvocationService(
                callerContext, permissionService, auditLogRecorder, failureAuditService);
        ProjectService projects = mock(ProjectService.class);
        LocalDateTime now = LocalDateTime.now();
        long unsafeId = 9_007_199_254_740_993L;
        when(projects.get(unsafeId)).thenReturn(new ProjectResponse(
                unsafeId, "Example", "EXAMPLE", Long.MAX_VALUE, "Owner", "ACTIVE", null, 0, now, now));
        McpContentCatalog catalog = new McpContentCatalog(
                projects, invocation, McpJsonDefaults.getMapper());
        var handler = catalog.prompts().getFirst().promptHandler();

        var success = handler.apply(null, new GetPromptRequest(
                "project.summary", Map.of("projectId", Long.toString(unsafeId))));
        assertThat(success.messages()).hasSize(1);
        TextContent content = (TextContent) success.messages().getFirst().content();
        assertThat(content.text())
                .contains("\"id\":\"9007199254740993\"")
                .contains("\"ownerId\":\"9223372036854775807\"")
                .contains("\"version\":0");
        verify(projects).get(unsafeId);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> handler.apply(null, new GetPromptRequest(
                "project.summary", Map.of("projectId", "not-a-number"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("positive decimal string");
        verify(failureAuditService).record(org.mockito.ArgumentMatchers.argThat(event ->
                "prompt:project.summary".equals(event.toolName())
                        && "FAILED".equals(event.result())
                        && "INVALID_ARGUMENT".equals(event.errorCode())));
        verify(auditLogRecorder).recordMcpCall(org.mockito.ArgumentMatchers.any(McpCallAuditEvent.class));
    }
}
