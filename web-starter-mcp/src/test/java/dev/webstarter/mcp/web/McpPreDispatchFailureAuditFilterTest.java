package dev.webstarter.mcp.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.OutputStream;
import java.util.Optional;
import java.util.Set;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.service.McpFailureAuditService;
import dev.webstarter.mcp.service.McpInvocationService;
import dev.webstarter.system.audit.McpCallAuditEvent;
import io.modelcontextprotocol.json.McpJsonDefaults;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class McpPreDispatchFailureAuditFilterTest {

    private static final String SENSITIVE_ARGUMENT = "must-not-appear-in-audit";

    private McpFailureAuditService failureAuditService;
    private McpPreDispatchFailureAuditFilter filter;

    @BeforeEach
    void setUp() {
        failureAuditService = mock(McpFailureAuditService.class);
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER,
                "7",
                "mcp-user",
                "MCP User",
                "token-9",
                "client-3",
                Set.of("project:create"),
                Set.of("project:create"),
                Set.of(),
                "trace-audit-0001");
        CallerContext callerContext = () -> Optional.of(caller);
        filter = new McpPreDispatchFailureAuditFilter(
                callerContext, failureAuditService, McpJsonDefaults.getMapper());
    }

    @Test
    void auditsUnknownToolWithoutPersistingArgumentsAndTruncatesLongName() throws Exception {
        String longToolName = "unknown." + "x".repeat(180);
        MockHttpServletRequest request = request("""
                {"jsonrpc":"2.0","id":"unknown-1","method":"tools/call","params":{
                  "name":"%s","arguments":{"secret":"%s"}
                }}
                """.formatted(longToolName, SENSITIVE_ARGUMENT));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (wrapped, result) -> {
            wrapped.getInputStream().transferTo(OutputStream.nullOutputStream());
            ((MockHttpServletResponse) result).setStatus(200);
        });

        McpCallAuditEvent event = capturedEvent();
        assertThat(event.toolName()).hasSize(128).isEqualTo(longToolName.substring(0, 128));
        assertThat(event.permissionCode()).isNull();
        assertThat(event.result()).isEqualTo("FAILED");
        assertThat(event.errorCode()).isEqualTo("UNKNOWN_TOOL");
        assertThat(event.actorId()).isEqualTo("7");
        assertThat(event.tokenId()).isEqualTo("token-9");
        assertThat(event.clientId()).isEqualTo("client-3");
        assertThat(event.traceId()).isEqualTo("trace-audit-0001");
        assertThat(event.toString()).doesNotContain(SENSITIVE_ARGUMENT);
    }

    @Test
    void auditsKnownToolRequestThatFailsBeforeHandlerConversion() throws Exception {
        MockHttpServletRequest request = request("""
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                  "name":"project.create","arguments":"not-an-object"
                }}
                """);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (wrapped, result) -> {
            wrapped.getInputStream().transferTo(OutputStream.nullOutputStream());
            ((MockHttpServletResponse) result).setStatus(200);
        });

        McpCallAuditEvent event = capturedEvent();
        assertThat(event.toolName()).isEqualTo("project.create");
        assertThat(event.permissionCode()).isEqualTo("project:create");
        assertThat(event.errorCode()).isEqualTo("INVALID_ARGUMENT");
    }

    @Test
    void doesNotDuplicateAuditAfterKnownHandlerReachedSharedBoundary() throws Exception {
        MockHttpServletRequest request = request("""
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                  "name":"project.list","arguments":{}
                }}
                """);

        filter.doFilter(request, new MockHttpServletResponse(), (wrapped, result) -> {
            wrapped.getInputStream().transferTo(OutputStream.nullOutputStream());
            wrapped.setAttribute(McpInvocationService.REQUEST_AUDIT_ATTRIBUTE, Boolean.TRUE);
            ((MockHttpServletResponse) result).setStatus(200);
        });

        verifyNoInteractions(failureAuditService);
    }

    @Test
    void doesNotTurnInvalidSessionTransportResponseIntoToolAudit() throws Exception {
        MockHttpServletRequest request = request("""
                {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
                  "name":"project.list","arguments":{}
                }}
                """);

        filter.doFilter(request, new MockHttpServletResponse(), (wrapped, result) -> {
            wrapped.getInputStream().transferTo(OutputStream.nullOutputStream());
            ((MockHttpServletResponse) result).setStatus(404);
        });

        verifyNoInteractions(failureAuditService);
    }

    private McpCallAuditEvent capturedEvent() {
        ArgumentCaptor<McpCallAuditEvent> event = ArgumentCaptor.forClass(McpCallAuditEvent.class);
        verify(failureAuditService).record(event.capture());
        return event.getValue();
    }

    private static MockHttpServletRequest request(String content) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mcp");
        request.setContentType("application/json");
        request.setContent(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        request.setRemoteAddr("192.0.2.10");
        return request;
    }
}
