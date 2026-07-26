package dev.webstarter.mcp.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.governance.McpRateLimiter;
import dev.webstarter.mcp.governance.McpSessionRegistry;
import dev.webstarter.mcp.governance.McpToolRisk;
import dev.webstarter.mcp.service.McpFailureAuditService;
import dev.webstarter.system.audit.McpCallAuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.modelcontextprotocol.json.McpJsonDefaults;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class McpGovernanceFilterTest {

    private static final String SESSION_ID = "session-abc";
    private McpSessionRegistry sessions;
    private McpRateLimiter limiter;
    private McpFailureAuditService audit;
    private McpSdkSessionCloser sdkSessionCloser;
    private McpGovernanceFilter filter;

    @BeforeEach
    void setUp() {
        sessions = mock(McpSessionRegistry.class);
        limiter = mock(McpRateLimiter.class);
        audit = mock(McpFailureAuditService.class);
        sdkSessionCloser = mock(McpSdkSessionCloser.class);
        CallerContext callers = () -> Optional.of(caller());
        when(limiter.checkAndConsume(any(), any())).thenReturn(McpRateLimiter.Decision.permit());
        filter = new McpGovernanceFilter(
                callers, sessions, limiter, audit,
                McpJsonDefaults.getMapper(), new SimpleMeterRegistry(), sdkSessionCloser);
    }

    @Test
    void reservesAndActivatesSuccessfulInitializeBeforeCopyingResponse() throws Exception {
        McpSessionRegistry.Reservation reservation = reservation();
        when(sessions.reserve(any())).thenReturn(reservation);
        MockHttpServletRequest request = post("""
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
                """);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (wrapped, result) -> {
            String replayed = new String(wrapped.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(replayed).contains("initialize");
            HttpServletResponse http = (HttpServletResponse) result;
            http.setStatus(200);
            http.setHeader("Mcp-Session-Id", SESSION_ID);
            http.getWriter().write("{\"initialized\":true}");
        });

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeader("Mcp-Session-Id")).isEqualTo(SESSION_ID);
        assertThat(response.getContentAsString()).contains("initialized");
        verify(sessions).activate(reservation, SESSION_ID);
        verify(sessions, never()).release(reservation);
        verifyNoInteractions(audit);
    }

    @Test
    void rejectsSubjectSessionCapWithRetryAfterAndAudit() throws Exception {
        when(sessions.reserve(any())).thenReturn(McpSessionRegistry.Reservation.rejected(17));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        filter.doFilter(post("""
                {"jsonrpc":"2.0","id":"init-2","method":"initialize","params":{}}
                """), response, downstream);

        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("17");
        assertThat(response.getContentAsString()).contains("SESSION_LIMIT");
        verify(downstream, never()).doFilter(any(), any());
        assertAudit("initialize", "SESSION_LIMIT");
    }

    @Test
    void activationFailureClosesUnexposedSdkSessionAndReleasesReservation() throws Exception {
        McpSessionRegistry.Reservation reservation = reservation();
        when(sessions.reserve(any())).thenReturn(reservation);
        doThrow(new IllegalStateException("redis unavailable"))
                .when(sessions).activate(reservation, SESSION_ID);
        MockHttpServletRequest request = post("""
                {"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}
                """);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (wrapped, result) -> {
            HttpServletResponse http = (HttpServletResponse) result;
            http.setStatus(200);
            http.setHeader("Mcp-Session-Id", SESSION_ID);
            http.getWriter().write("{\"initialized\":true}");
        });

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader("Mcp-Session-Id")).isNull();
        assertThat(response.getContentAsString()).contains("GOVERNANCE_UNAVAILABLE");
        assertThat(response.getContentAsString()).doesNotContain("redis unavailable");
        verify(sdkSessionCloser).close(any(), any(), org.mockito.ArgumentMatchers.eq(SESSION_ID));
        verify(sessions).release(reservation);
        assertAudit("initialize", "GOVERNANCE_UNAVAILABLE");
    }

    @Test
    void expiredSessionCannotReachSdkAndToolArgumentsAreNotAudited() throws Exception {
        String sensitive = "do-not-store-this";
        when(sessions.validateAndTouch(any(), any())).thenReturn(McpSessionRegistry.Validation.EXPIRED);
        MockHttpServletRequest request = post(("""
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                  "name":"project.update","arguments":{"secret":"%s"}
                }}
                """).formatted(sensitive));
        request.addHeader("Mcp-Session-Id", SESSION_ID);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        filter.doFilter(request, response, downstream);

        assertThat(response.getStatus()).isEqualTo(404);
        verify(downstream, never()).doFilter(any(), any());
        McpCallAuditEvent event = capturedAudit();
        assertThat(event.toolName()).isEqualTo("project.update");
        assertThat(event.permissionCode()).isEqualTo("project:update");
        assertThat(event.errorCode()).isEqualTo("SESSION_EXPIRED");
        assertThat(event.toString()).doesNotContain(sensitive);
        verify(sdkSessionCloser).close(any(), any(), org.mockito.ArgumentMatchers.eq(SESSION_ID));
    }

    @Test
    void rateLimitedDestructiveToolReturns429AndAuditsOutcome() throws Exception {
        when(sessions.validateAndTouch(any(), any())).thenReturn(McpSessionRegistry.Validation.ACTIVE);
        when(limiter.checkAndConsume(any(), any())).thenReturn(McpRateLimiter.Decision.blocked(4));
        MockHttpServletRequest request = post("""
                {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
                  "name":"project.remove","arguments":{"id":"9"}
                }}
                """);
        request.addHeader("Mcp-Session-Id", SESSION_ID);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        filter.doFilter(request, response, downstream);

        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("4");
        assertThat(response.getContentAsString()).contains("RATE_LIMITED");
        verify(limiter).checkAndConsume(any(), org.mockito.ArgumentMatchers.eq(McpToolRisk.DESTRUCTIVE));
        verify(downstream, never()).doFilter(any(), any());
        assertAudit("project.remove", "RATE_LIMITED");
    }

    @Test
    void validExplicitDeleteReachesOfficialTransportThenRemovesRegistryEntry() throws Exception {
        when(sessions.validateAndTouch(any(), any())).thenReturn(McpSessionRegistry.Validation.ACTIVE);
        when(sessions.delete(any(), any())).thenReturn(McpSessionRegistry.Validation.ACTIVE);
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/mcp");
        request.addHeader("Mcp-Session-Id", SESSION_ID);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (wrapped, result) ->
                ((HttpServletResponse) result).setStatus(200));

        assertThat(response.getStatus()).isEqualTo(200);
        verify(sessions).delete(any(), org.mockito.ArgumentMatchers.eq(SESSION_ID));
        verifyNoInteractions(audit);
    }

    @Test
    @SuppressWarnings("unchecked")
    void expiredExplicitDeleteReturnsIdLessProtocolErrorWithoutSecondaryFailure() throws Exception {
        when(sessions.validateAndTouch(any(), any())).thenReturn(McpSessionRegistry.Validation.EXPIRED);
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/mcp");
        request.addHeader("Mcp-Session-Id", SESSION_ID);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        filter.doFilter(request, response, downstream);

        assertThat(response.getStatus()).isEqualTo(404);
        Map<String, Object> body = McpJsonDefaults.getMapper()
                .readValue(response.getContentAsByteArray(), Map.class);
        assertThat(body).containsEntry("jsonrpc", "2.0");
        assertThat(body).doesNotContainKey("id");
        assertThat(body.get("error")).isInstanceOf(Map.class);
        Map<String, Object> error = (Map<String, Object>) body.get("error");
        assertThat(error.get("data")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) error.get("data"))
                .containsEntry("code", "SESSION_EXPIRED");
        verify(downstream, never()).doFilter(any(), any());
        verify(sdkSessionCloser).close(any(), any(), org.mockito.ArgumentMatchers.eq(SESSION_ID));
        assertAudit("session.delete", "SESSION_EXPIRED");
    }

    @Test
    void redisFailureFailsClosedWith503AndAudit() throws Exception {
        when(limiter.checkAndConsume(any(), any())).thenThrow(new IllegalStateException("redis unavailable"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(post("""
                {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
                  "name":"project.list","arguments":{}
                }}
                """), response, (wrapped, result) ->
                wrapped.getInputStream().transferTo(OutputStream.nullOutputStream()));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader("Retry-After")).isEqualTo("1");
        assertThat(response.getContentAsString()).contains("GOVERNANCE_UNAVAILABLE");
        assertThat(response.getContentAsString()).doesNotContain("redis unavailable");
        assertAudit("project.list", "GOVERNANCE_UNAVAILABLE");
    }

    @Test
    void sessionReservationFailureFailsClosedWithoutLeakingBackendDetails() throws Exception {
        when(sessions.reserve(any()))
                .thenThrow(new IllegalStateException("redis.internal.example:6379 credential=secret"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        Logger logger = (Logger) LoggerFactory.getLogger(McpGovernanceFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        try {
            filter.doFilter(post("""
                    {"jsonrpc":"2.0","id":6,"method":"initialize","params":{}}
                    """), response, downstream);
        }
        finally {
            logger.detachAppender(appender);
            appender.stop();
        }

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader("Retry-After")).isEqualTo("1");
        assertThat(response.getContentAsString()).contains("GOVERNANCE_UNAVAILABLE");
        assertThat(response.getContentAsString())
                .doesNotContain("redis.internal.example")
                .doesNotContain("credential")
                .doesNotContain("secret");
        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.getFirst().getFormattedMessage())
                .contains("causeType=java.lang.IllegalStateException")
                .doesNotContain("redis.internal.example")
                .doesNotContain("credential")
                .doesNotContain("secret");
        assertThat(appender.list.getFirst().getThrowableProxy()).isNull();
        verify(downstream, never()).doFilter(any(), any());
        assertAudit("initialize", "GOVERNANCE_UNAVAILABLE");
    }

    private void assertAudit(String operation, String errorCode) {
        McpCallAuditEvent event = capturedAudit();
        assertThat(event.toolName()).isEqualTo(operation);
        assertThat(event.errorCode()).isEqualTo(errorCode);
        assertThat(event.result()).isEqualTo("FAILED");
        assertThat(event.actorId()).isEqualTo("17");
        assertThat(event.clientId()).isEqualTo("client-2");
        assertThat(event.traceId()).isEqualTo("trace-governance-1");
    }

    private McpCallAuditEvent capturedAudit() {
        ArgumentCaptor<McpCallAuditEvent> event = ArgumentCaptor.forClass(McpCallAuditEvent.class);
        verify(audit).record(event.capture());
        return event.getValue();
    }

    private static MockHttpServletRequest post(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mcp");
        request.setContentType("application/json");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.setRemoteAddr("192.0.2.44");
        return request;
    }

    private static McpSessionRegistry.Reservation reservation() {
        return new McpSessionRegistry.Reservation(
                true, 0, "reservation-1", "subject-hash", "owner-hash", "client-hash");
    }

    private static CurrentCaller caller() {
        return new CurrentCaller(
                CallerType.USER, "17", "operator", "Operator", "token-1", "client-2",
                Set.of("project:list", "project:update", "project:remove"),
                Set.of("project:list", "project:update", "project:remove"),
                Set.of(), "trace-governance-1");
    }
}
