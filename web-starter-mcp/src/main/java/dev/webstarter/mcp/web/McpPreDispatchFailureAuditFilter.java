package dev.webstarter.mcp.web;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.mcp.config.WebStarterMcpConfiguration;
import dev.webstarter.mcp.service.McpFailureAuditService;
import dev.webstarter.mcp.service.McpInvocationService;
import dev.webstarter.mcp.service.McpToolCatalog;
import dev.webstarter.system.audit.McpCallAuditEvent;
import io.modelcontextprotocol.json.McpJsonMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

/**
 * Completes AC-33 for failures raised by the MCP SDK before a registered tool
 * handler is entered. It reads only the JSON-RPC envelope after the transport
 * has consumed it and never persists arguments or request content.
 */
@Component
@Order(-90) // Runs after Spring Security (-100), while the authenticated context is still available.
public class McpPreDispatchFailureAuditFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(McpPreDispatchFailureAuditFilter.class);
    private static final String TOOLS_CALL = "tools/call";
    private static final int REQUEST_CACHE_LIMIT = 64 * 1024;
    private static final int TOOL_NAME_LIMIT = 128;

    private final CallerContext callerContext;
    private final McpFailureAuditService failureAuditService;
    private final McpJsonMapper jsonMapper;
    private final McpToolCatalog toolCatalog;

    @Autowired
    public McpPreDispatchFailureAuditFilter(
            CallerContext callerContext,
            McpFailureAuditService failureAuditService,
            McpJsonMapper jsonMapper,
            McpToolCatalog toolCatalog) {
        this.callerContext = callerContext;
        this.failureAuditService = failureAuditService;
        this.jsonMapper = jsonMapper;
        this.toolCatalog = toolCatalog;
    }

    public McpPreDispatchFailureAuditFilter(
            CallerContext callerContext,
            McpFailureAuditService failureAuditService,
            McpJsonMapper jsonMapper) {
        this(callerContext, failureAuditService, jsonMapper, null);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod())
                || !WebStarterMcpConfiguration.MCP_ENDPOINT.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        long started = System.nanoTime();
        ContentCachingRequestWrapper cachedRequest = new ContentCachingRequestWrapper(
                request, REQUEST_CACHE_LIMIT);
        try {
            filterChain.doFilter(cachedRequest, response);
        }
        finally {
            if (response.getStatus() >= 200
                    && response.getStatus() < 300
                    && !Boolean.TRUE.equals(cachedRequest.getAttribute(
                            McpInvocationService.REQUEST_AUDIT_ATTRIBUTE))) {
                FailedToolCall failedCall = readFailedToolCall(cachedRequest.getContentAsByteArray());
                if (failedCall != null) {
                    recordFailure(failedCall, request, started);
                }
            }
        }
    }

    private FailedToolCall readFailedToolCall(byte[] content) {
        if (content.length == 0) {
            return null;
        }
        try {
            Map<?, ?> envelope = jsonMapper.readValue(content, Map.class);
            if (!TOOLS_CALL.equals(envelope.get("method"))) {
                return null;
            }
            Object paramsValue = envelope.get("params");
            if (!(paramsValue instanceof Map<?, ?> params)) {
                return new FailedToolCall(TOOLS_CALL, null, "INVALID_ARGUMENT");
            }
            Object nameValue = params.get("name");
            if (!(nameValue instanceof String toolName) || toolName.isBlank()) {
                return new FailedToolCall(TOOLS_CALL, null, "INVALID_ARGUMENT");
            }
            String permission = toolCatalog == null
                    ? McpToolCatalog.permissionFor(toolName)
                    : toolCatalog.permissionForRegisteredTool(toolName);
            return new FailedToolCall(
                    limit(toolName, TOOL_NAME_LIMIT),
                    permission,
                    permission == null ? "UNKNOWN_TOOL" : "INVALID_ARGUMENT");
        }
        catch (IOException | RuntimeException ignored) {
            // A body that cannot identify a tools/call request is a protocol or
            // transport failure, not a Tool invocation audit row.
            return null;
        }
    }

    private void recordFailure(
            FailedToolCall failedCall,
            HttpServletRequest request,
            long started) {
        CurrentCaller caller = callerContext.current().orElse(null);
        String traceId = caller != null && caller.traceId() != null
                ? caller.traceId() : TraceContext.traceId();
        McpCallAuditEvent event = new McpCallAuditEvent(
                caller == null ? "ANONYMOUS" : caller.callerType().name(),
                caller == null ? null : caller.subjectId(),
                caller == null ? null : caller.displayName(),
                caller == null ? null : caller.tokenId(),
                caller == null ? null : caller.clientId(),
                failedCall.toolName(),
                failedCall.permission(),
                "FAILED",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started),
                request.getRemoteAddr(),
                failedCall.errorCode(),
                null,
                false,
                traceId,
                LocalDateTime.now());
        try {
            failureAuditService.record(event);
        }
        catch (RuntimeException auditFailure) {
            log.error("Unable to persist pre-dispatch MCP failure audit", auditFailure);
        }
    }

    private record FailedToolCall(String toolName, String permission, String errorCode) {
    }

    private static String limit(String value, int maxCodePoints) {
        if (value.codePointCount(0, value.length()) <= maxCodePoints) {
            return value;
        }
        return value.substring(0, value.offsetByCodePoints(0, maxCodePoints));
    }
}
