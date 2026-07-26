package dev.webstarter.mcp.web;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.mcp.config.WebStarterMcpConfiguration;
import dev.webstarter.mcp.governance.McpRateLimiter;
import dev.webstarter.mcp.governance.McpSessionRegistry;
import dev.webstarter.mcp.service.McpFailureAuditService;
import dev.webstarter.mcp.service.McpInvocationService;
import dev.webstarter.mcp.service.McpToolCatalog;
import dev.webstarter.system.audit.McpCallAuditEvent;
import io.micrometer.core.instrument.MeterRegistry;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Enforces MCP session lifecycle and caller-aware application limits after
 * Spring Security authentication and before the official SDK Servlet.
 */
@Component
@Order(-95)
public final class McpGovernanceFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(McpGovernanceFilter.class);
    private static final String SESSION_HEADER = "Mcp-Session-Id";

    private final CallerContext callerContext;
    private final McpSessionRegistry sessionRegistry;
    private final McpRateLimiter rateLimiter;
    private final McpFailureAuditService failureAuditService;
    private final McpJsonMapper jsonMapper;
    private final MeterRegistry meterRegistry;
    private final McpSdkSessionCloser sdkSessionCloser;
    private final McpToolCatalog toolCatalog;

    @Autowired
    public McpGovernanceFilter(
            CallerContext callerContext,
            McpSessionRegistry sessionRegistry,
            McpRateLimiter rateLimiter,
            McpFailureAuditService failureAuditService,
            McpJsonMapper jsonMapper,
            MeterRegistry meterRegistry,
            McpSdkSessionCloser sdkSessionCloser,
            McpToolCatalog toolCatalog) {
        this.callerContext = callerContext;
        this.sessionRegistry = sessionRegistry;
        this.rateLimiter = rateLimiter;
        this.failureAuditService = failureAuditService;
        this.jsonMapper = jsonMapper;
        this.meterRegistry = meterRegistry;
        this.sdkSessionCloser = sdkSessionCloser;
        this.toolCatalog = toolCatalog;
    }

    public McpGovernanceFilter(
            CallerContext callerContext,
            McpSessionRegistry sessionRegistry,
            McpRateLimiter rateLimiter,
            McpFailureAuditService failureAuditService,
            McpJsonMapper jsonMapper,
            MeterRegistry meterRegistry,
            McpSdkSessionCloser sdkSessionCloser) {
        this(callerContext, sessionRegistry, rateLimiter, failureAuditService,
                jsonMapper, meterRegistry, sdkSessionCloser, null);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !WebStarterMcpConfiguration.MCP_ENDPOINT.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        long started = System.nanoTime();
        CurrentCaller caller = callerContext.current().orElse(null);
        HttpServletRequest effectiveRequest = request;
        McpRequestDescriptor descriptor;
        try {
            if ("POST".equals(request.getMethod())) {
                CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request);
                effectiveRequest = cached;
                descriptor = McpRequestDescriptor.describe(
                        request.getMethod(), cached.body(), jsonMapper, toolCatalog);
            }
            else {
                descriptor = McpRequestDescriptor.describe(
                        request.getMethod(), null, jsonMapper, toolCatalog);
            }
        }
        catch (CachedBodyHttpServletRequest.RequestBodyTooLargeException exception) {
            descriptor = McpRequestDescriptor.describe(
                    request.getMethod(), null, jsonMapper, toolCatalog);
            reject(caller, descriptor, request, response, started,
                    HttpStatus.PAYLOAD_TOO_LARGE.value(), "REQUEST_TOO_LARGE", 0);
            return;
        }

        if (caller == null) {
            reject(null, descriptor, request, response, started,
                    HttpStatus.UNAUTHORIZED.value(), "UNAUTHORIZED", 0);
            return;
        }

        String sessionId = request.getHeader(SESSION_HEADER);
        boolean hasSession = sessionId != null && !sessionId.isBlank();
        if (hasSession && sessionId.length() > 512) {
            reject(caller, descriptor, request, response, started,
                    HttpStatus.BAD_REQUEST.value(), "SESSION_ID_INVALID", 0);
            return;
        }

        if (hasSession) {
            try {
                if (!validateSession(caller, sessionId, descriptor, request, response, started)) {
                    return;
                }
            }
            catch (RuntimeException governanceFailure) {
                rejectGovernanceUnavailable(
                        caller, descriptor, request, response, started, governanceFailure);
                return;
            }
        }

        McpRateLimiter.Decision rateDecision;
        try {
            rateDecision = rateLimiter.checkAndConsume(caller, descriptor.risk());
        }
        catch (RuntimeException governanceFailure) {
            rejectGovernanceUnavailable(
                    caller, descriptor, request, response, started, governanceFailure);
            return;
        }
        if (!rateDecision.allowed()) {
            meterRegistry.counter("webstarter.mcp.rate_limited",
                    "risk", descriptor.risk().name().toLowerCase()).increment();
            reject(caller, descriptor, request, response, started,
                    HttpStatus.TOO_MANY_REQUESTS.value(), "RATE_LIMITED",
                    rateDecision.retryAfterSeconds());
            return;
        }

        if (descriptor.initialize()) {
            initializeSession(caller, descriptor, effectiveRequest, response, filterChain, started);
            return;
        }

        filterChain.doFilter(effectiveRequest, response);
        if ("DELETE".equals(request.getMethod()) && hasSession
                && (isSuccess(response.getStatus()) || response.getStatus() == HttpStatus.NOT_FOUND.value())) {
            try {
                sessionRegistry.delete(caller, sessionId);
                meterRegistry.counter("webstarter.mcp.sessions", "event", "deleted").increment();
            }
            catch (RuntimeException cleanupFailure) {
                // The official transport has already closed the node-local session and may
                // have committed its response. The rebuildable Redis row will expire by TTL.
                meterRegistry.counter("webstarter.mcp.sessions", "event", "cleanup_failed").increment();
                logGovernanceWarning(
                        "Unable to remove deleted MCP session coordination state", cleanupFailure);
            }
        }
    }

    private void initializeSession(
            CurrentCaller caller,
            McpRequestDescriptor descriptor,
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain,
            long started) throws IOException, ServletException {
        McpSessionRegistry.Reservation reservation;
        try {
            reservation = sessionRegistry.reserve(caller);
        }
        catch (RuntimeException governanceFailure) {
            rejectGovernanceUnavailable(
                    caller, descriptor, request, response, started, governanceFailure);
            return;
        }
        if (!reservation.accepted()) {
            meterRegistry.counter("webstarter.mcp.sessions", "event", "limit_rejected").increment();
            reject(caller, descriptor, request, response, started,
                    HttpStatus.TOO_MANY_REQUESTS.value(), "SESSION_LIMIT",
                    reservation.retryAfterSeconds());
            return;
        }

        ContentCachingResponseWrapper cachedResponse = new ContentCachingResponseWrapper(response);
        boolean activated = false;
        try {
            filterChain.doFilter(request, cachedResponse);
            String sessionId = cachedResponse.getHeader(SESSION_HEADER);
            if (isSuccess(cachedResponse.getStatus()) && sessionId != null && !sessionId.isBlank()) {
                try {
                    sessionRegistry.activate(reservation, sessionId);
                    activated = true;
                    meterRegistry.counter("webstarter.mcp.sessions", "event", "created").increment();
                }
                catch (RuntimeException activationFailure) {
                    sdkSessionCloser.close(request, cachedResponse, sessionId);
                    cachedResponse.reset();
                    logGovernanceError(
                            "Unable to activate MCP session lifecycle record", activationFailure);
                    reject(caller, descriptor, request, cachedResponse, started,
                            HttpStatus.SERVICE_UNAVAILABLE.value(), "GOVERNANCE_UNAVAILABLE", 1);
                }
            }
            cachedResponse.copyBodyToResponse();
        }
        finally {
            if (!activated) {
                try {
                    sessionRegistry.release(reservation);
                }
                catch (RuntimeException releaseFailure) {
                    logGovernanceWarning(
                            "Unable to release MCP session reservation", releaseFailure);
                }
            }
        }
    }

    private void rejectGovernanceUnavailable(
            CurrentCaller caller,
            McpRequestDescriptor descriptor,
            HttpServletRequest request,
            HttpServletResponse response,
            long started,
            RuntimeException governanceFailure) throws IOException {
        logGovernanceError("MCP governance store operation failed", governanceFailure);
        reject(caller, descriptor, request, response, started,
                HttpStatus.SERVICE_UNAVAILABLE.value(), "GOVERNANCE_UNAVAILABLE", 1);
    }

    private boolean validateSession(
            CurrentCaller caller,
            String sessionId,
            McpRequestDescriptor descriptor,
            HttpServletRequest request,
            HttpServletResponse response,
            long started) throws IOException {
        McpSessionRegistry.Validation validation = sessionRegistry.validateAndTouch(caller, sessionId);
        if (validation == McpSessionRegistry.Validation.ACTIVE) {
            return true;
        }
        String errorCode = validation == McpSessionRegistry.Validation.OWNER_MISMATCH
                ? "SESSION_OWNER_MISMATCH"
                : validation == McpSessionRegistry.Validation.EXPIRED
                        ? "SESSION_EXPIRED" : "SESSION_NOT_FOUND";
        meterRegistry.counter("webstarter.mcp.sessions",
                "event", validation.name().toLowerCase()).increment();
        if (validation == McpSessionRegistry.Validation.EXPIRED) {
            sdkSessionCloser.close(request, response, sessionId);
        }
        reject(caller, descriptor, request, response, started,
                HttpStatus.NOT_FOUND.value(), errorCode, 0);
        return false;
    }

    private void reject(
            CurrentCaller caller,
            McpRequestDescriptor descriptor,
            HttpServletRequest request,
            HttpServletResponse response,
            long started,
            int status,
            String errorCode,
            long retryAfterSeconds) throws IOException {
        request.setAttribute(McpInvocationService.REQUEST_AUDIT_ATTRIBUTE, Boolean.TRUE);
        recordFailure(caller, descriptor, request, started, errorCode);
        response.reset();
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        if (retryAfterSeconds > 0) {
            response.setHeader("Retry-After", Long.toString(retryAfterSeconds));
        }
        String traceId = caller != null && caller.traceId() != null
                ? caller.traceId() : TraceContext.traceId();
        McpError error = McpError.builder(-32000)
                .message(publicMessage(errorCode))
                .data(Map.of("code", errorCode, "traceId", traceId))
                .build();
        Object payload = descriptor.requestId() == null
                ? Map.of(
                        "jsonrpc", "2.0",
                        "error", error.getJsonRpcError())
                : McpSchema.JSONRPCResponse.error(
                        descriptor.requestId(), error.getJsonRpcError());
        response.getWriter().write(jsonMapper.writeValueAsString(payload));
        response.getWriter().flush();
    }

    private void recordFailure(
            CurrentCaller caller,
            McpRequestDescriptor descriptor,
            HttpServletRequest request,
            long started,
            String errorCode) {
        String traceId = caller != null && caller.traceId() != null
                ? caller.traceId() : TraceContext.traceId();
        McpCallAuditEvent event = new McpCallAuditEvent(
                caller == null ? "ANONYMOUS" : caller.callerType().name(),
                caller == null ? null : caller.subjectId(),
                caller == null ? null : caller.displayName(),
                caller == null ? null : caller.tokenId(),
                caller == null ? null : caller.clientId(),
                descriptor.auditOperation(),
                descriptor.permission(),
                "FAILED",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started),
                request.getRemoteAddr(),
                errorCode,
                null,
                false,
                traceId,
                LocalDateTime.now());
        try {
            failureAuditService.record(event);
        }
        catch (RuntimeException auditFailure) {
            logGovernanceError("Unable to persist MCP governance failure audit", auditFailure);
        }
    }

    /**
     * Infrastructure exception messages can contain endpoint or credential
     * material supplied by a driver. Keep the useful failure type while never
     * handing the exception or its message to the logging backend.
     */
    private static void logGovernanceError(String operation, RuntimeException failure) {
        log.error("{}; causeType={}", operation, failure.getClass().getName());
    }

    private static void logGovernanceWarning(String operation, RuntimeException failure) {
        log.warn("{}; causeType={}", operation, failure.getClass().getName());
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    private static String publicMessage(String errorCode) {
        return switch (errorCode) {
            case "RATE_LIMITED", "SESSION_LIMIT" -> "MCP request limit exceeded";
            case "GOVERNANCE_UNAVAILABLE" -> "MCP governance is temporarily unavailable";
            case "REQUEST_TOO_LARGE" -> "MCP request is too large";
            case "UNAUTHORIZED" -> "Authentication is required";
            default -> "MCP session is expired or unavailable";
        };
    }
}
