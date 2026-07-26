package dev.webstarter.mcp.service;

import java.time.LocalDateTime;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import dev.webstarter.core.exception.BusinessException;
import dev.webstarter.core.exception.PermissionDeniedException;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.McpCallAuditEvent;

@Service
public class McpInvocationService {

    private static final Logger log = LoggerFactory.getLogger(McpInvocationService.class);

    /**
     * Request marker used by the outer protocol-failure audit filter. A known
     * tool sets it as soon as it reaches the shared invocation boundary so the
     * filter never creates a duplicate row.
     */
    public static final String REQUEST_AUDIT_ATTRIBUTE =
            McpInvocationService.class.getName() + ".audited";

    private final CallerContext callerContext;
    private final PermissionService permissionService;
    private final AuditLogRecorder auditLogRecorder;
    private final McpFailureAuditService failureAuditService;

    public McpInvocationService(
            CallerContext callerContext,
            PermissionService permissionService,
            AuditLogRecorder auditLogRecorder,
            McpFailureAuditService failureAuditService) {
        this.callerContext = callerContext;
        this.permissionService = permissionService;
        this.auditLogRecorder = auditLogRecorder;
        this.failureAuditService = failureAuditService;
    }

    @Transactional
    public <T> T invoke(String operation, String permission, Supplier<T> action) {
        long startedAt = System.nanoTime();
        CurrentCaller caller = callerContext.required();
        markRequestAudited();
        McpInvocationMetadata.reset();
        try {
            permissionService.requirePermission(caller, permission);
            T result = action.get();
            record(caller, operation, permission, "SUCCESS", null, startedAt);
            return result;
        }
        catch (RuntimeException exception) {
            recordFailure(caller, operation, permission, errorCode(exception), startedAt);
            throw exception;
        }
        finally {
            McpInvocationMetadata.reset();
        }
    }

    private void recordFailure(
            CurrentCaller caller,
            String operation,
            String permission,
            String errorCode,
            long startedAt) {
        try {
            failureAuditService.record(event(
                    caller, operation, permission, "FAILED", errorCode, startedAt));
        }
        catch (RuntimeException auditFailure) {
            log.error("Unable to persist failed MCP invocation audit for {}", operation, auditFailure);
        }
    }

    private void record(
            CurrentCaller caller,
            String operation,
            String permission,
            String result,
            String errorCode,
            long startedAt) {
        auditLogRecorder.recordMcpCall(event(
                caller, operation, permission, result, errorCode, startedAt));
    }

    private McpCallAuditEvent event(
            CurrentCaller caller,
            String operation,
            String permission,
            String result,
            String errorCode,
            long startedAt) {
        return new McpCallAuditEvent(
                caller.callerType().name(),
                caller.subjectId(),
                caller.displayName(),
                caller.tokenId(),
                caller.clientId(),
                operation,
                permission,
                result,
                (System.nanoTime() - startedAt) / 1_000_000,
                remoteAddress(),
                errorCode,
                McpInvocationMetadata.keyHash(),
                McpInvocationMetadata.replayed(),
                caller.traceId() == null ? TraceContext.traceId() : caller.traceId(),
                LocalDateTime.now());
    }

    private static String remoteAddress() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            HttpServletRequest request = attributes.getRequest();
            return request.getRemoteAddr();
        }
        return null;
    }

    private static void markRequestAudited() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            attributes.getRequest().setAttribute(REQUEST_AUDIT_ATTRIBUTE, Boolean.TRUE);
        }
    }

    static String errorCode(Throwable throwable) {
        if (throwable instanceof AccessDeniedException) {
            return "FORBIDDEN";
        }
        if (throwable instanceof PermissionDeniedException) {
            return "FORBIDDEN";
        }
        if (throwable instanceof ConstraintViolationException) {
            return "INVALID_ARGUMENT";
        }
        if (throwable instanceof McpIdempotencyConflictException) {
            return "IDEMPOTENCY_CONFLICT";
        }
        if (throwable instanceof McpIdempotencyInProgressException) {
            return "IDEMPOTENCY_IN_PROGRESS";
        }
        if (throwable instanceof BusinessException businessException) {
            return "BUSINESS_" + businessException.getCode();
        }
        if (throwable instanceof IllegalArgumentException) {
            return "INVALID_ARGUMENT";
        }
        return "INTERNAL_ERROR";
    }
}
