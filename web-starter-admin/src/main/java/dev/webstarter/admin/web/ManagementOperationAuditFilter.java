package dev.webstarter.admin.web;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.security.auth.CallerSnapshotRequestFilter;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.OperationAuditEvent;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Makes successful management writes and their operation audit one database
 * transaction. Failure audits are written only after that transaction has
 * rolled back, through a separate REQUIRES_NEW service.
 */
@Component
@Order(-101) // Wrap Spring Security (-100) so CSRF and authorization failures are audited.
public class ManagementOperationAuditFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ManagementOperationAuditFilter.class);
    private static final Set<String> MUTATING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final List<String> AUDITED_PREFIXES = List.of(
            "/api/users",
            "/api/roles",
            "/api/permissions",
            "/api/menus",
            "/api/configs",
            "/api/security",
            "/api/projects");
    /**
     * REST prefixes whose shared business Service already records successful
     * writes for both Web and MCP. The filter still records their failures.
     */
    private static final List<String> SERVICE_AUDITED_PREFIXES = List.of(
            "/api/projects");

    private final AuditLogRecorder auditLogRecorder;
    private final OperationFailureAuditWriter failureAuditWriter;
    private final TransactionTemplate transactionTemplate;

    public ManagementOperationAuditFilter(
            AuditLogRecorder auditLogRecorder,
            OperationFailureAuditWriter failureAuditWriter,
            PlatformTransactionManager transactionManager) {
        this.auditLogRecorder = auditLogRecorder;
        this.failureAuditWriter = failureAuditWriter;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!MUTATING_METHODS.contains(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        return AUDITED_PREFIXES.stream().noneMatch(
                prefix -> path.equals(prefix) || path.startsWith(prefix + "/"));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        long started = System.nanoTime();
        ContentCachingResponseWrapper bufferedResponse = new ContentCachingResponseWrapper(response);
        try {
            transactionTemplate.executeWithoutResult(status -> {
                try {
                    filterChain.doFilter(request, bufferedResponse);
                }
                catch (ServletException | IOException exception) {
                    status.setRollbackOnly();
                    throw new FilterChainFailure(exception);
                }
                if (bufferedResponse.getStatus() >= 400) {
                    status.setRollbackOnly();
                    return;
                }
                // Shared Services in this list record success for both REST and MCP.
                // The filter handles only their failures to avoid duplicate success rows.
                if (!isServiceAuditedPath(request.getRequestURI())) {
                    auditLogRecorder.recordOperation(event(
                            request, started, "SUCCESS", null));
                }
            });
        }
        catch (FilterChainFailure failure) {
            recordFailure(request, started, failure.getCause());
            rethrow(failure.getCause());
            return;
        }
        catch (RuntimeException failure) {
            recordFailure(request, started, failure);
            if (!response.isCommitted()) {
                response.reset();
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            throw failure;
        }

        if (bufferedResponse.getStatus() >= 400) {
            recordFailure(request, started, null);
        }
        bufferedResponse.copyBodyToResponse();
    }

    private void recordFailure(
            HttpServletRequest request,
            long started,
            Throwable failure) {
        try {
            failureAuditWriter.recordFailure(event(
                    request,
                    started,
                    "FAILURE",
                    failure == null ? null : failure.getClass().getSimpleName()));
        }
        catch (RuntimeException auditFailure) {
            log.error("Unable to persist failed management operation audit", auditFailure);
        }
    }

    private static OperationAuditEvent event(
            HttpServletRequest request,
            long started,
            String result,
            String detail) {
        String path = request.getRequestURI();
        AuditDescriptor descriptor = describe(request);
        CurrentCaller caller = request.getAttribute(CallerSnapshotRequestFilter.REQUEST_ATTRIBUTE)
                instanceof CurrentCaller snapshot ? snapshot : null;
        return new OperationAuditEvent(
                caller == null ? "ANONYMOUS" : caller.callerType().name(),
                caller == null ? null : caller.subjectId(),
                caller == null ? null : caller.displayName(),
                descriptor.module(),
                descriptor.action(),
                descriptor.resourceType(),
                descriptor.resourceId(),
                result,
                request.getMethod(),
                path,
                request.getRemoteAddr(),
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started),
                detail,
                TraceContext.traceId(),
                LocalDateTime.now());
    }

    private static boolean isServiceAuditedPath(String path) {
        return SERVICE_AUDITED_PREFIXES.stream().anyMatch(
                prefix -> path.equals(prefix) || path.startsWith(prefix + "/"));
    }

    private static String module(String path) {
        String[] segments = path.split("/");
        if (segments.length > 3 && "security".equals(segments[2])) {
            return "security";
        }
        String module = segments.length > 2 ? segments[2] : "system";
        // Shared Services own their success audit and use the singular domain
        // module name. Keep filter-owned failures under the same query key.
        return isServiceAuditedPath(path) ? singular(module) : module;
    }

    static AuditDescriptor describe(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        String[] segments = path.split("/");
        boolean security = segments.length > 3 && "security".equals(segments[2]);
        String collection = security && segments.length > 3
                ? segments[3] : (segments.length > 2 ? segments[2] : "system");
        boolean tokenPath = collection.contains("tokens")
                || ("service-accounts".equals(collection) && path.contains("/tokens"));
        String resourceType = tokenPath ? "token" : singular(collection);
        String operation = action(method);
        if (path.endsWith("/password")) {
            operation = "RESET_PASSWORD";
        }
        else if (path.endsWith("/rotate-secret")) {
            operation = "ROTATE_SECRET";
        }
        else if (tokenPath && "POST".equals(method)) {
            operation = "ISSUE_TOKEN";
        }
        else if (tokenPath && "DELETE".equals(method)) {
            operation = "REVOKE_TOKEN";
        }
        else if ("service-accounts".equals(collection) && "DELETE".equals(method)) {
            operation = "DISABLE";
        }
        Object capturedId = request.getAttribute(OperationAuditRequestContext.RESOURCE_ID_ATTRIBUTE);
        String id = capturedId == null ? pathResourceId(segments, security, tokenPath) : capturedId.toString();
        return new AuditDescriptor(module(path), operation, resourceType, id);
    }

    private static String pathResourceId(String[] segments, boolean security, boolean tokenPath) {
        String candidate = null;
        if (security && tokenPath && segments.length > 6) {
            candidate = segments[6];
        }
        else if (security && segments.length > 4) {
            candidate = segments[4];
        }
        else if (!security && segments.length > 3) {
            candidate = segments[3];
        }
        return candidate != null && candidate.matches("[A-Za-z0-9._-]{1,128}") ? candidate : null;
    }

    private static String singular(String collection) {
        return switch (collection) {
            case "users" -> "user";
            case "roles" -> "role";
            case "permissions" -> "permission";
            case "menus" -> "menu";
            case "configs" -> "config";
            case "projects" -> "project";
            case "service-accounts" -> "service-account";
            case "oauth-clients" -> "oauth-client";
            case "personal-tokens" -> "personal-token";
            default -> collection;
        };
    }

    private static String resourceId(String path) {
        String[] segments = path.split("/");
        if (segments.length < 4) {
            return null;
        }
        String candidate = segments[segments.length - 1];
        return candidate.matches("[A-Za-z0-9._-]{1,128}") ? candidate : null;
    }

    private static String action(String method) {
        return switch (method.toUpperCase(Locale.ROOT)) {
            case "POST" -> "CREATE";
            case "DELETE" -> "REMOVE";
            default -> "UPDATE";
        };
    }

    private static void rethrow(Throwable failure) throws ServletException, IOException {
        if (failure instanceof ServletException servletException) {
            throw servletException;
        }
        if (failure instanceof IOException ioException) {
            throw ioException;
        }
        if (failure instanceof RuntimeException runtimeException) {
            throw runtimeException;
        }
        throw new ServletException(failure);
    }

    private static final class FilterChainFailure extends RuntimeException {
        private FilterChainFailure(Throwable cause) {
            super(cause);
        }
    }

    record AuditDescriptor(String module, String action, String resourceType, String resourceId) {
    }
}
