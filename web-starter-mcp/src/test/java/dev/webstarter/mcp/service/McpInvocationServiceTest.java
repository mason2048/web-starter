package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Set;

import jakarta.validation.ConstraintViolationException;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.exception.PermissionDeniedException;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.McpCallAuditEvent;

class McpInvocationServiceTest {

    @Test
    void validationAndPermissionFailuresHaveProtocolSafeErrorCodes() {
        assertThat(McpInvocationService.errorCode(new ConstraintViolationException(Set.of())))
                .isEqualTo("INVALID_ARGUMENT");
        assertThat(McpInvocationService.errorCode(new PermissionDeniedException("project:create")))
                .isEqualTo("FORBIDDEN");
        assertThat(McpInvocationService.errorCode(new McpIdempotencyConflictException("conflict")))
                .isEqualTo("IDEMPOTENCY_CONFLICT");
        assertThat(McpInvocationService.errorCode(new McpIdempotencyInProgressException()))
                .isEqualTo("IDEMPOTENCY_IN_PROGRESS");
    }

    @Test
    void successAuditFailureRollsBackOuterInvocationAndRecordsFailureSeparately() {
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.required()).thenReturn(caller());
        PermissionService permissionService = mock(PermissionService.class);
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        doThrow(new IllegalStateException("audit unavailable"))
                .when(auditLogRecorder).recordMcpCall(any());
        McpFailureAuditService failureAuditService = mock(McpFailureAuditService.class);
        McpInvocationService target = new McpInvocationService(
                callerContext, permissionService, auditLogRecorder, failureAuditService);
        RecordingTransactionManager transactionManager = new RecordingTransactionManager();
        ProxyFactory proxyFactory = new ProxyFactory(target);
        proxyFactory.addAdvice(new TransactionInterceptor(
                transactionManager,
                new AnnotationTransactionAttributeSource()));
        McpInvocationService transactional = (McpInvocationService) proxyFactory.getProxy();

        assertThatThrownBy(() -> transactional.invoke("project.create", "project:create", () -> "created"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("audit unavailable");

        assertThat(transactionManager.rolledBack).isTrue();
        assertThat(transactionManager.committed).isFalse();
        verify(permissionService).requirePermission(caller(), "project:create");
        verify(failureAuditService).record(any(McpCallAuditEvent.class));
    }

    @Test
    void marksRequestWhenKnownToolReachesSharedAuditBoundary() {
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.required()).thenReturn(caller());
        PermissionService permissionService = mock(PermissionService.class);
        when(permissionService.hasPermission(caller(), "project:create")).thenReturn(true);
        McpInvocationService target = new McpInvocationService(
                callerContext,
                permissionService,
                mock(AuditLogRecorder.class),
                mock(McpFailureAuditService.class));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mcp");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(target.invoke("project.create", "project:create", () -> "created"))
                    .isEqualTo("created");
            assertThat(request.getAttribute(McpInvocationService.REQUEST_AUDIT_ATTRIBUTE))
                    .isEqualTo(Boolean.TRUE);
        }
        finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void successAuditIncludesOnlyTheHashedIdempotencyKeyAndReplayMarker() {
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.required()).thenReturn(caller());
        PermissionService permissionService = mock(PermissionService.class);
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        McpInvocationService target = new McpInvocationService(
                callerContext,
                permissionService,
                auditLogRecorder,
                mock(McpFailureAuditService.class));

        assertThat(target.invoke("project.create", "project:create", () -> {
            McpInvocationMetadata.idempotency("hashed-key", true);
            return "replayed";
        })).isEqualTo("replayed");

        ArgumentCaptor<McpCallAuditEvent> event = ArgumentCaptor.forClass(McpCallAuditEvent.class);
        verify(auditLogRecorder).recordMcpCall(event.capture());
        assertThat(event.getValue().idempotencyKeyHash()).isEqualTo("hashed-key");
        assertThat(event.getValue().replayed()).isTrue();
        assertThat(McpInvocationMetadata.keyHash()).isNull();
        assertThat(McpInvocationMetadata.replayed()).isFalse();
    }

    private static CurrentCaller caller() {
        return new CurrentCaller(
                CallerType.USER,
                "1",
                "operator",
                "Operator",
                "token-1",
                null,
                Set.of("project:create"),
                Set.of("project:create"),
                Set.of(),
                "trace-1");
    }

    private static final class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        private boolean committed;
        private boolean rolledBack;

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            committed = true;
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            rolledBack = true;
        }
    }
}
