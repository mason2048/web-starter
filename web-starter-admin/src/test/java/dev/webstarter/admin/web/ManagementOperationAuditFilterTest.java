package dev.webstarter.admin.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.security.auth.CallerSnapshotRequestFilter;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.system.audit.McpCallAuditEvent;
import dev.webstarter.system.audit.OperationAuditEvent;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;

class ManagementOperationAuditFilterTest {

    @Test
    void successAuditRunsInsideAndCommitsWithBusinessTransaction() throws Exception {
        RecordingTransactionManager transactions = new RecordingTransactionManager();
        List<OperationAuditEvent> successes = new ArrayList<>();
        List<OperationAuditEvent> failures = new ArrayList<>();
        AuditLogRecorder recorder = recorder(event -> {
            assertThat(transactions.active).isTrue();
            successes.add(event);
        });
        OperationFailureAuditWriter failureWriter = event -> failures.add(event);
        var filter = filter(transactions, recorder, failureWriter);
        var request = request("POST", "/api/configs");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, currentResponse) -> {
            ((jakarta.servlet.http.HttpServletResponse) currentResponse).setStatus(200);
            currentResponse.getWriter().write("ok");
        });

        assertThat(transactions.commits).isEqualTo(1);
        assertThat(transactions.rollbacks).isZero();
        assertThat(successes).extracting(OperationAuditEvent::result).containsExactly("SUCCESS");
        assertThat(failures).isEmpty();
        assertThat(response.getContentAsString()).isEqualTo("ok");
    }

    @Test
    void handledFailureRollsBackThenWritesRequiresNewFailureAudit() throws Exception {
        RecordingTransactionManager transactions = new RecordingTransactionManager();
        List<OperationAuditEvent> failures = new ArrayList<>();
        var filter = filter(transactions, recorder(event -> {
            throw new AssertionError("success audit must not be written");
        }), event -> {
            assertThat(transactions.active).isFalse();
            failures.add(event);
        });
        var request = request("PUT", "/api/projects/7");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, currentResponse) -> {
            ((jakarta.servlet.http.HttpServletResponse) currentResponse).setStatus(409);
            currentResponse.getWriter().write("conflict");
        });

        assertThat(transactions.commits).isZero();
        assertThat(transactions.rollbacks).isEqualTo(1);
        assertThat(failures).extracting(OperationAuditEvent::result).containsExactly("FAILURE");
        assertThat(failures).extracting(OperationAuditEvent::module).containsExactly("project");
        assertThat(response.getContentAsString()).isEqualTo("conflict");
    }

    @Test
    void serviceAuditedModuleDoesNotReceiveDuplicateSuccessAudit() throws Exception {
        RecordingTransactionManager transactions = new RecordingTransactionManager();
        List<OperationAuditEvent> filterSuccesses = new ArrayList<>();
        var filter = filter(transactions, recorder(filterSuccesses::add), event -> {
            throw new AssertionError("failure audit must not be written");
        });
        var request = request("POST", "/api/projects");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, currentResponse) ->
                ((jakarta.servlet.http.HttpServletResponse) currentResponse).setStatus(200));

        assertThat(transactions.commits).isEqualTo(1);
        assertThat(transactions.rollbacks).isZero();
        assertThat(filterSuccesses).isEmpty();
    }

    @Test
    void successAuditInsertFailureRollsBackBusinessTransaction() {
        RecordingTransactionManager transactions = new RecordingTransactionManager();
        List<OperationAuditEvent> failures = new ArrayList<>();
        var filter = filter(transactions, recorder(event -> {
            throw new IllegalStateException("audit database unavailable");
        }), failures::add);
        var request = request("DELETE", "/api/users/9");
        var response = new MockHttpServletResponse();

        assertThatThrownBy(() -> filter.doFilter(
                request, response, (ignoredRequest, ignoredResponse) -> { }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("audit database unavailable");

        assertThat(transactions.commits).isZero();
        assertThat(transactions.rollbacks).isEqualTo(1);
        assertThat(failures).extracting(OperationAuditEvent::result).containsExactly("FAILURE");
        assertThat(response.getStatus()).isEqualTo(500);
    }

    @Test
    void derivesCanonicalActionsAndResourceIdsForNestedSecurityRoutes() {
        MockHttpServletRequest password = request("PUT", "/api/users/7/password");
        assertThat(ManagementOperationAuditFilter.describe(password))
                .isEqualTo(new ManagementOperationAuditFilter.AuditDescriptor(
                        "users", "RESET_PASSWORD", "user", "7"));

        MockHttpServletRequest rotate = request(
                "POST", "/api/security/oauth-clients/agent-1/rotate-secret");
        assertThat(ManagementOperationAuditFilter.describe(rotate))
                .isEqualTo(new ManagementOperationAuditFilter.AuditDescriptor(
                        "security", "ROTATE_SECRET", "oauth-client", "agent-1"));

        MockHttpServletRequest issue = request(
                "POST", "/api/security/service-accounts/10/tokens");
        issue.setAttribute(OperationAuditRequestContext.RESOURCE_ID_ATTRIBUTE, "99");
        assertThat(ManagementOperationAuditFilter.describe(issue))
                .isEqualTo(new ManagementOperationAuditFilter.AuditDescriptor(
                        "security", "ISSUE_TOKEN", "token", "99"));

        MockHttpServletRequest revoke = request(
                "DELETE", "/api/security/service-accounts/10/tokens/99");
        assertThat(ManagementOperationAuditFilter.describe(revoke))
                .isEqualTo(new ManagementOperationAuditFilter.AuditDescriptor(
                        "security", "REVOKE_TOKEN", "token", "99"));
    }

    private static ManagementOperationAuditFilter filter(
            RecordingTransactionManager transactions,
            AuditLogRecorder recorder,
            OperationFailureAuditWriter failureWriter) {
        return new ManagementOperationAuditFilter(
                recorder, failureWriter, transactions);
    }

    private static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRemoteAddr("10.0.0.8");
        request.setAttribute(CallerSnapshotRequestFilter.REQUEST_ATTRIBUTE, new CurrentCaller(
                CallerType.USER, "1", "operator", "Operator", null, null,
                Set.of(), Set.of("system:config:manage"), Set.of(), "trace-1"));
        return request;
    }

    private static AuditLogRecorder recorder(java.util.function.Consumer<OperationAuditEvent> operation) {
        return new AuditLogRecorder() {
            @Override public void recordLogin(LoginAuditEvent event) { }
            @Override public void recordOperation(OperationAuditEvent event) { operation.accept(event); }
            @Override public void recordMcpCall(McpCallAuditEvent event) { }
        };
    }

    private static final class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        private boolean active;
        private int commits;
        private int rollbacks;

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
            active = true;
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            commits++;
            active = false;
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            rollbacks++;
            active = false;
        }
    }
}
