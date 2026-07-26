package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.system.audit.McpCallAuditEvent;
import dev.webstarter.system.audit.OperationAuditEvent;
import dev.webstarter.system.domain.SysLoginLog;
import dev.webstarter.system.persistence.mapper.LoginLogMapper;
import dev.webstarter.system.persistence.mapper.McpCallLogMapper;
import dev.webstarter.system.persistence.mapper.OperationLogMapper;

class AuditLogRecorderImplTest {

    @Test
    void boundsUntrustedLoginMetadataWithoutSplittingUnicode() {
        LoginLogMapper loginLogs = mock(LoginLogMapper.class);
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        AuditLogRecorderImpl recorder = new AuditLogRecorderImpl(
                loginLogs, mock(OperationLogMapper.class), mock(McpCallLogMapper.class), metrics);

        recorder.recordLogin(new LoginAuditEvent(
                "u".repeat(80),
                "SUCCESS",
                null,
                "127.0.0.1",
                "\uD83D\uDE80".repeat(600),
                "trace-12345678",
                LocalDateTime.of(2026, 7, 18, 12, 0)));

        ArgumentCaptor<SysLoginLog> captured = ArgumentCaptor.forClass(SysLoginLog.class);
        verify(loginLogs).insert(captured.capture());
        assertThat(captured.getValue().getUsername()).hasSize(64);
        assertThat(captured.getValue().getUserAgent().codePointCount(
                0, captured.getValue().getUserAgent().length())).isEqualTo(500);
        assertThat(captured.getValue().getUserAgent()).doesNotEndWith("\uD83D");
        assertThat(metrics.get("webstarter.login.attempts")
                .tag("result", "SUCCESS").counter().count()).isEqualTo(1);
    }

    @Test
    void recordsLowCardinalityMcpMetricsWithoutUsingAnUntrustedToolAsATag() {
        McpCallLogMapper mcpLogs = mock(McpCallLogMapper.class);
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        AuditLogRecorderImpl recorder = new AuditLogRecorderImpl(
                mock(LoginLogMapper.class), mock(OperationLogMapper.class), mcpLogs, metrics);

        recorder.recordMcpCall(new McpCallAuditEvent(
                "USER", "7", "Operator", "pat-1", null,
                "attacker-controlled-tool-name", null, "FAILED", 12L,
                "127.0.0.1", "UNKNOWN_TOOL", null, false,
                "trace-1", LocalDateTime.now()));

        assertThat(metrics.get("webstarter.mcp.calls")
                .tags("tool", "unknown", "result", "FAILED").counter().count()).isEqualTo(1);
        assertThat(metrics.get("webstarter.mcp.call.duration")
                .tags("tool", "unknown", "result", "FAILED").timer().count()).isEqualTo(1);
    }

    @Test
    void countsOperationAuditsWithABoundedBoundaryTag() {
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        AuditLogRecorderImpl recorder = new AuditLogRecorderImpl(
                mock(LoginLogMapper.class), mock(OperationLogMapper.class),
                mock(McpCallLogMapper.class), metrics);

        recorder.recordOperation(new OperationAuditEvent(
                "USER", "7", "Operator", "attacker-controlled-module", "CREATE",
                "project", "42", "SUCCESS", "POST", "/api/projects", "127.0.0.1",
                8L, null, "trace-1", LocalDateTime.now()));

        assertThat(metrics.get("webstarter.audit.operations")
                .tags("boundary", "extension", "result", "SUCCESS")
                .counter().count()).isEqualTo(1);
    }

    @Test
    void countsAuditPersistenceFailuresAndStillPropagatesTheDatabaseError() {
        LoginLogMapper loginLogs = mock(LoginLogMapper.class);
        when(loginLogs.insert(org.mockito.ArgumentMatchers.any(SysLoginLog.class)))
                .thenThrow(new IllegalStateException("database unavailable"));
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        AuditLogRecorderImpl recorder = new AuditLogRecorderImpl(
                loginLogs, mock(OperationLogMapper.class), mock(McpCallLogMapper.class), metrics);

        assertThatThrownBy(() -> recorder.recordLogin(new LoginAuditEvent(
                "operator", "FAILURE", "BAD_CREDENTIALS", "127.0.0.1", null,
                "trace-1", LocalDateTime.now())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("database unavailable");
        assertThat(metrics.get("webstarter.audit.persist.failures")
                .tag("type", "login").counter().count()).isEqualTo(1);
    }
}
