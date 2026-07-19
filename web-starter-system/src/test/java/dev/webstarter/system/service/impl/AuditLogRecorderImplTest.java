package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.system.domain.SysLoginLog;
import dev.webstarter.system.persistence.mapper.LoginLogMapper;
import dev.webstarter.system.persistence.mapper.McpCallLogMapper;
import dev.webstarter.system.persistence.mapper.OperationLogMapper;

class AuditLogRecorderImplTest {

    @Test
    void boundsUntrustedLoginMetadataWithoutSplittingUnicode() {
        LoginLogMapper loginLogs = mock(LoginLogMapper.class);
        AuditLogRecorderImpl recorder = new AuditLogRecorderImpl(
                loginLogs, mock(OperationLogMapper.class), mock(McpCallLogMapper.class));

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
    }
}
