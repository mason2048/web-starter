package dev.webstarter.system.service.impl;

import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.system.audit.McpCallAuditEvent;
import dev.webstarter.system.audit.OperationAuditEvent;
import dev.webstarter.system.domain.SysLoginLog;
import dev.webstarter.system.domain.SysMcpCallLog;
import dev.webstarter.system.domain.SysOperationLog;
import dev.webstarter.system.persistence.mapper.LoginLogMapper;
import dev.webstarter.system.persistence.mapper.McpCallLogMapper;
import dev.webstarter.system.persistence.mapper.OperationLogMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;

@Service
public class AuditLogRecorderImpl implements AuditLogRecorder {

    private final LoginLogMapper loginLogMapper;
    private final OperationLogMapper operationLogMapper;
    private final McpCallLogMapper mcpCallLogMapper;
    private final MeterRegistry meterRegistry;

    public AuditLogRecorderImpl(LoginLogMapper loginLogMapper, OperationLogMapper operationLogMapper,
                                McpCallLogMapper mcpCallLogMapper, MeterRegistry meterRegistry) {
        this.loginLogMapper = loginLogMapper;
        this.operationLogMapper = operationLogMapper;
        this.mcpCallLogMapper = mcpCallLogMapper;
        this.meterRegistry = meterRegistry;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordLogin(LoginAuditEvent event) {
        SysLoginLog log = new SysLoginLog();
        log.setUsername(limit(event.username(), 64));
        log.setResult(limit(event.result(), 20));
        log.setFailureReason(limit(event.failureReason(), 500));
        log.setIpAddress(limit(event.ipAddress(), 64));
        log.setUserAgent(limit(event.userAgent(), 500));
        log.setTraceId(limit(event.traceId(), 64));
        initialize(log, event.occurredAt());
        persist("login", () -> loginLogMapper.insert(log));
        meterRegistry.counter("webstarter.login.attempts",
                "result", resultTag(event.result())).increment();
    }

    @Override
    @Transactional
    public void recordOperation(OperationAuditEvent event) {
        SysOperationLog log = new SysOperationLog();
        log.setActorType(limit(event.actorType(), 32));
        log.setActorId(limit(event.actorId(), 128));
        log.setActorName(limit(event.actorName(), 100));
        log.setModule(limit(event.module(), 64));
        log.setAction(limit(event.action(), 64));
        log.setResourceType(limit(event.resourceType(), 64));
        log.setResourceId(limit(event.resourceId(), 128));
        log.setResult(limit(event.result(), 20));
        log.setRequestMethod(limit(event.requestMethod(), 16));
        log.setRequestPath(limit(event.requestPath(), 500));
        log.setIpAddress(limit(event.ipAddress(), 64));
        log.setDurationMs(event.durationMs());
        log.setDetailJson(limit(event.detailJson(), 16_000));
        log.setTraceId(limit(event.traceId(), 64));
        initialize(log, event.occurredAt());
        persist("operation", () -> operationLogMapper.insert(log));
        meterRegistry.counter("webstarter.audit.operations",
                "boundary", operationBoundaryTag(event.module()),
                "result", resultTag(event.result())).increment();
    }

    @Override
    @Transactional
    public void recordMcpCall(McpCallAuditEvent event) {
        SysMcpCallLog log = new SysMcpCallLog();
        log.setActorType(limit(event.actorType(), 32));
        log.setActorId(limit(event.actorId(), 128));
        log.setActorName(limit(event.actorName(), 100));
        log.setTokenId(limit(event.tokenId(), 128));
        log.setClientId(limit(event.clientId(), 128));
        log.setToolName(limit(event.toolName(), 128));
        log.setPermissionCode(limit(event.permissionCode(), 128));
        log.setResult(limit(event.result(), 20));
        log.setDurationMs(event.durationMs());
        log.setIpAddress(limit(event.ipAddress(), 64));
        log.setErrorCode(limit(event.errorCode(), 64));
        log.setIdempotencyKeyHash(limit(event.idempotencyKeyHash(), 64));
        log.setReplayed(Boolean.TRUE.equals(event.replayed()));
        log.setTraceId(limit(event.traceId(), 64));
        initialize(log, event.occurredAt());
        persist("mcp", () -> mcpCallLogMapper.insert(log));
        String tool = toolTag(event.toolName());
        String result = resultTag(event.result());
        meterRegistry.counter("webstarter.mcp.calls", "tool", tool, "result", result).increment();
        Timer.builder("webstarter.mcp.call.duration")
                .tags("tool", tool, "result", result)
                .register(meterRegistry)
                .record(Duration.ofMillis(Math.max(
                        0L, event.durationMs() == null ? 0L : event.durationMs())));
    }

    private void persist(String auditType, Runnable write) {
        try {
            write.run();
        }
        catch (RuntimeException exception) {
            meterRegistry.counter("webstarter.audit.persist.failures", "type", auditType).increment();
            throw exception;
        }
    }

    private static String resultTag(String result) {
        return switch (result == null ? "" : result) {
            case "SUCCESS" -> "SUCCESS";
            case "FAILED", "FAILURE" -> "FAILED";
            default -> "OTHER";
        };
    }

    private static String toolTag(String toolName) {
        return switch (toolName == null ? "" : toolName) {
            case "system.info", "project.list", "project.get", "project.create",
                    "project.update", "project.remove", "audit.list" -> toolName;
            default -> "unknown";
        };
    }

    private static String operationBoundaryTag(String module) {
        return switch (module == null ? "" : module) {
            case "project" -> "project";
            case "security" -> "security";
            case "users", "roles", "permissions", "menus", "configs" -> "system";
            default -> "extension";
        };
    }

    private void initialize(dev.webstarter.system.domain.AbstractSystemEntity entity, LocalDateTime occurredAt) {
        LocalDateTime timestamp = occurredAt == null ? LocalDateTime.now() : occurredAt;
        entity.setCreatedAt(timestamp);
        entity.setUpdatedAt(timestamp);
        entity.setDeleted(0);
    }

    private static String limit(String value, int maxLength) {
        if (value == null) {
            return value;
        }
        int codePoints = value.codePointCount(0, value.length());
        if (codePoints <= maxLength) {
            return value;
        }
        return value.substring(0, value.offsetByCodePoints(0, maxLength));
    }
}
