package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import dev.webstarter.core.api.PageQuery;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.security.SecuredOperation;
import dev.webstarter.system.domain.SysLoginLog;
import dev.webstarter.system.domain.SysMcpCallLog;
import dev.webstarter.system.domain.SysOperationLog;
import dev.webstarter.system.dto.LoginLogResponse;
import dev.webstarter.system.dto.McpCallLogResponse;
import dev.webstarter.system.dto.OperationLogResponse;
import dev.webstarter.system.dto.TraceAuditResponse;
import dev.webstarter.system.persistence.mapper.LoginLogMapper;
import dev.webstarter.system.persistence.mapper.McpCallLogMapper;
import dev.webstarter.system.persistence.mapper.OperationLogMapper;
import dev.webstarter.system.service.AuditQueryService;
import dev.webstarter.system.service.AuditSearchQuery;
import dev.webstarter.system.service.SystemPermissions;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class AuditQueryServiceImpl extends SecuredOperation implements AuditQueryService {

    private static final int TRACE_ENTRY_LIMIT = 200;
    private static final Pattern SAFE_TRACE_ID = Pattern.compile("[A-Za-z0-9._-]{8,64}");

    private final LoginLogMapper loginLogMapper;
    private final OperationLogMapper operationLogMapper;
    private final McpCallLogMapper mcpCallLogMapper;

    public AuditQueryServiceImpl(CallerContext callerContext, PermissionService permissionService,
                                 LoginLogMapper loginLogMapper, OperationLogMapper operationLogMapper,
                                 McpCallLogMapper mcpCallLogMapper) {
        super(callerContext, permissionService);
        this.loginLogMapper = loginLogMapper;
        this.operationLogMapper = operationLogMapper;
        this.mcpCallLogMapper = mcpCallLogMapper;
    }

    @Override
    public PageResult<LoginLogResponse> pageLogin(AuditSearchQuery criteria) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        PageQuery query = new PageQuery(criteria.page(), criteria.size());
        Page<SysLoginLog> data = loginLogMapper.selectPage(new Page<>(query.page(), query.size()),
                new LambdaQueryWrapper<SysLoginLog>()
                        .like(hasText(criteria.subject()), SysLoginLog::getUsername, criteria.subject())
                        .eq(hasText(criteria.result()), SysLoginLog::getResult, criteria.result())
                        .eq(hasText(criteria.traceId()), SysLoginLog::getTraceId, criteria.traceId())
                        .ge(criteria.occurredFrom() != null, SysLoginLog::getCreatedAt, criteria.occurredFrom())
                        .le(criteria.occurredTo() != null, SysLoginLog::getCreatedAt, criteria.occurredTo())
                        .orderByDesc(SysLoginLog::getId));
        return PageResult.of(data.getRecords().stream().map(this::toLoginResponse).toList(), data.getTotal(), query.page(), query.size());
    }

    @Override
    public PageResult<OperationLogResponse> pageOperation(AuditSearchQuery criteria) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        PageQuery query = new PageQuery(criteria.page(), criteria.size());
        Page<SysOperationLog> data = operationLogMapper.selectPage(new Page<>(query.page(), query.size()),
                new LambdaQueryWrapper<SysOperationLog>()
                        .and(hasText(criteria.subject()), wrapper -> wrapper
                                .like(SysOperationLog::getActorName, criteria.subject())
                                .or()
                                .like(SysOperationLog::getActorId, criteria.subject()))
                        .eq(hasText(criteria.module()), SysOperationLog::getModule, criteria.module())
                        .eq(hasText(criteria.resourceType()), SysOperationLog::getResourceType, criteria.resourceType())
                        .eq(hasText(criteria.resourceId()), SysOperationLog::getResourceId, criteria.resourceId())
                        .eq(hasText(criteria.result()), SysOperationLog::getResult, criteria.result())
                        .eq(hasText(criteria.traceId()), SysOperationLog::getTraceId, criteria.traceId())
                        .ge(criteria.occurredFrom() != null, SysOperationLog::getCreatedAt, criteria.occurredFrom())
                        .le(criteria.occurredTo() != null, SysOperationLog::getCreatedAt, criteria.occurredTo())
                        .orderByDesc(SysOperationLog::getId));
        return PageResult.of(data.getRecords().stream().map(this::toOperationResponse).toList(), data.getTotal(), query.page(), query.size());
    }

    @Override
    public PageResult<McpCallLogResponse> pageMcp(AuditSearchQuery criteria) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        PageQuery query = new PageQuery(criteria.page(), criteria.size());
        Page<SysMcpCallLog> data = mcpCallLogMapper.selectPage(new Page<>(query.page(), query.size()),
                new LambdaQueryWrapper<SysMcpCallLog>()
                        .and(hasText(criteria.subject()), wrapper -> wrapper
                                .like(SysMcpCallLog::getActorName, criteria.subject())
                                .or()
                                .like(SysMcpCallLog::getActorId, criteria.subject())
                                .or()
                                .like(SysMcpCallLog::getClientId, criteria.subject()))
                        .eq(hasText(criteria.toolName()), SysMcpCallLog::getToolName, criteria.toolName())
                        .eq(hasText(criteria.result()), SysMcpCallLog::getResult, criteria.result())
                        .eq(hasText(criteria.traceId()), SysMcpCallLog::getTraceId, criteria.traceId())
                        .ge(criteria.occurredFrom() != null, SysMcpCallLog::getCreatedAt, criteria.occurredFrom())
                        .le(criteria.occurredTo() != null, SysMcpCallLog::getCreatedAt, criteria.occurredTo())
                        .orderByDesc(SysMcpCallLog::getId));
        return PageResult.of(data.getRecords().stream().map(this::toMcpResponse).toList(), data.getTotal(), query.page(), query.size());
    }

    @Override
    public TraceAuditResponse findByTrace(String traceId) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        String normalizedTraceId = requireTraceId(traceId);

        List<SysLoginLog> loginLogs = loginLogMapper.selectList(
                traceQuery(SysLoginLog::getTraceId, SysLoginLog::getCreatedAt, SysLoginLog::getId,
                        normalizedTraceId));
        List<SysOperationLog> operationLogs = operationLogMapper.selectList(
                traceQuery(SysOperationLog::getTraceId, SysOperationLog::getCreatedAt, SysOperationLog::getId,
                        normalizedTraceId));
        List<SysMcpCallLog> mcpCalls = mcpCallLogMapper.selectList(
                traceQuery(SysMcpCallLog::getTraceId, SysMcpCallLog::getCreatedAt, SysMcpCallLog::getId,
                        normalizedTraceId));

        boolean truncated = loginLogs.size() > TRACE_ENTRY_LIMIT
                || operationLogs.size() > TRACE_ENTRY_LIMIT
                || mcpCalls.size() > TRACE_ENTRY_LIMIT;
        return new TraceAuditResponse(
                normalizedTraceId,
                loginLogs.stream().limit(TRACE_ENTRY_LIMIT).map(this::toLoginResponse).toList(),
                operationLogs.stream().limit(TRACE_ENTRY_LIMIT).map(this::toOperationResponse).toList(),
                mcpCalls.stream().limit(TRACE_ENTRY_LIMIT).map(this::toMcpResponse).toList(),
                truncated);
    }

    private static <T> LambdaQueryWrapper<T> traceQuery(
            com.baomidou.mybatisplus.core.toolkit.support.SFunction<T, String> traceColumn,
            com.baomidou.mybatisplus.core.toolkit.support.SFunction<T, ?> occurredColumn,
            com.baomidou.mybatisplus.core.toolkit.support.SFunction<T, ?> idColumn,
            String traceId) {
        return new LambdaQueryWrapper<T>()
                .eq(traceColumn, traceId)
                .orderByAsc(occurredColumn)
                .orderByAsc(idColumn)
                .last("LIMIT " + (TRACE_ENTRY_LIMIT + 1));
    }

    private static String requireTraceId(String traceId) {
        if (!hasText(traceId)) {
            throw new IllegalArgumentException("traceId is required");
        }
        String normalized = traceId.trim();
        if (!SAFE_TRACE_ID.matcher(normalized).matches()) {
            throw new IllegalArgumentException("traceId has an invalid format");
        }
        return normalized;
    }

    private LoginLogResponse toLoginResponse(SysLoginLog item) {
        return new LoginLogResponse(item.getId(), item.getUsername(), item.getResult(), item.getFailureReason(),
                item.getIpAddress(), item.getUserAgent(), item.getTraceId(), item.getCreatedAt());
    }

    private OperationLogResponse toOperationResponse(SysOperationLog item) {
        return new OperationLogResponse(item.getId(), item.getActorType(), item.getActorId(), item.getActorName(),
                item.getModule(), item.getAction(), item.getResourceType(), item.getResourceId(), item.getResult(),
                item.getRequestMethod(), item.getRequestPath(), item.getIpAddress(), item.getDurationMs(),
                redactAuditDetail(item.getDetailJson()), item.getTraceId(), item.getCreatedAt());
    }

    private McpCallLogResponse toMcpResponse(SysMcpCallLog item) {
        return new McpCallLogResponse(item.getId(), item.getActorType(), item.getActorId(), item.getActorName(),
                item.getTokenId(), item.getClientId(), item.getToolName(), item.getPermissionCode(), item.getResult(),
                item.getDurationMs(), item.getIpAddress(), item.getErrorCode(), item.getIdempotencyKeyHash(),
                item.getReplayed(), item.getTraceId(), item.getCreatedAt());
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }

    /**
     * Arbitrary operation details stay in the database audit boundary. Search
     * and Trace responses preserve only the fact that a detail existed, never
     * its value, so extension modules cannot accidentally disclose a secret.
     */
    private static String redactAuditDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return null;
        }
        return "[REDACTED]";
    }
}
