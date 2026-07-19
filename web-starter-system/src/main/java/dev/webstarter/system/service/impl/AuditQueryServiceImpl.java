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
import dev.webstarter.system.persistence.mapper.LoginLogMapper;
import dev.webstarter.system.persistence.mapper.McpCallLogMapper;
import dev.webstarter.system.persistence.mapper.OperationLogMapper;
import dev.webstarter.system.service.AuditQueryService;
import dev.webstarter.system.service.SystemPermissions;
import org.springframework.stereotype.Service;

@Service
public class AuditQueryServiceImpl extends SecuredOperation implements AuditQueryService {

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
    public PageResult<LoginLogResponse> pageLogin(long page, long size, String username, String result) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        PageQuery query = new PageQuery(page, size);
        Page<SysLoginLog> data = loginLogMapper.selectPage(new Page<>(query.page(), query.size()),
                new LambdaQueryWrapper<SysLoginLog>()
                        .like(hasText(username), SysLoginLog::getUsername, username)
                        .eq(hasText(result), SysLoginLog::getResult, result)
                        .orderByDesc(SysLoginLog::getId));
        return PageResult.of(data.getRecords().stream().map(this::toLoginResponse).toList(), data.getTotal(), query.page(), query.size());
    }

    @Override
    public PageResult<OperationLogResponse> pageOperation(long page, long size, String actorName, String module, String result) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        PageQuery query = new PageQuery(page, size);
        Page<SysOperationLog> data = operationLogMapper.selectPage(new Page<>(query.page(), query.size()),
                new LambdaQueryWrapper<SysOperationLog>()
                        .like(hasText(actorName), SysOperationLog::getActorName, actorName)
                        .eq(hasText(module), SysOperationLog::getModule, module)
                        .eq(hasText(result), SysOperationLog::getResult, result)
                        .orderByDesc(SysOperationLog::getId));
        return PageResult.of(data.getRecords().stream().map(this::toOperationResponse).toList(), data.getTotal(), query.page(), query.size());
    }

    @Override
    public PageResult<McpCallLogResponse> pageMcp(long page, long size, String actorName, String toolName, String result) {
        requirePermission(SystemPermissions.AUDIT_LIST);
        PageQuery query = new PageQuery(page, size);
        Page<SysMcpCallLog> data = mcpCallLogMapper.selectPage(new Page<>(query.page(), query.size()),
                new LambdaQueryWrapper<SysMcpCallLog>()
                        .like(hasText(actorName), SysMcpCallLog::getActorName, actorName)
                        .eq(hasText(toolName), SysMcpCallLog::getToolName, toolName)
                        .eq(hasText(result), SysMcpCallLog::getResult, result)
                        .orderByDesc(SysMcpCallLog::getId));
        return PageResult.of(data.getRecords().stream().map(this::toMcpResponse).toList(), data.getTotal(), query.page(), query.size());
    }

    private LoginLogResponse toLoginResponse(SysLoginLog item) {
        return new LoginLogResponse(item.getId(), item.getUsername(), item.getResult(), item.getFailureReason(),
                item.getIpAddress(), item.getUserAgent(), item.getTraceId(), item.getCreatedAt());
    }

    private OperationLogResponse toOperationResponse(SysOperationLog item) {
        return new OperationLogResponse(item.getId(), item.getActorType(), item.getActorId(), item.getActorName(),
                item.getModule(), item.getAction(), item.getResourceType(), item.getResourceId(), item.getResult(),
                item.getRequestMethod(), item.getRequestPath(), item.getIpAddress(), item.getDurationMs(),
                item.getDetailJson(), item.getTraceId(), item.getCreatedAt());
    }

    private McpCallLogResponse toMcpResponse(SysMcpCallLog item) {
        return new McpCallLogResponse(item.getId(), item.getActorType(), item.getActorId(), item.getActorName(),
                item.getTokenId(), item.getClientId(), item.getToolName(), item.getPermissionCode(), item.getResult(),
                item.getDurationMs(), item.getIpAddress(), item.getErrorCode(), item.getTraceId(), item.getCreatedAt());
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
}
