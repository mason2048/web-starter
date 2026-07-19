package dev.webstarter.system.service;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.LoginLogResponse;
import dev.webstarter.system.dto.McpCallLogResponse;
import dev.webstarter.system.dto.OperationLogResponse;

public interface AuditQueryService {
    PageResult<LoginLogResponse> pageLogin(long page, long size, String username, String result);
    PageResult<OperationLogResponse> pageOperation(long page, long size, String actorName, String module, String result);
    PageResult<McpCallLogResponse> pageMcp(long page, long size, String actorName, String toolName, String result);
}
