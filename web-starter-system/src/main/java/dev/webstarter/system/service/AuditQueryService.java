package dev.webstarter.system.service;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.LoginLogResponse;
import dev.webstarter.system.dto.McpCallLogResponse;
import dev.webstarter.system.dto.OperationLogResponse;
import dev.webstarter.system.dto.TraceAuditResponse;

public interface AuditQueryService {
    PageResult<LoginLogResponse> pageLogin(AuditSearchQuery query);
    PageResult<OperationLogResponse> pageOperation(AuditSearchQuery query);
    PageResult<McpCallLogResponse> pageMcp(AuditSearchQuery query);
    TraceAuditResponse findByTrace(String traceId);
}
