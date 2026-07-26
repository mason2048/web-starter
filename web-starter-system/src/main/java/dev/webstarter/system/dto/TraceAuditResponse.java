package dev.webstarter.system.dto;

import java.util.List;

public record TraceAuditResponse(
        String traceId,
        List<LoginLogResponse> loginLogs,
        List<OperationLogResponse> operationLogs,
        List<McpCallLogResponse> mcpCalls,
        boolean truncated) {
}
