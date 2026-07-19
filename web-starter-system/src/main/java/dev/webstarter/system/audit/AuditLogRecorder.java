package dev.webstarter.system.audit;

public interface AuditLogRecorder {
    void recordLogin(LoginAuditEvent event);
    void recordOperation(OperationAuditEvent event);
    void recordMcpCall(McpCallAuditEvent event);
}
