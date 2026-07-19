package dev.webstarter.mcp.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.McpCallAuditEvent;

@Service
public class McpFailureAuditService {

    private final AuditLogRecorder auditLogRecorder;

    public McpFailureAuditService(AuditLogRecorder auditLogRecorder) {
        this.auditLogRecorder = auditLogRecorder;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(McpCallAuditEvent event) {
        auditLogRecorder.recordMcpCall(event);
    }
}
