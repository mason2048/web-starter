package dev.webstarter.admin.web;

import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.OperationAuditEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OperationFailureAuditService implements OperationFailureAuditWriter {

    private final AuditLogRecorder auditLogRecorder;

    public OperationFailureAuditService(AuditLogRecorder auditLogRecorder) {
        this.auditLogRecorder = auditLogRecorder;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(OperationAuditEvent event) {
        auditLogRecorder.recordOperation(event);
    }
}
