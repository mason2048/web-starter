package dev.webstarter.admin.web;

import dev.webstarter.system.audit.OperationAuditEvent;

public interface OperationFailureAuditWriter {

    void recordFailure(OperationAuditEvent event);
}
