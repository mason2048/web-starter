package dev.webstarter.system.audit;

import java.time.LocalDateTime;

public record LoginAuditEvent(
        String username,
        String result,
        String failureReason,
        String ipAddress,
        String userAgent,
        String traceId,
        LocalDateTime occurredAt
) {
}
