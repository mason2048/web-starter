package dev.webstarter.system.audit;

import java.time.LocalDateTime;

public record OperationAuditEvent(
        String actorType,
        String actorId,
        String actorName,
        String module,
        String action,
        String resourceType,
        String resourceId,
        String result,
        String requestMethod,
        String requestPath,
        String ipAddress,
        Long durationMs,
        String detailJson,
        String traceId,
        LocalDateTime occurredAt
) {
}
