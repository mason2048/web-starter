package dev.webstarter.system.audit;

import java.time.LocalDateTime;

public record McpCallAuditEvent(
        String actorType,
        String actorId,
        String actorName,
        String tokenId,
        String clientId,
        String toolName,
        String permissionCode,
        String result,
        Long durationMs,
        String ipAddress,
        String errorCode,
        String idempotencyKeyHash,
        Boolean replayed,
        String traceId,
        LocalDateTime occurredAt
) {
}
