package dev.webstarter.system.dto;

import java.time.LocalDateTime;

public record OperationLogResponse(
        Long id,
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
        LocalDateTime createdAt
) {
}
