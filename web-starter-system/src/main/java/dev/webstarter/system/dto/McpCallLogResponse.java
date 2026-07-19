package dev.webstarter.system.dto;

import java.time.LocalDateTime;

public record McpCallLogResponse(
        Long id,
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
        String traceId,
        LocalDateTime createdAt
) {
}
