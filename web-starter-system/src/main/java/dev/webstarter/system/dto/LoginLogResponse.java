package dev.webstarter.system.dto;

import java.time.LocalDateTime;

public record LoginLogResponse(
        Long id,
        String username,
        String result,
        String failureReason,
        String ipAddress,
        String userAgent,
        String traceId,
        LocalDateTime createdAt
) {
}
