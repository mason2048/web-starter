package dev.webstarter.system.dto;

import java.time.LocalDateTime;
import java.util.Set;

public record UserResponse(
        Long id,
        String username,
        String displayName,
        String email,
        String mobile,
        String status,
        Integer version,
        Set<Long> roleIds,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
