package dev.webstarter.system.dto;

import java.time.LocalDateTime;
import java.util.Set;

public record RoleResponse(
        Long id,
        String code,
        String name,
        String description,
        String status,
        Integer version,
        Set<Long> permissionIds,
        Set<Long> menuIds,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
