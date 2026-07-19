package dev.webstarter.project.dto;

import java.time.LocalDateTime;

public record ProjectResponse(
        Long id,
        String name,
        String code,
        Long ownerId,
        String ownerName,
        String status,
        String description,
        Integer version,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
