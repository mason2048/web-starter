package dev.webstarter.security.persistence.model;

import java.time.Instant;

public record ServiceAccountRecord(
        Long id,
        String code,
        String displayName,
        String description,
        boolean enabled,
        String roleIds,
        Long createdBy,
        Instant createdAt,
        Long updatedBy,
        Instant updatedAt) {
}
