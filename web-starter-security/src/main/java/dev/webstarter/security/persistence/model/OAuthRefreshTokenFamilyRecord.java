package dev.webstarter.security.persistence.model;

import java.time.Instant;

public record OAuthRefreshTokenFamilyRecord(
        String authorizationId,
        String currentTokenHash,
        long generation,
        Instant currentIssuedAt,
        Instant currentExpiresAt,
        Instant revokedAt,
        String revokeReason,
        Instant createdAt,
        Instant updatedAt) {
}
