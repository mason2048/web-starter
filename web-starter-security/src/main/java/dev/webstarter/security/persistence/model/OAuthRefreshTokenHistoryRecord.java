package dev.webstarter.security.persistence.model;

import java.time.Instant;

public record OAuthRefreshTokenHistoryRecord(
        String tokenHash,
        String authorizationId,
        long generation,
        Instant issuedAt,
        Instant expiresAt,
        Instant consumedAt,
        Instant revokedAt,
        String revokeReason,
        Instant createdAt) {
}
