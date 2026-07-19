package dev.webstarter.security.persistence.model;

import java.time.Instant;

public record OAuthTokenRegistryRecord(
        Long id,
        String jtiHash,
        String authorizationId,
        String tokenType,
        String subjectType,
        Long subjectId,
        String principalName,
        String clientId,
        String scopes,
        Instant issuedAt,
        Instant expiresAt,
        Instant revokedAt,
        Instant createdAt) {

    public boolean activeAt(Instant now) {
        return revokedAt == null && expiresAt != null && expiresAt.isAfter(now);
    }
}
