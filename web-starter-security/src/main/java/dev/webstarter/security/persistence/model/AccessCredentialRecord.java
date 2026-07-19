package dev.webstarter.security.persistence.model;

import java.time.Instant;

import dev.webstarter.security.token.CredentialType;

public record AccessCredentialRecord(
        Long id,
        CredentialType credentialType,
        Long subjectId,
        String name,
        String tokenHash,
        String tokenHint,
        String scopes,
        String ipCidrs,
        Instant expiresAt,
        Instant revokedAt,
        Instant lastUsedAt,
        Long createdBy,
        Instant createdAt) {

    public boolean activeAt(Instant now) {
        return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
    }
}
