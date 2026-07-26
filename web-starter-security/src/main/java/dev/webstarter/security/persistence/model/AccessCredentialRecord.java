package dev.webstarter.security.persistence.model;

import java.time.Instant;

import dev.webstarter.security.token.CredentialType;

public record AccessCredentialRecord(
        Long id,
        CredentialType credentialType,
        Long subjectId,
        long subjectSecurityEpoch,
        String name,
        String tokenHash,
        String pepperVersion,
        String tokenHint,
        String scopes,
        String ipCidrs,
        Instant expiresAt,
        Instant revokedAt,
        String revokedReason,
        Instant lastUsedAt,
        Long createdBy,
        Instant createdAt) {

    public AccessCredentialRecord(
            Long id,
            CredentialType credentialType,
            Long subjectId,
            long subjectSecurityEpoch,
            String name,
            String tokenHash,
            String tokenHint,
            String scopes,
            String ipCidrs,
            Instant expiresAt,
            Instant revokedAt,
            String revokedReason,
            Instant lastUsedAt,
            Long createdBy,
            Instant createdAt) {
        this(id, credentialType, subjectId, subjectSecurityEpoch, name, tokenHash, "v1",
                tokenHint, scopes, ipCidrs, expiresAt, revokedAt, revokedReason,
                lastUsedAt, createdBy, createdAt);
    }

    public AccessCredentialRecord(
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
        this(id, credentialType, subjectId, 0, name, tokenHash, "v1", tokenHint, scopes, ipCidrs,
                expiresAt, revokedAt, null, lastUsedAt, createdBy, createdAt);
    }

    public AccessCredentialRecord withPepper(String migratedHash, String migratedVersion) {
        return new AccessCredentialRecord(
                id, credentialType, subjectId, subjectSecurityEpoch, name, migratedHash,
                migratedVersion, tokenHint, scopes, ipCidrs, expiresAt, revokedAt,
                revokedReason, lastUsedAt, createdBy, createdAt);
    }

    public boolean activeAt(Instant now) {
        return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
    }
}
