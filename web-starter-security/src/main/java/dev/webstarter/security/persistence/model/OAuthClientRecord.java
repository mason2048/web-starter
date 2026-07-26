package dev.webstarter.security.persistence.model;

import java.time.Instant;

public record OAuthClientRecord(
        String id,
        String clientId,
        String clientSecretHash,
        String clientSecretVersion,
        String retiringClientSecretHash,
        String retiringClientSecretVersion,
        Instant retiringClientSecretExpiresAt,
        Instant clientSecretRotatedAt,
        String clientName,
        String authenticationMethods,
        String grantTypes,
        String redirectUris,
        String scopes,
        boolean requireConsent,
        boolean requirePkce,
        Long serviceAccountId,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt) {

    public OAuthClientRecord(
            String id,
            String clientId,
            String clientSecretHash,
            String clientName,
            String authenticationMethods,
            String grantTypes,
            String redirectUris,
            String scopes,
            boolean requireConsent,
            boolean requirePkce,
            Long serviceAccountId,
            boolean enabled,
            Instant createdAt,
            Instant updatedAt) {
        this(id, clientId, clientSecretHash, clientSecretHash == null ? null : "v1",
                null, null, null, null, clientName, authenticationMethods, grantTypes,
                redirectUris, scopes, requireConsent, requirePkce, serviceAccountId,
                enabled, createdAt, updatedAt);
    }
}
