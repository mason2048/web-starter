package dev.webstarter.security.persistence.model;

import java.time.Instant;

public record OAuthClientRecord(
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
}
