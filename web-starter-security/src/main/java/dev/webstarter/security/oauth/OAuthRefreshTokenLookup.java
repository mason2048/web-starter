package dev.webstarter.security.oauth;

import java.time.Instant;

public record OAuthRefreshTokenLookup(
        String authorizationId,
        OAuthRefreshTokenStatus status,
        long generation,
        String currentTokenHash,
        long presentedGeneration,
        Instant expiresAt,
        Instant revokedAt,
        String revokeReason) {

    public static OAuthRefreshTokenLookup unknown() {
        return new OAuthRefreshTokenLookup(
                null, OAuthRefreshTokenStatus.UNKNOWN, -1, null, -1, null, null, null);
    }
}
