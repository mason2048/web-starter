package dev.webstarter.security.oauth;

public enum OAuthRefreshTokenRotationResult {
    ROTATED,
    REPLAY,
    EXPIRED,
    REVOKED,
    NOT_FOUND,
    CONFLICT
}
