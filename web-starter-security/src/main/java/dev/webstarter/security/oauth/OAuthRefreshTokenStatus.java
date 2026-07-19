package dev.webstarter.security.oauth;

public enum OAuthRefreshTokenStatus {
    CURRENT,
    REPLAY,
    EXPIRED,
    REVOKED,
    UNKNOWN
}
