package dev.webstarter.security.oauth;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * Signals that a refresh-token family was revoked deliberately and that the revocation must
 * commit even though the token endpoint returns {@code invalid_grant}.
 */
final class RefreshTokenReuseDetectedException extends OAuth2AuthenticationException {

    RefreshTokenReuseDetectedException() {
        super(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
    }
}
