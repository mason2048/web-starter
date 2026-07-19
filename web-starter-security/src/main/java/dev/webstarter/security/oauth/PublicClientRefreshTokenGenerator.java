package dev.webstarter.security.oauth;

import java.time.Clock;
import java.util.Base64;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

/**
 * Generates rotating opaque refresh tokens for both confidential and PKCE public clients.
 *
 * <p>Spring Authorization Server intentionally suppresses refresh tokens for public authorization-code
 * clients. This starter permits them because every authorization-code client is forced to use PKCE S256,
 * refresh-token reuse is disabled, stored values are hashed, and replay invalidates the superseded token.
 */
public final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator keys;
    private Clock clock;

    public PublicClientRefreshTokenGenerator() {
        this(new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96), Clock.systemUTC());
    }

    PublicClientRefreshTokenGenerator(StringKeyGenerator keys, Clock clock) {
        this.keys = keys;
        this.clock = clock;
    }

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
                || context.getAuthorizationGrant() == null
                || !(context.getAuthorizationGrant().getPrincipal()
                        instanceof OAuth2ClientAuthenticationToken clientAuthentication)
                || !ClientAuthenticationMethod.NONE.equals(
                        clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }
        var issuedAt = clock.instant();
        var expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(keys.generateKey(), issuedAt, expiresAt);
    }

    void setClock(Clock clock) {
        Assert.notNull(clock, "clock cannot be null");
        this.clock = clock;
    }
}
