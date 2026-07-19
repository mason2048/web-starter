package dev.webstarter.security.oauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/**
 * Keeps refresh lookup, family rotation, access-token registry updates, and protocol persistence
 * in one database transaction.
 *
 * <p>OAuth protocol errors do not roll back deliberate replay revocation performed while looking
 * up a previously used refresh token. Infrastructure and persistence failures still roll back.
 */
public class TransactionalRefreshTokenAuthenticationProvider {

    private final OAuth2RefreshTokenAuthenticationProvider delegate;

    public TransactionalRefreshTokenAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.delegate = new OAuth2RefreshTokenAuthenticationProvider(authorizationService, tokenGenerator);
    }

    @Transactional(noRollbackFor = OAuth2AuthenticationException.class)
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return delegate.authenticate(authentication);
    }

    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }
}
