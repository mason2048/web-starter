package dev.webstarter.security.oauth;

import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/** Authenticates the narrowly-scoped public-client requests produced by the matching converter. */
public final class PublicClientNoneAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI =
            "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository clients;

    public PublicClientNoneAuthenticationProvider(RegisteredClientRepository clients) {
        Assert.notNull(clients, "clients cannot be null");
        this.clients = clients;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }
        Object requestKind = clientAuthentication.getAdditionalParameters()
                .get(PublicClientNoneAuthenticationConverter.REQUEST_KIND);
        if (!PublicClientNoneAuthenticationConverter.REFRESH_REQUEST.equals(requestKind)
                && !PublicClientNoneAuthenticationConverter.REVOCATION_REQUEST.equals(requestKind)) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        var client = clients.findByClientId(clientId);
        if (client == null
                || !client.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.NONE))
                || client.getClientSecret() != null) {
            throw invalidClient("client_id");
        }
        if (PublicClientNoneAuthenticationConverter.REFRESH_REQUEST.equals(requestKind)
                && (!client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                || !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                || !client.getClientSettings().isRequireProofKey()
                || client.getTokenSettings().isReuseRefreshTokens())) {
            throw invalidClient("grant_type");
        }

        return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2AuthenticationException invalidClient(String parameterName) {
        return new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Public client authentication failed: " + parameterName,
                ERROR_URI));
    }
}
