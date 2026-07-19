package dev.webstarter.security.auth;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import dev.webstarter.security.token.CredentialType;

/** Leaves prefixed internal credentials to {@link InternalCredentialAuthenticationFilter}. */
public final class OAuthOnlyBearerTokenResolver implements BearerTokenResolver {

    private final DefaultBearerTokenResolver delegate = new DefaultBearerTokenResolver();

    @Override
    public String resolve(HttpServletRequest request) {
        String token = delegate.resolve(request);
        if (token == null) {
            return null;
        }
        for (CredentialType type : CredentialType.values()) {
            if (token.startsWith(type.prefix())) {
                return null;
            }
        }
        return token;
    }
}
