package dev.webstarter.security.auth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import dev.webstarter.core.security.CurrentCaller;

public final class CallerAuthenticationToken extends AbstractAuthenticationToken {

    private final WebStarterPrincipal principal;
    private final Object credentials;

    private CallerAuthenticationToken(
            CurrentCaller caller,
            Object credentials,
            Collection<? extends GrantedAuthority> authorities,
            boolean authenticated) {
        super(authorities);
        this.principal = caller == null ? null : new WebStarterPrincipal(caller);
        this.credentials = credentials;
        super.setAuthenticated(authenticated);
    }

    public static CallerAuthenticationToken unauthenticated(String rawToken) {
        return new CallerAuthenticationToken(null, rawToken, null, false);
    }

    public static CallerAuthenticationToken authenticated(
            CurrentCaller caller,
            Collection<? extends GrantedAuthority> authorities) {
        return new CallerAuthenticationToken(caller, null, authorities, true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public WebStarterPrincipal getPrincipal() {
        return principal;
    }

    @Override
    public String getName() {
        return principal == null ? "" : principal.getName();
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Use the authenticated factory method");
        }
        super.setAuthenticated(false);
    }
}
