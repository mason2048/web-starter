package dev.webstarter.security.auth;

import java.io.Serializable;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.userdetails.UserDetails;

import dev.webstarter.core.security.CurrentCaller;

public final class SystemUserPrincipal
        implements UserDetails, CallerPrincipal, CredentialsContainer, Serializable {

    private static final long serialVersionUID = 1L;

    private final CurrentCaller caller;
    private final long securityEpoch;
    private String passwordHash;
    private final boolean enabled;
    private final Collection<? extends GrantedAuthority> authorities;

    public SystemUserPrincipal(
            CurrentCaller caller,
            String passwordHash,
            boolean enabled,
            Collection<? extends GrantedAuthority> authorities) {
        this(caller, passwordHash, enabled, authorities, 0);
    }

    public SystemUserPrincipal(
            CurrentCaller caller,
            String passwordHash,
            boolean enabled,
            Collection<? extends GrantedAuthority> authorities,
            long securityEpoch) {
        this.caller = caller;
        this.securityEpoch = securityEpoch;
        this.passwordHash = passwordHash;
        this.enabled = enabled;
        this.authorities = ListCopy.copy(authorities);
    }

    @Override
    public CurrentCaller caller() {
        return caller;
    }

    @Override
    public long securityEpoch() {
        return securityEpoch;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return caller.username();
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void eraseCredentials() {
        passwordHash = null;
    }

    private static final class ListCopy {
        private static <T> Collection<T> copy(Collection<T> source) {
            return source == null ? java.util.List.of() : java.util.List.copyOf(source);
        }
    }
}
