package dev.webstarter.security.auth;

import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.system.service.SystemIdentityService;

public final class SystemUserDetailsService implements UserDetailsService {

    private final SystemIdentityService identityService;

    public SystemUserDetailsService(SystemIdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var identity = identityService.loadByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid username or password"));
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER,
                identity.userId().toString(),
                identity.username(),
                identity.displayName(),
                null,
                null,
                Set.of(),
                identity.permissions(),
                identity.menuIds(),
                TraceContext.traceId());
        var authorities = identity.permissions().stream()
                .map(permission -> new SimpleGrantedAuthority("PERM_" + permission))
                .toList();
        return new SystemUserPrincipal(
                caller, identity.passwordHash(), identity.enabled(), authorities, identity.securityEpoch());
    }
}
