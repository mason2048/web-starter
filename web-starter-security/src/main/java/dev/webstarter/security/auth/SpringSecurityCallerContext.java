package dev.webstarter.security.auth;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;

public final class SpringSecurityCallerContext implements CallerContext {

    private final CredentialSubjectResolver subjectResolver;

    public SpringSecurityCallerContext(CredentialSubjectResolver subjectResolver) {
        this.subjectResolver = subjectResolver;
    }

    @Override
    public Optional<CurrentCaller> current() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }
        if (authentication.getPrincipal() instanceof CallerPrincipal principal) {
            CurrentCaller authenticated = principal.caller();
            Optional<CurrentCaller> live = switch (authenticated.callerType()) {
                case USER -> subjectResolver.resolveUser(Long.valueOf(authenticated.subjectId()));
                case SERVICE_ACCOUNT -> subjectResolver.resolveServiceAccount(
                        Long.valueOf(authenticated.subjectId()));
            };
            return live.map(subject -> new CurrentCaller(
                    subject.callerType(), subject.subjectId(), subject.username(), subject.displayName(),
                    authenticated.tokenId(), authenticated.clientId(), authenticated.scopes(),
                    subject.permissions(), subject.menuIds(), TraceContext.traceId()));
        }
        return Optional.empty();
    }
}
