package dev.webstarter.security.auth;

import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.security.persistence.model.AccessCredentialRecord;
import dev.webstarter.security.token.AccessCredentialService;
import dev.webstarter.security.token.CredentialType;
import dev.webstarter.security.token.ScopeCodec;

public final class InternalCredentialAuthenticationProvider implements AuthenticationProvider {

    private final AccessCredentialService credentialService;
    private final CredentialSubjectResolver subjectResolver;

    public InternalCredentialAuthenticationProvider(
            AccessCredentialService credentialService,
            CredentialSubjectResolver subjectResolver) {
        this.credentialService = credentialService;
        this.subjectResolver = subjectResolver;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String rawToken = (String) authentication.getCredentials();
        String remoteAddress = authentication.getDetails() instanceof String value ? value : null;
        AccessCredentialRecord credential = credentialService.findActiveByRawToken(rawToken, remoteAddress);
        if (credential == null) {
            throw new BadCredentialsException("Invalid internal credential");
        }
        ResolvedCredentialSubject resolved = (credential.credentialType() == CredentialType.PERSONAL_ACCESS_TOKEN
                ? subjectResolver.resolveUser(credential.subjectId())
                : subjectResolver.resolveServiceAccount(credential.subjectId()))
                .orElseThrow(() -> new BadCredentialsException("Credential subject is unavailable"));
        if (credential.subjectSecurityEpoch() != resolved.securityEpoch()) {
            throw new BadCredentialsException("Credential subject is unavailable");
        }
        CurrentCaller subject = resolved.caller();
        Set<String> scopes = ScopeCodec.decode(credential.scopes());
        CurrentCaller caller = new CurrentCaller(
                subject.callerType(),
                subject.subjectId(),
                subject.username(),
                subject.displayName(),
                credential.id().toString(),
                null,
                scopes,
                subject.permissions(),
                subject.menuIds(),
                TraceContext.traceId());
        var authorities = caller.permissions().stream()
                .map(permission -> new SimpleGrantedAuthority("PERM_" + permission))
                .toList();
        return CallerAuthenticationToken.authenticated(caller, resolved.securityEpoch(), authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CallerAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
