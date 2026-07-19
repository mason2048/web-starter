package dev.webstarter.security.oauth;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.security.auth.CallerAuthenticationToken;
import dev.webstarter.security.auth.CredentialSubjectResolver;

public final class JwtCallerAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private final CredentialSubjectResolver subjectResolver;

    public JwtCallerAuthenticationConverter(CredentialSubjectResolver subjectResolver) {
        this.subjectResolver = subjectResolver;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Long subjectId;
        try {
            subjectId = Long.valueOf(jwt.getClaimAsString("uid"));
        }
        catch (RuntimeException exception) {
            throw new InvalidBearerTokenException("OAuth token subject is invalid");
        }
        String subjectType = jwt.getClaimAsString("subject_type");
        CurrentCaller subject = ("SERVICE_ACCOUNT".equals(subjectType)
                ? subjectResolver.resolveServiceAccount(subjectId)
                : subjectResolver.resolveUser(subjectId))
                .orElseThrow(() -> new InvalidBearerTokenException("OAuth subject is unavailable"));
        Set<String> scopes = readScopes(jwt.getClaim("scope"));
        CurrentCaller caller = new CurrentCaller(
                subject.callerType(), subject.subjectId(), subject.username(), subject.displayName(),
                jwt.getId(), jwt.getClaimAsString("client_id"), scopes, subject.permissions(),
                subject.menuIds(),
                TraceContext.traceId());
        var authorities = caller.permissions().stream()
                .map(permission -> new SimpleGrantedAuthority("PERM_" + permission))
                .toList();
        return CallerAuthenticationToken.authenticated(caller, authorities);
    }

    private static Set<String> readScopes(Object claim) {
        if (claim instanceof String value) {
            return Set.of(value.split("\\s+"));
        }
        if (claim instanceof Collection<?> values) {
            Set<String> scopes = new LinkedHashSet<>();
            values.forEach(value -> scopes.add(value.toString()));
            return Set.copyOf(scopes);
        }
        return Set.of();
    }
}
