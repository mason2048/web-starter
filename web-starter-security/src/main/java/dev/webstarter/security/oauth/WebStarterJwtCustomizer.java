package dev.webstarter.security.oauth;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.security.auth.CallerPrincipal;
import dev.webstarter.security.auth.CredentialSubjectResolver;
import dev.webstarter.security.auth.ResolvedCredentialSubject;
import dev.webstarter.security.config.WebStarterSecurityProperties;

public final class WebStarterJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final CredentialSubjectResolver subjectResolver;
    private final WebStarterSecurityProperties properties;

    public WebStarterJwtCustomizer(
            CredentialSubjectResolver subjectResolver,
            WebStarterSecurityProperties properties) {
        this.subjectResolver = subjectResolver;
        this.properties = properties;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }
        ResolvedCredentialSubject subject = resolveCaller(context);
        CurrentCaller caller = subject.caller();
        context.getClaims()
                .id(UUID.randomUUID().toString())
                // Keep claim metadata on stable public collection types so the strict
                // Jackson 3 validator used by JDBC authorization persistence can read it back.
                .audience(new ArrayList<>(List.of(properties.resourceAudience())))
                .subject(caller.username())
                .claim("uid", caller.subjectId())
                // Keep the persisted token-claims map compatible with the strict
                // Jackson 3 polymorphic type validator used by the JDBC service.
                .claim("sepoch", Long.toString(subject.securityEpoch()))
                .claim("subject_type", caller.callerType().name())
                .claim("client_id", context.getRegisteredClient().getClientId());
    }

    private ResolvedCredentialSubject resolveCaller(JwtEncodingContext context) {
        if (context.getPrincipal().getPrincipal() instanceof CallerPrincipal principal) {
            ResolvedCredentialSubject live = resolveLive(principal.caller())
                    .orElseThrow(WebStarterJwtCustomizer::subjectUnavailable);
            if (live.securityEpoch() != principal.securityEpoch()) {
                throw subjectUnavailable();
            }
            return live;
        }
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
            Long accountId = context.getRegisteredClient().getClientSettings()
                    .getSetting(DatabaseRegisteredClientRepository.SERVICE_ACCOUNT_ID_SETTING);
            if (accountId == null) {
                throw subjectUnavailable();
            }
            return subjectResolver.resolveServiceAccount(accountId)
                    .orElseThrow(WebStarterJwtCustomizer::subjectUnavailable);
        }
        if (context.getAuthorization() != null) {
            String subjectId = context.getAuthorization()
                    .getAttribute(HashingOAuth2AuthorizationService.SUBJECT_ID_ATTRIBUTE);
            String subjectType = context.getAuthorization()
                    .getAttribute(HashingOAuth2AuthorizationService.SUBJECT_TYPE_ATTRIBUTE);
            Object storedEpoch = context.getAuthorization()
                    .getAttribute(HashingOAuth2AuthorizationService.SUBJECT_SECURITY_EPOCH_ATTRIBUTE);
            if (subjectId != null && "USER".equals(subjectType)) {
                return requireMatchingEpoch(
                        subjectResolver.resolveUser(Long.valueOf(subjectId))
                                .orElseThrow(WebStarterJwtCustomizer::subjectUnavailable),
                        storedEpoch);
            }
            if (subjectId != null && "SERVICE_ACCOUNT".equals(subjectType)) {
                return requireMatchingEpoch(
                        subjectResolver.resolveServiceAccount(Long.valueOf(subjectId))
                                .orElseThrow(WebStarterJwtCustomizer::subjectUnavailable),
                        storedEpoch);
            }
        }
        throw subjectUnavailable();
    }

    private java.util.Optional<ResolvedCredentialSubject> resolveLive(CurrentCaller caller) {
        try {
            Long id = Long.valueOf(caller.subjectId());
            return switch (caller.callerType()) {
                case USER -> subjectResolver.resolveUser(id);
                case SERVICE_ACCOUNT -> subjectResolver.resolveServiceAccount(id);
            };
        }
        catch (NumberFormatException exception) {
            return java.util.Optional.empty();
        }
    }

    private static ResolvedCredentialSubject requireMatchingEpoch(
            ResolvedCredentialSubject live,
            Object storedEpoch) {
        long expected = parseStoredEpoch(storedEpoch);
        if (live.securityEpoch() != expected) {
            throw subjectUnavailable();
        }
        return live;
    }

    private static long parseStoredEpoch(Object storedEpoch) {
        if (storedEpoch == null) {
            return 0;
        }
        if (storedEpoch instanceof Number number) {
            return number.longValue();
        }
        if (storedEpoch instanceof String value) {
            try {
                return Long.parseLong(value);
            }
            catch (NumberFormatException ignored) {
                // Converted to the protocol-safe invalid_grant response below.
            }
        }
        throw subjectUnavailable();
    }

    private static OAuth2AuthenticationException subjectUnavailable() {
        return new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_GRANT,
                "The OAuth subject is unavailable",
                null));
    }
}
