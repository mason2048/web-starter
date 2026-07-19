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
        CurrentCaller caller = resolveCaller(context);
        context.getClaims()
                .id(UUID.randomUUID().toString())
                // Keep claim metadata on stable public collection types so the strict
                // Jackson 3 validator used by JDBC authorization persistence can read it back.
                .audience(new ArrayList<>(List.of(properties.resourceAudience())))
                .subject(caller.username())
                .claim("uid", caller.subjectId())
                .claim("subject_type", caller.callerType().name())
                .claim("client_id", context.getRegisteredClient().getClientId());
    }

    private CurrentCaller resolveCaller(JwtEncodingContext context) {
        if (context.getPrincipal().getPrincipal() instanceof CallerPrincipal principal) {
            return principal.caller();
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
            if (subjectId != null && "USER".equals(subjectType)) {
                return subjectResolver.resolveUser(Long.valueOf(subjectId))
                        .orElseThrow(WebStarterJwtCustomizer::subjectUnavailable);
            }
            if (subjectId != null && "SERVICE_ACCOUNT".equals(subjectType)) {
                return subjectResolver.resolveServiceAccount(Long.valueOf(subjectId))
                        .orElseThrow(WebStarterJwtCustomizer::subjectUnavailable);
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
