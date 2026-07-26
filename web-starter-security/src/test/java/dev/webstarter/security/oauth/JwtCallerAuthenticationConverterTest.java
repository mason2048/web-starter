package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import dev.webstarter.security.auth.CredentialSubjectResolver;
import dev.webstarter.security.auth.ResolvedCredentialSubject;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;

class JwtCallerAuthenticationConverterTest {

    @Test
    void missingOrDisabledLiveSubjectIsAnAuthenticationFailureNotServerError() {
        CredentialSubjectResolver resolver = mock(CredentialSubjectResolver.class);
        when(resolver.resolveUser(7L)).thenReturn(Optional.empty());
        Jwt jwt = Jwt.withTokenValue("encoded")
                .header("alg", "RS256")
                .subject("operator")
                .claim("uid", "7")
                .claim("subject_type", "USER")
                .claim("scope", "project:list")
                .issuedAt(Instant.now().minusSeconds(1))
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThatThrownBy(() -> new JwtCallerAuthenticationConverter(resolver).convert(jwt))
                .isInstanceOf(InvalidBearerTokenException.class)
                .hasMessageContaining("unavailable");
    }

    @Test
    void rejectsOAuthTokenIssuedForAnOlderIdentityEpoch() {
        CredentialSubjectResolver resolver = mock(CredentialSubjectResolver.class);
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER, "7", "operator", "Operator", null, null,
                java.util.Set.of(), java.util.Set.of("project:list"), java.util.Set.of(), "trace");
        when(resolver.resolveUser(7L))
                .thenReturn(Optional.of(new ResolvedCredentialSubject(caller, 3)));
        Jwt stale = jwtWithEpoch(2);

        assertThatThrownBy(() -> new JwtCallerAuthenticationConverter(resolver).convert(stale))
                .isInstanceOf(InvalidBearerTokenException.class)
                .hasMessageContaining("stale");

        var current = new JwtCallerAuthenticationConverter(resolver).convert(jwtWithEpoch(3));
        assertThat(current.isAuthenticated()).isTrue();
    }

    private static Jwt jwtWithEpoch(long epoch) {
        return Jwt.withTokenValue("encoded")
                .header("alg", "RS256")
                .subject("operator")
                .claim("uid", "7")
                .claim("subject_type", "USER")
                .claim("sepoch", Long.toString(epoch))
                .claim("scope", "project:list")
                .issuedAt(Instant.now().minusSeconds(1))
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }
}
