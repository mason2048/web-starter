package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import dev.webstarter.security.auth.CredentialSubjectResolver;

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
}
