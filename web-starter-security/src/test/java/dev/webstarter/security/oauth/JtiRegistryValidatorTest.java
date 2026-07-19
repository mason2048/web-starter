package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.persistence.model.OAuthTokenRegistryRecord;
import dev.webstarter.security.token.TokenHasher;

class JtiRegistryValidatorTest {

    private static final String PEPPER = "0123456789abcdef0123456789abcdef";

    @Test
    void jwtIsAcceptedOnlyWhenItsHashedJtiIsActiveInRegistry() {
        OAuthTokenRegistryMapper mapper = mock(OAuthTokenRegistryMapper.class);
        OAuthClientMapper clientMapper = mock(OAuthClientMapper.class);
        TokenHasher hasher = new TokenHasher(PEPPER);
        JtiRegistryValidator validator = new JtiRegistryValidator(
                mapper, clientMapper, hasher, Clock.fixed(Instant.now(), ZoneOffset.UTC));
        Jwt jwt = jwt("jti-123");
        when(mapper.findByJtiHash(hasher.hash("jti-123"))).thenReturn(record(null, Instant.now().plusSeconds(60)));
        when(clientMapper.findByClientId("agent-client")).thenReturn(client(true));

        assertThat(validator.validate(jwt).hasErrors()).isFalse();

        when(mapper.findByJtiHash(hasher.hash("jti-123"))).thenReturn(record(Instant.now(), Instant.now().plusSeconds(60)));
        assertThat(validator.validate(jwt).hasErrors()).isTrue();

        when(mapper.findByJtiHash(hasher.hash("jti-123"))).thenReturn(null);
        assertThat(validator.validate(jwt).hasErrors()).isTrue();
    }

    @Test
    void jwtWithoutJtiIsRejected() {
        OAuthTokenRegistryMapper mapper = mock(OAuthTokenRegistryMapper.class);
        JtiRegistryValidator validator = new JtiRegistryValidator(
                mapper, mock(OAuthClientMapper.class), new TokenHasher(PEPPER));
        Jwt jwt = Jwt.withTokenValue("encoded")
                .header("alg", "RS256")
                .subject("user-1")
                .issuedAt(Instant.now().minusSeconds(1))
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThat(validator.validate(jwt).hasErrors()).isTrue();
    }

    @Test
    void disablingOAuthClientImmediatelyInvalidatesItsPreviouslyIssuedJwt() {
        OAuthTokenRegistryMapper mapper = mock(OAuthTokenRegistryMapper.class);
        OAuthClientMapper clientMapper = mock(OAuthClientMapper.class);
        TokenHasher hasher = new TokenHasher(PEPPER);
        Jwt jwt = jwt("jti-123");
        when(mapper.findByJtiHash(hasher.hash("jti-123")))
                .thenReturn(record(null, Instant.now().plusSeconds(60)));
        when(clientMapper.findByClientId("agent-client")).thenReturn(client(false));

        assertThat(new JtiRegistryValidator(mapper, clientMapper, hasher)
                .validate(jwt).hasErrors()).isTrue();
    }

    private static Jwt jwt(String jti) {
        return Jwt.withTokenValue("encoded")
                .headers(headers -> headers.putAll(Map.of("alg", "RS256")))
                .subject("user-1")
                .claim("jti", jti)
                .issuedAt(Instant.now().minusSeconds(1))
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    private static OAuthTokenRegistryRecord record(Instant revokedAt, Instant expiresAt) {
        return new OAuthTokenRegistryRecord(
                1L,
                "hash",
                "authorization-1",
                "ACCESS_TOKEN",
                "USER",
                1L,
                "operator",
                "agent-client",
                "project:list",
                Instant.now().minusSeconds(1),
                expiresAt,
                revokedAt,
                Instant.now().minusSeconds(1));
    }

    private static OAuthClientRecord client(boolean enabled) {
        Instant now = Instant.now();
        return new OAuthClientRecord(
                "client-record", "agent-client", null, "Agent", "none",
                "authorization_code", "https://agent.example/callback", "project:list",
                true, true, null, enabled, now, now);
    }
}
