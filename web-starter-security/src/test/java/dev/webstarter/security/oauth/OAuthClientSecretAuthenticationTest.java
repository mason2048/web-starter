package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import dev.webstarter.security.config.WebStarterSecurityProperties;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;

class OAuthClientSecretAuthenticationTest {

    private static final Instant NOW = Instant.parse("2026-07-19T03:00:00Z");
    private static final String ACTIVE_RAW = "active-oauth-secret-for-test";
    private static final String RETIRING_RAW = "retiring-oauth-secret-for-test";

    private OAuthClientMapper mapper;
    private BCryptPasswordEncoder bcrypt;
    private OAuthClientRecord record;

    @BeforeEach
    void setUp() {
        mapper = mock(OAuthClientMapper.class);
        bcrypt = new BCryptPasswordEncoder(4);
        record = new OAuthClientRecord(
                "client-record-id", "agent-client", bcrypt.encode(ACTIVE_RAW), "v2",
                bcrypt.encode(RETIRING_RAW), "v1", NOW.plusSeconds(60), NOW,
                "Agent client", "client_secret_basic", "client_credentials", "",
                "project:list", false, true, 10L, true, NOW.minusSeconds(3600), NOW);
        when(mapper.findByClientId(record.clientId())).thenReturn(record);
    }

    @Test
    void springAuthorizationServerAcceptsBothSecretsInsideOverlap() {
        ClientSecretAuthenticationProvider provider = providerAt(NOW.plusSeconds(30));

        var active = provider.authenticate(authentication(ACTIVE_RAW));
        var retiring = provider.authenticate(authentication(RETIRING_RAW));

        assertThat(active.isAuthenticated()).isTrue();
        assertThat(retiring.isAuthenticated()).isTrue();
        assertThat(active.getPrincipal()).isEqualTo(record.clientId());
        assertThat(record.clientSecretHash()).doesNotContain(ACTIVE_RAW);
        assertThat(record.retiringClientSecretHash()).doesNotContain(RETIRING_RAW);
    }

    @Test
    void springAuthorizationServerRejectsRetiringSecretAtCutoffButKeepsActiveSecret() {
        ClientSecretAuthenticationProvider provider = providerAt(NOW.plusSeconds(60));

        assertThatThrownBy(() -> provider.authenticate(authentication(RETIRING_RAW)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(exception -> assertThat(((OAuth2AuthenticationException) exception)
                        .getError().getErrorCode()).isEqualTo("invalid_client"));
        assertThat(provider.authenticate(authentication(ACTIVE_RAW)).isAuthenticated()).isTrue();
    }

    @Test
    void explicitRevocationRemovesRetiringSecretFromRepositoryEnvelope() {
        OAuthClientRecord revoked = new OAuthClientRecord(
                record.id(), record.clientId(), record.clientSecretHash(), record.clientSecretVersion(),
                null, null, null, record.clientSecretRotatedAt(), record.clientName(),
                record.authenticationMethods(), record.grantTypes(), record.redirectUris(), record.scopes(),
                record.requireConsent(), record.requirePkce(), record.serviceAccountId(), record.enabled(),
                record.createdAt(), NOW.plusSeconds(1));
        when(mapper.findByClientId(record.clientId())).thenReturn(revoked);
        ClientSecretAuthenticationProvider provider = providerAt(NOW.plusSeconds(2));

        assertThatThrownBy(() -> provider.authenticate(authentication(RETIRING_RAW)))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThat(provider.authenticate(authentication(ACTIVE_RAW)).isAuthenticated()).isTrue();
    }

    private ClientSecretAuthenticationProvider providerAt(Instant now) {
        var repository = new DatabaseRegisteredClientRepository(mapper, properties());
        var provider = new ClientSecretAuthenticationProvider(
                repository, mock(OAuth2AuthorizationService.class));
        provider.setPasswordEncoder(new OAuthClientSecretPasswordEncoder(
                bcrypt, Clock.fixed(now, ZoneOffset.UTC)));
        return provider;
    }

    private static OAuth2ClientAuthenticationToken authentication(String rawSecret) {
        return new OAuth2ClientAuthenticationToken(
                "agent-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                rawSecret, Map.of());
    }

    private static WebStarterSecurityProperties properties() {
        return new WebStarterSecurityProperties(
                "0123456789abcdef0123456789abcdef",
                "https://auth.example.internal",
                "https://api.example.internal/mcp",
                true, false, null, null,
                Duration.ofMinutes(10), Duration.ofHours(8));
    }
}
