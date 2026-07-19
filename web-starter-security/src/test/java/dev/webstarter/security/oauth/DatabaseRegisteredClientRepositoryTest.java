package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import dev.webstarter.security.config.WebStarterSecurityProperties;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;

class DatabaseRegisteredClientRepositoryTest {

    @Test
    void mapsPublicAuthorizationCodeClientToPkceAndRefreshToken() {
        OAuthClientMapper mapper = mock(OAuthClientMapper.class);
        OAuthClientRecord record = record(
                "none", "authorization_code refresh_token",
                "https://agent.example/callback", "project:list", null, true);
        when(mapper.findByClientId("agent-client")).thenReturn(record);

        var client = repository(mapper).findByClientId("agent-client");

        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getRedirectUris()).containsExactly("https://agent.example/callback");
        assertThat(client.getScopes()).containsExactly("project:list");
    }

    @Test
    void mapsClientCredentialsToServiceAccountAndHidesDisabledClients() {
        OAuthClientMapper mapper = mock(OAuthClientMapper.class);
        OAuthClientRecord enabled = record(
                "client_secret_basic", "client_credentials", "", "project:list", 10L, true);
        OAuthClientRecord disabled = record(
                "client_secret_basic", "client_credentials", "", "project:list", 10L, false);
        when(mapper.findById("enabled-id")).thenReturn(enabled);
        when(mapper.findById("disabled-id")).thenReturn(disabled);

        var client = repository(mapper).findById("enabled-id");

        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat((Long) client.getClientSettings().getSetting(
                DatabaseRegisteredClientRepository.SERVICE_ACCOUNT_ID_SETTING)).isEqualTo(10L);
        assertThat(repository(mapper).findById("disabled-id")).isNull();
    }

    private static DatabaseRegisteredClientRepository repository(OAuthClientMapper mapper) {
        return new DatabaseRegisteredClientRepository(mapper, new WebStarterSecurityProperties(
                "0123456789abcdef0123456789abcdef",
                "https://auth.example.internal",
                "https://api.example.internal/mcp",
                true,
                false,
                null,
                null,
                Duration.ofMinutes(10),
                Duration.ofHours(8)));
    }

    private static OAuthClientRecord record(
            String methods,
            String grants,
            String redirects,
            String scopes,
            Long serviceAccountId,
            boolean enabled) {
        Instant now = Instant.parse("2026-07-18T10:00:00Z");
        return new OAuthClientRecord(
                enabled ? "enabled-id" : "disabled-id",
                "agent-client",
                methods.contains("none") ? null : "{bcrypt}encoded-secret",
                "Agent client",
                methods,
                grants,
                redirects,
                scopes,
                true,
                true,
                serviceAccountId,
                enabled,
                now,
                now);
    }
}
