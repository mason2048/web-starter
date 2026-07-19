package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

class PublicClientNoneAuthenticationTest {

    private final PublicClientNoneAuthenticationConverter converter =
            new PublicClientNoneAuthenticationConverter(AuthorizationServerSettings.builder()
                    .issuer("https://issuer.example.test")
                    .build());

    @Test
    void convertsPublicRefreshAndRevocationRequestsOnly() {
        var refresh = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", "public-agent"));
        var refreshAuthentication = (OAuth2ClientAuthenticationToken) converter.convert(refresh);

        assertThat(refreshAuthentication.getPrincipal()).isEqualTo("public-agent");
        assertThat(refreshAuthentication.getClientAuthenticationMethod())
                .isEqualTo(ClientAuthenticationMethod.NONE);
        assertThat(refreshAuthentication.getAdditionalParameters())
                .containsEntry(PublicClientNoneAuthenticationConverter.REQUEST_KIND,
                        PublicClientNoneAuthenticationConverter.REFRESH_REQUEST)
                .doesNotContainKeys("refresh_token");

        var revocation = post("/oauth2/revoke", Map.of(
                "token", "access-value",
                "client_id", "public-agent"));
        var revocationAuthentication = (OAuth2ClientAuthenticationToken) converter.convert(revocation);
        assertThat(revocationAuthentication.getAdditionalParameters())
                .containsEntry(PublicClientNoneAuthenticationConverter.REQUEST_KIND,
                        PublicClientNoneAuthenticationConverter.REVOCATION_REQUEST);

        assertThat(converter.convert(post("/oauth2/token", Map.of(
                "grant_type", "client_credentials",
                "client_id", "machine-agent")))).isNull();
        assertThat(converter.convert(post("/oauth2/introspect", Map.of(
                "token", "access-value",
                "client_id", "public-agent")))).isNull();
    }

    @Test
    void leavesSecretAuthenticatedRequestsToBuiltInConverters() {
        var secretPost = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", "confidential-agent",
                "client_secret", "secret"));
        assertThat(converter.convert(secretPost)).isNull();

        var basic = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", "confidential-agent"));
        basic.addHeader(HttpHeaders.AUTHORIZATION, "Basic Zm9vOmJhcg==");
        assertThat(converter.convert(basic)).isNull();

        var assertion = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", "assertion-agent",
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion", "signed-assertion"));
        assertThat(converter.convert(assertion)).isNull();
    }

    @Test
    void rejectsMissingOrRepeatedPublicParameters() {
        var missingClient = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value"));
        assertInvalidRequest(missingClient);

        var repeatedClient = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", "public-agent"));
        repeatedClient.addParameter("client_id", "another-agent");
        assertInvalidRequest(repeatedClient);
    }

    @Test
    void authenticatesEnabledPkcePublicRefreshClient() {
        RegisteredClient publicClient = publicClient(true, true);
        var provider = new PublicClientNoneAuthenticationProvider(repository(publicClient));
        var converted = converter.convert(post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", publicClient.getClientId())));

        var authenticated = (OAuth2ClientAuthenticationToken) provider.authenticate(converted);

        assertThat(authenticated.isAuthenticated()).isTrue();
        assertThat(authenticated.getRegisteredClient()).isEqualTo(publicClient);
        assertThat(authenticated.getClientAuthenticationMethod())
                .isEqualTo(ClientAuthenticationMethod.NONE);
    }

    @Test
    void publicClientIdAndTokenFlowRevokesWithoutAClientSecret() {
        RegisteredClient publicClient = publicClient(true, true);
        var request = post("/oauth2/revoke", Map.of(
                "token", "access-value",
                "token_type_hint", "access_token",
                "client_id", publicClient.getClientId()));
        assertThat(request.getParameter("client_secret")).isNull();
        assertThat(request.getHeader(HttpHeaders.AUTHORIZATION)).isNull();

        var converted = converter.convert(request);
        var authenticatedClient = new PublicClientNoneAuthenticationProvider(repository(publicClient))
                .authenticate(converted);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-value",
                Instant.parse("2026-07-18T10:00:00Z"),
                Instant.parse("2026-07-18T10:10:00Z"),
                Set.of("project:list"));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(publicClient)
                .id("authorization-1")
                .principalName("operator")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("project:list"))
                .accessToken(accessToken)
                .build();
        OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
        when(authorizationService.findByToken("access-value", null)).thenReturn(authorization);
        var revocation = new OAuth2TokenRevocationAuthenticationToken(
                "access-value", authenticatedClient, "access_token");

        var result = new OAuth2TokenRevocationAuthenticationProvider(authorizationService)
                .authenticate(revocation);

        assertThat(result.isAuthenticated()).isTrue();
        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(saved.capture());
        assertThat(saved.getValue().getAccessToken().isInvalidated()).isTrue();
        verify(authorizationService).findByToken("access-value", null);
    }

    @Test
    void refusesUnknownNonPkceOrRefreshDisabledClients() {
        assertInvalidClient(new PublicClientNoneAuthenticationProvider(repository(null)), "missing-agent");
        assertInvalidClient(new PublicClientNoneAuthenticationProvider(repository(publicClient(false, true))),
                "public-agent");
        assertInvalidClient(new PublicClientNoneAuthenticationProvider(repository(publicClient(true, false))),
                "public-agent");
    }

    private void assertInvalidClient(PublicClientNoneAuthenticationProvider provider, String clientId) {
        var request = post("/oauth2/token", Map.of(
                "grant_type", "refresh_token",
                "refresh_token", "refresh-value",
                "client_id", clientId));
        assertThatThrownBy(() -> provider.authenticate(converter.convert(request)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    private void assertInvalidRequest(MockHttpServletRequest request) {
        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    private static RegisteredClient publicClient(boolean requirePkce, boolean allowRefresh) {
        var builder = RegisteredClient.withId("public-client-record")
                .clientId("public-agent")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1/callback")
                .clientSettings(ClientSettings.builder().requireProofKey(requirePkce).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build());
        if (allowRefresh) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        return builder.build();
    }

    private static RegisteredClientRepository repository(RegisteredClient client) {
        return new RegisteredClientRepository() {
            @Override
            public void save(RegisteredClient registeredClient) {
                throw new UnsupportedOperationException();
            }

            @Override
            public RegisteredClient findById(String id) {
                return client != null && client.getId().equals(id) ? client : null;
            }

            @Override
            public RegisteredClient findByClientId(String clientId) {
                return client != null && client.getClientId().equals(clientId) ? client : null;
            }
        };
    }

    private static MockHttpServletRequest post(String path, Map<String, String> parameters) {
        var request = new MockHttpServletRequest("POST", path);
        request.setContentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        parameters.forEach(request::addParameter);
        return request;
    }
}
