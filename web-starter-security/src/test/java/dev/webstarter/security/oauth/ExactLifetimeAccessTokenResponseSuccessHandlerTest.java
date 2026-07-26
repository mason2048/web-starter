package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

class ExactLifetimeAccessTokenResponseSuccessHandlerTest {

    @Test
    void exposesLifetimeFromSignedTokenInstantsInsteadOfCurrentWallClock() throws Exception {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        var accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "header.payload.signature",
                issuedAt,
                issuedAt.plusSeconds(600),
                Set.of("system:info", "project:list"));
        var registeredClient = RegisteredClient.withId("client-id")
                .clientId("client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("system:info")
                .scope("project:list")
                .build();
        var authentication = new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                new TestingAuthenticationToken("client", "secret"),
                accessToken,
                null,
                Map.of(
                        "trace_id", "trace-123",
                        "expires_in", 1,
                        "refresh_token", "injected"));
        var response = new MockHttpServletResponse();

        new ExactLifetimeAccessTokenResponseSuccessHandler().onAuthenticationSuccess(
                new MockHttpServletRequest(), response, authentication);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getContentAsString())
                .contains("\"access_token\":\"header.payload.signature\"")
                .contains("\"token_type\":\"Bearer\"")
                .contains("\"expires_in\":600")
                .contains("\"trace_id\":\"trace-123\"")
                .doesNotContain("\"expires_in\":1")
                .doesNotContain("injected");
    }
}
