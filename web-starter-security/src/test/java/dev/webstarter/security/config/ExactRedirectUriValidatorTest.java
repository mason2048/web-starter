package dev.webstarter.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

class ExactRedirectUriValidatorTest {

    @Test
    void loopbackRedirectPortMustMatchExactly() {
        RegisteredClient client = RegisteredClient.withId("client-1")
                .clientId("desktop-agent")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:4100/callback")
                .scope("project:list")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        assertThatThrownBy(() -> WebStarterSecurityConfiguration.validateExactRedirectUri(
                context(client, "http://127.0.0.1:9999/callback")))
                .isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
                .hasMessageContaining("redirect_uri")
                .satisfies(error -> assertThat(
                        ((OAuth2AuthorizationCodeRequestAuthenticationException) error)
                                .getAuthorizationCodeRequestAuthentication())
                        .isNull());
        assertThatCode(() -> WebStarterSecurityConfiguration.validateExactRedirectUri(
                context(client, "http://127.0.0.1:4100/callback")))
                .doesNotThrowAnyException();
    }

    private static OAuth2AuthorizationCodeRequestAuthenticationContext context(
            RegisteredClient client,
            String redirectUri) {
        var principal = UsernamePasswordAuthenticationToken.authenticated(
                "operator", "", java.util.List.of());
        var token = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                "https://auth.example/oauth2/authorize",
                client.getClientId(),
                principal,
                redirectUri,
                "state",
                Set.of("project:list"),
                Map.of(
                        PkceParameterNames.CODE_CHALLENGE,
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12",
                        PkceParameterNames.CODE_CHALLENGE_METHOD,
                        "S256"));
        return OAuth2AuthorizationCodeRequestAuthenticationContext.with(token)
                .registeredClient(client)
                .build();
    }
}
