package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;

class PublicClientRefreshTokenGeneratorTest {

    @Test
    void generatesAnExpiringRefreshTokenForAPkcePublicClient() {
        Instant now = Instant.parse("2026-07-18T12:00:00Z");
        StringKeyGenerator keys = () -> "opaque-refresh-token";
        var generator = new PublicClientRefreshTokenGenerator(
                keys, Clock.fixed(now, ZoneOffset.UTC));
        var client = RegisteredClient.withId("client-record-id")
                .clientId("public-agent")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1/callback")
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)
                        .build())
                .build();
        var context = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(new TestingAuthenticationToken(
                        new OAuth2ClientAuthenticationToken(
                                client, ClientAuthenticationMethod.NONE, null),
                        null))
                .build();

        var token = generator.generate(context);

        assertThat(token.getTokenValue()).isEqualTo("opaque-refresh-token");
        assertThat(token.getIssuedAt()).isEqualTo(now);
        assertThat(token.getExpiresAt()).isEqualTo(now.plus(Duration.ofHours(8)));
    }

    @Test
    void ignoresOtherTokenTypes() {
        var generator = new PublicClientRefreshTokenGenerator();
        var context = DefaultOAuth2TokenContext.builder()
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        assertThat(generator.generate(context)).isNull();
    }

    @Test
    void leavesRefreshRotationAndConfidentialClientsToTheFrameworkGenerator() {
        var generator = new PublicClientRefreshTokenGenerator();
        var publicClient = RegisteredClient.withId("public-record")
                .clientId("public-agent")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1/callback")
                .build();
        var refreshContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(publicClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(new TestingAuthenticationToken(
                        new OAuth2ClientAuthenticationToken(
                                publicClient, ClientAuthenticationMethod.NONE, null),
                        null))
                .build();

        assertThat(generator.generate(refreshContext)).isNull();
    }
}
