package dev.webstarter.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;

class AuthorizationServerMetadataPolicyTest {

    @Test
    void advertisesOnlyClientAndGrantTypesThatCanBeManagedByTheStarter() {
        var builder = OAuth2AuthorizationServerMetadata.builder()
                .issuer("https://starter.example.test")
                .authorizationEndpoint("https://starter.example.test/oauth2/authorize")
                .tokenEndpoint("https://starter.example.test/oauth2/token")
                .jwkSetUrl("https://starter.example.test/oauth2/jwks")
                .tokenRevocationEndpoint("https://starter.example.test/oauth2/revoke")
                .tokenIntrospectionEndpoint("https://starter.example.test/oauth2/introspect");

        WebStarterSecurityConfiguration.customizeAuthorizationServerMetadata(builder);
        var metadata = builder.build();

        assertThat(metadata.getTokenEndpointAuthenticationMethods())
                .containsExactlyInAnyOrder("none", "client_secret_basic", "client_secret_post");
        assertThat(metadata.getGrantTypes())
                .containsExactlyInAnyOrder("authorization_code", "refresh_token", "client_credentials");
        assertThat(metadata.getResponseTypes()).containsExactly("code");
        assertThat(metadata.getCodeChallengeMethods()).containsExactly("S256");
        assertThat(metadata.getTokenRevocationEndpointAuthenticationMethods())
                .containsExactlyInAnyOrder("none", "client_secret_basic", "client_secret_post");
        assertThat(metadata.getTokenIntrospectionEndpointAuthenticationMethods())
                .containsExactlyInAnyOrder("client_secret_basic", "client_secret_post");
        assertThat(metadata.isTlsClientCertificateBoundAccessTokens()).isFalse();
        assertThat(metadata.getDPoPSigningAlgorithms()).isNullOrEmpty();
    }
}
