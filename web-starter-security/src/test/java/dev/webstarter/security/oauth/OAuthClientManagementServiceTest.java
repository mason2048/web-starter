package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.crypto.password.PasswordEncoder;

import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.token.CredentialScopePolicy;
import dev.webstarter.security.token.ScopeCodec;

class OAuthClientManagementServiceTest {

    private OAuthClientMapper mapper;
    private CredentialScopePolicy scopePolicy;
    private OAuthClientManagementService service;

    @BeforeEach
    void setUp() {
        mapper = mock(OAuthClientMapper.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        scopePolicy = mock(CredentialScopePolicy.class);
        when(encoder.encode(any())).thenReturn("encoded-secret");
        when(scopePolicy.validateOAuthClientScopes(any(), any(), any())).thenAnswer(invocation ->
                ScopeCodec.decode(ScopeCodec.encode(invocation.getArgument(2))));
        service = new OAuthClientManagementService(mapper, encoder, scopePolicy);
    }

    @Test
    void publicClientCannotUseClientCredentials() {
        assertThatThrownBy(() -> create(
                Set.of("none"),
                Set.of("client_credentials"),
                List.of(),
                10L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Public clients");
        verify(mapper, never()).insert(any());
    }

    @Test
    void clientCredentialsCannotBeMixedWithAuthorizationCode() {
        assertThatThrownBy(() -> create(
                Set.of("client_secret_basic"),
                Set.of("authorization_code", "client_credentials"),
                List.of("https://agent.example/callback"),
                10L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot mix grant types");
    }

    @ParameterizedTest
    @MethodSource("unsafeRedirectUris")
    void rejectsUnsafeRedirectUri(String redirectUri) {
        assertThatThrownBy(() -> create(
                Set.of("none"),
                Set.of("authorization_code"),
                List.of(redirectUri),
                null))
                .isInstanceOf(IllegalArgumentException.class);
        verify(mapper, never()).insert(any());
    }

    @Test
    void acceptsHttpsAndLoopbackHttpForPkceClients() {
        assertThat(create(
                Set.of("none"),
                Set.of("authorization_code", "refresh_token"),
                List.of("https://agent.example/callback", "http://127.0.0.1:43123/callback"),
                null).rawSecret()).isNull();
        verify(mapper).insert(any());
    }

    @Test
    void acceptsDedicatedConfidentialServiceClient() {
        assertThat(create(
                Set.of("client_secret_basic"),
                Set.of("client_credentials"),
                List.of(),
                10L).rawSecret()).isNotBlank();
        verify(mapper).insert(any());
    }

    @Test
    void clientCanBeDisabledWithoutChangingItsAuthenticationClass() {
        OAuthClientRecord existing = create(
                Set.of("none"),
                Set.of("authorization_code"),
                List.of("https://agent.example/callback"),
                null).client();
        when(mapper.findById(existing.id())).thenReturn(existing);
        when(mapper.update(any())).thenReturn(1);

        OAuthClientRecord updated = service.update(
                existing.id(),
                "Disabled agent",
                Set.of("none"),
                Set.of("authorization_code"),
                List.of("https://agent.example/callback"),
                Set.of("project:list"),
                true,
                null,
                false);

        assertThat(updated.enabled()).isFalse();
        verify(mapper).update(any());
    }

    private OAuthClientManagementService.CreatedOAuthClient create(
            Set<String> methods,
            Set<String> grants,
            List<String> redirects,
            Long serviceAccountId) {
        return service.create(
                "agent-client",
                "Agent client",
                methods,
                grants,
                redirects,
                Set.of("project:list"),
                true,
                serviceAccountId);
    }

    private static Stream<String> unsafeRedirectUris() {
        return Stream.of(
                "http://agent.example/callback",
                "javascript:alert(1)",
                "https://user:secret@agent.example/callback",
                "https://agent.example/callback#fragment",
                "/relative/callback");
    }
}
