package dev.webstarter.security.oauth;

import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import dev.webstarter.security.config.WebStarterSecurityProperties;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.token.ScopeCodec;

public final class DatabaseRegisteredClientRepository implements RegisteredClientRepository {

    public static final String SERVICE_ACCOUNT_ID_SETTING = "webstarter.service-account-id";

    private final OAuthClientMapper mapper;
    private final WebStarterSecurityProperties properties;

    public DatabaseRegisteredClientRepository(
            OAuthClientMapper mapper,
            WebStarterSecurityProperties properties) {
        this.mapper = mapper;
        this.properties = properties;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("Use OAuthClientManagementService to save clients");
    }

    @Override
    public RegisteredClient findById(String id) {
        return convert(mapper.findById(id));
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return convert(mapper.findByClientId(clientId));
    }

    private RegisteredClient convert(OAuthClientRecord record) {
        if (record == null || !record.enabled()) {
            return null;
        }
        ClientSettings.Builder clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(record.requireConsent())
                .requireProofKey(record.requirePkce());
        if (record.serviceAccountId() != null) {
            clientSettings.setting(SERVICE_ACCOUNT_ID_SETTING, record.serviceAccountId());
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(record.id())
                .clientId(record.clientId())
                .clientName(record.clientName())
                .clientAuthenticationMethods(methods -> ScopeCodec.decode(record.authenticationMethods())
                        .forEach(value -> methods.add(new ClientAuthenticationMethod(value))))
                .authorizationGrantTypes(grants -> ScopeCodec.decode(record.grantTypes())
                        .forEach(value -> grants.add(new AuthorizationGrantType(value))))
                .redirectUris(uris -> uris.addAll(ScopeCodec.decodeLines(record.redirectUris())))
                .scopes(scopes -> scopes.addAll(ScopeCodec.decode(record.scopes())))
                .clientSettings(clientSettings.build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(properties.accessTokenTtl())
                        .refreshTokenTimeToLive(properties.refreshTokenTtl())
                        .reuseRefreshTokens(false)
                        .build());
        if (record.clientSecretHash() != null && !record.clientSecretHash().isBlank()) {
            builder.clientSecret(record.clientSecretHash());
        }
        return builder.build();
    }
}
