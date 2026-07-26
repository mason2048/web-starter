package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;

import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.mapper.OAuthRefreshTokenFamilyMapper;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenFamilyRecord;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenHistoryRecord;
import dev.webstarter.security.persistence.model.OAuthTokenRegistryRecord;
import dev.webstarter.security.auth.CallerAuthenticationToken;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.security.token.TokenHasher;

class HashingOAuth2AuthorizationServiceTest {

    private static final String PEPPER = "0123456789abcdef0123456789abcdef";
    private static final Instant NOW = Instant.parse("2026-07-18T10:00:00Z");

    @Test
    void delegateReceivesHashesInsteadOfRawOAuthCredentials() {
        Fixture fixture = fixture();
        OAuth2Authorization authorization = authorization(fixture.client());

        fixture.service().save(authorization);

        ArgumentCaptor<OAuth2Authorization> captor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(fixture.delegate()).save(captor.capture());
        OAuth2Authorization stored = captor.getValue();
        assertThat(stored.getAccessToken().getToken().getTokenValue())
                .startsWith("hmac$")
                .doesNotContain("raw-access-token");
        assertThat(stored.getRefreshToken().getToken().getTokenValue())
                .startsWith("hmac$")
                .doesNotContain("raw-refresh-token");
        assertThat(stored.getAccessToken().getClaims().get("aud"))
                .isInstanceOf(ArrayList.class)
                .isEqualTo(List.of("http://resource.example.test/mcp"));
        verify(fixture.registry()).upsert(any());
    }

    @Test
    void subjectSecurityEpochUsesJdbcJacksonSafeStringRepresentation() {
        Fixture fixture = fixture();
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER,
                "7",
                "operator",
                "Operator",
                null,
                "agent-client",
                Set.of("project:list"),
                Set.of("project:list"),
                Set.of(),
                "trace-1");
        CallerAuthenticationToken principal = CallerAuthenticationToken.authenticated(
                caller,
                23L,
                List.of(new SimpleGrantedAuthority("PERM_project:list")));
        OAuth2Authorization authorization = OAuth2Authorization.from(authorization(fixture.client()))
                .attribute(java.security.Principal.class.getName(), principal)
                .build();

        fixture.service().save(authorization);

        ArgumentCaptor<OAuth2Authorization> captor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(fixture.delegate()).save(captor.capture());
        Object storedEpoch = captor.getValue().getAttribute(
                HashingOAuth2AuthorizationService.SUBJECT_SECURITY_EPOCH_ATTRIBUTE);
        assertThat(storedEpoch)
                .isInstanceOf(String.class)
                .isEqualTo("23");
    }

    @Test
    void failedAuthorizationWriteMarksTheWholeSaveForRollback() {
        Fixture fixture = fixture();
        doThrow(new IllegalStateException("database write failed"))
                .when(fixture.delegate()).save(any());
        RecordingTransactionManager transactionManager = new RecordingTransactionManager();
        ProxyFactory proxyFactory = new ProxyFactory(fixture.service());
        proxyFactory.addAdvice(new TransactionInterceptor(
                transactionManager,
                new AnnotationTransactionAttributeSource()));
        OAuth2AuthorizationService transactional = (OAuth2AuthorizationService) proxyFactory.getProxy();

        assertThatThrownBy(() -> transactional.save(authorization(fixture.client())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("database write failed");

        verify(fixture.registry()).upsert(any());
        assertThat(transactionManager.rolledBack).isTrue();
        assertThat(transactionManager.committed).isFalse();
    }

    @Test
    void deliberateRefreshFamilyRevocationCommitsWhileReturningInvalidGrant() {
        OAuth2AuthorizationService delegate = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        OAuthTokenRegistryMapper registry = mock(OAuthTokenRegistryMapper.class);
        OAuthRefreshTokenFamilyMapper familyMapper = mock(OAuthRefreshTokenFamilyMapper.class);
        RegisteredClient client = fixture().client();
        when(clients.findById(client.getId())).thenReturn(client);
        HashingOAuth2AuthorizationService target = new HashingOAuth2AuthorizationService(
                delegate,
                clients,
                registry,
                new OAuthRefreshTokenFamilyService(familyMapper),
                new TokenHasher(PEPPER),
                Clock.fixed(NOW, ZoneOffset.UTC));
        RecordingTransactionManager transactionManager = new RecordingTransactionManager();
        ProxyFactory proxyFactory = new ProxyFactory(target);
        proxyFactory.addAdvice(new TransactionInterceptor(
                transactionManager,
                new AnnotationTransactionAttributeSource()));
        OAuth2AuthorizationService transactional = (OAuth2AuthorizationService) proxyFactory.getProxy();
        OAuth2Authorization rotationWithMissingFamily = OAuth2Authorization.from(authorization(client))
                .attribute(
                        HashingOAuth2AuthorizationService.PRESENTED_REFRESH_HASH_ATTRIBUTE,
                        "a".repeat(64))
                .attribute(
                        HashingOAuth2AuthorizationService.PRESENTED_REFRESH_GENERATION_ATTRIBUTE,
                        0L)
                .refreshToken(new OAuth2RefreshToken(
                        "new-raw-refresh-token",
                        NOW,
                        NOW.plusSeconds(3600)))
                .build();

        assertThatThrownBy(() -> transactional.save(rotationWithMissingFamily))
                .isInstanceOf(RefreshTokenReuseDetectedException.class);

        verify(registry).revokeAuthorization("authorization-1", NOW);
        assertThat(transactionManager.committed).isTrue();
        assertThat(transactionManager.rolledBack).isFalse();
    }

    @Test
    void refreshUsesLatestOnlyPolicySoOldAccessJtiIsRejectedAndNewJtiRemainsActive() {
        OAuth2AuthorizationService delegate = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        RegisteredClient client = fixture().client();
        when(clients.findById(client.getId())).thenReturn(client);
        InMemoryRegistry registry = new InMemoryRegistry();
        TokenHasher hasher = new TokenHasher(PEPPER);
        HashingOAuth2AuthorizationService service = new HashingOAuth2AuthorizationService(
                delegate,
                clients,
                registry,
                familyService(),
                hasher,
                Clock.fixed(NOW, ZoneOffset.UTC));

        service.save(authorization(client, "raw-access-t1", "jti-t1"));
        service.save(authorization(client, "raw-access-t2", "jti-t2"));

        OAuthClientMapper clientMapper = mock(OAuthClientMapper.class);
        when(clientMapper.findByClientId("agent-client")).thenReturn(new dev.webstarter.security.persistence.model.OAuthClientRecord(
                "registered-client-1", "agent-client", null, "Agent", "none",
                "authorization_code", "https://agent.example/callback", "project:list",
                true, true, null, true, NOW, NOW));
        JtiRegistryValidator validator = new JtiRegistryValidator(
                registry, clientMapper, hasher, Clock.fixed(NOW.plusSeconds(1), ZoneOffset.UTC));
        assertThat(validator.validate(jwt("jti-t1")).hasErrors()).isTrue();
        assertThat(validator.validate(jwt("jti-t2")).hasErrors()).isFalse();
    }

    @Test
    void externalTokenThatLooksLikeAnInternalHashMarkerIsStillHashedAgain() {
        Fixture fixture = fixture();
        String submitted = "hmac$" + "a".repeat(64);

        assertThat(fixture.service().findByToken(submitted, OAuth2TokenType.ACCESS_TOKEN))
                .isNull();

        String expectedLookup = "hmac$" + new TokenHasher(PEPPER).hash(submitted);
        verify(fixture.delegate()).findByToken(expectedLookup, OAuth2TokenType.ACCESS_TOKEN);
        verify(fixture.delegate(), never()).findByToken(submitted, OAuth2TokenType.ACCESS_TOKEN);
    }

    @Test
    void accessTokenRevocationPreservesTheStoredRefreshFamilyAndRevokesTheJti() {
        OAuth2AuthorizationService delegate = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        OAuthTokenRegistryMapper registry = mock(OAuthTokenRegistryMapper.class);
        OAuthRefreshTokenFamilyMapper familyMapper = mock(OAuthRefreshTokenFamilyMapper.class);
        RegisteredClient client = fixture().client();
        TokenHasher hasher = new TokenHasher(PEPPER);
        String rawAccess = "access-presented-for-revocation";
        String storedAccess = "hmac$" + hasher.hash(rawAccess);
        String storedRefresh = "hmac$" + hasher.hash("refresh-must-not-be-issued-again");
        OAuth2Authorization stored = authorizationWithRefresh(client, storedAccess, storedRefresh);
        when(clients.findById(client.getId())).thenReturn(client);
        when(delegate.findByToken(storedAccess, null)).thenReturn(stored);
        HashingOAuth2AuthorizationService service = new HashingOAuth2AuthorizationService(
                delegate,
                clients,
                registry,
                new OAuthRefreshTokenFamilyService(familyMapper),
                hasher,
                Clock.fixed(NOW, ZoneOffset.UTC));

        OAuth2Authorization lookedUp = service.findByToken(rawAccess, null);
        OAuth2Authorization.Token<?> matched = lookedUp.getToken(rawAccess);
        OAuth2Authorization revoked = OAuth2Authorization.from(lookedUp)
                .invalidate(matched.getToken())
                .build();

        service.save(revoked);

        verify(familyMapper, never()).insertFamily(any());
        verify(familyMapper, never()).insertHistory(any());
        verify(registry).revokeByJtiHash(hasher.hash("jti-stored"), NOW);
        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(delegate).save(saved.capture());
        assertThat(saved.getValue().getAccessToken().isInvalidated()).isTrue();
        assertThat(saved.getValue().getAccessToken().getToken().getTokenValue())
                .isEqualTo(storedAccess);
        assertThat(saved.getValue().getRefreshToken().getToken().getTokenValue())
                .isEqualTo(storedRefresh);
    }

    @Test
    void newlyIssuedCredentialAndStateMatchingTheStorageShapeAreStillHashed() {
        Fixture fixture = fixture();
        String markerShapedRawValue = "hmac$" + "a".repeat(64);
        OAuth2Authorization authorization = OAuth2Authorization.from(authorization(fixture.client()))
                .attribute(OAuth2ParameterNames.STATE, markerShapedRawValue)
                .refreshToken(new OAuth2RefreshToken(
                        markerShapedRawValue,
                        NOW,
                        NOW.plusSeconds(3600)))
                .build();

        fixture.service().save(authorization);

        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(fixture.delegate()).save(saved.capture());
        String expected = "hmac$" + new TokenHasher(PEPPER).hash(markerShapedRawValue);
        assertThat(saved.getValue().getRefreshToken().getToken().getTokenValue())
                .isEqualTo(expected)
                .isNotEqualTo(markerShapedRawValue);
        String persistedState = saved.getValue().getAttribute(OAuth2ParameterNames.STATE);
        assertThat(persistedState)
                .isEqualTo(expected)
                .isNotEqualTo(markerShapedRawValue);
    }

    @Test
    void refreshRotationUsesFamilyCasAndDoesNotPersistTransientLookupAttributes() {
        OAuth2AuthorizationService delegate = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        OAuthTokenRegistryMapper registry = mock(OAuthTokenRegistryMapper.class);
        OAuthRefreshTokenFamilyMapper familyMapper = mock(OAuthRefreshTokenFamilyMapper.class);
        RegisteredClient client = fixture().client();
        TokenHasher hasher = new TokenHasher(PEPPER);
        String oldRaw = "old-raw-refresh";
        String oldHash = hasher.hash(oldRaw);
        when(clients.findById(client.getId())).thenReturn(client);
        when(familyMapper.findAuthorizationIdByTokenHash(oldHash))
                .thenReturn("authorization-1");
        when(familyMapper.findFamilyForUpdate("authorization-1")).thenReturn(
                new OAuthRefreshTokenFamilyRecord(
                        "authorization-1", oldHash, 0, NOW, NOW.plusSeconds(3600),
                        null, null, NOW, NOW));
        when(familyMapper.findHistoryForUpdate("authorization-1", oldHash)).thenReturn(
                new OAuthRefreshTokenHistoryRecord(
                        oldHash, "authorization-1", 0, NOW, NOW.plusSeconds(3600),
                        null, null, null, NOW));
        when(familyMapper.rotateFamilyCas(
                eq("authorization-1"), eq(oldHash), eq(0L), any(), eq(1L),
                any(), any(), any())).thenReturn(1);
        when(familyMapper.consumeHistoryCas(
                eq("authorization-1"), eq(oldHash), eq(0L), any())).thenReturn(1);
        when(familyMapper.insertHistory(any())).thenReturn(1);
        HashingOAuth2AuthorizationService service = new HashingOAuth2AuthorizationService(
                delegate,
                clients,
                registry,
                new OAuthRefreshTokenFamilyService(familyMapper),
                hasher,
                Clock.fixed(NOW.plusSeconds(10), ZoneOffset.UTC));
        OAuth2Authorization stored = authorizationWithRefresh(
                client, "hmac$stored-access", "hmac$" + oldHash);
        when(delegate.findById("authorization-1")).thenReturn(stored);

        OAuth2Authorization lookedUp = service.findByToken(oldRaw, OAuth2TokenType.REFRESH_TOKEN);
        OAuth2AccessToken nextAccess = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "next-raw-access",
                NOW.plusSeconds(10),
                NOW.plusSeconds(610),
                Set.of("project:list"));
        OAuth2Authorization rotated = OAuth2Authorization.from(lookedUp)
                .token(nextAccess, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of(
                                "jti", "jti-next",
                                "uid", "1",
                                "subject_type", "USER",
                                "client_id", "agent-client")))
                .refreshToken(new OAuth2RefreshToken(
                        "next-raw-refresh",
                        NOW.plusSeconds(10),
                        NOW.plusSeconds(3610)))
                .build();

        service.save(rotated);

        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(delegate).save(saved.capture());
        assertThat(saved.getValue().getAttributes()).doesNotContainKeys(
                HashingOAuth2AuthorizationService.PRESENTED_REFRESH_HASH_ATTRIBUTE,
                HashingOAuth2AuthorizationService.PRESENTED_REFRESH_GENERATION_ATTRIBUTE,
                HashingOAuth2AuthorizationService.STORED_STATE_HASH_ATTRIBUTE,
                HashingOAuth2AuthorizationService.STORED_CODE_HASH_ATTRIBUTE,
                HashingOAuth2AuthorizationService.STORED_ACCESS_HASH_ATTRIBUTE,
                HashingOAuth2AuthorizationService.STORED_REFRESH_HASH_ATTRIBUTE);
        assertThat(saved.getValue().getRefreshToken().getToken().getTokenValue())
                .isEqualTo("hmac$" + hasher.hash("next-raw-refresh"));
        verify(familyMapper).rotateFamilyCas(
                eq("authorization-1"), eq(oldHash), eq(0L),
                eq(hasher.hash("next-raw-refresh")), eq(1L), any(), any(), any());
    }

    @Test
    void replayedOldRefreshTokenRevokesTheWholeAuthorizationBeforeLookupReturns() {
        OAuth2AuthorizationService delegate = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        OAuthTokenRegistryMapper registry = mock(OAuthTokenRegistryMapper.class);
        OAuthRefreshTokenFamilyMapper familyMapper = mock(OAuthRefreshTokenFamilyMapper.class);
        RegisteredClient client = fixture().client();
        TokenHasher hasher = new TokenHasher(PEPPER);
        String replayedRaw = "replayed-refresh";
        String replayedHash = hasher.hash(replayedRaw);
        String currentHash = "b".repeat(64);
        when(clients.findById(client.getId())).thenReturn(client);
        when(familyMapper.findAuthorizationIdByTokenHash(replayedHash))
                .thenReturn("authorization-1");
        when(familyMapper.findFamilyForUpdate("authorization-1")).thenReturn(
                new OAuthRefreshTokenFamilyRecord(
                        "authorization-1", currentHash, 1, NOW, NOW.plusSeconds(3600),
                        null, null, NOW, NOW));
        when(familyMapper.findHistoryForUpdate("authorization-1", replayedHash)).thenReturn(
                new OAuthRefreshTokenHistoryRecord(
                        replayedHash, "authorization-1", 0, NOW.minusSeconds(100),
                        NOW.plusSeconds(3500), NOW.minusSeconds(1), null, null, NOW));
        when(familyMapper.revokeFamily(eq("authorization-1"), any(), any())).thenReturn(1);
        when(familyMapper.revokeHistory(eq("authorization-1"), any(), any())).thenReturn(2);
        OAuth2Authorization stored = authorizationWithRefresh(
                client, "hmac$stored-access", "hmac$" + currentHash);
        when(delegate.findById("authorization-1")).thenReturn(stored);
        HashingOAuth2AuthorizationService service = new HashingOAuth2AuthorizationService(
                delegate,
                clients,
                registry,
                new OAuthRefreshTokenFamilyService(familyMapper),
                hasher,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(service.findByToken(replayedRaw, OAuth2TokenType.REFRESH_TOKEN)).isNull();

        verify(familyMapper).revokeFamily(
                eq("authorization-1"), eq("REFRESH_TOKEN_REUSE"), eq(NOW));
        verify(familyMapper).revokeHistory(
                eq("authorization-1"), eq("REFRESH_TOKEN_REUSE"), eq(NOW));
        verify(registry).revokeAuthorization("authorization-1", NOW);
        verify(delegate).remove(stored);
        verify(delegate, never()).findByToken(any(), eq(OAuth2TokenType.REFRESH_TOKEN));
    }

    private static Fixture fixture() {
        OAuth2AuthorizationService delegate = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        OAuthTokenRegistryMapper registry = mock(OAuthTokenRegistryMapper.class);
        RegisteredClient client = RegisteredClient.withId("registered-client-1")
                .clientId("agent-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://agent.example/callback")
                .scope("project:list")
                .build();
        when(clients.findById(client.getId())).thenReturn(client);
        HashingOAuth2AuthorizationService service = new HashingOAuth2AuthorizationService(
                delegate,
                clients,
                registry,
                familyService(),
                new TokenHasher(PEPPER),
                Clock.fixed(NOW, ZoneOffset.UTC));
        return new Fixture(service, delegate, clients, registry, client);
    }

    private static OAuthRefreshTokenFamilyService familyService() {
        OAuthRefreshTokenFamilyMapper mapper = mock(OAuthRefreshTokenFamilyMapper.class);
        when(mapper.insertFamily(any())).thenReturn(1);
        when(mapper.insertHistory(any())).thenReturn(1);
        return new OAuthRefreshTokenFamilyService(mapper);
    }

    private static OAuth2Authorization authorization(RegisteredClient client) {
        return authorization(client, "raw-access-token", "jti-123");
    }

    private static OAuth2Authorization authorization(
            RegisteredClient client,
            String rawAccessToken,
            String jti) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                rawAccessToken,
                NOW,
                NOW.plusSeconds(600),
                Set.of("project:list"));
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "raw-refresh-token",
                NOW,
                NOW.plusSeconds(3600));
        return OAuth2Authorization.withRegisteredClient(client)
                .id("authorization-1")
                .principalName("operator")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("project:list"))
                .token(accessToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of(
                                "jti", jti,
                                "uid", "1",
                                "subject_type", "USER",
                                "client_id", "agent-client",
                                "aud", List.of("http://resource.example.test/mcp"))))
                .refreshToken(refreshToken)
                .build();
    }

    private static OAuth2Authorization authorizationWithRefresh(
            RegisteredClient client,
            String accessValue,
            String refreshValue) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessValue,
                NOW,
                NOW.plusSeconds(600),
                Set.of("project:list"));
        return OAuth2Authorization.withRegisteredClient(client)
                .id("authorization-1")
                .principalName("operator")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("project:list"))
                .token(accessToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of(
                                "jti", "jti-stored",
                                "uid", "1",
                                "subject_type", "USER",
                                "client_id", "agent-client")))
                .refreshToken(new OAuth2RefreshToken(refreshValue, NOW, NOW.plusSeconds(3600)))
                .build();
    }

    private static org.springframework.security.oauth2.jwt.Jwt jwt(String jti) {
        return org.springframework.security.oauth2.jwt.Jwt.withTokenValue("encoded")
                .header("alg", "RS256")
                .subject("operator")
                .claim("jti", jti)
                .issuedAt(NOW)
                .expiresAt(NOW.plusSeconds(600))
                .build();
    }

    private record Fixture(
            HashingOAuth2AuthorizationService service,
            OAuth2AuthorizationService delegate,
            RegisteredClientRepository clients,
            OAuthTokenRegistryMapper registry,
            RegisteredClient client) {
    }

    private static final class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        private boolean committed;
        private boolean rolledBack;

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            committed = true;
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            rolledBack = true;
        }
    }

    private static final class InMemoryRegistry implements OAuthTokenRegistryMapper {
        private final Map<String, OAuthTokenRegistryRecord> records = new HashMap<>();

        @Override
        public int upsert(OAuthTokenRegistryRecord record) {
            records.put(record.jtiHash(), record);
            return 1;
        }

        @Override
        public OAuthTokenRegistryRecord findByJtiHash(String jtiHash) {
            return records.get(jtiHash);
        }

        @Override
        public int revokeByJtiHash(String jtiHash, Instant revokedAt) {
            OAuthTokenRegistryRecord current = records.get(jtiHash);
            if (current == null) {
                return 0;
            }
            records.put(jtiHash, revoked(current, revokedAt));
            return 1;
        }

        @Override
        public int revokeAuthorization(String authorizationId, Instant revokedAt) {
            int[] updated = {0};
            records.replaceAll((hash, current) -> {
                if (authorizationId.equals(current.authorizationId())) {
                    updated[0]++;
                    return revoked(current, revokedAt);
                }
                return current;
            });
            return updated[0];
        }

        @Override
        public int revokeOtherAccessTokens(
                String authorizationId,
                String currentJtiHash,
                Instant revokedAt) {
            int[] updated = {0};
            records.replaceAll((hash, current) -> {
                if (authorizationId.equals(current.authorizationId())
                        && "ACCESS_TOKEN".equals(current.tokenType())
                        && !currentJtiHash.equals(hash)) {
                    updated[0]++;
                    return revoked(current, revokedAt);
                }
                return current;
            });
            return updated[0];
        }

        @Override
        public int revokeServiceAccountAccessTokens(Long subjectId, Instant revokedAt) {
            int[] updated = {0};
            records.replaceAll((hash, current) -> {
                if ("SERVICE_ACCOUNT".equals(current.subjectType())
                        && subjectId.equals(current.subjectId())
                        && "ACCESS_TOKEN".equals(current.tokenType())) {
                    updated[0]++;
                    return revoked(current, revokedAt);
                }
                return current;
            });
            return updated[0];
        }

        private static OAuthTokenRegistryRecord revoked(
                OAuthTokenRegistryRecord current,
                Instant revokedAt) {
            return new OAuthTokenRegistryRecord(
                    current.id(), current.jtiHash(), current.authorizationId(), current.tokenType(),
                    current.subjectType(), current.subjectId(), current.principalName(), current.clientId(),
                    current.scopes(), current.issuedAt(), current.expiresAt(), revokedAt, current.createdAt());
        }
    }
}
