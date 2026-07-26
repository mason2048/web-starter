package dev.webstarter.security.oauth;

import java.security.Principal;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.model.OAuthTokenRegistryRecord;
import dev.webstarter.security.token.ScopeCodec;
import dev.webstarter.security.token.TokenHasher;

/**
 * Persists OAuth protocol credentials as HMAC-SHA-256 values. The delegate may use the
 * standard JDBC schema, but never receives an authorization code, access token, refresh
 * token, or state in plaintext. A token supplied for lookup is reattached only to the
 * returned in-memory aggregate for the duration of that request.
 */
public class HashingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Log LOGGER = LogFactory.getLog(HashingOAuth2AuthorizationService.class);
    private static final String HASH_MARKER = "hmac$";
    public static final String SUBJECT_ID_ATTRIBUTE = "webstarter.subject-id";
    public static final String SUBJECT_TYPE_ATTRIBUTE = "webstarter.subject-type";
    public static final String SUBJECT_SECURITY_EPOCH_ATTRIBUTE = "webstarter.subject-security-epoch";
    static final String PRESENTED_REFRESH_HASH_ATTRIBUTE =
            "webstarter.transient-presented-refresh-hash";
    static final String PRESENTED_REFRESH_GENERATION_ATTRIBUTE =
            "webstarter.transient-presented-refresh-generation";
    static final String STORED_STATE_HASH_ATTRIBUTE =
            "webstarter.transient-stored-state-hash";
    static final String STORED_CODE_HASH_ATTRIBUTE =
            "webstarter.transient-stored-code-hash";
    static final String STORED_ACCESS_HASH_ATTRIBUTE =
            "webstarter.transient-stored-access-hash";
    static final String STORED_REFRESH_HASH_ATTRIBUTE =
            "webstarter.transient-stored-refresh-hash";

    private final OAuth2AuthorizationService delegate;
    private final RegisteredClientRepository clients;
    private final OAuthTokenRegistryMapper tokenRegistry;
    private final OAuthRefreshTokenFamilyService refreshTokenFamilies;
    private final TokenHasher tokenHasher;
    private final Clock clock;

    public HashingOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            RegisteredClientRepository clients,
            OAuthTokenRegistryMapper tokenRegistry,
            OAuthRefreshTokenFamilyService refreshTokenFamilies,
            TokenHasher tokenHasher) {
        this(delegate, clients, tokenRegistry, refreshTokenFamilies, tokenHasher, Clock.systemUTC());
    }

    HashingOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            RegisteredClientRepository clients,
            OAuthTokenRegistryMapper tokenRegistry,
            OAuthRefreshTokenFamilyService refreshTokenFamilies,
            TokenHasher tokenHasher,
            Clock clock) {
        this.delegate = delegate;
        this.clients = clients;
        this.tokenRegistry = tokenRegistry;
        this.refreshTokenFamilies = refreshTokenFamilies;
        this.tokenHasher = tokenHasher;
        this.clock = clock;
    }

    @Override
    @Transactional(noRollbackFor = RefreshTokenReuseDetectedException.class)
    public void save(OAuth2Authorization authorization) {
        persistRefreshTokenFamily(authorization);
        registerAccessToken(authorization);
        delegate.save(copyWithHashedCredentials(authorization));
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        refreshTokenFamilies.revoke(
                authorization.getId(), "AUTHORIZATION_REMOVED", clock.instant());
        tokenRegistry.revokeAuthorization(authorization.getId(), clock.instant());
        delegate.remove(copyWithHashedCredentials(authorization));
    }

    @Override
    public OAuth2Authorization findById(String id) {
        OAuth2Authorization stored = delegate.findById(id);
        return stored == null ? null : copyStoredAuthorizationWithSnapshots(stored);
    }

    @Override
    @Transactional
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null) {
            return null;
        }
        OAuthRefreshTokenLookup refreshLookup = null;
        if (tokenType == null || OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            refreshLookup = refreshTokenFamilies.lookupForUpdate(tokenHasher.hash(token), clock.instant());
            if (refreshLookup.status() != OAuthRefreshTokenStatus.UNKNOWN) {
                if (refreshLookup.status() == OAuthRefreshTokenStatus.REPLAY) {
                    revokeAuthorizationFamily(
                            refreshLookup.authorizationId(), "REFRESH_TOKEN_REUSE");
                    LOGGER.warn("Revoked an OAuth authorization after refresh-token reuse detection");
                    return null;
                }
                if (refreshLookup.status() != OAuthRefreshTokenStatus.CURRENT) {
                    return null;
                }
            }
            else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
                return null;
            }
        }

        String lookupHash = hashExternalToken(token);
        if (refreshLookup != null
                && refreshLookup.status() == OAuthRefreshTokenStatus.CURRENT) {
            OAuth2Authorization stored = delegate.findById(refreshLookup.authorizationId());
            if (stored == null
                    || stored.getRefreshToken() == null
                    || !lookupHash.equals(
                            stored.getRefreshToken().getToken().getTokenValue())) {
                revokeAuthorizationFamily(
                        refreshLookup.authorizationId(), "REFRESH_TOKEN_ORPHANED");
                return null;
            }
            return copyReplacingLookupToken(
                    stored,
                    token,
                    OAuth2TokenType.REFRESH_TOKEN,
                    refreshLookup);
        }

        OAuth2Authorization stored = delegate.findByToken(lookupHash, tokenType);
        if (stored == null) {
            return null;
        }
        OAuth2TokenType resolvedType = inferTokenType(stored, tokenType, lookupHash);
        return copyReplacingLookupToken(stored, token, resolvedType, refreshLookup);
    }

    private OAuth2Authorization copyWithHashedCredentials(OAuth2Authorization source) {
        OAuth2Authorization.Builder builder = baseBuilder(source);
        source.getAttributes().forEach((name, value) -> {
            if (isTransientRefreshAttribute(name)) {
                return;
            }
            if (OAuth2ParameterNames.STATE.equals(name) && value instanceof String state) {
                builder.attribute(name, hashCredentialForPersistence(
                        state, source.getAttribute(STORED_STATE_HASH_ATTRIBUTE)));
            }
            else if (Principal.class.getName().equals(name) && value instanceof Authentication principal) {
                builder.attribute(name, UsernamePasswordAuthenticationToken.authenticated(
                        principal.getName(), "", principal.getAuthorities()));
                if (principal.getPrincipal() instanceof dev.webstarter.security.auth.CallerPrincipal caller) {
                    builder.attribute(SUBJECT_ID_ATTRIBUTE, caller.caller().subjectId());
                    builder.attribute(SUBJECT_TYPE_ATTRIBUTE, caller.caller().callerType().name());
                    // JdbcOAuth2AuthorizationService stores attributes as Object-valued
                    // polymorphic JSON. Spring Security's strict Jackson 3 validator
                    // intentionally rejects a java.lang.Long type id on read-back.
                    // A decimal string is stable across Jackson implementations and is
                    // parsed explicitly by the token customizer.
                    builder.attribute(
                            SUBJECT_SECURITY_EPOCH_ATTRIBUTE,
                            Long.toString(caller.securityEpoch()));
                }
            }
            else {
                builder.attribute(name, normalizeForPersistence(value));
            }
        });
        copyTokens(source, builder, null, null, false);
        return builder.build();
    }

    private OAuth2Authorization copyReplacingLookupToken(
            OAuth2Authorization stored,
            String rawToken,
            OAuth2TokenType tokenType,
            OAuthRefreshTokenLookup refreshLookup) {
        OAuth2Authorization.Builder builder = baseBuilder(stored);
        stored.getAttributes().forEach((name, value) -> {
            if (OAuth2ParameterNames.STATE.equals(name)
                    && OAuth2ParameterNames.STATE.equals(tokenType == null ? null : tokenType.getValue())) {
                builder.attribute(name, rawToken);
            }
            else {
                builder.attribute(name, value);
            }
        });
        attachCredentialSnapshots(stored, builder);
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)
                && refreshLookup != null
                && refreshLookup.status() == OAuthRefreshTokenStatus.CURRENT) {
            builder.attribute(PRESENTED_REFRESH_HASH_ATTRIBUTE, tokenHasher.hash(rawToken));
            builder.attribute(
                    PRESENTED_REFRESH_GENERATION_ATTRIBUTE,
                    refreshLookup.presentedGeneration());
        }
        copyTokens(stored, builder, rawToken, tokenType, true);
        return builder.build();
    }

    private OAuth2Authorization copyStoredAuthorizationWithSnapshots(
            OAuth2Authorization stored) {
        OAuth2Authorization.Builder builder = baseBuilder(stored);
        stored.getAttributes().forEach(builder::attribute);
        attachCredentialSnapshots(stored, builder);
        copyTokens(stored, builder, null, null, true);
        return builder.build();
    }

    private OAuth2Authorization.Builder baseBuilder(OAuth2Authorization source) {
        var registeredClient = clients.findById(source.getRegisteredClientId());
        if (registeredClient == null) {
            throw new IllegalStateException("OAuth client no longer exists: " + source.getRegisteredClientId());
        }
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(source.getId())
                .principalName(source.getPrincipalName())
                .authorizationGrantType(source.getAuthorizationGrantType())
                .authorizedScopes(source.getAuthorizedScopes());
    }

    private void copyTokens(
            OAuth2Authorization source,
            OAuth2Authorization.Builder builder,
            String rawLookupToken,
            OAuth2TokenType lookupType,
            boolean sourceCameFromStorage) {
        var code = source.getToken(OAuth2AuthorizationCode.class);
        if (code != null) {
            String value = isType(lookupType, OAuth2ParameterNames.CODE)
                    ? rawLookupToken : credentialValue(
                            code.getToken().getTokenValue(),
                            source.getAttribute(STORED_CODE_HASH_ATTRIBUTE),
                            sourceCameFromStorage);
            OAuth2AuthorizationCode replacement = new OAuth2AuthorizationCode(
                    value, code.getToken().getIssuedAt(), code.getToken().getExpiresAt());
            builder.token(replacement, metadata -> metadata.putAll(normalizeMap(code.getMetadata())));
        }
        var access = source.getAccessToken();
        if (access != null) {
            String value = OAuth2TokenType.ACCESS_TOKEN.equals(lookupType)
                    ? rawLookupToken : credentialValue(
                            access.getToken().getTokenValue(),
                            source.getAttribute(STORED_ACCESS_HASH_ATTRIBUTE),
                            sourceCameFromStorage);
            OAuth2AccessToken token = access.getToken();
            OAuth2AccessToken replacement = new OAuth2AccessToken(
                    token.getTokenType(), value, token.getIssuedAt(), token.getExpiresAt(), token.getScopes());
            builder.token(replacement, metadata -> metadata.putAll(normalizeMap(access.getMetadata())));
        }
        var refresh = source.getRefreshToken();
        if (refresh != null) {
            String value = OAuth2TokenType.REFRESH_TOKEN.equals(lookupType)
                    ? rawLookupToken : credentialValue(
                            refresh.getToken().getTokenValue(),
                            source.getAttribute(STORED_REFRESH_HASH_ATTRIBUTE),
                            sourceCameFromStorage);
            OAuth2RefreshToken token = refresh.getToken();
            OAuth2RefreshToken replacement = new OAuth2RefreshToken(
                    value, token.getIssuedAt(), token.getExpiresAt());
            builder.token(replacement, metadata -> metadata.putAll(normalizeMap(refresh.getMetadata())));
        }
    }

    private static void attachCredentialSnapshots(
            OAuth2Authorization stored,
            OAuth2Authorization.Builder builder) {
        Object state = stored.getAttribute(OAuth2ParameterNames.STATE);
        if (state instanceof String stateHash) {
            builder.attribute(STORED_STATE_HASH_ATTRIBUTE, stateHash);
        }
        var code = stored.getToken(OAuth2AuthorizationCode.class);
        if (code != null) {
            builder.attribute(STORED_CODE_HASH_ATTRIBUTE, code.getToken().getTokenValue());
        }
        var access = stored.getAccessToken();
        if (access != null) {
            builder.attribute(STORED_ACCESS_HASH_ATTRIBUTE, access.getToken().getTokenValue());
        }
        var refresh = stored.getRefreshToken();
        if (refresh != null) {
            builder.attribute(STORED_REFRESH_HASH_ATTRIBUTE, refresh.getToken().getTokenValue());
        }
    }

    private void persistRefreshTokenFamily(OAuth2Authorization authorization) {
        var refresh = authorization.getRefreshToken();
        if (refresh == null) {
            return;
        }
        String rawOrStoredValue = refresh.getToken().getTokenValue();
        Instant now = clock.instant();
        if (refresh.isInvalidated()) {
            refreshTokenFamilies.revoke(
                    authorization.getId(), "REFRESH_TOKEN_REVOKED", now);
            tokenRegistry.revokeAuthorization(authorization.getId(), now);
            return;
        }
        if (isStoredCredential(
                authorization, STORED_REFRESH_HASH_ATTRIBUTE, rawOrStoredValue)) {
            return;
        }

        String newHash = tokenHasher.hash(rawOrStoredValue);
        String presentedHash = authorization.getAttribute(PRESENTED_REFRESH_HASH_ATTRIBUTE);
        Number presentedGeneration = authorization.getAttribute(
                PRESENTED_REFRESH_GENERATION_ATTRIBUTE);
        if (presentedHash == null && presentedGeneration == null) {
            refreshTokenFamilies.issue(
                    authorization.getId(),
                    newHash,
                    refresh.getToken().getIssuedAt(),
                    refresh.getToken().getExpiresAt(),
                    now);
            return;
        }
        if (presentedHash == null || presentedGeneration == null) {
            revokeAndRejectRotation(authorization.getId(), "REFRESH_TOKEN_STATE_INVALID");
        }

        OAuthRefreshTokenRotationResult result = refreshTokenFamilies.rotate(
                authorization.getId(),
                presentedHash,
                presentedGeneration.longValue(),
                newHash,
                refresh.getToken().getIssuedAt(),
                refresh.getToken().getExpiresAt(),
                now);
        if (result != OAuthRefreshTokenRotationResult.ROTATED) {
            String reason = result == OAuthRefreshTokenRotationResult.REPLAY
                    || result == OAuthRefreshTokenRotationResult.CONFLICT
                    ? "REFRESH_TOKEN_REUSE" : "REFRESH_TOKEN_STATE_INVALID";
            revokeAndRejectRotation(authorization.getId(), reason);
        }
    }

    private void revokeAndRejectRotation(String authorizationId, String reason) {
        revokeAuthorizationFamily(authorizationId, reason);
        LOGGER.warn("Rejected OAuth refresh-token rotation and revoked its authorization family");
        throw new RefreshTokenReuseDetectedException();
    }

    private void revokeAuthorizationFamily(String authorizationId, String reason) {
        Instant now = clock.instant();
        refreshTokenFamilies.revoke(authorizationId, reason, now);
        tokenRegistry.revokeAuthorization(authorizationId, now);
        OAuth2Authorization stored = delegate.findById(authorizationId);
        if (stored != null) {
            delegate.remove(stored);
        }
    }

    private static Map<String, Object> normalizeMap(Map<String, Object> source) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        source.forEach((name, value) -> normalized.put(name, normalizeForPersistence(value)));
        return normalized;
    }

    private static Object normalizeForPersistence(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> normalized = new LinkedHashMap<>();
            map.forEach((key, nestedValue) ->
                    normalized.put(key, normalizeForPersistence(nestedValue)));
            return normalized;
        }
        if (value instanceof Collection<?> collection) {
            ArrayList<Object> normalized = new ArrayList<>(collection.size());
            collection.forEach(item -> normalized.add(normalizeForPersistence(item)));
            return normalized;
        }
        return value;
    }

    private void registerAccessToken(OAuth2Authorization authorization) {
        var access = authorization.getAccessToken();
        if (access == null) {
            return;
        }
        Map<String, Object> claims = new HashMap<>(access.getClaims());
        Object jtiValue = claims.get("jti");
        if (jtiValue == null) {
            throw new IllegalStateException("Issued OAuth access token is missing jti");
        }
        String jtiHash = tokenHasher.hash(jtiValue.toString());
        Instant now = clock.instant();
        String subjectId = stringClaim(claims, "uid");
        OAuthTokenRegistryRecord record = new OAuthTokenRegistryRecord(
                IdWorker.getId(),
                jtiHash,
                authorization.getId(),
                "ACCESS_TOKEN",
                stringClaim(claims, "subject_type"),
                subjectId == null ? null : Long.valueOf(subjectId),
                authorization.getPrincipalName(),
                stringClaim(claims, "client_id"),
                ScopeCodec.encode(access.getToken().getScopes()),
                access.getToken().getIssuedAt(),
                access.getToken().getExpiresAt(),
                access.isInvalidated() ? now : null,
                now);
        tokenRegistry.upsert(record);
        // Latest-only access-token policy: refreshing an authorization atomically
        // revokes every older JTI while the newly issued token remains active.
        tokenRegistry.revokeOtherAccessTokens(authorization.getId(), jtiHash, now);
        if (access.isInvalidated()) {
            tokenRegistry.revokeByJtiHash(jtiHash, now);
        }
    }

    private String credentialValue(
            String value,
            Object storedSnapshot,
            boolean sourceCameFromStorage) {
        // JDBC already contains the HMAC value. A lookup may replace exactly one
        // credential with the raw value supplied by the caller, while every other
        // credential must remain byte-for-byte identical to storage. Re-hashing a
        // non-looked-up stored refresh token makes a subsequent access-token
        // revocation look like a newly issued refresh token and attempts to insert
        // the same family twice.
        if (sourceCameFromStorage) {
            return value;
        }
        return hashCredentialForPersistence(value, storedSnapshot);
    }

    private String hashCredentialForPersistence(String value, Object storedSnapshot) {
        if (value == null || value.equals(storedSnapshot)) {
            return value;
        }
        return HASH_MARKER + tokenHasher.hash(value);
    }

    private String hashExternalToken(String value) {
        return value == null ? null : HASH_MARKER + tokenHasher.hash(value);
    }

    private static boolean isTransientRefreshAttribute(String name) {
        return PRESENTED_REFRESH_HASH_ATTRIBUTE.equals(name)
                || PRESENTED_REFRESH_GENERATION_ATTRIBUTE.equals(name)
                || STORED_STATE_HASH_ATTRIBUTE.equals(name)
                || STORED_CODE_HASH_ATTRIBUTE.equals(name)
                || STORED_ACCESS_HASH_ATTRIBUTE.equals(name)
                || STORED_REFRESH_HASH_ATTRIBUTE.equals(name);
    }

    private static boolean isStoredCredential(
            OAuth2Authorization authorization,
            String snapshotAttribute,
            String credentialValue) {
        return credentialValue.equals(authorization.getAttribute(snapshotAttribute));
    }

    private static boolean isType(OAuth2TokenType type, String value) {
        return type != null && value.equals(type.getValue());
    }

    private static OAuth2TokenType inferTokenType(
            OAuth2Authorization authorization,
            OAuth2TokenType requested,
            String hashedValue) {
        if (requested != null) {
            return requested;
        }
        if (authorization.getToken(OAuth2AuthorizationCode.class) != null
                && hashedValue.equals(authorization.getToken(OAuth2AuthorizationCode.class)
                        .getToken().getTokenValue())) {
            return new OAuth2TokenType(OAuth2ParameterNames.CODE);
        }
        if (authorization.getAccessToken() != null
                && hashedValue.equals(authorization.getAccessToken().getToken().getTokenValue())) {
            return OAuth2TokenType.ACCESS_TOKEN;
        }
        if (authorization.getRefreshToken() != null
                && hashedValue.equals(authorization.getRefreshToken().getToken().getTokenValue())) {
            return OAuth2TokenType.REFRESH_TOKEN;
        }
        if (hashedValue.equals(authorization.getAttribute(OAuth2ParameterNames.STATE))) {
            return new OAuth2TokenType(OAuth2ParameterNames.STATE);
        }
        return requested;
    }

    private static String stringClaim(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        return value == null ? null : value.toString();
    }
}
