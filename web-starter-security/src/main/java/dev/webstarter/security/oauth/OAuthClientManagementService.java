package dev.webstarter.security.oauth;

import java.security.SecureRandom;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.security.config.WebStarterSecurityProperties;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.token.CredentialScopePolicy;
import dev.webstarter.security.token.IpRestriction;
import dev.webstarter.security.token.ScopeCodec;

public class OAuthClientManagementService {

    private static final Set<String> SUPPORTED_GRANTS = Set.of(
            "authorization_code", "refresh_token", "client_credentials");
    private static final Set<String> SUPPORTED_AUTH_METHODS = Set.of(
            "client_secret_basic", "client_secret_post", "none");

    private final OAuthClientMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final CredentialScopePolicy scopePolicy;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final Duration defaultSecretOverlap;
    private final Duration maximumSecretOverlap;

    public OAuthClientManagementService(
            OAuthClientMapper mapper,
            PasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy) {
        this(mapper, passwordEncoder, scopePolicy, new SecureRandom(), Clock.systemUTC(),
                Duration.ofMinutes(15), Duration.ofHours(24));
    }

    public OAuthClientManagementService(
            OAuthClientMapper mapper,
            PasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy,
            WebStarterSecurityProperties properties) {
        this(mapper, passwordEncoder, scopePolicy, new SecureRandom(), Clock.systemUTC(),
                properties.oauthClientSecretOverlap(), properties.oauthClientSecretMaxOverlap());
    }

    OAuthClientManagementService(
            OAuthClientMapper mapper,
            PasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy,
            SecureRandom secureRandom,
            Clock clock) {
        this(mapper, passwordEncoder, scopePolicy, secureRandom, clock,
                Duration.ofMinutes(15), Duration.ofHours(24));
    }

    OAuthClientManagementService(
            OAuthClientMapper mapper,
            PasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy,
            SecureRandom secureRandom,
            Clock clock,
            Duration defaultSecretOverlap,
            Duration maximumSecretOverlap) {
        this.mapper = mapper;
        this.passwordEncoder = passwordEncoder;
        this.scopePolicy = scopePolicy;
        this.secureRandom = secureRandom;
        this.clock = clock;
        this.defaultSecretOverlap = defaultSecretOverlap;
        this.maximumSecretOverlap = maximumSecretOverlap;
    }

    public CreatedOAuthClient create(
            String clientId,
            String clientName,
            Collection<String> authenticationMethods,
            Collection<String> grantTypes,
            Collection<String> redirectUris,
            Collection<String> scopes,
            boolean requireConsent,
            Long serviceAccountId) {
        Set<String> validatedScopes = validate(
                clientId, clientName, authenticationMethods, grantTypes, redirectUris, scopes, serviceAccountId);
        if (mapper.findByClientId(clientId) != null) {
            throw new IllegalArgumentException("OAuth client id already exists");
        }
        Set<String> methods = ScopeCodec.decode(ScopeCodec.encode(authenticationMethods));
        String rawSecret = methods.contains("none") ? null : newSecret();
        Instant now = clock.instant();
        OAuthClientRecord record = new OAuthClientRecord(
                UUID.randomUUID().toString(), clientId,
                rawSecret == null ? null : passwordEncoder.encode(rawSecret),
                rawSecret == null ? null : newSecretVersion(),
                null, null, null, null,
                clientName, ScopeCodec.encode(methods), ScopeCodec.encode(grantTypes),
                ScopeCodec.encodeLines(redirectUris), ScopeCodec.encode(validatedScopes), requireConsent,
                true, serviceAccountId, true, now, now);
        mapper.insert(record);
        return new CreatedOAuthClient(record, rawSecret);
    }

    @Transactional
    public CreatedOAuthClient rotateSecret(String id) {
        return rotateSecret(id, defaultSecretOverlap);
    }

    @Transactional
    public CreatedOAuthClient rotateSecret(String id, Duration overlap) {
        OAuthClientRecord record = required(id);
        if (ScopeCodec.decode(record.authenticationMethods()).contains("none")) {
            throw new IllegalArgumentException("Public OAuth clients do not have a client secret");
        }
        validateOverlap(overlap);
        String rawSecret = newSecret();
        String encodedSecret = passwordEncoder.encode(rawSecret);
        String secretVersion = newSecretVersion();
        Instant rotatedAt = clock.instant();
        Instant retiringExpiresAt = rotatedAt.plus(overlap);
        if (mapper.rotateSecret(
                id, record.clientSecretHash(), record.clientSecretVersion(), encodedSecret, secretVersion,
                retiringExpiresAt, rotatedAt) != 1) {
            throw new IllegalStateException("OAuth client secret changed concurrently; retry rotation");
        }
        OAuthClientRecord updated = new OAuthClientRecord(
                record.id(), record.clientId(), encodedSecret, secretVersion,
                record.clientSecretHash(), record.clientSecretVersion(), retiringExpiresAt, rotatedAt,
                record.clientName(),
                record.authenticationMethods(), record.grantTypes(), record.redirectUris(), record.scopes(),
                record.requireConsent(), record.requirePkce(), record.serviceAccountId(), record.enabled(),
                record.createdAt(), rotatedAt);
        return new CreatedOAuthClient(updated, rawSecret);
    }

    @Transactional
    public OAuthClientRecord revokeRetiringSecret(String id) {
        OAuthClientRecord record = required(id);
        if (record.retiringClientSecretHash() == null) {
            throw new IllegalArgumentException("OAuth client does not have a retiring secret");
        }
        Instant revokedAt = clock.instant();
        if (mapper.revokeRetiringSecret(
                id, record.retiringClientSecretHash(), record.retiringClientSecretVersion(), revokedAt) != 1) {
            throw new IllegalStateException("OAuth retiring client secret changed concurrently; retry revocation");
        }
        return new OAuthClientRecord(
                record.id(), record.clientId(), record.clientSecretHash(), record.clientSecretVersion(),
                null, null, null, record.clientSecretRotatedAt(), record.clientName(),
                record.authenticationMethods(), record.grantTypes(), record.redirectUris(), record.scopes(),
                record.requireConsent(), record.requirePkce(), record.serviceAccountId(), record.enabled(),
                record.createdAt(), revokedAt);
    }

    public OAuthClientRecord update(
            String id,
            String clientName,
            Collection<String> authenticationMethods,
            Collection<String> grantTypes,
            Collection<String> redirectUris,
            Collection<String> scopes,
            boolean requireConsent,
            Long serviceAccountId,
            boolean enabled) {
        OAuthClientRecord current = required(id);
        Set<String> validatedScopes = validate(current.clientId(), clientName, authenticationMethods, grantTypes,
                redirectUris, scopes, serviceAccountId);
        Set<String> oldMethods = ScopeCodec.decode(current.authenticationMethods());
        Set<String> newMethods = ScopeCodec.decode(ScopeCodec.encode(authenticationMethods));
        if (oldMethods.contains("none") != newMethods.contains("none")) {
            throw new IllegalArgumentException(
                    "OAuth client authentication class cannot be changed; create a new client instead");
        }
        OAuthClientRecord updated = new OAuthClientRecord(
                current.id(), current.clientId(), current.clientSecretHash(), current.clientSecretVersion(),
                current.retiringClientSecretHash(), current.retiringClientSecretVersion(),
                current.retiringClientSecretExpiresAt(), current.clientSecretRotatedAt(), clientName.trim(),
                ScopeCodec.encode(newMethods), ScopeCodec.encode(grantTypes), ScopeCodec.encodeLines(redirectUris),
                ScopeCodec.encode(validatedScopes), requireConsent, true, serviceAccountId, enabled,
                current.createdAt(), clock.instant());
        if (mapper.update(updated) == 0) {
            throw new IllegalArgumentException("OAuth client does not exist");
        }
        return updated;
    }

    public OAuthClientRecord required(String id) {
        OAuthClientRecord record = mapper.findById(id);
        if (record == null) {
            throw new IllegalArgumentException("OAuth client does not exist");
        }
        return record;
    }

    public List<OAuthClientRecord> findAll() {
        return mapper.findAll();
    }

    private Set<String> validate(
            String clientId,
            String clientName,
            Collection<String> authenticationMethods,
            Collection<String> grantTypes,
            Collection<String> redirectUris,
            Collection<String> scopes,
            Long serviceAccountId) {
        if (clientId == null || !clientId.matches("[A-Za-z0-9][A-Za-z0-9._-]{2,127}")) {
            throw new IllegalArgumentException("Invalid OAuth client id");
        }
        if (clientName == null || clientName.isBlank()) {
            throw new IllegalArgumentException("OAuth client name must not be blank");
        }
        Set<String> methods = ScopeCodec.decode(ScopeCodec.encode(authenticationMethods));
        Set<String> grants = ScopeCodec.decode(ScopeCodec.encode(grantTypes));
        if (methods.isEmpty() || !SUPPORTED_AUTH_METHODS.containsAll(methods)) {
            throw new IllegalArgumentException("Unsupported client authentication method");
        }
        if (methods.contains("none") && methods.size() != 1) {
            throw new IllegalArgumentException("Public clients must use only the none authentication method");
        }
        if (grants.isEmpty() || !SUPPORTED_GRANTS.containsAll(grants)) {
            throw new IllegalArgumentException("Unsupported OAuth grant type");
        }
        if (grants.contains("refresh_token") && !grants.contains("authorization_code")) {
            throw new IllegalArgumentException("Refresh token requires authorization code grant");
        }
        if (methods.contains("none") && !grants.contains("authorization_code")) {
            throw new IllegalArgumentException("Public clients must use authorization code with PKCE");
        }
        if (methods.contains("none") && grants.contains("client_credentials")) {
            throw new IllegalArgumentException("Public clients cannot use client credentials grant");
        }
        if (grants.contains("client_credentials") && grants.size() != 1) {
            throw new IllegalArgumentException("Client credentials clients cannot mix grant types");
        }
        if (grants.contains("authorization_code") && (redirectUris == null || redirectUris.isEmpty())) {
            throw new IllegalArgumentException("Authorization code clients require a redirect URI");
        }
        if (grants.contains("authorization_code")) {
            redirectUris.forEach(this::validateRedirectUri);
        }
        else if (redirectUris != null && !redirectUris.isEmpty()) {
            throw new IllegalArgumentException("Redirect URIs are allowed only for authorization code clients");
        }
        if (grants.contains("client_credentials") && serviceAccountId == null) {
            throw new IllegalArgumentException("Client credentials grant requires a service account");
        }
        if (!grants.contains("client_credentials") && serviceAccountId != null) {
            throw new IllegalArgumentException("Service accounts are allowed only for client credentials clients");
        }
        return scopePolicy.validateOAuthClientScopes(grants, serviceAccountId, scopes);
    }

    private void validateRedirectUri(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("OAuth redirect URI must not be blank");
        }
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute() || uri.isOpaque() || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("OAuth redirect URI must be an absolute URI without user-info or fragment");
            }
            String scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
            if ("https".equals(scheme)) {
                return;
            }
            if ("http".equals(scheme) && isLoopbackHost(uri.getHost())) {
                return;
            }
            throw new IllegalArgumentException("OAuth redirect URI must use HTTPS or loopback HTTP");
        }
        catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid OAuth redirect URI", exception);
        }
    }

    private static boolean isLoopbackHost(String host) {
        String normalized = host.toLowerCase(java.util.Locale.ROOT);
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if ("localhost".equals(normalized) || "::1".equals(normalized)) {
            return true;
        }
        if (!normalized.startsWith("127.")) {
            return false;
        }
        try {
            IpRestriction.validate(List.of(normalized));
            return true;
        }
        catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private String newSecret() {
        byte[] value = new byte[32];
        secureRandom.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String newSecretVersion() {
        byte[] value = new byte[12];
        secureRandom.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private void validateOverlap(Duration overlap) {
        if (overlap == null || overlap.isZero() || overlap.isNegative()
                || overlap.compareTo(maximumSecretOverlap) > 0) {
            throw new IllegalArgumentException(
                    "OAuth client secret overlap must be positive and no longer than "
                            + maximumSecretOverlap);
        }
    }

    public record CreatedOAuthClient(OAuthClientRecord client, String rawSecret) {
    }
}
