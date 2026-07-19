package dev.webstarter.security.oauth;

import java.security.SecureRandom;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;

import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.token.CredentialScopePolicy;
import dev.webstarter.security.token.IpRestriction;
import dev.webstarter.security.token.ScopeCodec;

public final class OAuthClientManagementService {

    private static final Set<String> SUPPORTED_GRANTS = Set.of(
            "authorization_code", "refresh_token", "client_credentials");
    private static final Set<String> SUPPORTED_AUTH_METHODS = Set.of(
            "client_secret_basic", "client_secret_post", "none");

    private final OAuthClientMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final CredentialScopePolicy scopePolicy;
    private final SecureRandom secureRandom;
    private final Clock clock;

    public OAuthClientManagementService(
            OAuthClientMapper mapper,
            PasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy) {
        this(mapper, passwordEncoder, scopePolicy, new SecureRandom(), Clock.systemUTC());
    }

    OAuthClientManagementService(
            OAuthClientMapper mapper,
            PasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy,
            SecureRandom secureRandom,
            Clock clock) {
        this.mapper = mapper;
        this.passwordEncoder = passwordEncoder;
        this.scopePolicy = scopePolicy;
        this.secureRandom = secureRandom;
        this.clock = clock;
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
                UUID.randomUUID().toString(), clientId, rawSecret == null ? null : passwordEncoder.encode(rawSecret),
                clientName, ScopeCodec.encode(methods), ScopeCodec.encode(grantTypes),
                ScopeCodec.encodeLines(redirectUris), ScopeCodec.encode(validatedScopes), requireConsent,
                true, serviceAccountId, true, now, now);
        mapper.insert(record);
        return new CreatedOAuthClient(record, rawSecret);
    }

    public CreatedOAuthClient rotateSecret(String id) {
        OAuthClientRecord record = required(id);
        if (ScopeCodec.decode(record.authenticationMethods()).contains("none")) {
            throw new IllegalArgumentException("Public OAuth clients do not have a client secret");
        }
        String rawSecret = newSecret();
        String encodedSecret = passwordEncoder.encode(rawSecret);
        mapper.updateSecret(id, encodedSecret);
        OAuthClientRecord updated = new OAuthClientRecord(
                record.id(), record.clientId(), encodedSecret, record.clientName(),
                record.authenticationMethods(), record.grantTypes(), record.redirectUris(), record.scopes(),
                record.requireConsent(), record.requirePkce(), record.serviceAccountId(), record.enabled(),
                record.createdAt(), clock.instant());
        return new CreatedOAuthClient(updated, rawSecret);
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
                current.id(), current.clientId(), current.clientSecretHash(), clientName.trim(),
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

    public record CreatedOAuthClient(OAuthClientRecord client, String rawSecret) {
    }
}
