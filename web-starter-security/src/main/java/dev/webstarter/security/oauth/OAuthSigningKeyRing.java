package dev.webstarter.security.oauth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import dev.webstarter.security.config.WebStarterSecurityProperties;

/**
 * OAuth RSA key ring with one non-expiring active signing key and explicitly
 * time-bounded retiring verification keys.
 *
 * <p>The standard JWK {@code exp} member is the exclusive retain-until
 * boundary for every non-active key. A JWK {@code rev} member is an emergency
 * revocation state and removes that key immediately, regardless of its
 * {@code revoked_at} audit timestamp. The active key is never allowed to carry
 * either lifecycle member, so a bad rotation configuration fails before the
 * authorization server can start without a usable signer.</p>
 */
public final class OAuthSigningKeyRing {

    private final List<RSAKey> keys;
    private final RSAKey activeKey;
    private final Clock clock;

    private OAuthSigningKeyRing(List<RSAKey> keys, RSAKey activeKey, Clock clock) {
        this.keys = List.copyOf(keys);
        this.activeKey = Objects.requireNonNull(activeKey, "activeKey");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static OAuthSigningKeyRing from(WebStarterSecurityProperties properties) {
        return from(properties, Clock.systemUTC());
    }

    public static OAuthSigningKeyRing from(
            WebStarterSecurityProperties properties,
            Clock clock) {
        Objects.requireNonNull(properties, "properties");
        Objects.requireNonNull(clock, "clock");
        if (hasText(properties.rsaJwkSet())) {
            return parseJwkSet(properties.rsaJwkSet(), properties.rsaActiveKeyId(), clock);
        }
        RsaKeyMaterial material = RsaKeyMaterial.from(properties);
        String kid = keyId(material.publicKey().getEncoded());
        RSAKey key = new RSAKey.Builder(material.publicKey())
                .privateKey(material.privateKey())
                .keyID(kid)
                .build();
        return new OAuthSigningKeyRing(List.of(key), key, clock);
    }

    public List<RSAKey> keys() {
        return keys;
    }

    public RSAKey activeKey() {
        return activeKey;
    }

    public String activeKeyId() {
        return activeKey.getKeyID();
    }

    /**
     * Returns only keys that may verify a token at the current clock instant.
     * A fresh set is built on every selection so a retiring window cannot be
     * extended by a decoder created before its cutoff.
     */
    public JWKSet jwkSet() {
        Instant now = clock.instant();
        List<JWK> verificationKeys = keys.stream()
                .filter(key -> isVerificationAllowed(key, now))
                .map(key -> (JWK) key)
                .toList();
        return new JWKSet(new ArrayList<>(verificationKeys));
    }

    /** Selects the sole configured active key for every newly encoded JWT. */
    public JWK selectActiveSigningKey(List<JWK> candidates) {
        List<JWK> activeCandidates = candidates.stream()
                .filter(candidate -> activeKeyId().equals(candidate.getKeyID()))
                .toList();
        if (activeCandidates.size() != 1 || !activeCandidates.getFirst().isPrivate()) {
            throw new IllegalStateException("OAuth active signing key is unavailable");
        }
        return activeCandidates.getFirst();
    }

    @Override
    public String toString() {
        List<String> keyIds = keys.stream().map(RSAKey::getKeyID).toList();
        return "OAuthSigningKeyRing[activeKeyId=" + activeKeyId()
                + ", keyIds=" + keyIds + ']';
    }

    private boolean isVerificationAllowed(RSAKey key, Instant now) {
        if (activeKeyId().equals(key.getKeyID())) {
            return true;
        }
        return key.getKeyRevocation() == null
                && now.isBefore(key.getExpirationTime().toInstant());
    }

    private static OAuthSigningKeyRing parseJwkSet(
            String json,
            String configuredActiveKeyId,
            Clock clock) {
        JWKSet parsed;
        try {
            parsed = JWKSet.parse(json);
        }
        catch (java.text.ParseException exception) {
            throw new IllegalStateException("Invalid OAuth RSA JWK set", exception);
        }
        if (parsed.isEmpty()) {
            throw new IllegalStateException("OAuth RSA JWK set must contain at least one key");
        }
        Set<String> keyIds = new HashSet<>();
        List<RSAKey> keys = parsed.getKeys().stream()
                .map(key -> validateKey(key, keyIds))
                .toList();
        String activeKeyId = hasText(configuredActiveKeyId)
                ? configuredActiveKeyId.trim()
                : keys.size() == 1 ? keys.getFirst().getKeyID() : null;
        if (activeKeyId == null) {
            throw new IllegalStateException(
                    "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID is required for a multi-key JWK set");
        }
        RSAKey active = keys.stream()
                .filter(key -> activeKeyId.equals(key.getKeyID()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "OAuth active RSA key ID does not exist in the JWK set"));
        validateActiveKey(active);
        keys.stream()
                .filter(key -> !activeKeyId.equals(key.getKeyID()))
                .forEach(OAuthSigningKeyRing::validateRetiringKey);
        return new OAuthSigningKeyRing(keys, active, clock);
    }

    private static RSAKey validateKey(JWK key, Set<String> keyIds) {
        if (!(key instanceof RSAKey rsaKey)) {
            throw new IllegalStateException("OAuth JWK set may contain only RSA keys");
        }
        if (!hasText(rsaKey.getKeyID())) {
            throw new IllegalStateException("Every OAuth RSA JWK must have a kid");
        }
        if (!keyIds.add(rsaKey.getKeyID())) {
            throw new IllegalStateException("OAuth RSA JWK kid values must be unique");
        }
        if (rsaKey.size() < 3072) {
            throw new IllegalStateException("OAuth RSA JWK keys must be at least 3072 bits");
        }
        return rsaKey;
    }

    private static void validateActiveKey(RSAKey active) {
        if (!active.isPrivate()) {
            throw new IllegalStateException("OAuth active RSA key must include private key material");
        }
        if (active.getExpirationTime() != null || active.getKeyRevocation() != null) {
            throw new IllegalStateException(
                    "OAuth active RSA key must not be expiring or revoked; rotate active kid first");
        }
    }

    private static void validateRetiringKey(RSAKey retiring) {
        if (retiring.getExpirationTime() == null) {
            throw new IllegalStateException(
                    "Every retiring OAuth RSA JWK must declare an exp retain-until boundary");
        }
        if (retiring.getNotBeforeTime() != null
                && !retiring.getNotBeforeTime().before(retiring.getExpirationTime())) {
            throw new IllegalStateException(
                    "Retiring OAuth RSA JWK nbf must be before its exp retain-until boundary");
        }
    }

    private static String keyId(byte[] publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
