package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyRevocation;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import dev.webstarter.security.config.WebStarterSecurityProperties;

class OAuthSigningKeyRingTest {

    private static final Instant NOW = Instant.parse("2026-07-20T08:00:00Z");
    private static final Instant RETAIN_UNTIL = NOW.plus(Duration.ofMinutes(10));

    @Test
    void newJwtUsesOnlyTheActiveKidWhileRetiringJwtVerifiesBeforeCutoff() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey previousPrivate = rsaKey("previous-2025");
        RSAKey previousPublic = retiringPublic(previousPrivate, RETAIN_UNTIL);
        MutableClock clock = new MutableClock(NOW);
        OAuthSigningKeyRing ring = ring(active, previousPublic, "active-2026", clock);
        JWKSource<SecurityContext> source = source(ring);

        NimbusJwtEncoder encoder = new NimbusJwtEncoder(source);
        encoder.setJwkSelector(ring::selectActiveSigningKey);
        var encoded = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(),
                JwtClaimsSet.builder().subject("new-token").build()));

        assertThat(encoded.getHeaders().get("kid")).isEqualTo("active-2026");
        assertThat(NimbusJwtDecoder.withJwkSource(source).build()
                .decode(retiringToken(previousPrivate).serialize()).getSubject())
                .isEqualTo("existing-token");
        assertThat(ring.jwkSet().toPublicJWKSet().getKeys())
                .extracting(JWK::getKeyID)
                .containsExactly("active-2026", "previous-2025");
    }

    @Test
    void retiringJwtIsRejectedAtTheExclusiveRetainUntilBoundary() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey previousPrivate = rsaKey("previous-2025");
        MutableClock clock = new MutableClock(NOW);
        OAuthSigningKeyRing ring = ring(
                active, retiringPublic(previousPrivate, RETAIN_UNTIL), "active-2026", clock);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(source(ring)).build();
        String token = retiringToken(previousPrivate).serialize();

        assertThat(decoder.decode(token).getSubject()).isEqualTo("existing-token");

        clock.setInstant(RETAIN_UNTIL);

        assertThat(ring.jwkSet().getKeyByKeyId("previous-2025")).isNull();
        assertThatThrownBy(() -> decoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void emergencyRevocationRejectsRetiringJwtBeforeItsCutoff() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey previousPrivate = rsaKey("previous-2025");
        RSAKey revoked = new RSAKey.Builder(retiringPublic(previousPrivate, RETAIN_UNTIL))
                .keyRevocation(new KeyRevocation(
                        Date.from(NOW), KeyRevocation.Reason.COMPROMISED))
                .build();
        OAuthSigningKeyRing ring = ring(
                active, revoked, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(ring.jwkSet().getKeyByKeyId("previous-2025")).isNull();
        assertThatThrownBy(() -> NimbusJwtDecoder.withJwkSource(source(ring)).build()
                .decode(retiringToken(previousPrivate).serialize()))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void unknownKidIsRejected() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey unknown = rsaKey("unknown-key");
        OAuthSigningKeyRing ring = ring(
                active, null, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC));

        assertThatThrownBy(() -> NimbusJwtDecoder.withJwkSource(source(ring)).build()
                .decode(retiringToken(unknown).serialize()))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void multiKeyRingRequiresAnExplicitActiveKid() throws Exception {
        RSAKey first = rsaKey("first");
        RSAKey second = retiringPublic(rsaKey("second"), RETAIN_UNTIL);
        String json = jwkSet(first, second);

        assertThatThrownBy(() -> OAuthSigningKeyRing.from(
                properties(json, null), Clock.fixed(NOW, ZoneOffset.UTC)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ACTIVE_KEY_ID");
    }

    @Test
    void retiringKeyWithoutRetainUntilFailsFast() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey previous = rsaKey("previous-2025").toPublicJWK();

        assertThatThrownBy(() -> ring(
                active, previous, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("exp retain-until");
    }

    @Test
    void activeKeyCannotBeMarkedExpiredOrEmergencyRevoked() throws Exception {
        RSAKey base = rsaKey("active-2026");
        RSAKey expiringActive = new RSAKey.Builder(base)
                .expirationTime(Date.from(RETAIN_UNTIL))
                .build();
        RSAKey revokedActive = new RSAKey.Builder(base)
                .keyRevocation(new KeyRevocation(
                        Date.from(NOW), KeyRevocation.Reason.COMPROMISED))
                .build();

        assertThatThrownBy(() -> ring(
                expiringActive, null, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("rotate active kid first");
        assertThatThrownBy(() -> ring(
                revokedActive, null, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("rotate active kid first");
    }

    @Test
    void invalidRetiringWindowFailsFast() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey previous = new RSAKey.Builder(rsaKey("previous-2025").toPublicJWK())
                .notBeforeTime(Date.from(RETAIN_UNTIL))
                .expirationTime(Date.from(RETAIN_UNTIL))
                .build();

        assertThatThrownBy(() -> ring(
                active, previous, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("nbf must be before");
    }

    @Test
    void missingActiveKidFailsFastInsteadOfLeavingNoSigner() throws Exception {
        RSAKey active = rsaKey("active-2026");
        RSAKey previous = retiringPublic(rsaKey("previous-2025"), RETAIN_UNTIL);

        assertThatThrownBy(() -> ring(
                active, previous, "missing", Clock.fixed(NOW, ZoneOffset.UTC)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not exist");
    }

    @Test
    void diagnosticStringNeverContainsPrivateKeyMaterial() throws Exception {
        RSAKey active = rsaKey("active-2026");
        OAuthSigningKeyRing ring = ring(
                active, null, "active-2026", Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(ring.toString())
                .isEqualTo("OAuthSigningKeyRing[activeKeyId=active-2026, keyIds=[active-2026]]")
                .doesNotContain(active.getPrivateExponent().toString());
    }

    private static OAuthSigningKeyRing ring(
            RSAKey active,
            RSAKey retiring,
            String activeKeyId,
            Clock clock) {
        return OAuthSigningKeyRing.from(
                properties(jwkSet(active, retiring), activeKeyId), clock);
    }

    private static String jwkSet(RSAKey active, RSAKey retiring) {
        List<JWK> keys = new ArrayList<>();
        keys.add(active);
        if (retiring != null) {
            keys.add(retiring);
        }
        return new JWKSet(keys).toString(false);
    }

    private static JWKSource<SecurityContext> source(OAuthSigningKeyRing ring) {
        return (selector, context) -> selector.select(ring.jwkSet());
    }

    private static RSAKey retiringPublic(RSAKey key, Instant retainUntil) {
        return new RSAKey.Builder(key.toPublicJWK())
                .expirationTime(Date.from(retainUntil))
                .build();
    }

    private static SignedJWT retiringToken(RSAKey key) throws Exception {
        SignedJWT token = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("existing-token").build());
        token.sign(new RSASSASigner(key));
        return token;
    }

    private static RSAKey rsaKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        var pair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyID(kid)
                .build();
    }

    private static WebStarterSecurityProperties properties(String jwkSet, String activeKeyId) {
        return new WebStarterSecurityProperties(
                "0123456789abcdef0123456789abcdef",
                "https://auth.example.invalid",
                "https://auth.example.invalid/mcp",
                true,
                false,
                null,
                null,
                jwkSet,
                activeKeyId,
                Duration.ofMinutes(10),
                Duration.ofHours(8));
    }

    private static final class MutableClock extends Clock {

        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void setInstant(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("Only UTC is supported by this test clock");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
