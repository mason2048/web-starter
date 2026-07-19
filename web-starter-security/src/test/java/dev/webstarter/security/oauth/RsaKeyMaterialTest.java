package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import dev.webstarter.security.config.WebStarterSecurityProperties;

class RsaKeyMaterialTest {

    @Test
    void productionModeFailsFastWhenPersistentKeysAreMissing() {
        var properties = properties(false, "", "");

        assertThatThrownBy(() -> RsaKeyMaterial.from(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("OAuth RSA keys are required; ephemeral keys are allowed only for development");
    }

    @Test
    void developmentModeMayGenerateAnEphemeral3072BitKeyPair() {
        RsaKeyMaterial material = RsaKeyMaterial.from(properties(true, "", ""));

        assertThat(material.publicKey().getModulus()).isEqualTo(material.privateKey().getModulus());
        assertThat(material.publicKey().getModulus().bitLength()).isGreaterThanOrEqualTo(3072);
    }

    private static WebStarterSecurityProperties properties(
            boolean developmentKeysAllowed,
            String privateKey,
            String publicKey) {
        return new WebStarterSecurityProperties(
                "0123456789abcdef0123456789abcdef",
                "https://mcp.example.invalid",
                "https://mcp.example.invalid/mcp",
                true,
                developmentKeysAllowed,
                privateKey,
                publicKey,
                Duration.ofMinutes(10),
                Duration.ofHours(8));
    }
}
