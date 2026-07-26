package dev.webstarter.security.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import dev.webstarter.security.config.WebStarterSecurityProperties;

class CredentialPepperKeyRingTest {

    private static final String FIRST = "0123456789abcdef0123456789abcdef";
    private static final String SECOND = "abcdef0123456789abcdef0123456789";

    @Test
    void activeCandidatePrecedesRetiringCandidateWithoutExposingPepper() {
        CredentialPepperKeyRing ring = CredentialPepperKeyRing.from(
                properties(SECOND, "v2", FIRST, "v1"));

        var candidates = ring.lookupCandidates("wst_pat_example");

        assertThat(candidates).extracting(CredentialPepperKeyRing.HashCandidate::version)
                .containsExactly("v2", "v1");
        assertThat(candidates).extracting(CredentialPepperKeyRing.HashCandidate::active)
                .containsExactly(true, false);
        assertThat(candidates).allSatisfy(candidate -> assertThat(candidate.hash())
                .matches("[0-9a-f]{64}")
                .doesNotContain(FIRST)
                .doesNotContain(SECOND));
    }

    @Test
    void retiringPepperAndVersionMustBeConfiguredTogether() {
        assertThatThrownBy(() -> CredentialPepperKeyRing.from(
                properties(SECOND, "v2", FIRST, null)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("configured together");
    }

    @Test
    void activeAndRetiringVersionsAndValuesMustDiffer() {
        assertThatThrownBy(() -> CredentialPepperKeyRing.from(
                properties(SECOND, "v1", FIRST, "v1")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("versions must differ");
        assertThatThrownBy(() -> CredentialPepperKeyRing.from(
                properties(SECOND, "v2", SECOND, "v1")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("peppers must differ");
    }

    private static WebStarterSecurityProperties properties(
            String active,
            String activeVersion,
            String retiring,
            String retiringVersion) {
        return new WebStarterSecurityProperties(
                FIRST, "https://auth.example.invalid", "https://auth.example.invalid/mcp",
                true, false, null, null, null, null,
                Duration.ofMinutes(10), Duration.ofHours(8),
                active, activeVersion, retiring, retiringVersion,
                Duration.ofMinutes(15), Duration.ofHours(24));
    }
}
