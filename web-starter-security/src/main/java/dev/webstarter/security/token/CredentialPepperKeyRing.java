package dev.webstarter.security.token;

import java.util.List;
import java.util.Objects;

import dev.webstarter.security.config.WebStarterSecurityProperties;

/**
 * Versioned HMAC keys used only for long-lived PAT and service-account tokens.
 * The raw peppers never leave configuration and are never exposed by this type.
 */
public final class CredentialPepperKeyRing {

    private static final String VERSION_PATTERN = "[A-Za-z0-9][A-Za-z0-9._-]{0,31}";

    private final VersionedHasher active;
    private final List<VersionedHasher> retiring;

    private CredentialPepperKeyRing(VersionedHasher active, List<VersionedHasher> retiring) {
        this.active = active;
        this.retiring = List.copyOf(retiring);
    }

    public static CredentialPepperKeyRing from(WebStarterSecurityProperties properties) {
        Objects.requireNonNull(properties, "properties");
        String activeVersion = requireVersion(
                properties.credentialPepperActiveVersion(), "active credential pepper version");
        String activePepper = properties.requiredCredentialPepper();
        String retiringVersion = trimToNull(properties.credentialPepperRetiringVersion());
        String retiringPepper = trimToNull(properties.credentialPepperRetiring());
        if ((retiringVersion == null) != (retiringPepper == null)) {
            throw new IllegalStateException(
                    "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING and its version must be configured together");
        }
        if (retiringVersion == null) {
            return single(activeVersion, new TokenHasher(activePepper));
        }
        retiringVersion = requireVersion(retiringVersion, "retiring credential pepper version");
        if (retiringVersion.equals(activeVersion)) {
            throw new IllegalStateException("Active and retiring credential pepper versions must differ");
        }
        if (retiringPepper.length() < 32 || retiringPepper.startsWith("replace-with-")) {
            throw new IllegalStateException(
                    "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING must contain at least 32 characters");
        }
        if (retiringPepper.equals(activePepper)) {
            throw new IllegalStateException("Active and retiring credential peppers must differ");
        }
        return new CredentialPepperKeyRing(
                new VersionedHasher(activeVersion, new TokenHasher(activePepper)),
                List.of(new VersionedHasher(retiringVersion, new TokenHasher(retiringPepper))));
    }

    static CredentialPepperKeyRing single(String version, TokenHasher hasher) {
        return new CredentialPepperKeyRing(
                new VersionedHasher(requireVersion(version, "credential pepper version"), hasher),
                List.of());
    }

    public String activeVersion() {
        return active.version();
    }

    public String hashWithActive(String rawToken) {
        return active.hasher().hash(rawToken);
    }

    public List<HashCandidate> lookupCandidates(String rawToken) {
        var candidates = new java.util.ArrayList<HashCandidate>(retiring.size() + 1);
        candidates.add(new HashCandidate(active.version(), active.hasher().hash(rawToken), true));
        retiring.forEach(key -> candidates.add(
                new HashCandidate(key.version(), key.hasher().hash(rawToken), false)));
        return List.copyOf(candidates);
    }

    private static String requireVersion(String value, String label) {
        String normalized = trimToNull(value);
        if (normalized == null || !normalized.matches(VERSION_PATTERN)) {
            throw new IllegalStateException(label + " must match " + VERSION_PATTERN);
        }
        return normalized;
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public record HashCandidate(String version, String hash, boolean active) {
    }

    private record VersionedHasher(String version, TokenHasher hasher) {
    }
}
