package dev.webstarter.security.token;

import java.time.Instant;
import java.util.Set;

public record IssuedCredential(
        Long id,
        CredentialType credentialType,
        String rawToken,
        String tokenHint,
        Set<String> scopes,
        Instant expiresAt) {
}
