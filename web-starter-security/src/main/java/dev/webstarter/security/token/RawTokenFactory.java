package dev.webstarter.security.token;

import java.security.SecureRandom;
import java.util.Base64;

public final class RawTokenFactory {

    private static final int TOKEN_BYTES = 32;
    private final SecureRandom secureRandom;

    public RawTokenFactory() {
        this(new SecureRandom());
    }

    RawTokenFactory(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    public String create(CredentialType type) {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return type.prefix() + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
