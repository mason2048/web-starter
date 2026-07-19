package dev.webstarter.security.token;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class TokenHasher {

    private static final String ALGORITHM = "HmacSHA256";
    private final SecretKeySpec key;

    public TokenHasher(String pepper) {
        if (pepper == null || pepper.length() < 32) {
            throw new IllegalArgumentException("Token pepper must contain at least 32 characters");
        }
        this.key = new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public String hash(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Token value must not be blank");
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA-256 is unavailable", ex);
        }
    }
}
