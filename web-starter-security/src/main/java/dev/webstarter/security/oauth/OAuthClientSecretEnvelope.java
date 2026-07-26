package dev.webstarter.security.oauth;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import dev.webstarter.security.persistence.model.OAuthClientRecord;

/** In-memory envelope containing hashes and retirement metadata, never plaintext secrets. */
final class OAuthClientSecretEnvelope {

    static final String PREFIX = "{webstarter-client-secret-v1}";

    private OAuthClientSecretEnvelope() {
    }

    static String encode(OAuthClientRecord record) {
        if (record.clientSecretHash() == null || record.clientSecretHash().isBlank()) {
            return null;
        }
        return PREFIX
                + field(record.clientSecretHash()) + '.'
                + field(record.clientSecretVersion()) + '.'
                + field(record.retiringClientSecretHash()) + '.'
                + field(record.retiringClientSecretVersion()) + '.'
                + (record.retiringClientSecretExpiresAt() == null
                        ? "" : Long.toString(record.retiringClientSecretExpiresAt().toEpochMilli()));
    }

    static Parsed parse(String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            return null;
        }
        String[] fields = encoded.substring(PREFIX.length()).split("\\.", -1);
        if (fields.length != 5) {
            throw new IllegalArgumentException("Invalid OAuth client secret envelope");
        }
        String activeHash = decodeRequired(fields[0]);
        String activeVersion = decodeRequired(fields[1]);
        String retiringHash = decodeOptional(fields[2]);
        String retiringVersion = decodeOptional(fields[3]);
        Instant retiringExpiresAt = fields[4].isBlank()
                ? null : Instant.ofEpochMilli(Long.parseLong(fields[4]));
        if ((retiringHash == null) != (retiringVersion == null)
                || (retiringHash == null) != (retiringExpiresAt == null)) {
            throw new IllegalArgumentException("Incomplete OAuth retiring secret envelope");
        }
        return new Parsed(activeHash, activeVersion, retiringHash, retiringVersion, retiringExpiresAt);
    }

    private static String field(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decodeRequired(String value) {
        String decoded = decodeOptional(value);
        if (decoded == null) {
            throw new IllegalArgumentException("OAuth active client secret hash is missing");
        }
        return decoded;
    }

    private static String decodeOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    record Parsed(
            String activeHash,
            String activeVersion,
            String retiringHash,
            String retiringVersion,
            Instant retiringExpiresAt) {
    }
}
