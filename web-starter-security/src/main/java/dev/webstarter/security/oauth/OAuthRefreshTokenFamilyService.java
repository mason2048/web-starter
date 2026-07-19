package dev.webstarter.security.oauth;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.security.persistence.mapper.OAuthRefreshTokenFamilyMapper;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenFamilyRecord;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenHistoryRecord;

/**
 * Coordinates refresh-token rotation using caller-supplied HMAC-SHA-256 hashes.
 * Raw refresh-token values must never be passed to this service or its mapper.
 */
public class OAuthRefreshTokenFamilyService {

    private static final Pattern HMAC_SHA_256 = Pattern.compile("[0-9a-f]{64}");
    private static final int MAX_REASON_LENGTH = 100;
    private static final long INITIAL_GENERATION = 0;

    private final OAuthRefreshTokenFamilyMapper mapper;

    public OAuthRefreshTokenFamilyService(OAuthRefreshTokenFamilyMapper mapper) {
        this.mapper = Objects.requireNonNull(mapper, "mapper");
    }

    @Transactional
    public void issue(
            String authorizationId,
            String tokenHash,
            Instant issuedAt,
            Instant expiresAt,
            Instant now) {
        validateAuthorizationId(authorizationId);
        validateHash(tokenHash, "tokenHash");
        validateLifetime(issuedAt, expiresAt, now);
        OAuthRefreshTokenFamilyRecord family = new OAuthRefreshTokenFamilyRecord(
                authorizationId,
                tokenHash,
                INITIAL_GENERATION,
                issuedAt,
                expiresAt,
                null,
                null,
                now,
                now);
        OAuthRefreshTokenHistoryRecord history = new OAuthRefreshTokenHistoryRecord(
                tokenHash,
                authorizationId,
                INITIAL_GENERATION,
                issuedAt,
                expiresAt,
                null,
                null,
                null,
                now);
        requireSingleRow(mapper.insertFamily(family), "refresh-token family insert");
        requireSingleRow(mapper.insertHistory(history), "refresh-token history insert");
    }

    @Transactional
    public OAuthRefreshTokenLookup lookupForUpdate(String tokenHash, Instant now) {
        validateHash(tokenHash, "tokenHash");
        Objects.requireNonNull(now, "now");
        String authorizationId = mapper.findAuthorizationIdByTokenHash(tokenHash);
        if (authorizationId == null) {
            return OAuthRefreshTokenLookup.unknown();
        }
        OAuthRefreshTokenFamilyRecord family = mapper.findFamilyForUpdate(authorizationId);
        if (family == null) {
            return OAuthRefreshTokenLookup.unknown();
        }
        OAuthRefreshTokenHistoryRecord history = mapper.findHistoryForUpdate(
                authorizationId, tokenHash);
        if (history == null) {
            return OAuthRefreshTokenLookup.unknown();
        }
        OAuthRefreshTokenStatus status = classify(family, history, now);
        Instant revokedAt = family.revokedAt() != null
                ? family.revokedAt() : history.revokedAt();
        String revokeReason = family.revokeReason() != null
                ? family.revokeReason() : history.revokeReason();
        return new OAuthRefreshTokenLookup(
                family.authorizationId(),
                status,
                family.generation(),
                family.currentTokenHash(),
                history.generation(),
                history.expiresAt(),
                revokedAt,
                revokeReason);
    }

    @Transactional
    public OAuthRefreshTokenRotationResult rotate(
            String authorizationId,
            String expectedTokenHash,
            long expectedGeneration,
            String newTokenHash,
            Instant issuedAt,
            Instant expiresAt,
            Instant now) {
        validateAuthorizationId(authorizationId);
        validateHash(expectedTokenHash, "expectedTokenHash");
        validateHash(newTokenHash, "newTokenHash");
        if (expectedTokenHash.equals(newTokenHash)) {
            throw new IllegalArgumentException("New refresh-token hash must differ from the current hash");
        }
        if (expectedGeneration < INITIAL_GENERATION || expectedGeneration == Long.MAX_VALUE) {
            throw new IllegalArgumentException("Expected generation is outside the supported range");
        }
        validateLifetime(issuedAt, expiresAt, now);

        OAuthRefreshTokenLookup lookup = lookupForUpdate(expectedTokenHash, now);
        OAuthRefreshTokenRotationResult unusable = unusableResult(
                authorizationId, expectedGeneration, lookup);
        if (unusable != null) {
            return unusable;
        }

        long newGeneration = expectedGeneration + 1;
        int familyRows = mapper.rotateFamilyCas(
                authorizationId,
                expectedTokenHash,
                expectedGeneration,
                newTokenHash,
                newGeneration,
                issuedAt,
                expiresAt,
                now);
        if (familyRows == 0) {
            return classifyFailedCas(authorizationId, expectedTokenHash, now);
        }
        requireSingleRow(familyRows, "refresh-token family rotation");
        requireSingleRow(
                mapper.consumeHistoryCas(
                        authorizationId, expectedTokenHash, expectedGeneration, now),
                "refresh-token history consumption");
        requireSingleRow(mapper.insertHistory(new OAuthRefreshTokenHistoryRecord(
                newTokenHash,
                authorizationId,
                newGeneration,
                issuedAt,
                expiresAt,
                null,
                null,
                null,
                now)), "refresh-token history insert");
        return OAuthRefreshTokenRotationResult.ROTATED;
    }

    @Transactional
    public boolean revoke(String authorizationId, String reason, Instant now) {
        validateAuthorizationId(authorizationId);
        validateReason(reason);
        Objects.requireNonNull(now, "now");
        int familyRows = mapper.revokeFamily(authorizationId, reason, now);
        mapper.revokeHistory(authorizationId, reason, now);
        if (familyRows > 1) {
            throw new IllegalStateException("Refresh-token family revoke affected multiple rows");
        }
        return familyRows == 1;
    }

    private OAuthRefreshTokenRotationResult classifyFailedCas(
            String authorizationId,
            String expectedTokenHash,
            Instant now) {
        OAuthRefreshTokenLookup refreshed = lookupForUpdate(expectedTokenHash, now);
        if (refreshed.status() == OAuthRefreshTokenStatus.UNKNOWN
                || !authorizationId.equals(refreshed.authorizationId())) {
            return OAuthRefreshTokenRotationResult.NOT_FOUND;
        }
        return switch (refreshed.status()) {
            case REPLAY -> OAuthRefreshTokenRotationResult.REPLAY;
            case EXPIRED -> OAuthRefreshTokenRotationResult.EXPIRED;
            case REVOKED -> OAuthRefreshTokenRotationResult.REVOKED;
            case CURRENT, UNKNOWN -> OAuthRefreshTokenRotationResult.CONFLICT;
        };
    }

    private static OAuthRefreshTokenRotationResult unusableResult(
            String authorizationId,
            long expectedGeneration,
            OAuthRefreshTokenLookup lookup) {
        if (lookup.status() == OAuthRefreshTokenStatus.UNKNOWN
                || !authorizationId.equals(lookup.authorizationId())) {
            return OAuthRefreshTokenRotationResult.NOT_FOUND;
        }
        return switch (lookup.status()) {
            case REPLAY -> OAuthRefreshTokenRotationResult.REPLAY;
            case EXPIRED -> OAuthRefreshTokenRotationResult.EXPIRED;
            case REVOKED -> OAuthRefreshTokenRotationResult.REVOKED;
            case CURRENT -> lookup.generation() == expectedGeneration
                    ? null : OAuthRefreshTokenRotationResult.CONFLICT;
            case UNKNOWN -> OAuthRefreshTokenRotationResult.NOT_FOUND;
        };
    }

    private static OAuthRefreshTokenStatus classify(
            OAuthRefreshTokenFamilyRecord family,
            OAuthRefreshTokenHistoryRecord history,
            Instant now) {
        if (family.revokedAt() != null || history.revokedAt() != null) {
            return OAuthRefreshTokenStatus.REVOKED;
        }
        boolean isCurrent = family.currentTokenHash().equals(history.tokenHash())
                && family.generation() == history.generation()
                && history.consumedAt() == null;
        if (!isCurrent) {
            return OAuthRefreshTokenStatus.REPLAY;
        }
        if (family.currentExpiresAt() == null
                || !family.currentExpiresAt().isAfter(now)
                || history.expiresAt() == null
                || !history.expiresAt().isAfter(now)) {
            return OAuthRefreshTokenStatus.EXPIRED;
        }
        return OAuthRefreshTokenStatus.CURRENT;
    }

    private static void validateAuthorizationId(String authorizationId) {
        if (authorizationId == null || authorizationId.isBlank() || authorizationId.length() > 100) {
            throw new IllegalArgumentException("Authorization id must contain 1 to 100 characters");
        }
    }

    private static void validateHash(String tokenHash, String name) {
        if (tokenHash == null || !HMAC_SHA_256.matcher(tokenHash).matches()) {
            throw new IllegalArgumentException(name + " must be a lowercase HMAC-SHA-256 hex value");
        }
    }

    private static void validateLifetime(Instant issuedAt, Instant expiresAt, Instant now) {
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(now, "now");
        if (!expiresAt.isAfter(issuedAt) || !expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("Refresh-token expiry must be after issue time and now");
        }
    }

    private static void validateReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > MAX_REASON_LENGTH) {
            throw new IllegalArgumentException("Revoke reason must contain 1 to 100 characters");
        }
    }

    private static void requireSingleRow(int affectedRows, String operation) {
        if (affectedRows != 1) {
            throw new IllegalStateException(operation + " affected " + affectedRows + " rows");
        }
    }
}
