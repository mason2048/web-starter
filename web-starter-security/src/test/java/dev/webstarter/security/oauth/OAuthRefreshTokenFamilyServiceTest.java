package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.webstarter.security.persistence.mapper.OAuthRefreshTokenFamilyMapper;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenFamilyRecord;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenHistoryRecord;

class OAuthRefreshTokenFamilyServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-19T00:00:00Z");
    private static final String FIRST_HASH = "a".repeat(64);
    private static final String SECOND_HASH = "b".repeat(64);

    @Test
    void initialIssueStoresOnlyHashAndCanBeLookedUpAsCurrent() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);

        service.issue("authorization-1", FIRST_HASH, NOW, NOW.plusSeconds(3600), NOW);

        OAuthRefreshTokenLookup lookup = service.lookupForUpdate(FIRST_HASH, NOW.plusSeconds(1));
        assertThat(lookup.status()).isEqualTo(OAuthRefreshTokenStatus.CURRENT);
        assertThat(lookup.authorizationId()).isEqualTo("authorization-1");
        assertThat(lookup.generation()).isZero();
        assertThat(lookup.presentedGeneration()).isZero();
        assertThat(lookup.currentTokenHash()).isEqualTo(FIRST_HASH);
        assertThat(mapper.families.get("authorization-1").currentTokenHash())
                .isEqualTo(FIRST_HASH);
        assertThat(mapper.history).containsOnlyKeys(FIRST_HASH);
    }

    @Test
    void rotationUsesCasAndRetainsConsumedHashForReplayDetection() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);
        service.issue("authorization-1", FIRST_HASH, NOW, NOW.plusSeconds(3600), NOW);

        OAuthRefreshTokenRotationResult result = service.rotate(
                "authorization-1",
                FIRST_HASH,
                0,
                SECOND_HASH,
                NOW.plusSeconds(10),
                NOW.plusSeconds(3610),
                NOW.plusSeconds(10));

        assertThat(result).isEqualTo(OAuthRefreshTokenRotationResult.ROTATED);
        OAuthRefreshTokenLookup current = service.lookupForUpdate(SECOND_HASH, NOW.plusSeconds(11));
        assertThat(current.status()).isEqualTo(OAuthRefreshTokenStatus.CURRENT);
        assertThat(current.generation()).isEqualTo(1);
        assertThat(current.currentTokenHash()).isEqualTo(SECOND_HASH);
        OAuthRefreshTokenLookup replay = service.lookupForUpdate(FIRST_HASH, NOW.plusSeconds(11));
        assertThat(replay.status()).isEqualTo(OAuthRefreshTokenStatus.REPLAY);
        assertThat(replay.generation()).isEqualTo(1);
        assertThat(replay.presentedGeneration()).isZero();
        assertThat(mapper.history.get(FIRST_HASH).consumedAt()).isEqualTo(NOW.plusSeconds(10));
    }

    @Test
    void replayAndGenerationConflictCannotRotateFamilyAgain() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);
        service.issue("authorization-1", FIRST_HASH, NOW, NOW.plusSeconds(3600), NOW);
        assertThat(service.rotate(
                "authorization-1", FIRST_HASH, 0, SECOND_HASH,
                NOW.plusSeconds(10), NOW.plusSeconds(3610), NOW.plusSeconds(10)))
                .isEqualTo(OAuthRefreshTokenRotationResult.ROTATED);

        assertThat(service.rotate(
                "authorization-1", FIRST_HASH, 0, "c".repeat(64),
                NOW.plusSeconds(20), NOW.plusSeconds(3620), NOW.plusSeconds(20)))
                .isEqualTo(OAuthRefreshTokenRotationResult.REPLAY);
        assertThat(service.rotate(
                "authorization-1", SECOND_HASH, 0, "d".repeat(64),
                NOW.plusSeconds(20), NOW.plusSeconds(3620), NOW.plusSeconds(20)))
                .isEqualTo(OAuthRefreshTokenRotationResult.CONFLICT);
        assertThat(mapper.families.get("authorization-1").currentTokenHash())
                .isEqualTo(SECOND_HASH);
    }

    @Test
    void currentExpiredTokenAndUnknownHashAreDistinguished() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);
        service.issue("authorization-1", FIRST_HASH, NOW, NOW.plusSeconds(60), NOW);

        assertThat(service.lookupForUpdate(FIRST_HASH, NOW.plusSeconds(60)).status())
                .isEqualTo(OAuthRefreshTokenStatus.EXPIRED);
        assertThat(service.lookupForUpdate("f".repeat(64), NOW).status())
                .isEqualTo(OAuthRefreshTokenStatus.UNKNOWN);
        assertThat(service.rotate(
                "authorization-1", FIRST_HASH, 0, SECOND_HASH,
                NOW.plusSeconds(61), NOW.plusSeconds(120), NOW.plusSeconds(61)))
                .isEqualTo(OAuthRefreshTokenRotationResult.EXPIRED);
    }

    @Test
    void revokeMarksFamilyAndEveryHistoryGeneration() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);
        service.issue("authorization-1", FIRST_HASH, NOW, NOW.plusSeconds(3600), NOW);
        service.rotate(
                "authorization-1", FIRST_HASH, 0, SECOND_HASH,
                NOW.plusSeconds(10), NOW.plusSeconds(3610), NOW.plusSeconds(10));

        assertThat(service.revoke(
                "authorization-1", "REFRESH_TOKEN_REUSE", NOW.plusSeconds(20))).isTrue();

        assertThat(service.lookupForUpdate(FIRST_HASH, NOW.plusSeconds(21)).status())
                .isEqualTo(OAuthRefreshTokenStatus.REVOKED);
        OAuthRefreshTokenLookup current = service.lookupForUpdate(SECOND_HASH, NOW.plusSeconds(21));
        assertThat(current.status()).isEqualTo(OAuthRefreshTokenStatus.REVOKED);
        assertThat(current.revokeReason()).isEqualTo("REFRESH_TOKEN_REUSE");
        assertThat(mapper.history.values())
                .allSatisfy(record -> {
                    assertThat(record.revokedAt()).isEqualTo(NOW.plusSeconds(20));
                    assertThat(record.revokeReason()).isEqualTo("REFRESH_TOKEN_REUSE");
                });
    }

    @Test
    void rawOrMalformedTokenMaterialIsRejectedBeforePersistence() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);

        assertThatThrownBy(() -> service.issue(
                "authorization-1", "raw-refresh-token", NOW, NOW.plusSeconds(3600), NOW))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HMAC-SHA-256");
        assertThat(mapper.families).isEmpty();
        assertThat(mapper.history).isEmpty();
    }

    @Test
    void lookupAlwaysResolvesIdentityThenLocksFamilyBeforeHistory() {
        InMemoryMapper mapper = new InMemoryMapper();
        OAuthRefreshTokenFamilyService service = new OAuthRefreshTokenFamilyService(mapper);
        service.issue("authorization-1", FIRST_HASH, NOW, NOW.plusSeconds(3600), NOW);
        mapper.calls.clear();

        assertThat(service.lookupForUpdate(FIRST_HASH, NOW.plusSeconds(1)).status())
                .isEqualTo(OAuthRefreshTokenStatus.CURRENT);

        assertThat(mapper.calls).containsExactly(
                "findAuthorizationIdByTokenHash",
                "findFamilyForUpdate",
                "findHistoryForUpdate");
    }

    private static final class InMemoryMapper implements OAuthRefreshTokenFamilyMapper {
        private final Map<String, OAuthRefreshTokenFamilyRecord> families = new HashMap<>();
        private final Map<String, OAuthRefreshTokenHistoryRecord> history = new HashMap<>();
        private final List<String> calls = new ArrayList<>();

        @Override
        public int insertFamily(OAuthRefreshTokenFamilyRecord record) {
            calls.add("insertFamily");
            return families.putIfAbsent(record.authorizationId(), record) == null ? 1 : 0;
        }

        @Override
        public int insertHistory(OAuthRefreshTokenHistoryRecord record) {
            calls.add("insertHistory");
            return history.putIfAbsent(record.tokenHash(), record) == null ? 1 : 0;
        }

        @Override
        public String findAuthorizationIdByTokenHash(String tokenHash) {
            calls.add("findAuthorizationIdByTokenHash");
            OAuthRefreshTokenHistoryRecord record = history.get(tokenHash);
            return record == null ? null : record.authorizationId();
        }

        @Override
        public OAuthRefreshTokenFamilyRecord findFamilyForUpdate(String authorizationId) {
            calls.add("findFamilyForUpdate");
            return families.get(authorizationId);
        }

        @Override
        public OAuthRefreshTokenHistoryRecord findHistoryForUpdate(
                String authorizationId,
                String tokenHash) {
            calls.add("findHistoryForUpdate");
            OAuthRefreshTokenHistoryRecord record = history.get(tokenHash);
            if (record == null || !record.authorizationId().equals(authorizationId)) {
                return null;
            }
            return record;
        }

        @Override
        public int rotateFamilyCas(
                String authorizationId,
                String expectedTokenHash,
                long expectedGeneration,
                String newTokenHash,
                long newGeneration,
                Instant issuedAt,
                Instant expiresAt,
                Instant now) {
            OAuthRefreshTokenFamilyRecord current = families.get(authorizationId);
            if (current == null
                    || !current.currentTokenHash().equals(expectedTokenHash)
                    || current.generation() != expectedGeneration
                    || current.revokedAt() != null
                    || !current.currentExpiresAt().isAfter(now)) {
                return 0;
            }
            families.put(authorizationId, new OAuthRefreshTokenFamilyRecord(
                    authorizationId,
                    newTokenHash,
                    newGeneration,
                    issuedAt,
                    expiresAt,
                    null,
                    null,
                    current.createdAt(),
                    now));
            return 1;
        }

        @Override
        public int consumeHistoryCas(
                String authorizationId,
                String tokenHash,
                long generation,
                Instant consumedAt) {
            OAuthRefreshTokenHistoryRecord current = history.get(tokenHash);
            if (current == null
                    || !current.authorizationId().equals(authorizationId)
                    || current.generation() != generation
                    || current.consumedAt() != null
                    || current.revokedAt() != null
                    || !current.expiresAt().isAfter(consumedAt)) {
                return 0;
            }
            history.put(tokenHash, new OAuthRefreshTokenHistoryRecord(
                    current.tokenHash(),
                    current.authorizationId(),
                    current.generation(),
                    current.issuedAt(),
                    current.expiresAt(),
                    consumedAt,
                    current.revokedAt(),
                    current.revokeReason(),
                    current.createdAt()));
            return 1;
        }

        @Override
        public int revokeFamily(String authorizationId, String reason, Instant revokedAt) {
            OAuthRefreshTokenFamilyRecord current = families.get(authorizationId);
            if (current == null) {
                return 0;
            }
            families.put(authorizationId, new OAuthRefreshTokenFamilyRecord(
                    current.authorizationId(),
                    current.currentTokenHash(),
                    current.generation(),
                    current.currentIssuedAt(),
                    current.currentExpiresAt(),
                    current.revokedAt() == null ? revokedAt : current.revokedAt(),
                    current.revokeReason() == null ? reason : current.revokeReason(),
                    current.createdAt(),
                    revokedAt));
            return 1;
        }

        @Override
        public int revokeHistory(String authorizationId, String reason, Instant revokedAt) {
            int[] updated = {0};
            history.replaceAll((hash, current) -> {
                if (!current.authorizationId().equals(authorizationId)) {
                    return current;
                }
                updated[0]++;
                return new OAuthRefreshTokenHistoryRecord(
                        current.tokenHash(),
                        current.authorizationId(),
                        current.generation(),
                        current.issuedAt(),
                        current.expiresAt(),
                        current.consumedAt(),
                        current.revokedAt() == null ? revokedAt : current.revokedAt(),
                        current.revokeReason() == null ? reason : current.revokeReason(),
                        current.createdAt());
            });
            return updated[0];
        }
    }
}
