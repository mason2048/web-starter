package dev.webstarter.security.persistence.mapper;

import java.time.Instant;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.security.persistence.model.OAuthRefreshTokenFamilyRecord;
import dev.webstarter.security.persistence.model.OAuthRefreshTokenHistoryRecord;

@Mapper
public interface OAuthRefreshTokenFamilyMapper {

    @Insert("""
            INSERT INTO sec_oauth_refresh_family
                (authorization_id, current_token_hash, generation, current_issued_at,
                 current_expires_at, created_at, updated_at)
            VALUES
                (#{record.authorizationId}, #{record.currentTokenHash}, #{record.generation},
                 #{record.currentIssuedAt}, #{record.currentExpiresAt}, #{record.createdAt},
                 #{record.updatedAt})
            """)
    int insertFamily(@Param("record") OAuthRefreshTokenFamilyRecord record);

    @Insert("""
            INSERT INTO sec_oauth_refresh_history
                (token_hash, authorization_id, generation, issued_at, expires_at, consumed_at,
                 revoked_at, revoke_reason, created_at)
            VALUES
                (#{record.tokenHash}, #{record.authorizationId}, #{record.generation},
                 #{record.issuedAt}, #{record.expiresAt}, #{record.consumedAt},
                 #{record.revokedAt}, #{record.revokeReason}, #{record.createdAt})
            """)
    int insertHistory(@Param("record") OAuthRefreshTokenHistoryRecord record);

    /**
     * Resolves the immutable family identity without acquiring a row lock. The
     * caller must lock the family before locking the matching history row.
     */
    @Select("""
            SELECT authorization_id
              FROM sec_oauth_refresh_history
             WHERE token_hash = #{tokenHash}
            """)
    String findAuthorizationIdByTokenHash(@Param("tokenHash") String tokenHash);

    @Select("""
            SELECT authorization_id, current_token_hash, generation, current_issued_at,
                   current_expires_at, revoked_at, revoke_reason, created_at, updated_at
             FROM sec_oauth_refresh_family
             WHERE authorization_id = #{authorizationId}
             FOR UPDATE
            """)
    OAuthRefreshTokenFamilyRecord findFamilyForUpdate(
            @Param("authorizationId") String authorizationId);

    @Select("""
            SELECT token_hash, authorization_id, generation, issued_at, expires_at,
                   consumed_at, revoked_at, revoke_reason, created_at
              FROM sec_oauth_refresh_history
             WHERE authorization_id = #{authorizationId}
               AND token_hash = #{tokenHash}
             FOR UPDATE
            """)
    OAuthRefreshTokenHistoryRecord findHistoryForUpdate(
            @Param("authorizationId") String authorizationId,
            @Param("tokenHash") String tokenHash);

    @Update("""
            UPDATE sec_oauth_refresh_family
               SET current_token_hash = #{newTokenHash},
                   generation = #{newGeneration},
                   current_issued_at = #{issuedAt},
                   current_expires_at = #{expiresAt},
                   updated_at = #{now}
             WHERE authorization_id = #{authorizationId}
               AND current_token_hash = #{expectedTokenHash}
               AND generation = #{expectedGeneration}
               AND revoked_at IS NULL
               AND current_expires_at > #{now}
            """)
    int rotateFamilyCas(
            @Param("authorizationId") String authorizationId,
            @Param("expectedTokenHash") String expectedTokenHash,
            @Param("expectedGeneration") long expectedGeneration,
            @Param("newTokenHash") String newTokenHash,
            @Param("newGeneration") long newGeneration,
            @Param("issuedAt") Instant issuedAt,
            @Param("expiresAt") Instant expiresAt,
            @Param("now") Instant now);

    @Update("""
            UPDATE sec_oauth_refresh_history
               SET consumed_at = #{consumedAt}
             WHERE authorization_id = #{authorizationId}
               AND token_hash = #{tokenHash}
               AND generation = #{generation}
               AND consumed_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > #{consumedAt}
            """)
    int consumeHistoryCas(
            @Param("authorizationId") String authorizationId,
            @Param("tokenHash") String tokenHash,
            @Param("generation") long generation,
            @Param("consumedAt") Instant consumedAt);

    @Update("""
            UPDATE sec_oauth_refresh_family
               SET revoke_reason = COALESCE(revoke_reason, #{reason}),
                   revoked_at = COALESCE(revoked_at, #{revokedAt}),
                   updated_at = #{revokedAt}
             WHERE authorization_id = #{authorizationId}
            """)
    int revokeFamily(
            @Param("authorizationId") String authorizationId,
            @Param("reason") String reason,
            @Param("revokedAt") Instant revokedAt);

    @Update("""
            UPDATE sec_oauth_refresh_history
               SET revoke_reason = COALESCE(revoke_reason, #{reason}),
                   revoked_at = COALESCE(revoked_at, #{revokedAt})
             WHERE authorization_id = #{authorizationId}
            """)
    int revokeHistory(
            @Param("authorizationId") String authorizationId,
            @Param("reason") String reason,
            @Param("revokedAt") Instant revokedAt);
}
