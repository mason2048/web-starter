package dev.webstarter.security.persistence.mapper;

import java.time.Instant;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.security.persistence.model.OAuthTokenRegistryRecord;

@Mapper
public interface OAuthTokenRegistryMapper {

    @Insert("""
            INSERT INTO sec_oauth_token_registry
                (id, jti_hash, authorization_id, token_type, subject_type, subject_id,
                 principal_name, client_id, scopes, issued_at, expires_at, created_at)
            VALUES
                (#{id}, #{jtiHash}, #{authorizationId}, #{tokenType}, #{subjectType}, #{subjectId},
                 #{principalName}, #{clientId}, #{scopes}, #{issuedAt}, #{expiresAt}, #{createdAt})
            ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at), scopes = VALUES(scopes)
            """)
    int upsert(OAuthTokenRegistryRecord record);

    @Select("""
            SELECT id, jti_hash, authorization_id, token_type, subject_type, subject_id,
                   principal_name, client_id, scopes, issued_at, expires_at, revoked_at, created_at
              FROM sec_oauth_token_registry
             WHERE jti_hash = #{jtiHash}
            """)
    OAuthTokenRegistryRecord findByJtiHash(String jtiHash);

    @Update("""
            UPDATE sec_oauth_token_registry
               SET revoked_at = COALESCE(revoked_at, #{revokedAt})
             WHERE jti_hash = #{jtiHash}
            """)
    int revokeByJtiHash(
            @Param("jtiHash") String jtiHash,
            @Param("revokedAt") Instant revokedAt);

    @Update("""
            UPDATE sec_oauth_token_registry
               SET revoked_at = COALESCE(revoked_at, #{revokedAt})
             WHERE authorization_id = #{authorizationId}
            """)
    int revokeAuthorization(
            @Param("authorizationId") String authorizationId,
            @Param("revokedAt") Instant revokedAt);

    @Update("""
            UPDATE sec_oauth_token_registry
               SET revoked_at = COALESCE(revoked_at, #{revokedAt})
             WHERE authorization_id = #{authorizationId}
               AND token_type = 'ACCESS_TOKEN'
               AND jti_hash <> #{currentJtiHash}
            """)
    int revokeOtherAccessTokens(
            @Param("authorizationId") String authorizationId,
            @Param("currentJtiHash") String currentJtiHash,
            @Param("revokedAt") Instant revokedAt);

    @Update("""
            UPDATE sec_oauth_token_registry
               SET revoked_at = COALESCE(revoked_at, #{revokedAt})
             WHERE subject_type = 'SERVICE_ACCOUNT'
               AND subject_id = #{subjectId}
               AND token_type = 'ACCESS_TOKEN'
            """)
    int revokeServiceAccountAccessTokens(
            @Param("subjectId") Long subjectId,
            @Param("revokedAt") Instant revokedAt);
}
