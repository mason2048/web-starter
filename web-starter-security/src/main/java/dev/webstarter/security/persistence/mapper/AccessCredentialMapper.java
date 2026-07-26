package dev.webstarter.security.persistence.mapper;

import java.time.Instant;
import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.security.persistence.model.AccessCredentialRecord;

@Mapper
public interface AccessCredentialMapper {

    @Insert("""
            INSERT INTO sec_access_credential
                (id, credential_type, subject_id, subject_security_epoch, name, token_hash,
                 pepper_version, token_hint, scopes, ip_cidrs, expires_at, created_by, created_at)
            VALUES
                (#{id}, #{credentialType}, #{subjectId}, #{subjectSecurityEpoch}, #{name},
                 #{tokenHash}, #{pepperVersion}, #{tokenHint}, #{scopes}, #{ipCidrs}, #{expiresAt},
                 #{createdBy}, #{createdAt})
            """)
    int insert(AccessCredentialRecord record);

    @Select("""
            SELECT id, credential_type, subject_id, subject_security_epoch, name, token_hash, pepper_version,
                   token_hint, scopes, ip_cidrs, expires_at, revoked_at, revoked_reason,
                   last_used_at, created_by, created_at
              FROM sec_access_credential
             WHERE token_hash = #{tokenHash}
             LIMIT 1
            """)
    AccessCredentialRecord findByHash(String tokenHash);

    @Select("""
            SELECT id, credential_type, subject_id, subject_security_epoch, name, token_hash, pepper_version,
                   token_hint, scopes, ip_cidrs, expires_at, revoked_at, revoked_reason,
                   last_used_at, created_by, created_at
              FROM sec_access_credential
             WHERE pepper_version = #{pepperVersion}
               AND token_hash = #{tokenHash}
             LIMIT 1
            """)
    AccessCredentialRecord findByHashAndPepperVersion(
            @Param("tokenHash") String tokenHash,
            @Param("pepperVersion") String pepperVersion);

    @Select("""
            SELECT id, credential_type, subject_id, subject_security_epoch, name, token_hash, pepper_version,
                   token_hint, scopes, ip_cidrs, expires_at, revoked_at, revoked_reason,
                   last_used_at, created_by, created_at
              FROM sec_access_credential
             WHERE id = #{id}
            """)
    AccessCredentialRecord findById(Long id);

    @Select("""
            SELECT id, credential_type, subject_id, subject_security_epoch, name, token_hash, pepper_version,
                   token_hint, scopes, ip_cidrs, expires_at, revoked_at, revoked_reason,
                   last_used_at, created_by, created_at
              FROM sec_access_credential
             WHERE id = #{id}
             FOR UPDATE
            """)
    AccessCredentialRecord findByIdForUpdate(Long id);

    @Select("""
            SELECT id, credential_type, subject_id, subject_security_epoch, name, token_hash, pepper_version,
                   token_hint, scopes, ip_cidrs, expires_at, revoked_at, revoked_reason,
                   last_used_at, created_by, created_at
              FROM sec_access_credential
             WHERE subject_id = #{subjectId} AND credential_type = #{credentialType}
             ORDER BY id DESC
            """)
    List<AccessCredentialRecord> findBySubject(
            @Param("credentialType") String credentialType,
            @Param("subjectId") Long subjectId);

    @Update("""
            UPDATE sec_access_credential
               SET revoked_at = COALESCE(revoked_at, #{revokedAt}),
                   revoked_reason = COALESCE(revoked_reason, 'MANUAL')
             WHERE id = #{id}
            """)
    int revoke(@Param("id") Long id, @Param("revokedAt") Instant revokedAt);

    @Update("""
            UPDATE sec_access_credential
               SET revoked_at = COALESCE(revoked_at, #{revokedAt}),
                   revoked_reason = COALESCE(revoked_reason, #{reason})
             WHERE credential_type = #{credentialType}
               AND subject_id = #{subjectId}
               AND revoked_at IS NULL
            """)
    int revokeBySubject(
            @Param("credentialType") String credentialType,
            @Param("subjectId") Long subjectId,
            @Param("reason") String reason,
            @Param("revokedAt") Instant revokedAt);

    @Update("""
            UPDATE sec_access_credential
               SET last_used_at = #{lastUsedAt}
             WHERE id = #{id}
               AND (last_used_at IS NULL OR last_used_at < #{writeThreshold})
            """)
    int touchLastUsed(
            @Param("id") Long id,
            @Param("lastUsedAt") Instant lastUsedAt,
            @Param("writeThreshold") Instant writeThreshold);

    @Update("""
            UPDATE sec_access_credential
               SET token_hash = #{activeHash},
                   pepper_version = #{activePepperVersion}
             WHERE id = #{id}
               AND token_hash = #{retiringHash}
               AND pepper_version = #{retiringPepperVersion}
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > #{authenticatedAt})
            """)
    int migratePepper(
            @Param("id") Long id,
            @Param("retiringHash") String retiringHash,
            @Param("retiringPepperVersion") String retiringPepperVersion,
            @Param("activeHash") String activeHash,
            @Param("activePepperVersion") String activePepperVersion,
            @Param("authenticatedAt") Instant authenticatedAt);
}
