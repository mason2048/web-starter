package dev.webstarter.security.persistence.mapper;

import java.util.List;
import java.time.Instant;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.security.persistence.model.OAuthClientRecord;

@Mapper
public interface OAuthClientMapper {

    @Insert("""
            INSERT INTO sec_oauth_client
                (id, client_id, client_secret_hash, client_secret_version,
                 retiring_client_secret_hash, retiring_client_secret_version,
                 retiring_client_secret_expires_at, client_secret_rotated_at,
                 client_name, authentication_methods,
                 grant_types, redirect_uris, scopes, require_consent, require_pkce,
                 service_account_id, enabled, created_at, updated_at)
            VALUES
                (#{id}, #{clientId}, #{clientSecretHash}, #{clientSecretVersion},
                 #{retiringClientSecretHash}, #{retiringClientSecretVersion},
                 #{retiringClientSecretExpiresAt}, #{clientSecretRotatedAt},
                 #{clientName}, #{authenticationMethods},
                 #{grantTypes}, #{redirectUris}, #{scopes}, #{requireConsent}, #{requirePkce},
                 #{serviceAccountId}, #{enabled}, #{createdAt}, #{updatedAt})
            """)
    int insert(OAuthClientRecord record);

    @Select("""
            SELECT id, client_id, client_secret_hash, client_secret_version,
                   retiring_client_secret_hash, retiring_client_secret_version,
                   retiring_client_secret_expires_at, client_secret_rotated_at,
                   client_name, authentication_methods,
                   grant_types, redirect_uris, scopes, require_consent, require_pkce,
                   service_account_id, enabled, created_at, updated_at
              FROM sec_oauth_client
             WHERE id = #{id}
            """)
    OAuthClientRecord findById(String id);

    @Select("""
            SELECT id, client_id, client_secret_hash, client_secret_version,
                   retiring_client_secret_hash, retiring_client_secret_version,
                   retiring_client_secret_expires_at, client_secret_rotated_at,
                   client_name, authentication_methods,
                   grant_types, redirect_uris, scopes, require_consent, require_pkce,
                   service_account_id, enabled, created_at, updated_at
              FROM sec_oauth_client
             WHERE client_id = #{clientId}
            """)
    OAuthClientRecord findByClientId(String clientId);

    @Select("""
            SELECT id, client_id, client_secret_hash, client_secret_version,
                   retiring_client_secret_hash, retiring_client_secret_version,
                   retiring_client_secret_expires_at, client_secret_rotated_at,
                   client_name, authentication_methods,
                   grant_types, redirect_uris, scopes, require_consent, require_pkce,
                   service_account_id, enabled, created_at, updated_at
              FROM sec_oauth_client
             ORDER BY client_id
            """)
    List<OAuthClientRecord> findAll();

    @Update("""
            UPDATE sec_oauth_client
               SET client_name = #{clientName}, authentication_methods = #{authenticationMethods},
                   grant_types = #{grantTypes}, redirect_uris = #{redirectUris}, scopes = #{scopes},
                   require_consent = #{requireConsent}, require_pkce = #{requirePkce},
                   service_account_id = #{serviceAccountId}, enabled = #{enabled},
                   updated_at = #{updatedAt}
             WHERE id = #{id}
            """)
    int update(OAuthClientRecord record);

    @Update("""
            UPDATE sec_oauth_client
               SET retiring_client_secret_hash = client_secret_hash,
                   retiring_client_secret_version = client_secret_version,
                   retiring_client_secret_expires_at = #{retiringExpiresAt},
                   client_secret_hash = #{newSecretHash},
                   client_secret_version = #{newSecretVersion},
                   client_secret_rotated_at = #{rotatedAt},
                   updated_at = #{rotatedAt}
             WHERE id = #{id}
               AND client_secret_hash = #{expectedSecretHash}
               AND client_secret_version = #{expectedSecretVersion}
            """)
    int rotateSecret(
            @Param("id") String id,
            @Param("expectedSecretHash") String expectedSecretHash,
            @Param("expectedSecretVersion") String expectedSecretVersion,
            @Param("newSecretHash") String newSecretHash,
            @Param("newSecretVersion") String newSecretVersion,
            @Param("retiringExpiresAt") Instant retiringExpiresAt,
            @Param("rotatedAt") Instant rotatedAt);

    @Update("""
            UPDATE sec_oauth_client
               SET retiring_client_secret_hash = NULL,
                   retiring_client_secret_version = NULL,
                   retiring_client_secret_expires_at = NULL,
                   updated_at = #{revokedAt}
             WHERE id = #{id}
               AND retiring_client_secret_hash = #{expectedRetiringSecretHash}
               AND retiring_client_secret_version = #{expectedRetiringSecretVersion}
            """)
    int revokeRetiringSecret(
            @Param("id") String id,
            @Param("expectedRetiringSecretHash") String expectedRetiringSecretHash,
            @Param("expectedRetiringSecretVersion") String expectedRetiringSecretVersion,
            @Param("revokedAt") Instant revokedAt);
}
