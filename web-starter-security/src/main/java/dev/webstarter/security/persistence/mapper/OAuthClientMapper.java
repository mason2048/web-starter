package dev.webstarter.security.persistence.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import dev.webstarter.security.persistence.model.OAuthClientRecord;

@Mapper
public interface OAuthClientMapper {

    @Insert("""
            INSERT INTO sec_oauth_client
                (id, client_id, client_secret_hash, client_name, authentication_methods,
                 grant_types, redirect_uris, scopes, require_consent, require_pkce,
                 service_account_id, enabled, created_at, updated_at)
            VALUES
                (#{id}, #{clientId}, #{clientSecretHash}, #{clientName}, #{authenticationMethods},
                 #{grantTypes}, #{redirectUris}, #{scopes}, #{requireConsent}, #{requirePkce},
                 #{serviceAccountId}, #{enabled}, #{createdAt}, #{updatedAt})
            """)
    int insert(OAuthClientRecord record);

    @Select("""
            SELECT id, client_id, client_secret_hash, client_name, authentication_methods,
                   grant_types, redirect_uris, scopes, require_consent, require_pkce,
                   service_account_id, enabled, created_at, updated_at
              FROM sec_oauth_client
             WHERE id = #{id}
            """)
    OAuthClientRecord findById(String id);

    @Select("""
            SELECT id, client_id, client_secret_hash, client_name, authentication_methods,
                   grant_types, redirect_uris, scopes, require_consent, require_pkce,
                   service_account_id, enabled, created_at, updated_at
              FROM sec_oauth_client
             WHERE client_id = #{clientId}
            """)
    OAuthClientRecord findByClientId(String clientId);

    @Select("""
            SELECT id, client_id, client_secret_hash, client_name, authentication_methods,
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
               SET client_secret_hash = #{clientSecretHash}, updated_at = CURRENT_TIMESTAMP(6)
             WHERE id = #{id}
            """)
    int updateSecret(String id, String clientSecretHash);
}
