package dev.webstarter.admin.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import javax.sql.DataSource;

import com.baomidou.mybatisplus.core.MybatisSqlSessionFactoryBuilder;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import dev.webstarter.security.config.WebStarterSecurityProperties;
import dev.webstarter.security.oauth.DatabaseRegisteredClientRepository;
import dev.webstarter.security.oauth.OAuthClientManagementService;
import dev.webstarter.security.oauth.OAuthClientSecretPasswordEncoder;
import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.model.AccessCredentialRecord;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.token.AccessCredentialService;
import dev.webstarter.security.token.CredentialPepperKeyRing;
import dev.webstarter.security.token.CredentialScopePolicy;
import dev.webstarter.security.token.CredentialType;
import dev.webstarter.security.token.TokenHasher;

@Testcontainers
class CredentialRotationMySqlIT {

    @Container
    private static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");

    @Test
    void v1CompatibleRowsSurviveAppendOnlyRotationMigrationWithExplicitVersions() {
        Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword())
                .locations("classpath:db/migration")
                .target("6")
                .load()
                .migrate();
        DataSource dataSource = new org.springframework.jdbc.datasource.DriverManagerDataSource(
                MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword());
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        String credentialHash = "a".repeat(64);
        String clientHash = "$2a$12$" + "b".repeat(53);
        jdbc.update("""
                INSERT INTO sec_access_credential
                    (id, credential_type, subject_id, name, token_hash, token_hint, scopes,
                     created_by, created_at)
                VALUES (?, 'PERSONAL_ACCESS_TOKEN', ?, 'upgrade-fixture', ?, 'wst_pat_upgr',
                        'project:list', ?, CURRENT_TIMESTAMP(6))
                """, 9001L, 1L, credentialHash, 1L);
        jdbc.update("""
                INSERT INTO sec_oauth_client
                    (id, client_id, client_secret_hash, client_name, authentication_methods,
                     grant_types, redirect_uris, scopes, require_consent, require_pkce,
                     service_account_id, enabled, created_at, updated_at)
                VALUES ('upgrade-client-record', 'upgrade-client', ?, 'Upgrade fixture',
                        'client_secret_basic', 'client_credentials', '', 'project:list',
                        FALSE, TRUE, 1, TRUE, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6))
                """, clientHash);
        jdbc.update("""
                INSERT INTO sec_oauth_client
                    (id, client_id, client_secret_hash, client_name, authentication_methods,
                     grant_types, redirect_uris, scopes, require_consent, require_pkce,
                     service_account_id, enabled, created_at, updated_at)
                VALUES ('public-client-record', 'public-upgrade-client', NULL, 'Public fixture',
                        'none', 'authorization_code', 'https://agent.example/callback',
                        'project:list', TRUE, TRUE, NULL, TRUE,
                        CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6))
                """);

        Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();

        assertThat(jdbc.queryForObject(
                "SELECT pepper_version FROM sec_access_credential WHERE id = 9001",
                String.class)).isEqualTo("v1");
        assertThat(jdbc.queryForObject(
                "SELECT token_hash FROM sec_access_credential WHERE id = 9001",
                String.class)).isEqualTo(credentialHash);
        assertThat(jdbc.queryForObject(
                "SELECT client_secret_version FROM sec_oauth_client WHERE id = 'upgrade-client-record'",
                String.class)).isEqualTo("v1");
        assertThat(jdbc.queryForObject(
                "SELECT client_secret_hash FROM sec_oauth_client WHERE id = 'upgrade-client-record'",
                String.class)).isEqualTo(clientHash);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM sec_oauth_client WHERE id = 'public-client-record' "
                        + "AND client_secret_version IS NULL",
                Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history WHERE success = TRUE AND version = '7'",
                Integer.class)).isEqualTo(1);

        verifyRealMapperPepperMigration(dataSource, jdbc);
        verifyRealMapperOAuthOverlapAndRevocation(dataSource, jdbc);
    }

    private static void verifyRealMapperPepperMigration(DataSource dataSource, JdbcTemplate jdbc) {
        String rawToken = "wst_pat_" + "rotation-safe-value".repeat(3);
        String retiringPepper = "0123456789abcdef0123456789abcdef";
        String activePepper = "abcdef0123456789abcdef0123456789";
        WebStarterSecurityProperties properties = properties(activePepper, retiringPepper);
        CredentialPepperKeyRing ring = CredentialPepperKeyRing.from(properties);
        try (SqlSession session = sessionFactory(dataSource, AccessCredentialMapper.class).openSession(false)) {
            AccessCredentialMapper mapper = session.getMapper(AccessCredentialMapper.class);
            mapper.insert(new AccessCredentialRecord(
                    9002L, CredentialType.PERSONAL_ACCESS_TOKEN, 1L, 0,
                    "rotation-fixture", new TokenHasher(retiringPepper).hash(rawToken), "v1",
                    "wst_pat_rotat", "project:list", null,
                    Instant.parse("2099-01-01T00:00:00Z"), null, null, null, 1L,
                    Instant.parse("2026-07-19T03:00:00Z")));
            AccessCredentialService service = new AccessCredentialService(
                    mapper, ring, mock(CredentialScopePolicy.class), null);

            AccessCredentialRecord authenticated = service.findActiveByRawToken(rawToken, "10.0.0.8");
            session.commit();

            assertThat(authenticated).isNotNull();
            assertThat(authenticated.pepperVersion()).isEqualTo("v2");
            assertThat(jdbc.queryForObject(
                    "SELECT pepper_version FROM sec_access_credential WHERE id = 9002",
                    String.class)).isEqualTo("v2");
            assertThat(jdbc.queryForObject(
                    "SELECT token_hash FROM sec_access_credential WHERE id = 9002",
                    String.class))
                    .isEqualTo(new TokenHasher(activePepper).hash(rawToken))
                    .doesNotContain(rawToken);
        }
    }

    private static void verifyRealMapperOAuthOverlapAndRevocation(DataSource dataSource, JdbcTemplate jdbc) {
        String initialRaw = "initial-oauth-secret-for-mysql-it";
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(4);
        OAuthClientSecretPasswordEncoder secretEncoder = new OAuthClientSecretPasswordEncoder(bcrypt);
        WebStarterSecurityProperties properties = properties(
                "abcdef0123456789abcdef0123456789",
                "0123456789abcdef0123456789abcdef");
        try (SqlSession session = sessionFactory(dataSource, OAuthClientMapper.class).openSession(false)) {
            OAuthClientMapper mapper = session.getMapper(OAuthClientMapper.class);
            Instant now = Instant.now();
            OAuthClientRecord record = new OAuthClientRecord(
                    "rotation-client-record", "rotation-client", bcrypt.encode(initialRaw), "v1",
                    null, null, null, null, "Rotation client", "client_secret_basic",
                    "client_credentials", "", "project:list", false, true, 1L, true, now, now);
            mapper.insert(record);
            OAuthClientManagementService management = new OAuthClientManagementService(
                    mapper, secretEncoder, mock(CredentialScopePolicy.class), properties);

            var rotated = management.rotateSecret(record.id(), Duration.ofMinutes(5));
            session.commit();

            ClientSecretAuthenticationProvider provider = new ClientSecretAuthenticationProvider(
                    new DatabaseRegisteredClientRepository(mapper, properties),
                    mock(OAuth2AuthorizationService.class));
            provider.setPasswordEncoder(secretEncoder);
            assertThat(provider.authenticate(clientAuthentication(record.clientId(), initialRaw)).isAuthenticated())
                    .isTrue();
            assertThat(provider.authenticate(
                    clientAuthentication(record.clientId(), rotated.rawSecret())).isAuthenticated()).isTrue();
            assertThat(jdbc.queryForObject(
                    "SELECT retiring_client_secret_expires_at IS NOT NULL "
                            + "FROM sec_oauth_client WHERE id = 'rotation-client-record'",
                    Boolean.class)).isTrue();
            assertThat(jdbc.queryForObject(
                    "SELECT client_secret_hash FROM sec_oauth_client WHERE id = 'rotation-client-record'",
                    String.class)).doesNotContain(rotated.rawSecret()).doesNotContain(initialRaw);

            management.revokeRetiringSecret(record.id());
            session.commit();

            assertThatThrownBy(() -> provider.authenticate(
                    clientAuthentication(record.clientId(), initialRaw)))
                    .isInstanceOf(OAuth2AuthenticationException.class);
            assertThat(provider.authenticate(
                    clientAuthentication(record.clientId(), rotated.rawSecret())).isAuthenticated()).isTrue();
            assertThat(jdbc.queryForObject(
                    "SELECT COUNT(*) FROM sec_oauth_client WHERE id = 'rotation-client-record' "
                            + "AND retiring_client_secret_hash IS NULL "
                            + "AND retiring_client_secret_expires_at IS NULL",
                    Integer.class)).isEqualTo(1);
        }
    }

    private static OAuth2ClientAuthenticationToken clientAuthentication(String clientId, String rawSecret) {
        return new OAuth2ClientAuthenticationToken(
                clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, rawSecret, Map.of());
    }

    private static WebStarterSecurityProperties properties(String activePepper, String retiringPepper) {
        return new WebStarterSecurityProperties(
                retiringPepper, "https://auth.example.internal", "https://api.example.internal/mcp",
                true, false, null, null, null, null,
                Duration.ofMinutes(10), Duration.ofHours(8),
                activePepper, "v2", retiringPepper, "v1",
                Duration.ofMinutes(15), Duration.ofHours(24));
    }

    private static SqlSessionFactory sessionFactory(DataSource dataSource, Class<?> mapperType) {
        Environment environment = new Environment("credential-rotation-it", new JdbcTransactionFactory(), dataSource);
        com.baomidou.mybatisplus.core.MybatisConfiguration configuration =
                new com.baomidou.mybatisplus.core.MybatisConfiguration(environment);
        configuration.setMapUnderscoreToCamelCase(true);
        configuration.addMapper(mapperType);
        return new MybatisSqlSessionFactoryBuilder().build(configuration);
    }
}
