package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionConfigurationValidatorTest {

    @Test
    void developmentModeDoesNotApplyProductionOnlyPolicy() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("web-starter.runtime.mode", "development");

        assertThatCode(() -> ProductionConfigurationValidator.validate(environment))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsExplicitHardenedProductionConfiguration() {
        assertThatCode(() -> ProductionConfigurationValidator.validate(productionEnvironment()))
                .doesNotThrowAnyException();
    }

    @Test
    void productionRequiresCanonicalReleaseCommitIdentity() {
        assertRejected("web-starter.runtime.git-commit", "local", "WEB_STARTER_GIT_COMMIT");
        assertRejected("web-starter.runtime.git-commit", "A".repeat(40), "WEB_STARTER_GIT_COMMIT");
        assertRejected("web-starter.runtime.git-commit", "a".repeat(39), "WEB_STARTER_GIT_COMMIT");

        assertThatCode(() -> ProductionConfigurationValidator.validate(
                productionEnvironment().withProperty(
                        "web-starter.runtime.git-commit", "a".repeat(64))))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsUnknownModeInsteadOfSilentlyFallingBackToDevelopment() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("web-starter.runtime.mode", "productions");

        assertThatThrownBy(() -> ProductionConfigurationValidator.validate(environment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("WEB_STARTER_RUNTIME_MODE");
    }

    @Test
    void rejectsHttpOrLocalIssuer() {
        assertRejected("web-starter.security.issuer", "http://localhost:8080",
                "WEB_STARTER_OAUTH_ISSUER");
    }

    @Test
    void rejectsInsecureCookieAndDevelopmentSigningKeys() {
        assertRejected("server.servlet.session.cookie.secure", "false",
                "WEB_STARTER_COOKIE_SECURE");
        assertRejected("web-starter.security.development-keys-allowed", "true",
                "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED");
    }

    @Test
    void rejectsEmptyOrPlaceholderSecretsWithoutEchoingTheirValue() {
        assertRejected("spring.datasource.password", "replace-with-database-password",
                "WEB_STARTER_DB_PASSWORD");
        assertRejected("spring.data.redis.password", "",
                "WEB_STARTER_REDIS_PASSWORD");
        assertRejected("web-starter.security.token-pepper", "replace-with-pepper",
                "WEB_STARTER_TOKEN_PEPPER");
        assertRejected("web-starter.security.credential-pepper", "replace-with-credential-pepper",
                "WEB_STARTER_CREDENTIAL_PEPPER");
    }

    @Test
    void acceptsTokenPepperFallbackForCredentialHashing() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("web-starter.security.credential-pepper", "");

        assertThatCode(() -> ProductionConfigurationValidator.validate(environment))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsIncompleteOrAmbiguousCredentialPepperRotation() {
        assertRejected(
                "web-starter.security.credential-pepper-retiring",
                "fedcba9876543210fedcba9876543210",
                "RETIRING_VERSION");
        assertRejected(
                "web-starter.security.credential-pepper-retiring-version",
                "v0",
                "configured together");

        MockEnvironment duplicateVersion = productionEnvironment()
                .withProperty("web-starter.security.credential-pepper-active-version", "v2")
                .withProperty("web-starter.security.credential-pepper-retiring",
                        "fedcba9876543210fedcba9876543210")
                .withProperty("web-starter.security.credential-pepper-retiring-version", "v2");
        assertThatThrownBy(() -> ProductionConfigurationValidator.validate(duplicateVersion))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("versions must differ");

        MockEnvironment duplicatePepper = productionEnvironment()
                .withProperty("web-starter.security.credential-pepper-active-version", "v2")
                .withProperty("web-starter.security.credential-pepper-retiring",
                        "0123456789abcdef0123456789abcdef")
                .withProperty("web-starter.security.credential-pepper-retiring-version", "v1");
        assertThatThrownBy(() -> ProductionConfigurationValidator.validate(duplicatePepper))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Peppers must differ");
    }

    @Test
    void rejectsInvalidCredentialPepperVersionWithoutEchoingSecretMaterial() {
        assertRejected(
                "web-starter.security.credential-pepper-active-version",
                "version with spaces",
                "ACTIVE_VERSION");
    }

    @Test
    void rejectsMissingPersistentRsaMaterial() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("web-starter.security.rsa-private-key", "")
                .withProperty("web-starter.security.rsa-public-key", "");

        assertThatThrownBy(() -> ProductionConfigurationValidator.validate(environment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("RSA JWK set or private/public PEM pair");
    }

    @Test
    void rejectsBroadOrLocalMcpTrustConfiguration() {
        assertRejected("web-starter.mcp.allowed-hosts", "*.example.internal",
                "MCP_ALLOWED_HOSTS");
        assertRejected("web-starter.mcp.allowed-hosts", "localhost:8443",
                "MCP_ALLOWED_HOSTS");
        assertRejected("web-starter.mcp.allowed-hosts", "mcp.localhost:8443",
                "MCP_ALLOWED_HOSTS");
        assertRejected("web-starter.mcp.allowed-origins", "https://*.example.internal",
                "MCP_ALLOWED_ORIGINS");
        assertRejected("web-starter.mcp.allowed-origins", "https://mcp.localhost:8443",
                "MCP_ALLOWED_ORIGINS");
        assertRejected("web-starter.mcp.allowed-origins", "http://agent.example.internal",
                "MCP_ALLOWED_ORIGINS");
    }

    @Test
    void rejectsDangerousProductionLogLevel() {
        assertRejected("logging.level.dev.webstarter", "DEBUG", "logging level");
    }

    @Test
    void requiresDedicatedStrongOperationalCredentials() {
        assertRejected("web-starter.management.security.username", "",
                "WEB_STARTER_MANAGEMENT_USERNAME");
        assertRejected("web-starter.management.security.username", "admin",
                "must differ");
        assertRejected("web-starter.management.security.password", "too-short",
                "WEB_STARTER_MANAGEMENT_PASSWORD");
        assertRejected(
                "web-starter.management.security.password",
                "0123456789abcdef0123456789abcdef",
                "must not reuse");
    }

    private static void assertRejected(String property, String value, String messageFragment) {
        MockEnvironment environment = productionEnvironment().withProperty(property, value);
        assertThatThrownBy(() -> ProductionConfigurationValidator.validate(environment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(messageFragment);
    }

    private static MockEnvironment productionEnvironment() {
        return new MockEnvironment()
                .withProperty("web-starter.runtime.mode", "production")
                .withProperty("web-starter.runtime.git-commit",
                        "0123456789abcdef0123456789abcdef01234567")
                .withProperty("web-starter.security.issuer", "https://auth.starter.example")
                .withProperty("web-starter.security.resource-audience",
                        "https://mcp.starter.example/mcp")
                .withProperty("server.servlet.session.cookie.secure", "true")
                .withProperty("web-starter.security.development-keys-allowed", "false")
                .withProperty("spring.datasource.password", "database-password-42")
                .withProperty("spring.data.redis.password", "redis-password-42")
                .withProperty("web-starter.security.token-pepper",
                        "0123456789abcdef0123456789abcdef")
                .withProperty("web-starter.bootstrap-admin.password", "")
                .withProperty("web-starter.bootstrap-admin.username", "admin")
                .withProperty("web-starter.management.security.username", "starter_ops")
                .withProperty("web-starter.management.security.password",
                        "operations-password-0123456789abcdef")
                .withProperty("web-starter.security.rsa-private-key", "persistent-private-key")
                .withProperty("web-starter.security.rsa-public-key", "persistent-public-key")
                .withProperty("web-starter.mcp.allowed-hosts", "mcp.starter.example:443")
                .withProperty("web-starter.mcp.allowed-origins", "https://agent.starter.example")
                .withProperty("logging.level.root", "INFO")
                .withProperty("logging.level.dev.webstarter", "INFO");
    }
}
