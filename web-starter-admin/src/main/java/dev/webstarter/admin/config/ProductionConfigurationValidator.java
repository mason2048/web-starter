package dev.webstarter.admin.config;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

/**
 * Validates production trust, transport, secret, and logging settings before
 * the application context creates infrastructure beans.
 */
public final class ProductionConfigurationValidator {

    private static final Set<String> MODES = Set.of("development", "test", "production");
    private static final Set<String> DANGEROUS_LOG_LEVELS =
            Set.of("ALL", "TRACE", "DEBUG");
    private static final Set<String> EXACT_PLACEHOLDERS = Set.of(
            "admin", "changeme", "change-me", "password", "secret", "web_starter");
    private static final String CREDENTIAL_PEPPER_VERSION_PATTERN =
            "[A-Za-z0-9][A-Za-z0-9._-]{0,31}";
    private static final String MANAGEMENT_USERNAME_PATTERN =
            "[A-Za-z0-9][A-Za-z0-9._-]{2,63}";
    private static final String GIT_REVISION_PATTERN =
            "[0-9a-f]{40}(?:[0-9a-f]{24})?";

    private ProductionConfigurationValidator() {
    }

    public static void validate(Environment environment) {
        String mode = normalized(environment.getProperty(
                "web-starter.runtime.mode", "development"));
        if (!MODES.contains(mode)) {
            throw unsafe("WEB_STARTER_RUNTIME_MODE must be development, test, or production");
        }
        if (!"production".equals(mode)) {
            return;
        }

        requireGitRevision(environment);

        requireHttpsNonLocalUri(environment, "web-starter.security.issuer",
                "WEB_STARTER_OAUTH_ISSUER");
        requireHttpsNonLocalUri(environment, "web-starter.security.resource-audience",
                "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE");

        if (!environment.getProperty(
                "server.servlet.session.cookie.secure", Boolean.class, false)) {
            throw unsafe("WEB_STARTER_COOKIE_SECURE must be true in production");
        }
        if (environment.getProperty(
                "web-starter.security.development-keys-allowed", Boolean.class, false)) {
            throw unsafe("WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED must be false in production");
        }

        requireSecret(environment, "spring.datasource.password",
                "WEB_STARTER_DB_PASSWORD", 12);
        requireSecret(environment, "spring.data.redis.password",
                "WEB_STARTER_REDIS_PASSWORD", 16);
        requireSecret(environment, "web-starter.security.token-pepper",
                "WEB_STARTER_TOKEN_PEPPER", 32);
        validateCredentialPepperRotation(environment);
        validateOptionalSecret(environment, "web-starter.bootstrap-admin.password",
                "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD", 12);
        validateOperationalCredentials(environment);
        requirePersistentSigningKeys(environment);

        validateAllowedHosts(stringList(environment, "web-starter.mcp.allowed-hosts"));
        validateAllowedOrigins(stringList(environment, "web-starter.mcp.allowed-origins"));
        validateLogLevels(environment);
    }

    private static void requireGitRevision(Environment environment) {
        String revision = environment.getProperty("web-starter.runtime.git-commit");
        if (!hasText(revision)
                || !revision.equals(revision.trim())
                || !revision.matches(GIT_REVISION_PATTERN)) {
            throw unsafe("WEB_STARTER_GIT_COMMIT must be an exact lowercase 40/64-character Git object id");
        }
    }

    private static void requireHttpsNonLocalUri(
            Environment environment, String property, String environmentName) {
        String raw = environment.getProperty(property);
        URI uri;
        try {
            uri = raw == null ? null : URI.create(raw.trim());
        }
        catch (IllegalArgumentException exception) {
            throw unsafe(environmentName + " must be a valid absolute HTTPS URI");
        }
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme())
                || !hasText(uri.getHost()) || isLocalHost(uri.getHost())
                || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw unsafe(environmentName + " must be a non-local absolute HTTPS URI");
        }
    }

    private static void requireSecret(
            Environment environment, String property, String environmentName, int minimumLength) {
        validateSecret(environment.getProperty(property), environmentName, minimumLength, false);
    }

    private static void validateOptionalSecret(
            Environment environment, String property, String environmentName, int minimumLength) {
        validateSecret(environment.getProperty(property), environmentName, minimumLength, true);
    }

    private static void validateCredentialPepperRotation(Environment environment) {
        String tokenPepper = environment.getProperty("web-starter.security.token-pepper");
        String activePepper = environment.getProperty("web-starter.security.credential-pepper");
        if (!hasText(activePepper)) {
            activePepper = tokenPepper;
        }
        else {
            validateSecret(activePepper, "WEB_STARTER_CREDENTIAL_PEPPER", 32, false);
        }

        String activeVersion = environment.getProperty(
                "web-starter.security.credential-pepper-active-version", "v1");
        validateCredentialPepperVersion(
                activeVersion, "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION");

        String retiringPepper = environment.getProperty(
                "web-starter.security.credential-pepper-retiring");
        String retiringVersion = environment.getProperty(
                "web-starter.security.credential-pepper-retiring-version");
        if (hasText(retiringPepper) != hasText(retiringVersion)) {
            throw unsafe("WEB_STARTER_CREDENTIAL_PEPPER_RETIRING and "
                    + "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION must be configured together");
        }
        if (!hasText(retiringPepper)) {
            return;
        }

        validateSecret(retiringPepper, "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING", 32, false);
        validateCredentialPepperVersion(
                retiringVersion, "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION");
        if (activeVersion.trim().equals(retiringVersion.trim())) {
            throw unsafe("active and retiring credential Pepper versions must differ");
        }
        if (activePepper.trim().equals(retiringPepper.trim())) {
            throw unsafe("active and retiring credential Peppers must differ");
        }
    }

    private static void validateOperationalCredentials(Environment environment) {
        String username = environment.getProperty("web-starter.management.security.username");
        if (!hasText(username) || !username.trim().matches(MANAGEMENT_USERNAME_PATTERN)) {
            throw unsafe("WEB_STARTER_MANAGEMENT_USERNAME must be a 3-64 character operational identifier");
        }
        String bootstrapUsername = environment.getProperty("web-starter.bootstrap-admin.username");
        if (hasText(bootstrapUsername)
                && normalized(username).equals(normalized(bootstrapUsername))) {
            throw unsafe("WEB_STARTER_MANAGEMENT_USERNAME must differ from the Web bootstrap administrator");
        }

        String password = environment.getProperty("web-starter.management.security.password");
        validateSecret(password, "WEB_STARTER_MANAGEMENT_PASSWORD", 32, false);
        for (String otherProperty : List.of(
                "spring.datasource.password",
                "spring.data.redis.password",
                "web-starter.security.token-pepper",
                "web-starter.security.credential-pepper",
                "web-starter.bootstrap-admin.password")) {
            String other = environment.getProperty(otherProperty);
            if (hasText(other) && password.trim().equals(other.trim())) {
                throw unsafe("WEB_STARTER_MANAGEMENT_PASSWORD must not reuse another application secret");
            }
        }
    }

    private static void validateCredentialPepperVersion(String value, String environmentName) {
        if (!hasText(value) || !value.trim().matches(CREDENTIAL_PEPPER_VERSION_PATTERN)) {
            throw unsafe(environmentName + " must be a non-secret version identifier");
        }
    }

    private static void validateSecret(
            String value, String environmentName, int minimumLength, boolean emptyAllowed) {
        if (!hasText(value)) {
            if (emptyAllowed) {
                return;
            }
            throw unsafe(environmentName + " must not be empty in production");
        }
        String normalized = normalized(value);
        if (value.trim().length() < minimumLength
                || normalized.startsWith("replace-with-")
                || EXACT_PLACEHOLDERS.contains(normalized)) {
            throw unsafe(environmentName + " contains a weak or placeholder value");
        }
    }

    private static void requirePersistentSigningKeys(Environment environment) {
        boolean hasJwkSet = hasText(environment.getProperty("web-starter.security.rsa-jwk-set"));
        boolean hasPemPair = hasText(environment.getProperty("web-starter.security.rsa-private-key"))
                && hasText(environment.getProperty("web-starter.security.rsa-public-key"));
        if (!hasJwkSet && !hasPemPair) {
            throw unsafe("production requires an injected RSA JWK set or private/public PEM pair");
        }
    }

    private static void validateAllowedHosts(List<String> hosts) {
        if (hosts.isEmpty()) {
            throw unsafe("WEB_STARTER_MCP_ALLOWED_HOSTS must explicitly list production hosts");
        }
        for (String host : hosts) {
            String candidate = host.trim();
            URI parsed;
            try {
                parsed = URI.create("https://" + candidate);
            }
            catch (IllegalArgumentException exception) {
                throw unsafe("WEB_STARTER_MCP_ALLOWED_HOSTS contains an invalid host");
            }
            if (!hasText(candidate) || candidate.contains("*") || candidate.contains("/")
                    || candidate.contains("://") || parsed.getUserInfo() != null
                    || !hasText(parsed.getHost()) || isLocalHost(parsed.getHost())) {
                throw unsafe("WEB_STARTER_MCP_ALLOWED_HOSTS must contain exact non-local hosts");
            }
        }
    }

    private static void validateAllowedOrigins(List<String> origins) {
        if (origins.isEmpty()) {
            throw unsafe("WEB_STARTER_MCP_ALLOWED_ORIGINS must explicitly list production origins");
        }
        for (String origin : origins) {
            URI uri;
            try {
                uri = URI.create(origin.trim());
            }
            catch (IllegalArgumentException exception) {
                throw unsafe("WEB_STARTER_MCP_ALLOWED_ORIGINS contains an invalid origin");
            }
            if (!"https".equalsIgnoreCase(uri.getScheme()) || !hasText(uri.getHost())
                    || isLocalHost(uri.getHost()) || origin.contains("*")
                    || uri.getUserInfo() != null || hasText(uri.getPath())
                    || uri.getQuery() != null || uri.getFragment() != null) {
                throw unsafe("WEB_STARTER_MCP_ALLOWED_ORIGINS must contain exact non-local HTTPS origins");
            }
        }
    }

    private static void validateLogLevels(Environment environment) {
        Map<String, String> levels = Binder.get(environment)
                .bind("logging.level", Bindable.mapOf(String.class, String.class))
                .orElse(Map.of());
        levels.forEach((logger, level) -> {
            if (level != null && DANGEROUS_LOG_LEVELS.contains(
                    level.trim().toUpperCase(Locale.ROOT))) {
                throw unsafe("production logging level must not be ALL, TRACE, or DEBUG");
            }
        });
    }

    private static List<String> stringList(Environment environment, String property) {
        List<String> bound = Binder.get(environment)
                .bind(property, Bindable.listOf(String.class))
                .orElse(List.of());
        if (!bound.isEmpty()) {
            return bound.stream().filter(ProductionConfigurationValidator::hasText)
                    .map(String::trim).toList();
        }
        String raw = environment.getProperty(property);
        if (!hasText(raw)) {
            return List.of();
        }
        return Arrays.stream(raw.split(","))
                .filter(ProductionConfigurationValidator::hasText)
                .map(String::trim)
                .toList();
    }

    private static boolean isLocalHost(String host) {
        String value = normalized(host);
        return "localhost".equals(value) || "0.0.0.0".equals(value)
                || "::".equals(value) || "::1".equals(value)
                || value.startsWith("127.") || value.endsWith(".localhost");
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static IllegalStateException unsafe(String message) {
        return new IllegalStateException("Unsafe production configuration: " + message);
    }
}
