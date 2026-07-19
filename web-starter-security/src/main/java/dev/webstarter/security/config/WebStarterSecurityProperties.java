package dev.webstarter.security.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("web-starter.security")
public record WebStarterSecurityProperties(
        String tokenPepper,
        String issuer,
        String resourceAudience,
        boolean internalTokensEnabled,
        boolean developmentKeysAllowed,
        String rsaPrivateKey,
        String rsaPublicKey,
        Duration accessTokenTtl,
        Duration refreshTokenTtl) {

    public WebStarterSecurityProperties {
        issuer = blankToDefault(issuer, "http://127.0.0.1:8080");
        resourceAudience = blankToDefault(resourceAudience, issuer + "/mcp");
        accessTokenTtl = accessTokenTtl == null ? Duration.ofMinutes(10) : accessTokenTtl;
        refreshTokenTtl = refreshTokenTtl == null ? Duration.ofHours(8) : refreshTokenTtl;
    }

    public String requiredTokenPepper() {
        if (tokenPepper == null || tokenPepper.length() < 32 || tokenPepper.startsWith("replace-with-")) {
            throw new IllegalStateException(
                    "WEB_STARTER_TOKEN_PEPPER must contain at least 32 characters");
        }
        return tokenPepper;
    }

    private static String blankToDefault(String value, String defaultValue) {
        return value == null || value.isBlank() ? defaultValue : value;
    }
}
