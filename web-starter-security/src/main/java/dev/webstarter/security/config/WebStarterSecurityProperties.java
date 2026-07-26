package dev.webstarter.security.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties("web-starter.security")
public record WebStarterSecurityProperties(
        String tokenPepper,
        String issuer,
        String resourceAudience,
        boolean internalTokensEnabled,
        boolean developmentKeysAllowed,
        String rsaPrivateKey,
        String rsaPublicKey,
        String rsaJwkSet,
        String rsaActiveKeyId,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String credentialPepper,
        String credentialPepperActiveVersion,
        String credentialPepperRetiring,
        String credentialPepperRetiringVersion,
        Duration oauthClientSecretOverlap,
        Duration oauthClientSecretMaxOverlap) {

    @ConstructorBinding
    public WebStarterSecurityProperties {
        issuer = blankToDefault(issuer, "http://127.0.0.1:8080");
        resourceAudience = blankToDefault(resourceAudience, issuer + "/mcp");
        accessTokenTtl = accessTokenTtl == null ? Duration.ofMinutes(10) : accessTokenTtl;
        refreshTokenTtl = refreshTokenTtl == null ? Duration.ofHours(8) : refreshTokenTtl;
        credentialPepperActiveVersion = blankToDefault(credentialPepperActiveVersion, "v1");
        oauthClientSecretOverlap = oauthClientSecretOverlap == null
                ? Duration.ofMinutes(15) : oauthClientSecretOverlap;
        oauthClientSecretMaxOverlap = oauthClientSecretMaxOverlap == null
                ? Duration.ofHours(24) : oauthClientSecretMaxOverlap;
        if (oauthClientSecretOverlap.isNegative() || oauthClientSecretOverlap.isZero()) {
            throw new IllegalArgumentException("OAuth client secret overlap must be positive");
        }
        if (oauthClientSecretMaxOverlap.isNegative() || oauthClientSecretMaxOverlap.isZero()
                || oauthClientSecretOverlap.compareTo(oauthClientSecretMaxOverlap) > 0) {
            throw new IllegalArgumentException(
                    "OAuth client secret maximum overlap must be positive and not shorter than the default overlap");
        }
    }

    public WebStarterSecurityProperties(
            String tokenPepper,
            String issuer,
            String resourceAudience,
            boolean internalTokensEnabled,
            boolean developmentKeysAllowed,
            String rsaPrivateKey,
            String rsaPublicKey,
            Duration accessTokenTtl,
            Duration refreshTokenTtl) {
        this(tokenPepper, issuer, resourceAudience, internalTokensEnabled,
                developmentKeysAllowed, rsaPrivateKey, rsaPublicKey, null, null,
                accessTokenTtl, refreshTokenTtl, null, null, null, null, null, null);
    }

    public WebStarterSecurityProperties(
            String tokenPepper,
            String issuer,
            String resourceAudience,
            boolean internalTokensEnabled,
            boolean developmentKeysAllowed,
            String rsaPrivateKey,
            String rsaPublicKey,
            String rsaJwkSet,
            String rsaActiveKeyId,
            Duration accessTokenTtl,
            Duration refreshTokenTtl) {
        this(tokenPepper, issuer, resourceAudience, internalTokensEnabled,
                developmentKeysAllowed, rsaPrivateKey, rsaPublicKey, rsaJwkSet, rsaActiveKeyId,
                accessTokenTtl, refreshTokenTtl, null, null, null, null, null, null);
    }

    public String requiredTokenPepper() {
        if (tokenPepper == null || tokenPepper.length() < 32 || tokenPepper.startsWith("replace-with-")) {
            throw new IllegalStateException(
                    "WEB_STARTER_TOKEN_PEPPER must contain at least 32 characters");
        }
        return tokenPepper;
    }

    public String requiredCredentialPepper() {
        String value = credentialPepper == null || credentialPepper.isBlank()
                ? tokenPepper : credentialPepper;
        if (value == null || value.length() < 32 || value.startsWith("replace-with-")) {
            throw new IllegalStateException(
                    "WEB_STARTER_CREDENTIAL_PEPPER (or WEB_STARTER_TOKEN_PEPPER fallback) "
                            + "must contain at least 32 characters");
        }
        return value;
    }

    private static String blankToDefault(String value, String defaultValue) {
        return value == null || value.isBlank() ? defaultValue : value;
    }
}
