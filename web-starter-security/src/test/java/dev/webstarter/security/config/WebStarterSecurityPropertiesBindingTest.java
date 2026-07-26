package dev.webstarter.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import dev.webstarter.security.login.LoginRateLimitProperties;

class WebStarterSecurityPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfiguration.class);

    @Test
    void bindsCanonicalRecordConstructorWhenConvenienceConstructorsExist() {
        contextRunner.withPropertyValues(
                        "web-starter.security.token-pepper=0123456789abcdef0123456789abcdef",
                        "web-starter.security.issuer=https://identity.example.internal",
                        "web-starter.security.resource-audience=https://api.example.internal/mcp",
                        "web-starter.security.internal-tokens-enabled=true",
                        "web-starter.security.rsa-active-key-id=rotation-key",
                        "web-starter.security.access-token-ttl=7m",
                        "web-starter.security.refresh-token-ttl=12h",
                        "web-starter.security.credential-pepper-active-version=v2",
                        "web-starter.security.oauth-client-secret-overlap=20m",
                        "web-starter.security.oauth-client-secret-max-overlap=2h")
                .run(context -> {
                    assertThat(context).hasSingleBean(WebStarterSecurityProperties.class);
                    WebStarterSecurityProperties properties =
                            context.getBean(WebStarterSecurityProperties.class);
                    assertThat(properties.issuer()).isEqualTo("https://identity.example.internal");
                    assertThat(properties.resourceAudience())
                            .isEqualTo("https://api.example.internal/mcp");
                    assertThat(properties.internalTokensEnabled()).isTrue();
                    assertThat(properties.rsaActiveKeyId()).isEqualTo("rotation-key");
                    assertThat(properties.accessTokenTtl()).isEqualTo(Duration.ofMinutes(7));
                    assertThat(properties.refreshTokenTtl()).isEqualTo(Duration.ofHours(12));
                    assertThat(properties.credentialPepperActiveVersion()).isEqualTo("v2");
                    assertThat(properties.oauthClientSecretOverlap()).isEqualTo(Duration.ofMinutes(20));
                    assertThat(properties.oauthClientSecretMaxOverlap()).isEqualTo(Duration.ofHours(2));
                });
    }

    @Test
    void bindsNestedLoginRateLimitCanonicalConstructor() {
        contextRunner.withPropertyValues(
                        "web-starter.security.login-rate-limit.enabled=true",
                        "web-starter.security.login-rate-limit.max-failures-per-identity=7",
                        "web-starter.security.login-rate-limit.max-failures-per-pair=4",
                        "web-starter.security.login-rate-limit.window=12m",
                        "web-starter.security.login-rate-limit.initial-backoff=3s",
                        "web-starter.security.login-rate-limit.max-backoff=20m")
                .run(context -> {
                    assertThat(context).hasSingleBean(LoginRateLimitProperties.class);
                    LoginRateLimitProperties properties =
                            context.getBean(LoginRateLimitProperties.class);
                    assertThat(properties.enabled()).isTrue();
                    assertThat(properties.maxFailuresPerIdentity()).isEqualTo(7);
                    assertThat(properties.maxFailuresPerPair()).isEqualTo(4);
                    assertThat(properties.window()).isEqualTo(Duration.ofMinutes(12));
                    assertThat(properties.initialBackoff()).isEqualTo(Duration.ofSeconds(3));
                    assertThat(properties.maxBackoff()).isEqualTo(Duration.ofMinutes(20));
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties({
            WebStarterSecurityProperties.class,
            LoginRateLimitProperties.class
    })
    static class TestConfiguration {
    }
}
