package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MapPropertySource;

class ProductionConfigurationInitializerTest {

    @Test
    void rejectsUnsafeProductionConfigurationBeforeContextRefresh() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource(
                    "unsafe-production",
                    Map.of(
                            "web-starter.runtime.mode", "production",
                            "web-starter.runtime.git-commit", "a".repeat(40),
                            "web-starter.security.issuer", "http://issuer.example.test")));

            assertThatThrownBy(() -> new ProductionConfigurationInitializer().initialize(context))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("WEB_STARTER_OAUTH_ISSUER");
        }
    }
}
