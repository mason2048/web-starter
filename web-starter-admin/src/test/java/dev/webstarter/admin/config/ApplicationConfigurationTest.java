package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisProperties;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

class ApplicationConfigurationTest {

    @Test
    void usesTheSpringBoot4RedisSessionNamespace() throws IOException {
        StandardEnvironment environment = applicationEnvironment();

        SessionDataRedisProperties properties = Binder.get(environment)
                .bind("spring.session.data.redis", SessionDataRedisProperties.class)
                .orElseThrow(() -> new AssertionError("Redis session properties are not bound"));

        assertThat(properties.getNamespace()).isEqualTo("web-starter:session");
        assertThat(properties.getFlushMode().name()).isEqualTo("ON_SAVE");
        assertThat(properties.getRepositoryType().name()).isEqualTo("INDEXED");
    }

    @Test
    void boundsDatabasePoolAcquisitionAndValidationForReadiness() throws IOException {
        StandardEnvironment environment = applicationEnvironment();

        assertThat(environment.getProperty(
                "spring.datasource.hikari.connection-timeout", Long.class)).isEqualTo(5000L);
        assertThat(environment.getProperty(
                "spring.datasource.hikari.validation-timeout", Long.class)).isEqualTo(2000L);
    }

    @Test
    void keepsOperationalAuthenticationDisabledByDefault() throws IOException {
        StandardEnvironment environment = applicationEnvironment();

        assertThat(environment.getProperty("web-starter.management.security.username"))
                .isEmpty();
        assertThat(environment.getProperty("web-starter.management.security.password"))
                .isEmpty();
        assertThat(environment.getProperty("management.endpoints.web.exposure.include"))
                .isEqualTo("health,info,metrics,prometheus");
    }

    @Test
    void providesOnlyAnExplicitLocalRevisionFallbackForDevelopment() throws IOException {
        StandardEnvironment environment = applicationEnvironment();

        assertThat(environment.getProperty("web-starter.runtime.git-commit"))
                .isEqualTo("local");
    }

    @Test
    void boundsGracefulShutdownSoRestartCanCompleteInsideTheGovernanceWindow() throws IOException {
        StandardEnvironment environment = applicationEnvironment();

        assertThat(environment.getProperty("server.shutdown")).isEqualTo("graceful");
        assertThat(environment.getProperty("spring.lifecycle.timeout-per-shutdown-phase"))
                .isEqualTo("10s");
    }

    private static StandardEnvironment applicationEnvironment() throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("application", new ClassPathResource("application.yml"));
        for (PropertySource<?> source : sources) {
            environment.getPropertySources().addLast(source);
        }
        return environment;
    }
}
