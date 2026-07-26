package dev.webstarter.admin.config;

import java.sql.Connection;

import javax.sql.DataSource;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Bounded dependency checks used by the private readiness probe.
 *
 * <p>Spring Boot's default JDBC indicator calls {@code Connection.isValid(0)}.
 * JDBC defines zero as no timeout, so a half-open database connection can also
 * stall the probe that should remove the instance from service. The starter
 * deliberately uses a short, finite validation timeout instead.</p>
 */
@Configuration(proxyBeanMethods = false)
public class OperationalHealthConfiguration {

    static final int DATABASE_VALIDATION_TIMEOUT_SECONDS = 2;

    @Bean(name = "dbHealthContributor")
    HealthIndicator dbHealthContributor(DataSource dataSource) {
        return () -> databaseHealth(dataSource);
    }

    private static Health databaseHealth(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            boolean valid = connection.isValid(DATABASE_VALIDATION_TIMEOUT_SECONDS);
            Health.Builder health = valid ? Health.up() : Health.down();
            return health.withDetail(
                    "validationQuery",
                    "isValid(" + DATABASE_VALIDATION_TIMEOUT_SECONDS + ")")
                    .build();
        }
        catch (Exception exception) {
            return Health.down(exception).build();
        }
    }
}
