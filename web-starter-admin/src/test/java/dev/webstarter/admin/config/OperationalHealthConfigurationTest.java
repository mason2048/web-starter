package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;

class OperationalHealthConfigurationTest {

    private final OperationalHealthConfiguration configuration =
            new OperationalHealthConfiguration();

    @Test
    void reportsUpUsingAFiniteJdbcValidationTimeout() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(OperationalHealthConfiguration.DATABASE_VALIDATION_TIMEOUT_SECONDS))
                .thenReturn(true);

        Health health = indicator(dataSource).health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("validationQuery", "isValid(2)");
        verify(connection).close();
    }

    @Test
    void reportsDownWhenTheDatabaseCannotBeReached() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenThrow(new SQLException("database unavailable"));

        Health health = indicator(dataSource).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    }

    private HealthIndicator indicator(DataSource dataSource) {
        return configuration.dbHealthContributor(dataSource);
    }
}
