package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import java.util.stream.Collectors;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;

class OperationalMetricsConfigurationTest {

    @Test
    void registersCompleteBoundedSeriesBeforeFailureOrTrafficOccurs() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        new OperationalMetricsConfiguration().operationalMetricSeriesBinder().bindTo(registry);

        assertThat(tagValues(registry, "webstarter.audit.persist.failures", "type"))
                .containsExactlyInAnyOrder("login", "operation", "mcp");
        assertThat(tagValues(registry, "webstarter.protocol.requests", "endpoint"))
                .containsExactlyInAnyOrder("login", "oauth_token", "mcp");
        assertThat(tagValues(registry, "webstarter.mcp.rate_limited", "risk"))
                .containsExactlyInAnyOrder("read", "write", "destructive", "protocol");
        assertThat(tagValues(registry, "webstarter.mcp.sessions", "event"))
                .containsExactlyInAnyOrder(
                        "created", "deleted", "cleanup_failed", "limit_rejected",
                        "owner_mismatch", "expired", "not_found");
        assertThat(registry.find("webstarter.mcp.call.duration").timers()).hasSize(24);
        assertThat(registry.find("webstarter.protocol.requests").counters()).hasSize(60);

        assertThat(registry.getMeters()).allSatisfy(meter ->
                assertThat(meter.getId().getTags())
                        .noneMatch(tag -> Set.of(
                                "actor", "clientId", "credential", "ip", "principal",
                                "sessionId", "subject", "token", "traceId", "user"
                        ).contains(tag.getKey())));
    }

    private static Set<String> tagValues(
            SimpleMeterRegistry registry, String metric, String key) {
        return registry.find(metric).meters().stream()
                .map(Meter::getId)
                .flatMap(id -> id.getTags().stream())
                .filter(tag -> key.equals(tag.getKey()))
                .map(tag -> tag.getValue())
                .collect(Collectors.toSet());
    }
}
