package dev.webstarter.admin.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.MeterBinder;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Registers every bounded operational metric series before the first event occurs. */
@Configuration(proxyBeanMethods = false)
public class OperationalMetricsConfiguration {

    private static final String[] RESULTS = {"SUCCESS", "FAILED", "OTHER"};
    private static final String[] TOOLS = {
            "system.info", "project.list", "project.get", "project.create",
            "project.update", "project.remove", "audit.list", "unknown"
    };

    @Bean
    MeterBinder operationalMetricSeriesBinder() {
        return registry -> {
            registerAuditMetrics(registry);
            registerMcpMetrics(registry);
            registerProtocolMetrics(registry);
        };
    }

    private static void registerAuditMetrics(MeterRegistry registry) {
        for (String boundary : new String[] {"project", "security", "system", "extension"}) {
            for (String result : RESULTS) {
                registry.counter("webstarter.audit.operations",
                        "boundary", boundary, "result", result);
            }
        }
        for (String type : new String[] {"login", "operation", "mcp"}) {
            registry.counter("webstarter.audit.persist.failures", "type", type);
        }
        for (String result : RESULTS) {
            registry.counter("webstarter.login.attempts", "result", result);
        }
    }

    private static void registerMcpMetrics(MeterRegistry registry) {
        for (String tool : TOOLS) {
            for (String result : RESULTS) {
                registry.counter("webstarter.mcp.calls", "tool", tool, "result", result);
                Timer.builder("webstarter.mcp.call.duration")
                        .tags("tool", tool, "result", result)
                        .register(registry);
            }
        }
        for (String risk : new String[] {"read", "write", "destructive", "protocol"}) {
            registry.counter("webstarter.mcp.rate_limited", "risk", risk);
        }
        for (String event : new String[] {
                "created", "deleted", "cleanup_failed", "limit_rejected",
                "owner_mismatch", "expired", "not_found"
        }) {
            registry.counter("webstarter.mcp.sessions", "event", event);
        }
    }

    private static void registerProtocolMetrics(MeterRegistry registry) {
        for (String endpoint : new String[] {"login", "oauth_token", "mcp"}) {
            registry.counter("webstarter.rate_limited", "endpoint", endpoint);
            for (String method : new String[] {"GET", "POST", "DELETE", "OTHER"}) {
                for (String outcome : new String[] {
                        "SUCCESS", "RATE_LIMITED", "CLIENT_ERROR", "SERVER_ERROR", "OTHER"
                }) {
                    registry.counter("webstarter.protocol.requests",
                            "endpoint", endpoint, "method", method, "outcome", outcome);
                }
            }
        }
    }
}
