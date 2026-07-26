package dev.webstarter.mcp.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "web-starter.mcp.idempotency")
public record McpIdempotencyProperties(
        Duration ttl,
        Duration cleanupInterval) {

    private static final Duration DEFAULT_TTL = Duration.ofHours(24);
    private static final Duration DEFAULT_CLEANUP_INTERVAL = Duration.ofMinutes(10);

    public McpIdempotencyProperties {
        ttl = positiveOrDefault(ttl, DEFAULT_TTL, "ttl");
        cleanupInterval = positiveOrDefault(cleanupInterval, DEFAULT_CLEANUP_INTERVAL, "cleanupInterval");
    }

    private static Duration positiveOrDefault(Duration value, Duration fallback, String name) {
        Duration resolved = value == null ? fallback : value;
        if (resolved.isZero() || resolved.isNegative()) {
            throw new IllegalArgumentException("web-starter.mcp.idempotency." + name + " must be positive");
        }
        return resolved;
    }
}
