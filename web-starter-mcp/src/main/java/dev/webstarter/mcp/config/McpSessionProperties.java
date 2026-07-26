package dev.webstarter.mcp.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("web-starter.mcp.session")
public record McpSessionProperties(
        boolean enabled,
        Duration idleTtl,
        Duration absoluteTtl,
        int maxPerSubject,
        Duration reservationTtl) {

    public McpSessionProperties {
        idleTtl = positiveOrDefault(idleTtl, Duration.ofMinutes(30));
        absoluteTtl = positiveOrDefault(absoluteTtl, Duration.ofHours(8));
        if (absoluteTtl.compareTo(idleTtl) < 0) {
            throw new IllegalArgumentException("MCP absolute TTL must not be shorter than idle TTL");
        }
        maxPerSubject = maxPerSubject <= 0 ? 8 : maxPerSubject;
        reservationTtl = positiveOrDefault(reservationTtl, Duration.ofSeconds(30));
    }

    private static Duration positiveOrDefault(Duration value, Duration fallback) {
        return value == null || value.isZero() || value.isNegative() ? fallback : value;
    }
}
