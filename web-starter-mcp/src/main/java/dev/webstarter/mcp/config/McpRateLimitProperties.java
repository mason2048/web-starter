package dev.webstarter.mcp.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("web-starter.mcp.rate-limit")
public record McpRateLimitProperties(
        boolean enabled,
        Duration window,
        int maxPerSubject,
        int maxPerClient,
        int maxRead,
        int maxWrite,
        int maxDestructive,
        int maxProtocol) {

    public McpRateLimitProperties {
        window = window == null || window.isZero() || window.isNegative()
                ? Duration.ofMinutes(1) : window;
        maxPerSubject = positiveOrDefault(maxPerSubject, 240);
        maxPerClient = positiveOrDefault(maxPerClient, 480);
        maxRead = positiveOrDefault(maxRead, 180);
        maxWrite = positiveOrDefault(maxWrite, 60);
        maxDestructive = positiveOrDefault(maxDestructive, 20);
        maxProtocol = positiveOrDefault(maxProtocol, 120);
    }

    public int limitFor(dev.webstarter.mcp.governance.McpToolRisk risk) {
        return switch (risk) {
            case READ -> maxRead;
            case WRITE -> maxWrite;
            case DESTRUCTIVE -> maxDestructive;
            case PROTOCOL -> maxProtocol;
        };
    }

    private static int positiveOrDefault(int value, int fallback) {
        return value <= 0 ? fallback : value;
    }
}
