package dev.webstarter.mcp.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "web-starter.mcp")
public record WebStarterMcpProperties(
        List<String> allowedHosts,
        List<String> allowedOrigins) {

    private static final List<String> LOCAL_HOSTS = List.of(
            "localhost",
            "localhost:*",
            "127.0.0.1",
            "127.0.0.1:*",
            "[::1]",
            "[::1]:*");
    private static final List<String> LOCAL_ORIGINS = List.of(
            "http://localhost",
            "http://localhost:*",
            "https://localhost",
            "https://localhost:*",
            "http://127.0.0.1",
            "http://127.0.0.1:*",
            "https://127.0.0.1",
            "https://127.0.0.1:*",
            "http://[::1]",
            "http://[::1]:*",
            "https://[::1]",
            "https://[::1]:*");

    public WebStarterMcpProperties {
        allowedHosts = normalizedOrDefault(allowedHosts, LOCAL_HOSTS);
        allowedOrigins = normalizedOrDefault(allowedOrigins, LOCAL_ORIGINS);
    }

    private static List<String> normalizedOrDefault(List<String> configured, List<String> defaults) {
        if (configured == null) {
            return defaults;
        }
        List<String> normalized = configured.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .distinct()
                .toList();
        return normalized.isEmpty() ? defaults : normalized;
    }
}
