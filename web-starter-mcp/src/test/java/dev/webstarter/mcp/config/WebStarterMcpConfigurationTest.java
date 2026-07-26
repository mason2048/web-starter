package dev.webstarter.mcp.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;

import dev.webstarter.mcp.service.McpRuntimeIdentity;

class WebStarterMcpConfigurationTest {

    @Test
    void bindsRuntimeIdentityFromApplicationVersionAndGitRevision() {
        WebStarterMcpConfiguration configuration = new WebStarterMcpConfiguration();
        String commit = "0123456789abcdef0123456789abcdef01234567";

        McpRuntimeIdentity identity = configuration.mcpRuntimeIdentity("2.0.0", commit);

        assertThat(identity.applicationVersion()).isEqualTo("2.0.0");
        assertThat(identity.gitRevision()).isEqualTo(commit);
        assertThat(identity.serverInfo().version()).isEqualTo("2.0.0");
        assertThat(identity.serverInfo().description()).isEqualTo("gitRevision=" + commit);
    }

    @Test
    void streamableHttpServletIsMountedOnlyAtMcpEndpoint() {
        WebStarterMcpConfiguration configuration = new WebStarterMcpConfiguration();
        var mapper = configuration.mcpJsonMapper();
        var properties = new WebStarterMcpProperties(null, null);
        var validator = configuration.mcpTransportSecurityValidator(properties);
        var provider = configuration.mcpTransportProvider(mapper, validator);
        var registration = configuration.mcpServletRegistration(provider);

        assertThat(registration.getUrlMappings()).containsExactly("/mcp");
        assertThat(registration.getServletName()).isEqualTo("webStarterMcpStreamableHttp");
    }

    @Test
    void nonBrowserAgentWithoutOriginIsAllowedWhenHostIsAllowed() {
        WebStarterMcpConfiguration configuration = new WebStarterMcpConfiguration();
        var validator = configuration.mcpTransportSecurityValidator(
                new WebStarterMcpProperties(List.of("mcp.internal.example"), List.of("https://console.example")));

        assertThatCode(() -> validator.validateHeaders(Map.of(
                "Host", List.of("mcp.internal.example"))))
                .doesNotThrowAnyException();
    }

    @Test
    void localDefaultsAcceptHostsAndOriginsWithOrWithoutExplicitPorts() {
        WebStarterMcpConfiguration configuration = new WebStarterMcpConfiguration();
        var validator = configuration.mcpTransportSecurityValidator(
                new WebStarterMcpProperties(null, null));

        assertThatCode(() -> validator.validateHeaders(Map.of(
                "Host", List.of("localhost"),
                "Origin", List.of("http://localhost"))))
                .doesNotThrowAnyException();
        assertThatCode(() -> validator.validateHeaders(Map.of(
                "Host", List.of("127.0.0.1:8088"),
                "Origin", List.of("http://127.0.0.1:5173"))))
                .doesNotThrowAnyException();
        assertThatCode(() -> validator.validateHeaders(Map.of(
                "Host", List.of("[::1]"),
                "Origin", List.of("http://[::1]"))))
                .doesNotThrowAnyException();
    }

    @Test
    void browserOriginAndHostAreBothEnforced() {
        WebStarterMcpConfiguration configuration = new WebStarterMcpConfiguration();
        var validator = configuration.mcpTransportSecurityValidator(
                new WebStarterMcpProperties(List.of("mcp.internal.example"), List.of("https://console.example")));

        assertThatThrownBy(() -> validator.validateHeaders(Map.of(
                "Host", List.of("mcp.internal.example"),
                "Origin", List.of("https://evil.example"))))
                .isInstanceOfSatisfying(ServerTransportSecurityException.class,
                        exception -> assertThat(exception.getStatusCode()).isEqualTo(403));
        assertThatThrownBy(() -> validator.validateHeaders(Map.of(
                "Origin", List.of("https://console.example"))))
                .isInstanceOfSatisfying(ServerTransportSecurityException.class,
                        exception -> assertThat(exception.getStatusCode()).isEqualTo(421));
    }
}
