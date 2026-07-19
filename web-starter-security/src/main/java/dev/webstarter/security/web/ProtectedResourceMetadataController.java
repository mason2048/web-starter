package dev.webstarter.security.web;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.webstarter.security.config.WebStarterSecurityProperties;

@RestController
public class ProtectedResourceMetadataController {

    private final WebStarterSecurityProperties properties;

    public ProtectedResourceMetadataController(WebStarterSecurityProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/.well-known/oauth-protected-resource/mcp")
    public ProtectedResourceMetadata metadata() {
        return new ProtectedResourceMetadata(
                properties.resourceAudience(),
                List.of(properties.issuer()),
                List.of("header"),
                "启程 Web Starter MCP Server");
    }

    public record ProtectedResourceMetadata(
            String resource,
            @JsonProperty("authorization_servers")
            List<String> authorizationServers,
            @JsonProperty("bearer_methods_supported")
            List<String> bearerMethodsSupported,
            @JsonProperty("resource_name")
            String resourceName) {
    }
}
