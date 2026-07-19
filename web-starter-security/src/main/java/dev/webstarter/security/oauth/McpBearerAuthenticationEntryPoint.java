package dev.webstarter.security.oauth;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import dev.webstarter.security.config.WebStarterSecurityProperties;

public final class McpBearerAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final String metadataUri;

    public McpBearerAuthenticationEntryPoint(WebStarterSecurityProperties properties) {
        this.metadataUri = properties.issuer() + "/.well-known/oauth-protected-resource/mcp";
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate",
                "Bearer resource_metadata=\"" + metadataUri + "\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"unauthorized\"}");
    }
}
