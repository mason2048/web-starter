package dev.webstarter.security.oauth;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Redirects an unauthenticated browser authorization request to the SPA login page.
 * The return target is constructed exclusively from the current same-origin request.
 */
public final class OAuthLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authenticationException) throws IOException, ServletException {
        String requestTarget = request.getRequestURI();
        if (request.getQueryString() != null && !request.getQueryString().isBlank()) {
            requestTarget += "?" + request.getQueryString();
        }
        String encodedTarget = URLEncoder.encode(requestTarget, StandardCharsets.UTF_8);
        response.sendRedirect(request.getContextPath() + "/login?redirect=" + encodedTarget);
    }
}
