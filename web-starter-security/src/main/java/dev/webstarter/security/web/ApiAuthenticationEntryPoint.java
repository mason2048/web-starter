package dev.webstarter.security.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import dev.webstarter.core.api.ApiCodes;
import dev.webstarter.core.trace.TraceContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/** Returns the same JSON-shaped 401 contract for unauthenticated API requests. */
public final class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authenticationException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":" + ApiCodes.UNAUTHORIZED
                + ",\"message\":\"Authentication required\",\"data\":null,\"traceId\":\""
                + TraceContext.traceId() + "\"}");
    }
}
