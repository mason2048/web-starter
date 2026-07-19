package dev.webstarter.security.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import dev.webstarter.security.token.CredentialType;

public final class InternalCredentialAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";
    static final String INGRESS_HEADER = "X-Web-Starter-Ingress";
    static final String PUBLIC_INGRESS = "public";

    private final AuthenticationManager authenticationManager;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final boolean enabled;

    public InternalCredentialAuthenticationFilter(
            AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint,
            boolean enabled) {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.enabled = enabled;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String rawToken = resolveInternalToken(request);
        if (rawToken == null) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!enabled || PUBLIC_INGRESS.equalsIgnoreCase(request.getHeader(INGRESS_HEADER))) {
            authenticationEntryPoint.commence(
                    request,
                    response,
                    new BadInternalCredentialException("Internal credentials are disabled on this ingress"));
            return;
        }
        CallerAuthenticationToken authentication = CallerAuthenticationToken.unauthenticated(rawToken);
        authentication.setDetails(request.getRemoteAddr());
        try {
            Authentication result = authenticationManager.authenticate(authentication);
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(result);
            SecurityContextHolder.setContext(context);
            filterChain.doFilter(request, response);
        }
        catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, ex);
        }
    }

    static String resolveInternalToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return null;
        }
        String token = authorization.substring(BEARER.length()).trim();
        for (CredentialType type : CredentialType.values()) {
            if (token.startsWith(type.prefix())) {
                return token;
            }
        }
        return null;
    }

    private static final class BadInternalCredentialException extends AuthenticationException {
        private BadInternalCredentialException(String message) {
            super(message);
        }
    }
}
