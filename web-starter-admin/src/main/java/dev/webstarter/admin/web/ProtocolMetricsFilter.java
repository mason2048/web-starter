package dev.webstarter.admin.web;

import java.io.IOException;

import dev.webstarter.core.trace.TraceContext;
import io.micrometer.core.instrument.MeterRegistry;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Records low-cardinality transport outcomes without tagging subjects, IPs, or trace identifiers. */
@Component
@Order(-102)
public class ProtocolMetricsFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProtocolMetricsFilter.class);

    private final MeterRegistry meterRegistry;

    public ProtocolMetricsFilter(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        }
        finally {
            String endpoint = endpoint(request);
            if (endpoint != null) {
                String method = method(request.getMethod());
                String outcome = outcome(response.getStatus());
                meterRegistry.counter("webstarter.protocol.requests",
                        "endpoint", endpoint,
                        "method", method,
                        "outcome", outcome).increment();
                if (response.getStatus() == HttpStatus.TOO_MANY_REQUESTS.value()) {
                    meterRegistry.counter("webstarter.rate_limited",
                            "endpoint", endpoint).increment();
                }
                // ECS already promotes every MDC entry. Ensure the trace exists before logging, but do not
                // add the same key again through SLF4J: duplicate nested pairs make the ECS encoder reject
                // the complete event.
                TraceContext.traceId();
                LOGGER.atInfo()
                        .addKeyValue("endpoint", endpoint)
                        .addKeyValue("method", method)
                        .addKeyValue("outcome", outcome)
                        .log("protocol_request");
            }
        }
    }

    private static String endpoint(HttpServletRequest request) {
        String path = request.getRequestURI();
        if ("/oauth2/token".equals(path)) {
            return "oauth_token";
        }
        if ("/api/auth/login".equals(path)) {
            return "login";
        }
        if (path.equals("/mcp") || path.startsWith("/mcp/")) {
            return "mcp";
        }
        return null;
    }

    private static String method(String method) {
        return switch (method) {
            case "GET", "POST", "DELETE" -> method;
            default -> "OTHER";
        };
    }

    private static String outcome(int status) {
        if (status >= 200 && status < 300) {
            return "SUCCESS";
        }
        if (status == HttpStatus.TOO_MANY_REQUESTS.value()) {
            return "RATE_LIMITED";
        }
        if (status >= 400 && status < 500) {
            return "CLIENT_ERROR";
        }
        if (status >= 500) {
            return "SERVER_ERROR";
        }
        return "OTHER";
    }
}
