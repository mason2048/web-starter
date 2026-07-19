package dev.webstarter.security.auth;

import java.io.IOException;

import dev.webstarter.core.security.CallerContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

/** Captures the live authenticated caller before CSRF/authorization may reject the request. */
public final class CallerSnapshotRequestFilter extends OncePerRequestFilter {

    public static final String REQUEST_ATTRIBUTE =
            CallerSnapshotRequestFilter.class.getName() + ".caller";

    private final CallerContext callerContext;

    public CallerSnapshotRequestFilter(CallerContext callerContext) {
        this.callerContext = callerContext;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        callerContext.current().ifPresent(caller -> request.setAttribute(REQUEST_ATTRIBUTE, caller));
        filterChain.doFilter(request, response);
    }
}
