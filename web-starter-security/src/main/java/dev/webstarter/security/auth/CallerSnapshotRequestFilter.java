package dev.webstarter.security.auth;

import java.io.IOException;

import dev.webstarter.core.security.CallerContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Captures the live caller and clears stale identity epochs before authorization runs. */
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
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        var caller = callerContext.current();
        if (caller.isPresent()) {
            request.setAttribute(REQUEST_ATTRIBUTE, caller.get());
        }
        else if (authentication != null
                && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof CallerPrincipal) {
            SecurityContextHolder.clearContext();
            HttpSession session = request.getSession(false);
            if (session != null && !"/api/auth/logout".equals(request.getServletPath())) {
                session.invalidate();
            }
        }
        filterChain.doFilter(request, response);
    }
}
