package dev.webstarter.security.web;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.security.login.LoginAttemptLimiter;
import dev.webstarter.security.login.LoginRateLimitDecision;
import dev.webstarter.security.login.LoginRateLimitExceededException;
import dev.webstarter.security.login.LoginRateLimitUnavailableException;
import dev.webstarter.security.session.WebSessionManagementService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final CallerContext callerContext;
    private final AuditLogRecorder auditLogRecorder;
    private final LoginAttemptLimiter loginAttemptLimiter;
    private final Clock clock;

    @Autowired
    public AuthController(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            CallerContext callerContext,
            AuditLogRecorder auditLogRecorder,
            ObjectProvider<LoginAttemptLimiter> loginAttemptLimiter) {
        this(authenticationManager, securityContextRepository, callerContext, auditLogRecorder,
                loginAttemptLimiter.getIfAvailable(LoginAttemptLimiter::none),
                Clock.systemUTC());
    }

    AuthController(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            CallerContext callerContext,
            AuditLogRecorder auditLogRecorder) {
        this(authenticationManager, securityContextRepository, callerContext, auditLogRecorder,
                LoginAttemptLimiter.none(), Clock.systemUTC());
    }

    AuthController(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            CallerContext callerContext,
            AuditLogRecorder auditLogRecorder,
            Clock clock) {
        this(authenticationManager, securityContextRepository, callerContext, auditLogRecorder,
                LoginAttemptLimiter.none(), clock);
    }

    AuthController(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            CallerContext callerContext,
            AuditLogRecorder auditLogRecorder,
            LoginAttemptLimiter loginAttemptLimiter,
            Clock clock) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.callerContext = callerContext;
        this.auditLogRecorder = auditLogRecorder;
        this.loginAttemptLimiter = loginAttemptLimiter;
        this.clock = clock;
    }

    @PostMapping("/login")
    public ApiResponse<CurrentCaller> login(
            @Valid @RequestBody LoginRequest login,
            HttpServletRequest request,
            HttpServletResponse response) {
        String username = login.username().trim();
        LoginRateLimitDecision initialDecision;
        try {
            initialDecision = loginAttemptLimiter.check(username, request.getRemoteAddr());
        }
        catch (LoginRateLimitUnavailableException exception) {
            recordLogin(username, "FAILURE", "RATE_LIMIT_UNAVAILABLE", request);
            throw exception;
        }
        if (!initialDecision.allowed()) {
            recordLogin(username, "FAILURE", "RATE_LIMITED", request);
            throw new LoginRateLimitExceededException(initialDecision.retryAfterSeconds());
        }
        try {
            Authentication authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(
                            username, login.password()));
            try {
                loginAttemptLimiter.recordSuccess(username, request.getRemoteAddr());
            }
            catch (LoginRateLimitUnavailableException exception) {
                SecurityContextHolder.clearContext();
                recordLogin(username, "FAILURE", "RATE_LIMIT_UNAVAILABLE", request);
                throw exception;
            }
            var session = request.getSession(true);
            request.changeSessionId();
            session.setAttribute(
                    WebSessionManagementService.CLIENT_IP_ATTRIBUTE,
                    safeAttribute(request.getRemoteAddr(), 128));
            session.setAttribute(
                    WebSessionManagementService.USER_AGENT_ATTRIBUTE,
                    safeAttribute(request.getHeader("User-Agent"), 512));
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);
            CurrentCaller caller = callerContext.required();
            recordLogin(username, "SUCCESS", null, request);
            return ApiResponse.success(caller);
        }
        catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            LoginRateLimitDecision failureDecision;
            try {
                failureDecision = loginAttemptLimiter.recordFailure(
                        username, request.getRemoteAddr());
            }
            catch (LoginRateLimitUnavailableException limiterFailure) {
                recordLogin(username, "FAILURE", "RATE_LIMIT_UNAVAILABLE", request);
                throw limiterFailure;
            }
            String reason = failureDecision.allowed() ? "INVALID_CREDENTIALS" : "RATE_LIMITED";
            recordLogin(username, "FAILURE", reason, request);
            if (!failureDecision.allowed()) {
                throw new LoginRateLimitExceededException(failureDecision.retryAfterSeconds());
            }
            throw ex;
        }
    }

    @GetMapping("/me")
    public ApiResponse<CurrentCaller> me() {
        return ApiResponse.success(callerContext.required());
    }

    @GetMapping("/csrf")
    public ApiResponse<CsrfResponse> csrf(CsrfToken csrfToken) {
        return ApiResponse.success(new CsrfResponse(
                csrfToken.getHeaderName(), csrfToken.getParameterName(), csrfToken.getToken()));
    }

    private void recordLogin(
            String username,
            String result,
            String failureReason,
            HttpServletRequest request) {
        auditLogRecorder.recordLogin(new LoginAuditEvent(
                username,
                result,
                failureReason,
                request.getRemoteAddr(),
                request.getHeader("User-Agent"),
                TraceContext.traceId(),
                LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC)));
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
    }

    public record CsrfResponse(String headerName, String parameterName, String token) {
    }

    private static String safeAttribute(String value, int maximumLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maximumLength ? value : value.substring(0, maximumLength);
    }
}
