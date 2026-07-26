package dev.webstarter.security.web;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.security.session.WebSessionManagementService;
import dev.webstarter.security.session.WebSessionManagementService.SessionSummary;
import dev.webstarter.system.service.UserService;

@RestController
@RequestMapping("/api/security/me")
public class AccountSecurityController {

    private final CallerContext callerContext;
    private final UserService userService;
    private final WebSessionManagementService sessionService;

    public AccountSecurityController(
            CallerContext callerContext,
            UserService userService,
            WebSessionManagementService sessionService) {
        this.callerContext = callerContext;
        this.userService = userService;
        this.sessionService = sessionService;
    }

    @PutMapping("/password")
    public ApiResponse<Void> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            HttpServletRequest servletRequest) {
        var caller = requireUser();
        userService.changeOwnPassword(
                Long.valueOf(caller.subjectId()), request.currentPassword(), request.newPassword());
        HttpSession session = servletRequest.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        return ApiResponse.success();
    }

    @GetMapping("/sessions")
    public ApiResponse<List<SessionSummary>> sessions(HttpServletRequest request) {
        var caller = requireUser();
        HttpSession current = request.getSession(false);
        return ApiResponse.success(sessionService.findByPrincipal(
                caller.username(), current == null ? null : current.getId()));
    }

    @DeleteMapping("/sessions/{reference}")
    public ApiResponse<Void> revokeSession(
            @PathVariable String reference,
            HttpServletRequest request) {
        var caller = requireUser();
        HttpSession current = request.getSession(false);
        boolean revokingCurrent = current != null
                && sessionService.reference(current.getId()).equals(reference);
        if (!sessionService.revoke(caller.username(), reference)) {
            throw new IllegalArgumentException("Session does not exist");
        }
        if (revokingCurrent) {
            current.invalidate();
        }
        return ApiResponse.success();
    }

    @DeleteMapping("/sessions/others")
    public ApiResponse<RevokedSessionsResponse> revokeOtherSessions(HttpServletRequest request) {
        var caller = requireUser();
        HttpSession current = request.getSession(false);
        if (current == null) {
            throw new IllegalStateException("Current Web session is unavailable");
        }
        int revoked = sessionService.revokeOtherSessions(caller.username(), current.getId());
        return ApiResponse.success(new RevokedSessionsResponse(revoked));
    }

    /**
     * Invalidates every transport credential bound to the caller's current
     * identity epoch. Ordinary logout intentionally remains session-only.
     */
    @PostMapping("/security-logout")
    public ApiResponse<Void> securityLogout() {
        var caller = requireUser();
        userService.securityLogout(Long.valueOf(caller.subjectId()));
        return ApiResponse.success();
    }

    private dev.webstarter.core.security.CurrentCaller requireUser() {
        var caller = callerContext.required();
        if (caller.callerType() != CallerType.USER) {
            throw new IllegalArgumentException("A Web user session is required");
        }
        return caller;
    }

    public record PasswordChangeRequest(
            @NotBlank @Size(max = 128) String currentPassword,
            @NotBlank @Size(min = 12, max = 128) String newPassword) {
    }

    public record RevokedSessionsResponse(int revoked) {
    }
}
