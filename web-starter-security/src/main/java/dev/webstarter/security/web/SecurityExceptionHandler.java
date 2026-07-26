package dev.webstarter.security.web;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import dev.webstarter.core.api.ApiCodes;
import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.security.login.LoginRateLimitExceededException;
import dev.webstarter.security.login.LoginRateLimitUnavailableException;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityExceptionHandler {

    @ExceptionHandler(LoginRateLimitExceededException.class)
    public ResponseEntity<ApiResponse<Void>> handleLoginRateLimitExceeded(
            LoginRateLimitExceededException exception) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", Long.toString(exception.retryAfterSeconds()))
                .body(ApiResponse.error(
                        ApiCodes.TOO_MANY_REQUESTS,
                        "Too many login attempts; try again later"));
    }

    @ExceptionHandler(LoginRateLimitUnavailableException.class)
    public ResponseEntity<ApiResponse<Void>> handleLoginRateLimitUnavailable(
            LoginRateLimitUnavailableException exception) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(ApiResponse.error(
                        ApiCodes.SERVICE_UNAVAILABLE,
                        "Login is temporarily unavailable"));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthenticationException(AuthenticationException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ApiCodes.UNAUTHORIZED, "Invalid username or password"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(AccessDeniedException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error(ApiCodes.FORBIDDEN, "Access denied"));
    }
}
