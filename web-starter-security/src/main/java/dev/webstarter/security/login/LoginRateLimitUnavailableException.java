package dev.webstarter.security.login;

/** Raised when login rate-limit state cannot be checked or updated safely. */
public final class LoginRateLimitUnavailableException extends RuntimeException {

    public LoginRateLimitUnavailableException() {
        super("Login rate limiting is temporarily unavailable");
    }

    public LoginRateLimitUnavailableException(Throwable cause) {
        super("Login rate limiting is temporarily unavailable", cause);
    }
}
