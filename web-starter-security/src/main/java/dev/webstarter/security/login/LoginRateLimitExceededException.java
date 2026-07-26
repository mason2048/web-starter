package dev.webstarter.security.login;

import org.springframework.security.core.AuthenticationException;

public final class LoginRateLimitExceededException extends AuthenticationException {

    private final long retryAfterSeconds;

    public LoginRateLimitExceededException(long retryAfterSeconds) {
        super("Login attempts are temporarily rate limited");
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
