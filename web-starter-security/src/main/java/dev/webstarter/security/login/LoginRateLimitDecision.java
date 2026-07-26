package dev.webstarter.security.login;

public record LoginRateLimitDecision(boolean allowed, long retryAfterSeconds) {

    public static LoginRateLimitDecision permit() {
        return new LoginRateLimitDecision(true, 0);
    }

    public static LoginRateLimitDecision blocked(long retryAfterSeconds) {
        return new LoginRateLimitDecision(false, Math.max(1, retryAfterSeconds));
    }
}
