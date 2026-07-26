package dev.webstarter.security.login;

public interface LoginAttemptLimiter {

    LoginRateLimitDecision check(String username, String ipAddress);

    LoginRateLimitDecision recordFailure(String username, String ipAddress);

    void recordSuccess(String username, String ipAddress);

    static LoginAttemptLimiter none() {
        return new LoginAttemptLimiter() {
            @Override
            public LoginRateLimitDecision check(String username, String ipAddress) {
                return LoginRateLimitDecision.permit();
            }

            @Override
            public LoginRateLimitDecision recordFailure(String username, String ipAddress) {
                return LoginRateLimitDecision.permit();
            }

            @Override
            public void recordSuccess(String username, String ipAddress) {
            }
        };
    }
}
