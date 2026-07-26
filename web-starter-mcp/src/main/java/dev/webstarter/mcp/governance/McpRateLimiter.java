package dev.webstarter.mcp.governance;

import dev.webstarter.core.security.CurrentCaller;

public interface McpRateLimiter {

    Decision checkAndConsume(CurrentCaller caller, McpToolRisk risk);

    record Decision(boolean allowed, long retryAfterSeconds) {

        public static Decision permit() {
            return new Decision(true, 0);
        }

        public static Decision blocked(long retryAfterSeconds) {
            return new Decision(false, Math.max(1, retryAfterSeconds));
        }
    }
}
