package dev.webstarter.mcp.governance;

import dev.webstarter.core.security.CurrentCaller;

public interface McpSessionRegistry {

    Reservation reserve(CurrentCaller caller);

    void activate(Reservation reservation, String sessionId);

    void release(Reservation reservation);

    Validation validateAndTouch(CurrentCaller caller, String sessionId);

    Validation delete(CurrentCaller caller, String sessionId);

    void cleanupNodeSessions();

    record Reservation(
            boolean accepted,
            long retryAfterSeconds,
            String reservationId,
            String subjectHash,
            String ownerHash,
            String clientHash) {

        public static Reservation rejected(long retryAfterSeconds) {
            return new Reservation(false, Math.max(1, retryAfterSeconds), null, null, null, null);
        }
    }

    enum Validation {
        ACTIVE,
        MISSING,
        EXPIRED,
        OWNER_MISMATCH
    }
}
