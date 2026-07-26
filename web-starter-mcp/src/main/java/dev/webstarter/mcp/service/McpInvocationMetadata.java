package dev.webstarter.mcp.service;

final class McpInvocationMetadata {

    private static final ThreadLocal<State> CURRENT = ThreadLocal.withInitial(State::new);

    private McpInvocationMetadata() {
    }

    static void reset() {
        CURRENT.remove();
    }

    static void idempotency(String keyHash, boolean replayed) {
        State state = CURRENT.get();
        state.keyHash = keyHash;
        state.replayed = replayed;
    }

    static String keyHash() {
        return CURRENT.get().keyHash;
    }

    static boolean replayed() {
        return CURRENT.get().replayed;
    }

    private static final class State {
        private String keyHash;
        private boolean replayed;
    }
}
