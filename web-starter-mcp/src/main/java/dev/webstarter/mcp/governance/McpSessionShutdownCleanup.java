package dev.webstarter.mcp.governance;

import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

/** Removes this process' rebuildable Redis session index during graceful shutdown. */
@Component
public final class McpSessionShutdownCleanup implements SmartLifecycle {

    /**
     * Spring stops higher phases first. Spring Data Redis 4.1 uses phase 0 for
     * {@code LettuceConnectionFactory}, so phase 1 keeps Redis available while
     * the node-local session index is removed.
     */
    static final int CLEANUP_PHASE = 1;

    private final McpSessionRegistry sessionRegistry;
    private final AtomicBoolean running = new AtomicBoolean();

    public McpSessionShutdownCleanup(McpSessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public void start() {
        running.set(true);
    }

    @Override
    public void stop() {
        if (running.compareAndSet(true, false)) {
            sessionRegistry.cleanupNodeSessions();
        }
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        }
        finally {
            callback.run();
        }
    }

    @Override
    public boolean isRunning() {
        return running.get();
    }

    @Override
    public int getPhase() {
        return CLEANUP_PHASE;
    }
}
