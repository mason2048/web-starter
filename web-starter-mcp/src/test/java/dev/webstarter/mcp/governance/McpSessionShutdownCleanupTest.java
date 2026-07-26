package dev.webstarter.mcp.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

class McpSessionShutdownCleanupTest {

    @Test
    void closesBeforeThePhaseZeroRedisLifecycle() {
        List<String> events = new ArrayList<>();
        RecordingRedisLifecycle redis = new RecordingRedisLifecycle(events);
        McpSessionRegistry registry = mock(McpSessionRegistry.class);
        doAnswer(invocation -> {
            assertThat(redis.isRunning()).isTrue();
            events.add("session-cleanup");
            return null;
        }).when(registry).cleanupNodeSessions();

        try (var context = new AnnotationConfigApplicationContext()) {
            context.registerBean("redisLifecycle", RecordingRedisLifecycle.class, () -> redis);
            context.registerBean(McpSessionRegistry.class, () -> registry);
            context.registerBean(McpSessionShutdownCleanup.class);
            context.refresh();

            McpSessionShutdownCleanup cleanup = context.getBean(McpSessionShutdownCleanup.class);
            assertThat(cleanup.isRunning()).isTrue();
            assertThat(cleanup.getPhase()).isGreaterThan(new LettuceConnectionFactory().getPhase());
        }

        assertThat(events).containsExactly(
                "redis-start", "session-cleanup", "redis-stop");
        verify(registry, times(1)).cleanupNodeSessions();
    }

    @Test
    void propagatesCleanupFailureWithoutStrandingTheLifecycleCallback() {
        McpSessionRegistry registry = mock(McpSessionRegistry.class);
        IllegalStateException failure = new IllegalStateException("redis cleanup failed");
        doThrow(failure).when(registry).cleanupNodeSessions();
        McpSessionShutdownCleanup cleanup = new McpSessionShutdownCleanup(registry);
        AtomicBoolean callbackInvoked = new AtomicBoolean();
        cleanup.start();

        assertThatThrownBy(() -> cleanup.stop(() -> callbackInvoked.set(true)))
                .isSameAs(failure);
        assertThat(callbackInvoked).isTrue();
        assertThat(cleanup.isRunning()).isFalse();
        verify(registry, times(1)).cleanupNodeSessions();
    }

    private static final class RecordingRedisLifecycle implements SmartLifecycle {

        private final List<String> events;
        private boolean running;

        private RecordingRedisLifecycle(List<String> events) {
            this.events = events;
        }

        @Override
        public void start() {
            running = true;
            events.add("redis-start");
        }

        @Override
        public void stop() {
            events.add("redis-stop");
            running = false;
        }

        @Override
        public boolean isRunning() {
            return running;
        }

        @Override
        public int getPhase() {
            return 0;
        }
    }
}
