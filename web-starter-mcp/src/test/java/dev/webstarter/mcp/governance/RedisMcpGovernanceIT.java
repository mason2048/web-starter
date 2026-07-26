package dev.webstarter.mcp.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpRateLimitProperties;
import dev.webstarter.mcp.config.McpSessionProperties;
import dev.webstarter.security.token.TokenHasher;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;

/** Opt-in real Redis proof for atomic MCP governance scripts. */
class RedisMcpGovernanceIT {

    private static final GenericContainer<?> REDIS =
            new GenericContainer<>("redis:7.4-alpine").withExposedPorts(6379);
    private static final TokenHasher HASHER =
            new TokenHasher("0123456789abcdef0123456789abcdef");

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redis;
    private MutableClock clock;

    @BeforeAll
    static void startRedis() {
        REDIS.start();
        connectionFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connectionFactory.afterPropertiesSet();
        redis = new StringRedisTemplate(connectionFactory);
        redis.afterPropertiesSet();
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
        REDIS.stop();
    }

    @BeforeEach
    void resetRedisAndClock() {
        redis.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
        clock = new MutableClock(Instant.parse("2026-07-19T00:00:00Z"));
    }

    @Test
    void enforcesSubjectCapOwnershipIdleExpiryAndNodeCleanup() {
        RedisMcpSessionRegistry registry = registry("node-a", 2);
        McpSessionRegistry.Reservation first = registry.reserve(caller("client-a"));
        McpSessionRegistry.Reservation pending = registry.reserve(caller("client-b"));

        assertThat(first.accepted()).isTrue();
        assertThat(pending.accepted()).isTrue();
        assertThat(registry.reserve(caller("client-c")).accepted()).isFalse();

        registry.activate(first, "session-one");
        registry.release(pending);
        McpSessionRegistry.Reservation second = registry.reserve(caller("client-a"));
        registry.activate(second, "session-two");

        assertThat(registry.delete(caller("client-a"), "session-two"))
                .isEqualTo(McpSessionRegistry.Validation.ACTIVE);
        assertThat(registry.validateAndTouch(caller("client-a"), "session-two"))
                .isEqualTo(McpSessionRegistry.Validation.MISSING);
        McpSessionRegistry.Reservation third = registry.reserve(caller("client-a"));
        registry.activate(third, "session-three");

        assertThat(registry.validateAndTouch(caller("client-a"), "session-one"))
                .isEqualTo(McpSessionRegistry.Validation.ACTIVE);
        assertThat(registry.validateAndTouch(caller("client-b"), "session-one"))
                .isEqualTo(McpSessionRegistry.Validation.OWNER_MISMATCH);

        clock.advance(Duration.ofSeconds(11));
        assertThat(registry.validateAndTouch(caller("client-a"), "session-one"))
                .isEqualTo(McpSessionRegistry.Validation.EXPIRED);

        registry.cleanupNodeSessions();
        assertThat(registry.validateAndTouch(caller("client-a"), "session-three"))
                .isEqualTo(McpSessionRegistry.Validation.MISSING);
        assertThat(redis.keys("web-starter:mcp:session:metadata:*")).isEmpty();
    }

    @Test
    void absoluteTtlWinsEvenWhenIdleTtlIsContinuouslyRefreshed() {
        RedisMcpSessionRegistry registry = registry("node-b", 2);
        McpSessionRegistry.Reservation reservation = registry.reserve(caller("client-a"));
        registry.activate(reservation, "absolute-session");

        clock.advance(Duration.ofSeconds(8));
        assertThat(registry.validateAndTouch(caller("client-a"), "absolute-session"))
                .isEqualTo(McpSessionRegistry.Validation.ACTIVE);
        clock.advance(Duration.ofSeconds(8));
        assertThat(registry.validateAndTouch(caller("client-a"), "absolute-session"))
                .isEqualTo(McpSessionRegistry.Validation.ACTIVE);
        clock.advance(Duration.ofSeconds(15));
        assertThat(registry.validateAndTouch(caller("client-a"), "absolute-session"))
                .isEqualTo(McpSessionRegistry.Validation.EXPIRED);
    }

    @Test
    void expiredReservationCannotBeActivatedEvenBeforeAnotherReserveCleansTheIndex() {
        RedisMcpSessionRegistry registry = registry("node-expired-reservation", 2);
        McpSessionRegistry.Reservation reservation = registry.reserve(caller("client-a"));

        clock.advance(Duration.ofSeconds(5));

        assertThatThrownBy(() -> registry.activate(reservation, "too-late-session"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("MCP session reservation expired before activation");
        assertThat(redis.keys("web-starter:mcp:session:metadata:*")).isEmpty();
    }

    @Test
    void subjectReservationCapIsAtomicUnderConcurrency() throws Exception {
        RedisMcpSessionRegistry registry = registry("node-c", 3);
        var executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<McpSessionRegistry.Reservation>> calls = new ArrayList<>();
            for (int index = 0; index < 16; index++) {
                calls.add(() -> registry.reserve(caller("parallel-client")));
            }
            long accepted = executor.invokeAll(calls).stream()
                    .map(future -> {
                        try {
                            return future.get();
                        }
                        catch (Exception exception) {
                            throw new IllegalStateException(exception);
                        }
                    })
                    .filter(McpSessionRegistry.Reservation::accepted)
                    .count();
            assertThat(accepted).isEqualTo(3);
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    void rateLimitAtomicallyIntersectsSubjectClientAndRiskBuckets() {
        RedisMcpRateLimiter limiter = new RedisMcpRateLimiter(
                redis,
                HASHER,
                new McpRateLimitProperties(
                        true, Duration.ofMinutes(1), 2, 5, 5, 5, 5, 5));

        assertThat(limiter.checkAndConsume(caller("client-a"), McpToolRisk.READ).allowed()).isTrue();
        assertThat(limiter.checkAndConsume(caller("client-a"), McpToolRisk.READ).allowed()).isTrue();
        McpRateLimiter.Decision blocked =
                limiter.checkAndConsume(caller("client-a"), McpToolRisk.READ);

        assertThat(blocked.allowed()).isFalse();
        assertThat(blocked.retryAfterSeconds()).isBetween(1L, 60L);
        Set<String> keys = redis.keys("web-starter:mcp:rate:*");
        assertThat(keys).isNotNull().hasSize(3)
                .allMatch(key -> !key.contains("raw-subject-user-17")
                        && !key.contains("client-a")
                        && !key.contains("token-1"));
    }

    private RedisMcpSessionRegistry registry(String nodeId, int maximum) {
        return new RedisMcpSessionRegistry(
                redis,
                HASHER,
                new McpSessionProperties(
                        true, Duration.ofSeconds(10), Duration.ofSeconds(30), maximum,
                        Duration.ofSeconds(5)),
                clock,
                nodeId);
    }

    private static CurrentCaller caller(String clientId) {
        return new CurrentCaller(
                CallerType.USER, "raw-subject-user-17", "operator", "Operator", "token-1", clientId,
                Set.of("project:list"), Set.of("project:list"), Set.of(), "trace-redis-it");
    }

    private static final class MutableClock extends Clock {
        private Instant current;

        private MutableClock(Instant current) {
            this.current = current;
        }

        void advance(Duration duration) {
            current = current.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("Only UTC is supported by this test clock");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }
    }
}
