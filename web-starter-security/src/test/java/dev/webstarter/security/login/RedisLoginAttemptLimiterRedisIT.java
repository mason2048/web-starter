package dev.webstarter.security.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import dev.webstarter.security.token.TokenHasher;

/** Real Redis acceptance for atomic progressive login backoff and account isolation. */
class RedisLoginAttemptLimiterRedisIT {

    private static final GenericContainer<?> REDIS = new GenericContainer<>(
            DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;

    @BeforeAll
    static void startRedis() {
        REDIS.start();
        connections = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connections.afterPropertiesSet();
        connections.start();
        redis = new StringRedisTemplate(connections);
        redis.afterPropertiesSet();
    }

    @AfterAll
    static void stopRedis() {
        if (connections != null) {
            connections.destroy();
        }
        REDIS.stop();
    }

    @BeforeEach
    void clearRedis() {
        assertThat(redis.getConnectionFactory()).isNotNull();
        try (RedisConnection connection = redis.getConnectionFactory().getConnection()) {
            connection.serverCommands().flushDb();
        }
    }

    @Test
    void tenConcurrentFailuresAreAtomicAndBackOffProgressively() throws Exception {
        RedisLoginAttemptLimiter limiter = limiter(5, 5);
        CountDownLatch ready = new CountDownLatch(10);
        CountDownLatch start = new CountDownLatch(1);
        List<LoginRateLimitDecision> decisions = new ArrayList<>();

        try (var executor = Executors.newFixedThreadPool(10)) {
            List<Future<LoginRateLimitDecision>> futures = new ArrayList<>();
            for (int index = 0; index < 10; index++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    if (!start.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Concurrent start barrier timed out");
                    }
                    return limiter.recordFailure("Operator", "10.20.30.40");
                }));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            for (Future<LoginRateLimitDecision> future : futures) {
                decisions.add(future.get(20, TimeUnit.SECONDS));
            }
        }

        assertThat(decisions.stream().filter(LoginRateLimitDecision::allowed)).hasSize(4);
        assertThat(decisions.stream()
                .filter(decision -> !decision.allowed())
                .map(LoginRateLimitDecision::retryAfterSeconds)
                .sorted())
                .containsExactly(1L, 2L, 4L, 8L, 8L, 8L);
        assertThat(limiter.check("Operator", "10.20.30.40").allowed()).isFalse();
    }

    @Test
    void oneSourceCannotBlockAnotherAccountAndSuccessClearsOnlyTheAccountState() {
        RedisLoginAttemptLimiter limiter = limiter(3, 3);

        assertThat(limiter.recordFailure("Alice", "10.20.30.40").allowed()).isTrue();
        assertThat(limiter.recordFailure("Alice", "10.20.30.40").allowed()).isTrue();
        assertThat(limiter.recordFailure("Alice", "10.20.30.40").allowed()).isFalse();

        assertThat(limiter.check("Bob", "10.20.30.40").allowed()).isTrue();
        assertThat(limiter.check("Alice", "10.20.30.41").allowed()).isFalse();

        limiter.recordSuccess("Alice", "10.20.30.40");
        assertThat(limiter.check("Alice", "10.20.30.40").allowed()).isTrue();
        assertThat(limiter.check("Bob", "10.20.30.40").allowed()).isTrue();
    }

    private static RedisLoginAttemptLimiter limiter(int identityLimit, int pairLimit) {
        LoginRateLimitProperties properties = new LoginRateLimitProperties(
                true,
                identityLimit,
                pairLimit,
                Duration.ofMinutes(5),
                Duration.ofSeconds(1),
                Duration.ofSeconds(8));
        return new RedisLoginAttemptLimiter(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                properties);
    }
}
