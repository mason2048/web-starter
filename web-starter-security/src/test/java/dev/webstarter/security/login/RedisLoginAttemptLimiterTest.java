package dev.webstarter.security.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import dev.webstarter.security.token.TokenHasher;

class RedisLoginAttemptLimiterTest {

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void returnsRetryAfterAndUsesOnlyPseudonymousRedisKeys() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(5_001L).when(redis).execute(
                any(RedisScript.class), anyList(), any(), any(), any(), any(), any());
        RedisLoginAttemptLimiter limiter = new RedisLoginAttemptLimiter(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new LoginRateLimitProperties(
                        true, 5, 5, Duration.ofMinutes(15),
                        Duration.ofSeconds(2), Duration.ofMinutes(15)));

        LoginRateLimitDecision decision = limiter.recordFailure("Operator", "10.20.30.40");

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.retryAfterSeconds()).isEqualTo(6);
        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redis).execute(
                any(RedisScript.class), keys.capture(), any(), any(), any(), any(), any());
        assertThat(keys.getValue())
                .hasSize(2)
                .allMatch(key -> !key.contains("operator") && !key.contains("10.20.30.40"));
        assertThat(keys.getValue().get(0)).contains(":identity:");
        assertThat(keys.getValue().get(1)).contains(":pair:");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void nullCheckResultFailsClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(null).when(redis).execute(any(RedisScript.class), anyList(), any());
        RedisLoginAttemptLimiter limiter = limiter(redis);

        assertThatThrownBy(() -> limiter.check("Operator", "10.20.30.40"))
                .isInstanceOf(LoginRateLimitUnavailableException.class);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void nullFailureResultFailsClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(null).when(redis).execute(
                any(RedisScript.class), anyList(), any(), any(), any(), any(), any());
        RedisLoginAttemptLimiter limiter = limiter(redis);

        assertThatThrownBy(() -> limiter.recordFailure("Operator", "10.20.30.40"))
                .isInstanceOf(LoginRateLimitUnavailableException.class);
    }

    @Test
    void redisFailureIsWrappedWithoutLeakingItsMessage() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.execute(any(RedisScript.class), anyList(), any()))
                .thenThrow(new IllegalStateException("redis.internal.example:6379"));
        RedisLoginAttemptLimiter limiter = limiter(redis);

        assertThatThrownBy(() -> limiter.check("Operator", "10.20.30.40"))
                .isInstanceOf(LoginRateLimitUnavailableException.class)
                .hasMessage("Login rate limiting is temporarily unavailable")
                .hasCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void nullSuccessCleanupResultFailsClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.delete(anyList())).thenReturn(null);
        RedisLoginAttemptLimiter limiter = limiter(redis);

        assertThatThrownBy(() -> limiter.recordSuccess("Operator", "10.20.30.40"))
                .isInstanceOf(LoginRateLimitUnavailableException.class);
    }

    private static RedisLoginAttemptLimiter limiter(StringRedisTemplate redis) {
        return new RedisLoginAttemptLimiter(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new LoginRateLimitProperties(
                        true, 5, 5, Duration.ofMinutes(15),
                        Duration.ofSeconds(2), Duration.ofMinutes(15)));
    }
}
