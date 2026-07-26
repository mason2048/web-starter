package dev.webstarter.mcp.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpRateLimitProperties;
import dev.webstarter.security.token.TokenHasher;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

class RedisMcpRateLimiterTest {

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void blocksWithCeilingRetryAndUsesOnlyPseudonymousKeys() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(1_501L).when(redis).execute(
                any(RedisScript.class), anyList(), any(), any(), any(), any());
        RedisMcpRateLimiter limiter = new RedisMcpRateLimiter(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new McpRateLimitProperties(true, Duration.ofMinutes(1), 10, 20, 8, 4, 2, 6));

        McpRateLimiter.Decision decision = limiter.checkAndConsume(caller(), McpToolRisk.DESTRUCTIVE);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.retryAfterSeconds()).isEqualTo(2);
        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redis).execute(any(RedisScript.class), keys.capture(), any(), any(), any(), any());
        assertThat(keys.getValue()).hasSize(3)
                .allMatch(key -> !key.contains("user-17")
                        && !key.contains("token-secret-id")
                        && !key.contains("oauth-client"));
        assertThat(keys.getValue().get(2)).contains(":risk:destructive:");
    }

    @Test
    void disabledLimiterDoesNotAccessRedis() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        RedisMcpRateLimiter limiter = new RedisMcpRateLimiter(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new McpRateLimitProperties(false, Duration.ofMinutes(1), 10, 20, 8, 4, 2, 6));

        assertThat(limiter.checkAndConsume(caller(), McpToolRisk.READ).allowed()).isTrue();
        verifyNoInteractions(redis);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void missingRedisScriptDecisionFailsClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(null).when(redis).execute(
                any(RedisScript.class), anyList(), any(), any(), any(), any());
        RedisMcpRateLimiter limiter = new RedisMcpRateLimiter(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new McpRateLimitProperties(true, Duration.ofMinutes(1), 10, 20, 8, 4, 2, 6));

        assertThatThrownBy(() -> limiter.checkAndConsume(caller(), McpToolRisk.READ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("MCP rate-limit store returned no decision");
    }

    private static CurrentCaller caller() {
        return new CurrentCaller(
                CallerType.USER, "user-17", "operator", "Operator",
                "token-secret-id", "oauth-client", Set.of(), Set.of(), Set.of(), "trace-1");
    }
}
