package dev.webstarter.mcp.governance;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpSessionProperties;
import dev.webstarter.security.token.TokenHasher;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

class RedisMcpSessionRegistryTest {

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void missingRedisReservationDecisionFailsClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(null).when(redis).execute(
                any(RedisScript.class), anyList(), any(), any(), any(), any(), any());
        RedisMcpSessionRegistry registry = new RedisMcpSessionRegistry(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new McpSessionProperties(
                        true, Duration.ofMinutes(1), Duration.ofHours(1), 4,
                        Duration.ofSeconds(30)),
                Clock.fixed(Instant.parse("2026-07-20T00:00:00Z"), ZoneOffset.UTC),
                "test-node");

        assertThatThrownBy(() -> registry.reserve(caller()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("MCP session store returned no reservation decision");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void missingRedisValidationDecisionFailsClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doReturn(null).when(redis).execute(
                any(RedisScript.class), anyList(),
                any(), any(), any(), any(), any(), any(), any());
        RedisMcpSessionRegistry registry = new RedisMcpSessionRegistry(
                redis,
                new TokenHasher("0123456789abcdef0123456789abcdef"),
                new McpSessionProperties(
                        true, Duration.ofMinutes(1), Duration.ofHours(1), 4,
                        Duration.ofSeconds(30)),
                Clock.fixed(Instant.parse("2026-07-20T00:00:00Z"), ZoneOffset.UTC),
                "test-node");

        assertThatThrownBy(() -> registry.validateAndTouch(caller(), "session-1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("MCP session store returned no validation decision");
    }

    private static CurrentCaller caller() {
        return new CurrentCaller(
                CallerType.USER, "17", "operator", "Operator", "token-1", "client-1",
                Set.of(), Set.of(), Set.of(), "trace-session-null");
    }
}
