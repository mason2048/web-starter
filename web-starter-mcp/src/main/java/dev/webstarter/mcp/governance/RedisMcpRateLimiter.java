package dev.webstarter.mcp.governance;

import java.util.List;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpRateLimitProperties;
import dev.webstarter.security.token.TokenHasher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/**
 * Atomic fixed-window application limiter. Redis keys contain keyed HMAC
 * pseudonyms only; caller, token and client identifiers are never used as key
 * material in plaintext.
 */
public final class RedisMcpRateLimiter implements McpRateLimiter {

    private static final String KEY_PREFIX = "web-starter:mcp:rate:";
    private static final DefaultRedisScript<Long> CONSUME_SCRIPT = new DefaultRedisScript<>("""
            local retry = 0
            local window = tonumber(ARGV[4])
            for i = 1, #KEYS do
              local count = tonumber(redis.call('GET', KEYS[i]) or '0')
              local limit = tonumber(ARGV[i])
              if count >= limit then
                local ttl = redis.call('PTTL', KEYS[i])
                if ttl < 1 then
                  ttl = window
                  redis.call('PEXPIRE', KEYS[i], ttl)
                end
                if ttl > retry then retry = ttl end
              end
            end
            if retry > 0 then return retry end
            for i = 1, #KEYS do
              local count = redis.call('INCR', KEYS[i])
              if count == 1 or redis.call('PTTL', KEYS[i]) < 1 then
                redis.call('PEXPIRE', KEYS[i], window)
              end
            end
            return 0
            """, Long.class);

    private final StringRedisTemplate redis;
    private final TokenHasher tokenHasher;
    private final McpRateLimitProperties properties;

    public RedisMcpRateLimiter(
            StringRedisTemplate redis,
            TokenHasher tokenHasher,
            McpRateLimitProperties properties) {
        this.redis = redis;
        this.tokenHasher = tokenHasher;
        this.properties = properties;
    }

    @Override
    public Decision checkAndConsume(CurrentCaller caller, McpToolRisk risk) {
        if (!properties.enabled()) {
            return Decision.permit();
        }
        String subjectHash = hash("subject:" + caller.callerType() + ":" + caller.subjectId());
        String clientHash = hash("client:" + clientIdentity(caller));
        String ownerHash = hash("owner:" + subjectHash + ":" + clientHash);
        Long retryMillis = redis.execute(
                CONSUME_SCRIPT,
                List.of(
                        KEY_PREFIX + "subject:" + subjectHash,
                        KEY_PREFIX + "client:" + clientHash,
                        KEY_PREFIX + "risk:" + risk.name().toLowerCase() + ":" + ownerHash),
                Integer.toString(properties.maxPerSubject()),
                Integer.toString(properties.maxPerClient()),
                Integer.toString(properties.limitFor(risk)),
                Long.toString(properties.window().toMillis()));
        if (retryMillis == null) {
            throw new IllegalStateException("MCP rate-limit store returned no decision");
        }
        if (retryMillis <= 0) {
            return Decision.permit();
        }
        return Decision.blocked(toSecondsCeiling(retryMillis));
    }

    private String hash(String value) {
        return tokenHasher.hash("mcp-rate-limit:" + value);
    }

    static String clientIdentity(CurrentCaller caller) {
        if (hasText(caller.clientId())) {
            return "oauth:" + caller.clientId();
        }
        if (hasText(caller.tokenId())) {
            return "credential:" + caller.tokenId();
        }
        return "subject:" + caller.callerType() + ":" + caller.subjectId();
    }

    private static long toSecondsCeiling(long millis) {
        return millis / 1_000 + (millis % 1_000 == 0 ? 0 : 1);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
