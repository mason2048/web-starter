package dev.webstarter.security.login;

import java.util.List;
import java.util.Locale;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import dev.webstarter.security.token.TokenHasher;

/** Atomic Redis progressive-backoff limiter. Redis keys contain only HMAC pseudonyms. */
public final class RedisLoginAttemptLimiter implements LoginAttemptLimiter {

    private static final DefaultRedisScript<Long> CHECK_SCRIPT = new DefaultRedisScript<>("""
            local time = redis.call('TIME')
            local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
            local retry = 0
            for i = 1, #KEYS do
              local blockedUntil = tonumber(redis.call('HGET', KEYS[i], 'blocked_until') or '0')
              if blockedUntil > now then
                local remaining = blockedUntil - now
                if remaining > retry then retry = remaining end
              end
            end
            return retry
            """, Long.class);

    private static final DefaultRedisScript<Long> FAILURE_SCRIPT = new DefaultRedisScript<>("""
            local time = redis.call('TIME')
            local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
            local retry = 0
            local window = tonumber(ARGV[3])
            local initialBackoff = tonumber(ARGV[4])
            local maxBackoff = tonumber(ARGV[5])
            for i = 1, #KEYS do
              local count = redis.call('HINCRBY', KEYS[i], 'failures', 1)
              if count >= tonumber(ARGV[i]) then
                local exponent = count - tonumber(ARGV[i])
                if exponent > 20 then exponent = 20 end
                local delay = initialBackoff * (2 ^ exponent)
                if delay > maxBackoff then delay = maxBackoff end
                redis.call('HSET', KEYS[i], 'blocked_until', now + delay)
                if delay > retry then retry = delay end
              end
              local ttl = window
              if retry > ttl then ttl = retry end
              redis.call('PEXPIRE', KEYS[i], ttl)
            end
            return retry
            """, Long.class);

    private final StringRedisTemplate redis;
    private final TokenHasher tokenHasher;
    private final LoginRateLimitProperties properties;

    public RedisLoginAttemptLimiter(
            StringRedisTemplate redis,
            TokenHasher tokenHasher,
            LoginRateLimitProperties properties) {
        this.redis = redis;
        this.tokenHasher = tokenHasher;
        this.properties = properties;
    }

    @Override
    public LoginRateLimitDecision check(String username, String ipAddress) {
        if (!properties.enabled()) {
            return LoginRateLimitDecision.permit();
        }
        Long retryMillis;
        try {
            retryMillis = redis.execute(
                    CHECK_SCRIPT,
                    keys(username, ipAddress),
                    "0");
        }
        catch (RuntimeException exception) {
            throw unavailable(exception);
        }
        return decision(retryMillis);
    }

    @Override
    public LoginRateLimitDecision recordFailure(String username, String ipAddress) {
        if (!properties.enabled()) {
            return LoginRateLimitDecision.permit();
        }
        Long retryMillis;
        try {
            retryMillis = redis.execute(
                    FAILURE_SCRIPT,
                    keys(username, ipAddress),
                    Integer.toString(properties.maxFailuresPerIdentity()),
                    Integer.toString(properties.maxFailuresPerPair()),
                    Long.toString(properties.window().toMillis()),
                    Long.toString(properties.initialBackoff().toMillis()),
                    Long.toString(properties.maxBackoff().toMillis()));
        }
        catch (RuntimeException exception) {
            throw unavailable(exception);
        }
        return decision(retryMillis);
    }

    @Override
    public void recordSuccess(String username, String ipAddress) {
        if (properties.enabled()) {
            Long deleted;
            try {
                deleted = redis.delete(keys(username, ipAddress));
            }
            catch (RuntimeException exception) {
                throw unavailable(exception);
            }
            if (deleted == null) {
                throw new LoginRateLimitUnavailableException();
            }
        }
    }

    private List<String> keys(String username, String ipAddress) {
        return List.of(identityKey(username), pairKey(username, ipAddress));
    }

    private String identityKey(String username) {
        String normalized = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        return "web-starter:login-limit:identity:" + tokenHasher.hash("login-identity:" + normalized);
    }

    private String pairKey(String username, String ipAddress) {
        String normalizedUsername = username == null
                ? "" : username.trim().toLowerCase(Locale.ROOT);
        String normalizedIp = ipAddress == null
                ? "unknown" : ipAddress.trim().toLowerCase(Locale.ROOT);
        return "web-starter:login-limit:pair:"
                + tokenHasher.hash("login-pair:" + normalizedUsername + '\n' + normalizedIp);
    }

    private static LoginRateLimitDecision decision(Long retryMillis) {
        if (retryMillis == null) {
            throw new LoginRateLimitUnavailableException();
        }
        if (retryMillis <= 0) {
            return LoginRateLimitDecision.permit();
        }
        long retrySeconds = retryMillis / 1_000 + (retryMillis % 1_000 == 0 ? 0 : 1);
        return LoginRateLimitDecision.blocked(retrySeconds);
    }

    private static LoginRateLimitUnavailableException unavailable(RuntimeException exception) {
        if (exception instanceof LoginRateLimitUnavailableException unavailable) {
            return unavailable;
        }
        return new LoginRateLimitUnavailableException(exception);
    }
}
