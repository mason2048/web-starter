package dev.webstarter.mcp.governance;

import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpSessionProperties;
import dev.webstarter.security.token.TokenHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** Redis-backed, rebuildable lifecycle index for node-local MCP SDK sessions. */
public final class RedisMcpSessionRegistry implements McpSessionRegistry {

    private static final Logger log = LoggerFactory.getLogger(RedisMcpSessionRegistry.class);
    private static final String KEY_PREFIX = "web-starter:mcp:session:";

    private static final DefaultRedisScript<Long> RESERVE_SCRIPT = new DefaultRedisScript<>("""
            local now = tonumber(ARGV[1])
            local maximum = tonumber(ARGV[2])
            local reservation_ttl = tonumber(ARGV[3])
            redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
            if redis.call('ZCARD', KEYS[1]) >= maximum then
              local first = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
              local retry = reservation_ttl
              if first[2] then retry = math.max(1, tonumber(first[2]) - now) end
              return retry
            end
            redis.call('ZADD', KEYS[1], now + reservation_ttl, ARGV[4])
            redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[5]))
            return 0
            """, Long.class);

    private static final DefaultRedisScript<Long> ACTIVATE_SCRIPT = new DefaultRedisScript<>("""
            local reservation_expires = redis.call('ZSCORE', KEYS[1], ARGV[1])
            if not reservation_expires then return 0 end
            local now = tonumber(ARGV[6])
            if tonumber(reservation_expires) <= now then
              redis.call('ZREM', KEYS[1], ARGV[1])
              return -1
            end
            redis.call('ZREM', KEYS[1], ARGV[1])
            local idle = tonumber(ARGV[7])
            local absolute = tonumber(ARGV[8])
            local expires = math.min(now + idle, now + absolute)
            redis.call('HSET', KEYS[2],
              'owner', ARGV[3], 'subject', ARGV[4], 'client', ARGV[5],
              'created', now, 'last_seen', now, 'node', ARGV[9])
            redis.call('PEXPIRE', KEYS[2], absolute + tonumber(ARGV[10]))
            redis.call('ZADD', KEYS[1], expires, ARGV[2])
            redis.call('PEXPIRE', KEYS[1], absolute + tonumber(ARGV[10]))
            redis.call('SADD', KEYS[3], ARGV[11])
            redis.call('PEXPIRE', KEYS[3], absolute + tonumber(ARGV[10]))
            return 1
            """, Long.class);

    private static final DefaultRedisScript<Long> VALIDATE_SCRIPT = new DefaultRedisScript<>("""
            local values = redis.call('HMGET', KEYS[1], 'owner', 'created', 'last_seen')
            if not values[1] then return 0 end
            if values[1] ~= ARGV[1] then return -1 end
            local now = tonumber(ARGV[3])
            local created = tonumber(values[2])
            local last_seen = tonumber(values[3])
            local idle = tonumber(ARGV[4])
            local absolute = tonumber(ARGV[5])
            if now >= created + absolute or now >= last_seen + idle then
              redis.call('DEL', KEYS[1])
              redis.call('ZREM', KEYS[2], ARGV[2])
              redis.call('SREM', KEYS[3], ARGV[6])
              return -2
            end
            local remaining = math.min(idle, created + absolute - now)
            redis.call('HSET', KEYS[1], 'last_seen', now)
            redis.call('PEXPIRE', KEYS[1], math.max(1, created + absolute - now + tonumber(ARGV[7])))
            redis.call('ZADD', KEYS[2], now + remaining, ARGV[2])
            return remaining
            """, Long.class);

    private static final DefaultRedisScript<Long> DELETE_SCRIPT = new DefaultRedisScript<>("""
            local owner = redis.call('HGET', KEYS[1], 'owner')
            if not owner then return 0 end
            if owner ~= ARGV[1] then return -1 end
            redis.call('DEL', KEYS[1])
            redis.call('ZREM', KEYS[2], ARGV[2])
            redis.call('SREM', KEYS[3], ARGV[3])
            return 1
            """, Long.class);

    private final StringRedisTemplate redis;
    private final TokenHasher tokenHasher;
    private final McpSessionProperties properties;
    private final Clock clock;
    private final String nodeId;

    public RedisMcpSessionRegistry(
            StringRedisTemplate redis,
            TokenHasher tokenHasher,
            McpSessionProperties properties,
            Clock clock,
            String nodeId) {
        this.redis = redis;
        this.tokenHasher = tokenHasher;
        this.properties = properties;
        this.clock = clock;
        this.nodeId = nodeId;
    }

    @Override
    public Reservation reserve(CurrentCaller caller) {
        if (!properties.enabled()) {
            return acceptedReservation(caller, "disabled");
        }
        String reservationId = UUID.randomUUID().toString().replace("-", "");
        Reservation reservation = acceptedReservation(caller, reservationId);
        String reservationMember = reservationMember(reservationId);
        Long retryMillis = redis.execute(
                RESERVE_SCRIPT,
                List.of(subjectKey(reservation.subjectHash())),
                Long.toString(clock.millis()),
                Integer.toString(properties.maxPerSubject()),
                Long.toString(properties.reservationTtl().toMillis()),
                reservationMember,
                Long.toString(properties.absoluteTtl().plus(properties.reservationTtl()).toMillis()));
        if (retryMillis == null) {
            throw new IllegalStateException("MCP session store returned no reservation decision");
        }
        if (retryMillis <= 0) {
            return reservation;
        }
        return Reservation.rejected(toSecondsCeiling(retryMillis));
    }

    @Override
    public void activate(Reservation reservation, String sessionId) {
        if (!properties.enabled()) {
            return;
        }
        requireAccepted(reservation);
        String sessionHash = sessionHash(sessionId);
        String member = sessionMember(sessionHash);
        String nodeMember = nodeMember(reservation.subjectHash(), sessionHash);
        Long activated = redis.execute(
                ACTIVATE_SCRIPT,
                List.of(
                        subjectKey(reservation.subjectHash()),
                        metadataKey(sessionHash),
                        nodeKey()),
                reservationMember(reservation.reservationId()),
                member,
                reservation.ownerHash(),
                reservation.subjectHash(),
                reservation.clientHash(),
                Long.toString(clock.millis()),
                Long.toString(properties.idleTtl().toMillis()),
                Long.toString(properties.absoluteTtl().toMillis()),
                nodeId,
                Long.toString(properties.reservationTtl().toMillis()),
                nodeMember);
        if (activated == null || activated != 1L) {
            throw new IllegalStateException("MCP session reservation expired before activation");
        }
    }

    @Override
    public void release(Reservation reservation) {
        if (!properties.enabled() || reservation == null || !reservation.accepted()
                || reservation.reservationId() == null || reservation.subjectHash() == null) {
            return;
        }
        redis.opsForZSet().remove(
                subjectKey(reservation.subjectHash()),
                reservationMember(reservation.reservationId()));
    }

    @Override
    public Validation validateAndTouch(CurrentCaller caller, String sessionId) {
        if (!properties.enabled()) {
            return Validation.ACTIVE;
        }
        Identity identity = identity(caller);
        String sessionHash = sessionHash(sessionId);
        Long result = redis.execute(
                VALIDATE_SCRIPT,
                List.of(metadataKey(sessionHash), subjectKey(identity.subjectHash()), nodeKey()),
                identity.ownerHash(),
                sessionMember(sessionHash),
                Long.toString(clock.millis()),
                Long.toString(properties.idleTtl().toMillis()),
                Long.toString(properties.absoluteTtl().toMillis()),
                nodeMember(identity.subjectHash(), sessionHash),
                Long.toString(properties.reservationTtl().toMillis()));
        return validation(result);
    }

    @Override
    public Validation delete(CurrentCaller caller, String sessionId) {
        if (!properties.enabled()) {
            return Validation.ACTIVE;
        }
        Identity identity = identity(caller);
        String sessionHash = sessionHash(sessionId);
        Long result = redis.execute(
                DELETE_SCRIPT,
                List.of(metadataKey(sessionHash), subjectKey(identity.subjectHash()), nodeKey()),
                identity.ownerHash(),
                sessionMember(sessionHash),
                nodeMember(identity.subjectHash(), sessionHash));
        return validation(result);
    }

    @Override
    public void cleanupNodeSessions() {
        if (!properties.enabled()) {
            return;
        }
        Set<String> members = redis.opsForSet().members(nodeKey());
        if (members == null || members.isEmpty()) {
            redis.delete(nodeKey());
            return;
        }
        for (String member : members) {
            String[] parts = member.split(":", 2);
            if (parts.length != 2 || !isHash(parts[0]) || !isHash(parts[1])) {
                log.warn("Ignoring malformed MCP node session index entry");
                continue;
            }
            redis.delete(metadataKey(parts[1]));
            redis.opsForZSet().remove(subjectKey(parts[0]), sessionMember(parts[1]));
        }
        redis.delete(nodeKey());
    }

    private Reservation acceptedReservation(CurrentCaller caller, String reservationId) {
        Identity identity = identity(caller);
        return new Reservation(
                true, 0, reservationId,
                identity.subjectHash(), identity.ownerHash(), identity.clientHash());
    }

    private Identity identity(CurrentCaller caller) {
        String subjectHash = hash("subject:" + caller.callerType() + ":" + caller.subjectId());
        String clientHash = hash("client:" + RedisMcpRateLimiter.clientIdentity(caller));
        String ownerHash = hash("owner:" + subjectHash + ":" + clientHash);
        return new Identity(subjectHash, ownerHash, clientHash);
    }

    private String sessionHash(String sessionId) {
        if (sessionId == null || sessionId.isBlank() || sessionId.length() > 512) {
            throw new IllegalArgumentException("MCP session ID is invalid");
        }
        return hash("session:" + sessionId);
    }

    private String hash(String value) {
        return tokenHasher.hash("mcp-session:" + value);
    }

    private String subjectKey(String subjectHash) {
        return KEY_PREFIX + "subject:" + subjectHash;
    }

    private String metadataKey(String sessionHash) {
        return KEY_PREFIX + "metadata:" + sessionHash;
    }

    private String nodeKey() {
        return KEY_PREFIX + "node:" + nodeId;
    }

    private static String reservationMember(String reservationId) {
        return "r:" + reservationId;
    }

    private static String sessionMember(String sessionHash) {
        return "s:" + sessionHash;
    }

    private static String nodeMember(String subjectHash, String sessionHash) {
        return subjectHash + ":" + sessionHash;
    }

    private static Validation validation(Long result) {
        if (result == null) {
            throw new IllegalStateException("MCP session store returned no validation decision");
        }
        if (result == 0L) {
            return Validation.MISSING;
        }
        if (result == -1L) {
            return Validation.OWNER_MISMATCH;
        }
        if (result == -2L) {
            return Validation.EXPIRED;
        }
        return Validation.ACTIVE;
    }

    private static void requireAccepted(Reservation reservation) {
        if (reservation == null || !reservation.accepted() || reservation.reservationId() == null) {
            throw new IllegalArgumentException("Accepted MCP session reservation is required");
        }
    }

    private static long toSecondsCeiling(long millis) {
        return millis / 1_000 + (millis % 1_000 == 0 ? 0 : 1);
    }

    private static boolean isHash(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    private record Identity(String subjectHash, String ownerHash, String clientHash) {
    }
}
