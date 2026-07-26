package dev.webstarter.mcp.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Supplier;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;
import io.modelcontextprotocol.json.McpJsonMapper;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpIdempotencyProperties;
import dev.webstarter.mcp.persistence.mapper.McpIdempotencyMapper;
import dev.webstarter.mcp.persistence.model.McpIdempotencyRecord;

@Service
public class McpIdempotencyService {

    static final String ARGUMENT_NAME = "idempotencyKey";
    private static final String PENDING = "PENDING";
    private static final String COMPLETED = "COMPLETED";

    private final McpIdempotencyMapper mapper;
    private final CallerContext callerContext;
    private final McpJsonMapper jsonMapper;
    private final McpIdempotencyProperties properties;

    public McpIdempotencyService(
            McpIdempotencyMapper mapper,
            CallerContext callerContext,
            McpJsonMapper jsonMapper,
            McpIdempotencyProperties properties) {
        this.mapper = mapper;
        this.callerContext = callerContext;
        this.jsonMapper = jsonMapper;
        this.properties = properties;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public <T> T execute(
            String toolName,
            Map<String, Object> arguments,
            String idempotencyKey,
            Supplier<T> action) {
        if (idempotencyKey == null) {
            return action.get();
        }

        validateKey(idempotencyKey);
        CurrentCaller caller = callerContext.required();
        String namespaceHash = sha256(namespace(caller));
        String keyHash = sha256(idempotencyKey);
        String requestHash = sha256(writeJson(canonicalArguments(arguments)));
        LocalDateTime now = LocalDateTime.now();

        McpInvocationMetadata.idempotency(keyHash, false);

        McpIdempotencyRecord reservation = new McpIdempotencyRecord();
        reservation.setId(IdWorker.getId());
        reservation.setNamespaceHash(namespaceHash);
        reservation.setToolName(toolName);
        reservation.setIdempotencyKeyHash(keyHash);
        reservation.setReservationNonce(UUID.randomUUID().toString().replace("-", ""));
        reservation.setRequestHash(requestHash);
        reservation.setStatus(PENDING);
        reservation.setCreatedAt(now);
        reservation.setExpiresAt(now.plus(properties.ttl()));

        mapper.claim(reservation);
        McpIdempotencyRecord existing = mapper.findForUpdate(namespaceHash, toolName, keyHash);
        if (existing == null) {
            throw new IllegalStateException("Unable to load MCP idempotency reservation");
        }
        boolean acquired = reservation.getReservationNonce().equals(existing.getReservationNonce());

        if (acquired) {
            T result = action.get();
            String responseJson = writeJson(result);
            LocalDateTime completedAt = LocalDateTime.now();
            if (mapper.complete(namespaceHash, toolName, keyHash, reservation.getReservationNonce(),
                    responseJson, resourceId(result),
                    completedAt, completedAt.plus(properties.ttl())) != 1) {
                throw new IllegalStateException("Unable to complete MCP idempotency record");
            }
            return result;
        }

        if (!requestHash.equals(existing.getRequestHash())) {
            throw new McpIdempotencyConflictException(
                    "The idempotency key was already used with different arguments");
        }
        if (!COMPLETED.equals(existing.getStatus()) || existing.getResponseJson() == null) {
            throw new McpIdempotencyInProgressException();
        }

        McpInvocationMetadata.idempotency(keyHash, true);
        return readJson(existing.getResponseJson());
    }

    static void validateKey(String value) {
        if (value.length() < 16 || value.length() > 128
                || !value.matches("[A-Za-z0-9._:-]+")) {
            throw new IllegalArgumentException(
                    "idempotencyKey must be 16-128 URL-safe characters");
        }
    }

    private static String namespace(CurrentCaller caller) {
        String credential = hasText(caller.clientId())
                ? "client:" + caller.clientId()
                : "credential:" + (caller.tokenId() == null ? "session" : caller.tokenId());
        return caller.callerType().name() + ':' + caller.subjectId() + ':' + credential;
    }

    private Map<String, Object> canonicalArguments(Map<String, Object> arguments) {
        Map<String, Object> withoutKey = new LinkedHashMap<>(arguments == null ? Map.of() : arguments);
        withoutKey.remove(ARGUMENT_NAME);
        return canonicalMap(withoutKey);
    }

    private static Map<String, Object> canonicalMap(Map<String, Object> source) {
        Map<String, Object> result = new TreeMap<>();
        source.forEach((key, value) -> result.put(key, canonicalValue(value)));
        return result;
    }

    private static Object canonicalValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> stringMap = new LinkedHashMap<>();
            map.forEach((key, item) -> stringMap.put(String.valueOf(key), item));
            return canonicalMap(stringMap);
        }
        if (value instanceof List<?> list) {
            List<Object> result = new ArrayList<>(list.size());
            list.forEach(item -> result.add(canonicalValue(item)));
            return result;
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private <T> T readJson(String value) {
        try {
            return (T) jsonMapper.readValue(value, Object.class);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Unable to deserialize MCP idempotency result", exception);
        }
    }

    private String writeJson(Object value) {
        try {
            return jsonMapper.writeValueAsString(value);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Unable to serialize MCP idempotency value", exception);
        }
    }

    private static String resourceId(Object result) {
        if (result instanceof Map<?, ?> map && map.get("id") != null) {
            return String.valueOf(map.get("id"));
        }
        try {
            Object converted = result == null ? null : result.getClass().getMethod("id").invoke(result);
            return converted == null ? null : String.valueOf(converted);
        }
        catch (ReflectiveOperationException ignored) {
            return null;
        }
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
