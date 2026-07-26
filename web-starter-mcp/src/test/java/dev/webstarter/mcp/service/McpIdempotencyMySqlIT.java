package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import io.modelcontextprotocol.json.McpJsonDefaults;

import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.mysql.MySQLContainer;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpIdempotencyProperties;
import dev.webstarter.mcp.persistence.mapper.McpIdempotencyMapper;

/**
 * Opt-in MySQL 8.4 locking acceptance. It exercises the annotated mapper SQL and
 * service algorithm with independent database transactions.
 */
class McpIdempotencyMySqlIT {

    private static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4");

    private static SqlSessionFactory sessions;

    @BeforeAll
    static void startMySql() throws Exception {
        MYSQL.start();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword());
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE mcp_idempotency_record (
                        id BIGINT NOT NULL,
                        namespace_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                        tool_name VARCHAR(128) NOT NULL,
                        idempotency_key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                        reservation_nonce CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                        request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        response_json JSON NULL,
                        resource_id VARCHAR(128) NULL,
                        created_at DATETIME(6) NOT NULL,
                        completed_at DATETIME(6) NULL,
                        expires_at DATETIME(6) NOT NULL,
                        PRIMARY KEY (id),
                        UNIQUE KEY uk_mcp_idempotency_identity
                            (namespace_hash, tool_name, idempotency_key_hash),
                        KEY idx_mcp_idempotency_expiry (expires_at, id)
                    ) ENGINE=InnoDB
                    """);
            statement.execute("""
                    CREATE TABLE mcp_business_effect (
                        id BIGINT NOT NULL AUTO_INCREMENT,
                        effect_key VARCHAR(128) NOT NULL,
                        effect_value VARCHAR(128) NOT NULL,
                        PRIMARY KEY (id),
                        KEY idx_mcp_business_effect_key (effect_key)
                    ) ENGINE=InnoDB
                    """);
        }
        org.apache.ibatis.session.Configuration configuration =
                new org.apache.ibatis.session.Configuration(new Environment(
                        "mysql-it", new JdbcTransactionFactory(), dataSource));
        configuration.addMapper(McpIdempotencyMapper.class);
        sessions = new SqlSessionFactoryBuilder().build(configuration);
    }

    @AfterAll
    static void stopMySql() {
        MYSQL.stop();
    }

    @ParameterizedTest(name = "{0} commits once across three concurrent first attempts")
    @ValueSource(strings = {"project.create", "project.update", "project.remove"})
    void threeConcurrentFirstAttemptsCommitTheBusinessActionOnlyOnce(String toolName) throws Exception {
        String suffix = toolName.substring(toolName.indexOf('.') + 1);
        String effectKey = "fresh-concurrency-effect-" + suffix;
        AtomicInteger writes = new AtomicInteger();
        List<Object> results = concurrentAttempts(
                3,
                "fresh-concurrency-key-" + suffix,
                Duration.ofHours(1),
                writes,
                true,
                effectKey,
                toolName);

        assertThat(writes).hasValue(1);
        assertThat(countBusinessEffects(effectKey)).isEqualTo(1);
        assertThat(results).hasSize(3).allSatisfy(result ->
                assertThat(result).isEqualTo(Map.of("id", "42", "name", "Concurrent")));
    }

    @Test
    void twoConcurrentAttemptsAtomicallyReplaceOneExpiredRecord() throws Exception {
        String key = "expired-concurrency-key-01";
        String effectKey = "expired-concurrency-effect-01";
        AtomicInteger seedWrites = new AtomicInteger();
        executeInTransaction(key, Duration.ofMillis(5), seedWrites, false,
                effectKey, "project.create", "Concurrent", caller("7", "agent-client"), false);
        assertThat(seedWrites).hasValue(1);
        assertThat(countBusinessEffects(effectKey)).isEqualTo(1);
        Thread.sleep(30);

        AtomicInteger retryWrites = new AtomicInteger();
        List<Object> results = concurrentAttempts(
                2,
                key,
                Duration.ofHours(1),
                retryWrites,
                true,
                effectKey,
                "project.create");

        assertThat(retryWrites).hasValue(1);
        assertThat(countBusinessEffects(effectKey)).isEqualTo(2);
        assertThat(results).hasSize(2).allSatisfy(result ->
                assertThat(result).isEqualTo(Map.of("id", "42", "name", "Concurrent")));
    }

    @Test
    void concurrentDifferentArgumentsCommitOneActionAndReturnOneConflict() throws Exception {
        String key = "different-arguments-key-0001";
        String effectKey = "different-arguments-effect-0001";
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<Object>> futures = List.of(
                    executor.submit(() -> attemptAfterBarrier(
                            ready, start, key, "First", effectKey)),
                    executor.submit(() -> attemptAfterBarrier(
                            ready, start, key, "Second", effectKey)));
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            List<Object> outcomes = new ArrayList<>();
            for (Future<Object> future : futures) {
                outcomes.add(future.get(20, TimeUnit.SECONDS));
            }
            assertThat(outcomes.stream().filter(Map.class::isInstance)).hasSize(1);
            assertThat(outcomes.stream().filter(McpIdempotencyConflictException.class::isInstance))
                    .hasSize(1);
        }
        assertThat(countBusinessEffects(effectKey)).isEqualTo(1);
    }

    @Test
    void failedBusinessTransactionRollsBackReservationAndSideEffectBeforeRetry() {
        String key = "rollback-retry-key-000001";
        String effectKey = "rollback-retry-effect-000001";
        AtomicInteger writes = new AtomicInteger();
        int recordsBeforeAttempt = countIdempotencyRecords();

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> executeInTransaction(
                        key, Duration.ofHours(1), writes, false, effectKey,
                        "project.create", "Rollback", caller("7", "agent-client"), true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Deliberate business failure");
        assertThat(countBusinessEffects(effectKey)).isZero();
        assertThat(countIdempotencyRecords()).isEqualTo(recordsBeforeAttempt);

        Object retried = executeInTransaction(
                key, Duration.ofHours(1), writes, false, effectKey,
                "project.create", "Rollback", caller("7", "agent-client"), false);
        assertThat(retried).isEqualTo(Map.of("id", "42", "name", "Rollback"));
        assertThat(countBusinessEffects(effectKey)).isEqualTo(1);
        assertThat(countIdempotencyRecords()).isEqualTo(recordsBeforeAttempt + 1);
    }

    @Test
    void sameKeyIsIsolatedBySubjectClientAndTool() {
        String key = "namespace-isolation-key-001";
        String effectKey = "namespace-isolation-effect-001";
        AtomicInteger writes = new AtomicInteger();

        executeInTransaction(key, Duration.ofHours(1), writes, false, effectKey,
                "project.create", "Isolated", caller("7", "client-a"), false);
        executeInTransaction(key, Duration.ofHours(1), writes, false, effectKey,
                "project.create", "Isolated", caller("8", "client-a"), false);
        executeInTransaction(key, Duration.ofHours(1), writes, false, effectKey,
                "project.create", "Isolated", caller("7", "client-b"), false);
        executeInTransaction(key, Duration.ofHours(1), writes, false, effectKey,
                "project.update", "Isolated", caller("7", "client-a"), false);

        assertThat(writes).hasValue(4);
        assertThat(countBusinessEffects(effectKey)).isEqualTo(4);
    }

    @Test
    void completedRecordContainsOnlyHashesNecessaryReplayOutputAndIsPhysicallyCleaned() throws Exception {
        String key = "storage-redaction-key-0001";
        String keyHash = sha256(key);
        String effectKey = "storage-redaction-effect-0001";
        executeInTransaction(
                key, Duration.ofMillis(10), new AtomicInteger(), false, effectKey,
                "project.create", "Storage proof", caller("7", "agent-client"), false);

        try (SqlSession session = sessions.openSession(true);
                PreparedStatement statement = session.getConnection().prepareStatement("""
                        SELECT namespace_hash, idempotency_key_hash, request_hash, status,
                               response_json, resource_id, completed_at, expires_at
                          FROM mcp_idempotency_record
                         WHERE tool_name = 'project.create' AND idempotency_key_hash = ?
                        """)) {
            statement.setString(1, keyHash);
            try (ResultSet result = statement.executeQuery()) {
                assertThat(result.next()).isTrue();
                assertThat(result.getString("namespace_hash")).matches("[0-9a-f]{64}");
                assertThat(result.getString("idempotency_key_hash")).isEqualTo(keyHash);
                assertThat(result.getString("request_hash")).matches("[0-9a-f]{64}");
                assertThat(result.getString("status")).isEqualTo("COMPLETED");
                String replayJson = result.getString("response_json");
                assertThat(replayJson)
                        .contains("Storage proof")
                        .doesNotContain(key)
                        .doesNotContain("idempotencyKey")
                        .doesNotContain("access_token")
                        .doesNotContain("password")
                        .doesNotContain("secret");
                assertThat(result.getString("resource_id")).isEqualTo("42");
                LocalDateTime completedAt = result.getTimestamp("completed_at").toLocalDateTime();
                LocalDateTime expiresAt = result.getTimestamp("expires_at").toLocalDateTime();
                assertThat(expiresAt).isAfter(completedAt);
                assertThat(result.next()).isFalse();
            }
        }

        assertThat(idempotencyColumnNames()).containsExactly(
                "id", "namespace_hash", "tool_name", "idempotency_key_hash",
                "reservation_nonce", "request_hash", "status", "response_json",
                "resource_id", "created_at", "completed_at", "expires_at");

        Thread.sleep(40);
        try (SqlSession session = sessions.openSession(false)) {
            assertThat(session.getMapper(McpIdempotencyMapper.class)
                    .deleteExpiredBatch(LocalDateTime.now(), 500)).isGreaterThanOrEqualTo(1);
            session.commit();
        }
        assertThat(countIdempotencyRecords(keyHash)).isZero();
    }

    private static List<Object> concurrentAttempts(
            int count,
            String key,
            Duration ttl,
            AtomicInteger writes,
            boolean delayWriter,
            String effectKey,
            String toolName) throws Exception {
        CountDownLatch ready = new CountDownLatch(count);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(count)) {
            List<Future<Object>> futures = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                Callable<Object> task = () -> {
                    ready.countDown();
                    if (!start.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Concurrent start barrier timed out");
                    }
                    return executeInTransaction(key, ttl, writes, delayWriter,
                            effectKey, toolName, "Concurrent",
                            caller("7", "agent-client"), false);
                };
                futures.add(executor.submit(task));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            List<Object> results = new ArrayList<>();
            for (Future<Object> future : futures) {
                results.add(future.get(20, TimeUnit.SECONDS));
            }
            return results;
        }
    }

    private static Object executeInTransaction(
            String key,
            Duration ttl,
            AtomicInteger writes,
            boolean delayWriter,
            String effectKey,
            String toolName,
            String requestName,
            CurrentCaller caller,
            boolean failAfterWrite) {
        try (SqlSession session = sessions.openSession(false)) {
            McpIdempotencyService service = new McpIdempotencyService(
                    session.getMapper(McpIdempotencyMapper.class),
                    () -> Optional.of(caller),
                    McpJsonDefaults.getMapper(),
                    new McpIdempotencyProperties(ttl, Duration.ofMinutes(10)));
            try {
                Object result = service.execute(
                        toolName,
                        Map.of("name", requestName, McpIdempotencyService.ARGUMENT_NAME, key),
                        key,
                        () -> {
                            writes.incrementAndGet();
                            insertBusinessEffect(session, effectKey, requestName);
                            if (delayWriter) {
                                try {
                                    Thread.sleep(250);
                                }
                                catch (InterruptedException exception) {
                                    Thread.currentThread().interrupt();
                                    throw new IllegalStateException("Interrupted", exception);
                                }
                            }
                            if (failAfterWrite) {
                                throw new IllegalStateException("Deliberate business failure");
                            }
                            return Map.of("id", "42", "name", requestName);
                        });
                session.commit();
                return result;
            }
            catch (RuntimeException exception) {
                session.rollback();
                throw exception;
            }
        }
    }

    private static Object attemptAfterBarrier(
            CountDownLatch ready,
            CountDownLatch start,
            String key,
            String requestName,
            String effectKey) throws Exception {
        ready.countDown();
        if (!start.await(10, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Concurrent start barrier timed out");
        }
        try {
            return executeInTransaction(
                    key, Duration.ofHours(1), new AtomicInteger(), true, effectKey,
                    "project.create", requestName, caller("7", "agent-client"), false);
        }
        catch (McpIdempotencyConflictException exception) {
            return exception;
        }
    }

    private static void insertBusinessEffect(
            SqlSession session, String effectKey, String effectValue) {
        try (PreparedStatement statement = session.getConnection().prepareStatement(
                "INSERT INTO mcp_business_effect (effect_key, effect_value) VALUES (?, ?)")) {
            statement.setString(1, effectKey);
            statement.setString(2, effectValue);
            statement.executeUpdate();
        }
        catch (SQLException exception) {
            throw new IllegalStateException("Unable to insert test business effect", exception);
        }
    }

    private static int countBusinessEffects(String effectKey) {
        try (SqlSession session = sessions.openSession(true);
                PreparedStatement statement = session.getConnection().prepareStatement(
                        "SELECT COUNT(*) FROM mcp_business_effect WHERE effect_key = ?")) {
            statement.setString(1, effectKey);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
        catch (SQLException exception) {
            throw new IllegalStateException("Unable to count test business effects", exception);
        }
    }

    private static int countIdempotencyRecords() {
        try (SqlSession session = sessions.openSession(true);
                Statement statement = session.getConnection().createStatement();
                ResultSet result = statement.executeQuery(
                        "SELECT COUNT(*) FROM mcp_idempotency_record")) {
            result.next();
            return result.getInt(1);
        }
        catch (SQLException exception) {
            throw new IllegalStateException("Unable to count idempotency records", exception);
        }
    }

    private static int countIdempotencyRecords(String keyHash) {
        try (SqlSession session = sessions.openSession(true);
                PreparedStatement statement = session.getConnection().prepareStatement(
                        "SELECT COUNT(*) FROM mcp_idempotency_record WHERE idempotency_key_hash = ?")) {
            statement.setString(1, keyHash);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
        catch (SQLException exception) {
            throw new IllegalStateException("Unable to count one idempotency record", exception);
        }
    }

    private static List<String> idempotencyColumnNames() {
        try (SqlSession session = sessions.openSession(true);
                Statement statement = session.getConnection().createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT column_name
                          FROM information_schema.columns
                         WHERE table_schema = DATABASE()
                           AND table_name = 'mcp_idempotency_record'
                         ORDER BY ordinal_position
                        """)) {
            List<String> names = new ArrayList<>();
            while (result.next()) {
                names.add(result.getString(1));
            }
            return List.copyOf(names);
        }
        catch (SQLException exception) {
            throw new IllegalStateException("Unable to inspect idempotency columns", exception);
        }
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static CurrentCaller caller(String subjectId, String clientId) {
        return new CurrentCaller(
                CallerType.USER,
                subjectId,
                "operator",
                "Operator",
                "pat-17",
                clientId,
                Set.of("project:create"),
                Set.of("project:create"),
                Set.of(),
                "trace-it");
    }
}
