package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import org.junit.jupiter.api.Test;

/** Opt-in runtime acceptance for mutating tools, idempotency, and audit correlation. */
class McpSdkCrudRuntimeIT {

    private static final String TRANSACTION_FAILURE_PROJECT_CODE = "MCP_TX_ROLLBACK";
    private static final String TRANSACTION_FAILURE_IDEMPOTENCY_KEY =
            "crud-transaction-rollback";

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\\"(?:token|access_token)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern FORBIDDEN_AUDIT_FIELD = Pattern.compile(
            "\\\"(?:access_token|refresh_token|client_secret|password|authorization|cookie|"
                    + "requestBody|responseBody)\\\"\\s*:",
            Pattern.CASE_INSENSITIVE);

    @Test
    void provesEachWriteCommitsOnceAcrossConcurrencyRetryConflictAndAudit() throws Exception {
        String baseUrl = requiredEnvironment("WEB_STARTER_MCP_BASE_URL");
        String privateWebBaseUrl = requiredEnvironment(
                "WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL");
        String bearer = readBearer(Path.of(requiredEnvironment(
                "WEB_STARTER_MCP_TOKEN_RESPONSE_FILE")));
        String ownerId = requiredEnvironment("WEB_STARTER_MCP_OWNER_ID");
        String tracePrefix = requiredEnvironment("WEB_STARTER_MCP_TRACE_PREFIX");
        String adminUsername = requiredEnvironment("WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME");
        String adminPassword = requiredEnvironment("WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD");
        AtomicInteger requestNumber = new AtomicInteger();
        AtomicReference<String> currentTrace = new AtomicReference<>();

        try (WebAuditClient webAudit = WebAuditClient.login(
                    privateWebBaseUrl, adminUsername, adminPassword, List.of(bearer));
                var client = mutableTraceClient(
                baseUrl, bearer, currentTrace, requestNumber,
                "web-starter-crud-acceptance")) {
            useTrace(currentTrace, tracePrefix, "initialize");
            assertThat(client.initialize().protocolVersion()).isEqualTo("2025-11-25");

            proveBusinessRollbackAndIndependentFailureAudit(
                    client, webAudit, currentTrace, ownerId, tracePrefix, bearer);

            // Keep one deterministic committed CREATE trace. The browser audit
            // acceptance consumes this exact fixture after this test passes.
            String code = randomCode("MCP_CRUD");
            String createKey = "crud-create-" + UUID.randomUUID();
            Map<String, Object> createArguments = Map.of(
                    "name", "MCP CRUD Acceptance",
                    "code", code,
                    "ownerId", ownerId,
                    "status", "PLANNING",
                    "description", "Created by the official Java MCP SDK",
                    "idempotencyKey", createKey);
            String createTrace = useTrace(currentTrace, tracePrefix, "create-first");
            var created = client.callTool(new CallToolRequest("project.create", createArguments));
            assertThat(created.isError()).isFalse();
            Map<?, ?> createdProject = structuredMap(created.structuredContent());
            String projectId = requiredString(createdProject, "id");
            assertThat(projectId).matches("[1-9][0-9]*");
            assertThat(requiredNumber(createdProject, "version").intValue()).isZero();

            String createReplayTrace = useTrace(currentTrace, tracePrefix, "create-replay");
            var replayedCreate = client.callTool(new CallToolRequest("project.create", createArguments));
            assertSuccessfulReplay(replayedCreate, createdProject);

            String createConflictTrace = useTrace(currentTrace, tracePrefix, "create-conflict");
            assertIdempotencyConflict(client.callTool(new CallToolRequest("project.create", Map.of(
                    "name", "Different arguments",
                    "code", code,
                    "ownerId", ownerId,
                    "status", "PLANNING",
                    "idempotencyKey", createKey))));

            assertAudit(client, "project.create", createTrace, "SUCCESS", false, null,
                    createKey, bearer, currentTrace);
            assertAudit(client, "project.create", createReplayTrace, "SUCCESS", true, null,
                    createKey, bearer, currentTrace);
            assertAudit(client, "project.create", createConflictTrace, "FAILED", false,
                    "IDEMPOTENCY_CONFLICT", createKey, bearer, currentTrace);
            assertBusinessAuditBoundary(
                    webAudit, projectId, "CREATE", createTrace,
                    List.of(createReplayTrace, createConflictTrace), List.of(createKey));
            assertSingleVisibleProject(client, currentTrace, tracePrefix, code, projectId, 0);

            // A second project proves two simultaneous first CREATE attempts use
            // one reservation and produce one business row, not merely a cached
            // response after an already-completed sequential call.
            proveConcurrentCreate(
                    client, webAudit, currentTrace, requestNumber,
                    baseUrl, bearer, ownerId, tracePrefix);

            useTrace(currentTrace, tracePrefix, "get-created");
            var fetched = client.callTool(new CallToolRequest(
                    "project.get", Map.of("id", projectId)));
            assertThat(fetched.isError()).isFalse();
            assertThat(requiredString(structuredMap(fetched.structuredContent()), "code"))
                    .isEqualTo(code);

            String updateKey = "crud-update-" + UUID.randomUUID();
            Map<String, Object> updateArguments = Map.of(
                    "id", projectId,
                    "name", "MCP CRUD Acceptance Updated",
                    "ownerId", ownerId,
                    "status", "IN_PROGRESS",
                    "description", "Updated by the official Java MCP SDK",
                    "version", 0,
                    "idempotencyKey", updateKey);
            String updateTraceA = trace(tracePrefix, "update-concurrent-a");
            String updateTraceB = trace(tracePrefix, "update-concurrent-b");
            List<CallToolResult> updateResults = callConcurrently(
                    baseUrl, bearer, requestNumber, "project.update", updateArguments,
                    updateTraceA, updateTraceB);
            Map<?, ?> updatedProject = assertStableConcurrentSuccess(updateResults);
            assertThat(requiredString(updatedProject, "id")).isEqualTo(projectId);
            assertThat(requiredString(updatedProject, "status")).isEqualTo("IN_PROGRESS");
            int updatedVersion = requiredNumber(updatedProject, "version").intValue();
            assertThat(updatedVersion).isEqualTo(1);
            ConcurrentAudit updateConcurrentAudit = assertConcurrentAuditPair(
                    client, currentTrace, "project.update", updateTraceA, updateTraceB,
                    updateKey, bearer);

            String updateReplayTrace = useTrace(currentTrace, tracePrefix, "update-replay");
            assertSuccessfulReplay(
                    client.callTool(new CallToolRequest("project.update", updateArguments)),
                    updatedProject);
            String updateConflictTrace = useTrace(currentTrace, tracePrefix, "update-conflict");
            assertIdempotencyConflict(client.callTool(new CallToolRequest("project.update", Map.of(
                    "id", projectId,
                    "name", "Different update arguments",
                    "ownerId", ownerId,
                    "status", "IN_PROGRESS",
                    "version", 0,
                    "idempotencyKey", updateKey))));
            assertAudit(client, "project.update", updateReplayTrace, "SUCCESS", true, null,
                    updateKey, bearer, currentTrace);
            assertAudit(client, "project.update", updateConflictTrace, "FAILED", false,
                    "IDEMPOTENCY_CONFLICT", updateKey, bearer, currentTrace);
            assertBusinessAuditBoundary(
                    webAudit, projectId, "UPDATE", updateConcurrentAudit.committedTrace(),
                    List.of(updateConcurrentAudit.replayedTrace(), updateReplayTrace, updateConflictTrace),
                    List.of(createKey, updateKey));
            assertSingleVisibleProject(client, currentTrace, tracePrefix, code, projectId, 1);

            String removeKey = "crud-remove-" + UUID.randomUUID();
            Map<String, Object> removeArguments = Map.of(
                    "id", projectId,
                    "version", updatedVersion,
                    "idempotencyKey", removeKey);
            String removeTraceA = trace(tracePrefix, "remove-concurrent-a");
            String removeTraceB = trace(tracePrefix, "remove-concurrent-b");
            List<CallToolResult> removeResults = callConcurrently(
                    baseUrl, bearer, requestNumber, "project.remove", removeArguments,
                    removeTraceA, removeTraceB);
            Map<?, ?> removedResult = assertStableConcurrentSuccess(removeResults);
            assertThat(requiredString(removedResult, "id")).isEqualTo(projectId);
            assertThat(removedResult.get("removed")).isEqualTo(true);
            ConcurrentAudit removeConcurrentAudit = assertConcurrentAuditPair(
                    client, currentTrace, "project.remove", removeTraceA, removeTraceB,
                    removeKey, bearer);

            String removeReplayTrace = useTrace(currentTrace, tracePrefix, "remove-replay");
            assertSuccessfulReplay(
                    client.callTool(new CallToolRequest("project.remove", removeArguments)),
                    removedResult);
            String removeConflictTrace = useTrace(currentTrace, tracePrefix, "remove-conflict");
            assertIdempotencyConflict(client.callTool(new CallToolRequest("project.remove", Map.of(
                    "id", projectId,
                    "version", updatedVersion + 1,
                    "idempotencyKey", removeKey))));
            assertAudit(client, "project.remove", removeReplayTrace, "SUCCESS", true, null,
                    removeKey, bearer, currentTrace);
            assertAudit(client, "project.remove", removeConflictTrace, "FAILED", false,
                    "IDEMPOTENCY_CONFLICT", removeKey, bearer, currentTrace);
            assertBusinessAuditBoundary(
                    webAudit, projectId, "REMOVE", removeConcurrentAudit.committedTrace(),
                    List.of(removeConcurrentAudit.replayedTrace(), removeReplayTrace, removeConflictTrace),
                    List.of(createKey, updateKey, removeKey));

            useTrace(currentTrace, tracePrefix, "get-removed");
            var missing = client.callTool(new CallToolRequest(
                    "project.get", Map.of("id", projectId)));
            assertThat(missing.isError()).isTrue();
            assertThat(structuredMap(missing.structuredContent()).get("code"))
                    .isEqualTo("BUSINESS_4004");

            System.out.printf(
                    "MCP SDK CRUD idempotency acceptance passed: requests=%d tracePrefix=%s%n",
                    requestNumber.get(), tracePrefix);
        }
    }

    private static void proveBusinessRollbackAndIndependentFailureAudit(
            McpSyncClient client,
            WebAuditClient webAudit,
            AtomicReference<String> currentTrace,
            String ownerId,
            String tracePrefix,
            String bearer) throws Exception {
        String failureTrace = useTrace(
                currentTrace, tracePrefix, "transaction-audit-failure");
        var failed = client.callTool(new CallToolRequest("project.create", Map.of(
                "name", "MCP Transaction Rollback Acceptance",
                "code", TRANSACTION_FAILURE_PROJECT_CODE,
                "ownerId", ownerId,
                "status", "PLANNING",
                "description", "Must roll back when the joined operation audit fails",
                "idempotencyKey", TRANSACTION_FAILURE_IDEMPOTENCY_KEY)));

        assertThat(failed.isError()).isTrue();
        Map<?, ?> error = structuredMap(failed.structuredContent());
        assertThat(error.get("code")).isEqualTo("INTERNAL_ERROR");
        assertThat(error.get("traceId")).isEqualTo(failureTrace);

        assertAudit(
                client,
                "project.create",
                failureTrace,
                "FAILED",
                false,
                "INTERNAL_ERROR",
                TRANSACTION_FAILURE_IDEMPOTENCY_KEY,
                bearer,
                currentTrace);

        useTrace(currentTrace, tracePrefix, "transaction-project-rollback");
        var projects = client.callTool(new CallToolRequest("project.list", Map.of(
                "page", 1,
                "size", 20,
                "keyword", TRANSACTION_FAILURE_PROJECT_CODE)));
        assertThat(projects.isError()).isFalse();
        Map<?, ?> projectPage = structuredMap(projects.structuredContent());
        assertThat(requiredNumber(projectPage, "total").longValue()).isZero();
        assertThat(requiredList(projectPage, "records")).isEmpty();

        Map<?, ?> operationPage = webAudit.operationAuditPageForTrace(
                failureTrace,
                List.of(TRANSACTION_FAILURE_IDEMPOTENCY_KEY, bearer));
        assertThat(requiredNumber(operationPage, "total").longValue()).isZero();
        assertThat(requiredList(operationPage, "records")).isEmpty();
    }

    private static void proveConcurrentCreate(
            McpSyncClient auditClient,
            WebAuditClient webAudit,
            AtomicReference<String> currentTrace,
            AtomicInteger requestNumber,
            String baseUrl,
            String bearer,
            String ownerId,
            String tracePrefix) throws Exception {
        String code = randomCode("MCP_RACE");
        String key = "crud-create-race-" + UUID.randomUUID();
        Map<String, Object> arguments = Map.of(
                "name", "MCP Concurrent Create Acceptance",
                "code", code,
                "ownerId", ownerId,
                "status", "PLANNING",
                "description", "Concurrent official SDK acceptance",
                "idempotencyKey", key);
        String traceA = trace(tracePrefix, "create-concurrent-a");
        String traceB = trace(tracePrefix, "create-concurrent-b");
        Map<?, ?> created = assertStableConcurrentSuccess(callConcurrently(
                baseUrl, bearer, requestNumber, "project.create", arguments, traceA, traceB));
        String projectId = requiredString(created, "id");
        assertThat(requiredNumber(created, "version").intValue()).isZero();
        ConcurrentAudit concurrentAudit = assertConcurrentAuditPair(
                auditClient, currentTrace, "project.create", traceA, traceB, key, bearer);

        String retryTrace = useTrace(currentTrace, tracePrefix, "create-concurrent-retry");
        assertSuccessfulReplay(
                auditClient.callTool(new CallToolRequest("project.create", arguments)), created);
        String conflictTrace = useTrace(currentTrace, tracePrefix, "create-concurrent-conflict");
        assertIdempotencyConflict(auditClient.callTool(new CallToolRequest("project.create", Map.of(
                "name", "Different concurrent create arguments",
                "code", code,
                "ownerId", ownerId,
                "status", "PLANNING",
                "idempotencyKey", key))));
        assertAudit(auditClient, "project.create", retryTrace, "SUCCESS", true, null,
                key, bearer, currentTrace);
        assertAudit(auditClient, "project.create", conflictTrace, "FAILED", false,
                "IDEMPOTENCY_CONFLICT", key, bearer, currentTrace);
        assertBusinessAuditBoundary(
                webAudit, projectId, "CREATE", concurrentAudit.committedTrace(),
                List.of(concurrentAudit.replayedTrace(), retryTrace, conflictTrace), List.of(key));
        assertSingleVisibleProject(auditClient, currentTrace, tracePrefix, code, projectId, 0);

        // Remove the independent concurrency fixture so acceptance leaves no
        // active sample project behind. The main project still proves REMOVE.
        useTrace(currentTrace, tracePrefix, "create-concurrent-cleanup");
        var cleanup = auditClient.callTool(new CallToolRequest("project.remove", Map.of(
                "id", projectId,
                "version", 0,
                "idempotencyKey", "crud-cleanup-" + UUID.randomUUID())));
        assertThat(cleanup.isError()).isFalse();
    }

    private static McpSyncClient mutableTraceClient(
            String baseUrl,
            String bearer,
            AtomicReference<String> currentTrace,
            AtomicInteger requestNumber,
            String clientName) {
        var transport = HttpClientStreamableHttpTransport.builder(baseUrl)
                .endpoint("/mcp")
                .connectTimeout(Duration.ofSeconds(10))
                .httpRequestCustomizer((request, method, uri, body, context) -> {
                    String traceId = currentTrace.get();
                    if (traceId == null || traceId.isBlank()) {
                        throw new IllegalStateException("A logical MCP call trace was not assigned");
                    }
                    requestNumber.incrementAndGet();
                    request.header("Authorization", "Bearer " + bearer);
                    request.header("X-Trace-Id", traceId);
                })
                .build();
        return McpClient.sync(transport)
                .clientInfo(new Implementation(clientName, "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(30))
                .build();
    }

    private static McpSyncClient fixedTraceClient(
            String baseUrl,
            String bearer,
            String traceId,
            AtomicInteger requestNumber,
            String clientName) {
        var transport = HttpClientStreamableHttpTransport.builder(baseUrl)
                .endpoint("/mcp")
                .connectTimeout(Duration.ofSeconds(10))
                .httpRequestCustomizer((request, method, uri, body, context) -> {
                    requestNumber.incrementAndGet();
                    request.header("Authorization", "Bearer " + bearer);
                    request.header("X-Trace-Id", traceId);
                })
                .build();
        McpSyncClient client = McpClient.sync(transport)
                .clientInfo(new Implementation(clientName, "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(30))
                .build();
        assertThat(client.initialize().protocolVersion()).isEqualTo("2025-11-25");
        return client;
    }

    private static List<CallToolResult> callConcurrently(
            String baseUrl,
            String bearer,
            AtomicInteger requestNumber,
            String toolName,
            Map<String, Object> arguments,
            String traceA,
            String traceB) throws Exception {
        try (McpSyncClient clientA = fixedTraceClient(
                    baseUrl, bearer, traceA, requestNumber, "crud-race-a");
                McpSyncClient clientB = fixedTraceClient(
                    baseUrl, bearer, traceB, requestNumber, "crud-race-b");
                var executor = Executors.newFixedThreadPool(2)) {
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<CallToolResult>> futures = new ArrayList<>();
            for (McpSyncClient client : List.of(clientA, clientB)) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    if (!start.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Concurrent MCP start barrier timed out");
                    }
                    return client.callTool(new CallToolRequest(toolName, arguments));
                }));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            List<CallToolResult> results = new ArrayList<>();
            for (Future<CallToolResult> future : futures) {
                results.add(future.get(45, TimeUnit.SECONDS));
            }
            return List.copyOf(results);
        }
    }

    private static Map<?, ?> assertStableConcurrentSuccess(List<CallToolResult> results) {
        assertThat(results).hasSize(2).allSatisfy(result -> assertThat(result.isError()).isFalse());
        Map<?, ?> first = structuredMap(results.get(0).structuredContent());
        assertThat(structuredMap(results.get(1).structuredContent())).isEqualTo(first);
        return first;
    }

    private static void assertSuccessfulReplay(CallToolResult result, Map<?, ?> expected) {
        assertThat(result.isError()).isFalse();
        assertThat(structuredMap(result.structuredContent())).isEqualTo(expected);
    }

    private static void assertIdempotencyConflict(CallToolResult result) {
        assertThat(result.isError()).isTrue();
        Map<?, ?> error = structuredMap(result.structuredContent());
        assertThat(error.get("code")).isEqualTo("IDEMPOTENCY_CONFLICT");
        assertThat(error.get("traceId")).isInstanceOf(String.class);
    }

    private static ConcurrentAudit assertConcurrentAuditPair(
            McpSyncClient client,
            AtomicReference<String> currentTrace,
            String toolName,
            String traceA,
            String traceB,
            String rawIdempotencyKey,
            String bearer) {
        AuditRecord auditA = assertAudit(client, toolName, traceA, "SUCCESS", null, null,
                rawIdempotencyKey, bearer, currentTrace);
        AuditRecord auditB = assertAudit(client, toolName, traceB, "SUCCESS", null, null,
                rawIdempotencyKey, bearer, currentTrace);
        assertThat(List.of(auditA.replayed(), auditB.replayed()))
                .containsExactlyInAnyOrder(false, true);
        return auditA.replayed()
                ? new ConcurrentAudit(traceB, traceA)
                : new ConcurrentAudit(traceA, traceB);
    }

    private static AuditRecord assertAudit(
            McpSyncClient client,
            String toolName,
            String traceId,
            String result,
            Boolean replayed,
            String errorCode,
            String rawIdempotencyKey,
            String bearer,
            AtomicReference<String> currentTrace) {
        // Audit queries need their own bounded trace. Some formal upgrade
        // prefixes already leave too little room to append another readable
        // suffix to the original 64-character tool trace.
        currentTrace.set("audit-" + sha256(traceId).substring(0, 24));
        var audit = client.callTool(new CallToolRequest("audit.list", Map.of(
                "page", 1,
                "size", 20,
                "toolName", toolName,
                "traceId", traceId,
                "result", result)));
        assertThat(audit.isError()).isFalse();
        assertRedacted(audit.structuredContent().toString(), List.of(rawIdempotencyKey, bearer));
        Map<?, ?> page = structuredMap(audit.structuredContent());
        assertThat(requiredNumber(page, "total").longValue()).isEqualTo(1L);
        List<?> records = requiredList(page, "records");
        assertThat(records).hasSize(1);
        Map<?, ?> record = structuredMap(records.getFirst());
        assertThat(record.get("toolName")).isEqualTo(toolName);
        assertThat(record.get("permissionCode")).isEqualTo(toolName.replace('.', ':'));
        assertThat(record.get("traceId")).isEqualTo(traceId);
        assertThat(record.get("result")).isEqualTo(result);
        assertThat(record.get("replayed")).isInstanceOf(Boolean.class);
        boolean observedReplay = (Boolean) record.get("replayed");
        if (replayed != null) {
            assertThat(observedReplay).isEqualTo(replayed);
        }
        if (errorCode == null) {
            assertThat(record.get("errorCode")).isNull();
        }
        else {
            assertThat(record.get("errorCode")).isEqualTo(errorCode);
        }
        assertThat(record.get("idempotencyKeyHash")).isEqualTo(sha256(rawIdempotencyKey));
        return new AuditRecord(traceId, observedReplay);
    }

    private static void assertBusinessAuditBoundary(
            WebAuditClient webAudit,
            String projectId,
            String expectedAction,
            String committedTrace,
            List<String> noBusinessEffectTraces,
            List<String> sensitiveValues) throws Exception {
        Map<?, ?> committedPage = webAudit.operationAuditPage(
                projectId, committedTrace, sensitiveValues);
        assertThat(requiredNumber(committedPage, "total").longValue()).isEqualTo(1L);
        List<?> committedRecords = requiredList(committedPage, "records");
        assertThat(committedRecords).hasSize(1);
        Map<?, ?> committed = structuredMap(committedRecords.getFirst());
        assertThat(committed.get("module")).isEqualTo("project");
        assertThat(committed.get("action")).isEqualTo(expectedAction);
        assertThat(committed.get("resourceType")).isEqualTo("project");
        assertThat(committed.get("resourceId")).isEqualTo(projectId);
        assertThat(committed.get("result")).isEqualTo("SUCCESS");
        assertThat(committed.get("traceId")).isEqualTo(committedTrace);
        assertThat(committed.get("detailJson")).isNull();

        for (String traceId : noBusinessEffectTraces) {
            Map<?, ?> page = webAudit.operationAuditPage(
                    projectId, traceId, sensitiveValues);
            assertThat(requiredNumber(page, "total").longValue()).isZero();
            assertThat(requiredList(page, "records")).isEmpty();
        }
    }

    private static void assertSingleVisibleProject(
            McpSyncClient client,
            AtomicReference<String> currentTrace,
            String tracePrefix,
            String code,
            String projectId,
            int version) {
        useTrace(currentTrace, tracePrefix, "list-" + code.substring(code.length() - 8));
        var listed = client.callTool(new CallToolRequest("project.list", Map.of(
                "page", 1,
                "size", 20,
                "keyword", code)));
        assertThat(listed.isError()).isFalse();
        Map<?, ?> page = structuredMap(listed.structuredContent());
        assertThat(requiredNumber(page, "total").longValue()).isEqualTo(1L);
        List<?> records = requiredList(page, "records");
        assertThat(records).hasSize(1);
        Map<?, ?> project = structuredMap(records.getFirst());
        assertThat(project.get("id")).isEqualTo(projectId);
        assertThat(project.get("code")).isEqualTo(code);
        assertThat(requiredNumber(project, "version").intValue()).isEqualTo(version);
    }

    private static Map<?, ?> structuredMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static List<?> requiredList(Map<?, ?> value, String key) {
        assertThat(value.get(key)).isInstanceOf(List.class);
        return (List<?>) value.get(key);
    }

    private static String useTrace(
            AtomicReference<String> currentTrace, String tracePrefix, String suffix) {
        String traceId = trace(tracePrefix, suffix);
        currentTrace.set(traceId);
        return traceId;
    }

    private static String trace(String tracePrefix, String suffix) {
        String traceId = tracePrefix + "-" + suffix;
        assertThat(traceId).hasSizeBetween(8, 64).matches("[A-Za-z0-9._-]+");
        return traceId;
    }

    private static String randomCode(String prefix) {
        return prefix + "_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16)
                .toUpperCase(java.util.Locale.ROOT);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void assertRedacted(String serialized, List<String> sensitiveValues) {
        if (FORBIDDEN_AUDIT_FIELD.matcher(serialized).find()) {
            throw new AssertionError("Runtime audit evidence exposed a forbidden credential field");
        }
        for (String sensitive : sensitiveValues) {
            if (sensitive != null && !sensitive.isEmpty() && serialized.contains(sensitive)) {
                throw new AssertionError("Runtime audit evidence exposed raw credential material");
            }
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

    private static String requiredString(Map<?, ?> value, String key) {
        assertThat(value.get(key)).isInstanceOf(String.class);
        return (String) value.get(key);
    }

    private static Number requiredNumber(Map<?, ?> value, String key) {
        assertThat(value.get(key)).isInstanceOf(Number.class);
        return (Number) value.get(key);
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    name + " is required for the opt-in runtime acceptance test");
        }
        return value.trim();
    }

    private static String readBearer(Path responseFile) throws Exception {
        var matcher = TOKEN_PATTERN.matcher(Files.readString(responseFile));
        if (!matcher.find()) {
            throw new IllegalStateException("The response file does not contain a bearer token");
        }
        return matcher.group(1);
    }

    /**
     * PAT authentication is deliberately scoped to the /mcp security chain.
     * Business operation audits therefore have to be read through a genuine
     * short-lived Web session instead of accidentally treating a PAT as a Web
     * API credential. The session is logged out even when the assertions fail.
     */
    private static final class WebAuditClient implements AutoCloseable {

        private final String baseUrl;
        private final HttpClient client;
        private final String csrfHeader;
        private final String csrfToken;
        private final String cookieHeader;
        private final List<String> forbiddenValues;

        private WebAuditClient(
                String baseUrl,
                HttpClient client,
                String csrfHeader,
                String csrfToken,
                String cookieHeader,
                List<String> forbiddenValues) {
            this.baseUrl = baseUrl;
            this.client = client;
            this.csrfHeader = csrfHeader;
            this.csrfToken = csrfToken;
            this.cookieHeader = cookieHeader;
            this.forbiddenValues = List.copyOf(forbiddenValues);
        }

        static WebAuditClient login(
                String baseUrl,
                String username,
                String password,
                List<String> additionalForbiddenValues) throws Exception {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            List<String> forbidden = new ArrayList<>(additionalForbiddenValues);
            forbidden.add(password);

            HttpResponse<byte[]> csrfResponse = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/csrf"))
                            .timeout(Duration.ofSeconds(15))
                            .header("Accept", "application/json")
                            .header("X-Trace-Id", "crud-web-csrf-" + shortUuid())
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            Map<?, ?> csrfEnvelope = apiEnvelope(csrfResponse, 200, forbidden);
            Map<?, ?> csrf = structuredMap(csrfEnvelope.get("data"));
            String headerName = requiredString(csrf, "headerName");
            String token = requiredString(csrf, "token");
            String csrfCookie = responseCookie(csrfResponse, "XSRF-TOKEN");
            assertThat(headerName).matches("[A-Za-z0-9-]{1,64}");
            assertThat(token).isNotBlank();

            String body = McpJsonDefaults.getMapper().writeValueAsString(Map.of(
                    "username", username,
                    "password", password));
            HttpResponse<byte[]> loginResponse = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/login"))
                            .timeout(Duration.ofSeconds(15))
                            .header("Accept", "application/json")
                            .header("Content-Type", "application/json")
                            .header("User-Agent", "web-starter-mcp-crud-acceptance/1.0")
                            .header("X-Trace-Id", "crud-web-login-" + shortUuid())
                            .header(headerName, token)
                            .header("Cookie", "XSRF-TOKEN=" + csrfCookie)
                            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            apiEnvelope(loginResponse, 200, forbidden);
            String sessionCookie = responseCookie(loginResponse, "WEB_STARTER_SESSION");
            String cookieHeader = "XSRF-TOKEN=" + csrfCookie
                    + "; WEB_STARTER_SESSION=" + sessionCookie;
            forbidden.add(token);
            forbidden.add(csrfCookie);
            forbidden.add(sessionCookie);
            return new WebAuditClient(
                    baseUrl, client, headerName, token, cookieHeader, forbidden);
        }

        @SuppressWarnings("unchecked")
        Map<?, ?> operationAuditPage(
                String projectId,
                String traceId,
                List<String> additionalForbiddenValues) throws Exception {
            String query = "page=1&size=20&module=project&resourceType=project&resourceId="
                    + encode(projectId) + "&traceId=" + encode(traceId);
            HttpResponse<byte[]> response = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/api/logs/operation?" + query))
                            .timeout(Duration.ofSeconds(15))
                            .header("Accept", "application/json")
                            .header("X-Trace-Id", "crud-web-audit-" + shortUuid())
                            .header("Cookie", cookieHeader)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            List<String> forbidden = new ArrayList<>(forbiddenValues);
            forbidden.addAll(additionalForbiddenValues);
            Map<?, ?> envelope = apiEnvelope(response, 200, forbidden);
            assertThat(envelope.get("data")).isInstanceOf(Map.class);
            return (Map<?, ?>) envelope.get("data");
        }

        @SuppressWarnings("unchecked")
        Map<?, ?> operationAuditPageForTrace(
                String traceId,
                List<String> additionalForbiddenValues) throws Exception {
            String query = "page=1&size=20&module=project&resourceType=project&traceId="
                    + encode(traceId);
            HttpResponse<byte[]> response = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/api/logs/operation?" + query))
                            .timeout(Duration.ofSeconds(15))
                            .header("Accept", "application/json")
                            .header("X-Trace-Id", "crud-web-transaction-audit-" + shortUuid())
                            .header("Cookie", cookieHeader)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            List<String> forbidden = new ArrayList<>(forbiddenValues);
            forbidden.addAll(additionalForbiddenValues);
            Map<?, ?> envelope = apiEnvelope(response, 200, forbidden);
            assertThat(envelope.get("data")).isInstanceOf(Map.class);
            return (Map<?, ?>) envelope.get("data");
        }

        @Override
        public void close() throws Exception {
            HttpResponse<byte[]> response = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/logout"))
                            .timeout(Duration.ofSeconds(15))
                            .header("Accept", "application/json")
                            .header("X-Trace-Id", "crud-web-logout-" + shortUuid())
                            .header(csrfHeader, csrfToken)
                            .header("Cookie", cookieHeader)
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertThat(response.statusCode()).isEqualTo(204);
            assertRedacted(new String(response.body(), StandardCharsets.UTF_8), forbiddenValues);
        }

        @SuppressWarnings("unchecked")
        private static Map<?, ?> apiEnvelope(
                HttpResponse<byte[]> response,
                int expectedStatus,
                List<String> forbiddenValues) throws Exception {
            assertThat(response.statusCode()).isEqualTo(expectedStatus);
            assertRedacted(
                    new String(response.body(), StandardCharsets.UTF_8), forbiddenValues);
            Map<String, Object> envelope = McpJsonDefaults.getMapper()
                    .readValue(response.body(), Map.class);
            assertThat(envelope.get("code")).isEqualTo(0);
            return envelope;
        }

        private static String responseCookie(
                HttpResponse<?> response, String expectedName) {
            for (String header : response.headers().allValues("Set-Cookie")) {
                String first = header.split(";", 2)[0].trim();
                String prefix = expectedName + "=";
                if (first.startsWith(prefix)) {
                    String value = first.substring(prefix.length());
                    if (value.isBlank() || value.length() > 4096
                            || value.chars().anyMatch(character -> character < 0x21 || character > 0x7e)) {
                        throw new AssertionError("Web acceptance cookie is invalid");
                    }
                    return value;
                }
            }
            throw new AssertionError("Web acceptance response omitted " + expectedName);
        }

        private static String shortUuid() {
            return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        }
    }

    private record AuditRecord(String traceId, boolean replayed) { }

    private record ConcurrentAudit(String committedTrace, String replayedTrace) { }
}
