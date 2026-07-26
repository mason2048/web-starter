package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import org.junit.jupiter.api.Test;

/** Opt-in, external-stack acceptance for V2-AC-34 and the live half of V2-AC-35. */
class McpSdkGovernanceRuntimeIT {

    @Test
    void provesOfficialHttpSessionLifecycleIndependentRateLimitsAndAudit() throws Exception {
        McpGovernanceRuntimeSupport runtime = new McpGovernanceRuntimeSupport();
        Path credentials = McpGovernanceRuntimeSupport.credentialDirectory();
        String prefix = McpGovernanceRuntimeSupport.tracePrefix();

        String sdkBearer = McpGovernanceRuntimeSupport.bearer(credentials, "sdk.json");
        var officialSdkSession = runtime.initializeOfficialSdk(
                sdkBearer,
                trace(prefix, "official-sdk"),
                "web-starter-governance-acceptance");
        assertThat(officialSdkSession.client().closeGracefully()).isTrue();

        String sessionBearer = McpGovernanceRuntimeSupport.bearer(credentials, "session.json");
        var cappedA = runtime.initialize(sessionBearer, trace(prefix, "cap-init-a"));
        var cappedB = runtime.initialize(sessionBearer, trace(prefix, "cap-init-b"));
        var capRejected = runtime.request(
                "POST", sessionBearer, null, trace(prefix, "cap-rejected"), initializeBody("cap-c"));
        assertThat(capRejected.status()).isEqualTo(429);
        assertThat(McpGovernanceRuntimeSupport.errorCode(capRejected)).isEqualTo("SESSION_LIMIT");
        assertThat(capRejected.retryAfter()).isNotNull().matches("[1-9][0-9]*");
        assertThat(Long.parseLong(capRejected.retryAfter()))
                .isBetween(1L, (long) McpGovernanceRuntimeSupport.ABSOLUTE_TTL_SECONDS);

        String deleteBearer = McpGovernanceRuntimeSupport.bearer(credentials, "delete.json");
        var deleted = runtime.initialize(deleteBearer, trace(prefix, "delete-init"));
        assertThat(runtime.delete(deleted, trace(prefix, "delete-explicit")).status())
                .isBetween(200, 299);
        var deleteReplay = runtime.ping(deleted, trace(prefix, "delete-replay"));
        assertThat(deleteReplay.status()).isEqualTo(404);
        assertThat(McpGovernanceRuntimeSupport.errorCode(deleteReplay))
                .isEqualTo("SESSION_NOT_FOUND");

        String ttlBearer = McpGovernanceRuntimeSupport.bearer(credentials, "ttl.json");
        var idleBoundary = runtime.initialize(ttlBearer, trace(prefix, "idle-boundary-init"));
        var idleExpiry = runtime.initialize(ttlBearer, trace(prefix, "idle-expiry-init"));
        Thread.sleep(Duration.ofSeconds(McpGovernanceRuntimeSupport.IDLE_TTL_SECONDS - 2L));
        assertThat(runtime.ping(idleBoundary, trace(prefix, "idle-before-boundary")).status())
                .isBetween(200, 299);
        Thread.sleep(Duration.ofSeconds(3));
        var idleExpired = runtime.callTool(
                idleExpiry, trace(prefix, "idle-expired"), "system.info", Map.of());
        assertThat(idleExpired.status()).isEqualTo(404);
        assertThat(McpGovernanceRuntimeSupport.errorCode(idleExpired))
                .isEqualTo("SESSION_EXPIRED");

        var absolute = runtime.initialize(ttlBearer, trace(prefix, "absolute-init"));
        Thread.sleep(Duration.ofSeconds(20));
        assertThat(runtime.ping(absolute, trace(prefix, "absolute-touch-20")).status())
                .isBetween(200, 299);
        Thread.sleep(Duration.ofSeconds(20));
        assertThat(runtime.ping(absolute, trace(prefix, "absolute-touch-40")).status())
                .isBetween(200, 299);
        Thread.sleep(Duration.ofSeconds(19));
        assertThat(runtime.ping(absolute, trace(prefix, "absolute-before-boundary")).status())
                .isBetween(200, 299);
        Thread.sleep(Duration.ofSeconds(2));
        var absoluteExpired = runtime.callTool(
                absolute, trace(prefix, "absolute-expired"), "system.info", Map.of());
        assertThat(absoluteExpired.status()).isEqualTo(404);
        assertThat(McpGovernanceRuntimeSupport.errorCode(absoluteExpired))
                .isEqualTo("SESSION_EXPIRED");

        Map<String, String> evidenceTraces = new HashMap<>();
        proveSubjectLimit(runtime, credentials, prefix, evidenceTraces);
        proveClientLimit(runtime, credentials, prefix, evidenceTraces);
        proveRiskLimit(runtime, credentials, prefix, evidenceTraces);
        assertAuditedIdentitiesAndOutcomes(credentials, prefix, evidenceTraces);

        // The lifecycle checks above deliberately take longer than the fixed
        // 60-second absolute TTL. Create the shutdown probe only now so the
        // external SIGTERM/restart observation cannot be mistaken for TTL expiry.
        var shutdownProbeSession = runtime.initializeOfficialSdk(
                sdkBearer,
                trace(prefix, "shutdown-probe"),
                "web-starter-governance-shutdown-probe");
        McpGovernanceRuntimeSupport.writeShutdownState(
                McpGovernanceRuntimeSupport.stateFile(), shutdownProbeSession.rawSession(), prefix);

        // The official SDK client is deliberately not closed: its captured Session
        // is the exact shutdown probe that the post-restart test must reject.
        assertThat(shutdownProbeSession.client().isInitialized()).isTrue();
        assertThat(cappedA.id()).isNotEqualTo(cappedB.id());
    }

    private static void proveSubjectLimit(
            McpGovernanceRuntimeSupport runtime,
            Path credentials,
            String prefix,
            Map<String, String> traces) throws Exception {
        var first = runtime.initialize(
                McpGovernanceRuntimeSupport.bearer(credentials, "rate-subject-a.json"),
                trace(prefix, "subject-init-a"));
        var second = runtime.initialize(
                McpGovernanceRuntimeSupport.bearer(credentials, "rate-subject-b.json"),
                trace(prefix, "subject-init-b"));
        String successA = trace(prefix, "subject-success-a");
        String successB = trace(prefix, "subject-success-b");
        String blocked = trace(prefix, "subject-blocked");
        assertThat(runtime.callTool(first, successA, "system.info", Map.of()).status())
                .isBetween(200, 299);
        assertThat(runtime.callTool(second, successB, "system.info", Map.of()).status())
                .isBetween(200, 299);
        assertThat(runtime.callTool(first, trace(prefix, "subject-success-c"),
                "system.info", Map.of()).status()).isBetween(200, 299);
        McpGovernanceRuntimeSupport.assertRateLimited(
                runtime.callTool(first, blocked, "system.info", Map.of()));
        traces.put("subjectSuccessA", successA);
        traces.put("subjectSuccessB", successB);
        traces.put("subjectBlocked", blocked);
    }

    private static void proveClientLimit(
            McpGovernanceRuntimeSupport runtime,
            Path credentials,
            String prefix,
            Map<String, String> traces) throws Exception {
        var first = runtime.initialize(
                McpGovernanceRuntimeSupport.bearer(credentials, "rate-client-a.json"),
                trace(prefix, "client-init-a"));
        var second = runtime.initialize(
                McpGovernanceRuntimeSupport.bearer(credentials, "rate-client-b.json"),
                trace(prefix, "client-init-b"));
        String success = trace(prefix, "client-success");
        String blocked = trace(prefix, "client-blocked");
        assertThat(runtime.callTool(first, success, "system.info", Map.of()).status())
                .isBetween(200, 299);
        assertThat(runtime.callTool(second, trace(prefix, "client-success-b"),
                "system.info", Map.of()).status()).isBetween(200, 299);
        assertThat(runtime.callTool(first, trace(prefix, "client-success-c"),
                "system.info", Map.of()).status()).isBetween(200, 299);
        McpGovernanceRuntimeSupport.assertRateLimited(runtime.callTool(
                second, blocked, "project.create", Map.of()));
        traces.put("clientSuccess", success);
        traces.put("clientBlocked", blocked);
    }

    private static void proveRiskLimit(
            McpGovernanceRuntimeSupport runtime,
            Path credentials,
            String prefix,
            Map<String, String> traces) throws Exception {
        var session = runtime.initialize(
                McpGovernanceRuntimeSupport.bearer(credentials, "rate-risk.json"),
                trace(prefix, "risk-init"));
        Map<String, Object> arguments = Map.of(
                "id", Long.toString(Long.MAX_VALUE),
                "version", 0,
                "idempotencyKey", "governance-risk-observation-0001");
        String first = trace(prefix, "risk-first");
        String blocked = trace(prefix, "risk-blocked");
        assertThat(runtime.callTool(session, first, "project.remove", arguments).status())
                .isBetween(200, 299);
        McpGovernanceRuntimeSupport.assertRateLimited(
                runtime.callTool(session, blocked, "project.remove", arguments));
        traces.put("riskFirst", first);
        traces.put("riskBlocked", blocked);
    }

    private static void assertAuditedIdentitiesAndOutcomes(
            Path credentials,
            String prefix,
            Map<String, String> traces) throws Exception {
        String baseUrl = requiredEnvironment("WEB_STARTER_MCP_BASE_URL");
        String bearer = McpGovernanceRuntimeSupport.bearer(credentials, "audit.json");
        var transport = HttpClientStreamableHttpTransport.builder(baseUrl)
                .endpoint("/mcp")
                .connectTimeout(Duration.ofSeconds(10))
                .httpRequestCustomizer((request, method, uri, body, context) -> {
                    request.header("Authorization", "Bearer " + bearer);
                    request.header("X-Trace-Id", trace(prefix, "audit-readback"));
                })
                .build();
        var client = McpClient.sync(transport)
                .clientInfo(new Implementation("web-starter-governance-auditor", "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(20))
                .build();
        assertThat(client.initialize().protocolVersion()).isEqualTo("2025-11-25");
        var result = client.callTool(new CallToolRequest(
                "audit.list", Map.of("page", 1, "size", 200)));
        assertThat(result.isError()).isFalse();
        Map<?, ?> page = map(result.structuredContent());
        List<?> records = list(page.get("records"));
        Map<String, Map<?, ?>> byTrace = records.stream()
                .map(McpSdkGovernanceRuntimeIT::map)
                .filter(record -> record.get("traceId") instanceof String)
                .collect(Collectors.toMap(
                        record -> (String) record.get("traceId"),
                        Function.identity(),
                        (left, right) -> left));
        assertThat(byTrace.keySet()).containsAll(traces.values());

        Map<?, ?> subjectA = byTrace.get(traces.get("subjectSuccessA"));
        Map<?, ?> subjectB = byTrace.get(traces.get("subjectSuccessB"));
        assertThat(subjectA.get("actorId")).isEqualTo(subjectB.get("actorId"));
        assertThat(subjectA.get("tokenId")).isNotEqualTo(subjectB.get("tokenId"));
        assertThat(subjectA.get("clientId")).isNull();
        assertThat(subjectB.get("clientId")).isNull();
        assertRateAudit(byTrace.get(traces.get("subjectBlocked")), "system.info");

        Map<?, ?> clientA = byTrace.get(traces.get("clientSuccess"));
        Map<?, ?> clientB = byTrace.get(traces.get("clientBlocked"));
        assertThat(clientA.get("actorId")).isNotEqualTo(clientB.get("actorId"));
        assertThat(clientA.get("clientId")).isInstanceOf(String.class).isNotEqualTo("");
        assertThat(clientA.get("clientId")).isEqualTo(clientB.get("clientId"));
        assertRateAudit(clientB, "project.create");

        Map<?, ?> riskFirst = byTrace.get(traces.get("riskFirst"));
        assertThat(riskFirst.get("toolName")).isEqualTo("project.remove");
        assertThat(riskFirst.get("result")).isEqualTo("FAILED");
        assertThat(riskFirst.get("errorCode")).isEqualTo("BUSINESS_4004");
        assertRateAudit(byTrace.get(traces.get("riskBlocked")), "project.remove");
    }

    private static void assertRateAudit(Map<?, ?> record, String tool) {
        assertThat(record).isNotNull();
        assertThat(record.get("toolName")).isEqualTo(tool);
        assertThat(record.get("result")).isEqualTo("FAILED");
        assertThat(record.get("errorCode")).isEqualTo("RATE_LIMITED");
        assertThat(record.get("traceId")).isInstanceOf(String.class);
    }

    private static String initializeBody(String id) {
        return """
                {"jsonrpc":"2.0","id":"%s","method":"initialize","params":{
                  "protocolVersion":"2025-11-25","capabilities":{},
                  "clientInfo":{"name":"web-starter-governance-cap","version":"1.0.0"}
                }}
                """.formatted(id);
    }

    private static String trace(String prefix, String suffix) {
        return McpGovernanceRuntimeSupport.trace(prefix, suffix);
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for MCP governance runtime acceptance");
        }
        return value.trim();
    }

    private static Map<?, ?> map(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static List<?> list(Object value) {
        assertThat(value).isInstanceOf(List.class);
        return (List<?>) value;
    }
}
