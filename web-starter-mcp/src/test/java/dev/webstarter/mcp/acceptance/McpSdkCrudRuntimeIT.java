package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import org.junit.jupiter.api.Test;

/** Opt-in runtime acceptance for the mutating project tools and audit.list. */
class McpSdkCrudRuntimeIT {

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\\"(?:token|access_token)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    @Test
    void createsReadsUpdatesAuditsAndRemovesThroughTheOfficialSdk() throws Exception {
        String baseUrl = requiredEnvironment("WEB_STARTER_MCP_BASE_URL");
        String bearer = readBearer(Path.of(requiredEnvironment(
                "WEB_STARTER_MCP_TOKEN_RESPONSE_FILE")));
        String ownerId = requiredEnvironment("WEB_STARTER_MCP_OWNER_ID");
        String tracePrefix = requiredEnvironment("WEB_STARTER_MCP_TRACE_PREFIX");
        AtomicInteger requestNumber = new AtomicInteger();

        var transport = HttpClientStreamableHttpTransport.builder(baseUrl)
                .endpoint("/mcp")
                .connectTimeout(Duration.ofSeconds(10))
                .httpRequestCustomizer((request, method, uri, body, context) -> {
                    request.header("Authorization", "Bearer " + bearer);
                    request.header("X-Trace-Id", tracePrefix + "-" + requestNumber.incrementAndGet());
                })
                .build();

        try (var client = McpClient.sync(transport)
                .clientInfo(new Implementation("web-starter-crud-acceptance", "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(15))
                .build()) {
            assertThat(client.initialize().protocolVersion()).isEqualTo("2025-11-25");

            String code = "MCP_CRUD_" + System.currentTimeMillis();
            var created = client.callTool(new CallToolRequest("project.create", Map.of(
                    "name", "MCP CRUD Acceptance",
                    "code", code,
                    "ownerId", ownerId,
                    "status", "PLANNING",
                    "description", "Created by the official Java MCP SDK")));
            assertThat(created.isError()).isFalse();
            Map<?, ?> createdProject = structuredMap(created.structuredContent());
            String projectId = requiredString(createdProject, "id");
            assertThat(projectId).matches("[1-9][0-9]*");
            assertThat(requiredNumber(createdProject, "version").intValue()).isZero();

            var fetched = client.callTool(new CallToolRequest(
                    "project.get", Map.of("id", projectId)));
            assertThat(fetched.isError()).isFalse();
            assertThat(requiredString(structuredMap(fetched.structuredContent()), "code"))
                    .isEqualTo(code);

            var updated = client.callTool(new CallToolRequest("project.update", Map.of(
                    "id", projectId,
                    "name", "MCP CRUD Acceptance Updated",
                    "ownerId", ownerId,
                    "status", "IN_PROGRESS",
                    "description", "Updated by the official Java MCP SDK",
                    "version", 0)));
            assertThat(updated.isError()).isFalse();
            Map<?, ?> updatedProject = structuredMap(updated.structuredContent());
            assertThat(requiredString(updatedProject, "id")).isEqualTo(projectId);
            assertThat(requiredString(updatedProject, "status")).isEqualTo("IN_PROGRESS");
            int updatedVersion = requiredNumber(updatedProject, "version").intValue();
            assertThat(updatedVersion).isEqualTo(1);

            var audit = client.callTool(new CallToolRequest("audit.list", Map.of(
                    "page", 1,
                    "size", 20,
                    "toolName", "project.update")));
            assertThat(audit.isError()).isFalse();
            assertThat(audit.structuredContent().toString())
                    .contains("project.update")
                    .contains(tracePrefix);

            var removed = client.callTool(new CallToolRequest("project.remove", Map.of(
                    "id", projectId,
                    "version", updatedVersion)));
            assertThat(removed.isError()).isFalse();
            Map<?, ?> removedResult = structuredMap(removed.structuredContent());
            assertThat(requiredString(removedResult, "id")).isEqualTo(projectId);
            assertThat(removedResult.get("removed")).isEqualTo(true);

            var missing = client.callTool(new CallToolRequest(
                    "project.get", Map.of("id", projectId)));
            assertThat(missing.isError()).isTrue();
            assertThat(structuredMap(missing.structuredContent()).get("code"))
                    .isEqualTo("BUSINESS_4004");

            System.out.printf(
                    "MCP SDK CRUD acceptance passed: project=%s requests=%d tracePrefix=%s%n",
                    projectId, requestNumber.get(), tracePrefix);
        }
    }

    private static Map<?, ?> structuredMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
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
}
