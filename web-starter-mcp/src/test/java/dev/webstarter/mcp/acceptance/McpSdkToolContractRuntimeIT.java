package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import org.junit.jupiter.api.Test;

/**
 * Opt-in V2 Tool-contract acceptance through the official MCP Java SDK.
 *
 * <p>This test deliberately identifies as the frozen V1 client and omits the V2
 * {@code idempotencyKey} on all three write calls. A clean Surefire result therefore proves the
 * compatibility path against a disposable real deployment; schema and annotation assertions are
 * made against the server response received through the SDK, not against an in-process catalog.
 */
class McpSdkToolContractRuntimeIT {

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\\"(?:token|access_token)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern STABLE_ERROR_CODE = Pattern.compile(
            "^(?:FORBIDDEN|INVALID_ARGUMENT|IDEMPOTENCY_CONFLICT|"
                    + "IDEMPOTENCY_IN_PROGRESS|INTERNAL_ERROR|BUSINESS_[0-9]{4})$");

    @Test
    void provesExactBaselineSchemasAnnotationsErrorsAndV1WriteCompatibility() throws Exception {
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
                .clientInfo(new Implementation("web-starter-v1-contract-client", "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(30))
                .build()) {
            assertThat(client.initialize().protocolVersion()).isEqualTo("2025-11-25");

            List<Tool> tools = client.listTools().tools();
            Set<String> names = tools.stream().map(Tool::name).collect(Collectors.toSet());
            assertThat(names).containsExactlyInAnyOrderElementsOf(
                    McpRuntimeToolExpectations.parse(null));
            assertThat(tools).hasSize(7);

            Tool create = requiredTool(tools, "project.create");
            Tool update = requiredTool(tools, "project.update");
            Tool remove = requiredTool(tools, "project.remove");
            assertWriteContract(create, false, false,
                    Set.of("id", "name", "code", "ownerId", "status", "version"));
            assertWriteContract(update, true, true,
                    Set.of("id", "name", "code", "ownerId", "status", "version"));
            assertWriteContract(remove, true, true, Set.of("id", "removed"));

            for (Tool tool : List.of(create, update, remove)) {
                assertThat(requiredList(tool.inputSchema(), "required"))
                        .as("V1 compatibility: %s does not require idempotencyKey", tool.name())
                        .doesNotContain("idempotencyKey");
            }

            assertToolError(client.callTool(new CallToolRequest("project.create", Map.of())),
                    "INVALID_ARGUMENT");
            assertToolError(client.callTool(new CallToolRequest("project.update", Map.of())),
                    "INVALID_ARGUMENT");
            assertToolError(client.callTool(new CallToolRequest("project.remove", Map.of())),
                    "INVALID_ARGUMENT");

            String code = "MCP_LEGACY_" + UUID.randomUUID().toString()
                    .replace("-", "").substring(0, 20).toUpperCase();
            Map<String, Object> createArguments = Map.of(
                    "name", "MCP V1 Contract Compatibility",
                    "code", code,
                    "ownerId", ownerId,
                    "status", "PLANNING",
                    "description", "Official SDK V1 write compatibility proof");
            CallToolResult created = client.callTool(
                    new CallToolRequest("project.create", createArguments));
            assertThat(created.isError()).isFalse();
            Map<String, Object> createdProject = objectMap(created.structuredContent());
            String projectId = requiredString(createdProject, "id");
            assertThat(requiredNumber(createdProject, "version").intValue()).isZero();

            assertToolError(client.callTool(
                    new CallToolRequest("project.create", createArguments)), "BUSINESS_4090");

            CallToolResult updated = client.callTool(new CallToolRequest("project.update", Map.of(
                    "id", projectId,
                    "name", "MCP V1 Contract Compatibility Updated",
                    "ownerId", ownerId,
                    "status", "IN_PROGRESS",
                    "description", "Legacy request without a retry key",
                    "version", 0)));
            assertThat(updated.isError()).isFalse();
            Map<String, Object> updatedProject = objectMap(updated.structuredContent());
            assertThat(requiredString(updatedProject, "id")).isEqualTo(projectId);
            int updatedVersion = requiredNumber(updatedProject, "version").intValue();
            assertThat(updatedVersion).isEqualTo(1);

            CallToolResult removed = client.callTool(new CallToolRequest("project.remove", Map.of(
                    "id", projectId,
                    "version", updatedVersion)));
            assertThat(removed.isError()).isFalse();
            assertThat(objectMap(removed.structuredContent()))
                    .containsEntry("id", projectId)
                    .containsEntry("removed", true);

            assertToolError(client.callTool(new CallToolRequest(
                    "project.get", Map.of("id", projectId))), "BUSINESS_4004");

            System.out.printf(
                    "MCP SDK Tool contract acceptance passed: tools=%d requests=%d tracePrefix=%s "
                            + "legacyWrites=create,update,remove%n",
                    tools.size(), requestNumber.get(), tracePrefix);
        }
    }

    private static void assertWriteContract(
            Tool tool,
            boolean destructive,
            boolean idempotent,
            Set<String> requiredSuccessProperties) {
        assertThat(tool.inputSchema()).containsEntry("type", "object")
                .containsEntry("additionalProperties", false);
        assertThat(objectMap(tool.inputSchema().get("properties")))
                .containsKey("idempotencyKey");

        Map<String, Object> output = tool.outputSchema();
        assertThat(output).isNotNull().containsEntry("type", "object");
        List<?> alternatives = requiredList(output, "oneOf");
        assertThat(alternatives).hasSize(2);
        Map<String, Object> success = objectMap(alternatives.getFirst());
        Map<String, Object> error = objectMap(alternatives.get(1));
        assertThat(requiredList(success, "required"))
                .containsExactlyInAnyOrderElementsOf(requiredSuccessProperties);
        Map<String, Object> errorProperties = objectMap(error.get("properties"));
        assertThat(requiredList(error, "required"))
                .containsExactlyInAnyOrder("code", "message", "traceId");
        assertThat(objectMap(errorProperties.get("code")))
                .containsEntry("pattern", STABLE_ERROR_CODE.pattern());
        assertThat(objectMap(errorProperties.get("traceId")))
                .containsEntry("pattern", "^[A-Za-z0-9._-]{8,64}$");

        ToolAnnotations annotations = tool.annotations();
        assertThat(annotations).isNotNull();
        assertThat(annotations.readOnlyHint()).isFalse();
        assertThat(annotations.destructiveHint()).isEqualTo(destructive);
        assertThat(annotations.idempotentHint()).isEqualTo(idempotent);
        assertThat(annotations.openWorldHint()).isFalse();
    }

    private static Tool requiredTool(List<Tool> tools, String name) {
        return tools.stream().filter(tool -> name.equals(tool.name())).findFirst().orElseThrow();
    }

    private static void assertToolError(CallToolResult result, String expectedCode) {
        assertThat(result.isError()).isTrue();
        Map<String, Object> error = objectMap(result.structuredContent());
        assertThat(requiredString(error, "code"))
                .matches(STABLE_ERROR_CODE)
                .isEqualTo(expectedCode);
        assertThat(requiredString(error, "message")).isNotBlank();
        assertThat(requiredString(error, "traceId")).matches("^[A-Za-z0-9._-]{8,64}$");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> requiredList(Map<String, Object> value, String key) {
        Object raw = value.get(key);
        assertThat(raw).isInstanceOf(List.class);
        return (List<Object>) raw;
    }

    private static String requiredString(Map<String, Object> value, String key) {
        Object raw = value.get(key);
        assertThat(raw).isInstanceOf(String.class);
        return (String) raw;
    }

    private static Number requiredNumber(Map<String, Object> value, String key) {
        Object raw = value.get(key);
        assertThat(raw).isInstanceOf(Number.class);
        return (Number) raw;
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for Tool contract acceptance");
        }
        return value.trim();
    }

    private static String readBearer(Path responseFile) throws Exception {
        String response = Files.readString(responseFile);
        var matcher = TOKEN_PATTERN.matcher(response);
        if (!matcher.find()) {
            throw new IllegalStateException("The response file does not contain a bearer token");
        }
        return matcher.group(1);
    }
}
