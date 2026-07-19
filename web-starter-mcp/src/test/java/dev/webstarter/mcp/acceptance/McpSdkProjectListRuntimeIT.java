package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import org.junit.jupiter.api.Test;

/** Opt-in SDK acceptance for a principal whose effective permissions contain only project:list. */
class McpSdkProjectListRuntimeIT {

    private static final Set<String> EXPECTED_TOOLS = Set.of(
            "system.info", "project.list", "project.get", "project.create",
            "project.update", "project.remove", "audit.list");
    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\\"(?:token|access_token)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    @Test
    void projectListWorksWhileProjectCreateIsDenied() throws Exception {
        String baseUrl = requiredEnvironment("WEB_STARTER_MCP_BASE_URL");
        String bearer = readBearer(Path.of(requiredEnvironment("WEB_STARTER_MCP_TOKEN_RESPONSE_FILE")));
        String ownerId = requiredEnvironment("WEB_STARTER_MCP_OWNER_ID");
        String tracePrefix = requiredEnvironment("WEB_STARTER_MCP_TRACE_PREFIX");
        boolean expectProjectListDenied = Boolean.parseBoolean(
                System.getenv().getOrDefault("WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED", "false"));
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
                .clientInfo(new Implementation("web-starter-project-list-acceptance", "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(15))
                .build()) {
            var initialized = client.initialize();
            assertThat(initialized.protocolVersion()).isEqualTo("2025-11-25");

            Set<String> toolNames = client.listTools().tools().stream()
                    .map(tool -> tool.name())
                    .collect(Collectors.toSet());
            assertThat(toolNames).containsExactlyInAnyOrderElementsOf(EXPECTED_TOOLS);

            var projectList = client.callTool(new CallToolRequest(
                    "project.list", Map.of("page", 1, "size", 20)));
            if (expectProjectListDenied) {
                assertThat(projectList.isError()).isTrue();
                assertThat(projectList.structuredContent()).isInstanceOf(Map.class);
                assertThat(((Map<?, ?>) projectList.structuredContent()).get("code"))
                        .isEqualTo("FORBIDDEN");
            }
            else {
                assertThat(projectList.isError()).isFalse();
                assertThat(projectList.structuredContent().toString()).contains("MCP Acceptance Project");
            }

            var projectCreate = client.callTool(new CallToolRequest("project.create", Map.of(
                    "name", "Must Not Be Created",
                    "code", "SDK_DENIED_" + System.currentTimeMillis(),
                    "ownerId", ownerId,
                    "status", "PLANNING")));
            assertThat(projectCreate.isError()).isTrue();
            assertThat(projectCreate.structuredContent()).isInstanceOf(Map.class);
            assertThat(((Map<?, ?>) projectCreate.structuredContent()).get("code"))
                    .isEqualTo("FORBIDDEN");

            System.out.printf(
                    "MCP project-list SDK acceptance passed: tools=%d requests=%d tracePrefix=%s%n",
                    toolNames.size(), requestNumber.get(), tracePrefix);
        }
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for the opt-in runtime acceptance test");
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
