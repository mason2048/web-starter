package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import io.modelcontextprotocol.spec.McpSchema.ReadResourceRequest;
import org.junit.jupiter.api.Test;

/** Opt-in SDK acceptance for a read-only principal with no project write permission. */
class McpSdkProjectListRuntimeIT {

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
            assertThat(toolNames).containsExactlyInAnyOrderElementsOf(
                    McpRuntimeToolExpectations.fromEnvironment());

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

            assertThat(client.listResources().resources())
                    .extracting(resource -> resource.uri())
                    .containsExactly("web-starter://system/info");
            var systemResource = client.readResource(
                    new ReadResourceRequest("web-starter://system/info"));
            assertThat(systemResource.contents()).hasSize(1);
            assertThat(systemResource.toString()).contains("web-starter-mcp");

            URI privateOrigin = URI.create(baseUrl);
            assertThat(privateOrigin.getScheme()).isEqualTo("http");
            int privatePort = privateOrigin.getPort() < 0 ? 80 : privateOrigin.getPort();
            assertTransportRejected(
                    privateOrigin,
                    bearer,
                    "untrusted.webstarter.invalid:" + privatePort,
                    null,
                    tracePrefix + "-invalid-host");
            assertTransportRejected(
                    privateOrigin,
                    bearer,
                    privateOrigin.getHost() + ":" + privatePort,
                    "https://untrusted.webstarter.invalid",
                    tracePrefix + "-invalid-origin");

            System.out.printf(
                    "MCP project-list SDK acceptance passed: tools=%d requests=%d "
                            + "readOnlyResource=true transportRejected=true tracePrefix=%s%n",
                    toolNames.size(), requestNumber.get(), tracePrefix);
        }
    }

    private static void assertTransportRejected(
            URI origin,
            String bearer,
            String hostHeader,
            String originHeader,
            String traceId) throws Exception {
        byte[] body = ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                + "\"params\":{\"protocolVersion\":\"2025-11-25\","
                + "\"capabilities\":{},\"clientInfo\":{\"name\":\"transport-negative\","
                + "\"version\":\"1.0.0\"}}}").getBytes(StandardCharsets.UTF_8);
        int port = origin.getPort() < 0 ? 80 : origin.getPort();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(origin.getHost(), port), 5_000);
            socket.setSoTimeout(5_000);
            String headers = "POST /mcp HTTP/1.1\r\n"
                    + "Host: " + hostHeader + "\r\n"
                    + (originHeader == null ? "" : "Origin: " + originHeader + "\r\n")
                    + "Authorization: Bearer " + bearer + "\r\n"
                    + "X-Trace-Id: " + traceId + "\r\n"
                    + "Accept: application/json, text/event-stream\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + body.length + "\r\n"
                    + "Connection: close\r\n\r\n";
            socket.getOutputStream().write(headers.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(body);
            socket.getOutputStream().flush();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII))) {
                String statusLine = reader.readLine();
                // The SDK maps invalid Host/Origin to 421/403. Depending on the
                // Servlet container and reverse-proxy path, sendError may also
                // be surfaced as an immediate connection close. Both outcomes
                // reject the request before MCP protocol handling; any HTTP
                // response other than the explicit transport 4xx remains a
                // failure, and a stalled connection still fails by timeout.
                if (statusLine != null) {
                    assertThat(statusLine)
                            .as("invalid MCP Host/Origin must be rejected before protocol handling")
                            .matches("HTTP/1\\.[01] (?:400|403|421)(?: .*)?");
                }
            }
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
