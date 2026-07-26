package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.Implementation;

/** Shared, fixed HTTP observations for the opt-in MCP governance acceptance. */
final class McpGovernanceRuntimeSupport {

    static final int IDLE_TTL_SECONDS = 50;
    static final int ABSOLUTE_TTL_SECONDS = 60;
    static final int MAX_SESSIONS_PER_SUBJECT = 2;
    static final int RATE_WINDOW_SECONDS = 15;
    static final int MAX_RATE_PER_SUBJECT = 5;
    static final int MAX_RATE_PER_CLIENT = 5;
    static final int MAX_READ_RATE = 5;
    static final int MAX_WRITE_RATE = 5;
    static final int MAX_DESTRUCTIVE_RATE = 1;
    static final int MAX_PROTOCOL_RATE = 5;
    static final String STATE_FILE = "mcp-governance-shutdown-probe.properties";
    static final String EXPECTED_VERSION_ENV = "WEB_STARTER_MCP_GOVERNANCE_EXPECTED_VERSION";
    static final String EXPECTED_GIT_COMMIT_ENV =
            "WEB_STARTER_MCP_GOVERNANCE_EXPECTED_GIT_COMMIT";
    static final String SERVER_NAME = "web-starter-mcp";
    static final String REVISION_DESCRIPTION_PREFIX = "gitRevision=";

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\\"(?:token|access_token)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern TRACE_PREFIX = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,31}");
    private static final Pattern SESSION_ID = Pattern.compile("[A-Za-z0-9._~-]{8,512}");
    private static final Pattern RELEASE_VERSION = Pattern.compile(
            "[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?");
    private static final Pattern GIT_COMMIT = Pattern.compile("[0-9a-f]{40}(?:[0-9a-f]{24})?");
    private static final Set<PosixFilePermission> PRIVATE_FILE = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE);

    private final URI endpoint;
    private final HttpClient httpClient;
    private final AtomicInteger requestId = new AtomicInteger();

    McpGovernanceRuntimeSupport() {
        String baseUrl = requiredEnvironment("WEB_STARTER_MCP_BASE_URL");
        this.endpoint = URI.create(baseUrl.replaceFirst("/+$", "") + "/mcp");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    RawSession initialize(String bearer, String traceId) throws Exception {
        String id = "init-" + requestId.incrementAndGet();
        String body = """
                {"jsonrpc":"2.0","id":"%s","method":"initialize","params":{
                  "protocolVersion":"2025-11-25","capabilities":{},
                  "clientInfo":{"name":"web-starter-governance-acceptance","version":"1.0.0"}
                }}
                """.formatted(id);
        HttpObservation response = request("POST", bearer, null, traceId, body);
        assertThat(response.status()).as("initialize HTTP status").isBetween(200, 299);
        String sessionId = response.sessionId();
        assertThat(sessionId).as("Mcp-Session-Id").isNotNull().matches(SESSION_ID);
        return new RawSession(sessionId, bearer);
    }

    OfficialSdkSession initializeOfficialSdk(
            String bearer,
            String traceId,
            String clientName) throws Exception {
        ExpectedRuntimeIdentity expected = expectedRuntimeIdentity();
        SessionCapturingHttpClientBuilder clientBuilder =
                new SessionCapturingHttpClientBuilder(HttpClient.newBuilder());
        var transport = HttpClientStreamableHttpTransport.builder(requiredEnvironment(
                        "WEB_STARTER_MCP_BASE_URL"))
                .endpoint("/mcp")
                .clientBuilder(clientBuilder)
                .connectTimeout(Duration.ofSeconds(10))
                .httpRequestCustomizer((request, method, uri, body, context) -> {
                    request.header("Authorization", "Bearer " + bearer);
                    request.header("X-Trace-Id", traceId);
                })
                .build();
        McpSyncClient client = McpClient.sync(transport)
                .clientInfo(new Implementation(clientName, "1.0.0"))
                .initializationTimeout(Duration.ofSeconds(15))
                .requestTimeout(Duration.ofSeconds(20))
                .build();
        try {
            var initialized = client.initialize();
            assertThat(initialized.protocolVersion()).isEqualTo("2025-11-25");
            assertThat(initialized.serverInfo().name()).isEqualTo(SERVER_NAME);
            assertThat(initialized.serverInfo().version()).isEqualTo(expected.version());
            assertThat(initialized.serverInfo().description())
                    .isEqualTo(REVISION_DESCRIPTION_PREFIX + expected.gitCommit());

            var info = client.callTool(new CallToolRequest("system.info", Map.of()));
            assertThat(info.isError()).isFalse();
            assertThat(info.structuredContent()).isInstanceOf(Map.class);
            Map<?, ?> identity = (Map<?, ?>) info.structuredContent();
            assertThat(identity.get("server")).isEqualTo(SERVER_NAME);
            assertThat(identity.get("version")).isEqualTo(expected.version());
            assertThat(identity.get("gitRevision")).isEqualTo(expected.gitCommit());

            return new OfficialSdkSession(
                    client,
                    new RawSession(clientBuilder.requiredSessionId(), bearer),
                    expected);
        }
        catch (Exception | AssertionError failure) {
            client.close();
            throw failure;
        }
    }

    HttpObservation ping(RawSession session, String traceId) throws Exception {
        String body = """
                {"jsonrpc":"2.0","id":"ping-%d","method":"ping","params":{}}
                """.formatted(requestId.incrementAndGet());
        return request("POST", session.bearer(), session.id(), traceId, body);
    }

    HttpObservation callTool(
            RawSession session,
            String traceId,
            String tool,
            Map<String, Object> arguments) throws Exception {
        Map<String, Object> request = Map.of(
                "jsonrpc", "2.0",
                "id", "tool-" + requestId.incrementAndGet(),
                "method", "tools/call",
                "params", Map.of("name", tool, "arguments", arguments));
        return request(
                "POST", session.bearer(), session.id(), traceId,
                McpJsonDefaults.getMapper().writeValueAsString(request));
    }

    HttpObservation delete(RawSession session, String traceId) throws Exception {
        return request("DELETE", session.bearer(), session.id(), traceId, null);
    }

    HttpObservation request(
            String method,
            String bearer,
            String sessionId,
            String traceId,
            String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/json, text/event-stream")
                .header("X-Trace-Id", traceId);
        if (sessionId != null) {
            request.header("Mcp-Session-Id", sessionId);
        }
        if (body == null) {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        else {
            request.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        }
        HttpResponse<String> response = httpClient.send(
                request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new HttpObservation(
                response.statusCode(),
                response.headers().firstValue("Mcp-Session-Id").orElse(null),
                response.headers().firstValue("Retry-After").orElse(null),
                response.body());
    }

    static String bearer(Path credentialDirectory, String filename) throws Exception {
        requirePrivateDirectory(credentialDirectory);
        Path file = credentialDirectory.resolve(filename).normalize();
        assertThat(file.getParent()).isEqualTo(credentialDirectory);
        assertThat(Files.isSymbolicLink(file)).isFalse();
        assertThat(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)).isTrue();
        requirePrivateFile(file);
        String response = Files.readString(file, StandardCharsets.UTF_8);
        Matcher matcher = TOKEN_PATTERN.matcher(response);
        if (!matcher.find()) {
            throw new IllegalStateException(filename + " does not contain a token response");
        }
        return matcher.group(1);
    }

    static Path credentialDirectory() throws Exception {
        Path directory = Path.of(requiredEnvironment(
                "WEB_STARTER_MCP_GOVERNANCE_CREDENTIAL_DIR")).toAbsolutePath().normalize();
        requirePrivateDirectory(directory);
        return directory;
    }

    static Path stateFile() throws Exception {
        Path path = Path.of(requiredEnvironment(
                "WEB_STARTER_MCP_GOVERNANCE_STATE_FILE")).toAbsolutePath().normalize();
        assertThat(path.getFileName().toString()).isEqualTo(STATE_FILE);
        requirePrivateDirectory(path.getParent());
        return path;
    }

    static String tracePrefix() {
        String prefix = requiredEnvironment("WEB_STARTER_MCP_GOVERNANCE_TRACE_PREFIX");
        assertThat(prefix).matches(TRACE_PREFIX);
        return prefix;
    }

    static ExpectedRuntimeIdentity expectedRuntimeIdentity() {
        return expectedRuntimeIdentity(
                requiredEnvironment(EXPECTED_VERSION_ENV),
                requiredEnvironment(EXPECTED_GIT_COMMIT_ENV));
    }

    static ExpectedRuntimeIdentity expectedRuntimeIdentity(String version, String gitCommit) {
        assertThat(version)
                .as(EXPECTED_VERSION_ENV)
                .matches(RELEASE_VERSION)
                .doesNotContainIgnoringCase("SNAPSHOT");
        assertThat(gitCommit)
                .as(EXPECTED_GIT_COMMIT_ENV)
                .matches(GIT_COMMIT);
        return new ExpectedRuntimeIdentity(version, gitCommit);
    }

    static String trace(String prefix, String suffix) {
        String trace = prefix + "-" + suffix;
        assertThat(trace).hasSizeBetween(8, 64).matches("[A-Za-z0-9._-]+");
        return trace;
    }

    static void assertRateLimited(HttpObservation response) throws Exception {
        assertThat(response.status()).isEqualTo(429);
        assertThat(errorCode(response)).isEqualTo("RATE_LIMITED");
        assertThat(response.retryAfter()).isNotNull().matches("[1-9][0-9]*");
        assertThat(Long.parseLong(response.retryAfter()))
                .isBetween(1L, (long) RATE_WINDOW_SECONDS);
    }

    static String errorCode(HttpObservation response) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = McpJsonDefaults.getMapper().readValue(response.body(), Map.class);
        assertThat(payload.get("error")).isInstanceOf(Map.class);
        Map<?, ?> error = (Map<?, ?>) payload.get("error");
        assertThat(error.get("data")).isInstanceOf(Map.class);
        Object code = ((Map<?, ?>) error.get("data")).get("code");
        assertThat(code).isInstanceOf(String.class);
        return (String) code;
    }

    static void writeShutdownState(Path path, RawSession session, String tracePrefix) throws Exception {
        assertThat(Files.exists(path, LinkOption.NOFOLLOW_LINKS)).isFalse();
        long createdAt = System.currentTimeMillis();
        String payload = """
                schemaVersion=1
                sessionId=%s
                createdAtEpochMillis=%d
                tracePrefix=%s
                expectedIdleTtlSeconds=%d
                expectedAbsoluteTtlSeconds=%d
                """.formatted(
                session.id(), createdAt, tracePrefix, IDLE_TTL_SECONDS, ABSOLUTE_TTL_SECONDS);
        Files.writeString(
                path,
                payload,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        try {
            Files.setPosixFilePermissions(path, PRIVATE_FILE);
        }
        catch (UnsupportedOperationException ignored) {
            // Windows ACLs are outside this POSIX-only release evidence contract.
        }
        requirePrivateFile(path);
    }

    static ShutdownState readShutdownState(Path path) throws Exception {
        assertThat(Files.isSymbolicLink(path)).isFalse();
        assertThat(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)).isTrue();
        requirePrivateFile(path);
        String payload = Files.readString(path, StandardCharsets.UTF_8);
        Pattern canonical = Pattern.compile(
                "schemaVersion=1\\n"
                        + "sessionId=([A-Za-z0-9._~-]{8,512})\\n"
                        + "createdAtEpochMillis=([1-9][0-9]{12})\\n"
                        + "tracePrefix=([A-Za-z0-9][A-Za-z0-9._-]{0,31})\\n"
                        + "expectedIdleTtlSeconds=" + IDLE_TTL_SECONDS + "\\n"
                        + "expectedAbsoluteTtlSeconds=" + ABSOLUTE_TTL_SECONDS + "\\n");
        Matcher matcher = canonical.matcher(payload);
        assertThat(matcher.matches()).isTrue();
        return new ShutdownState(matcher.group(1), Long.parseLong(matcher.group(2)), matcher.group(3));
    }

    private static void requirePrivateDirectory(Path directory) throws Exception {
        assertThat(directory).isNotNull();
        assertThat(Files.isSymbolicLink(directory)).isFalse();
        assertThat(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)).isTrue();
        try {
            assertThat(Files.getPosixFilePermissions(directory)).isEqualTo(PRIVATE_DIRECTORY);
        }
        catch (UnsupportedOperationException ignored) {
            // The formal runner is POSIX; local compilation may be cross-platform.
        }
    }

    private static void requirePrivateFile(Path file) throws Exception {
        try {
            assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PRIVATE_FILE);
        }
        catch (UnsupportedOperationException ignored) {
            // The formal runner is POSIX; local compilation may be cross-platform.
        }
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for MCP governance runtime acceptance");
        }
        return value.trim();
    }

    record RawSession(String id, String bearer) {
    }

    record OfficialSdkSession(
            McpSyncClient client,
            RawSession rawSession,
            ExpectedRuntimeIdentity expectedIdentity) {
    }

    record ExpectedRuntimeIdentity(String version, String gitCommit) {
    }

    record HttpObservation(int status, String sessionId, String retryAfter, String body) {
    }

    record ShutdownState(String sessionId, long createdAtEpochMillis, String tracePrefix) {
    }

    /**
     * Test-only client builder that observes the SDK's actual initialize response
     * header without reaching into private SDK state.
     */
    private static final class SessionCapturingHttpClientBuilder implements HttpClient.Builder {

        private final HttpClient.Builder delegate;
        private final AtomicReference<String> sessionId = new AtomicReference<>();

        private SessionCapturingHttpClientBuilder(HttpClient.Builder delegate) {
            this.delegate = delegate;
        }

        String requiredSessionId() {
            String captured = sessionId.get();
            assertThat(captured).as("official SDK Mcp-Session-Id").isNotNull().matches(SESSION_ID);
            return captured;
        }

        @Override
        public HttpClient.Builder cookieHandler(CookieHandler cookieHandler) {
            delegate.cookieHandler(cookieHandler);
            return this;
        }

        @Override
        public HttpClient.Builder connectTimeout(Duration duration) {
            delegate.connectTimeout(duration);
            return this;
        }

        @Override
        public HttpClient.Builder sslContext(SSLContext sslContext) {
            delegate.sslContext(sslContext);
            return this;
        }

        @Override
        public HttpClient.Builder sslParameters(SSLParameters sslParameters) {
            delegate.sslParameters(sslParameters);
            return this;
        }

        @Override
        public HttpClient.Builder executor(Executor executor) {
            delegate.executor(executor);
            return this;
        }

        @Override
        public HttpClient.Builder followRedirects(HttpClient.Redirect policy) {
            delegate.followRedirects(policy);
            return this;
        }

        @Override
        public HttpClient.Builder version(HttpClient.Version version) {
            delegate.version(version);
            return this;
        }

        @Override
        public HttpClient.Builder priority(int priority) {
            delegate.priority(priority);
            return this;
        }

        @Override
        public HttpClient.Builder proxy(ProxySelector proxySelector) {
            delegate.proxy(proxySelector);
            return this;
        }

        @Override
        public HttpClient.Builder authenticator(Authenticator authenticator) {
            delegate.authenticator(authenticator);
            return this;
        }

        @Override
        public HttpClient.Builder localAddress(InetAddress localAddress) {
            delegate.localAddress(localAddress);
            return this;
        }

        @Override
        public HttpClient build() {
            return new SessionCapturingHttpClient(delegate.build(), sessionId);
        }
    }

    private static final class SessionCapturingHttpClient extends HttpClient {

        private final HttpClient delegate;
        private final AtomicReference<String> sessionId;

        private SessionCapturingHttpClient(
                HttpClient delegate,
                AtomicReference<String> sessionId) {
            this.delegate = delegate;
            this.sessionId = sessionId;
        }

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return delegate.cookieHandler();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return delegate.connectTimeout();
        }

        @Override
        public Redirect followRedirects() {
            return delegate.followRedirects();
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return delegate.proxy();
        }

        @Override
        public SSLContext sslContext() {
            return delegate.sslContext();
        }

        @Override
        public SSLParameters sslParameters() {
            return delegate.sslParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return delegate.authenticator();
        }

        @Override
        public Version version() {
            return delegate.version();
        }

        @Override
        public Optional<Executor> executor() {
            return delegate.executor();
        }

        @Override
        public <T> HttpResponse<T> send(
                HttpRequest request,
                HttpResponse.BodyHandler<T> responseBodyHandler)
                throws java.io.IOException, InterruptedException {
            return capture(delegate.send(request, responseBodyHandler));
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request,
                HttpResponse.BodyHandler<T> responseBodyHandler) {
            return delegate.sendAsync(request, responseBodyHandler).thenApply(this::capture);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request,
                HttpResponse.BodyHandler<T> responseBodyHandler,
                HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
            return delegate.sendAsync(request, responseBodyHandler, pushPromiseHandler)
                    .thenApply(this::capture);
        }

        @Override
        public WebSocket.Builder newWebSocketBuilder() {
            return delegate.newWebSocketBuilder();
        }

        @Override
        public void shutdown() {
            delegate.shutdown();
        }

        @Override
        public boolean awaitTermination(Duration duration) throws InterruptedException {
            return delegate.awaitTermination(duration);
        }

        @Override
        public boolean isTerminated() {
            return delegate.isTerminated();
        }

        @Override
        public void shutdownNow() {
            delegate.shutdownNow();
        }

        @Override
        public void close() {
            delegate.close();
        }

        private <T> HttpResponse<T> capture(HttpResponse<T> response) {
            response.headers().firstValue("Mcp-Session-Id").ifPresent(this::captureSessionId);
            return response;
        }

        private void captureSessionId(String candidate) {
            assertThat(candidate).as("Mcp-Session-Id response header").matches(SESSION_ID);
            String previous = sessionId.compareAndExchange(null, candidate);
            if (previous != null) {
                assertThat(candidate).as("stable official SDK Session ID").isEqualTo(previous);
            }
        }
    }
}
