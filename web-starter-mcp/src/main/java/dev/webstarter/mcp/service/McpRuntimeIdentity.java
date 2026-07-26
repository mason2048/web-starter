package dev.webstarter.mcp.service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import io.modelcontextprotocol.spec.McpSchema.Implementation;

/** Non-secret release identity shared by MCP initialize, Tools and Resources. */
public final class McpRuntimeIdentity {

    public static final String PRODUCT_NAME = "启程 Web Starter";
    public static final String SERVER_NAME = "web-starter-mcp";
    public static final String LOCAL_REVISION = "local";
    public static final String REVISION_DESCRIPTION_PREFIX = "gitRevision=";

    private static final Pattern SAFE_VERSION = Pattern.compile("[0-9A-Za-z][0-9A-Za-z._+-]{0,63}");
    private static final Pattern GIT_REVISION = Pattern.compile("[0-9a-f]{40}(?:[0-9a-f]{24})?");

    private final String applicationVersion;
    private final String gitRevision;

    public McpRuntimeIdentity(String applicationVersion, String gitRevision) {
        this.applicationVersion = requireCanonical(
                applicationVersion, SAFE_VERSION, "application version");
        this.gitRevision = requireGitRevision(gitRevision);
    }

    public String applicationVersion() {
        return applicationVersion;
    }

    public String gitRevision() {
        return gitRevision;
    }

    public Implementation serverInfo() {
        return Implementation.builder(SERVER_NAME, applicationVersion)
                .title(PRODUCT_NAME + " MCP")
                .description(REVISION_DESCRIPTION_PREFIX + gitRevision)
                .build();
    }

    public Map<String, Object> systemInfo() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("product", PRODUCT_NAME);
        result.put("server", SERVER_NAME);
        result.put("version", applicationVersion);
        result.put("gitRevision", gitRevision);
        result.put("java", Runtime.version().feature());
        result.put("time", Instant.now().toString());
        return result;
    }

    static McpRuntimeIdentity localTestIdentity() {
        return new McpRuntimeIdentity("test", LOCAL_REVISION);
    }

    private static String requireGitRevision(String value) {
        String revision = Objects.requireNonNull(value, "git revision must not be null");
        if (!revision.equals(revision.trim())
                || !(LOCAL_REVISION.equals(revision) || GIT_REVISION.matcher(revision).matches())) {
            throw new IllegalArgumentException(
                    "git revision must be 'local' or a lowercase 40/64-character Git object id");
        }
        return revision;
    }

    private static String requireCanonical(String value, Pattern pattern, String label) {
        String candidate = Objects.requireNonNull(value, label + " must not be null");
        if (!candidate.equals(candidate.trim()) || !pattern.matcher(candidate).matches()) {
            throw new IllegalArgumentException(label + " is malformed");
        }
        return candidate;
    }
}
