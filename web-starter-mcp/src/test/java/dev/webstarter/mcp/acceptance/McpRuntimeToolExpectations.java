package dev.webstarter.mcp.acceptance;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

final class McpRuntimeToolExpectations {

    private static final String ADDITIONAL_TOOLS_ENV =
            "WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS";
    private static final Pattern GENERATED_TOOL = Pattern.compile(
            "[a-z][a-z0-9]{1,30}\\.(?:list|get|create|update|remove)");
    private static final Set<String> BASE_TOOLS = Set.of(
            "system.info",
            "project.list",
            "project.get",
            "project.create",
            "project.update",
            "project.remove",
            "audit.list");

    private McpRuntimeToolExpectations() {
    }

    static Set<String> fromEnvironment() {
        return parse(System.getenv(ADDITIONAL_TOOLS_ENV));
    }

    static Set<String> parse(String additionalTools) {
        LinkedHashSet<String> expected = new LinkedHashSet<>(BASE_TOOLS);
        if (additionalTools == null || additionalTools.isBlank()) {
            return Collections.unmodifiableSet(expected);
        }
        for (String raw : additionalTools.split(",", -1)) {
            String tool = raw.trim();
            if (!GENERATED_TOOL.matcher(tool).matches()) {
                throw new IllegalArgumentException(
                        ADDITIONAL_TOOLS_ENV + " contains an invalid generated Tool name");
            }
            if (!expected.add(tool)) {
                throw new IllegalArgumentException(
                        ADDITIONAL_TOOLS_ENV + " repeats a Tool name");
            }
        }
        return Collections.unmodifiableSet(expected);
    }
}
