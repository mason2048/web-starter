package dev.webstarter.mcp.service;

import java.util.Objects;

import dev.webstarter.mcp.governance.McpToolRisk;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;

/**
 * A statically compiled MCP Tool contributed by an explicit domain module.
 *
 * <p>The permission and risk metadata are kept beside the official SDK
 * specification so pre-dispatch audit and governance cannot drift from the
 * handler contract.</p>
 */
public record McpToolContribution(
        SyncToolSpecification specification,
        String permission,
        McpToolRisk risk) {

    public McpToolContribution {
        Objects.requireNonNull(specification, "specification");
        Objects.requireNonNull(risk, "risk");
        if (specification.tool() == null || specification.tool().name() == null
                || specification.tool().name().isBlank()) {
            throw new IllegalArgumentException("Contributed MCP Tool must have a name");
        }
        if (permission == null || permission.isBlank()) {
            throw new IllegalArgumentException("Contributed MCP Tool must have a permission");
        }
    }

    public String name() {
        return specification.tool().name();
    }
}
