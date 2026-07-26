package dev.webstarter.mcp.service;

import java.util.List;

/**
 * Compile-time extension point used only by explicitly generated domain
 * modules. Implementations are ordinary Spring beans; no runtime scripts,
 * reflection-based templates, remote downloads, or dynamic code are accepted.
 */
public interface McpToolContributor {

    List<McpToolContribution> contributions();
}
