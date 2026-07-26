package dev.webstarter.mcp.governance;

import dev.webstarter.mcp.service.McpToolCatalog;

public enum McpToolRisk {
    READ,
    WRITE,
    DESTRUCTIVE,
    PROTOCOL;

    public static McpToolRisk forTool(String toolName) {
        if (toolName == null) {
            return PROTOCOL;
        }
        return switch (toolName) {
            case McpToolCatalog.SYSTEM_INFO,
                    McpToolCatalog.PROJECT_LIST,
                    McpToolCatalog.PROJECT_GET,
                    McpToolCatalog.AUDIT_LIST -> READ;
            case McpToolCatalog.PROJECT_CREATE,
                    McpToolCatalog.PROJECT_UPDATE -> WRITE;
            case McpToolCatalog.PROJECT_REMOVE -> DESTRUCTIVE;
            default -> PROTOCOL;
        };
    }
}
