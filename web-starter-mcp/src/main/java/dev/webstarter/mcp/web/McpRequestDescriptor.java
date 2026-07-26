package dev.webstarter.mcp.web;

import java.io.IOException;
import java.util.Map;

import dev.webstarter.mcp.governance.McpToolRisk;
import dev.webstarter.mcp.service.McpToolCatalog;
import io.modelcontextprotocol.json.McpJsonMapper;

record McpRequestDescriptor(
        String method,
        String toolName,
        String permission,
        Object requestId,
        McpToolRisk risk) {

    static McpRequestDescriptor describe(
            String httpMethod,
            byte[] body,
            McpJsonMapper jsonMapper) {
        return describe(httpMethod, body, jsonMapper, null);
    }

    static McpRequestDescriptor describe(
            String httpMethod,
            byte[] body,
            McpJsonMapper jsonMapper,
            McpToolCatalog toolCatalog) {
        if (!"POST".equals(httpMethod) || body == null || body.length == 0) {
            return protocol(httpMethod);
        }
        try {
            Map<?, ?> envelope = jsonMapper.readValue(body, Map.class);
            String method = envelope.get("method") instanceof String value ? limit(value, 128) : "protocol";
            Object id = safeId(envelope.get("id"));
            if ("tools/call".equals(method) && envelope.get("params") instanceof Map<?, ?> params) {
                String toolName = params.get("name") instanceof String value ? limit(value, 128) : null;
                String permission = toolCatalog == null
                        ? McpToolCatalog.permissionFor(toolName)
                        : toolCatalog.permissionForRegisteredTool(toolName);
                McpToolRisk risk = toolCatalog == null
                        ? McpToolRisk.forTool(toolName)
                        : toolCatalog.riskForRegisteredTool(toolName);
                return new McpRequestDescriptor(
                        method,
                        toolName,
                        permission,
                        id,
                        risk);
            }
            return new McpRequestDescriptor(method, null, null, id, McpToolRisk.PROTOCOL);
        }
        catch (IOException | RuntimeException ignored) {
            return protocol(httpMethod);
        }
    }

    boolean initialize() {
        return "initialize".equals(method);
    }

    String auditOperation() {
        if (toolName != null) {
            return toolName;
        }
        return switch (method == null ? "" : method) {
            case "GET" -> "session.stream";
            case "DELETE" -> "session.delete";
            case "initialize" -> "initialize";
            default -> limit(method == null ? "protocol" : method, 128);
        };
    }

    private static McpRequestDescriptor protocol(String httpMethod) {
        String operation = httpMethod == null ? "protocol" : httpMethod;
        return new McpRequestDescriptor(operation, null, null, null, McpToolRisk.PROTOCOL);
    }

    private static Object safeId(Object value) {
        return value instanceof String || value instanceof Number ? value : null;
    }

    private static String limit(String value, int maxCodePoints) {
        if (value == null || value.codePointCount(0, value.length()) <= maxCodePoints) {
            return value;
        }
        return value.substring(0, value.offsetByCodePoints(0, maxCodePoints));
    }
}
