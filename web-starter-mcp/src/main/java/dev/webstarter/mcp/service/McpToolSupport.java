package dev.webstarter.mcp.service;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

import jakarta.validation.ConstraintViolationException;

import dev.webstarter.core.exception.BusinessException;
import dev.webstarter.core.exception.PermissionDeniedException;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.mcp.governance.McpToolRisk;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/** Shared, audited construction support for statically generated MCP Tools. */
@Component
public final class McpToolSupport {

    public static final String IDEMPOTENCY_KEY = "idempotencyKey";

    private static final Logger log = LoggerFactory.getLogger(McpToolSupport.class);

    private final McpInvocationService invocationService;
    private final McpIdempotencyService idempotencyService;
    private final McpJsonMapper jsonMapper;

    @Autowired
    public McpToolSupport(
            McpInvocationService invocationService,
            McpIdempotencyService idempotencyService,
            McpJsonMapper jsonMapper) {
        this(invocationService, idempotencyService, jsonMapper, true);
    }

    private McpToolSupport(
            McpInvocationService invocationService,
            McpIdempotencyService idempotencyService,
            McpJsonMapper jsonMapper,
            boolean executable) {
        this.invocationService = executable
                ? Objects.requireNonNull(invocationService, "invocationService") : null;
        this.idempotencyService = executable
                ? Objects.requireNonNull(idempotencyService, "idempotencyService") : null;
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper");
    }

    /**
     * Creates a non-executable helper for inspecting generated Tool contracts without
     * Mockito, bytecode agents, a Spring context, or infrastructure dependencies.
     */
    public static McpToolSupport forContractInspection(McpJsonMapper jsonMapper) {
        return new McpToolSupport(null, null, jsonMapper, false);
    }

    public McpToolContribution specification(
            String name,
            String description,
            Map<String, Object> inputSchema,
            Map<String, Object> outputSchema,
            ToolAnnotations annotations,
            String permission,
            McpToolRisk risk,
            Function<Map<String, Object>, Object> action) {
        Tool.Builder builder = Tool.builder()
                .name(name)
                .description(description)
                .inputSchema(inputSchema)
                .annotations(annotations);
        if (outputSchema != null) {
            builder.outputSchema(toolResultSchema(outputSchema));
        }
        SyncToolSpecification specification = SyncToolSpecification.builder()
                .tool(builder.build())
                .callHandler((exchange, request) -> invoke(name, permission, () -> action.apply(
                        McpInputValidator.validate(inputSchema, request.arguments()))))
                .build();
        return new McpToolContribution(specification, permission, risk);
    }

    public <T> T idempotent(
            String toolName,
            Map<String, Object> arguments,
            Supplier<T> action) {
        requireExecutable();
        String key = new McpArguments(arguments).requiredString(IDEMPOTENCY_KEY);
        return idempotencyService.execute(toolName, arguments, key, action);
    }

    private CallToolResult invoke(String operation, String permission, Supplier<Object> action) {
        requireExecutable();
        try {
            Object result = invocationService.invoke(operation, permission, action);
            Object safeResult = McpIdentifierContract.normalizeOutput(jsonMapper, result);
            return CallToolResult.builder()
                    .addTextContent(writeJson(safeResult))
                    .structuredContent(safeResult)
                    .isError(false)
                    .build();
        }
        catch (RuntimeException exception) {
            String code = McpInvocationService.errorCode(exception);
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("code", code);
            error.put("message", safeMessage(exception));
            error.put("traceId", TraceContext.traceId());
            if ("INTERNAL_ERROR".equals(code)) {
                log.error("Unhandled contributed MCP tool failure for {}", operation, exception);
            }
            return CallToolResult.builder()
                    .addTextContent(writeJson(error))
                    .structuredContent(error)
                    .isError(true)
                    .build();
        }
    }

    private void requireExecutable() {
        if (invocationService == null || idempotencyService == null) {
            throw new IllegalStateException(
                    "Contract-inspection MCP Tool support cannot execute handlers");
        }
    }

    private String writeJson(Object value) {
        try {
            return jsonMapper.writeValueAsString(value);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Unable to serialize MCP result", exception);
        }
    }

    private static String safeMessage(RuntimeException exception) {
        if (exception instanceof ConstraintViolationException violationException) {
            String details = violationException.getConstraintViolations().stream()
                    .map(violation -> violation.getMessage())
                    .filter(message -> message != null && !message.isBlank())
                    .distinct()
                    .sorted()
                    .collect(java.util.stream.Collectors.joining("; "));
            return details.isBlank() ? "One or more tool arguments are invalid" : details;
        }
        if (exception instanceof PermissionDeniedException || exception instanceof AccessDeniedException) {
            return "The caller is not allowed to perform this operation";
        }
        if (exception instanceof McpIdempotencyConflictException
                || exception instanceof McpIdempotencyInProgressException
                || exception instanceof BusinessException
                || exception instanceof IllegalArgumentException) {
            return exception.getMessage();
        }
        return "The MCP operation failed";
    }

    public static ToolAnnotations readOnly() {
        return ToolAnnotations.builder()
                .readOnlyHint(true)
                .destructiveHint(false)
                .idempotentHint(true)
                .openWorldHint(false)
                .build();
    }

    public static ToolAnnotations mutating(boolean destructive) {
        return ToolAnnotations.builder()
                .readOnlyHint(false)
                .destructiveHint(destructive)
                .idempotentHint(true)
                .openWorldHint(false)
                .build();
    }

    public static Map<String, Object> objectSchema(
            Map<String, Object> properties,
            List<String> required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", required);
        schema.put("additionalProperties", false);
        return schema;
    }

    public static Map<String, Object> boundedStringSchema(
            String description,
            int minimumLength,
            int maximumLength) {
        return Map.of(
                "type", "string",
                "description", description,
                "minLength", minimumLength,
                "maxLength", maximumLength);
    }

    public static Map<String, Object> enumSchema(String description, List<String> values) {
        return Map.of("type", "string", "description", description, "enum", values);
    }

    public static Map<String, Object> integerSchema(String description, int minimum) {
        return Map.of("type", "integer", "description", description, "minimum", minimum);
    }

    public static Map<String, Object> idStringSchema(String description) {
        return Map.of(
                "type", "string",
                "description", description + " (opaque positive decimal identifier)",
                "pattern", McpIdentifierContract.POSITIVE_LONG_PATTERN);
    }

    public static Map<String, Object> idempotencyKeySchema() {
        return Map.of(
                "type", "string",
                "description", "Stable retry key for this logical write operation",
                "minLength", 16,
                "maxLength", 128,
                "pattern", "^[A-Za-z0-9._:-]+$");
    }

    private static Map<String, Object> toolResultSchema(Map<String, Object> successSchema) {
        Map<String, Object> errorProperties = new LinkedHashMap<>();
        errorProperties.put("code", boundedStringSchema("Stable error code", 1, 128));
        errorProperties.put("message", boundedStringSchema("Safe error message", 1, 2000));
        errorProperties.put("traceId", boundedStringSchema("Trace identifier", 1, 128));
        Map<String, Object> errorSchema = objectSchema(
                errorProperties, List.of("code", "message", "traceId"));
        return Map.of("oneOf", List.of(successSchema, errorSchema));
    }
}
