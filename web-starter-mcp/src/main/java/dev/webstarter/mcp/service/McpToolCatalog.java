package dev.webstarter.mcp.service;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.validation.ConstraintViolationException;

import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import dev.webstarter.core.exception.BusinessException;
import dev.webstarter.core.exception.PermissionDeniedException;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.project.dto.ProjectCreateRequest;
import dev.webstarter.project.dto.ProjectUpdateRequest;
import dev.webstarter.project.service.ProjectPermissions;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.system.service.AuditQueryService;
import dev.webstarter.system.service.SystemPermissions;

@Component
public class McpToolCatalog {

    public static final String SYSTEM_INFO = "system.info";
    public static final String PROJECT_LIST = "project.list";
    public static final String PROJECT_GET = "project.get";
    public static final String PROJECT_CREATE = "project.create";
    public static final String PROJECT_UPDATE = "project.update";
    public static final String PROJECT_REMOVE = "project.remove";
    public static final String AUDIT_LIST = "audit.list";

    private static final Logger log = LoggerFactory.getLogger(McpToolCatalog.class);

    private final ProjectService projectService;
    private final AuditQueryService auditQueryService;
    private final McpInvocationService invocationService;
    private final McpJsonMapper jsonMapper;

    public McpToolCatalog(
            ProjectService projectService,
            AuditQueryService auditQueryService,
            McpInvocationService invocationService,
            McpJsonMapper jsonMapper) {
        this.projectService = projectService;
        this.auditQueryService = auditQueryService;
        this.invocationService = invocationService;
        this.jsonMapper = jsonMapper;
    }

    public List<SyncToolSpecification> specifications() {
        return List.of(
                specification(SYSTEM_INFO, "Return non-sensitive server information", emptySchema(), readOnly(),
                        McpPermissions.SYSTEM_INFO, request -> systemInfo()),
                specification(PROJECT_LIST, "List projects visible to the caller", projectListSchema(), readOnly(),
                        ProjectPermissions.LIST, this::projectList),
                specification(PROJECT_GET, "Get a project by id", idSchema(false), readOnly(),
                        ProjectPermissions.LIST, this::projectGet),
                specification(PROJECT_CREATE, "Create a project", projectCreateSchema(), mutating(false),
                        ProjectPermissions.CREATE, this::projectCreate),
                specification(PROJECT_UPDATE, "Update a project using optimistic locking", projectUpdateSchema(),
                        mutating(false), ProjectPermissions.UPDATE, this::projectUpdate),
                specification(PROJECT_REMOVE, "Remove a project using optimistic locking", idSchema(true),
                        mutating(true), ProjectPermissions.REMOVE, this::projectRemove),
                specification(AUDIT_LIST, "List MCP invocation audit records", auditListSchema(), readOnly(),
                        SystemPermissions.AUDIT_LIST, this::auditList));
    }

    /** Returns the frozen V1 permission for a tool, or {@code null} for an unknown name. */
    public static String permissionFor(String toolName) {
        return switch (toolName) {
            case SYSTEM_INFO -> McpPermissions.SYSTEM_INFO;
            case PROJECT_LIST, PROJECT_GET -> ProjectPermissions.LIST;
            case PROJECT_CREATE -> ProjectPermissions.CREATE;
            case PROJECT_UPDATE -> ProjectPermissions.UPDATE;
            case PROJECT_REMOVE -> ProjectPermissions.REMOVE;
            case AUDIT_LIST -> SystemPermissions.AUDIT_LIST;
            default -> null;
        };
    }

    private SyncToolSpecification specification(
            String name,
            String description,
            Map<String, Object> schema,
            ToolAnnotations annotations,
            String permission,
            java.util.function.Function<Map<String, Object>, Object> action) {
        Tool tool = Tool.builder()
                .name(name)
                .description(description)
                .inputSchema(schema)
                .annotations(annotations)
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, request) -> invoke(name, permission, () -> action.apply(
                        McpInputValidator.validate(schema, request.arguments()))))
                .build();
    }

    private CallToolResult invoke(String operation, String permission, Supplier<Object> action) {
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
            String message = safeMessage(exception);
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("code", code);
            error.put("message", message);
            error.put("traceId", TraceContext.traceId());
            if ("INTERNAL_ERROR".equals(code)) {
                log.error("Unhandled MCP tool failure for {}", operation, exception);
            }
            return CallToolResult.builder()
                    .addTextContent(writeJson(error))
                    .structuredContent(error)
                    .isError(true)
                    .build();
        }
    }

    private Map<String, Object> systemInfo() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("product", "启程 Web Starter");
        result.put("server", "web-starter-mcp");
        result.put("java", Runtime.version().feature());
        result.put("time", Instant.now().toString());
        return result;
    }

    private Object projectList(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        return projectService.page(
                arguments.longValue("page", 1),
                arguments.longValue("size", 20),
                arguments.optionalString("keyword"),
                arguments.optionalString("status"),
                arguments.optionalId("ownerId"));
    }

    private Object projectGet(Map<String, Object> rawArguments) {
        return projectService.get(new McpArguments(rawArguments).requiredId("id"));
    }

    private Object projectCreate(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        return projectService.create(new ProjectCreateRequest(
                arguments.requiredString("name"),
                arguments.requiredString("code"),
                arguments.requiredId("ownerId"),
                arguments.requiredString("status"),
                arguments.optionalString("description")));
    }

    private Object projectUpdate(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        long id = arguments.requiredId("id");
        return projectService.update(id, new ProjectUpdateRequest(
                arguments.requiredString("name"),
                arguments.requiredId("ownerId"),
                arguments.requiredString("status"),
                arguments.optionalString("description"),
                arguments.requiredInteger("version")));
    }

    private Object projectRemove(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        long id = arguments.requiredId("id");
        int version = arguments.requiredInteger("version");
        projectService.remove(id, version);
        return Map.of("id", id, "removed", true);
    }

    private Object auditList(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        return auditQueryService.pageMcp(
                arguments.longValue("page", 1),
                arguments.longValue("size", 20),
                arguments.optionalString("actorName"),
                arguments.optionalString("toolName"),
                arguments.optionalString("result"));
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
        if (exception instanceof PermissionDeniedException) {
            return "The caller is not allowed to perform this operation";
        }
        if (exception instanceof BusinessException || exception instanceof IllegalArgumentException) {
            return exception.getMessage();
        }
        if (exception instanceof org.springframework.security.access.AccessDeniedException) {
            return "The caller is not allowed to perform this operation";
        }
        return "The MCP operation failed";
    }

    private static ToolAnnotations readOnly() {
        return ToolAnnotations.builder()
                .readOnlyHint(true)
                .destructiveHint(false)
                .idempotentHint(true)
                .openWorldHint(false)
                .build();
    }

    private static ToolAnnotations mutating(boolean destructive) {
        return ToolAnnotations.builder()
                .readOnlyHint(false)
                .destructiveHint(destructive)
                .idempotentHint(false)
                .openWorldHint(false)
                .build();
    }

    private static Map<String, Object> emptySchema() {
        return objectSchema(Map.of(), List.of());
    }

    private static Map<String, Object> idSchema(boolean includeVersion) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("id", idStringSchema("Project id"));
        if (includeVersion) {
            properties.put("version", integerSchema("Current optimistic-lock version", 0));
        }
        return objectSchema(properties, includeVersion ? List.of("id", "version") : List.of("id"));
    }

    private static Map<String, Object> projectListSchema() {
        Map<String, Object> properties = pageProperties();
        properties.put("keyword", stringSchema("Name, code, or owner keyword"));
        properties.put("status", statusSchema("Project status"));
        properties.put("ownerId", idStringSchema("Owner user id"));
        return objectSchema(properties, List.of());
    }

    private static Map<String, Object> auditListSchema() {
        Map<String, Object> properties = pageProperties();
        properties.put("actorName", stringSchema("Actor display name"));
        properties.put("toolName", stringSchema("MCP operation name"));
        properties.put("result", Map.of("type", "string", "enum", List.of("SUCCESS", "FAILED")));
        return objectSchema(properties, List.of());
    }

    private static Map<String, Object> projectCreateSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("name", boundedStringSchema("Project name", 1, 120));
        properties.put("code", Map.of(
                "type", "string",
                "description", "Unique project code",
                "minLength", 2,
                "maxLength", 64,
                "pattern", "[A-Za-z][A-Za-z0-9_-]{1,63}"));
        properties.put("ownerId", idStringSchema("Owner user id"));
        properties.put("status", statusSchema("Project status"));
        properties.put("description", boundedStringSchema("Optional project description", 0, 2000));
        return objectSchema(properties, List.of("name", "code", "ownerId", "status"));
    }

    private static Map<String, Object> projectUpdateSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("id", idStringSchema("Project id"));
        properties.put("name", boundedStringSchema("Project name", 1, 120));
        properties.put("ownerId", idStringSchema("Owner user id"));
        properties.put("status", statusSchema("Project status"));
        properties.put("description", boundedStringSchema("Optional project description", 0, 2000));
        properties.put("version", integerSchema("Current optimistic-lock version", 0));
        return objectSchema(properties, List.of("id", "name", "ownerId", "status", "version"));
    }

    private static Map<String, Object> pageProperties() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("page", integerSchema("Page number", 1));
        properties.put("size", Map.of(
                "type", "integer", "description", "Page size", "minimum", 1, "maximum", 200));
        return properties;
    }

    private static Map<String, Object> objectSchema(
            Map<String, Object> properties,
            List<String> required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", required);
        schema.put("additionalProperties", false);
        return schema;
    }

    private static Map<String, Object> stringSchema(String description) {
        return Map.of("type", "string", "description", description, "minLength", 1);
    }

    private static Map<String, Object> boundedStringSchema(
            String description,
            int minimumLength,
            int maximumLength) {
        return Map.of(
                "type", "string",
                "description", description,
                "minLength", minimumLength,
                "maxLength", maximumLength);
    }

    private static Map<String, Object> statusSchema(String description) {
        return Map.of(
                "type", "string",
                "description", description,
                "enum", List.of("PLANNING", "IN_PROGRESS", "ARCHIVED"));
    }

    private static Map<String, Object> integerSchema(String description, int minimum) {
        return Map.of("type", "integer", "description", description, "minimum", minimum);
    }

    private static Map<String, Object> idStringSchema(String description) {
        return Map.of(
                "type", "string",
                "description", description + " (opaque positive decimal identifier)",
                "pattern", McpIdentifierContract.POSITIVE_LONG_PATTERN);
    }
}
