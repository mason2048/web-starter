package dev.webstarter.mcp.service;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import jakarta.validation.ConstraintViolationException;

import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import dev.webstarter.core.exception.BusinessException;
import dev.webstarter.core.exception.PermissionDeniedException;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.mcp.governance.McpToolRisk;
import dev.webstarter.project.dto.ProjectCreateRequest;
import dev.webstarter.project.dto.ProjectUpdateRequest;
import dev.webstarter.project.service.ProjectPermissions;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.system.service.AuditQueryService;
import dev.webstarter.system.service.AuditSearchQuery;
import dev.webstarter.system.service.SystemPermissions;

@Component
public class McpToolCatalog {

    static final String TOOL_ERROR_CODE_PATTERN =
            "^(?:FORBIDDEN|INVALID_ARGUMENT|IDEMPOTENCY_CONFLICT|"
                    + "IDEMPOTENCY_IN_PROGRESS|INTERNAL_ERROR|BUSINESS_[0-9]{4})$";

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
    private final McpIdempotencyService idempotencyService;
    private final McpJsonMapper jsonMapper;
    private final McpRuntimeIdentity runtimeIdentity;
    private final List<McpToolContribution> contributions;

    @Autowired
    public McpToolCatalog(
            ProjectService projectService,
            AuditQueryService auditQueryService,
            McpInvocationService invocationService,
            McpIdempotencyService idempotencyService,
            McpJsonMapper jsonMapper,
            McpRuntimeIdentity runtimeIdentity,
            List<McpToolContributor> contributors) {
        this.projectService = projectService;
        this.auditQueryService = auditQueryService;
        this.invocationService = invocationService;
        this.idempotencyService = idempotencyService;
        this.jsonMapper = jsonMapper;
        this.runtimeIdentity = runtimeIdentity;
        this.contributions = collectContributions(contributors);
    }

    public McpToolCatalog(
            ProjectService projectService,
            AuditQueryService auditQueryService,
            McpInvocationService invocationService,
            McpIdempotencyService idempotencyService,
            McpJsonMapper jsonMapper,
            List<McpToolContributor> contributors) {
        this(projectService, auditQueryService, invocationService, idempotencyService,
                jsonMapper, McpRuntimeIdentity.localTestIdentity(), contributors);
    }

    public McpToolCatalog(
            ProjectService projectService,
            AuditQueryService auditQueryService,
            McpInvocationService invocationService,
            McpIdempotencyService idempotencyService,
            McpJsonMapper jsonMapper) {
        this(projectService, auditQueryService, invocationService, idempotencyService,
                jsonMapper, McpRuntimeIdentity.localTestIdentity(), List.of());
    }

    public List<SyncToolSpecification> specifications() {
        List<SyncToolSpecification> specifications = new ArrayList<>(List.of(
                specification(SYSTEM_INFO, "Return non-sensitive server information", emptySchema(), null, readOnly(),
                        McpPermissions.SYSTEM_INFO, request -> systemInfo()),
                specification(PROJECT_LIST, "List projects visible to the caller", projectListSchema(), null, readOnly(),
                        ProjectPermissions.LIST, this::projectList),
                specification(PROJECT_GET, "Get a project by id", idSchema(false, false), projectOutputSchema(), readOnly(),
                        ProjectPermissions.LIST, this::projectGet),
                specification(PROJECT_CREATE, "Create a project", projectCreateSchema(), projectOutputSchema(),
                        mutating(false, false),
                        ProjectPermissions.CREATE, this::projectCreate),
                specification(PROJECT_UPDATE, "Update a project using optimistic locking", projectUpdateSchema(),
                        projectOutputSchema(), mutating(true, true), ProjectPermissions.UPDATE, this::projectUpdate),
                specification(PROJECT_REMOVE, "Remove a project using optimistic locking", idSchema(true, true),
                        removeOutputSchema(), mutating(true, true), ProjectPermissions.REMOVE, this::projectRemove),
                specification(AUDIT_LIST, "List MCP invocation audit records", auditListSchema(), null, readOnly(),
                        SystemPermissions.AUDIT_LIST, this::auditList)));
        contributions.stream().map(McpToolContribution::specification).forEach(specifications::add);
        return List.copyOf(specifications);
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

    /** Resolves both the frozen built-ins and statically contributed module Tools. */
    public String permissionForRegisteredTool(String toolName) {
        String builtIn = permissionFor(toolName);
        if (builtIn != null) {
            return builtIn;
        }
        return contributions.stream()
                .filter(contribution -> contribution.name().equals(toolName))
                .map(McpToolContribution::permission)
                .findFirst()
                .orElse(null);
    }

    /** Returns the governance risk for a registered Tool, or PROTOCOL for unknown input. */
    public McpToolRisk riskForRegisteredTool(String toolName) {
        if (permissionFor(toolName) != null) {
            return McpToolRisk.forTool(toolName);
        }
        return contributions.stream()
                .filter(contribution -> contribution.name().equals(toolName))
                .map(McpToolContribution::risk)
                .findFirst()
                .orElse(McpToolRisk.PROTOCOL);
    }

    private static List<McpToolContribution> collectContributions(
            List<McpToolContributor> contributors) {
        if (contributors == null || contributors.isEmpty()) {
            return List.of();
        }
        Set<String> names = new HashSet<>(Set.of(
                SYSTEM_INFO, PROJECT_LIST, PROJECT_GET, PROJECT_CREATE,
                PROJECT_UPDATE, PROJECT_REMOVE, AUDIT_LIST));
        List<McpToolContribution> result = new ArrayList<>();
        for (McpToolContributor contributor : contributors) {
            if (contributor == null) {
                throw new IllegalStateException("MCP Tool contributor returned null");
            }
            List<McpToolContribution> contributedTools = contributor.contributions();
            if (contributedTools == null) {
                throw new IllegalStateException("MCP Tool contributor returned null");
            }
            for (McpToolContribution contribution : contributedTools) {
                if (contribution == null || !names.add(contribution.name())) {
                    throw new IllegalStateException("Duplicate MCP Tool name: "
                            + (contribution == null ? "<null>" : contribution.name()));
                }
                result.add(contribution);
            }
        }
        return List.copyOf(result);
    }

    private SyncToolSpecification specification(
            String name,
            String description,
            Map<String, Object> schema,
            Map<String, Object> outputSchema,
            ToolAnnotations annotations,
            String permission,
            java.util.function.Function<Map<String, Object>, Object> action) {
        Tool.Builder builder = Tool.builder()
                .name(name)
                .description(description)
                .inputSchema(schema)
                .annotations(annotations);
        if (outputSchema != null) {
            builder.outputSchema(toolResultSchema(outputSchema));
        }
        Tool tool = builder.build();
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
        return runtimeIdentity.systemInfo();
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
        return idempotencyService.execute(PROJECT_CREATE, rawArguments,
                arguments.optionalString(McpIdempotencyService.ARGUMENT_NAME),
                () -> projectService.create(new ProjectCreateRequest(
                        arguments.requiredString("name"),
                        arguments.requiredString("code"),
                        arguments.requiredId("ownerId"),
                        arguments.requiredString("status"),
                        arguments.optionalString("description"))));
    }

    private Object projectUpdate(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        long id = arguments.requiredId("id");
        return idempotencyService.execute(PROJECT_UPDATE, rawArguments,
                arguments.optionalString(McpIdempotencyService.ARGUMENT_NAME),
                () -> projectService.update(id, new ProjectUpdateRequest(
                        arguments.requiredString("name"),
                        arguments.requiredId("ownerId"),
                        arguments.requiredString("status"),
                        arguments.optionalString("description"),
                        arguments.requiredInteger("version"))));
    }

    private Object projectRemove(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        long id = arguments.requiredId("id");
        int version = arguments.requiredInteger("version");
        return idempotencyService.execute(PROJECT_REMOVE, rawArguments,
                arguments.optionalString(McpIdempotencyService.ARGUMENT_NAME), () -> {
                    projectService.remove(id, version);
                    return Map.of("id", id, "removed", true);
                });
    }

    private Object auditList(Map<String, Object> rawArguments) {
        McpArguments arguments = new McpArguments(rawArguments);
        return auditQueryService.pageMcp(new AuditSearchQuery(
                arguments.longValue("page", 1),
                arguments.longValue("size", 20),
                arguments.optionalString("actorName"),
                arguments.optionalString("result"),
                arguments.optionalString("traceId"),
                null,
                null,
                null,
                arguments.optionalString("toolName"),
                null,
                null));
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
        if (exception instanceof McpIdempotencyConflictException
                || exception instanceof McpIdempotencyInProgressException) {
            return exception.getMessage();
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

    private static ToolAnnotations mutating(boolean destructive, boolean idempotent) {
        return ToolAnnotations.builder()
                .readOnlyHint(false)
                .destructiveHint(destructive)
                .idempotentHint(idempotent)
                .openWorldHint(false)
                .build();
    }

    private static Map<String, Object> emptySchema() {
        return objectSchema(Map.of(), List.of());
    }

    private static Map<String, Object> idSchema(boolean includeVersion, boolean includeIdempotencyKey) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("id", idStringSchema("Project id"));
        if (includeVersion) {
            properties.put("version", integerSchema("Current optimistic-lock version", 0));
        }
        if (includeIdempotencyKey) {
            properties.put(McpIdempotencyService.ARGUMENT_NAME, idempotencyKeySchema());
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
        properties.put("traceId", traceIdSchema());
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
                "pattern", "^[A-Za-z][A-Za-z0-9_-]{1,63}$"));
        properties.put("ownerId", idStringSchema("Owner user id"));
        properties.put("status", statusSchema("Project status"));
        properties.put("description", boundedStringSchema("Optional project description", 0, 2000));
        properties.put(McpIdempotencyService.ARGUMENT_NAME, idempotencyKeySchema());
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
        properties.put(McpIdempotencyService.ARGUMENT_NAME, idempotencyKeySchema());
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

    private static Map<String, Object> traceIdSchema() {
        return Map.of(
                "type", "string",
                "description", "Exact trace identifier",
                "minLength", 8,
                "maxLength", 64,
                "pattern", "^[A-Za-z0-9._-]{8,64}$");
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

    private static Map<String, Object> idempotencyKeySchema() {
        return Map.of(
                "type", "string",
                "description", "Stable retry key for this logical write operation",
                "minLength", 16,
                "maxLength", 128,
                "pattern", "^[A-Za-z0-9._:-]+$");
    }

    private static Map<String, Object> projectOutputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("id", idStringSchema("Project id"));
        properties.put("name", boundedStringSchema("Project name", 1, 120));
        properties.put("code", stringSchema("Project code"));
        properties.put("ownerId", idStringSchema("Owner user id"));
        properties.put("ownerName", Map.of("type", List.of("string", "null")));
        properties.put("status", statusSchema("Project status"));
        properties.put("description", Map.of("type", List.of("string", "null")));
        properties.put("version", integerSchema("Optimistic-lock version", 0));
        properties.put("createdAt", Map.of(
                "type", List.of("string", "null"),
                "description", "Server-local creation timestamp"));
        properties.put("updatedAt", Map.of(
                "type", List.of("string", "null"),
                "description", "Server-local update timestamp"));
        return objectSchema(properties, List.of("id", "name", "code", "ownerId", "status", "version"));
    }

    private static Map<String, Object> removeOutputSchema() {
        return objectSchema(Map.of(
                "id", idStringSchema("Removed project id"),
                "removed", Map.of("type", "boolean")), List.of("id", "removed"));
    }

    private static Map<String, Object> toolResultSchema(Map<String, Object> successSchema) {
        Map<String, Object> errorProperties = new LinkedHashMap<>();
        errorProperties.put("code", Map.of(
                "type", "string",
                "description", "Stable machine-readable error code",
                "pattern", TOOL_ERROR_CODE_PATTERN));
        errorProperties.put("message", stringSchema("Safe error message"));
        errorProperties.put("traceId", traceIdSchema());
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("oneOf", List.of(
                successSchema,
                objectSchema(errorProperties, List.of("code", "message", "traceId"))));
        return schema;
    }
}
