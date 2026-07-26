package dev.webstarter.tooling.module;

import java.nio.file.Path;

final class ModuleTemplates {

    private ModuleTemplates() {
    }

    static String pom(WorkspaceIdentity workspace, ModuleSpec spec) {
        String mcpDependency = spec.withMcp() ? """
                        <dependency>
                            <groupId>%s</groupId>
                            <artifactId>%s-mcp</artifactId>
                            <version>${project.version}</version>
                        </dependency>
                """.formatted(workspace.groupId(), workspace.artifactId()) : "";
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0"
                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
                    <modelVersion>4.0.0</modelVersion>

                    <parent>
                        <groupId>%s</groupId>
                        <artifactId>%s</artifactId>
                        <version>%s</version>
                        <relativePath>../pom.xml</relativePath>
                    </parent>

                    <artifactId>%s-%s</artifactId>
                    <name>%s-%s</name>

                    <dependencies>
                        <dependency>
                            <groupId>%s</groupId>
                            <artifactId>%s-core</artifactId>
                            <version>${project.version}</version>
                        </dependency>
                        <dependency>
                            <groupId>%s</groupId>
                            <artifactId>%s-system</artifactId>
                            <version>${project.version}</version>
                        </dependency>
                        <dependency>
                            <groupId>com.baomidou</groupId>
                            <artifactId>mybatis-plus-spring-boot4-starter</artifactId>
                        </dependency>
                        <dependency>
                            <groupId>org.springframework</groupId>
                            <artifactId>spring-web</artifactId>
                        </dependency>
                        <dependency>
                            <groupId>org.springframework</groupId>
                            <artifactId>spring-tx</artifactId>
                        </dependency>
                        <dependency>
                            <groupId>jakarta.validation</groupId>
                            <artifactId>jakarta.validation-api</artifactId>
                        </dependency>
                %s
                        <dependency>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-test</artifactId>
                            <scope>test</scope>
                        </dependency>
                    </dependencies>
                </project>
                """.formatted(
                workspace.groupId(), workspace.artifactId(), workspace.version(),
                workspace.artifactId(), spec.name(), workspace.artifactId(), spec.name(),
                workspace.groupId(), workspace.artifactId(), workspace.groupId(), workspace.artifactId(),
                mcpDependency);
    }

    static String domain(String packageName, ModuleSpec spec) {
        return """
                package %s.domain;

                import com.baomidou.mybatisplus.annotation.IdType;
                import com.baomidou.mybatisplus.annotation.TableId;
                import com.baomidou.mybatisplus.annotation.TableLogic;
                import com.baomidou.mybatisplus.annotation.TableName;
                import com.baomidou.mybatisplus.annotation.Version;

                import java.time.LocalDateTime;

                @TableName("`%s`")
                public class %s {

                    @TableId(type = IdType.ASSIGN_ID)
                    private Long id;
                    private String code;
                    private String name;
                    private String status;
                    private String description;
                    @Version
                    private Integer version;
                    private LocalDateTime createdAt;
                    private LocalDateTime updatedAt;
                    @TableLogic
                    private Integer deleted;

                    public Long getId() { return id; }
                    public void setId(Long id) { this.id = id; }
                    public String getCode() { return code; }
                    public void setCode(String code) { this.code = code; }
                    public String getName() { return name; }
                    public void setName(String name) { this.name = name; }
                    public String getStatus() { return status; }
                    public void setStatus(String status) { this.status = status; }
                    public String getDescription() { return description; }
                    public void setDescription(String description) { this.description = description; }
                    public Integer getVersion() { return version; }
                    public void setVersion(Integer version) { this.version = version; }
                    public LocalDateTime getCreatedAt() { return createdAt; }
                    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
                    public LocalDateTime getUpdatedAt() { return updatedAt; }
                    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
                    public Integer getDeleted() { return deleted; }
                    public void setDeleted(Integer deleted) { this.deleted = deleted; }
                }
                """.formatted(packageName, spec.table(), spec.className());
    }

    static String createRequest(String packageName, ModuleSpec spec) {
        return """
                package %s.dto;

                import jakarta.validation.constraints.NotBlank;
                import jakarta.validation.constraints.Pattern;
                import jakarta.validation.constraints.Size;

                public record %sCreateRequest(
                        @NotBlank @Size(min = 2, max = 64)
                        @Pattern(regexp = "[A-Za-z][A-Za-z0-9_-]{1,63}") String code,
                        @NotBlank @Size(min = 1, max = 120) String name,
                        @NotBlank @Pattern(regexp = "ACTIVE|INACTIVE|ARCHIVED") String status,
                        @Size(max = 2000) String description) {
                }
                """.formatted(packageName, spec.className());
    }

    static String updateRequest(String packageName, ModuleSpec spec) {
        return """
                package %s.dto;

                import jakarta.validation.constraints.Min;
                import jakarta.validation.constraints.NotBlank;
                import jakarta.validation.constraints.NotNull;
                import jakarta.validation.constraints.Pattern;
                import jakarta.validation.constraints.Size;

                public record %sUpdateRequest(
                        @NotBlank @Size(min = 2, max = 64)
                        @Pattern(regexp = "[A-Za-z][A-Za-z0-9_-]{1,63}") String code,
                        @NotBlank @Size(min = 1, max = 120) String name,
                        @NotBlank @Pattern(regexp = "ACTIVE|INACTIVE|ARCHIVED") String status,
                        @Size(max = 2000) String description,
                        @NotNull @Min(0) Integer version) {
                }
                """.formatted(packageName, spec.className());
    }

    static String response(String packageName, ModuleSpec spec) {
        return """
                package %s.dto;

                import java.time.LocalDateTime;

                public record %sResponse(
                        Long id,
                        String code,
                        String name,
                        String status,
                        String description,
                        Integer version,
                        LocalDateTime createdAt,
                        LocalDateTime updatedAt) {
                }
                """.formatted(packageName, spec.className());
    }

    static String mapper(String packageName, ModuleSpec spec) {
        return """
                package %s.persistence.mapper;

                import com.baomidou.mybatisplus.core.mapper.BaseMapper;
                import %s.domain.%s;
                import org.apache.ibatis.annotations.Param;
                import org.apache.ibatis.annotations.Update;

                import java.time.LocalDateTime;

                public interface %sMapper extends BaseMapper<%s> {

                    @Update(\"\"\"
                            UPDATE `%s`
                            SET deleted = 1, updated_at = #{updatedAt}, version = version + 1
                            WHERE id = #{id} AND version = #{version} AND deleted = 0
                            \"\"\")
                    int logicalDeleteWithVersion(
                            @Param("id") Long id,
                            @Param("version") Integer version,
                            @Param("updatedAt") LocalDateTime updatedAt);
                }
                """.formatted(packageName, packageName, spec.className(), spec.className(), spec.className(), spec.table());
    }

    static String persistenceConfiguration(String packageName, ModuleSpec spec) {
        return """
                package %s.config;

                import org.mybatis.spring.annotation.MapperScan;
                import org.springframework.context.annotation.Configuration;

                @Configuration(proxyBeanMethods = false)
                @MapperScan("%s.persistence.mapper")
                public class %sPersistenceConfiguration {
                }
                """.formatted(packageName, packageName, spec.className());
    }

    static String permissions(String packageName, ModuleSpec spec) {
        return """
                package %s.service;

                public final class %sPermissions {
                    public static final String LIST = "%s:list";
                    public static final String CREATE = "%s:create";
                    public static final String UPDATE = "%s:update";
                    public static final String REMOVE = "%s:remove";

                    private %sPermissions() {
                    }
                }
                """.formatted(packageName, spec.className(), spec.name(), spec.name(), spec.name(), spec.name(), spec.className());
    }

    static String service(String packageName, ModuleSpec spec) {
        return """
                package %s.service;

                import dev.webstarter.core.api.PageResult;
                import %s.dto.%sCreateRequest;
                import %s.dto.%sResponse;
                import %s.dto.%sUpdateRequest;
                import jakarta.validation.Valid;

                public interface %sService {
                    PageResult<%sResponse> page(long page, long size, String keyword, String status);
                    %sResponse get(Long id);
                    %sResponse create(@Valid %sCreateRequest request);
                    %sResponse update(Long id, @Valid %sUpdateRequest request);
                    void remove(Long id, Integer version);
                }
                """.formatted(
                packageName,
                packageName, spec.className(), packageName, spec.className(), packageName, spec.className(),
                spec.className(), spec.className(), spec.className(), spec.className(), spec.className(),
                spec.className(), spec.className());
    }

    static String serviceImplementation(String packageName, ModuleSpec spec) {
        String template = """
                package %s.service.impl;

                import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
                import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
                import dev.webstarter.core.api.PageQuery;
                import dev.webstarter.core.api.PageResult;
                import dev.webstarter.core.exception.ConflictException;
                import dev.webstarter.core.exception.NotFoundException;
                import dev.webstarter.core.security.CallerContext;
                import dev.webstarter.core.security.CurrentCaller;
                import dev.webstarter.core.security.PermissionService;
                import dev.webstarter.core.security.SecuredOperation;
                import dev.webstarter.core.trace.TraceContext;
                import dev.webstarter.system.audit.AuditLogRecorder;
                import dev.webstarter.system.audit.OperationAuditEvent;
                import %s.domain.%s;
                import %s.dto.%sCreateRequest;
                import %s.dto.%sResponse;
                import %s.dto.%sUpdateRequest;
                import %s.persistence.mapper.%sMapper;
                import %s.service.%sPermissions;
                import %s.service.%sService;
                import jakarta.validation.Valid;
                import org.springframework.stereotype.Service;
                import org.springframework.transaction.annotation.Transactional;
                import org.springframework.validation.annotation.Validated;

                import java.time.LocalDateTime;
                import java.util.Locale;

                @Service
                @Validated
                public class %sServiceImpl extends SecuredOperation implements %sService {

                    private final %sMapper mapper;
                    private final AuditLogRecorder auditLogRecorder;

                    public %sServiceImpl(
                            CallerContext callerContext,
                            PermissionService permissionService,
                            %sMapper mapper,
                            AuditLogRecorder auditLogRecorder) {
                        super(callerContext, permissionService);
                        this.mapper = mapper;
                        this.auditLogRecorder = auditLogRecorder;
                    }

                    @Override
                    public PageResult<%sResponse> page(long page, long size, String keyword, String status) {
                        requirePermission(%sPermissions.LIST);
                        PageQuery query = new PageQuery(page, size);
                        LambdaQueryWrapper<%s> wrapper = new LambdaQueryWrapper<%s>()
                                .eq(hasText(status), %s::getStatus, status)
                                .and(hasText(keyword), item -> item.like(%s::getName, keyword)
                                        .or().like(%s::getCode, keyword))
                                .orderByDesc(%s::getId);
                        Page<%s> result = mapper.selectPage(new Page<>(query.page(), query.size()), wrapper);
                        return PageResult.of(result.getRecords().stream().map(this::toResponse).toList(),
                                result.getTotal(), query.page(), query.size());
                    }

                    @Override
                    public %sResponse get(Long id) {
                        requirePermission(%sPermissions.LIST);
                        return toResponse(requireEntity(id));
                    }

                    @Override
                    @Transactional
                    public %sResponse create(@Valid %sCreateRequest request) {
                        long started = System.nanoTime();
                        CurrentCaller caller = requirePermission(%sPermissions.CREATE);
                        String code = normalizeCode(request.code());
                        ensureUniqueCode(code, null);
                        LocalDateTime now = LocalDateTime.now();
                        %s entity = new %s();
                        entity.setCode(code);
                        entity.setName(request.name().trim());
                        entity.setStatus(request.status());
                        entity.setDescription(trimToNull(request.description()));
                        entity.setVersion(0);
                        entity.setCreatedAt(now);
                        entity.setUpdatedAt(now);
                        entity.setDeleted(0);
                        mapper.insert(entity);
                        record(caller, "CREATE", entity.getId(), started);
                        return toResponse(entity);
                    }

                    @Override
                    @Transactional
                    public %sResponse update(Long id, @Valid %sUpdateRequest request) {
                        long started = System.nanoTime();
                        CurrentCaller caller = requirePermission(%sPermissions.UPDATE);
                        %s entity = requireEntity(id);
                        if (!request.version().equals(entity.getVersion())) {
                            throw new ConflictException("%s was changed by another request");
                        }
                        String code = normalizeCode(request.code());
                        ensureUniqueCode(code, id);
                        entity.setCode(code);
                        entity.setName(request.name().trim());
                        entity.setStatus(request.status());
                        entity.setDescription(trimToNull(request.description()));
                        entity.setUpdatedAt(LocalDateTime.now());
                        if (mapper.updateById(entity) == 0) {
                            throw new ConflictException("%s was changed by another request");
                        }
                        record(caller, "UPDATE", id, started);
                        return toResponse(requireEntity(id));
                    }

                    @Override
                    @Transactional
                    public void remove(Long id, Integer version) {
                        long started = System.nanoTime();
                        CurrentCaller caller = requirePermission(%sPermissions.REMOVE);
                        if (version == null) {
                            throw new IllegalArgumentException("version is required");
                        }
                        requireEntity(id);
                        if (mapper.logicalDeleteWithVersion(id, version, LocalDateTime.now()) == 0) {
                            throw new ConflictException("%s was changed by another request");
                        }
                        record(caller, "REMOVE", id, started);
                    }

                    private %s requireEntity(Long id) {
                        %s entity = id == null ? null : mapper.selectById(id);
                        if (entity == null) {
                            throw new NotFoundException("%s not found");
                        }
                        return entity;
                    }

                    private void ensureUniqueCode(String code, Long excludedId) {
                        LambdaQueryWrapper<%s> query = new LambdaQueryWrapper<%s>()
                                .eq(%s::getCode, code)
                                .ne(excludedId != null, %s::getId, excludedId);
                        if (mapper.selectCount(query) > 0) {
                            throw new ConflictException("%s code already exists");
                        }
                    }

                    private void record(CurrentCaller caller, String action, Long id, long started) {
                        auditLogRecorder.recordOperation(new OperationAuditEvent(
                                caller.callerType().name(), caller.subjectId(), caller.displayName(), "%s", action,
                                "%s", String.valueOf(id), "SUCCESS", null, null, null,
                                (System.nanoTime() - started) / 1_000_000, null,
                                caller.traceId() == null ? TraceContext.traceId() : caller.traceId(), LocalDateTime.now()));
                    }

                    private %sResponse toResponse(%s entity) {
                        return new %sResponse(entity.getId(), entity.getCode(), entity.getName(), entity.getStatus(),
                                entity.getDescription(), entity.getVersion(), entity.getCreatedAt(), entity.getUpdatedAt());
                    }

                    private static String normalizeCode(String value) { return value.trim().toUpperCase(Locale.ROOT); }
                    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
                    private static String trimToNull(String value) { return hasText(value) ? value.trim() : null; }
                }
                """;
        String className = spec.className();
        java.util.List<Object> arguments = new java.util.ArrayList<>(57);
        arguments.add(packageName);
        for (int index = 0; index < 7; index++) {
            arguments.add(packageName);
            arguments.add(className);
        }
        for (int index = 0; index < 37; index++) {
            arguments.add(className);
        }
        arguments.add(spec.name());
        arguments.add(spec.name());
        arguments.add(className);
        arguments.add(className);
        arguments.add(className);
        return template.formatted(arguments.toArray());
    }

    static String controller(String packageName, ModuleSpec spec) {
        return """
                package %s.web;

                import dev.webstarter.core.api.ApiResponse;
                import dev.webstarter.core.api.PageResult;
                import %s.dto.%sCreateRequest;
                import %s.dto.%sResponse;
                import %s.dto.%sUpdateRequest;
                import %s.service.%sService;
                import jakarta.validation.Valid;
                import org.springframework.web.bind.annotation.DeleteMapping;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.PutMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RequestParam;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                @RequestMapping("/api/%s")
                public class %sController {
                    private final %sService service;

                    public %sController(%sService service) {
                        this.service = service;
                    }

                    @GetMapping
                    public ApiResponse<PageResult<%sResponse>> page(
                            @RequestParam(defaultValue = "1") long page,
                            @RequestParam(defaultValue = "20") long size,
                            @RequestParam(required = false) String keyword,
                            @RequestParam(required = false) String status) {
                        return ApiResponse.success(service.page(page, size, keyword, status));
                    }

                    @GetMapping("/{id}")
                    public ApiResponse<%sResponse> get(@PathVariable Long id) {
                        return ApiResponse.success(service.get(id));
                    }

                    @PostMapping
                    public ApiResponse<%sResponse> create(@Valid @RequestBody %sCreateRequest request) {
                        return ApiResponse.success(service.create(request));
                    }

                    @PutMapping("/{id}")
                    public ApiResponse<%sResponse> update(
                            @PathVariable Long id,
                            @Valid @RequestBody %sUpdateRequest request) {
                        return ApiResponse.success(service.update(id, request));
                    }

                    @DeleteMapping("/{id}")
                    public ApiResponse<Void> remove(@PathVariable Long id, @RequestParam Integer version) {
                        service.remove(id, version);
                        return ApiResponse.success();
                    }
                }
                """.formatted(
                packageName,
                packageName, spec.className(), packageName, spec.className(), packageName, spec.className(),
                packageName, spec.className(), spec.plural(), spec.className(), spec.className(),
                spec.className(), spec.className(), spec.className(), spec.className(), spec.className(),
                spec.className(), spec.className(), spec.className(), spec.className());
    }

    static String operationAuditRouteContributor(String packageName, ModuleSpec spec) {
        return """
                package %1$s.audit;

                import java.util.List;

                import dev.webstarter.system.audit.OperationAuditRoute;
                import dev.webstarter.system.audit.OperationAuditRouteContributor;
                import org.springframework.stereotype.Component;

                /** REST failures are filter-audited; successful writes are audited by the shared Service. */
                @Component
                public final class %2$sOperationAuditRouteContributor
                        implements OperationAuditRouteContributor {

                    private static final List<OperationAuditRoute> ROUTES = List.of(
                            OperationAuditRoute.serviceOwned("/api/%3$s", "%4$s", "%4$s"));

                    @Override
                    public List<OperationAuditRoute> operationAuditRoutes() {
                        return ROUTES;
                    }
                }
                """.formatted(packageName, spec.className(), spec.plural(), spec.name());
    }

    static String operationAuditRouteContributorTest(String packageName, ModuleSpec spec) {
        return """
                package %1$s.audit;

                import static org.junit.jupiter.api.Assertions.assertEquals;
                import static org.junit.jupiter.api.Assertions.assertSame;
                import static org.junit.jupiter.api.Assertions.assertTrue;

                import java.util.List;

                import dev.webstarter.system.audit.OperationAuditRoute;
                import dev.webstarter.system.audit.OperationAuditRouteRegistry;
                import org.junit.jupiter.api.Test;

                class %2$sOperationAuditRouteContributorTest {

                    @Test
                    void contributesTheServiceAuditedRestBoundaryWithoutDependingOnAdmin() {
                        var contributor = new %2$sOperationAuditRouteContributor();
                        OperationAuditRoute route = contributor.operationAuditRoutes().getFirst();

                        assertEquals("/api/%3$s", route.pathPrefix());
                        assertEquals("%4$s", route.module());
                        assertEquals("%4$s", route.resourceType());
                        assertTrue(route.successAuditedByService());

                        var registry = new OperationAuditRouteRegistry(List.of(contributor));
                        assertSame(route, registry.match("/api/%3$s/9007199254740993").orElseThrow());
                        assertTrue(registry.match("/api/%3$s-archive").isEmpty());
                    }
                }
                """.formatted(packageName, spec.className(), spec.plural(), spec.name());
    }

    static String serviceImplementationTest(String packageName, ModuleSpec spec) {
        return """
                package %1$s.service.impl;

                import static org.junit.jupiter.api.Assertions.assertEquals;
                import static org.junit.jupiter.api.Assertions.assertNotNull;
                import static org.junit.jupiter.api.Assertions.assertNull;
                import static org.junit.jupiter.api.Assertions.assertThrows;
                import static org.junit.jupiter.api.Assertions.assertTrue;

                import java.lang.reflect.Proxy;
                import java.lang.reflect.Method;
                import java.util.Optional;
                import java.util.Set;
                import java.util.concurrent.atomic.AtomicInteger;
                import java.util.concurrent.atomic.AtomicReference;

                import dev.webstarter.core.exception.PermissionDeniedException;
                import dev.webstarter.core.security.CallerContext;
                import dev.webstarter.core.security.CallerType;
                import dev.webstarter.core.security.CurrentCaller;
                import dev.webstarter.core.security.PermissionService;
                import dev.webstarter.system.audit.AuditLogRecorder;
                import dev.webstarter.system.audit.LoginAuditEvent;
                import dev.webstarter.system.audit.McpCallAuditEvent;
                import dev.webstarter.system.audit.OperationAuditEvent;
                import %1$s.domain.%2$s;
                import %1$s.dto.%2$sCreateRequest;
                import %1$s.dto.%2$sUpdateRequest;
                import %1$s.persistence.mapper.%2$sMapper;
                import %1$s.service.%2$sService;
                import jakarta.validation.Valid;
                import org.junit.jupiter.api.Test;

                class %2$sServiceImplTest {

                    @Test
                    void createRequiresPermissionNormalizesCodeAndWritesAudit() {
                        CurrentCaller caller = caller(Set.of("%3$s:create"));
                        CallerContext callerContext = () -> Optional.of(caller);
                        PermissionService permissionService = (current, permission) ->
                                current.permissions().contains(permission);
                        AtomicInteger mapperCalls = new AtomicInteger();
                        AtomicReference<%2$s> inserted = new AtomicReference<>();
                        AtomicReference<OperationAuditEvent> audit = new AtomicReference<>();
                        %2$sMapper mapper = mapper(mapperCalls, inserted);
                        AuditLogRecorder auditLogRecorder = auditRecorder(audit);
                        %2$sServiceImpl service = new %2$sServiceImpl(
                                callerContext, permissionService, mapper, auditLogRecorder);

                        var response = service.create(new %2$sCreateRequest(
                                "%3$s_one", " Generated record ", "ACTIVE", " details "));

                        assertEquals(10L, response.id());
                        assertEquals("%4$s_ONE", response.code());
                        assertEquals("Generated record", response.name());
                        assertEquals("details", response.description());
                        assertEquals(2, mapperCalls.get());
                        assertNotNull(inserted.get());
                        assertNotNull(audit.get());
                        assertEquals("%3$s", audit.get().module());
                        assertEquals("CREATE", audit.get().action());
                        assertEquals("10", audit.get().resourceId());
                        assertEquals("trace-generated", audit.get().traceId());
                    }

                    @Test
                    void createIsDeniedBeforePersistenceWhenPermissionIsMissing() {
                        CurrentCaller caller = caller(Set.of());
                        CallerContext callerContext = () -> Optional.of(caller);
                        PermissionService permissionService = (current, permission) ->
                                current.permissions().contains(permission);
                        AtomicInteger mapperCalls = new AtomicInteger();
                        AtomicReference<%2$s> inserted = new AtomicReference<>();
                        AtomicReference<OperationAuditEvent> audit = new AtomicReference<>();
                        %2$sMapper mapper = mapper(mapperCalls, inserted);
                        AuditLogRecorder auditLogRecorder = auditRecorder(audit);
                        %2$sServiceImpl service = new %2$sServiceImpl(
                                callerContext, permissionService, mapper, auditLogRecorder);

                        assertThrows(PermissionDeniedException.class, () -> service.create(new %2$sCreateRequest(
                                "%3$s_one", "Generated record", "ACTIVE", null)));
                        assertEquals(0, mapperCalls.get());
                        assertNull(inserted.get());
                        assertNull(audit.get());
                    }

                    @Test
                    void interfaceAndImplementationExposeMatchingValidConstraints() throws Exception {
                        assertValidContract(
                                %2$sService.class.getMethod("create", %2$sCreateRequest.class),
                                %2$sServiceImpl.class.getMethod("create", %2$sCreateRequest.class),
                                0);
                        assertValidContract(
                                %2$sService.class.getMethod("update", Long.class, %2$sUpdateRequest.class),
                                %2$sServiceImpl.class.getMethod("update", Long.class, %2$sUpdateRequest.class),
                                1);
                    }

                    private static void assertValidContract(
                            Method serviceMethod,
                            Method implementationMethod,
                            int requestParameter) {
                        boolean serviceValid = hasValid(serviceMethod, requestParameter);
                        boolean implementationValid = hasValid(implementationMethod, requestParameter);
                        assertTrue(serviceValid, "Service request parameter must declare @Valid");
                        assertEquals(serviceValid, implementationValid,
                                "Service and implementation validation constraints must match");
                    }

                    private static boolean hasValid(Method method, int parameter) {
                        for (var annotation : method.getParameterAnnotations()[parameter]) {
                            if (annotation.annotationType().equals(Valid.class)) {
                                return true;
                            }
                        }
                        return false;
                    }

                    private static %2$sMapper mapper(
                            AtomicInteger calls,
                            AtomicReference<%2$s> inserted) {
                        return (%2$sMapper) Proxy.newProxyInstance(
                                %2$sMapper.class.getClassLoader(),
                                new Class<?>[] {%2$sMapper.class},
                                (proxy, method, arguments) -> {
                                    calls.incrementAndGet();
                                    if ("selectCount".equals(method.getName())) {
                                        return 0L;
                                    }
                                    if ("insert".equals(method.getName())) {
                                        %2$s entity = (%2$s) arguments[0];
                                        entity.setId(10L);
                                        inserted.set(entity);
                                        return 1;
                                    }
                                    throw new AssertionError("Unexpected mapper call: " + method.getName());
                                });
                    }

                    private static AuditLogRecorder auditRecorder(
                            AtomicReference<OperationAuditEvent> operation) {
                        return new AuditLogRecorder() {
                            @Override
                            public void recordLogin(LoginAuditEvent event) {
                            }

                            @Override
                            public void recordOperation(OperationAuditEvent event) {
                                operation.set(event);
                            }

                            @Override
                            public void recordMcpCall(McpCallAuditEvent event) {
                            }
                        };
                    }

                    private static CurrentCaller caller(Set<String> permissions) {
                        return new CurrentCaller(
                                CallerType.USER,
                                "1",
                                "generated-test",
                                "Generated Test User",
                                null,
                                null,
                                Set.of(),
                                permissions,
                                Set.of(),
                                "trace-generated");
                    }
                }
                """.formatted(
                packageName,
                spec.className(),
                spec.name(),
                spec.name().toUpperCase(java.util.Locale.ROOT));
    }

    static String controllerTest(String packageName, ModuleSpec spec) {
        return """
                package %1$s.web;

                import static org.junit.jupiter.api.Assertions.assertArrayEquals;
                import static org.junit.jupiter.api.Assertions.assertEquals;
                import static org.junit.jupiter.api.Assertions.assertNull;
                import static org.junit.jupiter.api.Assertions.assertSame;

                import java.lang.reflect.InvocationHandler;
                import java.lang.reflect.Proxy;
                import java.time.LocalDateTime;
                import java.util.concurrent.atomic.AtomicReference;

                import dev.webstarter.core.api.ApiResponse;
                import %1$s.dto.%2$sCreateRequest;
                import %1$s.dto.%2$sResponse;
                import %1$s.service.%2$sService;
                import org.junit.jupiter.api.Test;

                class %2$sControllerTest {

                    @Test
                    void createReturnsTheSharedServiceResult() {
                        %2$sCreateRequest request = new %2$sCreateRequest(
                                "%3$s_one", "Generated record", "ACTIVE", null);
                        LocalDateTime now = LocalDateTime.now();
                        %2$sResponse expected = new %2$sResponse(
                                10L, "%4$s_ONE", "Generated record", "ACTIVE", null, 0, now, now);
                        AtomicReference<%2$sCreateRequest> delegated = new AtomicReference<>();
                        %2$sService service = service((proxy, method, arguments) -> {
                            if (!"create".equals(method.getName())) {
                                throw new AssertionError("Unexpected service call: " + method.getName());
                            }
                            delegated.set((%2$sCreateRequest) arguments[0]);
                            return expected;
                        });
                        %2$sController controller = new %2$sController(service);

                        ApiResponse<%2$sResponse> response = controller.create(request);

                        assertEquals(0, response.code());
                        assertSame(expected, response.data());
                        assertSame(request, delegated.get());
                    }

                    @Test
                    void removeDelegatesTheOptimisticLockVersion() {
                        AtomicReference<Object[]> delegated = new AtomicReference<>();
                        %2$sService service = service((proxy, method, arguments) -> {
                            if (!"remove".equals(method.getName())) {
                                throw new AssertionError("Unexpected service call: " + method.getName());
                            }
                            delegated.set(arguments);
                            return null;
                        });
                        %2$sController controller = new %2$sController(service);

                        ApiResponse<Void> response = controller.remove(10L, 3);

                        assertEquals(0, response.code());
                        assertNull(response.data());
                        assertArrayEquals(new Object[] {10L, 3}, delegated.get());
                    }

                    private static %2$sService service(InvocationHandler handler) {
                        return (%2$sService) Proxy.newProxyInstance(
                                %2$sService.class.getClassLoader(),
                                new Class<?>[] {%2$sService.class},
                                handler);
                    }
                }
                """.formatted(
                packageName,
                spec.className(),
                spec.name(),
                spec.name().toUpperCase(java.util.Locale.ROOT));
    }

    static String migration(ModuleSpec spec) {
        String label = sqlLiteral(spec.label());
        return """
                CREATE TABLE `%s` (
                    id BIGINT NOT NULL,
                    code VARCHAR(64) NOT NULL,
                    name VARCHAR(120) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    description VARCHAR(2000) NULL,
                    version INT NOT NULL DEFAULT 0,
                    created_at DATETIME(6) NOT NULL,
                    updated_at DATETIME(6) NOT NULL,
                    deleted TINYINT NOT NULL DEFAULT 0,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_%s_code (code),
                    KEY idx_%s_status (status, deleted, id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

                INSERT INTO sys_permission
                    (id, code, name, type, description, status, created_at, updated_at, deleted)
                VALUES
                    (%d, '%s:list', '查看%s', 'API', '查询%s列表与详情', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
                    (%d, '%s:create', '创建%s', 'API', '创建%s', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
                    (%d, '%s:update', '更新%s', 'API', '更新%s', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
                    (%d, '%s:remove', '删除%s', 'API', '逻辑删除%s', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0);

                INSERT INTO sys_role_permission (role_id, permission_id)
                SELECT 1, id FROM sys_permission WHERE code LIKE '%s:%%' AND deleted = 0;

                INSERT INTO sys_menu
                    (id, parent_id, name, path, component, icon, sort_order, visible, status,
                     permission_code, created_at, updated_at, deleted)
                VALUES
                    (%d, NULL, '%s管理', '%s', '%sView', 'Files', 60, TRUE, 'ENABLED',
                     '%s:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0);

                INSERT INTO sys_role_menu (role_id, menu_id) VALUES (1, %d);
                """.formatted(
                spec.table(), spec.table(), spec.table(),
                spec.permissionIdBase(), spec.name(), label, label,
                spec.permissionIdBase() + 1, spec.name(), label, label,
                spec.permissionIdBase() + 2, spec.name(), label, label,
                spec.permissionIdBase() + 3, spec.name(), label, label,
                spec.name(), spec.menuId(), label, spec.route(), spec.className(), spec.name(), spec.menuId());
    }

    static String mcpPlan(String packageName, ModuleSpec spec) {
        return """
                # Explicit MCP generation request for module %s.
                # Registration is statically compiled through the generated Spring contributor.
                module=%s
                service=%s.service.%sService
                tools=%s.list,%s.get,%s.create,%s.update,%s.remove
                permissions=%s:list,%s:create,%s:update,%s:remove
                idFormat=opaque-decimal-string
                registration=compiled-spring-contributor
                idempotency=required-for-write-tools
                runtimeTest=%s.mcp.%sMcpRuntimeIT
                """.formatted(
                spec.name(), spec.name(), packageName, spec.className(),
                spec.name(), spec.name(), spec.name(), spec.name(), spec.name(),
                spec.name(), spec.name(), spec.name(), spec.name(), packageName, spec.className());
    }

    static String moduleAcceptancePlan(
            WorkspaceIdentity workspace,
            ModuleSpec spec,
            Path migration,
            Path browserRuntimeTest) {
        String base = """
                # Static metadata for isolated generated-module acceptance. Values are never commands.
                schemaVersion=1
                module=%s
                artifactId=%s-%s
                migration=%s
                route=%s
                plural=%s
                apiPath=/api/%s
                resourceType=%s
                permissions=%s:list,%s:create,%s:update,%s:remove
                browserTest=%s
                browserTitle=%s
                withMcp=%s
                """.formatted(
                spec.name(), workspace.artifactId(), spec.name(), normalized(migration),
                spec.route(), spec.plural(), spec.plural(), spec.name(),
                spec.name(), spec.name(), spec.name(), spec.name(),
                normalized(browserRuntimeTest), browserRuntimeTitle(spec), spec.withMcp());
        if (!spec.withMcp()) {
            return base;
        }
        return base + """
                mcpRuntimeTest=%s.%s.mcp.%sMcpRuntimeIT
                mcpTools=%s.list,%s.get,%s.create,%s.update,%s.remove
                """.formatted(
                workspace.groupId(), spec.name(), spec.className(),
                spec.name(), spec.name(), spec.name(), spec.name(), spec.name());
    }

    static String browserRuntimeTitle(ModuleSpec spec) {
        return "generated " + spec.name()
                + " module closes browser CRUD conflict authorization and audit loop";
    }

    static String browserRuntimeTest(ModuleSpec spec) {
        return """
                import { readFileSync } from 'node:fs'
                import { test, expect, type Page } from '@playwright/test'

                interface RuntimeManifest {
                  schemaVersion: number
                  privateBaseUrl: string
                  tokenFiles: { accountUser: string }
                }

                interface AccountCredential { username: string; password: string }
                interface RecordData {
                  id: string
                  code: string
                  name: string
                  status: 'ACTIVE' | 'INACTIVE' | 'ARCHIVED'
                  description?: string
                  version: number
                }
                interface OperationAudit {
                  action: string
                  module: string
                  resourceType: string
                  resourceId: string
                  result: string
                  traceId: string
                }

                function required(name: string): string {
                  const value = process.env[name]?.trim()
                  if (!value) throw new Error(`${name} is required`)
                  return value
                }

                function manifest(): RuntimeManifest {
                  const value = JSON.parse(
                    readFileSync(required('WEB_STARTER_ACCEPTANCE_MANIFEST'), 'utf8'),
                  ) as RuntimeManifest
                  if (value.schemaVersion !== 1 || !value.privateBaseUrl) {
                    throw new Error('Generated module runtime manifest is invalid')
                  }
                  return value
                }

                async function login(
                  page: Page,
                  baseUrl: string,
                  username: string,
                  password: string,
                  destination: string,
                ): Promise<void> {
                  const url = new URL('/login', baseUrl)
                  url.searchParams.set('redirect', destination)
                  await page.goto(url.toString())
                  await page.getByPlaceholder('请输入用户名').fill(username)
                  await page.getByPlaceholder('请输入密码').fill(password)
                  await page.getByRole('button', { name: '登录', exact: true }).click()
                  await expect(page).toHaveURL((current) => current.pathname === destination)
                }

                test.describe.configure({ mode: 'serial' })

                test('%1$s', async ({ page, browser }) => {
                  const runtime = manifest()
                  const adminUsername = required('WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME')
                  const adminPassword = required('WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD')
                  const apiPath = '/api/%4$s'
                  await login(page, runtime.privateBaseUrl, adminUsername, adminPassword, '%2$s')
                  await expect(page.getByRole('heading', { name: '%3$s管理', exact: true })).toBeVisible()

                  const suffix = Date.now().toString(36).toUpperCase()
                  const code = `BROWSER_${suffix}`
                  const createResponsePromise = page.waitForResponse((response) =>
                    response.request().method() === 'POST'
                      && new URL(response.url()).pathname === apiPath,
                  )
                  await page.getByRole('button', { name: '新建%3$s', exact: true }).click()
                  const createDialog = page.getByRole('dialog', { name: '新建%3$s' })
                  await createDialog.getByRole('textbox', { name: '编码' }).fill(code)
                  await createDialog.getByRole('textbox', { name: '名称' }).fill('生成模块浏览器验收')
                  await createDialog.getByRole('button', { name: '保存', exact: true }).click()
                  const createResponse = await createResponsePromise
                  expect(createResponse.status()).toBe(200)
                  const createEnvelope = await createResponse.json() as {
                    data?: RecordData
                    traceId?: string
                  }
                  const created = createEnvelope.data
                  if (!created?.id || !createEnvelope.traceId) throw new Error('Create response is incomplete')
                  await expect(page.getByText('保存成功')).toBeVisible()

                  let row = page.getByRole('row').filter({ hasText: code })
                  await expect(row).toHaveCount(1)
                  const getResponsePromise = page.waitForResponse((response) =>
                    response.request().method() === 'GET'
                      && new URL(response.url()).pathname === `${apiPath}/${created.id}`,
                  )
                  await row.getByRole('button', { name: '编辑', exact: true }).click()
                  const getResponse = await getResponsePromise
                  const getEnvelope = await getResponse.json() as { data?: RecordData }
                  const loaded = getEnvelope.data
                  if (!loaded) throw new Error('Edit did not load the generated record')
                  const editDialog = page.getByRole('dialog', { name: '编辑%3$s' })
                  await expect(editDialog).toBeVisible()

                  const directUpdate = await page.evaluate(async ({ path, record }) => {
                    const csrf = await fetch('/api/auth/csrf')
                    const csrfEnvelope = await csrf.json() as {
                      data?: { headerName?: string; token?: string }
                    }
                    const token = csrfEnvelope.data?.token
                    if (!token) throw new Error('CSRF token missing')
                    const response = await fetch(path, {
                      method: 'PUT',
                      headers: {
                        'Content-Type': 'application/json',
                        [csrfEnvelope.data?.headerName || 'X-XSRF-TOKEN']: token,
                      },
                      body: JSON.stringify({
                        code: record.code,
                        name: '生成模块并发更新',
                        status: 'INACTIVE',
                        description: record.description,
                        version: record.version,
                      }),
                    })
                    return { status: response.status, body: await response.json() }
                  }, { path: `${apiPath}/${created.id}`, record: loaded })
                  expect(directUpdate.status).toBe(200)

                  await editDialog.getByRole('textbox', { name: '名称' }).fill('应触发版本冲突')
                  const conflictResponsePromise = page.waitForResponse((response) =>
                    response.request().method() === 'PUT'
                      && new URL(response.url()).pathname === `${apiPath}/${created.id}`,
                  )
                  await editDialog.getByRole('button', { name: '保存', exact: true }).click()
                  const conflictResponse = await conflictResponsePromise
                  expect(conflictResponse.status()).toBe(409)
                  const conflictEnvelope = await conflictResponse.json() as { traceId?: string }
                  if (!conflictEnvelope.traceId) throw new Error('Conflict response has no trace ID')
                  await expect(editDialog.getByText('数据已发生变化', { exact: true })).toBeVisible()
                  await editDialog.getByRole('button', { name: '取消', exact: true }).click()

                  await page.reload()
                  row = page.getByRole('row').filter({ hasText: code })
                  await expect(row.getByText('生成模块并发更新', { exact: true })).toBeVisible()
                  const deleteResponsePromise = page.waitForResponse((response) =>
                    response.request().method() === 'DELETE'
                      && new URL(response.url()).pathname === `${apiPath}/${created.id}`,
                  )
                  await row.getByRole('button', { name: '删除', exact: true }).click()
                  const confirmation = page.getByRole('dialog', { name: '删除确认' })
                  await confirmation.getByRole('button', { name: '确定', exact: true }).click()
                  const deleteResponse = await deleteResponsePromise
                  expect(deleteResponse.status()).toBe(200)
                  const deleteEnvelope = await deleteResponse.json() as { traceId?: string }
                  if (!deleteEnvelope.traceId) throw new Error('Delete response has no trace ID')
                  await expect(page.getByText('删除成功')).toBeVisible()
                  await expect(page.getByRole('row').filter({ hasText: code })).toHaveCount(0)

                  const auditUrl = new URL('/api/logs/operation', runtime.privateBaseUrl)
                  auditUrl.searchParams.set('module', '%5$s')
                  auditUrl.searchParams.set('resourceType', '%5$s')
                  auditUrl.searchParams.set('resourceId', created.id)
                  auditUrl.searchParams.set('size', '20')
                  const auditResponse = await page.request.get(auditUrl.toString())
                  expect(auditResponse.status()).toBe(200)
                  const auditEnvelope = await auditResponse.json() as {
                    data?: { records?: OperationAudit[] }
                  }
                  const records = auditEnvelope.data?.records || []
                  for (const action of ['CREATE', 'UPDATE', 'REMOVE']) {
                    expect(records.some((entry) => entry.action === action
                      && entry.result === 'SUCCESS'
                      && entry.module === '%5$s'
                      && entry.resourceType === '%5$s'
                      && entry.resourceId === created.id)).toBe(true)
                  }
                  expect(records.some((entry) => entry.action === 'UPDATE'
                    && entry.result === 'FAILURE'
                    && entry.traceId === conflictEnvelope.traceId)).toBe(true)
                  const encodedAudit = JSON.stringify(auditEnvelope)
                  const forbiddenCredentialField =
                    /"(?:password|authorization|cookie|tokenHash|accessToken|refreshToken|clientSecret)"\\s*:/i
                  if (encodedAudit.includes(adminPassword) || forbiddenCredentialField.test(encodedAudit)) {
                    throw new Error('Audit response contains forbidden credential material')
                  }

                  const account = JSON.parse(
                    readFileSync(runtime.tokenFiles.accountUser, 'utf8'),
                  ) as AccountCredential
                  const restricted = await browser.newContext()
                  try {
                    const restrictedPage = await restricted.newPage()
                    await login(
                      restrictedPage,
                      runtime.privateBaseUrl,
                      account.username,
                      account.password,
                      '/security/account',
                    )
                    const forbidden = await restrictedPage.evaluate(async (path) =>
                      (await fetch(path)).status, apiPath)
                    expect(forbidden).toBe(403)
                  } finally {
                    await restricted.close()
                  }
                })
                """.formatted(
                browserRuntimeTitle(spec), spec.route(), spec.label(), spec.plural(), spec.name());
    }

    static String mcpContributor(String packageName, ModuleSpec spec) {
        return """
                package %1$s.mcp;

                import java.util.LinkedHashMap;
                import java.util.List;
                import java.util.Map;

                import dev.webstarter.mcp.governance.McpToolRisk;
                import dev.webstarter.mcp.service.McpArguments;
                import dev.webstarter.mcp.service.McpToolContribution;
                import dev.webstarter.mcp.service.McpToolContributor;
                import dev.webstarter.mcp.service.McpToolSupport;
                import %1$s.dto.%2$sCreateRequest;
                import %1$s.dto.%2$sUpdateRequest;
                import %1$s.service.%2$sPermissions;
                import %1$s.service.%2$sService;
                import org.springframework.stereotype.Component;

                @Component
                public final class %2$sMcpToolContributor implements McpToolContributor {

                    public static final String LIST = "%3$s.list";
                    public static final String GET = "%3$s.get";
                    public static final String CREATE = "%3$s.create";
                    public static final String UPDATE = "%3$s.update";
                    public static final String REMOVE = "%3$s.remove";

                    private final %2$sService service;
                    private final McpToolSupport support;

                    public %2$sMcpToolContributor(%2$sService service, McpToolSupport support) {
                        this.service = service;
                        this.support = support;
                    }

                    @Override
                    public List<McpToolContribution> contributions() {
                        return List.of(
                                support.specification(LIST, "List %3$s records", listSchema(), pageOutputSchema(),
                                        McpToolSupport.readOnly(), %2$sPermissions.LIST, McpToolRisk.READ, this::list),
                                support.specification(GET, "Get a %3$s record", idSchema(false), recordOutputSchema(),
                                        McpToolSupport.readOnly(), %2$sPermissions.LIST, McpToolRisk.READ, this::get),
                                support.specification(CREATE, "Create a %3$s record", createSchema(), recordOutputSchema(),
                                        McpToolSupport.mutating(false), %2$sPermissions.CREATE, McpToolRisk.WRITE,
                                        this::create),
                                support.specification(UPDATE, "Update a %3$s record", updateSchema(), recordOutputSchema(),
                                        McpToolSupport.mutating(false), %2$sPermissions.UPDATE, McpToolRisk.WRITE,
                                        this::update),
                                support.specification(REMOVE, "Remove a %3$s record", idSchema(true), removeOutputSchema(),
                                        McpToolSupport.mutating(true), %2$sPermissions.REMOVE, McpToolRisk.DESTRUCTIVE,
                                        this::remove));
                    }

                    private Object list(Map<String, Object> raw) {
                        McpArguments arguments = new McpArguments(raw);
                        return service.page(
                                arguments.longValue("page", 1),
                                arguments.longValue("size", 20),
                                arguments.optionalString("keyword"),
                                arguments.optionalString("status"));
                    }

                    private Object get(Map<String, Object> raw) {
                        return service.get(new McpArguments(raw).requiredId("id"));
                    }

                    private Object create(Map<String, Object> raw) {
                        McpArguments arguments = new McpArguments(raw);
                        return support.idempotent(CREATE, raw, () -> service.create(new %2$sCreateRequest(
                                arguments.requiredString("code"),
                                arguments.requiredString("name"),
                                arguments.requiredString("status"),
                                arguments.optionalString("description"))));
                    }

                    private Object update(Map<String, Object> raw) {
                        McpArguments arguments = new McpArguments(raw);
                        long id = arguments.requiredId("id");
                        return support.idempotent(UPDATE, raw, () -> service.update(id, new %2$sUpdateRequest(
                                arguments.requiredString("code"),
                                arguments.requiredString("name"),
                                arguments.requiredString("status"),
                                arguments.optionalString("description"),
                                arguments.requiredInteger("version"))));
                    }

                    private Object remove(Map<String, Object> raw) {
                        McpArguments arguments = new McpArguments(raw);
                        long id = arguments.requiredId("id");
                        int version = arguments.requiredInteger("version");
                        return support.idempotent(REMOVE, raw, () -> {
                            service.remove(id, version);
                            return Map.of("id", id, "removed", true);
                        });
                    }

                    private static Map<String, Object> listSchema() {
                        Map<String, Object> properties = new LinkedHashMap<>();
                        properties.put("page", McpToolSupport.integerSchema("Page number", 1));
                        properties.put("size", Map.of("type", "integer", "minimum", 1, "maximum", 200));
                        properties.put("keyword", McpToolSupport.boundedStringSchema("Name or code keyword", 1, 120));
                        properties.put("status", statusSchema());
                        return McpToolSupport.objectSchema(properties, List.of());
                    }

                    private static Map<String, Object> idSchema(boolean write) {
                        Map<String, Object> properties = new LinkedHashMap<>();
                        properties.put("id", McpToolSupport.idStringSchema("%2$s id"));
                        if (write) {
                            properties.put("version", McpToolSupport.integerSchema("Optimistic-lock version", 0));
                            properties.put(McpToolSupport.IDEMPOTENCY_KEY, McpToolSupport.idempotencyKeySchema());
                        }
                        return McpToolSupport.objectSchema(properties,
                                write ? List.of("id", "version", McpToolSupport.IDEMPOTENCY_KEY) : List.of("id"));
                    }

                    private static Map<String, Object> createSchema() {
                        Map<String, Object> properties = mutableProperties();
                        properties.put(McpToolSupport.IDEMPOTENCY_KEY, McpToolSupport.idempotencyKeySchema());
                        return McpToolSupport.objectSchema(properties,
                                List.of("code", "name", "status", McpToolSupport.IDEMPOTENCY_KEY));
                    }

                    private static Map<String, Object> updateSchema() {
                        Map<String, Object> properties = mutableProperties();
                        properties.put("id", McpToolSupport.idStringSchema("%2$s id"));
                        properties.put("version", McpToolSupport.integerSchema("Optimistic-lock version", 0));
                        properties.put(McpToolSupport.IDEMPOTENCY_KEY, McpToolSupport.idempotencyKeySchema());
                        return McpToolSupport.objectSchema(properties,
                                List.of("id", "code", "name", "status", "version",
                                        McpToolSupport.IDEMPOTENCY_KEY));
                    }

                    private static Map<String, Object> mutableProperties() {
                        Map<String, Object> properties = new LinkedHashMap<>();
                        properties.put("code", Map.of(
                                "type", "string", "minLength", 2, "maxLength", 64,
                                "pattern", "^[A-Za-z][A-Za-z0-9_-]{1,63}$"));
                        properties.put("name", McpToolSupport.boundedStringSchema("Name", 1, 120));
                        properties.put("status", statusSchema());
                        properties.put("description",
                                McpToolSupport.boundedStringSchema("Optional description", 0, 2000));
                        return properties;
                    }

                    private static Map<String, Object> statusSchema() {
                        return McpToolSupport.enumSchema(
                                "Status", List.of("ACTIVE", "INACTIVE", "ARCHIVED"));
                    }

                    private static Map<String, Object> recordOutputSchema() {
                        Map<String, Object> properties = new LinkedHashMap<>();
                        properties.put("id", McpToolSupport.idStringSchema("%2$s id"));
                        properties.put("code", McpToolSupport.boundedStringSchema("Code", 2, 64));
                        properties.put("name", McpToolSupport.boundedStringSchema("Name", 1, 120));
                        properties.put("status", statusSchema());
                        properties.put("description", Map.of("type", List.of("string", "null")));
                        properties.put("version", McpToolSupport.integerSchema("Optimistic-lock version", 0));
                        properties.put("createdAt", Map.of("type", List.of("string", "null")));
                        properties.put("updatedAt", Map.of("type", List.of("string", "null")));
                        return McpToolSupport.objectSchema(properties,
                                List.of("id", "code", "name", "status", "version"));
                    }

                    private static Map<String, Object> pageOutputSchema() {
                        Map<String, Object> properties = new LinkedHashMap<>();
                        properties.put("records", Map.of("type", "array", "items", recordOutputSchema()));
                        properties.put("total", McpToolSupport.integerSchema("Total records", 0));
                        properties.put("page", McpToolSupport.integerSchema("Page number", 1));
                        properties.put("size", McpToolSupport.integerSchema("Page size", 1));
                        return McpToolSupport.objectSchema(properties,
                                List.of("records", "total", "page", "size"));
                    }

                    private static Map<String, Object> removeOutputSchema() {
                        return McpToolSupport.objectSchema(Map.of(
                                "id", McpToolSupport.idStringSchema("Removed %2$s id"),
                                "removed", Map.of("type", "boolean")), List.of("id", "removed"));
                    }
                }
                """.formatted(packageName, spec.className(), spec.name());
    }

    static String mcpContributorTest(String packageName, ModuleSpec spec) {
        return """
                package %1$s.mcp;

                import static org.assertj.core.api.Assertions.assertThat;

                import java.lang.reflect.Proxy;
                import java.util.List;
                import java.util.Map;

                import dev.webstarter.mcp.governance.McpToolRisk;
                import dev.webstarter.mcp.service.McpToolContribution;
                import dev.webstarter.mcp.service.McpToolSupport;
                import %1$s.service.%2$sService;
                import io.modelcontextprotocol.json.McpJsonDefaults;
                import org.junit.jupiter.api.Test;

                class %2$sMcpToolContributorTest {

                    @Test
                    void exposesFiveFixedToolsWithPermissionRiskSchemaAndWriteIdempotency() {
                        McpToolSupport support = McpToolSupport.forContractInspection(
                                McpJsonDefaults.getMapper());
                        %2$sService service = (%2$sService) Proxy.newProxyInstance(
                                %2$sService.class.getClassLoader(),
                                new Class<?>[] {%2$sService.class},
                                (proxy, method, arguments) -> {
                                    throw new AssertionError("Contract inspection must not invoke the service");
                                });
                        var contributor = new %2$sMcpToolContributor(service, support);

                        List<McpToolContribution> tools = contributor.contributions();

                        assertThat(tools).extracting(McpToolContribution::name).containsExactly(
                                "%3$s.list", "%3$s.get", "%3$s.create", "%3$s.update", "%3$s.remove");
                        assertThat(tools).extracting(McpToolContribution::permission).containsExactly(
                                "%3$s:list", "%3$s:list", "%3$s:create", "%3$s:update", "%3$s:remove");
                        assertThat(tools).extracting(McpToolContribution::risk).containsExactly(
                                McpToolRisk.READ, McpToolRisk.READ, McpToolRisk.WRITE,
                                McpToolRisk.WRITE, McpToolRisk.DESTRUCTIVE);
                        tools.forEach(tool -> {
                            assertThat(tool.specification().tool().inputSchema())
                                    .containsKeys("type", "properties", "required", "additionalProperties");
                            assertThat(tool.specification().tool().outputSchema()).containsKey("oneOf");
                        });
                        tools.stream().filter(tool -> tool.risk() != McpToolRisk.READ).forEach(tool -> {
                            Map<?, ?> properties = (Map<?, ?>) tool.specification().tool()
                                    .inputSchema().get("properties");
                            assertThat(properties.containsKey(McpToolSupport.IDEMPOTENCY_KEY)).isTrue();
                            assertThat(((List<?>) tool.specification().tool().inputSchema().get("required"))
                                    .contains(McpToolSupport.IDEMPOTENCY_KEY)).isTrue();
                            assertThat(tool.specification().tool().annotations().idempotentHint()).isTrue();
                        });
                    }
                }
                """.formatted(packageName, spec.className(), spec.name());
    }

    static String mcpRuntimeTest(String packageName, ModuleSpec spec) {
        return """
                package %1$s.mcp;

                import static org.assertj.core.api.Assertions.assertThat;

                import java.nio.file.Files;
                import java.nio.file.Path;
                import java.time.Duration;
                import java.util.Map;
                import java.util.UUID;
                import java.util.concurrent.atomic.AtomicInteger;
                import java.util.regex.Pattern;

                import io.modelcontextprotocol.client.McpClient;
                import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
                import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
                import io.modelcontextprotocol.spec.McpSchema.Implementation;
                import org.junit.jupiter.api.Test;

                /** Opt-in full-stack test through the official MCP Java SDK. */
                class %2$sMcpRuntimeIT {

                    private static final Pattern TOKEN_PATTERN = Pattern.compile(
                            "\\\"(?:token|access_token)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

                    @Test
                    void performsGeneratedCrudThroughOfficialSdk() throws Exception {
                        String baseUrl = required("WEB_STARTER_GENERATED_MCP_BASE_URL");
                        String bearer = readBearer(Path.of(required(
                                "WEB_STARTER_GENERATED_MCP_TOKEN_RESPONSE_FILE")));
                        String tracePrefix = required("WEB_STARTER_GENERATED_MCP_TRACE_PREFIX");
                        AtomicInteger request = new AtomicInteger();
                        var transport = HttpClientStreamableHttpTransport.builder(baseUrl)
                                .endpoint("/mcp")
                                .connectTimeout(Duration.ofSeconds(10))
                                .httpRequestCustomizer((builder, method, uri, body, context) -> {
                                    builder.header("Authorization", "Bearer " + bearer);
                                    builder.header("X-Trace-Id", tracePrefix + "-" + request.incrementAndGet());
                                })
                                .build();

                        try (var client = McpClient.sync(transport)
                                .clientInfo(new Implementation("generated-%3$s-acceptance", "1.0.0"))
                                .initializationTimeout(Duration.ofSeconds(15))
                                .requestTimeout(Duration.ofSeconds(15))
                                .build()) {
                            client.initialize();
                            assertThat(client.listTools().tools()).extracting(tool -> tool.name())
                                    .contains("%3$s.list", "%3$s.get", "%3$s.create",
                                            "%3$s.update", "%3$s.remove");
                            String code = "GEN_" + System.currentTimeMillis();
                            var created = client.callTool(new CallToolRequest("%3$s.create", Map.of(
                                    "code", code,
                                    "name", "Generated MCP acceptance",
                                    "status", "ACTIVE",
                                    "idempotencyKey", "create-" + UUID.randomUUID())));
                            assertThat(created.isError()).isFalse();
                            Map<?, ?> record = structured(created.structuredContent());
                            String id = (String) record.get("id");
                            assertThat(id).matches("[1-9][0-9]*");

                            var fetched = client.callTool(new CallToolRequest(
                                    "%3$s.get", Map.of("id", id)));
                            assertThat(fetched.isError()).isFalse();
                            assertThat(structured(fetched.structuredContent()).get("code")).isEqualTo(code);

                            var updated = client.callTool(new CallToolRequest("%3$s.update", Map.of(
                                    "id", id,
                                    "code", code,
                                    "name", "Generated MCP acceptance updated",
                                    "status", "INACTIVE",
                                    "version", 0,
                                    "idempotencyKey", "update-" + UUID.randomUUID())));
                            assertThat(updated.isError()).isFalse();
                            int version = ((Number) structured(updated.structuredContent()).get("version")).intValue();

                            var removed = client.callTool(new CallToolRequest("%3$s.remove", Map.of(
                                    "id", id,
                                    "version", version,
                                    "idempotencyKey", "remove-" + UUID.randomUUID())));
                            assertThat(removed.isError()).isFalse();
                            assertThat(structured(removed.structuredContent()).get("removed")).isEqualTo(true);
                        }
                    }

                    private static Map<?, ?> structured(Object value) {
                        assertThat(value).isInstanceOf(Map.class);
                        return (Map<?, ?>) value;
                    }

                    private static String required(String name) {
                        String value = System.getenv(name);
                        if (value == null || value.isBlank()) {
                            throw new IllegalStateException(name + " is required for opt-in runtime acceptance");
                        }
                        return value.trim();
                    }

                    private static String readBearer(Path responseFile) throws Exception {
                        var matcher = TOKEN_PATTERN.matcher(Files.readString(responseFile));
                        if (!matcher.find()) {
                            throw new IllegalStateException("Token response file does not contain a bearer token");
                        }
                        return matcher.group(1);
                    }
                }
                """.formatted(packageName, spec.className(), spec.name());
    }

    static String frontendTypes(ModuleSpec spec) {
        return """
                export type %sStatus = 'ACTIVE' | 'INACTIVE' | 'ARCHIVED'

                export interface %sRecord {
                  id: string
                  code: string
                  name: string
                  status: %sStatus
                  description?: string
                  version: number
                  createdAt: string
                  updatedAt: string
                }

                export interface %sPayload {
                  code: string
                  name: string
                  status: %sStatus
                  description?: string
                }

                export interface %sUpdatePayload extends %sPayload {
                  version: number
                }
                """.formatted(
                spec.className(), spec.className(), spec.className(),
                spec.className(), spec.className(), spec.className(), spec.className());
    }

    static String frontendApi(ModuleSpec spec) {
        String pluralClass = dev.webstarter.tooling.Checks.pascalCase(spec.plural());
        return """
                import { request } from '@/api/http'
                import type { PageData, PageQuery } from '@/types/api'
                import type { %sPayload, %sRecord, %sUpdatePayload } from './types'

                export function list%s(params: PageQuery): Promise<PageData<%sRecord>> {
                  return request<PageData<%sRecord>>({ url: '/%s', method: 'GET', params })
                }

                export function get%s(id: string): Promise<%sRecord> {
                  return request<%sRecord>({ url: `/%s/${encodeURIComponent(id)}`, method: 'GET' })
                }

                export function create%s(payload: %sPayload): Promise<%sRecord> {
                  return request<%sRecord>({ url: '/%s', method: 'POST', data: payload, csrf: true })
                }

                export function update%s(id: string, payload: %sUpdatePayload): Promise<%sRecord> {
                  return request<%sRecord>({
                    url: `/%s/${encodeURIComponent(id)}`,
                    method: 'PUT',
                    data: payload,
                    csrf: true,
                  })
                }

                export function remove%s(id: string, version: number): Promise<void> {
                  return request<void>({
                    url: `/%s/${encodeURIComponent(id)}`,
                    method: 'DELETE',
                    params: { version },
                    csrf: true,
                  })
                }
                """.formatted(
                spec.className(), spec.className(), spec.className(),
                pluralClass, spec.className(), spec.className(), spec.plural(),
                spec.className(), spec.className(), spec.className(), spec.plural(),
                spec.className(), spec.className(), spec.className(), spec.className(), spec.plural(),
                spec.className(), spec.className(), spec.className(), spec.className(), spec.plural(),
                spec.className(), spec.plural());
    }

    static String frontendContractTest(ModuleSpec spec) {
        return """
                import { beforeEach, describe, expect, it, vi } from 'vitest'
                import { request } from '@/api/http'
                import { remove%s, update%s } from './api'

                vi.mock('@/api/http', () => ({ request: vi.fn() }))
                const requestMock = vi.mocked(request)

                describe('%s API contract', () => {
                  beforeEach(() => requestMock.mockReset())

                  it('keeps opaque ids and sends version plus CSRF for writes', () => {
                    update%s('9007199254740993', {
                      code: 'ITEM_ONE',
                      name: 'Item one',
                      status: 'ACTIVE',
                      description: 'Generated contract',
                      version: 4,
                    })
                    remove%s('9007199254740993', 4)

                    expect(requestMock.mock.calls[0]?.[0]).toMatchObject({
                      url: '/%s/9007199254740993',
                      method: 'PUT',
                      csrf: true,
                      data: { version: 4 },
                    })
                    expect(requestMock.mock.calls[1]?.[0]).toEqual({
                      url: '/%s/9007199254740993',
                      method: 'DELETE',
                      params: { version: 4 },
                      csrf: true,
                    })
                  })
                })
                """.formatted(
                spec.className(), spec.className(), spec.name(), spec.className(), spec.className(),
                spec.plural(), spec.plural());
    }

    static String frontendView(ModuleSpec spec) {
        String pluralClass = dev.webstarter.tooling.Checks.pascalCase(spec.plural());
        return """
                <template>
                  <div class="page-content">
                    <PageHeader title="%s管理" description="由离线模块生成器创建的标准 CRUD 页面">
                      <template #actions>
                        <el-button v-if="can('%s:create')" type="primary" :icon="Plus" @click="openCreate">新建%s</el-button>
                      </template>
                    </PageHeader>

                    <RequestError :failure="failure" />

                    <div class="filter-row">
                      <el-input v-model.trim="query.keyword" placeholder="搜索名称或编码" clearable @keyup.enter="search" @clear="search" />
                      <el-select v-model="query.status" placeholder="全部状态" clearable @change="search">
                        <el-option v-for="option in statusOptions" :key="option.value" :label="option.label" :value="option.value" />
                      </el-select>
                      <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
                    </div>

                    <div class="table-panel">
                      <el-table v-loading="loading" :data="records" row-key="id" empty-text="暂无数据">
                        <el-table-column prop="name" label="名称" min-width="160" />
                        <el-table-column prop="code" label="编码" min-width="140" />
                        <el-table-column label="状态" width="110"><template #default="{ row }"><StatusTag :value="row.status" /></template></el-table-column>
                        <el-table-column label="更新时间" min-width="170"><template #default="{ row }">{{ formatDateTime(row.updatedAt) }}</template></el-table-column>
                        <el-table-column label="操作" width="188" fixed="right">
                          <template #default="{ row }">
                            <el-button link type="primary" @click="openView(row)">查看</el-button>
                            <el-button v-if="can('%s:update')" link type="primary" @click="openEdit(row)">编辑</el-button>
                            <el-button v-if="can('%s:remove')" link type="danger" @click="confirmRemove(row)">删除</el-button>
                          </template>
                        </el-table-column>
                      </el-table>
                    </div>

                    <div class="pagination-row">
                      <span>共 {{ total }} 条</span>
                      <el-pagination
                        v-model:current-page="query.page"
                        v-model:page-size="query.size"
                        background
                        layout="sizes, prev, pager, next"
                        :page-sizes="[10, 20, 50]"
                        :total="total"
                        @current-change="load"
                        @size-change="handleSizeChange"
                      />
                    </div>

                    <el-dialog v-model="dialogOpen" :title="dialogTitle" width="520px" destroy-on-close>
                      <RequestError :failure="dialogFailure" />
                      <el-form ref="formRef" :model="form" :rules="rules" label-position="top" :disabled="mode === 'view'">
                        <el-form-item label="编码" prop="code"><el-input v-model.trim="form.code" maxlength="64" /></el-form-item>
                        <el-form-item label="名称" prop="name"><el-input v-model.trim="form.name" maxlength="120" /></el-form-item>
                        <el-form-item label="状态" prop="status">
                          <el-select v-model="form.status"><el-option v-for="option in statusOptions" :key="option.value" :label="option.label" :value="option.value" /></el-select>
                        </el-form-item>
                        <el-form-item label="说明" prop="description"><el-input v-model="form.description" type="textarea" :rows="4" maxlength="2000" /></el-form-item>
                      </el-form>
                      <template #footer>
                        <el-button @click="dialogOpen = false">{{ mode === 'view' ? '关闭' : '取消' }}</el-button>
                        <el-button v-if="mode !== 'view'" type="primary" :loading="saving" @click="save">保存</el-button>
                      </template>
                    </el-dialog>
                  </div>
                </template>

                <script setup lang="ts">
                import { computed, reactive, ref } from 'vue'
                import { useRoute, useRouter } from 'vue-router'
                import { Plus, Refresh } from '@element-plus/icons-vue'
                import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
                import PageHeader from '@/components/PageHeader.vue'
                import RequestError from '@/components/RequestError.vue'
                import StatusTag from '@/components/StatusTag.vue'
                import { usePermission } from '@/composables/usePermission'
                import { useStandardCrudPage } from '@/crud/useStandardCrudPage'
                import { toRequestFailure, type RequestFailure } from '@/api/requestFailure'
                import { formatDateTime } from '@/utils/format'
                import { create%s, get%s, list%s, remove%s, update%s } from './api'
                import type { %sRecord, %sStatus } from './types'

                type Mode = 'create' | 'edit' | 'view'
                const { can } = usePermission()
                const route = useRoute()
                const router = useRouter()
                const statusOptions: Array<{ label: string; value: %sStatus }> = [
                  { label: '启用', value: 'ACTIVE' }, { label: '停用', value: 'INACTIVE' }, { label: '归档', value: 'ARCHIVED' },
                ]
                const saving = ref(false)
                const dialogFailure = ref<RequestFailure | null>(null)
                const dialogOpen = ref(false)
                const mode = ref<Mode>('create')
                const selectedId = ref<string | null>(null)
                const selectedVersion = ref<number | null>(null)
                const formRef = ref<FormInstance>()
                const crudPage = useStandardCrudPage<%sRecord>({
                  route,
                  router,
                  statuses: statusOptions.map((option) => option.value),
                  fetchPage: list%s,
                })
                const {
                  query,
                  records,
                  total,
                  loading,
                  failure,
                  load,
                  search,
                  handleSizeChange,
                  captureFailure,
                } = crudPage
                const form = reactive<{ code: string; name: string; status: %sStatus; description?: string }>({
                  code: '', name: '', status: 'ACTIVE', description: '',
                })
                const rules: FormRules<typeof form> = {
                  code: [{ required: true, message: '请输入编码', trigger: 'blur' }],
                  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
                  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
                }
                const dialogTitle = computed(() => ({ create: '新建%s', edit: '编辑%s', view: '%s详情' })[mode.value])

                function resetForm(): void {
                  Object.assign(form, { code: '', name: '', status: 'ACTIVE', description: '' })
                  selectedId.value = null
                  selectedVersion.value = null
                  dialogFailure.value = null
                  formRef.value?.clearValidate()
                }
                function openCreate(): void { resetForm(); mode.value = 'create'; dialogOpen.value = true }
                async function openView(record: %sRecord): Promise<void> { await openExisting(record, 'view') }
                async function openEdit(record: %sRecord): Promise<void> { await openExisting(record, 'edit') }
                async function openExisting(record: %sRecord, nextMode: Mode): Promise<void> {
                  resetForm(); mode.value = nextMode; dialogOpen.value = true
                  try {
                    const current = await get%s(record.id)
                    selectedId.value = current.id; selectedVersion.value = current.version
                    Object.assign(form, { code: current.code, name: current.name, status: current.status, description: current.description || '' })
                  } catch (error) { dialogFailure.value = toRequestFailure(error) }
                }
                async function save(): Promise<void> {
                  if (!(await formRef.value?.validate().catch(() => false))) return
                  saving.value = true
                  try {
                    const payload = { ...form, description: form.description || undefined }
                    if (mode.value === 'create') await create%s(payload)
                    else if (selectedId.value && selectedVersion.value !== null) await update%s(selectedId.value, { ...payload, version: selectedVersion.value })
                    ElMessage.success('保存成功'); dialogOpen.value = false; await load()
                  } catch (error) { dialogFailure.value = toRequestFailure(error) }
                  finally { saving.value = false }
                }
                async function confirmRemove(record: %sRecord): Promise<void> {
                  try {
                    await ElMessageBox.confirm(`确定删除“${record.name}”吗？`, '删除确认', { type: 'warning' })
                    await remove%s(record.id, record.version); ElMessage.success('删除成功'); await load()
                  } catch (error) { if (error !== 'cancel' && error !== 'close') captureFailure(error) }
                }
                </script>
                """.formatted(
                spec.label(), spec.name(), spec.label(), spec.name(), spec.name(),
                spec.className(), spec.className(), pluralClass, spec.className(), spec.className(),
                spec.className(), spec.className(), spec.className(), spec.className(), pluralClass,
                spec.className(), spec.label(), spec.label(), spec.label(), spec.className(),
                spec.className(), spec.className(), spec.className(), spec.className(),
                spec.className(), spec.className(), spec.className());
    }

    static String navigationItem(ModuleSpec spec) {
        return """
                  {
                    path: '%s',
                    name: '%s',
                    label: '%s管理',
                    title: '%s管理',
                    icon: Files,
                    component: () => import('@/features/%s/%sView.vue'),
                    permission: '%s:list',
                    menuId: MENU_IDS.%s,
                    sidebar: true,
                    command: true,
                  },
                """.formatted(
                spec.route(), spec.plural(), spec.label(), spec.label(), spec.name(), spec.className(),
                spec.name(), spec.permissionConstant());
    }

    static String menuConstant(ModuleSpec spec) {
        return "  %s: '%d',\n".formatted(spec.permissionConstant(), spec.menuId());
    }

    private static String normalized(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static String sqlLiteral(String value) {
        return value.replace("'", "''");
    }
}
