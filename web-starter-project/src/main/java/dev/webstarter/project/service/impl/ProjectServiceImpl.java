package dev.webstarter.project.service.impl;

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
import dev.webstarter.project.domain.Project;
import dev.webstarter.project.dto.ProjectCreateRequest;
import dev.webstarter.project.dto.ProjectOwnerResponse;
import dev.webstarter.project.dto.ProjectResponse;
import dev.webstarter.project.dto.ProjectUpdateRequest;
import dev.webstarter.project.persistence.mapper.ProjectMapper;
import dev.webstarter.project.service.ProjectPermissions;
import dev.webstarter.project.service.ProjectService;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.OperationAuditEvent;
import dev.webstarter.system.service.SystemIdentity;
import dev.webstarter.system.service.SystemIdentityService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

@Service
@Validated
public class ProjectServiceImpl extends SecuredOperation implements ProjectService {

    private final ProjectMapper projectMapper;
    private final SystemIdentityService systemIdentityService;
    private final AuditLogRecorder auditLogRecorder;

    public ProjectServiceImpl(
            CallerContext callerContext,
            PermissionService permissionService,
            ProjectMapper projectMapper,
            SystemIdentityService systemIdentityService,
            AuditLogRecorder auditLogRecorder
    ) {
        super(callerContext, permissionService);
        this.projectMapper = projectMapper;
        this.systemIdentityService = systemIdentityService;
        this.auditLogRecorder = auditLogRecorder;
    }

    @Override
    public PageResult<ProjectResponse> page(long page, long size, String keyword, String status, Long ownerId) {
        requirePermission(ProjectPermissions.LIST);
        PageQuery query = new PageQuery(page, size);
        LambdaQueryWrapper<Project> wrapper = new LambdaQueryWrapper<Project>()
                .eq(hasText(status), Project::getStatus, status)
                .eq(ownerId != null, Project::getOwnerId, ownerId)
                .and(hasText(keyword), item -> item.like(Project::getName, keyword)
                        .or().like(Project::getCode, keyword)
                        .or().like(Project::getOwnerName, keyword))
                .orderByDesc(Project::getId);
        Page<Project> result = projectMapper.selectPage(new Page<>(query.page(), query.size()), wrapper);
        return PageResult.of(result.getRecords().stream().map(this::toResponse).toList(), result.getTotal(), query.page(), query.size());
    }

    @Override
    public ProjectResponse get(Long id) {
        requirePermission(ProjectPermissions.LIST);
        return toResponse(requireProject(id));
    }

    @Override
    public List<ProjectOwnerResponse> listOwners() {
        requirePermission(ProjectPermissions.LIST);
        return systemIdentityService.listEnabledUsers().stream()
                .map(user -> new ProjectOwnerResponse(user.id(), user.username(), user.displayName()))
                .toList();
    }

    @Override
    @Transactional
    public ProjectResponse create(@Valid ProjectCreateRequest request) {
        long started = System.nanoTime();
        CurrentCaller caller = requirePermission(ProjectPermissions.CREATE);
        String normalizedCode = request.code().trim().toUpperCase(Locale.ROOT);
        if (projectMapper.selectCount(new LambdaQueryWrapper<Project>().eq(Project::getCode, normalizedCode)) > 0) {
            throw new ConflictException("Project code already exists");
        }
        SystemIdentity owner = requireOwner(request.ownerId());
        LocalDateTime now = LocalDateTime.now();
        Project project = new Project();
        project.setName(request.name().trim());
        project.setCode(normalizedCode);
        project.setOwnerId(owner.userId());
        project.setOwnerName(owner.displayName());
        project.setStatus(request.status());
        project.setDescription(trimToNull(request.description()));
        project.setVersion(0);
        project.setCreatedAt(now);
        project.setUpdatedAt(now);
        project.setDeleted(0);
        projectMapper.insert(project);
        recordOperation(caller, "CREATE", project.getId(), started);
        return toResponse(project);
    }

    @Override
    @Transactional
    public ProjectResponse update(Long id, @Valid ProjectUpdateRequest request) {
        long started = System.nanoTime();
        CurrentCaller caller = requirePermission(ProjectPermissions.UPDATE);
        Project project = requireProject(id);
        if (!request.version().equals(project.getVersion())) {
            throw new ConflictException("Project was changed by another request");
        }
        SystemIdentity owner = requireOwner(request.ownerId());
        project.setName(request.name().trim());
        project.setOwnerId(owner.userId());
        project.setOwnerName(owner.displayName());
        project.setStatus(request.status());
        project.setDescription(trimToNull(request.description()));
        project.setUpdatedAt(LocalDateTime.now());
        if (projectMapper.updateById(project) == 0) {
            throw new ConflictException("Project was changed by another request");
        }
        recordOperation(caller, "UPDATE", id, started);
        return toResponse(requireProject(id));
    }

    @Override
    @Transactional
    public void remove(Long id, Integer version) {
        long started = System.nanoTime();
        CurrentCaller caller = requirePermission(ProjectPermissions.REMOVE);
        if (version == null) {
            throw new IllegalArgumentException("version is required");
        }
        requireProject(id);
        if (projectMapper.logicalDeleteWithVersion(id, version, LocalDateTime.now()) == 0) {
            throw new ConflictException("Project was changed by another request");
        }
        recordOperation(caller, "REMOVE", id, started);
    }

    private Project requireProject(Long id) {
        Project project = id == null ? null : projectMapper.selectById(id);
        if (project == null) {
            throw new NotFoundException("Project not found");
        }
        return project;
    }

    private SystemIdentity requireOwner(Long ownerId) {
        SystemIdentity owner = systemIdentityService.loadById(ownerId)
                .orElseThrow(() -> new IllegalArgumentException("Project owner does not exist"));
        if (!owner.enabled()) {
            throw new IllegalArgumentException("Project owner is disabled");
        }
        return owner;
    }

    private void recordOperation(CurrentCaller caller, String action, Long projectId, long started) {
        auditLogRecorder.recordOperation(new OperationAuditEvent(
                caller.callerType().name(), caller.subjectId(), caller.displayName(), "project", action,
                "project", String.valueOf(projectId), "SUCCESS", null, null, null,
                (System.nanoTime() - started) / 1_000_000, null,
                caller.traceId() == null ? TraceContext.traceId() : caller.traceId(), LocalDateTime.now()
        ));
    }

    private ProjectResponse toResponse(Project project) {
        return new ProjectResponse(project.getId(), project.getName(), project.getCode(), project.getOwnerId(),
                project.getOwnerName(), project.getStatus(), project.getDescription(), project.getVersion(),
                project.getCreatedAt(), project.getUpdatedAt());
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
    private static String trimToNull(String value) { return hasText(value) ? value.trim() : null; }
}
