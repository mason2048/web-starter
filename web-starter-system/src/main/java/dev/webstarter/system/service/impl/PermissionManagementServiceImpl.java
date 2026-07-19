package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.core.exception.NotFoundException;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.security.SecuredOperation;
import dev.webstarter.system.domain.SysPermission;
import dev.webstarter.system.dto.PermissionResponse;
import dev.webstarter.system.dto.PermissionUpsertRequest;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.persistence.mapper.RolePermissionMapper;
import dev.webstarter.system.service.PermissionManagementService;
import dev.webstarter.system.service.SystemPermissions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class PermissionManagementServiceImpl extends SecuredOperation implements PermissionManagementService {

    private final PermissionMapper permissionMapper;
    private final PermissionAssignmentGuard assignmentGuard;

    public PermissionManagementServiceImpl(CallerContext callerContext, PermissionService permissionService,
                                           PermissionMapper permissionMapper,
                                           RolePermissionMapper rolePermissionMapper) {
        super(callerContext, permissionService);
        this.permissionMapper = permissionMapper;
        this.assignmentGuard = new PermissionAssignmentGuard(rolePermissionMapper);
    }

    @Override
    public List<PermissionResponse> list(String keyword, String status) {
        requirePermission(SystemPermissions.PERMISSION_LIST);
        LambdaQueryWrapper<SysPermission> wrapper = new LambdaQueryWrapper<SysPermission>()
                .eq(hasText(status), SysPermission::getStatus, status)
                .and(hasText(keyword), item -> item.like(SysPermission::getCode, keyword)
                        .or().like(SysPermission::getName, keyword))
                .orderByAsc(SysPermission::getCode);
        return permissionMapper.selectList(wrapper).stream().map(this::toResponse).toList();
    }

    @Override
    @Transactional
    public PermissionResponse create(PermissionUpsertRequest request) {
        requirePermission(SystemPermissions.PERMISSION_MANAGE);
        ensureCodeAvailable(request.code(), null);
        SysPermission permission = new SysPermission();
        apply(permission, request);
        LocalDateTime now = LocalDateTime.now();
        permission.setDeleted(0);
        permission.setCreatedAt(now);
        permission.setUpdatedAt(now);
        permissionMapper.insert(permission);
        return toResponse(permission);
    }

    @Override
    @Transactional
    public PermissionResponse update(Long id, PermissionUpsertRequest request) {
        requirePermission(SystemPermissions.PERMISSION_MANAGE);
        SysPermission permission = requirePermissionEntity(id);
        assignmentGuard.validateUpdate(permission, request);
        apply(permission, request);
        permission.setUpdatedAt(LocalDateTime.now());
        permissionMapper.updateById(permission);
        return toResponse(permission);
    }

    @Override
    @Transactional
    public void remove(Long id) {
        requirePermission(SystemPermissions.PERMISSION_MANAGE);
        requirePermissionEntity(id);
        assignmentGuard.validateRemove(id);
        permissionMapper.deleteById(id);
    }

    private void apply(SysPermission target, PermissionUpsertRequest request) {
        target.setCode(request.code().trim());
        target.setName(request.name().trim());
        target.setType(request.type().trim());
        target.setDescription(trimToNull(request.description()));
        target.setStatus(request.status());
    }

    private void ensureCodeAvailable(String code, Long excludedId) {
        LambdaQueryWrapper<SysPermission> wrapper = new LambdaQueryWrapper<SysPermission>()
                .eq(SysPermission::getCode, code.trim())
                .ne(excludedId != null, SysPermission::getId, excludedId);
        if (permissionMapper.selectCount(wrapper) > 0) {
            throw new ConflictException("Permission code already exists");
        }
    }

    private SysPermission requirePermissionEntity(Long id) {
        SysPermission permission = id == null ? null : permissionMapper.selectById(id);
        if (permission == null) {
            throw new NotFoundException("Permission not found");
        }
        return permission;
    }

    private PermissionResponse toResponse(SysPermission item) {
        return new PermissionResponse(item.getId(), item.getCode(), item.getName(), item.getType(), item.getDescription(), item.getStatus());
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
    private static String trimToNull(String value) { return hasText(value) ? value.trim() : null; }
}
