package dev.webstarter.system.service.impl;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.domain.SysPermission;
import dev.webstarter.system.dto.PermissionUpsertRequest;
import dev.webstarter.system.persistence.mapper.RolePermissionMapper;

final class PermissionAssignmentGuard {

    private final RolePermissionMapper rolePermissionMapper;

    PermissionAssignmentGuard(RolePermissionMapper rolePermissionMapper) {
        this.rolePermissionMapper = rolePermissionMapper;
    }

    void validateUpdate(SysPermission current, PermissionUpsertRequest request) {
        if (!current.getCode().equals(request.code().trim())) {
            throw new ConflictException("Permission code cannot be changed after creation");
        }
        if (!"ENABLED".equals(request.status())
                && rolePermissionMapper.countByPermissionAndRoleCode(
                        current.getId(), AdministratorContinuityGuard.ADMIN_ROLE_CODE) > 0) {
            throw new ConflictException("A permission assigned to the administrator role cannot be disabled");
        }
    }

    void validateRemove(Long permissionId) {
        if (rolePermissionMapper.countRolesByPermissionId(permissionId) > 0) {
            throw new ConflictException("A permission assigned to a role cannot be deleted");
        }
    }
}
