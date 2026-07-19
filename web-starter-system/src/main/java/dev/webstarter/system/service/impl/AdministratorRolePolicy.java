package dev.webstarter.system.service.impl;

import java.util.Set;

import dev.webstarter.core.exception.ConflictException;

final class AdministratorRolePolicy {

    private AdministratorRolePolicy() {
    }

    static void validateUpdate(
            String roleCode,
            String nextStatus,
            Set<Long> existingPermissionIds,
            Set<Long> nextPermissionIds,
            Set<Long> existingMenuIds,
            Set<Long> nextMenuIds) {
        if (!AdministratorContinuityGuard.ADMIN_ROLE_CODE.equals(roleCode)) {
            return;
        }
        if (!"ENABLED".equals(nextStatus)) {
            throw new ConflictException("The built-in administrator role cannot be disabled");
        }
        if (nextPermissionIds.isEmpty() || !nextPermissionIds.containsAll(existingPermissionIds)) {
            throw new ConflictException("Permissions cannot be removed from the built-in administrator role");
        }
        if (nextMenuIds.isEmpty() || !nextMenuIds.containsAll(existingMenuIds)) {
            throw new ConflictException("Menus cannot be removed from the built-in administrator role");
        }
    }
}
