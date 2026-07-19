package dev.webstarter.system.service.impl;

import java.util.Set;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;

final class AdministratorContinuityGuard {

    static final String ADMIN_ROLE_CODE = "ADMIN";

    private final RoleMapper roleMapper;
    private final UserRoleMapper userRoleMapper;

    AdministratorContinuityGuard(RoleMapper roleMapper, UserRoleMapper userRoleMapper) {
        this.roleMapper = roleMapper;
        this.userRoleMapper = userRoleMapper;
    }

    void ensureTransitionKeepsEnabledAdministrator(
            Long userId,
            String currentStatus,
            String nextStatus,
            Set<Long> nextRoleIds) {
        Long administratorRoleId = roleMapper.selectIdByCodeForUpdate(ADMIN_ROLE_CODE);
        if (administratorRoleId == null) {
            throw new ConflictException("The built-in administrator role is unavailable");
        }
        boolean currentlyEnabledAdministrator = "ENABLED".equals(currentStatus)
                && userRoleMapper.selectRoleIds(userId).contains(administratorRoleId);
        boolean remainsEnabledAdministrator = "ENABLED".equals(nextStatus)
                && nextRoleIds.contains(administratorRoleId);
        if (currentlyEnabledAdministrator
                && !remainsEnabledAdministrator
                && userRoleMapper.countEnabledUsersByRoleCode(ADMIN_ROLE_CODE) <= 1) {
            throw new ConflictException("At least one enabled administrator account must remain");
        }
    }
}
