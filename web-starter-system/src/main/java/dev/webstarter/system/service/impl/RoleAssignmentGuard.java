package dev.webstarter.system.service.impl;

import java.util.List;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;
import dev.webstarter.system.service.RoleUsageChecker;

final class RoleAssignmentGuard {

    private final UserRoleMapper userRoleMapper;
    private final List<RoleUsageChecker> externalCheckers;

    RoleAssignmentGuard(UserRoleMapper userRoleMapper, List<RoleUsageChecker> externalCheckers) {
        this.userRoleMapper = userRoleMapper;
        this.externalCheckers = List.copyOf(externalCheckers);
    }

    void validateRemove(Long roleId) {
        if (userRoleMapper.countUsersByRoleId(roleId) > 0
                || externalCheckers.stream().anyMatch(checker -> checker.isRoleInUse(roleId))) {
            throw new ConflictException("Role is assigned to a principal and cannot be deleted");
        }
    }
}
