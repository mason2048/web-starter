package dev.webstarter.system.service.impl;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.persistence.mapper.RoleMenuMapper;

final class MenuAssignmentGuard {

    private final RoleMenuMapper roleMenuMapper;

    MenuAssignmentGuard(RoleMenuMapper roleMenuMapper) {
        this.roleMenuMapper = roleMenuMapper;
    }

    void validateRemove(Long menuId) {
        if (roleMenuMapper.countRolesByMenuId(menuId) > 0) {
            throw new ConflictException("Menu is assigned to a role and cannot be deleted");
        }
    }
}
