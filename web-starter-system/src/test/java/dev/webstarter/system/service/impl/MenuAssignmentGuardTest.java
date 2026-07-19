package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.persistence.mapper.RoleMenuMapper;

class MenuAssignmentGuardTest {

    @Test
    void assignedMenuCannotBeDeleted() {
        assertThatThrownBy(() -> guard(1).validateRemove(2001L))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("assigned to a role");
    }

    @Test
    void unassignedMenuCanBeDeleted() {
        assertThatCode(() -> guard(0).validateRemove(9000L))
                .doesNotThrowAnyException();
    }

    private static MenuAssignmentGuard guard(long assignments) {
        RoleMenuMapper mapper = (RoleMenuMapper) Proxy.newProxyInstance(
                RoleMenuMapper.class.getClassLoader(),
                new Class<?>[] {RoleMenuMapper.class},
                (instance, method, arguments) -> switch (method.getName()) {
                    case "countRolesByMenuId" -> assignments;
                    case "toString" -> "role-menu-stub";
                    case "hashCode" -> 1;
                    case "equals" -> false;
                    default -> null;
                });
        return new MenuAssignmentGuard(mapper);
    }
}
