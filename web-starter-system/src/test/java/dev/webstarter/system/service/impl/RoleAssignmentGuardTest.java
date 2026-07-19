package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;

class RoleAssignmentGuardTest {

    @Test
    void roleAssignedToAUserCannotBeDeleted() {
        assertThatThrownBy(() -> guard(1, false).validateRemove(7L))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("assigned to a principal");
    }

    @Test
    void roleAssignedByAnotherModuleCannotBeDeleted() {
        assertThatThrownBy(() -> guard(0, true).validateRemove(7L))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("assigned to a principal");
    }

    @Test
    void unusedRoleCanBeDeleted() {
        assertThatCode(() -> guard(0, false).validateRemove(7L))
                .doesNotThrowAnyException();
    }

    private static RoleAssignmentGuard guard(long userAssignments, boolean externalAssignment) {
        UserRoleMapper mapper = (UserRoleMapper) Proxy.newProxyInstance(
                UserRoleMapper.class.getClassLoader(),
                new Class<?>[] {UserRoleMapper.class},
                (instance, method, arguments) -> switch (method.getName()) {
                    case "countUsersByRoleId" -> userAssignments;
                    case "toString" -> "user-role-stub";
                    case "hashCode" -> 1;
                    case "equals" -> false;
                    default -> null;
                });
        return new RoleAssignmentGuard(mapper, List.of(roleId -> externalAssignment));
    }
}
