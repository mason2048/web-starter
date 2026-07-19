package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.domain.SysPermission;
import dev.webstarter.system.dto.PermissionUpsertRequest;
import dev.webstarter.system.persistence.mapper.RolePermissionMapper;

class PermissionAssignmentGuardTest {

    @Test
    void permissionCodeIsImmutable() {
        PermissionAssignmentGuard guard = guard(0, 0);

        assertThatThrownBy(() -> guard.validateUpdate(permission(), request("project:renamed", "ENABLED")))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("cannot be changed");
    }

    @Test
    void administratorPermissionCannotBeDisabled() {
        PermissionAssignmentGuard guard = guard(1, 1);

        assertThatThrownBy(() -> guard.validateUpdate(permission(), request("project:list", "DISABLED")))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("administrator role cannot be disabled");
    }

    @Test
    void assignedPermissionCannotBeDeletedButUnassignedPermissionCan() {
        assertThatThrownBy(() -> guard(2, 0).validateRemove(100L))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("assigned to a role");
        assertThatCode(() -> guard(0, 0).validateRemove(100L))
                .doesNotThrowAnyException();
    }

    private static PermissionAssignmentGuard guard(long roleCount, long administratorCount) {
        RolePermissionMapper mapper = (RolePermissionMapper) Proxy.newProxyInstance(
                RolePermissionMapper.class.getClassLoader(),
                new Class<?>[] {RolePermissionMapper.class},
                (instance, method, arguments) -> switch (method.getName()) {
                    case "countRolesByPermissionId" -> roleCount;
                    case "countByPermissionAndRoleCode" -> administratorCount;
                    case "toString" -> "role-permission-stub";
                    case "hashCode" -> 1;
                    case "equals" -> false;
                    default -> null;
                });
        return new PermissionAssignmentGuard(mapper);
    }

    private static SysPermission permission() {
        SysPermission permission = new SysPermission();
        permission.setId(100L);
        permission.setCode("project:list");
        permission.setStatus("ENABLED");
        return permission;
    }

    private static PermissionUpsertRequest request(String code, String status) {
        return new PermissionUpsertRequest(code, "Project list", "API", null, status);
    }
}
