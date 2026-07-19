package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;

class AdministratorContinuityGuardTest {

    @Test
    void lastEnabledAdministratorCannotBeDisabledRemovedOrStrippedOfRole() {
        AdministratorContinuityGuard guard = guard(List.of(1L), 1L);

        assertThatThrownBy(() -> guard.ensureTransitionKeepsEnabledAdministrator(
                7L, "ENABLED", "DISABLED", Set.of(1L)))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("At least one enabled administrator");
        assertThatThrownBy(() -> guard.ensureTransitionKeepsEnabledAdministrator(
                7L, "ENABLED", "ENABLED", Set.of()))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("At least one enabled administrator");
    }

    @Test
    void transitionIsAllowedWhenAnotherEnabledAdministratorRemains() {
        AdministratorContinuityGuard guard = guard(List.of(1L), 2L);

        assertThatCode(() -> guard.ensureTransitionKeepsEnabledAdministrator(
                7L, "ENABLED", "DISABLED", Set.of()))
                .doesNotThrowAnyException();
    }

    @Test
    void nonAdministratorTransitionDoesNotDependOnAdministratorCount() {
        AdministratorContinuityGuard guard = guard(List.of(2L), 1L);

        assertThatCode(() -> guard.ensureTransitionKeepsEnabledAdministrator(
                7L, "ENABLED", "DISABLED", Set.of()))
                .doesNotThrowAnyException();
    }

    private static AdministratorContinuityGuard guard(List<Long> currentRoles, long enabledAdministrators) {
        RoleMapper roleMapper = proxy(RoleMapper.class, (method, arguments) ->
                "selectIdByCodeForUpdate".equals(method) ? 1L : defaultValue(method));
        UserRoleMapper userRoleMapper = proxy(UserRoleMapper.class, (method, arguments) -> {
            if ("selectRoleIds".equals(method)) {
                return currentRoles;
            }
            if ("countEnabledUsersByRoleCode".equals(method)) {
                return enabledAdministrators;
            }
            return defaultValue(method);
        });
        return new AdministratorContinuityGuard(roleMapper, userRoleMapper);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Stub stub) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                (instance, method, arguments) -> stub.invoke(method.getName(), arguments));
    }

    private static Object defaultValue(String method) {
        return switch (method) {
            case "toString" -> "stub";
            case "hashCode" -> 1;
            case "equals" -> false;
            default -> null;
        };
    }

    @FunctionalInterface
    private interface Stub {
        Object invoke(String method, Object[] arguments);
    }
}
