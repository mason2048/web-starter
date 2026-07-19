package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.exception.ConflictException;

class AdministratorRolePolicyTest {

    @Test
    void builtInAdministratorCannotLosePermissionsOrMenus() {
        assertThatThrownBy(() -> AdministratorRolePolicy.validateUpdate(
                "ADMIN", "ENABLED", Set.of(1L, 2L), Set.of(1L), Set.of(10L, 11L), Set.of(10L, 11L)))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("Permissions cannot be removed");
        assertThatThrownBy(() -> AdministratorRolePolicy.validateUpdate(
                "ADMIN", "ENABLED", Set.of(1L, 2L), Set.of(1L, 2L), Set.of(10L, 11L), Set.of()))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("Menus cannot be removed");
    }

    @Test
    void builtInAdministratorCanReceiveAdditionalRelationsButCannotBeDisabled() {
        assertThatCode(() -> AdministratorRolePolicy.validateUpdate(
                "ADMIN", "ENABLED", Set.of(1L), Set.of(1L, 2L), Set.of(10L), Set.of(10L, 11L)))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> AdministratorRolePolicy.validateUpdate(
                "ADMIN", "DISABLED", Set.of(1L), Set.of(1L), Set.of(10L), Set.of(10L)))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("cannot be disabled");
    }
}
