package dev.webstarter.admin.bootstrap;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.mock.env.MockEnvironment;

import dev.webstarter.core.security.PasswordHasher;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;

class BootstrapAdminInitializerTest {

    @Test
    void retainedUsernameWithoutOneTimePasswordIsANoOpOnRestart() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("web-starter.bootstrap-admin.username", "admin");
        UserMapper users = mock(UserMapper.class);
        when(users.selectCount(any())).thenReturn(1L);
        PasswordHasher passwordHasher = mock(PasswordHasher.class);

        BootstrapAdminInitializer initializer = new BootstrapAdminInitializer(
                environment,
                users,
                mock(RoleMapper.class),
                mock(UserRoleMapper.class),
                passwordHasher);

        assertThatCode(() -> initializer.run(mock(ApplicationArguments.class)))
                .doesNotThrowAnyException();
        verify(users, never()).insert(any(dev.webstarter.system.domain.SysUser.class));
        verify(passwordHasher, never()).hash(any());
    }

    @Test
    void passwordWithoutUsernameIsRejectedBeforeDatabaseMutation() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("web-starter.bootstrap-admin.password", "a-strong-bootstrap-password");
        UserMapper users = mock(UserMapper.class);

        BootstrapAdminInitializer initializer = new BootstrapAdminInitializer(
                environment,
                users,
                mock(RoleMapper.class),
                mock(UserRoleMapper.class),
                mock(PasswordHasher.class));

        assertThatThrownBy(() -> initializer.run(mock(ApplicationArguments.class)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("username is required");
        verify(users, never()).insert(any(dev.webstarter.system.domain.SysUser.class));
    }
}
