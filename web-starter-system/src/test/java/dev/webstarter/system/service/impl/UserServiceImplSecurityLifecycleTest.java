package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PasswordHasher;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.system.domain.SysUser;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;
import dev.webstarter.system.service.IdentitySecurityLifecyclePort;

import java.util.Optional;
import java.util.Set;

class UserServiceImplSecurityLifecycleTest {

    @Test
    void ownPasswordChangeAdvancesEpochAndInvalidatesEarlierCredentials() {
        UserMapper userMapper = mock(UserMapper.class);
        PasswordHasher passwordHasher = mock(PasswordHasher.class);
        IdentitySecurityLifecyclePort lifecycle = mock(IdentitySecurityLifecyclePort.class);
        CallerContext callerContext = callerContext(7L);
        SysUser user = user(7L, 4L);
        when(userMapper.selectById(7L)).thenReturn(user);
        when(passwordHasher.matches("current-secret", "old-hash")).thenReturn(true);
        when(passwordHasher.matches("new-secret-value", "old-hash")).thenReturn(false);
        when(passwordHasher.hash("new-secret-value")).thenReturn("new-hash");
        when(userMapper.updateById(user)).thenReturn(1);
        UserServiceImpl service = service(callerContext, userMapper, passwordHasher, lifecycle);

        service.changeOwnPassword(7L, "current-secret", "new-secret-value");

        assertThat(user.getPasswordHash()).isEqualTo("new-hash");
        assertThat(user.getSecurityEpoch()).isEqualTo(5);
        assertThat(user.getPasswordChangedAt()).isNotNull();
        verify(lifecycle).userSecurityEpochAdvanced(
                7L, "operator", 5L, "PASSWORD_CHANGED");
    }

    @Test
    void wrongCurrentPasswordDoesNotMutateTheIdentity() {
        UserMapper userMapper = mock(UserMapper.class);
        PasswordHasher passwordHasher = mock(PasswordHasher.class);
        IdentitySecurityLifecyclePort lifecycle = mock(IdentitySecurityLifecyclePort.class);
        CallerContext callerContext = callerContext(7L);
        SysUser user = user(7L, 4L);
        when(userMapper.selectById(7L)).thenReturn(user);
        when(passwordHasher.matches("wrong", "old-hash")).thenReturn(false);
        UserServiceImpl service = service(callerContext, userMapper, passwordHasher, lifecycle);

        assertThatThrownBy(() -> service.changeOwnPassword(7L, "wrong", "new-secret-value"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Current password is incorrect");

        verify(userMapper, never()).updateById(user);
        verify(lifecycle, never()).userSecurityEpochAdvanced(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void securityLogoutAdvancesEpochWithoutChangingPassword() {
        UserMapper userMapper = mock(UserMapper.class);
        PasswordHasher passwordHasher = mock(PasswordHasher.class);
        IdentitySecurityLifecyclePort lifecycle = mock(IdentitySecurityLifecyclePort.class);
        CallerContext callerContext = callerContext(7L);
        SysUser user = user(7L, 4L);
        when(userMapper.selectById(7L)).thenReturn(user);
        when(userMapper.updateById(user)).thenReturn(1);
        UserServiceImpl service = service(callerContext, userMapper, passwordHasher, lifecycle);

        service.securityLogout(7L);

        assertThat(user.getPasswordHash()).isEqualTo("old-hash");
        assertThat(user.getSecurityEpoch()).isEqualTo(5);
        verify(lifecycle).userSecurityEpochAdvanced(
                7L, "operator", 5L, "SECURITY_LOGOUT");
    }

    @Test
    void securityLogoutCannotTargetAnotherUser() {
        UserMapper userMapper = mock(UserMapper.class);
        IdentitySecurityLifecyclePort lifecycle = mock(IdentitySecurityLifecyclePort.class);
        UserServiceImpl service = service(
                callerContext(7L), userMapper, mock(PasswordHasher.class), lifecycle);

        assertThatThrownBy(() -> service.securityLogout(8L))
                .isInstanceOf(dev.webstarter.core.exception.PermissionDeniedException.class);

        verify(userMapper, never()).selectById(8L);
        verify(lifecycle, never()).userSecurityEpochAdvanced(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any());
    }

    private static UserServiceImpl service(
            CallerContext callerContext,
            UserMapper userMapper,
            PasswordHasher passwordHasher,
            IdentitySecurityLifecyclePort lifecycle) {
        return new UserServiceImpl(
                callerContext,
                mock(PermissionService.class),
                userMapper,
                mock(RoleMapper.class),
                mock(UserRoleMapper.class),
                passwordHasher,
                lifecycle);
    }

    private static CallerContext callerContext(Long userId) {
        CallerContext context = mock(CallerContext.class);
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER,
                userId.toString(),
                "operator",
                "Operator",
                null,
                null,
                Set.of(),
                Set.of(),
                Set.of(),
                "trace");
        when(context.current()).thenReturn(Optional.of(caller));
        when(context.required()).thenReturn(caller);
        return context;
    }

    private static SysUser user(Long id, Long epoch) {
        SysUser user = new SysUser();
        user.setId(id);
        user.setUsername("operator");
        user.setPasswordHash("old-hash");
        user.setStatus("ENABLED");
        user.setSecurityEpoch(epoch);
        user.setVersion(0);
        return user;
    }
}
