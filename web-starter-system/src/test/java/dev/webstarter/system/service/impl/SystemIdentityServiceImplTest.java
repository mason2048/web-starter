package dev.webstarter.system.service.impl;

import dev.webstarter.system.domain.SysUser;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.persistence.mapper.MenuMapper;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserMapper;
import dev.webstarter.system.service.SystemIdentity;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SystemIdentityServiceImplTest {

    @Test
    void loadsIdentityWithLiveRolesAndPermissions() {
        SysUser user = new SysUser();
        user.setId(7L);
        user.setUsername("operator");
        user.setDisplayName("Operator");
        user.setPasswordHash("encoded");
        user.setStatus("ENABLED");

        UserMapper userMapper = proxy(UserMapper.class, (method, args) ->
                method.equals("selectOne") || method.equals("selectById") ? user : null);
        RoleMapper roleMapper = proxy(RoleMapper.class, (method, args) ->
                method.equals("selectCodesByUserId") ? List.of("project-reader") : List.of());
        PermissionMapper permissionMapper = proxy(PermissionMapper.class, (method, args) ->
                method.equals("selectCodesByUserId") ? List.of("project:list") : List.of());
        MenuMapper menuMapper = proxy(MenuMapper.class, (method, args) ->
                method.equals("selectVisibleIdsByUserId") ? List.of(2002L) : List.of());

        SystemIdentityServiceImpl service = new SystemIdentityServiceImpl(
                userMapper, roleMapper, permissionMapper, menuMapper);
        SystemIdentity identity = service.loadByUsername("operator").orElseThrow();

        assertEquals(7L, identity.userId());
        assertTrue(identity.enabled());
        assertEquals(List.of("project-reader"), identity.roles().stream().toList());
        assertEquals(List.of("project:list"), identity.permissions().stream().toList());
        assertEquals(List.of(2002L), identity.menuIds().stream().toList());
    }

    @Test
    void listsOnlyEnabledUsersAsOwnerCandidates() {
        SysUser user = new SysUser();
        user.setId(7L);
        user.setUsername("operator");
        user.setDisplayName("Operator");

        UserMapper userMapper = proxy(UserMapper.class, (method, args) ->
                method.equals("selectList") ? List.of(user) : null);
        RoleMapper roleMapper = proxy(RoleMapper.class, (method, args) -> List.of());
        PermissionMapper permissionMapper = proxy(PermissionMapper.class, (method, args) -> List.of());
        MenuMapper menuMapper = proxy(MenuMapper.class, (method, args) -> List.of());

        SystemIdentityServiceImpl service = new SystemIdentityServiceImpl(
                userMapper, roleMapper, permissionMapper, menuMapper);

        assertEquals(1, service.listEnabledUsers().size());
        assertEquals("operator", service.listEnabledUsers().getFirst().username());
    }

    @SuppressWarnings("unchecked")
    private <T> T proxy(Class<T> type, Stub stub) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (instance, method, args) -> stub.invoke(method.getName(), args));
    }

    @FunctionalInterface
    private interface Stub {
        Object invoke(String method, Object[] args);
    }
}
