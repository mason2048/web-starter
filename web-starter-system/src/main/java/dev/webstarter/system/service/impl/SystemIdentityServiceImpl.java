package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import dev.webstarter.system.domain.SysUser;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.persistence.mapper.MenuMapper;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserMapper;
import dev.webstarter.system.service.RbacSnapshot;
import dev.webstarter.system.service.SystemIdentity;
import dev.webstarter.system.service.SystemIdentityService;
import dev.webstarter.system.service.SystemUserSummary;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class SystemIdentityServiceImpl implements SystemIdentityService {

    private final UserMapper userMapper;
    private final RoleMapper roleMapper;
    private final PermissionMapper permissionMapper;
    private final MenuMapper menuMapper;

    public SystemIdentityServiceImpl(
            UserMapper userMapper,
            RoleMapper roleMapper,
            PermissionMapper permissionMapper,
            MenuMapper menuMapper) {
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.permissionMapper = permissionMapper;
        this.menuMapper = menuMapper;
    }

    @Override
    public Optional<SystemIdentity> loadByUsername(String username) {
        if (username == null || username.isBlank()) {
            return Optional.empty();
        }
        SysUser user = userMapper.selectOne(new LambdaQueryWrapper<SysUser>()
                .eq(SysUser::getUsername, username.trim()));
        return Optional.ofNullable(user).map(this::toIdentity);
    }

    @Override
    public Optional<SystemIdentity> loadById(Long userId) {
        if (userId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(userMapper.selectById(userId)).map(this::toIdentity);
    }

    @Override
    public List<SystemUserSummary> listEnabledUsers() {
        return userMapper.selectList(new LambdaQueryWrapper<SysUser>()
                        .eq(SysUser::getStatus, "ENABLED")
                        .orderByAsc(SysUser::getDisplayName)
                        .orderByAsc(SysUser::getId))
                .stream()
                .map(user -> new SystemUserSummary(user.getId(), user.getUsername(), user.getDisplayName()))
                .toList();
    }

    @Override
    public RbacSnapshot resolveRbacByRoleIds(Collection<Long> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return RbacSnapshot.empty();
        }
        return new RbacSnapshot(
                new LinkedHashSet<>(roleMapper.selectCodesByIds(roleIds)),
                new LinkedHashSet<>(permissionMapper.selectCodesByRoleIds(roleIds)),
                new LinkedHashSet<>(menuMapper.selectVisibleIdsByRoleIds(roleIds))
        );
    }

    private SystemIdentity toIdentity(SysUser user) {
        Set<String> roles = new LinkedHashSet<>(roleMapper.selectCodesByUserId(user.getId()));
        Set<String> permissions = new LinkedHashSet<>(permissionMapper.selectCodesByUserId(user.getId()));
        return new SystemIdentity(
                user.getId(),
                user.getUsername(),
                user.getDisplayName(),
                user.getPasswordHash(),
                user.getStatus(),
                roles,
                permissions,
                new LinkedHashSet<>(menuMapper.selectVisibleIdsByUserId(user.getId()))
        );
    }
}
