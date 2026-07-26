package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import dev.webstarter.core.api.PageQuery;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.core.exception.NotFoundException;
import dev.webstarter.core.exception.PermissionDeniedException;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PasswordHasher;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.security.SecuredOperation;
import dev.webstarter.system.domain.SysRole;
import dev.webstarter.system.domain.SysUser;
import dev.webstarter.system.dto.UserCreateRequest;
import dev.webstarter.system.dto.UserPasswordResetRequest;
import dev.webstarter.system.dto.UserResponse;
import dev.webstarter.system.dto.UserUpdateRequest;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;
import dev.webstarter.system.service.SystemPermissions;
import dev.webstarter.system.service.IdentitySecurityLifecyclePort;
import dev.webstarter.system.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServiceImpl extends SecuredOperation implements UserService {

    private final UserMapper userMapper;
    private final CallerContext callerContext;
    private final RoleMapper roleMapper;
    private final UserRoleMapper userRoleMapper;
    private final PasswordHasher passwordHasher;
    private final IdentitySecurityLifecyclePort securityLifecycle;
    private final AdministratorContinuityGuard administratorContinuityGuard;

    public UserServiceImpl(
            CallerContext callerContext,
            PermissionService permissionService,
            UserMapper userMapper,
            RoleMapper roleMapper,
            UserRoleMapper userRoleMapper,
            PasswordHasher passwordHasher,
            IdentitySecurityLifecyclePort securityLifecycle
    ) {
        super(callerContext, permissionService);
        this.callerContext = callerContext;
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.userRoleMapper = userRoleMapper;
        this.passwordHasher = passwordHasher;
        this.securityLifecycle = securityLifecycle;
        this.administratorContinuityGuard = new AdministratorContinuityGuard(roleMapper, userRoleMapper);
    }

    @Override
    public PageResult<UserResponse> page(long page, long size, String keyword, String status) {
        requirePermission(SystemPermissions.USER_LIST);
        PageQuery query = new PageQuery(page, size);
        LambdaQueryWrapper<SysUser> wrapper = new LambdaQueryWrapper<SysUser>()
                .eq(hasText(status), SysUser::getStatus, status)
                .and(hasText(keyword), item -> item.like(SysUser::getUsername, keyword)
                        .or().like(SysUser::getDisplayName, keyword))
                .orderByDesc(SysUser::getId);
        Page<SysUser> result = userMapper.selectPage(new Page<>(query.page(), query.size()), wrapper);
        List<UserResponse> records = result.getRecords().stream().map(this::toResponse).toList();
        return PageResult.of(records, result.getTotal(), query.page(), query.size());
    }

    @Override
    public UserResponse get(Long id) {
        requirePermission(SystemPermissions.USER_LIST);
        return toResponse(requireUser(id));
    }

    @Override
    @Transactional
    public UserResponse create(UserCreateRequest request) {
        requirePermission(SystemPermissions.USER_CREATE);
        String username = request.username().trim();
        if (userMapper.selectCount(new LambdaQueryWrapper<SysUser>().eq(SysUser::getUsername, username)) > 0) {
            throw new ConflictException("Username already exists");
        }
        ensureRolesExist(request.roleIds());

        LocalDateTime now = LocalDateTime.now();
        SysUser user = new SysUser();
        user.setUsername(username);
        user.setDisplayName(request.displayName().trim());
        user.setPasswordHash(passwordHasher.hash(request.password()));
        user.setEmail(trimToNull(request.email()));
        user.setMobile(trimToNull(request.mobile()));
        user.setStatus(defaultStatus(request.status()));
        user.setSecurityEpoch(0L);
        user.setVersion(0);
        user.setDeleted(0);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        userMapper.insert(user);
        replaceRoles(user.getId(), request.roleIds());
        return toResponse(user);
    }

    @Override
    @Transactional
    public UserResponse update(Long id, UserUpdateRequest request) {
        CurrentCaller caller = requirePermission(SystemPermissions.USER_UPDATE);
        SysUser user = requireUser(id);
        if (caller.subjectId().equals(String.valueOf(id)) && !"ENABLED".equals(request.status())) {
            throw new ConflictException("You cannot disable your own account");
        }
        if (!request.version().equals(user.getVersion())) {
            throw new ConflictException("User was changed by another request");
        }
        ensureRolesExist(request.roleIds());
        administratorContinuityGuard.ensureTransitionKeepsEnabledAdministrator(
                id, user.getStatus(), request.status(), request.roleIds());
        boolean disabledNow = "ENABLED".equals(user.getStatus())
                && !"ENABLED".equals(request.status());
        user.setDisplayName(request.displayName().trim());
        user.setEmail(trimToNull(request.email()));
        user.setMobile(trimToNull(request.mobile()));
        user.setStatus(request.status());
        if (disabledNow) {
            user.setSecurityEpoch(securityEpoch(user) + 1);
        }
        user.setUpdatedAt(LocalDateTime.now());
        if (userMapper.updateById(user) == 0) {
            throw new ConflictException("User was changed by another request");
        }
        replaceRoles(id, request.roleIds());
        if (disabledNow) {
            securityLifecycle.userSecurityEpochAdvanced(
                    id, user.getUsername(), securityEpoch(user), "SUBJECT_DISABLED");
        }
        return toResponse(requireUser(id));
    }

    @Override
    @Transactional
    public void resetPassword(Long id, UserPasswordResetRequest request) {
        requirePermission(SystemPermissions.USER_UPDATE);
        SysUser user = requireUser(id);
        user.setPasswordHash(passwordHasher.hash(request.password()));
        LocalDateTime now = LocalDateTime.now();
        user.setSecurityEpoch(securityEpoch(user) + 1);
        user.setPasswordChangedAt(now);
        user.setUpdatedAt(now);
        if (userMapper.updateById(user) == 0) {
            throw new ConflictException("User was changed by another request");
        }
        securityLifecycle.userSecurityEpochAdvanced(
                id, user.getUsername(), securityEpoch(user), "PASSWORD_CHANGED");
    }

    @Override
    @Transactional
    public void securityLogout(Long id) {
        CurrentCaller caller = callerContext.required();
        if (caller.callerType() != CallerType.USER
                || !caller.subjectId().equals(String.valueOf(id))) {
            throw new PermissionDeniedException("account:security-logout");
        }
        SysUser user = requireUser(id);
        user.setSecurityEpoch(securityEpoch(user) + 1);
        user.setUpdatedAt(LocalDateTime.now());
        if (userMapper.updateById(user) == 0) {
            throw new ConflictException("User was changed by another request");
        }
        securityLifecycle.userSecurityEpochAdvanced(
                id, user.getUsername(), securityEpoch(user), "SECURITY_LOGOUT");
    }

    @Override
    @Transactional
    public void changeOwnPassword(Long id, String currentPassword, String newPassword) {
        CurrentCaller caller = callerContext.required();
        if (caller.callerType() != CallerType.USER
                || !caller.subjectId().equals(String.valueOf(id))) {
            throw new PermissionDeniedException("account:self-password");
        }
        SysUser user = requireUser(id);
        if (!passwordHasher.matches(currentPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }
        if (passwordHasher.matches(newPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("New password must differ from the current password");
        }
        LocalDateTime now = LocalDateTime.now();
        user.setPasswordHash(passwordHasher.hash(newPassword));
        user.setSecurityEpoch(securityEpoch(user) + 1);
        user.setPasswordChangedAt(now);
        user.setUpdatedAt(now);
        if (userMapper.updateById(user) == 0) {
            throw new ConflictException("User was changed by another request");
        }
        securityLifecycle.userSecurityEpochAdvanced(
                id, user.getUsername(), securityEpoch(user), "PASSWORD_CHANGED");
    }

    @Override
    @Transactional
    public void remove(Long id) {
        CurrentCaller caller = requirePermission(SystemPermissions.USER_REMOVE);
        if (caller.subjectId().equals(String.valueOf(id))) {
            throw new ConflictException("You cannot delete your own account");
        }
        SysUser user = requireUser(id);
        administratorContinuityGuard.ensureTransitionKeepsEnabledAdministrator(
                id, user.getStatus(), "DISABLED", Set.of());
        userRoleMapper.deleteByUserId(id);
        userMapper.deleteById(id);
        securityLifecycle.userSecurityEpochAdvanced(
                id, user.getUsername(), securityEpoch(user) + 1, "SUBJECT_REMOVED");
    }

    private SysUser requireUser(Long id) {
        SysUser user = id == null ? null : userMapper.selectById(id);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private void ensureRolesExist(Set<Long> roleIds) {
        if (roleIds.isEmpty()) {
            return;
        }
        List<SysRole> roles = roleMapper.selectBatchIds(roleIds);
        if (roles.size() != roleIds.size()) {
            throw new IllegalArgumentException("One or more roles do not exist");
        }
    }

    private void replaceRoles(Long userId, Set<Long> roleIds) {
        userRoleMapper.deleteByUserId(userId);
        if (!roleIds.isEmpty()) {
            userRoleMapper.insertBatch(userId, roleIds);
        }
    }

    private UserResponse toResponse(SysUser user) {
        return new UserResponse(
                user.getId(), user.getUsername(), user.getDisplayName(), user.getEmail(), user.getMobile(),
                user.getStatus(), user.getVersion(),
                new LinkedHashSet<>(userRoleMapper.selectRoleIds(user.getId())),
                user.getCreatedAt(), user.getUpdatedAt()
        );
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String trimToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private static String defaultStatus(String status) {
        return hasText(status) ? status : "ENABLED";
    }

    private static long securityEpoch(SysUser user) {
        return user.getSecurityEpoch() == null ? 0 : user.getSecurityEpoch();
    }
}
