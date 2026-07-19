package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import dev.webstarter.core.api.PageQuery;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.core.exception.NotFoundException;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.security.SecuredOperation;
import dev.webstarter.system.domain.SysMenu;
import dev.webstarter.system.domain.SysPermission;
import dev.webstarter.system.domain.SysRole;
import dev.webstarter.system.dto.RoleCreateRequest;
import dev.webstarter.system.dto.RoleResponse;
import dev.webstarter.system.dto.RoleUpdateRequest;
import dev.webstarter.system.persistence.mapper.MenuMapper;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.RoleMenuMapper;
import dev.webstarter.system.persistence.mapper.RolePermissionMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;
import dev.webstarter.system.service.RoleUsageChecker;
import dev.webstarter.system.service.RoleService;
import dev.webstarter.system.service.SystemPermissions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class RoleServiceImpl extends SecuredOperation implements RoleService {

    private final RoleMapper roleMapper;
    private final PermissionMapper permissionMapper;
    private final MenuMapper menuMapper;
    private final RolePermissionMapper rolePermissionMapper;
    private final RoleMenuMapper roleMenuMapper;
    private final RoleAssignmentGuard assignmentGuard;

    public RoleServiceImpl(
            CallerContext callerContext,
            PermissionService permissionService,
            RoleMapper roleMapper,
            PermissionMapper permissionMapper,
            MenuMapper menuMapper,
            RolePermissionMapper rolePermissionMapper,
            RoleMenuMapper roleMenuMapper,
            UserRoleMapper userRoleMapper,
            List<RoleUsageChecker> roleUsageCheckers
    ) {
        super(callerContext, permissionService);
        this.roleMapper = roleMapper;
        this.permissionMapper = permissionMapper;
        this.menuMapper = menuMapper;
        this.rolePermissionMapper = rolePermissionMapper;
        this.roleMenuMapper = roleMenuMapper;
        this.assignmentGuard = new RoleAssignmentGuard(userRoleMapper, roleUsageCheckers);
    }

    @Override
    public PageResult<RoleResponse> page(long page, long size, String keyword, String status) {
        requirePermission(SystemPermissions.ROLE_LIST);
        PageQuery query = new PageQuery(page, size);
        LambdaQueryWrapper<SysRole> wrapper = new LambdaQueryWrapper<SysRole>()
                .eq(hasText(status), SysRole::getStatus, status)
                .and(hasText(keyword), item -> item.like(SysRole::getCode, keyword).or().like(SysRole::getName, keyword))
                .orderByAsc(SysRole::getId);
        Page<SysRole> result = roleMapper.selectPage(new Page<>(query.page(), query.size()), wrapper);
        return PageResult.of(result.getRecords().stream().map(this::toResponse).toList(), result.getTotal(), query.page(), query.size());
    }

    @Override
    public RoleResponse get(Long id) {
        requirePermission(SystemPermissions.ROLE_LIST);
        return toResponse(requireRole(id));
    }

    @Override
    @Transactional
    public RoleResponse create(RoleCreateRequest request) {
        requirePermission(SystemPermissions.ROLE_CREATE);
        String code = request.code().trim();
        if (roleMapper.selectCount(new LambdaQueryWrapper<SysRole>().eq(SysRole::getCode, code)) > 0) {
            throw new ConflictException("Role code already exists");
        }
        ensureRelationsExist(request.permissionIds(), request.menuIds());
        LocalDateTime now = LocalDateTime.now();
        SysRole role = new SysRole();
        role.setCode(code);
        role.setName(request.name().trim());
        role.setDescription(trimToNull(request.description()));
        role.setStatus(defaultStatus(request.status()));
        role.setVersion(0);
        role.setDeleted(0);
        role.setCreatedAt(now);
        role.setUpdatedAt(now);
        roleMapper.insert(role);
        replaceRelations(role.getId(), request.permissionIds(), request.menuIds());
        return toResponse(role);
    }

    @Override
    @Transactional
    public RoleResponse update(Long id, RoleUpdateRequest request) {
        requirePermission(SystemPermissions.ROLE_UPDATE);
        SysRole role = requireRole(id);
        if (!request.version().equals(role.getVersion())) {
            throw new ConflictException("Role was changed by another request");
        }
        AdministratorRolePolicy.validateUpdate(
                role.getCode(),
                request.status(),
                new LinkedHashSet<>(rolePermissionMapper.selectPermissionIds(id)),
                request.permissionIds(),
                new LinkedHashSet<>(roleMenuMapper.selectMenuIds(id)),
                request.menuIds());
        ensureRelationsExist(request.permissionIds(), request.menuIds());
        role.setName(request.name().trim());
        role.setDescription(trimToNull(request.description()));
        role.setStatus(request.status());
        role.setUpdatedAt(LocalDateTime.now());
        if (roleMapper.updateById(role) == 0) {
            throw new ConflictException("Role was changed by another request");
        }
        replaceRelations(id, request.permissionIds(), request.menuIds());
        return toResponse(requireRole(id));
    }

    @Override
    @Transactional
    public void remove(Long id) {
        requirePermission(SystemPermissions.ROLE_REMOVE);
        SysRole role = requireRole(id);
        if ("ADMIN".equals(role.getCode())) {
            throw new ConflictException("The built-in administrator role cannot be deleted");
        }
        assignmentGuard.validateRemove(id);
        rolePermissionMapper.deleteByRoleId(id);
        roleMenuMapper.deleteByRoleId(id);
        roleMapper.deleteById(id);
    }

    private SysRole requireRole(Long id) {
        SysRole role = id == null ? null : roleMapper.selectById(id);
        if (role == null) {
            throw new NotFoundException("Role not found");
        }
        return role;
    }

    private void ensureRelationsExist(Set<Long> permissionIds, Set<Long> menuIds) {
        if (!permissionIds.isEmpty()) {
            List<SysPermission> permissions = permissionMapper.selectBatchIds(permissionIds);
            if (permissions.size() != permissionIds.size()) {
                throw new IllegalArgumentException("One or more permissions do not exist");
            }
        }
        if (!menuIds.isEmpty()) {
            List<SysMenu> menus = menuMapper.selectBatchIds(menuIds);
            if (menus.size() != menuIds.size()) {
                throw new IllegalArgumentException("One or more menus do not exist");
            }
        }
    }

    private void replaceRelations(Long roleId, Set<Long> permissionIds, Set<Long> menuIds) {
        rolePermissionMapper.deleteByRoleId(roleId);
        roleMenuMapper.deleteByRoleId(roleId);
        if (!permissionIds.isEmpty()) {
            rolePermissionMapper.insertBatch(roleId, permissionIds);
        }
        if (!menuIds.isEmpty()) {
            roleMenuMapper.insertBatch(roleId, menuIds);
        }
    }

    private RoleResponse toResponse(SysRole role) {
        return new RoleResponse(
                role.getId(), role.getCode(), role.getName(), role.getDescription(), role.getStatus(), role.getVersion(),
                new LinkedHashSet<>(rolePermissionMapper.selectPermissionIds(role.getId())),
                new LinkedHashSet<>(roleMenuMapper.selectMenuIds(role.getId())),
                role.getCreatedAt(), role.getUpdatedAt()
        );
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
    private static String trimToNull(String value) { return hasText(value) ? value.trim() : null; }
    private static String defaultStatus(String value) { return hasText(value) ? value : "ENABLED"; }
}
