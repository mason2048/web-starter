package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.core.exception.NotFoundException;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.security.SecuredOperation;
import dev.webstarter.system.domain.SysMenu;
import dev.webstarter.system.dto.MenuResponse;
import dev.webstarter.system.dto.MenuUpsertRequest;
import dev.webstarter.system.persistence.mapper.MenuMapper;
import dev.webstarter.system.persistence.mapper.RoleMenuMapper;
import dev.webstarter.system.service.MenuService;
import dev.webstarter.system.service.SystemPermissions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class MenuServiceImpl extends SecuredOperation implements MenuService {

    private final MenuMapper menuMapper;
    private final MenuAssignmentGuard assignmentGuard;

    public MenuServiceImpl(CallerContext callerContext, PermissionService permissionService, MenuMapper menuMapper,
                           RoleMenuMapper roleMenuMapper) {
        super(callerContext, permissionService);
        this.menuMapper = menuMapper;
        this.assignmentGuard = new MenuAssignmentGuard(roleMenuMapper);
    }

    @Override
    public List<MenuResponse> list(String status) {
        requirePermission(SystemPermissions.MENU_LIST);
        return menuMapper.selectList(new LambdaQueryWrapper<SysMenu>()
                        .eq(hasText(status), SysMenu::getStatus, status)
                        .orderByAsc(SysMenu::getSortOrder).orderByAsc(SysMenu::getId))
                .stream().map(this::toResponse).toList();
    }

    @Override
    @Transactional
    public MenuResponse create(MenuUpsertRequest request) {
        requirePermission(SystemPermissions.MENU_MANAGE);
        validateParent(request.parentId(), null);
        SysMenu menu = new SysMenu();
        apply(menu, request);
        LocalDateTime now = LocalDateTime.now();
        menu.setDeleted(0);
        menu.setCreatedAt(now);
        menu.setUpdatedAt(now);
        menuMapper.insert(menu);
        return toResponse(menu);
    }

    @Override
    @Transactional
    public MenuResponse update(Long id, MenuUpsertRequest request) {
        requirePermission(SystemPermissions.MENU_MANAGE);
        SysMenu menu = requireMenu(id);
        validateParent(request.parentId(), id);
        apply(menu, request);
        menu.setUpdatedAt(LocalDateTime.now());
        menuMapper.updateById(menu);
        return toResponse(menu);
    }

    @Override
    @Transactional
    public void remove(Long id) {
        requirePermission(SystemPermissions.MENU_MANAGE);
        requireMenu(id);
        if (menuMapper.selectCount(new LambdaQueryWrapper<SysMenu>().eq(SysMenu::getParentId, id)) > 0) {
            throw new ConflictException("Delete child menus first");
        }
        assignmentGuard.validateRemove(id);
        menuMapper.deleteById(id);
    }

    private void validateParent(Long parentId, Long currentId) {
        if (parentId == null || parentId == 0) {
            return;
        }
        if (parentId.equals(currentId)) {
            throw new IllegalArgumentException("Menu cannot be its own parent");
        }
        requireMenu(parentId);
    }

    private SysMenu requireMenu(Long id) {
        SysMenu menu = id == null ? null : menuMapper.selectById(id);
        if (menu == null) {
            throw new NotFoundException("Menu not found");
        }
        return menu;
    }

    private void apply(SysMenu target, MenuUpsertRequest request) {
        target.setParentId(request.parentId() == null ? 0L : request.parentId());
        target.setName(request.name().trim());
        target.setPath(trimToNull(request.path()));
        target.setComponent(trimToNull(request.component()));
        target.setIcon(trimToNull(request.icon()));
        target.setSortOrder(request.sortOrder());
        target.setVisible(request.visible());
        target.setStatus(request.status());
        target.setPermissionCode(trimToNull(request.permissionCode()));
    }

    private MenuResponse toResponse(SysMenu menu) {
        return new MenuResponse(menu.getId(), menu.getParentId(), menu.getName(), menu.getPath(), menu.getComponent(),
                menu.getIcon(), menu.getSortOrder(), menu.getVisible(), menu.getStatus(), menu.getPermissionCode());
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
    private static String trimToNull(String value) { return hasText(value) ? value.trim() : null; }
}
