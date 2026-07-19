package dev.webstarter.security.auth;

import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;

/**
 * Web sessions have no token id and therefore use live RBAC permissions directly.
 * Every token-authenticated caller must satisfy both live RBAC and credential scope.
 */
public final class IntersectingPermissionService implements PermissionService {

    @Override
    public boolean hasPermission(CurrentCaller caller, String permission) {
        if (caller == null || permission == null || permission.isBlank()) {
            return false;
        }
        boolean rbacAllows = caller.permissions().contains("*")
                || caller.permissions().contains(permission);
        if (!rbacAllows) {
            return false;
        }
        if (caller.tokenId() == null || caller.tokenId().isBlank()) {
            return true;
        }
        return caller.scopes().contains(permission);
    }
}
