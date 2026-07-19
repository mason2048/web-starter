package dev.webstarter.core.security;

import dev.webstarter.core.exception.PermissionDeniedException;

public interface PermissionService {

    boolean hasPermission(CurrentCaller caller, String permission);

    default void requirePermission(CurrentCaller caller, String permission) {
        if (!hasPermission(caller, permission)) {
            throw new PermissionDeniedException(permission);
        }
    }
}
