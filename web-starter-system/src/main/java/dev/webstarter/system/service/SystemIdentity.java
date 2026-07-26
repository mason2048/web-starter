package dev.webstarter.system.service;

import java.util.Set;

public record SystemIdentity(
        Long userId,
        String username,
        String displayName,
        String passwordHash,
        String status,
        long securityEpoch,
        Set<String> roles,
        Set<String> permissions,
        Set<Long> menuIds
) {
    public SystemIdentity {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        menuIds = menuIds == null ? Set.of() : Set.copyOf(menuIds);
    }

    public SystemIdentity(
            Long userId,
            String username,
            String displayName,
            String passwordHash,
            String status,
            Set<String> roles,
            Set<String> permissions,
            Set<Long> menuIds) {
        this(userId, username, displayName, passwordHash, status, 0, roles, permissions, menuIds);
    }

    public boolean enabled() {
        return "ENABLED".equals(status);
    }
}
