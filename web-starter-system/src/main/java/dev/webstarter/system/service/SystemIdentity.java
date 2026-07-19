package dev.webstarter.system.service;

import java.util.Set;

public record SystemIdentity(
        Long userId,
        String username,
        String displayName,
        String passwordHash,
        String status,
        Set<String> roles,
        Set<String> permissions,
        Set<Long> menuIds
) {
    public SystemIdentity {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        menuIds = menuIds == null ? Set.of() : Set.copyOf(menuIds);
    }

    public boolean enabled() {
        return "ENABLED".equals(status);
    }
}
