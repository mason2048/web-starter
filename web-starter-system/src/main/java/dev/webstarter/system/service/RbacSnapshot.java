package dev.webstarter.system.service;

import java.util.Set;

public record RbacSnapshot(Set<String> roles, Set<String> permissions, Set<Long> menuIds) {
    public RbacSnapshot {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        menuIds = menuIds == null ? Set.of() : Set.copyOf(menuIds);
    }

    public static RbacSnapshot empty() {
        return new RbacSnapshot(Set.of(), Set.of(), Set.of());
    }
}
