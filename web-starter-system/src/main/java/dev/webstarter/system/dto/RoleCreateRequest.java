package dev.webstarter.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record RoleCreateRequest(
        @NotBlank @Pattern(regexp = "[A-Z][A-Z0-9:_-]{1,63}") String code,
        @NotBlank @Size(max = 100) String name,
        @Size(max = 500) String description,
        @Pattern(regexp = "ENABLED|DISABLED") String status,
        Set<Long> permissionIds,
        Set<Long> menuIds
) {
    public RoleCreateRequest {
        permissionIds = permissionIds == null ? Set.of() : Set.copyOf(permissionIds);
        menuIds = menuIds == null ? Set.of() : Set.copyOf(menuIds);
    }
}
