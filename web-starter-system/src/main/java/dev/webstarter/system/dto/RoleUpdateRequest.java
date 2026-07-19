package dev.webstarter.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record RoleUpdateRequest(
        @NotBlank @Size(max = 100) String name,
        @Size(max = 500) String description,
        @NotBlank @Pattern(regexp = "ENABLED|DISABLED") String status,
        @NotNull Integer version,
        Set<Long> permissionIds,
        Set<Long> menuIds
) {
    public RoleUpdateRequest {
        permissionIds = permissionIds == null ? Set.of() : Set.copyOf(permissionIds);
        menuIds = menuIds == null ? Set.of() : Set.copyOf(menuIds);
    }
}
