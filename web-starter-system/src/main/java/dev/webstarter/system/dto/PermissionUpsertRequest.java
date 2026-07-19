package dev.webstarter.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PermissionUpsertRequest(
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9:_-]{1,127}") String code,
        @NotBlank @Size(max = 100) String name,
        @NotBlank @Pattern(regexp = "API|MCP|MENU|BUTTON") String type,
        @Size(max = 500) String description,
        @NotBlank @Pattern(regexp = "ENABLED|DISABLED") String status
) {
}
