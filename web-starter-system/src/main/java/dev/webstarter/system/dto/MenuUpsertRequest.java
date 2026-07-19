package dev.webstarter.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record MenuUpsertRequest(
        Long parentId,
        @NotBlank @Size(max = 100) String name,
        @Size(max = 255) String path,
        @Size(max = 255) String component,
        @Size(max = 100) String icon,
        @NotNull Integer sortOrder,
        @NotNull Boolean visible,
        @NotBlank @Pattern(regexp = "ENABLED|DISABLED") String status,
        @Size(max = 128) String permissionCode
) {
}
