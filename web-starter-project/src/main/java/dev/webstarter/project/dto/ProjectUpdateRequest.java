package dev.webstarter.project.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ProjectUpdateRequest(
        @NotBlank @Size(max = 120) String name,
        @NotNull Long ownerId,
        @NotBlank @Pattern(regexp = "PLANNING|IN_PROGRESS|ARCHIVED") String status,
        @Size(max = 2000) String description,
        @NotNull Integer version
) {
}
