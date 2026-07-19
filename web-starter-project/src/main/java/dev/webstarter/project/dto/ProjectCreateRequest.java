package dev.webstarter.project.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ProjectCreateRequest(
        @NotBlank @Size(max = 120) String name,
        @NotBlank @Pattern(regexp = "[A-Za-z][A-Za-z0-9_-]{1,63}") String code,
        @NotNull Long ownerId,
        @NotBlank @Pattern(regexp = "PLANNING|IN_PROGRESS|ARCHIVED") String status,
        @Size(max = 2000) String description
) {
}
