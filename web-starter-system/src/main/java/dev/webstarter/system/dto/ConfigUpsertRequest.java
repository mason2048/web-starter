package dev.webstarter.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ConfigUpsertRequest(
        @NotBlank @Pattern(regexp = "[a-zA-Z][a-zA-Z0-9._-]{1,127}") String configKey,
        @NotBlank @Size(max = 4000) String configValue,
        @NotBlank @Size(max = 32) String valueType,
        @Size(max = 500) String description
) {
}
