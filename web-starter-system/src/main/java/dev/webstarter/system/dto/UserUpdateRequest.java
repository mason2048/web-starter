package dev.webstarter.system.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record UserUpdateRequest(
        @NotBlank @Size(max = 100) String displayName,
        @Email @Size(max = 200) String email,
        @Size(max = 32) String mobile,
        @NotBlank @Pattern(regexp = "ENABLED|DISABLED") String status,
        @NotNull Integer version,
        Set<Long> roleIds
) {
    public UserUpdateRequest {
        roleIds = roleIds == null ? Set.of() : Set.copyOf(roleIds);
    }
}
