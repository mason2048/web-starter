package dev.webstarter.system.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record UserCreateRequest(
        @NotBlank @Size(max = 64) String username,
        @NotBlank @Size(max = 100) String displayName,
        @NotBlank @Size(min = 12, max = 128) String password,
        @Email @Size(max = 200) String email,
        @Size(max = 32) String mobile,
        @Pattern(regexp = "ENABLED|DISABLED") String status,
        Set<Long> roleIds
) {
    public UserCreateRequest {
        roleIds = roleIds == null ? Set.of() : Set.copyOf(roleIds);
    }
}
