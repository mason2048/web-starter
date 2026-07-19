package dev.webstarter.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UserPasswordResetRequest(@NotBlank @Size(min = 12, max = 128) String password) {
}
