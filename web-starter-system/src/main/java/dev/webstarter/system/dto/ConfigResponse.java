package dev.webstarter.system.dto;

public record ConfigResponse(
        Long id,
        String configKey,
        String configValue,
        String valueType,
        String description,
        Boolean builtin
) {
}
