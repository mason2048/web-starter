package dev.webstarter.system.dto;

public record MenuResponse(
        Long id,
        Long parentId,
        String name,
        String path,
        String component,
        String icon,
        Integer sortOrder,
        Boolean visible,
        String status,
        String permissionCode
) {
}
