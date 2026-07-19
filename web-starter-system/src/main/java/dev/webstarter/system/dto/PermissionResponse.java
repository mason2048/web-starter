package dev.webstarter.system.dto;

public record PermissionResponse(Long id, String code, String name, String type, String description, String status) {
}
