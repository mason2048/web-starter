package dev.webstarter.system.service;

import dev.webstarter.system.dto.PermissionResponse;
import dev.webstarter.system.dto.PermissionUpsertRequest;

import java.util.List;

public interface PermissionManagementService {
    List<PermissionResponse> list(String keyword, String status);
    PermissionResponse create(PermissionUpsertRequest request);
    PermissionResponse update(Long id, PermissionUpsertRequest request);
    void remove(Long id);
}
