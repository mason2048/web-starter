package dev.webstarter.system.service;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.RoleCreateRequest;
import dev.webstarter.system.dto.RoleResponse;
import dev.webstarter.system.dto.RoleUpdateRequest;

public interface RoleService {
    PageResult<RoleResponse> page(long page, long size, String keyword, String status);
    RoleResponse get(Long id);
    RoleResponse create(RoleCreateRequest request);
    RoleResponse update(Long id, RoleUpdateRequest request);
    void remove(Long id);
}
