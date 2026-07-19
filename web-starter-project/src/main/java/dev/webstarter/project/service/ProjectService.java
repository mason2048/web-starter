package dev.webstarter.project.service;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.project.dto.ProjectCreateRequest;
import dev.webstarter.project.dto.ProjectOwnerResponse;
import dev.webstarter.project.dto.ProjectResponse;
import dev.webstarter.project.dto.ProjectUpdateRequest;
import jakarta.validation.Valid;

import java.util.List;

public interface ProjectService {
    PageResult<ProjectResponse> page(long page, long size, String keyword, String status, Long ownerId);
    List<ProjectOwnerResponse> listOwners();
    ProjectResponse get(Long id);
    ProjectResponse create(@Valid ProjectCreateRequest request);
    ProjectResponse update(Long id, @Valid ProjectUpdateRequest request);
    void remove(Long id, Integer version);
}
