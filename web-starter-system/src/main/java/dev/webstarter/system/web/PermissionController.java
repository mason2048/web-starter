package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.system.dto.PermissionResponse;
import dev.webstarter.system.dto.PermissionUpsertRequest;
import dev.webstarter.system.service.PermissionManagementService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/permissions")
public class PermissionController {
    private final PermissionManagementService service;

    public PermissionController(PermissionManagementService service) { this.service = service; }

    @GetMapping
    public ApiResponse<List<PermissionResponse>> list(@RequestParam(required = false) String keyword,
                                                      @RequestParam(required = false) String status) {
        return ApiResponse.success(service.list(keyword, status));
    }

    @PostMapping
    public ApiResponse<PermissionResponse> create(@Valid @RequestBody PermissionUpsertRequest request) {
        return ApiResponse.success(service.create(request));
    }

    @PutMapping("/{id}")
    public ApiResponse<PermissionResponse> update(@PathVariable Long id, @Valid @RequestBody PermissionUpsertRequest request) {
        return ApiResponse.success(service.update(id, request));
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> remove(@PathVariable Long id) {
        service.remove(id);
        return ApiResponse.success();
    }
}
