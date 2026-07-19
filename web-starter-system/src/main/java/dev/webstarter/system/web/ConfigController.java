package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.ConfigResponse;
import dev.webstarter.system.dto.ConfigUpsertRequest;
import dev.webstarter.system.service.ConfigService;
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

@RestController
@RequestMapping("/api/configs")
public class ConfigController {
    private final ConfigService configService;

    public ConfigController(ConfigService configService) { this.configService = configService; }

    @GetMapping
    public ApiResponse<PageResult<ConfigResponse>> page(@RequestParam(defaultValue = "1") long page,
                                                        @RequestParam(defaultValue = "20") long size,
                                                        @RequestParam(required = false) String keyword) {
        return ApiResponse.success(configService.page(page, size, keyword));
    }

    @PostMapping
    public ApiResponse<ConfigResponse> create(@Valid @RequestBody ConfigUpsertRequest request) {
        return ApiResponse.success(configService.create(request));
    }

    @PutMapping("/{id}")
    public ApiResponse<ConfigResponse> update(@PathVariable Long id, @Valid @RequestBody ConfigUpsertRequest request) {
        return ApiResponse.success(configService.update(id, request));
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> remove(@PathVariable Long id) {
        configService.remove(id);
        return ApiResponse.success();
    }
}
