package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.system.dto.MenuResponse;
import dev.webstarter.system.dto.MenuUpsertRequest;
import dev.webstarter.system.service.MenuService;
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
@RequestMapping("/api/menus")
public class MenuController {
    private final MenuService menuService;

    public MenuController(MenuService menuService) { this.menuService = menuService; }

    @GetMapping
    public ApiResponse<List<MenuResponse>> list(@RequestParam(required = false) String status) {
        return ApiResponse.success(menuService.list(status));
    }

    @PostMapping
    public ApiResponse<MenuResponse> create(@Valid @RequestBody MenuUpsertRequest request) {
        return ApiResponse.success(menuService.create(request));
    }

    @PutMapping("/{id}")
    public ApiResponse<MenuResponse> update(@PathVariable Long id, @Valid @RequestBody MenuUpsertRequest request) {
        return ApiResponse.success(menuService.update(id, request));
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> remove(@PathVariable Long id) {
        menuService.remove(id);
        return ApiResponse.success();
    }
}
