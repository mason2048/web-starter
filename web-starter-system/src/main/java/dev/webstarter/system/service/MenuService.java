package dev.webstarter.system.service;

import dev.webstarter.system.dto.MenuResponse;
import dev.webstarter.system.dto.MenuUpsertRequest;

import java.util.List;

public interface MenuService {
    List<MenuResponse> list(String status);
    MenuResponse create(MenuUpsertRequest request);
    MenuResponse update(Long id, MenuUpsertRequest request);
    void remove(Long id);
}
