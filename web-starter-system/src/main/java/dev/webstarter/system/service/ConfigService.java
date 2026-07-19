package dev.webstarter.system.service;

import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.ConfigResponse;
import dev.webstarter.system.dto.ConfigUpsertRequest;

public interface ConfigService {
    PageResult<ConfigResponse> page(long page, long size, String keyword);
    ConfigResponse create(ConfigUpsertRequest request);
    ConfigResponse update(Long id, ConfigUpsertRequest request);
    void remove(Long id);
}
