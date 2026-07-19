package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import dev.webstarter.core.api.PageQuery;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.core.exception.ConflictException;
import dev.webstarter.core.exception.NotFoundException;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.core.security.SecuredOperation;
import dev.webstarter.system.domain.SysConfig;
import dev.webstarter.system.dto.ConfigResponse;
import dev.webstarter.system.dto.ConfigUpsertRequest;
import dev.webstarter.system.persistence.mapper.ConfigMapper;
import dev.webstarter.system.service.ConfigService;
import dev.webstarter.system.service.SystemPermissions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Set;

@Service
public class ConfigServiceImpl extends SecuredOperation implements ConfigService {

    private static final Set<String> SENSITIVE_KEY_MARKERS = Set.of(
            "password",
            "passwd",
            "passphrase",
            "secret",
            "token",
            "credential",
            "privatekey",
            "signingkey",
            "encryptionkey",
            "apikey",
            "accesskey",
            "authkey",
            "masterkey",
            "clientsecret",
            "authorization",
            "cookie",
            "keystore",
            "truststore");

    private final ConfigMapper configMapper;

    public ConfigServiceImpl(CallerContext callerContext, PermissionService permissionService, ConfigMapper configMapper) {
        super(callerContext, permissionService);
        this.configMapper = configMapper;
    }

    @Override
    public PageResult<ConfigResponse> page(long page, long size, String keyword) {
        requirePermission(SystemPermissions.CONFIG_LIST);
        PageQuery query = new PageQuery(page, size);
        LambdaQueryWrapper<SysConfig> wrapper = new LambdaQueryWrapper<SysConfig>()
                .and(hasText(keyword), item -> item.like(SysConfig::getConfigKey, keyword)
                        .or().like(SysConfig::getDescription, keyword))
                .orderByAsc(SysConfig::getConfigKey);
        Page<SysConfig> result = configMapper.selectPage(new Page<>(query.page(), query.size()), wrapper);
        return PageResult.of(result.getRecords().stream().map(this::toResponse).toList(), result.getTotal(), query.page(), query.size());
    }

    @Override
    @Transactional
    public ConfigResponse create(ConfigUpsertRequest request) {
        requirePermission(SystemPermissions.CONFIG_MANAGE);
        ensureKeyAvailable(request.configKey(), null);
        SysConfig config = new SysConfig();
        apply(config, request);
        config.setBuiltin(false);
        config.setDeleted(0);
        LocalDateTime now = LocalDateTime.now();
        config.setCreatedAt(now);
        config.setUpdatedAt(now);
        configMapper.insert(config);
        return toResponse(config);
    }

    @Override
    @Transactional
    public ConfigResponse update(Long id, ConfigUpsertRequest request) {
        requirePermission(SystemPermissions.CONFIG_MANAGE);
        SysConfig config = requireConfig(id);
        ensureKeyAvailable(request.configKey(), id);
        apply(config, request);
        config.setUpdatedAt(LocalDateTime.now());
        configMapper.updateById(config);
        return toResponse(config);
    }

    @Override
    @Transactional
    public void remove(Long id) {
        requirePermission(SystemPermissions.CONFIG_MANAGE);
        SysConfig config = requireConfig(id);
        if (Boolean.TRUE.equals(config.getBuiltin())) {
            throw new ConflictException("Built-in configuration cannot be deleted");
        }
        configMapper.deleteById(id);
    }

    private void apply(SysConfig target, ConfigUpsertRequest request) {
        String key = request.configKey().trim();
        rejectSensitiveKey(key);
        target.setConfigKey(key);
        target.setConfigValue(request.configValue());
        target.setValueType(request.valueType().trim());
        target.setDescription(trimToNull(request.description()));
    }

    private void ensureKeyAvailable(String key, Long excludedId) {
        rejectSensitiveKey(key);
        LambdaQueryWrapper<SysConfig> wrapper = new LambdaQueryWrapper<SysConfig>()
                .eq(SysConfig::getConfigKey, key.trim())
                .ne(excludedId != null, SysConfig::getId, excludedId);
        if (configMapper.selectCount(wrapper) > 0) {
            throw new ConflictException("Configuration key already exists");
        }
    }

    private SysConfig requireConfig(Long id) {
        SysConfig config = id == null ? null : configMapper.selectById(id);
        if (config == null) {
            throw new NotFoundException("Configuration not found");
        }
        return config;
    }

    private ConfigResponse toResponse(SysConfig config) {
        return new ConfigResponse(config.getId(), config.getConfigKey(), config.getConfigValue(), config.getValueType(),
                config.getDescription(), config.getBuiltin());
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
    private static String trimToNull(String value) { return hasText(value) ? value.trim() : null; }

    private static void rejectSensitiveKey(String key) {
        if (isSensitiveKey(key)) {
            throw new IllegalArgumentException(
                    "Sensitive values must be injected through the deployment environment");
        }
    }

    static boolean isSensitiveKey(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String canonical = key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        return SENSITIVE_KEY_MARKERS.stream().anyMatch(canonical::contains);
    }
}
