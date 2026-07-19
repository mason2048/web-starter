package dev.webstarter.security.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;

import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.persistence.model.ServiceAccountRecord;
import dev.webstarter.system.domain.SysRole;
import dev.webstarter.system.persistence.mapper.RoleMapper;

public final class ServiceAccountService {

    private final ServiceAccountMapper mapper;
    private final RoleMapper roleMapper;
    private final Clock clock;

    public ServiceAccountService(ServiceAccountMapper mapper, RoleMapper roleMapper) {
        this(mapper, roleMapper, Clock.systemUTC());
    }

    ServiceAccountService(ServiceAccountMapper mapper, RoleMapper roleMapper, Clock clock) {
        this.mapper = mapper;
        this.roleMapper = roleMapper;
        this.clock = clock;
    }

    public ServiceAccountRecord create(
            String code,
            String displayName,
            String description,
            Collection<Long> roleIds,
            Long operatorId) {
        String normalizedCode = normalizeCode(code);
        if (mapper.findByCode(normalizedCode) != null) {
            throw new IllegalArgumentException("Service account code already exists");
        }
        Set<Long> validatedRoleIds = validateRoleIds(roleIds);
        Instant now = clock.instant();
        ServiceAccountRecord record = new ServiceAccountRecord(
                IdWorker.getId(), normalizedCode, requireDisplayName(displayName), description,
                true, ScopeCodec.encodeLongs(validatedRoleIds), operatorId, now, operatorId, now);
        mapper.insert(record);
        return record;
    }

    public ServiceAccountRecord update(
            Long id,
            String displayName,
            String description,
            boolean enabled,
            Collection<Long> roleIds,
            Long operatorId) {
        ServiceAccountRecord current = required(id);
        Set<Long> validatedRoleIds = validateRoleIds(roleIds);
        ServiceAccountRecord updated = new ServiceAccountRecord(
                current.id(), current.code(), requireDisplayName(displayName), description,
                enabled, ScopeCodec.encodeLongs(validatedRoleIds), current.createdBy(), current.createdAt(),
                operatorId, clock.instant());
        mapper.update(updated);
        return updated;
    }

    public ServiceAccountRecord required(Long id) {
        ServiceAccountRecord record = mapper.findById(id);
        if (record == null) {
            throw new IllegalArgumentException("Service account does not exist");
        }
        return record;
    }

    public List<ServiceAccountRecord> findAll() {
        return mapper.findAll();
    }

    public void disable(Long id, Long operatorId) {
        if (mapper.disable(id, operatorId, clock.instant()) == 0) {
            throw new IllegalArgumentException("Service account does not exist");
        }
    }

    private static String normalizeCode(String code) {
        if (code == null || !code.matches("[A-Za-z][A-Za-z0-9_-]{2,63}")) {
            throw new IllegalArgumentException(
                    "Service account code must be 3-64 characters and start with a letter");
        }
        return code.toLowerCase(Locale.ROOT);
    }

    private static String requireDisplayName(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("Display name must not be blank");
        }
        return displayName.trim();
    }

    private Set<Long> validateRoleIds(Collection<Long> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Set.of();
        }
        Set<Long> uniqueRoleIds = new LinkedHashSet<>(roleIds);
        if (uniqueRoleIds.contains(null) || uniqueRoleIds.stream().anyMatch(id -> id <= 0)) {
            throw new IllegalArgumentException("Role IDs must be positive numbers");
        }
        List<SysRole> roles = roleMapper.selectBatchIds(uniqueRoleIds);
        if (roles.size() != uniqueRoleIds.size()) {
            throw new IllegalArgumentException("One or more roles do not exist");
        }
        if (roles.stream().anyMatch(role -> !"ENABLED".equals(role.getStatus()))) {
            throw new IllegalArgumentException("Service accounts can only use enabled roles");
        }
        return uniqueRoleIds;
    }
}
