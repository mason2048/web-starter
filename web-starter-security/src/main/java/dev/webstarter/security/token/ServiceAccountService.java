package dev.webstarter.security.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;

import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.persistence.model.ServiceAccountRecord;
import dev.webstarter.system.domain.SysRole;
import dev.webstarter.system.persistence.mapper.RoleMapper;

public class ServiceAccountService {

    private final ServiceAccountMapper mapper;
    private final RoleMapper roleMapper;
    private final AccessCredentialMapper credentialMapper;
    private final OAuthTokenRegistryMapper oauthTokenRegistryMapper;
    private final Clock clock;

    public ServiceAccountService(ServiceAccountMapper mapper, RoleMapper roleMapper) {
        this(mapper, roleMapper, null, null, Clock.systemUTC());
    }

    public ServiceAccountService(
            ServiceAccountMapper mapper,
            RoleMapper roleMapper,
            AccessCredentialMapper credentialMapper) {
        this(mapper, roleMapper, credentialMapper, null, Clock.systemUTC());
    }

    public ServiceAccountService(
            ServiceAccountMapper mapper,
            RoleMapper roleMapper,
            AccessCredentialMapper credentialMapper,
            OAuthTokenRegistryMapper oauthTokenRegistryMapper) {
        this(mapper, roleMapper, credentialMapper, oauthTokenRegistryMapper, Clock.systemUTC());
    }

    ServiceAccountService(ServiceAccountMapper mapper, RoleMapper roleMapper, Clock clock) {
        this(mapper, roleMapper, null, null, clock);
    }

    ServiceAccountService(
            ServiceAccountMapper mapper,
            RoleMapper roleMapper,
            AccessCredentialMapper credentialMapper,
            OAuthTokenRegistryMapper oauthTokenRegistryMapper,
            Clock clock) {
        this.mapper = mapper;
        this.roleMapper = roleMapper;
        this.credentialMapper = credentialMapper;
        this.oauthTokenRegistryMapper = oauthTokenRegistryMapper;
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
                true, 0, null, ScopeCodec.encodeLongs(validatedRoleIds),
                operatorId, now, operatorId, now);
        mapper.insert(record);
        return record;
    }

    @Transactional
    public ServiceAccountRecord update(
            Long id,
            String displayName,
            String description,
            boolean enabled,
            Collection<Long> roleIds,
            Long operatorId) {
        ServiceAccountRecord current = required(id);
        Set<Long> validatedRoleIds = validateRoleIds(roleIds);
        String encodedRoleIds = ScopeCodec.encodeLongs(validatedRoleIds);
        boolean rolesChanged = !Objects.equals(current.roleIds(), encodedRoleIds);
        boolean disabledNow = current.enabled() && !enabled;
        long securityEpoch = disabledNow ? current.securityEpoch() + 1 : current.securityEpoch();
        Instant now = clock.instant();
        ServiceAccountRecord updated = new ServiceAccountRecord(
                current.id(), current.code(), requireDisplayName(displayName), description,
                enabled, securityEpoch, disabledNow ? now : current.disabledAt(),
                encodedRoleIds, current.createdBy(), current.createdAt(),
                operatorId, now);
        if (mapper.update(updated) == 0) {
            throw new IllegalStateException("Service account was changed by another request");
        }
        if (disabledNow && credentialMapper != null) {
            credentialMapper.revokeBySubject(
                    CredentialType.SERVICE_ACCOUNT_TOKEN.name(), id, "SUBJECT_DISABLED", now);
        }
        if (rolesChanged && oauthTokenRegistryMapper != null) {
            oauthTokenRegistryMapper.revokeServiceAccountAccessTokens(id, now);
        }
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

    @Transactional
    public void disable(Long id, Long operatorId) {
        ServiceAccountRecord current = required(id);
        if (!current.enabled()) {
            return;
        }
        Instant now = clock.instant();
        if (mapper.disable(id, operatorId, now) == 0) {
            throw new IllegalStateException("Service account was changed by another request");
        }
        if (credentialMapper != null) {
            credentialMapper.revokeBySubject(
                    CredentialType.SERVICE_ACCOUNT_TOKEN.name(), id, "SUBJECT_DISABLED", now);
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
