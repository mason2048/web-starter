package dev.webstarter.security.token;

import org.springframework.stereotype.Component;

import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.system.service.RoleUsageChecker;

@Component
public final class ServiceAccountRoleUsageChecker implements RoleUsageChecker {

    private final ServiceAccountMapper serviceAccountMapper;

    public ServiceAccountRoleUsageChecker(ServiceAccountMapper serviceAccountMapper) {
        this.serviceAccountMapper = serviceAccountMapper;
    }

    @Override
    public boolean isRoleInUse(Long roleId) {
        return serviceAccountMapper.countByRoleId(roleId) > 0;
    }
}
