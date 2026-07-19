package dev.webstarter.system.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface SystemIdentityService {

    Optional<SystemIdentity> loadByUsername(String username);

    Optional<SystemIdentity> loadById(Long userId);

    List<SystemUserSummary> listEnabledUsers();

    RbacSnapshot resolveRbacByRoleIds(Collection<Long> roleIds);
}
