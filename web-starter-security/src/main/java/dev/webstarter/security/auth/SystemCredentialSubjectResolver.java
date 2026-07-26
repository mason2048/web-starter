package dev.webstarter.security.auth;

import java.util.Optional;
import java.util.Set;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.trace.TraceContext;
import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.token.ScopeCodec;
import dev.webstarter.system.service.SystemIdentityService;

public final class SystemCredentialSubjectResolver implements CredentialSubjectResolver {

    private final SystemIdentityService identityService;
    private final ServiceAccountMapper serviceAccountMapper;

    public SystemCredentialSubjectResolver(
            SystemIdentityService identityService,
            ServiceAccountMapper serviceAccountMapper) {
        this.identityService = identityService;
        this.serviceAccountMapper = serviceAccountMapper;
    }

    @Override
    public Optional<ResolvedCredentialSubject> resolveUser(Long userId) {
        return identityService.loadById(userId)
                .filter(identity -> identity.enabled())
                .map(identity -> new ResolvedCredentialSubject(
                        new CurrentCaller(
                                CallerType.USER,
                                identity.userId().toString(),
                                identity.username(),
                                identity.displayName(),
                                null,
                                null,
                                Set.of(),
                                identity.permissions(),
                                identity.menuIds(),
                                TraceContext.traceId()),
                        identity.securityEpoch()));
    }

    @Override
    public Optional<ResolvedCredentialSubject> resolveServiceAccount(Long serviceAccountId) {
        var account = serviceAccountMapper.findById(serviceAccountId);
        if (account == null || !account.enabled()) {
            return Optional.empty();
        }
        var rbac = identityService.resolveRbacByRoleIds(ScopeCodec.decodeLongs(account.roleIds()));
        return Optional.of(new ResolvedCredentialSubject(
                new CurrentCaller(
                        CallerType.SERVICE_ACCOUNT,
                        account.id().toString(),
                        account.code(),
                        account.displayName(),
                        null,
                        null,
                        Set.of(),
                        rbac.permissions(),
                        rbac.menuIds(),
                        TraceContext.traceId()),
                account.securityEpoch()));
    }
}
