package dev.webstarter.security.token;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.persistence.model.ServiceAccountRecord;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.service.SystemIdentity;
import dev.webstarter.system.service.SystemIdentityService;

public final class DatabaseCredentialScopePolicy implements CredentialScopePolicy {

    private static final Pattern PERMISSION_CODE = Pattern.compile("[a-z][a-z0-9:_-]{1,127}");

    private final SystemIdentityService identityService;
    private final ServiceAccountMapper serviceAccountMapper;
    private final PermissionMapper permissionMapper;

    public DatabaseCredentialScopePolicy(
            SystemIdentityService identityService,
            ServiceAccountMapper serviceAccountMapper,
            PermissionMapper permissionMapper) {
        this.identityService = identityService;
        this.serviceAccountMapper = serviceAccountMapper;
        this.permissionMapper = permissionMapper;
    }

    @Override
    public Set<String> validateCredentialScopes(
            CredentialType credentialType,
            Long subjectId,
            Collection<String> scopes) {
        Set<String> requested = normalize(scopes);
        Set<String> allowed = switch (credentialType) {
            case PERSONAL_ACCESS_TOKEN -> resolveUserPermissions(subjectId);
            case SERVICE_ACCOUNT_TOKEN -> resolveServiceAccountPermissions(subjectId);
        };
        requireSubset(requested, allowed, "Credential scopes exceed the subject's current RBAC permissions");
        return requested;
    }

    @Override
    public Set<String> validateOAuthClientScopes(
            Collection<String> grantTypes,
            Long serviceAccountId,
            Collection<String> scopes) {
        Set<String> requested = normalize(scopes);
        Set<String> grants = ScopeCodec.decode(ScopeCodec.encode(grantTypes));
        if (grants.contains("client_credentials")) {
            requireSubset(
                    requested,
                    resolveServiceAccountPermissions(serviceAccountId),
                    "OAuth client scopes exceed the service account's current RBAC permissions");
            return requested;
        }
        Set<String> enabled = new LinkedHashSet<>(permissionMapper.selectEnabledCodes(requested));
        requireSubset(requested, enabled, "OAuth client scopes must reference enabled permissions");
        return requested;
    }

    private Set<String> resolveUserPermissions(Long userId) {
        SystemIdentity identity = identityService.loadById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Credential user does not exist"));
        if (!identity.enabled()) {
            throw new IllegalArgumentException("Credential user is disabled");
        }
        return identity.permissions();
    }

    private Set<String> resolveServiceAccountPermissions(Long accountId) {
        ServiceAccountRecord account = accountId == null ? null : serviceAccountMapper.findById(accountId);
        if (account == null) {
            throw new IllegalArgumentException("Service account does not exist");
        }
        if (!account.enabled()) {
            throw new IllegalArgumentException("Service account is disabled");
        }
        return identityService.resolveRbacByRoleIds(ScopeCodec.decodeLongs(account.roleIds())).permissions();
    }

    private static Set<String> normalize(Collection<String> scopes) {
        Set<String> normalized = ScopeCodec.decode(ScopeCodec.encode(scopes));
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("At least one permission scope is required");
        }
        for (String scope : normalized) {
            if (!PERMISSION_CODE.matcher(scope).matches()) {
                throw new IllegalArgumentException("Invalid permission scope: " + scope);
            }
        }
        return Set.copyOf(normalized);
    }

    private static void requireSubset(Set<String> requested, Collection<String> allowed, String message) {
        if (allowed == null || !allowed.containsAll(requested)) {
            throw new IllegalArgumentException(message);
        }
    }
}
