package dev.webstarter.security.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.persistence.model.ServiceAccountRecord;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.service.RbacSnapshot;
import dev.webstarter.system.service.SystemIdentity;
import dev.webstarter.system.service.SystemIdentityService;

class DatabaseCredentialScopePolicyTest {

    private SystemIdentityService identityService;
    private ServiceAccountMapper serviceAccountMapper;
    private PermissionMapper permissionMapper;
    private DatabaseCredentialScopePolicy policy;

    @BeforeEach
    void setUp() {
        identityService = mock(SystemIdentityService.class);
        serviceAccountMapper = mock(ServiceAccountMapper.class);
        permissionMapper = mock(PermissionMapper.class);
        policy = new DatabaseCredentialScopePolicy(identityService, serviceAccountMapper, permissionMapper);
    }

    @Test
    void personalTokenScopesMustBeAnExactSubsetOfLiveUserRbac() {
        when(identityService.loadById(7L)).thenReturn(Optional.of(user(Set.of("project:list"))));

        assertThat(policy.validateCredentialScopes(
                CredentialType.PERSONAL_ACCESS_TOKEN, 7L, Set.of("project:list")))
                .containsExactly("project:list");
        assertThatThrownBy(() -> policy.validateCredentialScopes(
                CredentialType.PERSONAL_ACCESS_TOKEN, 7L, Set.of("project:create")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("current RBAC");
    }

    @Test
    void wildcardAndMalformedScopesAreRejectedBeforeSubjectLookup() {
        assertThatThrownBy(() -> policy.validateCredentialScopes(
                CredentialType.PERSONAL_ACCESS_TOKEN, 7L, Set.of("*")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid permission scope");
        assertThatThrownBy(() -> policy.validateCredentialScopes(
                CredentialType.PERSONAL_ACCESS_TOKEN, 7L, Set.of("Project List")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid permission scope");
    }

    @Test
    void serviceTokensAndClientCredentialsCannotExceedServiceAccountRbac() {
        when(serviceAccountMapper.findById(10L)).thenReturn(serviceAccount(true));
        when(identityService.resolveRbacByRoleIds(List.of(3L))).thenReturn(
                new RbacSnapshot(Set.of("AGENT"), Set.of("project:list"), Set.of()));

        assertThat(policy.validateCredentialScopes(
                CredentialType.SERVICE_ACCOUNT_TOKEN, 10L, Set.of("project:list")))
                .containsExactly("project:list");
        assertThatThrownBy(() -> policy.validateOAuthClientScopes(
                Set.of("client_credentials"), 10L, Set.of("project:create")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("service account");
    }

    @Test
    void userAgentClientScopesMustReferenceEnabledPermissions() {
        when(permissionMapper.selectEnabledCodes(Set.of("project:list")))
                .thenReturn(List.of("project:list"));

        assertThat(policy.validateOAuthClientScopes(
                Set.of("authorization_code"), null, Set.of("project:list")))
                .containsExactly("project:list");
        assertThatThrownBy(() -> policy.validateOAuthClientScopes(
                Set.of("authorization_code"), null, Set.of("project:create")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("enabled permissions");
    }

    private static SystemIdentity user(Set<String> permissions) {
        return new SystemIdentity(
                7L, "operator", "Operator", "hash", "ENABLED",
                Set.of("USER"), permissions, Set.of());
    }

    private static ServiceAccountRecord serviceAccount(boolean enabled) {
        Instant now = Instant.parse("2026-07-18T10:00:00Z");
        return new ServiceAccountRecord(
                10L, "agent", "Agent", null, enabled, "3",
                1L, now, 1L, now);
    }
}
