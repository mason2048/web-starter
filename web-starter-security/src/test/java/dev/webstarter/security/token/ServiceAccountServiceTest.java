package dev.webstarter.security.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.model.ServiceAccountRecord;
import dev.webstarter.system.domain.SysRole;
import dev.webstarter.system.persistence.mapper.RoleMapper;

class ServiceAccountServiceTest {

    private ServiceAccountMapper mapper;
    private RoleMapper roleMapper;
    private AccessCredentialMapper credentialMapper;
    private OAuthTokenRegistryMapper oauthTokenRegistryMapper;
    private ServiceAccountService service;

    @BeforeEach
    void setUp() {
        mapper = mock(ServiceAccountMapper.class);
        roleMapper = mock(RoleMapper.class);
        credentialMapper = mock(AccessCredentialMapper.class);
        oauthTokenRegistryMapper = mock(OAuthTokenRegistryMapper.class);
        when(mapper.update(any(ServiceAccountRecord.class))).thenReturn(1);
        service = new ServiceAccountService(
                mapper,
                roleMapper,
                credentialMapper,
                oauthTokenRegistryMapper,
                Clock.fixed(Instant.parse("2026-07-18T10:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void createPersistsOnlyExistingEnabledRoles() {
        when(roleMapper.selectBatchIds(Set.of(3L, 5L))).thenReturn(List.of(role(3L, "ENABLED"), role(5L, "ENABLED")));

        ServiceAccountRecord created = service.create("Agent_01", "Agent", null, Set.of(5L, 3L), 7L);

        assertThat(created.roleIds()).isEqualTo("3,5");
        verify(mapper).insert(created);
    }

    @Test
    void createRejectsUnknownRolesBeforePersisting() {
        when(roleMapper.selectBatchIds(Set.of(3L, 99L))).thenReturn(List.of(role(3L, "ENABLED")));

        assertThatThrownBy(() -> service.create("agent01", "Agent", null, Set.of(3L, 99L), 7L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("do not exist");
        verify(mapper, never()).insert(any(ServiceAccountRecord.class));
    }

    @Test
    void updateRejectsDisabledRolesBeforePersisting() {
        when(mapper.findById(10L)).thenReturn(existingAccount());
        when(roleMapper.selectBatchIds(Set.of(3L))).thenReturn(List.of(role(3L, "DISABLED")));

        assertThatThrownBy(() -> service.update(10L, "Agent", null, true, Set.of(3L), 7L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("enabled roles");
        verify(mapper, never()).update(any(ServiceAccountRecord.class));
    }

    @Test
    void emptyRoleSetIsAllowedWithoutDatabaseLookup() {
        ServiceAccountRecord created = service.create("agent01", "Agent", null, null, 7L);

        assertThat(created.roleIds()).isEmpty();
        verify(roleMapper, never()).selectBatchIds(any());
    }

    @Test
    void disablingAccountAdvancesEpochAndRevokesExistingServiceTokens() {
        when(mapper.findById(10L)).thenReturn(new ServiceAccountRecord(
                10L, "agent01", "Agent", null, true, 4, null, "",
                7L, Instant.parse("2026-07-18T09:00:00Z"), 7L,
                Instant.parse("2026-07-18T09:00:00Z")));

        ServiceAccountRecord updated = service.update(10L, "Agent", null, false, Set.of(), 7L);

        assertThat(updated.securityEpoch()).isEqualTo(5);
        assertThat(updated.disabledAt()).isEqualTo(Instant.parse("2026-07-18T10:00:00Z"));
        verify(credentialMapper).revokeBySubject(
                CredentialType.SERVICE_ACCOUNT_TOKEN.name(),
                10L,
                "SUBJECT_DISABLED",
                Instant.parse("2026-07-18T10:00:00Z"));
    }

    @Test
    void changingRolesRevokesExistingOAuthAccessWithoutInvalidatingServiceTokens() {
        when(mapper.findById(10L)).thenReturn(new ServiceAccountRecord(
                10L, "agent01", "Agent", null, true, 4, null, "3",
                7L, Instant.parse("2026-07-18T09:00:00Z"), 7L,
                Instant.parse("2026-07-18T09:00:00Z")));

        ServiceAccountRecord updated = service.update(10L, "Agent", null, true, Set.of(), 7L);

        assertThat(updated.securityEpoch()).isEqualTo(4);
        verify(oauthTokenRegistryMapper).revokeServiceAccountAccessTokens(
                10L, Instant.parse("2026-07-18T10:00:00Z"));
        verifyNoInteractions(credentialMapper);
    }

    @Test
    void metadataOnlyUpdateDoesNotRevokeOAuthAccess() {
        when(mapper.findById(10L)).thenReturn(existingAccount());

        service.update(10L, "Renamed Agent", "description", true, Set.of(), 7L);

        verifyNoInteractions(oauthTokenRegistryMapper);
        verifyNoInteractions(credentialMapper);
    }

    private static SysRole role(long id, String status) {
        SysRole role = new SysRole();
        role.setId(id);
        role.setStatus(status);
        return role;
    }

    private static ServiceAccountRecord existingAccount() {
        Instant now = Instant.parse("2026-07-18T09:00:00Z");
        return new ServiceAccountRecord(10L, "agent01", "Agent", null, true, "",
                7L, now, 7L, now);
    }
}
