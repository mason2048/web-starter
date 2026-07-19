package dev.webstarter.security.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.model.AccessCredentialRecord;

class AccessCredentialServiceTest {

    private static final String PEPPER = "0123456789abcdef0123456789abcdef";
    private static final Instant NOW = Instant.parse("2026-07-18T10:00:00Z");

    @Mock
    private AccessCredentialMapper mapper;
    @Mock
    private CredentialScopePolicy scopePolicy;

    private TokenHasher tokenHasher;
    private AccessCredentialService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        tokenHasher = new TokenHasher(PEPPER);
        when(scopePolicy.validateCredentialScopes(any(), any(), any())).thenAnswer(invocation ->
                Set.copyOf(invocation.getArgument(2)));
        service = new AccessCredentialService(
                mapper,
                tokenHasher,
                scopePolicy,
                new RawTokenFactory(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void issuePersistsOnlyHmacAndReturnsRawValueOnce() {
        IssuedCredential issued = service.issue(
                CredentialType.PERSONAL_ACCESS_TOKEN,
                7L,
                "automation",
                Set.of("project:list"),
                List.of("10.0.0.0/8"),
                NOW.plusSeconds(3600),
                1L);

        ArgumentCaptor<AccessCredentialRecord> captor = ArgumentCaptor.forClass(AccessCredentialRecord.class);
        verify(mapper).insert(captor.capture());
        AccessCredentialRecord stored = captor.getValue();
        assertThat(issued.rawToken()).startsWith("wst_pat_");
        assertThat(stored.tokenHash())
                .isEqualTo(tokenHasher.hash(issued.rawToken()))
                .matches("[0-9a-f]{64}")
                .doesNotContain(issued.rawToken());
        assertThat(stored.tokenHint()).isNotEqualTo(issued.rawToken());
    }

    @Test
    void ipRestrictionIsCheckedBeforeLastUsedIsTouched() {
        String rawToken = "wst_pat_example";
        AccessCredentialRecord record = activeRecord(rawToken, "10.0.0.0/8");
        when(mapper.findByHash(tokenHasher.hash(rawToken))).thenReturn(record);

        assertThat(service.findActiveByRawToken(rawToken, "192.168.1.10")).isNull();
        verify(mapper, never()).touchLastUsed(any(), any(), any());

        assertThat(service.findActiveByRawToken(rawToken, "10.20.30.40")).isEqualTo(record);
        verify(mapper).touchLastUsed(eq(record.id()), eq(NOW), eq(NOW.minusSeconds(60)));
    }

    @Test
    void revokedCredentialCannotAuthenticateAndRevokeIsExplicit() {
        String rawToken = "wst_svc_example";
        AccessCredentialRecord revoked = new AccessCredentialRecord(
                9L,
                CredentialType.SERVICE_ACCOUNT_TOKEN,
                5L,
                "agent",
                tokenHasher.hash(rawToken),
                "wst_svc_exam",
                "project:list",
                null,
                NOW.plusSeconds(3600),
                NOW.minusSeconds(1),
                null,
                1L,
                NOW.minusSeconds(60));
        when(mapper.findByHash(tokenHasher.hash(rawToken))).thenReturn(revoked);
        when(mapper.revoke(9L, NOW)).thenReturn(1);

        assertThat(service.findActiveByRawToken(rawToken, "10.0.0.1")).isNull();
        service.revoke(9L);
        verify(mapper).revoke(9L, NOW);
    }

    @Test
    void unknownCredentialCannotBeReportedAsRevoked() {
        when(mapper.revoke(99L, NOW)).thenReturn(0);
        assertThatThrownBy(() -> service.revoke(99L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Credential does not exist");
    }

    @Test
    void ipRestrictionAcceptsIpLiteralsOnly() {
        assertThat(IpRestriction.permits("2001:db8::10", List.of("2001:db8::/32"))).isTrue();
        assertThat(IpRestriction.permits("2001:dead::10", List.of("2001:db8::/32"))).isFalse();
        assertThat(IpRestriction.permits("example.invalid", List.of("10.0.0.0/8"))).isFalse();
        assertThat(IpRestriction.permits("10.1.2.3", List.of("example.invalid/24"))).isFalse();
    }

    @Test
    void issueRejectsInvalidCidrsBeforePersistingCredential() {
        assertThatThrownBy(() -> service.issue(
                CredentialType.PERSONAL_ACCESS_TOKEN,
                7L,
                "automation",
                Set.of("project:list"),
                List.of("10.0.0.0/33"),
                NOW.plusSeconds(3600),
                1L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid IP CIDR");
        verify(mapper, never()).insert(any());
    }

    private AccessCredentialRecord activeRecord(String rawToken, String cidrs) {
        return new AccessCredentialRecord(
                8L,
                CredentialType.PERSONAL_ACCESS_TOKEN,
                7L,
                "automation",
                tokenHasher.hash(rawToken),
                "wst_pat_exam",
                "project:list",
                cidrs,
                NOW.plusSeconds(3600),
                null,
                null,
                1L,
                NOW.minusSeconds(60));
    }
}
