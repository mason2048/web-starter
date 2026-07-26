package dev.webstarter.security.auth;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.security.persistence.model.AccessCredentialRecord;
import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.token.AccessCredentialService;
import dev.webstarter.security.token.CredentialType;
import dev.webstarter.security.token.CredentialScopePolicy;
import dev.webstarter.security.token.TokenHasher;

class InternalCredentialAuthenticationProviderEpochTest {

    @Test
    void tokenFromEarlierIdentityEpochIsRejected() {
        AccessCredentialMapper mapper = mock(AccessCredentialMapper.class);
        TokenHasher tokenHasher = new TokenHasher("0123456789abcdef0123456789abcdef");
        AccessCredentialService credentialService = new AccessCredentialService(
                mapper, tokenHasher, mock(CredentialScopePolicy.class));
        CredentialSubjectResolver resolver = mock(CredentialSubjectResolver.class);
        String rawToken = "wst_pat_example";
        AccessCredentialRecord credential = new AccessCredentialRecord(
                9L, CredentialType.PERSONAL_ACCESS_TOKEN, 7L, 3,
                "automation", "hash", "wst_pat_exam", "project:list", null,
                Instant.now().plusSeconds(60), null, null, null, 1L, Instant.now());
        when(mapper.findByHashAndPepperVersion(tokenHasher.hash(rawToken), "v1"))
                .thenReturn(credential);
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER, "7", "operator", "Operator", null, null,
                Set.of(), Set.of("project:list"), Set.of(), "trace");
        when(resolver.resolveUser(7L))
                .thenReturn(Optional.of(new ResolvedCredentialSubject(caller, 4)));

        var authentication = CallerAuthenticationToken.unauthenticated(rawToken);
        assertThatThrownBy(() -> new InternalCredentialAuthenticationProvider(
                credentialService, resolver).authenticate(authentication))
                .isInstanceOf(BadCredentialsException.class);
    }
}
