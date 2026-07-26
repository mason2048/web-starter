package dev.webstarter.security.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;

class SpringSecurityCallerContextEpochTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void oldWebSessionCannotBecomeValidAgainAfterIdentityEpochAdvances() {
        CurrentCaller caller = new CurrentCaller(
                CallerType.USER, "7", "operator", "Operator", null, null,
                Set.of(), Set.of("project:list"), Set.of(), "old-trace");
        CredentialSubjectResolver resolver = mock(CredentialSubjectResolver.class);
        when(resolver.resolveUser(7L))
                .thenReturn(Optional.of(new ResolvedCredentialSubject(caller, 2)));
        SecurityContextHolder.getContext().setAuthentication(
                CallerAuthenticationToken.authenticated(caller, 1, List.of()));

        assertThat(new SpringSecurityCallerContext(resolver).current()).isEmpty();

        // Re-enabling the user leaves epoch 2 unchanged, so epoch-1 session state stays stale.
        when(resolver.resolveUser(7L))
                .thenReturn(Optional.of(new ResolvedCredentialSubject(caller, 2)));
        assertThat(new SpringSecurityCallerContext(resolver).current()).isEmpty();
    }
}
