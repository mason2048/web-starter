package dev.webstarter.security.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;

class CallerSnapshotRequestFilterEpochTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void staleAuthenticatedSessionIsClearedBeforeAuthorization() throws Exception {
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.current()).thenReturn(Optional.empty());
        CurrentCaller staleCaller = new CurrentCaller(
                CallerType.USER, "7", "operator", "Operator", null, null,
                Set.of(), Set.of(), Set.of(), "trace");
        SecurityContextHolder.getContext().setAuthentication(
                CallerAuthenticationToken.authenticated(staleCaller, 1, List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = (MockHttpSession) request.getSession(true);

        new CallerSnapshotRequestFilter(callerContext).doFilter(
                request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
        assertThat(request.getAttribute(CallerSnapshotRequestFilter.REQUEST_ATTRIBUTE)).isNull();
    }
}
