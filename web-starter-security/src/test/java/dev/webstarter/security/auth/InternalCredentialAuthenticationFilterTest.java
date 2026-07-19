package dev.webstarter.security.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.stream.Stream;

import jakarta.servlet.FilterChain;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.AuthenticationEntryPoint;

class InternalCredentialAuthenticationFilterTest {

    @ParameterizedTest
    @MethodSource("internalCredentials")
    void publicIngressRejectsEveryInternalCredentialType(String rawToken) throws Exception {
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        AuthenticationEntryPoint entryPoint = (request, response, exception) -> response.sendError(401);
        InternalCredentialAuthenticationFilter filter = new InternalCredentialAuthenticationFilter(
                authenticationManager, entryPoint, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mcp");
        request.addHeader("Authorization", "Bearer " + rawToken);
        request.addHeader(InternalCredentialAuthenticationFilter.INGRESS_HEADER,
                InternalCredentialAuthenticationFilter.PUBLIC_INGRESS);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        verifyNoInteractions(authenticationManager, chain);
    }

    private static Stream<String> internalCredentials() {
        return Stream.of(
                "wst_pat_example",
                "wst_svc_example");
    }
}
