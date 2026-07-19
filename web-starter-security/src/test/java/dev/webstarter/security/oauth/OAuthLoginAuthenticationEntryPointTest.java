package dev.webstarter.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

class OAuthLoginAuthenticationEntryPointTest {

    @Test
    void authorizeRequestIsReturnedToSpaAsSameOriginRedirectTarget() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setQueryString("response_type=code&client_id=agent");
        MockHttpServletResponse response = new MockHttpServletResponse();

        new OAuthLoginAuthenticationEntryPoint().commence(
                request,
                response,
                new InsufficientAuthenticationException("login required"));

        assertThat(response.getRedirectedUrl()).isEqualTo(
                "/login?redirect=%2Foauth2%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Dagent");
    }
}
