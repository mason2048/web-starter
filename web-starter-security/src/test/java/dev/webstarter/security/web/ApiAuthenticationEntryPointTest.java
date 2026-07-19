package dev.webstarter.security.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

class ApiAuthenticationEntryPointTest {

    @Test
    void returnsJson401WithTraceId() throws Exception {
        MDC.put("traceId", "trace-api-401");
        try {
            MockHttpServletResponse response = new MockHttpServletResponse();

            new ApiAuthenticationEntryPoint().commence(
                    new MockHttpServletRequest("GET", "/api/projects"),
                    response,
                    new BadCredentialsException("not exposed"));

            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(response.getContentType()).startsWith("application/json");
            assertThat(response.getContentAsString())
                    .contains("\"code\":4001")
                    .contains("\"traceId\":\"trace-api-401\"")
                    .doesNotContain("not exposed");
        }
        finally {
            MDC.remove("traceId");
        }
    }
}
