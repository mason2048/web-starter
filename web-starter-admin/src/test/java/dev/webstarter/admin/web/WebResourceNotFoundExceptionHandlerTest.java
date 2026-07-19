package dev.webstarter.admin.web;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.resource.NoResourceFoundException;

class WebResourceNotFoundExceptionHandlerTest {

    @Test
    void missingApiAndDynamicRegistrationPathsReturnNonSensitive404Responses() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new MissingResourceController())
                .setControllerAdvice(new WebResourceNotFoundExceptionHandler())
                .build();

        assertMissing(mockMvc, "/api/not-present");
        assertMissing(mockMvc, "/connect/register");
    }

    private static void assertMissing(MockMvc mockMvc, String path) throws Exception {
        mockMvc.perform(get(path))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(4004))
                .andExpect(jsonPath("$.message").value("Resource not found"))
                .andExpect(jsonPath("$.data").doesNotExist())
                .andExpect(jsonPath("$.traceId").isNotEmpty())
                .andExpect(content().string(not(containsString("No static resource"))))
                .andExpect(content().string(not(containsString(path))));
    }

    @RestController
    private static final class MissingResourceController {

        @GetMapping({"/api/not-present", "/connect/register"})
        void missing(HttpServletRequest request) throws NoResourceFoundException {
            throw new NoResourceFoundException(
                    HttpMethod.GET, request.getRequestURI(), "classpath static resources");
        }
    }
}
