package dev.webstarter.security.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.LoginAuditEvent;

class AuthControllerTest {

    @Test
    void springSelectsTheProductionConstructorWhenTestClockOverloadExists() {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.registerBean(AuthenticationManager.class, () -> mock(AuthenticationManager.class));
            context.registerBean(SecurityContextRepository.class, () -> mock(SecurityContextRepository.class));
            context.registerBean(CallerContext.class, () -> mock(CallerContext.class));
            context.registerBean(AuditLogRecorder.class, () -> mock(AuditLogRecorder.class));
            context.registerBean(AuthController.class);

            context.refresh();

            assertThat(context.getBean(AuthController.class)).isNotNull();
        }
    }

    @Test
    void invalidLoginReturnsJson401AndRecordsFailure() throws Exception {
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        doThrow(new BadCredentialsException("secret detail"))
                .when(authenticationManager).authenticate(any());
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        AuthController controller = new AuthController(
                authenticationManager,
                mock(SecurityContextRepository.class),
                mock(CallerContext.class),
                auditLogRecorder);
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new SecurityExceptionHandler())
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"operator\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(4001))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));

        verify(auditLogRecorder).recordLogin(any(LoginAuditEvent.class));
    }
}
