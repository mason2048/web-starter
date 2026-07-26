package dev.webstarter.security.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.security.login.LoginAttemptLimiter;
import dev.webstarter.security.login.LoginRateLimitDecision;
import dev.webstarter.security.login.LoginRateLimitUnavailableException;

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

    @Test
    void blockedLoginReturns429WithRetryAfterWithoutCheckingPassword() throws Exception {
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        LoginAttemptLimiter limiter = mock(LoginAttemptLimiter.class);
        when(limiter.check("operator", "127.0.0.1"))
                .thenReturn(LoginRateLimitDecision.blocked(90));
        AuthController controller = new AuthController(
                authenticationManager,
                mock(SecurityContextRepository.class),
                mock(CallerContext.class),
                mock(AuditLogRecorder.class),
                limiter,
                Clock.fixed(Instant.parse("2026-07-18T10:00:00Z"), ZoneOffset.UTC));
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new SecurityExceptionHandler())
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"operator\",\"password\":\"wrong\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("Retry-After", "90"))
                .andExpect(jsonPath("$.code").value(4290))
                .andExpect(jsonPath("$.message").value("Too many login attempts; try again later"));

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void unavailableLimiterReturnsAudited503WithoutCheckingPasswordOrLeakingCause() throws Exception {
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        LoginAttemptLimiter limiter = mock(LoginAttemptLimiter.class);
        when(limiter.check("operator", "127.0.0.1"))
                .thenThrow(new LoginRateLimitUnavailableException(
                        new IllegalStateException("redis.internal.example:6379")));
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        AuthController controller = new AuthController(
                authenticationManager,
                mock(SecurityContextRepository.class),
                mock(CallerContext.class),
                auditLogRecorder,
                limiter,
                Clock.fixed(Instant.parse("2026-07-18T10:00:00Z"), ZoneOffset.UTC));
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new SecurityExceptionHandler())
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"operator\",\"password\":\"wrong\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value(5030))
                .andExpect(jsonPath("$.message").value("Login is temporarily unavailable"))
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("redis"))));

        verify(authenticationManager, never()).authenticate(any());
        ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(auditLogRecorder).recordLogin(event.capture());
        assertThat(event.getValue().result()).isEqualTo("FAILURE");
        assertThat(event.getValue().failureReason()).isEqualTo("RATE_LIMIT_UNAVAILABLE");
    }

    @Test
    void unavailableFailureCounterOverridesInvalidCredentialsWithAudited503() throws Exception {
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        doThrow(new BadCredentialsException("secret detail"))
                .when(authenticationManager).authenticate(any());
        LoginAttemptLimiter limiter = mock(LoginAttemptLimiter.class);
        when(limiter.check("operator", "127.0.0.1"))
                .thenReturn(LoginRateLimitDecision.permit());
        when(limiter.recordFailure("operator", "127.0.0.1"))
                .thenThrow(new LoginRateLimitUnavailableException());
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        AuthController controller = new AuthController(
                authenticationManager,
                mock(SecurityContextRepository.class),
                mock(CallerContext.class),
                auditLogRecorder,
                limiter,
                Clock.fixed(Instant.parse("2026-07-18T10:00:00Z"), ZoneOffset.UTC));
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new SecurityExceptionHandler())
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"operator\",\"password\":\"wrong\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value(5030))
                .andExpect(jsonPath("$.message").value("Login is temporarily unavailable"));

        ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(auditLogRecorder).recordLogin(event.capture());
        assertThat(event.getValue().failureReason()).isEqualTo("RATE_LIMIT_UNAVAILABLE");
    }

    @Test
    void unavailableSuccessCleanupPreventsSessionCreationAndReturnsAudited503() throws Exception {
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        when(authenticationManager.authenticate(any()))
                .thenReturn(mock(org.springframework.security.core.Authentication.class));
        LoginAttemptLimiter limiter = mock(LoginAttemptLimiter.class);
        when(limiter.check("operator", "127.0.0.1"))
                .thenReturn(LoginRateLimitDecision.permit());
        doThrow(new LoginRateLimitUnavailableException())
                .when(limiter).recordSuccess("operator", "127.0.0.1");
        AuditLogRecorder auditLogRecorder = mock(AuditLogRecorder.class);
        SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
        AuthController controller = new AuthController(
                authenticationManager,
                securityContextRepository,
                mock(CallerContext.class),
                auditLogRecorder,
                limiter,
                Clock.fixed(Instant.parse("2026-07-18T10:00:00Z"), ZoneOffset.UTC));
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new SecurityExceptionHandler())
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"operator\",\"password\":\"correct\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value(5030))
                .andExpect(jsonPath("$.message").value("Login is temporarily unavailable"));

        verify(securityContextRepository, never()).saveContext(any(), any(), any());
        ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(auditLogRecorder).recordLogin(event.capture());
        assertThat(event.getValue().failureReason()).isEqualTo("RATE_LIMIT_UNAVAILABLE");
    }
}
