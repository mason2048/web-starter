package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class OperationalEndpointSecurityConfigurationTest {

    @Test
    void authenticatesOnlyTheDedicatedOperationalIdentity() {
        OperationalEndpointSecurityProperties properties = properties(
                "starter_ops", "operations-password-0123456789abcdef");
        var manager = OperationalEndpointSecurityConfiguration.authenticationManager(properties);

        var authenticated = manager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        "starter_ops", "operations-password-0123456789abcdef"));

        assertThat(authenticated.isAuthenticated()).isTrue();
        assertThat(authenticated.getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .contains(OperationalEndpointSecurityConfiguration.AUTHORITY);
        assertThatThrownBy(() -> manager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        "admin", "operations-password-0123456789abcdef")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void rejectsWrongPasswordWithoutFallingBackToWebAuthentication() {
        var manager = OperationalEndpointSecurityConfiguration.authenticationManager(
                properties("starter_ops", "operations-password-0123456789abcdef"));

        assertThatThrownBy(() -> manager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        "starter_ops", "wrong-password")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void missingDevelopmentCredentialsFailClosedAndPartialConfigurationFailsFast() {
        var disabled = OperationalEndpointSecurityConfiguration.authenticationManager(
                properties(null, null));

        assertThatThrownBy(() -> disabled.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated("anyone", "anything")))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("disabled");
        assertThatThrownBy(() -> OperationalEndpointSecurityConfiguration.authenticationManager(
                properties("starter_ops", null)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("configured together");
    }

    private static OperationalEndpointSecurityProperties properties(
            String username, String password) {
        OperationalEndpointSecurityProperties properties =
                new OperationalEndpointSecurityProperties();
        properties.setUsername(username);
        properties.setPassword(password);
        return properties;
    }
}
