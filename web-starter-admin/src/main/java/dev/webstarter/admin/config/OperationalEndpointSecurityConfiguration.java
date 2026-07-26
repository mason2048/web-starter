package dev.webstarter.admin.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Gives the separate management server its own stateless Spring Security
 * boundary. A normal Web session or database user is deliberately not an
 * authentication source for operational endpoints.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OperationalEndpointSecurityProperties.class)
public class OperationalEndpointSecurityConfiguration {

    static final String AUTHORITY = "OPERATIONS_OBSERVABILITY";

    @Bean
    @Order(0)
    SecurityFilterChain operationalEndpointSecurityFilterChain(
            HttpSecurity http,
            OperationalEndpointSecurityProperties properties) throws Exception {
        http.securityMatcher("/actuator/**")
                .authenticationManager(authenticationManager(properties))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(
                                "/actuator/info",
                                "/actuator/metrics",
                                "/actuator/metrics/**",
                                "/actuator/prometheus")
                        .hasAuthority(AUTHORITY)
                        .anyRequest().denyAll())
                .csrf(csrf -> csrf.disable())
                .requestCache(cache -> cache.disable())
                .securityContext(context -> context.requireExplicitSave(false))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(basic -> basic.realmName("web-starter-operations"));
        return http.build();
    }

    static AuthenticationManager authenticationManager(
            OperationalEndpointSecurityProperties properties) {
        if (properties.partiallyConfigured()) {
            throw new IllegalStateException(
                    "Operational management username and password must be configured together");
        }
        if (!properties.configured()) {
            return authentication -> {
                throw new BadCredentialsException("Operational management authentication is disabled");
            };
        }

        var passwordEncoder = new BCryptPasswordEncoder(12);
        var user = User.withUsername(properties.getUsername().trim())
                .password(passwordEncoder.encode(properties.getPassword()))
                .authorities(AUTHORITY)
                .build();
        var provider = new DaoAuthenticationProvider(new InMemoryUserDetailsManager(user));
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }
}
