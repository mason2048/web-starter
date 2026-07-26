package dev.webstarter.admin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Dedicated credentials for the isolated operational management endpoint. */
@ConfigurationProperties("web-starter.management.security")
public class OperationalEndpointSecurityProperties {

    private String username;
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean configured() {
        return hasText(username) && hasText(password);
    }

    public boolean partiallyConfigured() {
        return hasText(username) != hasText(password);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
