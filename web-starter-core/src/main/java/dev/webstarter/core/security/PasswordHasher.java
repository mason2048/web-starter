package dev.webstarter.core.security;

public interface PasswordHasher {

    String hash(CharSequence rawPassword);

    boolean matches(CharSequence rawPassword, String encodedPassword);
}
