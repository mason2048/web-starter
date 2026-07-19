package dev.webstarter.security.auth;

import org.springframework.security.crypto.password.PasswordEncoder;

import dev.webstarter.core.security.PasswordHasher;

public final class SpringPasswordHasher implements PasswordHasher {

    private final PasswordEncoder delegate;

    public SpringPasswordHasher(PasswordEncoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public String hash(CharSequence rawPassword) {
        return delegate.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegate.matches(rawPassword, encodedPassword);
    }
}
