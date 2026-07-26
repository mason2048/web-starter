package dev.webstarter.security.oauth;

import java.time.Clock;
import java.util.Objects;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Spring Authorization Server password encoder that accepts the active client
 * secret and, only before its explicit cutoff, one retiring secret.
 */
public final class OAuthClientSecretPasswordEncoder implements PasswordEncoder {

    private final PasswordEncoder delegate;
    private final Clock clock;

    public OAuthClientSecretPasswordEncoder(PasswordEncoder delegate) {
        this(delegate, Clock.systemUTC());
    }

    OAuthClientSecretPasswordEncoder(PasswordEncoder delegate, Clock clock) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        OAuthClientSecretEnvelope.Parsed envelope;
        try {
            envelope = OAuthClientSecretEnvelope.parse(encodedPassword);
        }
        catch (IllegalArgumentException exception) {
            return false;
        }
        if (envelope == null) {
            return delegate.matches(rawPassword, encodedPassword);
        }
        boolean activeMatches = delegate.matches(rawPassword, envelope.activeHash());
        boolean retiringMatches = envelope.retiringHash() != null
                && clock.instant().isBefore(envelope.retiringExpiresAt())
                && delegate.matches(rawPassword, envelope.retiringHash());
        return activeMatches || retiringMatches;
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        if (encodedPassword != null && encodedPassword.startsWith(OAuthClientSecretEnvelope.PREFIX)) {
            return false;
        }
        return delegate.upgradeEncoding(encodedPassword);
    }
}
