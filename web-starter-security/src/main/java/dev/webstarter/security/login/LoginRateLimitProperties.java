package dev.webstarter.security.login;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties("web-starter.security.login-rate-limit")
public record LoginRateLimitProperties(
        boolean enabled,
        int maxFailuresPerIdentity,
        int maxFailuresPerPair,
        Duration window,
        Duration initialBackoff,
        Duration maxBackoff) {

    @ConstructorBinding
    public LoginRateLimitProperties {
        maxFailuresPerIdentity = maxFailuresPerIdentity <= 0 ? 5 : maxFailuresPerIdentity;
        maxFailuresPerPair = maxFailuresPerPair <= 0
                ? maxFailuresPerIdentity
                : maxFailuresPerPair;
        window = window == null || window.isNegative() || window.isZero()
                ? Duration.ofMinutes(15) : window;
        initialBackoff = initialBackoff == null || initialBackoff.isNegative()
                || initialBackoff.isZero() ? Duration.ofSeconds(2) : initialBackoff;
        maxBackoff = maxBackoff == null || maxBackoff.compareTo(initialBackoff) < 0
                ? Duration.ofMinutes(15) : maxBackoff;
    }

}
