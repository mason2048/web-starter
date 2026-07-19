package dev.webstarter.core.security;

import dev.webstarter.core.exception.AuthenticationRequiredException;

import java.util.Optional;

public interface CallerContext {

    Optional<CurrentCaller> current();

    default CurrentCaller required() {
        return current().orElseThrow(AuthenticationRequiredException::new);
    }
}
