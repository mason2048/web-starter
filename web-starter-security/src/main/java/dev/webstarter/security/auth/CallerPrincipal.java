package dev.webstarter.security.auth;

import dev.webstarter.core.security.CurrentCaller;

public interface CallerPrincipal {
    CurrentCaller caller();
}
