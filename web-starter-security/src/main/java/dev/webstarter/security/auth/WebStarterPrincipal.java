package dev.webstarter.security.auth;

import java.security.Principal;

import dev.webstarter.core.security.CurrentCaller;

public record WebStarterPrincipal(CurrentCaller caller) implements Principal, CallerPrincipal {

    @Override
    public String getName() {
        return caller.username();
    }
}
